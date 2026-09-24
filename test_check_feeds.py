"""Tests for the upstream-feed watchdog.

The numbers are the ones NIST actually served on 2026-08-27, measured live:
seven year feeds and the modified feed were HTTP 200 with intact gzip and a
truthful envelope over a near-empty array, while the other eighteen years were
healthy. Healthy files ran 321-896 gzipped bytes per record; the truncated
ones ran 0.063-2.099.
"""

import check_feeds
import nvd

# year -> (gzipped Content-Length, records the baseline expects)
HEALTHY = {
    2002: (2176229, 6771),
    2009: (4528035, 5054),   # the sparsest healthy feed: 896 bytes/record
    2020: (13979100, 21074),
    2024: (24983095, 39227),
}
TRUNCATED = {
    2015: (3767, 8779),
    2019: (2378, 17623),
    2021: (2288, 23452),
    2022: (3454, 27531),
    2023: (2381, 31249),
    2025: (2838, 45185),
    2026: (104748, 49906),   # least truncated of the set: 2.099 bytes/record
}


def _fake_crawler(sizes: dict[int, int]):
    """A crawler whose HEAD returns the given size for each year's feed."""

    class FakeSession:
        headers: dict = {}

        def head(self, url, **kwargs):
            year = int(url.rsplit("-", 1)[1].split(".")[0])

            class Resp:
                status_code = 200
                headers = {"Content-Length": str(sizes[year])}

            return Resp()

    crawler = nvd.Crawler(session=FakeSession(), user_agents=["ua"])
    return crawler


def test_healthy_feeds_produce_no_findings():
    sizes = {y: s for y, (s, _) in HEALTHY.items()}
    baseline = {y: c for y, (_, c) in HEALTHY.items()}
    # 2002 aggregates the earlier years, so give it its real components.
    baseline.update({1999: 1579, 2000: 1243, 2001: 1556, 2002: 2393})

    for year in HEALTHY:
        problems, _ = check_feeds.check_year_feeds(
            _fake_crawler(sizes), baseline, year, year
        )
        assert problems == [], f"year {year} false-positived: {problems}"


def test_every_truncated_feed_is_caught():
    sizes = {y: s for y, (s, _) in TRUNCATED.items()}
    baseline = {y: c for y, (_, c) in TRUNCATED.items()}

    for year in TRUNCATED:
        problems, _ = check_feeds.check_year_feeds(
            _fake_crawler(sizes), baseline, year, year
        )
        assert len(problems) == 1, f"year {year} went undetected"
        # The finding has to carry the numbers; "feed looks small" is not
        # actionable at 3am.
        assert str(sizes[year]) in problems[0]
        assert str(baseline[year]) in problems[0]


def test_the_floor_has_headroom_on_both_sides():
    """The floor must sit clear of both populations, not just separate them.

    Healthy: 321 bytes/record at the worst. Truncated: 2.099 at the best.
    A floor anywhere in between works; the point of asserting it is that a
    future edit cannot quietly slide it into either population.
    """
    worst_healthy = min(s / c for s, c in HEALTHY.values())
    best_truncated = max(s / c for s, c in TRUNCATED.values())

    assert best_truncated < check_feeds.MIN_GZ_BYTES_PER_RECORD < worst_healthy
    assert check_feeds.MIN_GZ_BYTES_PER_RECORD / best_truncated > 10
    assert worst_healthy / check_feeds.MIN_GZ_BYTES_PER_RECORD > 5


def test_2002_is_sized_against_its_aggregated_years():
    """nvdcve-2.0-2002.json.gz holds 1999-2002. Sizing it against
    baseline[2002] alone would expect 2393 records instead of 6771, inflating
    its bytes/record by 2.8x and blinding the check to real truncation."""
    baseline = {1999: 1579, 2000: 1243, 2001: 1556, 2002: 2393}

    assert nvd.expected_feed_size(2002, baseline) == 6771

    # A 2002 feed truncated to the size of the real 2022 one must be caught,
    # which it would not be if the expectation were only 2393 records.
    problems, _ = check_feeds.check_year_feeds(
        _fake_crawler({2002: 3454}), baseline, 2002, 2002
    )
    assert len(problems) == 1


def test_an_unreachable_feed_is_a_note_not_a_finding():
    """NIST being down is the scraper's problem to ride out. This watchdog
    exists for feeds that are served and wrong, so it must not cry wolf."""

    class DeadSession:
        headers: dict = {}

        def head(self, url, **kwargs):
            raise check_feeds.requests.ConnectionError("refused")

    crawler = nvd.Crawler(session=DeadSession(), user_agents=["ua"])
    problems, notes = check_feeds.check_year_feeds(crawler, {2022: 27531}, 2022, 2022)

    assert problems == []
    assert any("size unknown" in n for n in notes)


def test_a_year_without_a_baseline_is_skipped():
    problems, notes = check_feeds.check_year_feeds(
        _fake_crawler({}), {2022: 27531}, 2099, 2099
    )

    assert problems == []
    assert any("no baseline" in n for n in notes)


def test_main_exits_2_when_the_baseline_is_unreadable(monkeypatch):
    def boom(url):
        raise check_feeds.requests.RequestException("timeout")

    monkeypatch.setattr(check_feeds, "fetch_baseline_year_counts", boom)
    assert check_feeds.main([]) == 2


def test_main_exits_2_on_a_baseline_with_no_year_counts(monkeypatch):
    monkeypatch.setattr(check_feeds, "fetch_baseline_year_counts", lambda url: {})
    assert check_feeds.main([]) == 2


def test_main_reports_the_outage_and_exits_1(monkeypatch):
    baseline = {y: c for y, (_, c) in TRUNCATED.items()}
    monkeypatch.setattr(check_feeds, "fetch_baseline_year_counts", lambda url: baseline)
    monkeypatch.setattr(
        check_feeds,
        "check_year_feeds",
        lambda *a, **k: (["year 2022 feed is 3454 gzipped bytes"], []),
    )
    monkeypatch.setattr(check_feeds, "check_modified_feed", lambda c: ([], []))

    assert check_feeds.main([]) == 1


def test_main_is_green_when_upstream_is_healthy(monkeypatch):
    monkeypatch.setattr(
        check_feeds, "fetch_baseline_year_counts", lambda url: {2024: 39227}
    )
    monkeypatch.setattr(check_feeds, "check_year_feeds", lambda *a, **k: ([], ["ok"]))
    monkeypatch.setattr(check_feeds, "check_modified_feed", lambda c: ([], ["ok"]))

    assert check_feeds.main([]) == 0


def test_modified_feed_truncation_is_a_finding():
    """The modified feed is the leading edge, so a truncated copy ages the
    snapshot without shrinking it -- the one shortfall the publish gates can
    miss. It is checked exactly, against its own envelope."""
    import gzip
    import io
    import json

    payload = {
        "resultsPerPage": 7842,
        "totalResults": 7842,
        "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i:04d}"}} for i in range(551)],
    }
    body = io.BytesIO()
    with gzip.GzipFile(fileobj=body, mode="wb") as gz:
        gz.write(json.dumps(payload).encode())
    raw = io.BytesIO(body.getvalue())
    raw.decode_content = False

    class Resp:
        status_code = 200
        headers = {"Content-Type": "application/gzip"}

        def __init__(self):
            self.raw = raw

        def raise_for_status(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    class Session:
        headers: dict = {}

        def get(self, url, **kwargs):
            return Resp()

    crawler = nvd.Crawler(session=Session(), user_agents=["ua"])
    problems, _ = check_feeds.check_modified_feed(crawler)

    assert len(problems) == 1
    assert "7842" in problems[0] and "551" in problems[0]


def test_a_truncated_gzip_stream_is_a_note_not_a_finding():
    """A gzip stream cut short raises EOFError, which is not an OSError. On
    2026-09-23 that escaped, crashed the check with exit 1, and opened an
    upstream-feeds issue for what was only a short read."""
    import gzip
    import io
    import json

    body = io.BytesIO()
    with gzip.GzipFile(fileobj=body, mode="wb") as gz:
        gz.write(json.dumps({"vulnerabilities": []}).encode())
    raw = io.BytesIO(body.getvalue()[:-12])
    raw.decode_content = False

    class Resp:
        status_code = 200
        headers = {"Content-Type": "application/gzip"}

        def __init__(self):
            self.raw = raw

        def raise_for_status(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    class Session:
        headers: dict = {}

        def get(self, url, **kwargs):
            return Resp()

    crawler = nvd.Crawler(session=Session(), user_agents=["ua"])
    problems, notes = check_feeds.check_modified_feed(crawler)

    assert problems == []
    assert any("EOFError" in n for n in notes)


def test_main_exits_2_when_the_check_itself_crashes(monkeypatch):
    """A crash would otherwise exit 1 and be filed as an upstream outage."""
    monkeypatch.setattr(check_feeds, "fetch_baseline_year_counts", lambda url: {2026: 1})
    monkeypatch.setattr(check_feeds.nvd, "build_crawler", lambda key: object())

    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(check_feeds, "check_year_feeds", boom)

    assert check_feeds.main([]) == 2
