"""Smoke test for the streaming writer in nvd.py.

This test exercises the JSON-array streaming logic without hitting the
real NVD API. It feeds a fake page iterator into `write_stream()` and
asserts the output is valid JSON containing every item.
"""

import gzip
import io
import json
import os
import tempfile
from unittest.mock import Mock

import nvd


def test_write_stream_produces_valid_json_array():
    fake_pages = [
        [{"cve": {"id": "CVE-2025-0001"}}, {"cve": {"id": "CVE-2025-0002"}}],
        [{"cve": {"id": "CVE-2025-0003"}}],
        [],  # Empty final page (mimics exhausted pagination)
    ]

    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "nvd.json")
        count = nvd.write_stream(iter(fake_pages), out_path)

        assert count == 3

        with open(out_path) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 3
        assert data[0]["cve"]["id"] == "CVE-2025-0001"
        assert data[2]["cve"]["id"] == "CVE-2025-0003"


def test_write_stream_handles_empty_input():
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "nvd.json")
        count = nvd.write_stream(iter([]), out_path)

        assert count == 0

        with open(out_path) as f:
            data = json.load(f)

        assert data == []


def test_modified_feed_url_points_to_static_modified_snapshot():
    urls = nvd.modified_feed_urls()

    assert len(urls) >= 1
    assert all(url.endswith("/nvdcve-2.0-modified.json.gz") for url in urls)


def test_fetch_modified_overrides_builds_cve_id_map(monkeypatch):
    monkeypatch.setattr(
        nvd,
        "fetch_modified_feed",
        lambda session: [
            {"cve": {"id": "CVE-2025-0001"}},
            {"cve": {"id": "CVE-2025-0001", "lastModified": "new"}},
            {"cve": {"id": "CVE-2025-0002"}},
        ],
    )

    overrides = nvd.fetch_modified_overrides(Mock())

    assert set(overrides) == {"CVE-2025-0001", "CVE-2025-0002"}
    assert overrides["CVE-2025-0001"]["cve"]["lastModified"] == "new"


def test_iter_all_pages_replaces_overridden_cves(monkeypatch):
    monkeypatch.setattr(
        nvd,
        "fetch_feed",
        lambda session, year: [
            {"cve": {"id": f"CVE-{year}-0001"}},
            {"cve": {"id": f"CVE-{year}-0002"}},
        ],
    )

    overrides = {
        "CVE-2002-0002": {"cve": {"id": "CVE-2002-0002", "lastModified": "new"}},
        "CVE-2025-9999": {"cve": {"id": "CVE-2025-9999"}},
    }

    pages = list(nvd.iter_all_pages(Mock(), 2002, 2003, overrides))

    assert pages[0] == [{"cve": {"id": "CVE-2002-0001"}}]
    assert pages[1] == [
        {"cve": {"id": "CVE-2003-0001"}},
        {"cve": {"id": "CVE-2003-0002"}},
    ]
    assert pages[2] == list(overrides.values())


def test_year_from_cve_id():
    assert nvd.year_from_cve_id("CVE-1999-0001") == 1999
    assert nvd.year_from_cve_id("CVE-2026-12345") == 2026
    assert nvd.year_from_cve_id("garbage") is None
    assert nvd.year_from_cve_id("CVE-notayear-0001") is None


def test_write_stream_populates_year_counts():
    fake_pages = [
        [{"cve": {"id": "CVE-1999-0001"}}, {"cve": {"id": "CVE-1999-0002"}}],
        [{"cve": {"id": "CVE-2000-0001"}}, {"cve": {"id": "CVE-1999-0001"}}],  # dup
    ]

    with tempfile.TemporaryDirectory() as tmp:
        year_counts: dict[int, int] = {}
        count = nvd.write_stream(iter(fake_pages), os.path.join(tmp, "nvd.json"), year_counts)

    # Dedup means the repeated CVE-1999-0001 is counted once.
    assert count == 3
    assert year_counts == {1999: 2, 2000: 1}


def _full_year_map(current_year=2026, per_year=1000):
    """A healthy, gap-free map of CVE-ID-year -> count for 1999..current_year."""
    return {year: per_year for year in range(1999, current_year + 1)}


def test_verify_year_coverage_passes_on_healthy_full_range():
    counts = _full_year_map()
    assert nvd.verify_year_coverage(counts, baseline={}, current_year=2026) == []


def test_verify_year_coverage_flags_empty_historical_year():
    # 1999 present but zero, 2001 dropped from the map entirely -- both are
    # complete historical years (current_year=2026) and must be non-empty.
    counts = _full_year_map()
    counts[1999] = 0
    del counts[2001]
    problems = nvd.verify_year_coverage(counts, baseline={}, current_year=2026)

    assert any("1999" in p and "empty" in p for p in problems)
    assert any("2001" in p and "empty" in p for p in problems)


def test_verify_year_coverage_does_not_flag_current_year_empty():
    # The still-accumulating current year is allowed to be empty (e.g. Jan 1).
    counts = _full_year_map()
    counts[2026] = 0
    assert nvd.verify_year_coverage(counts, baseline={}, current_year=2026) == []


def test_verify_year_coverage_flags_shrink_beyond_tolerance():
    counts = _full_year_map()
    baseline = dict(counts)
    # 1999 loses ~75% of its records (mimicking the real outage); rest steady.
    baseline[1999] = 1579
    counts[1999] = 400
    problems = nvd.verify_year_coverage(counts, baseline, current_year=2026)

    assert any("1999" in p and "shrank" in p for p in problems)
    assert not any(p.startswith("year 2000") for p in problems)


def test_verify_year_coverage_allows_growth_and_small_noise():
    counts = _full_year_map()
    baseline = dict(counts)
    baseline[1999], counts[1999] = 1579, 1580  # grew by 1
    baseline[2000], counts[2000] = 1243, 1241  # dropped by 2 (within MIN_ABS)
    baseline[2025], counts[2025] = 40000, 41000  # grew
    problems = nvd.verify_year_coverage(counts, baseline, current_year=2026)

    assert problems == []


def test_verify_year_coverage_empty_input_is_a_problem():
    assert nvd.verify_year_coverage({}, {}, 2026) == ["no per-year counts were computed"]


# --- non-regression guard -------------------------------------------------


def test_verify_year_coverage_flags_small_absolute_shrink():
    # The regression that actually reached consumers: ~385 CVEs missing from
    # the current year. Under the old 2% tolerance (~800 CVEs on a big year)
    # this passed silently.
    counts = _full_year_map(per_year=40000)
    baseline = dict(counts)
    counts[2026] = baseline[2026] - 385
    problems = nvd.verify_year_coverage(counts, baseline, current_year=2026)

    assert any("2026" in p and "shrank" in p for p in problems)


def test_verify_year_coverage_allows_reject_sized_shrink():
    counts = _full_year_map(per_year=40000)
    baseline = dict(counts)
    counts[2020] = baseline[2020] - nvd.YEAR_DROP_ALLOWANCE
    counts[2026] = baseline[2026] - nvd.CURRENT_YEAR_DROP_ALLOWANCE
    assert nvd.verify_year_coverage(counts, baseline, current_year=2026) == []


def test_verify_year_coverage_catches_year_vanishing_off_the_low_end():
    # 1999 disappears entirely. Deriving the floor's range from year_counts
    # alone made this invisible: the range simply started at 2000 instead.
    counts = _full_year_map()
    baseline = dict(counts)
    del counts[1999]
    problems = nvd.verify_year_coverage(counts, baseline, current_year=2026)

    assert any("1999" in p and "empty" in p for p in problems)


def test_verify_year_coverage_flags_total_regression():
    # Every year is individually within allowance, but the sum is not.
    counts = _full_year_map(per_year=40000)
    baseline = dict(counts)
    for year in counts:
        counts[year] -= 4
    problems = nvd.verify_year_coverage(
        counts,
        baseline,
        current_year=2026,
        cve_count=sum(counts.values()),
        baseline_total=sum(baseline.values()),
    )

    assert not any("shrank from" in p and p.startswith("year") for p in problems)
    assert any(p.startswith("corpus total shrank") for p in problems)


def test_verify_year_coverage_passes_on_growth_with_totals():
    counts = _full_year_map(per_year=40000)
    baseline = dict(counts)
    counts[2026] += 300
    assert (
        nvd.verify_year_coverage(
            counts,
            baseline,
            current_year=2026,
            cve_count=sum(counts.values()),
            baseline_total=sum(baseline.values()),
        )
        == []
    )


# --- baseline handling ----------------------------------------------------


def test_fetch_baseline_metadata_returns_none_when_unreachable(monkeypatch):
    def boom(*args, **kwargs):
        raise nvd.requests.RequestException("connection reset")

    monkeypatch.setattr(nvd.requests, "get", boom)
    assert nvd.fetch_baseline_metadata("https://example.invalid/metadata.json") is None


def test_baseline_year_counts_parses_string_keys():
    assert nvd.baseline_year_counts({"year_counts": {"1999": "1579", "2026": 43280}}) == {
        1999: 1579,
        2026: 43280,
    }


def test_baseline_year_counts_tolerates_missing_and_malformed():
    assert nvd.baseline_year_counts({}) == {}
    assert nvd.baseline_year_counts({"year_counts": {"nope": "nope"}}) == {}


# --- API fallback is not a substitute for a year feed ---------------------


def test_fetch_feed_raises_when_api_fallback_disabled(monkeypatch):
    monkeypatch.setattr(
        nvd,
        "_load_gzip_json_from_urls",
        Mock(side_effect=RuntimeError("feed 502")),
    )
    api = Mock()
    monkeypatch.setattr(nvd, "fetch_year_via_api", api)

    crawler = nvd.build_crawler("", allow_api_fallback=False)
    try:
        nvd.fetch_feed(crawler, 2023)
    except RuntimeError as exc:
        assert "publication date" in str(exc)
    else:
        raise AssertionError("expected fetch_feed to raise")

    api.assert_not_called()
    assert crawler.years_via_api == []


def test_fetch_feed_still_falls_back_when_allowed(monkeypatch):
    monkeypatch.setattr(
        nvd,
        "_load_gzip_json_from_urls",
        Mock(side_effect=RuntimeError("feed 502")),
    )
    monkeypatch.setattr(nvd, "fetch_year_via_api", lambda crawler, year: [{"x": year}])

    crawler = nvd.build_crawler("", allow_api_fallback=True)
    assert nvd.fetch_feed(crawler, 2023) == [{"x": 2023}]
    assert crawler.years_via_api == [2023]


def test_year_and_modified_feeds_share_one_retry_profile(monkeypatch):
    """Both fail the same way (502 on static, 404 on the primary) in the same
    NIST regeneration window, and both are fatal, so neither may be less
    patient than the other."""
    seen = []

    def fake_load(crawler, urls, label, *args, **kwargs):
        seen.append((label, args, kwargs))
        return {"vulnerabilities": []}

    monkeypatch.setattr(nvd, "_load_gzip_json_from_urls", fake_load)
    nvd.fetch_modified_feed(Mock())
    nvd.fetch_feed(nvd.build_crawler(""), 2023)

    # Neither call site overrides the shared retry profile. min_records and
    # baseline_built_at are not part of that profile -- they are the per-feed
    # sanity floor and freshness reference -- so they are exempt here rather
    # than asserted absent, which would forbid those checks outright.
    retry_knobs = {"max_attempts", "base_backoff", "max_backoff"}
    assert all(args == () for _, args, _ in seen)
    assert all(not (retry_knobs & set(kwargs)) for _, _, kwargs in seen)
    assert [label for label, _, _ in seen] == ["modified feed", "feed year=2023"]


def test_retry_delay_backs_off_exponentially_and_caps():
    exc = RuntimeError("nope")
    delays = [nvd._retry_delay_seconds(exc, a, 15, 240) for a in range(1, 7)]
    assert delays == [15, 30, 60, 120, 240, 240]


def test_feed_retry_profile_outlasts_a_regeneration_window():
    """The observed failure had 11 seconds of patience and gave up inside the
    window; the same feed served fine on the next run. Budget minutes."""
    exc = RuntimeError("nope")
    ladder = [
        nvd._retry_delay_seconds(
            exc, a, nvd.FEED_BACKOFF_SECONDS, nvd.FEED_MAX_BACKOFF_SECONDS
        )
        for a in range(1, nvd.MAX_FEED_RETRIES)
    ]
    assert sum(ladder) >= 300


# --- manifest fields ------------------------------------------------------


def test_write_metadata_includes_manifest_fields():
    import datetime as _dt

    with tempfile.TemporaryDirectory() as tmp:
        data_path = os.path.join(tmp, "nvd.json")
        with open(data_path, "w") as f:
            f.write('[{"cve":{"id":"CVE-1999-0001"}}]')

        expected_bytes = os.path.getsize(data_path)
        expected_sha = nvd.sha256_file(data_path)

        meta_path = os.path.join(tmp, "metadata.json")
        now = _dt.datetime(2026, 8, 17, tzinfo=_dt.timezone.utc)
        nvd.write_metadata(
            meta_path,
            1,
            now,
            now,
            [],
            1,
            {1999: 1},
            data_bytes=expected_bytes,
            data_sha256=expected_sha,
        )

        with open(meta_path) as f:
            meta = json.load(f)

    assert meta["schema_version"] == 2
    assert meta["data_object_key"] == "nvd.json"
    assert meta["bytes"] == expected_bytes
    assert meta["sha256"] == expected_sha
    assert len(meta["sha256"]) == 64
    assert meta["year_counts"] == {"1999": 1}


def test_sha256_file_matches_hashlib():
    import hashlib

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "blob")
        payload = b"x" * (3 * 1024 * 1024)
        with open(path, "wb") as f:
            f.write(payload)
        # Chunk size below the payload size to exercise the streaming loop.
        assert nvd.sha256_file(path, chunk_size=1024) == hashlib.sha256(payload).hexdigest()


def test_guard_blocks_the_2026_08_14_regression():
    """Replay of a real published regression.

    Run 31759152941 published 377,150 CVEs at 01:33 UTC; run 31770594445
    published 376,849 at 05:19 with an older modified-feed overlay (6,869
    records instead of 7,205). The year-feed backbone was byte-identical
    across both, so the entire 301-CVE shortfall sat in the leading edge.
    The old 2% tolerance passed it and consumers saw the dataset move
    backwards.
    """
    # Year-feed backbone, identical in both runs (from the run logs).
    backbone = {
        1999: 1579, 2000: 1243, 2001: 1556, 2002: 2393, 2003: 1555, 2004: 2707,
        2005: 4770, 2006: 7145, 2007: 6580, 2008: 7179, 2009: 5054, 2010: 5249,
        2011: 4899, 2012: 5939, 2013: 6830, 2014: 9002, 2015: 8779, 2016: 10647,
        2017: 17104, 2018: 17817, 2019: 17619, 2020: 21069, 2021: 23445,
        2022: 27525, 2023: 31244, 2024: 39218, 2025: 45138,
    }
    baseline = {**backbone, 2026: 377150 - sum(backbone.values())}
    counts = {**backbone, 2026: 376849 - sum(backbone.values())}

    assert sum(baseline.values()) - sum(counts.values()) == 301

    problems = nvd.verify_year_coverage(
        counts,
        baseline,
        current_year=2026,
        cve_count=376849,
        baseline_total=377150,
    )

    assert any("2026" in p and "shrank" in p for p in problems)
    assert any(p.startswith("corpus total shrank") for p in problems)


# --- feed truncation detection --------------------------------------------
#
# The 2026-08-27 outage: NIST served year files that were truncated at the
# source with no transport-level symptom. HTTP 200, a complete CRC-valid gzip
# stream, well-formed JSON, and a truthful envelope above a near-empty array.
# Captured from the live feeds that day:
#
#   year  resultsPerPage  vulnerabilities
#   2015            8779                2
#   2019           17623                1
#   2021           23452                1
#   2022           27531                1
#   2023           31267               18
#   2025           45200                2
#   modified        7842              551
#
# Healthy files on the same day satisfied resultsPerPage == len(...) exactly
# (2024: 39227, 2020: 21071, 2002: 6771).


def _envelope(promised, actual, year=2022):
    return {
        "resultsPerPage": promised,
        "startIndex": 0,
        "totalResults": promised,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {"cve": {"id": f"CVE-{year}-{i:04d}"}} for i in range(actual)
        ],
    }


def testassert_feed_intact_accepts_a_healthy_feed():
    # 2024 as served on the day of the outage.
    nvd.assert_feed_intact(_envelope(39227, 39227, 2024))


def testassert_feed_intact_rejects_the_2026_08_27_truncated_feeds():
    for year, promised, actual in [
        (2015, 8779, 2),
        (2019, 17623, 1),
        (2021, 23452, 1),
        (2022, 27531, 1),
        (2023, 31267, 18),
        (2025, 45200, 2),
    ]:
        try:
            nvd.assert_feed_intact(_envelope(promised, actual, year))
        except nvd.TruncatedFeedError as exc:
            # The message has to name the shortfall; reading "size=1" off the
            # old log told you nothing.
            assert str(promised) in str(exc)
            assert str(actual) in str(exc)
        else:
            raise AssertionError(f"year {year} truncation went undetected")


def testassert_feed_intact_catches_the_truncated_modified_feed():
    try:
        nvd.assert_feed_intact(_envelope(7842, 551))
    except nvd.TruncatedFeedError:
        pass
    else:
        raise AssertionError("truncated modified feed went undetected")


def test_truncated_feed_error_is_retried_as_a_fetch_failure():
    """A truncated feed must reach the retry ladder, not the caller.

    TruncatedFeedError subclasses ValueError precisely so the existing except
    clause in the fetch loop catches it. If that inheritance is ever dropped
    the exception escapes the loop uncaught and the run dies with a traceback
    instead of retrying and failing cleanly.
    """
    assert issubclass(nvd.TruncatedFeedError, ValueError)


def testassert_feed_intact_tolerates_pagination():
    """Compared against resultsPerPage, not totalResults, so a paginated year
    file would not fail every fetch."""
    payload = _envelope(500, 500)
    payload["totalResults"] = 27531
    nvd.assert_feed_intact(payload)


def testassert_feed_intact_tolerates_a_missing_envelope_count():
    nvd.assert_feed_intact({"vulnerabilities": []})


def testassert_feed_intact_applies_the_baseline_floor():
    """An envelope-consistent but grossly short feed -- the same failure with a
    header that has caught up -- is invisible to the envelope check."""
    payload = _envelope(3, 3)
    nvd.assert_feed_intact(payload)  # envelope agrees
    try:
        nvd.assert_feed_intact(payload, min_records=13765)
    except nvd.TruncatedFeedError as exc:
        assert "13765" in str(exc)
    else:
        raise AssertionError("baseline floor did not fire")


def test_expected_feed_size_folds_earlier_years_into_the_2002_file():
    """nvdcve-2.0-2002.json.gz holds every CVE-ID year up to 2002 (verified
    2026-08-27: 6771 records spanning 1999-2002). Reading baseline[2002] alone
    would set its floor at a third of the truth."""
    baseline = {1999: 1579, 2000: 1243, 2001: 1556, 2002: 2393, 2003: 1555}

    assert nvd.expected_feed_size(2002, baseline) == 6771
    assert nvd.expected_feed_size(2003, baseline) == 1555
    assert nvd.expected_feed_size(2099, baseline) is None
    assert nvd.expected_feed_size(2002, {}) is None


def test_feed_min_records_tolerates_ordinary_drift():
    """The 2020 feed served 21071 against a published baseline of 21074: a
    rejected CVE leaves the feed but stays in our snapshot. The floor must not
    fire on that -- the precise rule is verify_year_coverage()'s job."""
    floor = nvd.feed_min_records(2020, {2020: 21074})

    assert floor is not None and floor < 21071
    # But it must still catch the outage: 2020 serving a single record.
    assert floor > 1


def test_feed_min_records_is_none_without_a_baseline():
    assert nvd.feed_min_records(2022, {}) is None


def test_fetch_feed_passes_the_baseline_floor_to_the_loader():
    calls = {}

    def fake_load(crawler, urls, label, **kwargs):
        calls.update(kwargs)
        return _envelope(10, 10)

    crawler = nvd.build_crawler("", baseline_year_counts={2022: 27531})
    import unittest.mock

    with unittest.mock.patch.object(nvd, "_load_gzip_json_from_urls", fake_load):
        nvd.fetch_feed(crawler, 2022)

    assert calls["min_records"] == int(27531 * nvd.FEED_YEAR_MIN_RATIO)


def test_truncated_year_feed_is_fatal_when_api_fallback_is_disabled():
    """The whole point: a near-empty feed must abort the run at the year that
    caused it, naming it, rather than being counted as a successful fetch of
    one CVE and surfacing 25 feeds later as a 46.9% aggregate ratio."""
    import unittest.mock

    def always_truncated(crawler, urls, label, **kwargs):
        raise RuntimeError(
            f"Feed fetch failed for {label} after 6 attempts: {label}: envelope "
            f"promises 27531 records but the array holds 1"
        )

    crawler = nvd.build_crawler("", allow_api_fallback=False)
    with unittest.mock.patch.object(nvd, "_load_gzip_json_from_urls", always_truncated):
        try:
            nvd.fetch_feed(crawler, 2022)
        except RuntimeError as exc:
            assert "year=2022" in str(exc)
            assert "27531" in str(exc)  # the cause is chained into the message
        else:
            raise AssertionError("expected the truncated feed to be fatal")


# --- feed freshness -------------------------------------------------------
#
# The 2026-09-11 failure: run 34602304649 read 55,867 records from the 2026
# year feed -- exactly what that feed had served all the previous day --
# because a CDN edge replayed the day-old build. Unlike the 08-27 truncation
# it was a *complete* copy, just of the wrong day, so its envelope agreed with
# its contents and assert_feed_intact had nothing to catch. It was 394 records
# short, and only the coverage gate noticed, 32 minutes of scraping later.


class _FakeRaw(io.BytesIO):
    """BytesIO that tolerates the decode_content flag the loader sets."""

    decode_content = False


class _FakeResponse:
    def __init__(self, payload):
        self.status_code = 200
        self.headers = {"Content-Type": "application/gzip"}
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(json.dumps(payload).encode())
        self.raw = _FakeRaw(buf.getvalue())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        pass


class _FakeSession:
    """Serves a canned payload per URL and records what was asked for."""

    def __init__(self, by_url):
        self.by_url = by_url
        self.headers = {}
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        return _FakeResponse(self.by_url[url])


def _crawler_with(by_url, builds=None):
    crawler = nvd.Crawler(
        session=_FakeSession(by_url),
        user_agents=list(nvd.DEFAULT_USER_AGENTS),
        baseline_feed_timestamps=builds or {},
    )
    crawler.apply_user_agent()
    return crawler


def _built(timestamp):
    return nvd.feed_build_timestamp({"timestamp": timestamp})


def _dated_feed(timestamp, count, year=2026):
    """A feed that is internally consistent -- the point is the build date."""
    payload = _envelope(count, count, year=year)
    payload["timestamp"] = timestamp
    return payload


def test_feed_build_timestamp_parses_nist_format_as_utc():
    # NIST writes seven fractional digits and no offset; the field is UTC.
    built = nvd.feed_build_timestamp({"timestamp": "2026-09-11T03:00:01.8043137"})

    assert built is not None
    assert built.utcoffset().total_seconds() == 0
    assert (built.year, built.month, built.day, built.hour) == (2026, 9, 11, 3)


def test_feed_build_timestamp_returns_none_when_unusable():
    assert nvd.feed_build_timestamp({}) is None
    assert nvd.feed_build_timestamp({"timestamp": ""}) is None
    assert nvd.feed_build_timestamp({"timestamp": "not a date"}) is None
    assert nvd.feed_build_timestamp({"timestamp": 1757559601}) is None


def test_baseline_feed_timestamps_parses_and_tolerates_junk():
    parsed = nvd.baseline_feed_timestamps(
        {
            "feed_timestamps": {
                "2026": "2026-09-11T03:00:01.804313+00:00",
                "modified": "2026-09-11T13:00:00+00:00",
                "2025": "garbage",
            }
        }
    )

    assert set(parsed) == {"2026", "modified"}
    assert parsed["2026"] < parsed["modified"]
    assert nvd.baseline_feed_timestamps({}) == {}
    assert nvd.baseline_feed_timestamps({"feed_timestamps": "nope"}) == {}


def test_assert_feed_fresh_accepts_the_same_daily_build_again():
    """The reason this compares builds and not run clocks.

    NIST rebuilds a year file only when its contents change -- the 2003 feed
    served on 2026-09-11 was built on 2026-08-28 -- while this scraper runs
    every 3 hours regardless. The correct, current build is therefore almost
    always older than the run that last used it, and comparing against a run
    clock would reject every feed we fetch.
    """
    build = "2026-09-11T03:00:01.8043137"

    nvd.assert_feed_fresh({"timestamp": build}, _built(build))


def test_assert_feed_fresh_rejects_an_older_build_and_allows_a_newer_one():
    baseline = _built("2026-09-11T03:00:01")

    try:
        nvd.assert_feed_fresh({"timestamp": "2026-09-10T03:00:02"}, baseline)
    except nvd.StaleFeedError as exc:
        assert "rolled-back copy" in str(exc)
    else:
        raise AssertionError("expected a day-old build to be refused")

    nvd.assert_feed_fresh({"timestamp": "2026-09-12T03:00:00"}, baseline)


def test_assert_feed_fresh_is_inert_without_a_baseline_or_a_timestamp():
    # Bootstrap, and metadata predating feed_timestamps, must not block a run.
    nvd.assert_feed_fresh({"timestamp": "2020-01-01T00:00:00"}, None)
    nvd.assert_feed_fresh({}, _built("2026-09-11T03:00:01"))


def test_stale_feed_error_is_retried_as_a_fetch_failure():
    """Same contract as TruncatedFeedError: ValueError, so the fetch loop's
    existing except clause catches it and the stale copy gets the host
    failover instead of escaping as a traceback."""
    assert issubclass(nvd.StaleFeedError, ValueError)


def test_stale_feed_fails_over_to_the_other_host():
    """Replay of 2026-09-11, through the real fetch path."""
    stale, fresh = nvd.feed_urls_for_year(2026)
    crawler = _crawler_with(
        {
            stale: _dated_feed("2026-09-10T03:00:07.1", 55867),
            fresh: _dated_feed("2026-09-11T03:00:01.8043137", 56261),
        },
        {"2026": _built("2026-09-11T03:00:01.8043137")},
    )

    items = nvd.fetch_feed(crawler, 2026)

    assert len(items) == 56261
    # The stale host was tried first and skipped, not silently accepted.
    assert crawler.session.requested == [stale, fresh]
    # And the accepted build is what gets published for the next run to use.
    assert crawler.feed_timestamps["2026"].startswith("2026-09-11T03:00:01")
    assert crawler.years_via_api == []


def test_every_host_stale_is_a_failed_fetch_not_a_short_feed():
    urls = nvd.feed_urls_for_year(2026)
    crawler = _crawler_with({url: _dated_feed("2026-09-10T03:00:07.1", 55867) for url in urls})

    try:
        nvd._load_gzip_json_from_urls(
            crawler,
            urls,
            "feed year=2026",
            max_attempts=1,
            baseline_built_at=_built("2026-09-11T03:00:01"),
        )
    except RuntimeError as exc:
        assert "after 1 attempts" in str(exc)
        assert "rolled-back copy" in str(exc)  # the cause is chained in
    else:
        raise AssertionError("expected a stale feed to raise, not return short data")

    assert crawler.session.requested == urls


def test_modified_feed_is_freshness_checked_too():
    """The leading edge rebuilds every couple of hours, and it is the only
    source of every CVE published since the last year-feed rebuild, so a
    stale copy here is hundreds of CVEs off the top of the dataset."""
    stale, fresh = nvd.modified_feed_urls()
    crawler = _crawler_with(
        {
            stale: _dated_feed("2026-09-11T09:00:00", 6869),
            fresh: _dated_feed("2026-09-11T13:00:00", 7205),
        },
        {"modified": _built("2026-09-11T11:00:00")},
    )

    assert len(nvd.fetch_modified_feed(crawler)) == 7205
    assert crawler.feed_timestamps["modified"].startswith("2026-09-11T13:00:00")


def test_fetch_feed_passes_both_the_floor_and_the_freshness_reference():
    calls = {}

    def fake_load(crawler, urls, label, **kwargs):
        calls.update(kwargs)
        return _dated_feed("2026-09-11T03:00:01", 10)

    crawler = nvd.build_crawler(
        "",
        baseline_year_counts={2026: 56261},
        baseline_feed_timestamps={"2026": _built("2026-09-11T03:00:01")},
    )
    import unittest.mock

    with unittest.mock.patch.object(nvd, "_load_gzip_json_from_urls", fake_load):
        nvd.fetch_feed(crawler, 2026)

    assert calls["min_records"] == int(56261 * nvd.FEED_YEAR_MIN_RATIO)
    assert calls["baseline_built_at"] == _built("2026-09-11T03:00:01")


def test_write_metadata_publishes_the_feed_builds_it_consumed():
    import datetime as _dt

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "metadata.json")
        now = _dt.datetime(2026, 9, 11, tzinfo=_dt.timezone.utc)
        nvd.write_metadata(
            path, 10, now, now, [], 10, {2026: 10},
            feed_timestamps={
                "modified": "2026-09-11T13:00:00+00:00",
                "2026": "2026-09-11T03:00:01+00:00",
            },
        )

        with open(path) as f:
            meta = json.load(f)

    assert meta["feed_timestamps"]["2026"] == "2026-09-11T03:00:01+00:00"
    # Sorted, so a diff between two published manifests stays readable.
    assert list(meta["feed_timestamps"]) == ["2026", "modified"]
    # Purely additive: consumers pinned to v2 keep working.
    assert meta["schema_version"] == 2


def test_write_metadata_omits_feed_timestamps_gracefully():
    import datetime as _dt

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "metadata.json")
        now = _dt.datetime(2026, 9, 11, tzinfo=_dt.timezone.utc)
        nvd.write_metadata(path, 10, now, now, [], 10, {2026: 10})

        with open(path) as f:
            meta = json.load(f)

    assert meta["feed_timestamps"] == {}


def test_baseline_feed_timestamps_reach_the_crawler(monkeypatch):
    """End of the wire: what the published manifest says a run consumed is
    what the next run's freshness check compares against."""
    monkeypatch.delenv("NVD_SKIP_FEED_FRESHNESS", raising=False)
    monkeypatch.delenv("NVD_ALLOW_MISSING_BASELINE", raising=False)
    monkeypatch.setattr(
        nvd,
        "fetch_baseline_metadata",
        lambda *a, **k: {
            "cve_count": 389910,
            "year_counts": {"2026": 56261},
            "feed_timestamps": {"2026": "2026-09-11T03:00:01.804313+00:00"},
        },
    )
    seen = {}

    def capture(crawler, *args, **kwargs):
        seen["builds"] = crawler.baseline_feed_timestamps
        seen["counts"] = crawler.baseline_year_counts
        raise RuntimeError("stop here -- the wiring is what is under test")

    monkeypatch.setattr(nvd, "fetch_modified_overrides", capture)

    assert nvd.main() == 7  # modified-feed overlay unavailable
    assert set(seen["builds"]) == {"2026"}
    assert seen["builds"]["2026"].hour == 3
    assert seen["counts"] == {2026: 56261}


def test_feed_freshness_can_be_switched_off_without_losing_the_other_gates(monkeypatch):
    """The off switch exists for one scenario: NIST republishing a feed with
    an earlier timestamp, which would wedge every run. It must not take the
    per-year sanity floor or the coverage gate down with it."""
    monkeypatch.setenv("NVD_SKIP_FEED_FRESHNESS", "1")
    monkeypatch.delenv("NVD_ALLOW_MISSING_BASELINE", raising=False)
    baseline = {
        "cve_count": 389910,
        "year_counts": {"2026": 56261},
        "feed_timestamps": {"2026": "2026-09-11T03:00:01+00:00"},
    }
    monkeypatch.setattr(nvd, "fetch_baseline_metadata", lambda *a, **k: baseline)
    seen = {}

    def capture(crawler, *args, **kwargs):
        seen["builds"] = crawler.baseline_feed_timestamps
        seen["counts"] = crawler.baseline_year_counts
        raise RuntimeError("stop here")

    monkeypatch.setattr(nvd, "fetch_modified_overrides", capture)

    assert nvd.main() == 7
    assert seen["builds"] == {}
    # The counts baseline is untouched, so the floor and the gate still bite.
    assert seen["counts"] == {2026: 56261}
    assert nvd.baseline_year_counts(baseline) == {2026: 56261}


def test_missing_baseline_aborts_before_the_scrape(monkeypatch):
    """The baseline is read at the top of main() because both fetch-time
    checks need it -- the sanity floor and the freshness reference. That also
    means a run with no baseline costs seconds instead of failing after a
    half-hour scrape, so keep it that way."""
    for var in (
        "NVD_ALLOW_MISSING_BASELINE",
        "NVD_SKIP_FEED_FRESHNESS",
        "NVD_FEED_START_YEAR",
        "NVD_FEED_END_YEAR",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(nvd, "fetch_baseline_metadata", lambda *a, **k: None)

    def explode(*args, **kwargs):
        raise AssertionError("scraped before checking the baseline")

    monkeypatch.setattr(nvd, "fetch_modified_overrides", explode)
    monkeypatch.setattr(nvd, "write_stream", explode)

    assert nvd.main() == 8
