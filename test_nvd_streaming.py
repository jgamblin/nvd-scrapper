"""Smoke test for the streaming writer in nvd.py.

This test exercises the JSON-array streaming logic without hitting the
real NVD API. It feeds a fake page iterator into `write_stream()` and
asserts the output is valid JSON containing every item.
"""

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

    # Neither call site overrides the shared defaults.
    assert all(args == () and kwargs == {} for _, args, kwargs in seen)
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
