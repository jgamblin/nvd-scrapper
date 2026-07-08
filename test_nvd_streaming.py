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
