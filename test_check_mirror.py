"""Tests for the published-snapshot watchdog.

The numbers come from the production incident of 2026-08-06, where the
scraper published 373,140 CVEs after having already published 373,525.
"""

import json
import os
import tempfile

import check_mirror

GOOD = {
    "cve_count": 373525,
    "last_run_iso": "2026-08-06T01:29:00+00:00",
    "degraded": False,
    "year_counts": {"1999": 1579, "2025": 45138, "2026": 43280},
}
REGRESSED = {
    "cve_count": 373140,
    "last_run_iso": "2026-08-06T05:50:00+00:00",
    "degraded": False,
    "year_counts": {"1999": 1579, "2025": 45138, "2026": 42895},
}


def test_compare_is_quiet_on_a_healthy_snapshot():
    highwater = check_mirror.update_highwater(GOOD, {})
    assert check_mirror.compare(GOOD, highwater, allowance=25) == []


def test_compare_catches_the_real_regression():
    highwater = check_mirror.update_highwater(GOOD, {})
    problems = check_mirror.compare(REGRESSED, highwater, allowance=25)

    assert any("cve_count" in p for p in problems)
    assert any("year 2026" in p for p in problems)


def test_regression_stays_visible_across_later_runs():
    # High-water marks only rise, so a second bad snapshot is still flagged
    # rather than being normalised against the first one.
    highwater = check_mirror.update_highwater(GOOD, {})
    highwater = check_mirror.update_highwater(REGRESSED, highwater)

    assert highwater["cve_count"] == 373525
    assert check_mirror.compare(REGRESSED, highwater, allowance=25) != []


def test_compare_flags_a_degraded_snapshot():
    meta = dict(GOOD, degraded=True, years_via_api=[2023])
    problems = check_mirror.compare(meta, {}, allowance=25)

    assert any("degraded" in p for p in problems)


def test_compare_tolerates_reject_sized_movement():
    meta = dict(GOOD, cve_count=GOOD["cve_count"] - 3)
    meta["year_counts"] = dict(GOOD["year_counts"], **{"2026": 43277})
    highwater = check_mirror.update_highwater(GOOD, {})

    assert check_mirror.compare(meta, highwater, allowance=25) == []


def test_update_highwater_keeps_years_the_new_snapshot_omits():
    highwater = check_mirror.update_highwater(GOOD, {})
    thin = {"cve_count": 1, "year_counts": {"2026": 1}}
    highwater = check_mirror.update_highwater(thin, highwater)

    assert highwater["year_counts"]["1999"] == 1579
    assert check_mirror.compare(thin, highwater, allowance=25) != []


def test_main_reports_regression_and_persists_state(monkeypatch):
    responses = iter([GOOD, REGRESSED])
    monkeypatch.setattr(check_mirror, "fetch_metadata", lambda url: next(responses))

    with tempfile.TemporaryDirectory() as tmp:
        state = os.path.join(tmp, "state.json")
        assert check_mirror.main(["--state", state]) == 0
        assert check_mirror.main(["--state", state]) == 1

        with open(state) as f:
            saved = json.load(f)

    assert saved["highwater"]["cve_count"] == 373525
    assert saved["last_seen"]["cve_count"] == 373140


def test_main_exits_2_when_the_mirror_is_unreachable(monkeypatch):
    def boom(url):
        raise check_mirror.requests.RequestException("timeout")

    monkeypatch.setattr(check_mirror, "fetch_metadata", boom)
    with tempfile.TemporaryDirectory() as tmp:
        assert check_mirror.main(["--state", os.path.join(tmp, "state.json")]) == 2
