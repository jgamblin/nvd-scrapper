"""Tests for the mirror freshness watchdog.

The healthy manifest is the live one from 2026-10-05's first run with the API
delta; the stale case is the same morning without it, when the modified feed
sat on one build from 01:00 to 06:00 ET.
"""

from datetime import datetime, timezone

import check_freshness

NOW = datetime(2026, 10, 5, 14, 0, tzinfo=timezone.utc)
FRESH = {
    "last_run_iso": "2026-10-05T13:48:31.721445+00:00",
    "data_current_through": "2026-10-05T13:38:37.950977+00:00",
    "api_delta": {"status": "ok"},
}
FEED_ONLY_OVERNIGHT = {
    # Published on time, but the delta failed and the modified feed's newest
    # change was hours old: last_run_iso alone would call this healthy.
    "last_run_iso": "2026-10-05T13:48:31+00:00",
    "data_current_through": "2026-10-05T09:17:13.887000+00:00",
    "api_delta": {"status": "failed", "error": "API delta offset=0: out of time"},
}


def _serve(monkeypatch, meta):
    monkeypatch.setattr(check_freshness, "fetch_metadata", lambda url: meta)


def test_a_working_delta_is_fresh(monkeypatch, capsys):
    _serve(monkeypatch, FRESH)

    assert check_freshness.main([], now=NOW) == 0
    assert "api_delta=ok" in capsys.readouterr().out


def test_stale_data_is_caught_even_when_the_run_was_on_time(monkeypatch, capsys):
    _serve(monkeypatch, FEED_ONLY_OVERNIGHT)

    assert check_freshness.main([], now=NOW) == 1
    err = capsys.readouterr().err
    assert "STALE" in err
    assert "out of time" in err  # says why, when the delta is the cause


def test_one_failed_delta_by_day_stays_quiet(monkeypatch):
    # Daytime the modified feed rebuilds every 2h, so feed-only data is at
    # most ~2h45m old: under the default threshold.
    meta = dict(FEED_ONLY_OVERNIGHT, data_current_through="2026-10-05T11:20:00+00:00")
    _serve(monkeypatch, meta)

    assert check_freshness.main([], now=NOW) == 0


def test_threshold_is_configurable(monkeypatch):
    _serve(monkeypatch, FRESH)

    assert check_freshness.main(["--max-lag-hours", "0.1"], now=NOW) == 1


def test_a_manifest_without_the_field_cannot_be_evaluated(monkeypatch):
    _serve(monkeypatch, {"last_run_iso": "2026-10-05T13:48:31+00:00"})

    assert check_freshness.main([], now=NOW) == 2


def test_a_naive_timestamp_is_refused_rather_than_guessed(monkeypatch):
    # The feed envelope's naive timestamps turned out to be US Eastern, not
    # UTC. Never assume a zone again.
    _serve(monkeypatch, dict(FRESH, data_current_through="2026-10-05T13:38:37"))

    assert check_freshness.main([], now=NOW) == 2


def test_an_unreachable_mirror_exits_2(monkeypatch):
    def boom(url):
        raise check_freshness.requests.RequestException("timeout")

    monkeypatch.setattr(check_freshness, "fetch_metadata", boom)

    assert check_freshness.main([], now=NOW) == 2
