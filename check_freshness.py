"""Scheduled watchdog for how current the published mirror is.

check_mirror.py asks whether the snapshot went backwards; this asks whether
it has stopped moving forwards. They fail differently and want different
responses, so they are separate scripts and separate issues.

The signal is the manifest's `data_current_through`: the UTC instant up to
which every NVD change is in the snapshot. Not `last_run_iso` -- a run can
publish on time and still carry old data, which is exactly what happens when
the API delta fails and the run falls back to the modified feed, whose newest
change can be up to six hours old overnight.

The default threshold sits between the two regimes. With the delta working
the lag is the run cadence plus one run, under about an hour. Feed-only, it
runs 1-6 hours. So 3 hours stays quiet through a single failed delta in
daytime, and fires when the delta has been failing for a while, when NIST
stops rebuilding the modified feed on top of that, or when publishing has
stopped altogether.

Usage:
    python3 check_freshness.py [--url URL] [--max-lag-hours N]

Exit codes: 0 fresh, 1 stale, 2 could not evaluate.
"""

import argparse
import os
import sys
from datetime import datetime, timezone

import requests

DEFAULT_URL = os.environ.get(
    "MIRROR_METADATA_URL", "https://nvd.handsonhacking.org/metadata.json"
)
DEFAULT_MAX_LAG_HOURS = 3.0


def fetch_metadata(url: str) -> dict:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("metadata is not a JSON object")
    return data


def data_current_through(meta: dict) -> datetime:
    """The manifest's freshness instant, as aware UTC. Raises ValueError."""
    raw = meta.get("data_current_through")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("metadata has no data_current_through")
    parsed = datetime.fromisoformat(raw.strip())
    if parsed.tzinfo is None:
        raise ValueError(f"data_current_through {raw!r} has no UTC offset")
    return parsed.astimezone(timezone.utc)


def lag_hours(meta: dict, now: datetime) -> float:
    return (now - data_current_through(meta)).total_seconds() / 3600


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--max-lag-hours", type=float, default=DEFAULT_MAX_LAG_HOURS)
    args = parser.parse_args(argv)
    now = now or datetime.now(timezone.utc)

    try:
        meta = fetch_metadata(args.url)
        lag = lag_hours(meta, now)
    except (requests.RequestException, ValueError) as exc:
        print(f"could not evaluate {args.url}: {exc}", file=sys.stderr)
        return 2

    delta = meta.get("api_delta") or {}
    summary = (
        f"data_current_through={meta.get('data_current_through')} "
        f"lag={lag:.2f}h last_run_iso={meta.get('last_run_iso')} "
        f"api_delta={delta.get('status', 'unknown')}"
    )
    if lag > args.max_lag_hours:
        print(f"STALE ({lag:.2f}h > {args.max_lag_hours:g}h): {summary}", file=sys.stderr)
        if delta.get("status") == "failed":
            print(f"  api_delta error: {delta.get('error')}", file=sys.stderr)
        return 1

    print(f"mirror fresh: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
