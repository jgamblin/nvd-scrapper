"""Scheduled watchdog for the published mirror.

Fetches https://nvd.handsonhacking.org/metadata.json (about 2 KB, not the
1.7 GB object) and fails if the snapshot has gone backwards against the best
values ever observed.

Watching Last-Modified and ETag for non-monotonic movement -- the obvious
check -- would have caught none of the regressions this repo has actually
shipped. In every case the object was freshly published with a correctly
advancing Last-Modified, and simply contained fewer CVEs than the object
before it. So the signal to watch is the content counts, and the high-water
marks below are what make a multi-run regression visible instead of only a
single-step one.

Usage:
    python3 check_mirror.py [--url URL] [--state PATH] [--allowance N]

Exit codes: 0 healthy, 1 regression detected, 2 the mirror could not be read.
"""

import argparse
import json
import os
import sys

import requests

DEFAULT_URL = os.environ.get(
    "MIRROR_METADATA_URL", "https://nvd.handsonhacking.org/metadata.json"
)
DEFAULT_STATE = os.environ.get("MIRROR_STATE_PATH", ".mirror-state.json")
# Genuine CVE rejections shrink a year by a handful of records a week, so a
# small allowance keeps the watchdog from crying wolf. Anything larger is the
# failure mode this exists to catch.
DEFAULT_ALLOWANCE = 25


def load_state(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(path: str, state: dict) -> None:
    with open(path, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def fetch_metadata(url: str) -> dict:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("metadata is not a JSON object")
    return data


def compare(meta: dict, highwater: dict, allowance: int) -> list[str]:
    """Return a list of regressions against the high-water marks."""
    problems = []

    if meta.get("degraded"):
        problems.append(
            f"snapshot is flagged degraded (years_via_api={meta.get('years_via_api')})"
        )

    count = meta.get("cve_count")
    best_count = highwater.get("cve_count")
    if isinstance(count, int) and isinstance(best_count, int):
        if count < best_count - allowance:
            problems.append(
                f"cve_count {count} is {best_count - count} below the high-water "
                f"mark {best_count}"
            )

    years = meta.get("year_counts") or {}
    best_years = highwater.get("year_counts") or {}
    for year, best in sorted(best_years.items()):
        now = years.get(year, 0)
        if now < best - allowance:
            problems.append(
                f"year {year} is {best - now} CVEs below its high-water mark "
                f"({now} vs {best})"
            )

    return problems


def update_highwater(meta: dict, highwater: dict) -> dict:
    """Raise the recorded maxima to include this observation."""
    updated = {
        "cve_count": max(
            meta.get("cve_count") or 0, highwater.get("cve_count") or 0
        ),
        "year_counts": dict(highwater.get("year_counts") or {}),
    }
    for year, count in (meta.get("year_counts") or {}).items():
        updated["year_counts"][year] = max(
            count, updated["year_counts"].get(year, 0)
        )
    return updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--state", default=DEFAULT_STATE)
    parser.add_argument("--allowance", type=int, default=DEFAULT_ALLOWANCE)
    args = parser.parse_args(argv)

    try:
        meta = fetch_metadata(args.url)
    except (requests.RequestException, ValueError) as exc:
        print(f"could not read {args.url}: {exc}", file=sys.stderr)
        return 2

    state = load_state(args.state)
    highwater = state.get("highwater") or {}
    problems = compare(meta, highwater, args.allowance)

    # Record the observation either way. The high-water marks only ever rise,
    # so a regression stays visible on every subsequent run until the mirror
    # actually recovers.
    state["highwater"] = update_highwater(meta, highwater)
    state["last_seen"] = {
        "last_run_iso": meta.get("last_run_iso"),
        "cve_count": meta.get("cve_count"),
        "sha256": meta.get("sha256"),
        "bytes": meta.get("bytes"),
    }
    save_state(args.state, state)

    if problems:
        print(
            f"REGRESSION in {args.url} "
            f"(last_run_iso={meta.get('last_run_iso')}):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"mirror healthy: cve_count={meta.get('cve_count')} "
        f"last_run_iso={meta.get('last_run_iso')} "
        f"years={len(meta.get('year_counts') or {})}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
