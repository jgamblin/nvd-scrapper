"""Scheduled watchdog for NIST's upstream JSON 2.0 feeds.

Answers one question the mirror watchdog cannot: is the *source* healthy right
now? check_mirror.py watches what we published, so when NIST breaks it stays
green while the scraper fails on every run -- correct, but it leaves "why" to
be reconstructed from a failed scrape log.

The failure this exists to catch has no transport-level symptom. On
2026-08-27 NIST served year feeds that were HTTP 200, a complete CRC-valid
gzip stream, well-formed JSON, and carried a truthful envelope
(nvdcve-2.0-2022.json.gz declared resultsPerPage=27531) above a
`vulnerabilities` array holding a single record. Six years, 2026, and the
modified feed were each serving 1-18 records. Nothing was broken; the files
contradicted themselves.

Two checks, split by what they cost:

  Year feeds -- HEAD only, no bodies. A feed's gzipped size divided by the
  record count NVD reports for that year is tightly bounded in practice: 321
  to 896 bytes per record across all of 2002-2026 when healthy, against 0.06
  to 2.1 when truncated. Three orders of magnitude of headroom, so a floor set
  6x below the lowest healthy value separates them with room to spare, and the
  whole sweep is ~25 requests with no payload.

  Modified feed -- fetched and checked exactly, via nvd.assert_feed_intact.
  It has no per-year baseline to size against, it is small, and it is the
  highest-consequence file of the set: it is the sole source of the leading
  edge, so a truncated copy silently ages the snapshot rather than shrinking
  it, which is the one shortfall the publish gates can miss.

Expected record counts come from our own published metadata.json -- the same
baseline the scraper uses -- so there is no second table to maintain.

Usage:
    python3 check_feeds.py [--url URL] [--start-year N] [--end-year N]
                           [--min-bytes-per-record N] [--skip-modified]

Exit codes: 0 healthy, 1 upstream feeds are degraded, 2 could not evaluate.
"""

import argparse
import gzip
import json
import os
import sys
import traceback
import zlib

import requests

import nvd

DEFAULT_BASELINE_URL = os.environ.get(
    "BASELINE_METADATA_URL", "https://nvd.handsonhacking.org/metadata.json"
)
# Gzipped bytes per record, below which a year feed cannot be a complete copy.
# Measured live on 2026-08-27 across 2002-2026: healthy files ran 321 (2002,
# the densest because it aggregates four sparse early years) to 896 (2009);
# the truncated files ran 0.063 to 2.099. This floor sits 6x below the lowest
# healthy observation and 24x above the highest truncated one. It is a smoke
# alarm, not a scale -- the scraper's own envelope check is the exact rule.
MIN_GZ_BYTES_PER_RECORD = 50


def fetch_baseline_year_counts(url: str) -> dict[int, int]:
    """Expected records per CVE-ID year, from our published manifest."""
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("metadata is not a JSON object")
    return nvd.baseline_year_counts(data)


def head_content_length(crawler: nvd.Crawler, urls: list[str]) -> tuple[int | None, str]:
    """Content-Length of the first URL that answers, and the URL that did.

    Tries the hosts in order, exactly as the scraper does, so this reports on
    the same bytes a real run would receive. Returns (None, reason) if no host
    gives a usable answer -- including a WAF block, which says nothing about
    whether the feed itself is intact.
    """
    problems = []
    for url in urls:
        try:
            resp = crawler.session.head(url, timeout=60, allow_redirects=True)
        except requests.RequestException as exc:
            problems.append(f"{type(exc).__name__} on {url}")
            continue
        if nvd.looks_like_block(resp):
            crawler.rotate_user_agent()
            problems.append(f"blocked HTTP {resp.status_code} on {url}")
            continue
        if resp.status_code >= 400:
            problems.append(f"HTTP {resp.status_code} on {url}")
            continue
        raw = resp.headers.get("Content-Length")
        if raw is None:
            problems.append(f"no Content-Length on {url}")
            continue
        try:
            return int(raw), url
        except ValueError:
            problems.append(f"unparseable Content-Length {raw!r} on {url}")
    return None, "; ".join(problems) or "no hosts tried"


def check_year_feeds(
    crawler: nvd.Crawler,
    baseline: dict[int, int],
    start_year: int,
    end_year: int,
    min_bytes_per_record: int = MIN_GZ_BYTES_PER_RECORD,
) -> tuple[list[str], list[str]]:
    """Return (problems, notes) for the year feeds over the given range."""
    problems: list[str] = []
    notes: list[str] = []

    for year in nvd.iter_feed_years(start_year, end_year):
        expected = nvd.expected_feed_size(year, baseline)
        if not expected:
            notes.append(f"year {year}: no baseline count, not size-checked")
            continue

        size, why = head_content_length(crawler, nvd.feed_urls_for_year(year))
        if size is None:
            # Unreachable is not the same as truncated, and this watchdog must
            # not cry wolf about NIST being down -- the scraper's own retries
            # and the failure issue already cover that.
            notes.append(f"year {year}: size unknown ({why})")
            continue

        density = size / expected
        if density < min_bytes_per_record:
            problems.append(
                f"year {year} feed is {size} gzipped bytes for {expected} expected "
                f"records ({density:.3f} bytes/record, floor {min_bytes_per_record}) "
                f"-- served but nowhere near a complete copy"
            )
        else:
            notes.append(
                f"year {year}: {size} bytes / {expected} records = "
                f"{density:.0f} bytes/record"
            )

    return problems, notes


def check_modified_feed(crawler: nvd.Crawler) -> tuple[list[str], list[str]]:
    """Fetch the modified feed and check it against its own envelope.

    Fetched here rather than through nvd.fetch_modified_feed() on purpose. The
    intactness *rule* is shared -- nvd.assert_feed_intact, one definition -- but
    the retry *policy* is not: the scraper spends eight minutes riding out a
    regeneration window because giving up costs it the whole leading edge,
    whereas a watchdog that runs every hour should take one look and report.
    """
    problems: list[str] = []
    notes: list[str] = []

    for url in nvd.modified_feed_urls():
        try:
            with crawler.session.get(url, timeout=120, stream=True) as resp:
                if nvd.looks_like_block(resp):
                    crawler.rotate_user_agent()
                    notes.append(f"modified feed: blocked HTTP {resp.status_code}")
                    continue
                resp.raise_for_status()
                resp.raw.decode_content = False
                with gzip.GzipFile(fileobj=resp.raw) as gz_stream:
                    payload = json.load(gz_stream)
        except (
            OSError, EOFError, zlib.error, requests.RequestException, ValueError
        ) as exc:
            # Unreachable, 404 mid-regeneration, a truncated gzip stream: all
            # upstream weather the scraper's retry ladder is built to ride out,
            # so none of it is this watchdog's finding. EOFError (a gzip cut
            # short) and zlib.error (a corrupt deflate stream) are listed
            # separately because neither is an OSError -- missing them let a
            # short read on 2026-09-23 crash the check, and the crash's exit
            # code 1 was reported as NIST serving incomplete feeds.
            notes.append(f"modified feed: not evaluated ({type(exc).__name__}: {exc})")
            continue

        try:
            nvd.assert_feed_intact(payload)
        except nvd.TruncatedFeedError as exc:
            problems.append(f"modified feed: {exc}")
        else:
            count = len(payload.get("vulnerabilities") or [])
            notes.append(
                f"modified feed: {count} records, consistent with its envelope"
            )
        return problems, notes

    return problems, notes


def main(argv: list[str] | None = None) -> int:
    """Run the check, mapping any unexpected crash to exit 2.

    An uncaught exception would exit 1, which the workflow reads as "NIST is
    serving incomplete feeds" and files an issue for. A bug in this script is
    not evidence about upstream, so it must land on "could not evaluate".
    """
    try:
        return _run(argv)
    except Exception:
        traceback.print_exc()
        print("check_feeds crashed; upstream health not evaluated", file=sys.stderr)
        return 2


def _run(argv: list[str] | None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_BASELINE_URL)
    parser.add_argument("--start-year", type=int, default=nvd.FIRST_FEED_YEAR)
    parser.add_argument("--end-year", type=int, default=None)
    parser.add_argument(
        "--min-bytes-per-record", type=int, default=MIN_GZ_BYTES_PER_RECORD
    )
    parser.add_argument("--skip-modified", action="store_true")
    args = parser.parse_args(argv)

    try:
        baseline = fetch_baseline_year_counts(args.url)
    except (requests.RequestException, ValueError) as exc:
        print(f"could not read the baseline at {args.url}: {exc}", file=sys.stderr)
        return 2
    if not baseline:
        print(f"baseline at {args.url} has no year_counts", file=sys.stderr)
        return 2

    end_year = args.end_year if args.end_year is not None else max(baseline)
    crawler = nvd.build_crawler(os.environ.get("NVD_API_KEY", ""))

    problems, notes = check_year_feeds(
        crawler, baseline, args.start_year, end_year, args.min_bytes_per_record
    )
    if not args.skip_modified:
        mod_problems, mod_notes = check_modified_feed(crawler)
        problems += mod_problems
        notes += mod_notes

    for note in notes:
        print(f"  {note}")
    # stdout and stderr are separately buffered, so without this the findings
    # below land above the notes in a CI log and read as a different run.
    sys.stdout.flush()

    if problems:
        print(
            f"\nUPSTREAM FEEDS DEGRADED: {len(problems)} feed(s) are being served "
            f"but are nowhere near complete.",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nThis is a NIST-side fault, not a fault in this repo. The scraper "
            "will refuse to publish while it lasts, which is correct: the "
            "last-known-good snapshot in R2 keeps being served.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nupstream feeds healthy: {args.start_year}-{end_year} all above the "
        f"{args.min_bytes_per_record} bytes/record floor"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
