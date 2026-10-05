"""NVD CVE scraper -- streams the full dataset to disk.

Reads `NVD_API_KEY` from the environment. Writes a JSON array to
`nvd.json` (and a byte-identical copy to `nvd.jsonl` for consumer
compatibility). Also writes `metadata.json` with run statistics.

Data path:
  1. Gzip feed files from nvd.nist.gov / static.nvd.nist.gov, partitioned by
     CVE-ID year (nvdcve-2.0-<year>.json.gz holds every CVE-<year>-* record
     regardless of publication date). NIST rebuilds these ~daily, so they are
     the static backbone of the dataset.
  2. The `modified` feed, overlaid on top. This is the only source of every
     CVE published since the last year-feed rebuild, so it carries the entire
     leading edge. Losing it publishes a snapshot that looks internally
     complete but is hundreds of CVEs short, which is why it is fatal here
     rather than a warning.
  3. An NVD REST API delta, overlaid last: every record modified since the
     newest change in the modified feed. NIST rebuilds that feed only every
     two hours by day and every five overnight, so without this the leading
     edge lags NVD by up to six hours. Strictly bounded and never fatal -- the
     API is unstable enough to have stalled this pipeline for weeks before --
     so on any failure the run publishes the feed-only snapshot.
  4. NVD REST API (services.nvd.nist.gov) -- a per-year fallback that is
     DISABLED for full-corpus runs. The API can only be queried by publication
     date while the feeds partition by CVE-ID year, so substituting it drops
     every CVE-<year>-* record published in a later year. Set
     NVD_ALLOW_API_FALLBACK=1 to re-enable it.

Nothing is published unless the result is at or above the last published
snapshot, per year and in total; see verify_year_coverage.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import sys
import time
import gzip
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests
import urllib3.exceptions

NVD_FEED_BASES = [
    # nvd.nist.gov leads: static.nvd.nist.gov returns HTTP 502 to CI ranges on
    # essentially every request, so trying it first cost a wasted round trip
    # and a spurious warning on all 26 fetches of every run. Keep it as the
    # failover host in case the primary is the one having a bad day.
    "https://nvd.nist.gov/feeds/json/cve/2.0",
    "https://static.nvd.nist.gov/feeds/json/cve/2.0",
]
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
# NIST's WAF (fronting Cloudflare/Akamai) blocks non-browser User-Agents from
# flagged source IPs such as CI runners, so a browser-like UA is required. A
# single hardcoded string is a single point of failure: if NIST ever blocks it
# we want to rotate without a code deploy. Hence a pool plus an env override
# (NVD_USER_AGENT). Order is rotation priority; keep these current -- a stale
# browser version is itself a signal WAFs score as suspicious.
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
# The NVD REST API rejects any pubStartDate/pubEndDate range wider than 120
# days (HTTP 404). Stay safely under that when chunking a year.
API_MAX_WINDOW_DAYS = 120
# Retry profile for every gzip feed, year files and the modified feed alike.
#
# Both fail the same way and in the same window: while NIST regenerates a
# file, static.nvd.nist.gov returns 502 and nvd.nist.gov returns 404. The old
# budget (2 attempts, ~11 seconds) gave up inside that window. For the
# modified feed that meant publishing a snapshot which looked internally
# complete but was missing the entire leading edge; for a year file it meant
# falling through to the REST API and its wrong partition.
#
# Both are fatal now, so both wait the regeneration out. This ladder spans
# roughly eight minutes (15 + 30 + 60 + 120 + 240). The cost is paid once:
# the first year that exhausts its retries aborts the whole run, so a bad NIST
# day does not multiply the wait across 25 files.
MAX_FEED_RETRIES = 6
FEED_BACKOFF_SECONDS = 15
FEED_MAX_BACKOFF_SECONDS = 240
# NVD's year files start at 2002, and that first file is not a single-year
# partition: it holds every CVE-ID year up to and including 2002. Verified
# 2026-08-27 -- nvdcve-2.0-2002.json.gz carried 6771 records spanning
# 1999-2002, exactly the published per-year counts for those four years
# summed. Every later file is a clean single year. So the expected size of the
# 2002 feed is the sum of the baseline's 2002-and-earlier years; reading
# baseline[2002] alone would set its floor at a third of the truth.
FIRST_FEED_YEAR = 2002
# Fetch-time sanity floor for a year feed, as a fraction of what the last
# published run holds for that year. Only a gross shortfall: the precise
# non-regression rule is verify_year_coverage()'s job, and this one has to
# tolerate ordinary drift in the other direction -- the 2020 feed serves 21071
# against a published baseline of 21074, because a rejected CVE leaves the
# feed while staying in our snapshot.
FEED_YEAR_MIN_RATIO = 0.5
# The clock NIST writes feed build timestamps in. They carry no offset, and
# they are NOT UTC: on 2026-10-05 the modified feed's `timestamp` read
# 06:00:03 while its .meta file said 06:00:05-04:00 and the HTTP
# Last-Modified said 10:00:09 GMT. Record-level `lastModified` fields, in the
# feeds and the API alike, are UTC -- only the feed envelope is local time.
NIST_FEED_TZ = ZoneInfo("America/New_York")
# API delta overlay (see apply_api_delta). The budget is wall-clock for the
# whole delta, every page and retry included, and exhausting it only skips the
# delta. The API has stalled this pipeline for weeks before; it must never be
# able to do that again.
API_DELTA_BUDGET_SECONDS = 300
API_DELTA_REQUEST_TIMEOUT = 60
API_DELTA_BACKOFF_SECONDS = 5
# Re-read a little before the modified feed's newest change, so a record
# written while NIST was building that feed cannot fall between the two.
# Overlap is harmless: the newer lastModified wins either way.
API_DELTA_OVERLAP = timedelta(minutes=15)
# The best-effort totalResults probe gets a bound of its own for the same
# reason. It used the fallback's retry ladder, which could spend ~27 minutes
# on a dead API to fetch a number no run depends on.
API_TOTAL_BUDGET_SECONDS = 60
# REST API fallback: more patience since it's the last resort.
MAX_API_RETRIES = 5
RETRY_BACKOFF_SECONDS = 10
API_MAX_BACKOFF_SECONDS = 120
# NVD requires 6s between API requests without a key; with a key the limit is
# 50 requests per 30s. A 1s delay is conservative but keeps us well clear.
API_PAGE_DELAY_SECONDS = 1.0
REQUEST_TIMEOUT = 300
# Abort if the final dataset is grossly short of what the API reports as the
# total CVE count. Catches silently-dropped years that the size check misses.
COMPLETENESS_MIN_RATIO = 0.90
# Per-year coverage guard. The global completeness ratio can't see a single
# lost early year -- 1999 is ~1.5k of ~360k, well inside 90% -- so also check
# each year individually. Historical CVE-ID-year counts only ever grow (NVD
# keeps rejected CVEs as REJECT records), so any shrink means dropped records.
#
# This is a hard non-regression check rather than a percentage tolerance. The
# 2% tolerance it replaces worked out to ~800 CVEs on a big year, which let
# every regression actually observed in production (45 to 447 CVEs) through
# untouched. The allowances below exist only to absorb genuine CVE rejections,
# which run at a handful per week across the whole corpus.
YEAR_DROP_ALLOWANCE = 5
# The current year is still accumulating and sees the most reject churn, so
# give it a wider allowance than a settled historical year.
CURRENT_YEAR_DROP_ALLOWANCE = 25
# The same rule applied to the corpus total, which catches a shortfall spread
# thinly across many years.
TOTAL_DROP_ALLOWANCE = 25
# Last published run's metadata, read for the previous per-year counts and
# total. A baseline that cannot be read is fatal for a full-corpus run unless
# NVD_ALLOW_MISSING_BASELINE=1: silently skipping the regression check is how
# a short dataset reaches consumers in the first place.
BASELINE_METADATA_URL = os.environ.get(
    "BASELINE_METADATA_URL", "https://nvd.handsonhacking.org/metadata.json"
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("nvd")


@dataclass
class Crawler:
    """Holds the HTTP session, User-Agent rotation state, and run stats.

    A single object threaded through the fetch path so that a block detected
    on any request can rotate the shared UA, and so fallback years can be
    recorded for the metadata health report.
    """

    session: requests.Session
    user_agents: list[str]
    ua_index: int = 0
    years_via_api: list[int] = field(default_factory=list)
    # When False, a failed year feed aborts the run instead of falling back to
    # the REST API. The API can only be queried by publication date while the
    # feeds partition by CVE-ID year, so substituting one for the other
    # silently drops every CVE-<year>-* record published in a later year. A
    # single 2023 feed failure cost ~7.5k records that way.
    allow_api_fallback: bool = True
    # Per-year counts from the last published run, used as a fetch-time sanity
    # floor (see assert_feed_intact). Empty disables that floor; the
    # envelope check is unconditional either way.
    baseline_year_counts: dict[int, int] = field(default_factory=dict)
    # Feed build timestamps the last published run consumed, keyed by feed
    # ("2026", "modified"), and the ones this run actually accepted. The first
    # is the reference for assert_feed_fresh; the second is published in
    # metadata.json so the next run has a baseline in turn. Empty disables the
    # freshness check, the same way empty baseline_year_counts disables the
    # sanity floor.
    baseline_feed_timestamps: dict[str, datetime] = field(default_factory=dict)
    feed_timestamps: dict[str, str] = field(default_factory=dict)

    def apply_user_agent(self) -> None:
        self.session.headers["User-Agent"] = self.user_agents[self.ua_index]

    def rotate_user_agent(self) -> bool:
        """Advance to the next UA in the pool. Returns False if exhausted."""
        if self.ua_index + 1 < len(self.user_agents):
            self.ua_index += 1
            self.apply_user_agent()
            return True
        return False


def resolve_user_agents() -> list[str]:
    override = os.environ.get("NVD_USER_AGENT", "").strip()
    if override:
        return [override]
    return list(DEFAULT_USER_AGENTS)


def build_crawler(
    api_key: str,
    allow_api_fallback: bool = True,
    baseline_year_counts: dict[int, int] | None = None,
    baseline_feed_timestamps: dict[str, datetime] | None = None,
) -> Crawler:
    session = requests.Session()
    # An empty apiKey header makes the REST API return 404; only send it when
    # we actually have a key.
    if api_key:
        session.headers["apiKey"] = api_key
    crawler = Crawler(
        session=session,
        user_agents=resolve_user_agents(),
        allow_api_fallback=allow_api_fallback,
        baseline_year_counts=dict(baseline_year_counts or {}),
        baseline_feed_timestamps=dict(baseline_feed_timestamps or {}),
    )
    crawler.apply_user_agent()
    return crawler


class TruncatedFeedError(ValueError):
    """A feed whose contents fall short of what the feed itself promises.

    On 2026-08-27 NIST began serving year files that were truncated at the
    source with no transport-level symptom whatsoever: HTTP 200, a complete
    and CRC-valid gzip stream, well-formed JSON, and an honest envelope --
    nvdcve-2.0-2022.json.gz declared resultsPerPage=27531 above a
    `vulnerabilities` array holding one record. Six years plus the modified
    feed were serving 1-18 records each.

    Nothing below this layer can see that, because nothing is broken; the file
    simply contradicts itself. The old code logged it as `Fetched feed
    year=2022 size=1` -- an ordinary success -- and the shortfall only
    surfaced 25 feeds later as a 46.9% aggregate completeness ratio, with no
    indication in the log of which years were responsible.

    Subclasses ValueError so the fetch retry loop already catches it: a
    truncated feed is a failed fetch, gets the host failover and the full
    backoff ladder, and if it persists it is fatal for that year by name.
    """


def assert_feed_intact(payload: dict, min_records: int | None = None) -> None:
    """Raise TruncatedFeedError if `payload` holds fewer records than expected.

    Public because check_feeds.py watches the upstream feeds with the same
    rule the scraper enforces; two copies of "intact" would drift.

    Two independent floors, because they catch different failures:

      1. The envelope's own count. Exact, needs no external reference, and
         costs nothing -- the feed is compared against itself. Compared
         against resultsPerPage (what this document promises) rather than
         totalResults, so that if NVD ever starts paginating a year file the
         check keeps passing instead of failing every fetch.
      2. `min_records`, derived from the last published run. Catches a feed
         that is internally consistent but grossly short -- the same failure
         with a header that has caught up to the truncation, which floor 1 is
         structurally unable to see.
    """
    if not isinstance(payload, dict):
        return

    actual = len(payload.get("vulnerabilities") or [])

    promised = payload.get("resultsPerPage")
    if isinstance(promised, int) and actual < promised:
        raise TruncatedFeedError(
            f"envelope promises {promised} records but the array holds {actual} "
            f"({promised - actual} missing) -- truncated at the source"
        )

    if min_records is not None and actual < min_records:
        raise TruncatedFeedError(
            f"{actual} records is below the sanity floor of {min_records} for this "
            f"feed, so it cannot be a complete copy"
        )


class StaleFeedError(ValueError):
    """A feed build older than the one the last published run already used.

    On 2026-09-11 a CDN edge replayed the previous day's 2026 year file: HTTP
    200, intact gzip, well-formed JSON, and an envelope that agreed with its
    own contents, so assert_feed_intact had nothing to catch -- a stale build
    is a complete copy of the wrong day. It was 394 records short, and the
    only thing that noticed was the coverage gate, 32 minutes of scraping
    later, by which point the whole run was lost.

    Subclasses ValueError for the same reason TruncatedFeedError does: the
    fetch loop already catches it, so a stale copy becomes the failed fetch it
    is and gets the host failover and the backoff ladder.
    """


def assert_feed_fresh(payload: dict, baseline_built_at: datetime | None) -> None:
    """Raise StaleFeedError if `payload` predates the build we already used.

    The comparison is against the build the last published run consumed, NOT
    against that run's own clock. NIST rebuilds a year file only when its
    contents change -- the 2003 feed served on 2026-09-11 was built on
    2026-08-28 -- while this scraper runs every half hour regardless, so the
    correct, current build is almost always older than the run that last used
    it. Comparing against a run clock would reject every feed we fetch.

    A missing baseline and an unreadable timestamp both mean "nothing to
    compare", and neither may block a run that is otherwise fine.
    """
    if baseline_built_at is None:
        return
    built_at = feed_build_timestamp(payload)
    if built_at is None or built_at >= baseline_built_at:
        return
    raise StaleFeedError(
        f"build {built_at.isoformat()} predates the {baseline_built_at.isoformat()} "
        f"build the last published run used -- a rolled-back copy, not new data"
    )


def looks_like_block(resp: requests.Response) -> bool:
    """True if a response looks like a WAF block rather than real data.

    Catches hard blocks (401/403/418/429) and "soft" blocks where a challenge
    page is returned as a 2xx/3xx with an HTML body -- which would otherwise
    surface as a confusing gzip/JSON decode error deep in parsing.

    A 5xx response with an HTML body is a gateway/origin error (e.g. NIST's
    502 pages), not a WAF block, so it is deliberately NOT treated as one --
    rotating the limited UA pool on plain outages would exhaust it before a
    real block could use it.
    """
    if resp.status_code in (401, 403, 418, 429):
        return True
    if resp.status_code < 400:
        return "text/html" in resp.headers.get("Content-Type", "").lower()
    return False


def iter_feed_years(start_year: int = 2002, end_year: int | None = None):
    if end_year is None:
        end_year = datetime.now(timezone.utc).year
    for year in range(start_year, end_year + 1):
        yield year


def feed_urls_for_year(year: int) -> list[str]:
    return [f"{base}/nvdcve-2.0-{year}.json.gz" for base in NVD_FEED_BASES]


def expected_feed_size(year: int, baseline: dict[int, int]) -> int | None:
    """Records the year `year` feed file should hold, per the published baseline.

    Returns None when there is nothing to compare against. Accounts for the
    2002 file aggregating every earlier year (see FIRST_FEED_YEAR).
    """
    if not baseline:
        return None
    if year <= FIRST_FEED_YEAR:
        return sum(count for y, count in baseline.items() if y <= year) or None
    return baseline.get(year)


def feed_min_records(year: int, baseline: dict[int, int]) -> int | None:
    """The fetch-time floor for a year feed, or None if it cannot be computed."""
    expected = expected_feed_size(year, baseline)
    if not expected:
        return None
    return int(expected * FEED_YEAR_MIN_RATIO)


def modified_feed_urls() -> list[str]:
    return [f"{base}/nvdcve-2.0-modified.json.gz" for base in NVD_FEED_BASES]


def cve_id_for_item(item: dict) -> str:
    return item["cve"]["id"]


def feed_build_timestamp(payload: dict) -> datetime | None:
    """Parse a feed payload's own build timestamp, as UTC.

    NIST stamps every feed with the time it was generated, e.g.
    "2026-09-11T03:00:01.8043137" -- naive, and in US Eastern time, not UTC
    (see NIST_FEED_TZ). Manifests published before this was corrected carry
    these values mislabelled +00:00, which reads as 4-5 hours *earlier* than
    the truth, so comparing a correctly parsed build against one of them can
    only err towards accepting it, never towards a false "stale". Returns
    None when the field is missing or unparseable, which callers must treat
    as "unknown" rather than "stale": an unreadable timestamp means NIST
    changed the format, not that the feed rolled back.
    """
    raw = payload.get("timestamp")
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    # NIST writes 7 fractional digits; fromisoformat took at most 6 before
    # 3.11. Truncating keeps this parseable across interpreter versions.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        log.warning("Feed timestamp %r is not ISO 8601; treating it as unknown", raw)
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=NIST_FEED_TZ)
    return parsed.astimezone(timezone.utc)


def record_last_modified(item: dict) -> datetime | None:
    """A CVE record's own `lastModified`, as UTC, or None if unreadable.

    Unlike the feed envelope's timestamp this field is UTC, and it is the same
    value whether the record came from a feed or the API (checked 2026-10-05
    against three CVEs present in both).
    """
    raw = (item.get("cve") or {}).get("lastModified")
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", raw.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_newer_record(candidate: dict, current: dict) -> bool:
    """True if `candidate` is a strictly later version of `current`.

    Unreadable timestamps never win, so a record with a malformed date cannot
    displace one we can vouch for.
    """
    new = record_last_modified(candidate)
    old = record_last_modified(current)
    return new is not None and (old is None or new > old)


def newest_last_modified(items) -> datetime | None:
    """The latest `lastModified` across `items`, or None if none is readable."""
    stamps = [ts for ts in map(record_last_modified, items) if ts is not None]
    return max(stamps, default=None)


def _record_feed_timestamp(crawler: Crawler, key: str, payload: dict) -> None:
    """Remember the build we accepted, so the next run can compare against it."""
    built_at = feed_build_timestamp(payload)
    if built_at is not None:
        crawler.feed_timestamps[key] = built_at.isoformat()


def baseline_feed_timestamps(metadata: dict) -> dict[str, datetime]:
    """Extract {feed -> build time} from published metadata, or {} if absent.

    Empty is legitimate for metadata predating this field; the caller simply
    has no freshness baseline for that run, and the coverage gate still backs
    it up after the fact.
    """
    raw = metadata.get("feed_timestamps") or {}
    if not isinstance(raw, dict):
        log.warning("Baseline feed_timestamps is malformed; treating it as absent")
        return {}
    parsed: dict[str, datetime] = {}
    for key, value in raw.items():
        built_at = feed_build_timestamp({"timestamp": value})
        if built_at is not None:
            parsed[str(key)] = built_at
    return parsed


def year_from_cve_id(cve_id: str) -> int | None:
    """Extract the numeric year from a CVE ID like 'CVE-1999-0001'."""
    parts = cve_id.split("-")
    if len(parts) >= 3:
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


def _retry_delay_seconds(
    exc: Exception,
    attempt: int,
    base_seconds: float = RETRY_BACKOFF_SECONDS,
    max_seconds: float = API_MAX_BACKOFF_SECONDS,
) -> float:
    """Seconds to wait before `attempt`+1, honouring Retry-After when given.

    Backs off exponentially from `base_seconds` and caps at `max_seconds`, so
    a caller can spend a long time waiting out a feed regeneration without
    hammering NIST.
    """
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        retry_after = exc.response.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(retry_after)
                    return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())
                except (TypeError, ValueError):
                    pass
    return float(min(max_seconds, base_seconds * (2 ** (attempt - 1))))


def _log_request_error(label: str, attempt: int, max_attempts: int, url: str, exc: Exception) -> None:
    status = None
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        status = exc.response.status_code
    if status:
        log.warning("%s attempt %s/%s HTTP %s: %s", label, attempt, max_attempts, status, url)
    else:
        log.warning("%s attempt %s/%s %s(%s): %s", label, attempt, max_attempts, type(exc).__name__, exc, url)


def _load_gzip_json_from_urls(
    crawler: Crawler,
    urls: list[str],
    label: str,
    max_attempts: int = MAX_FEED_RETRIES,
    base_backoff: float = FEED_BACKOFF_SECONDS,
    max_backoff: float = FEED_MAX_BACKOFF_SECONDS,
    min_records: int | None = None,
    baseline_built_at: datetime | None = None,
) -> dict:
    """Fetch and parse a gzipped JSON feed, trying every host then retrying.

    A payload that parses is not necessarily the payload we want: it can be
    truncated at the source (assert_feed_intact) or a stale replay of an older
    build (assert_feed_fresh). Both are checked here so that a bad copy is
    treated as a failed fetch and gets the host failover and the backoff
    ladder, rather than reaching the caller as a thin success.
    """
    last_exc = None

    for attempt in range(1, max_attempts + 1):
        for url in urls:
            try:
                with crawler.session.get(url, timeout=REQUEST_TIMEOUT, stream=True) as resp:
                    if looks_like_block(resp):
                        rotated = crawler.rotate_user_agent()
                        log.warning(
                            "%s appears blocked (HTTP %s) on %s; rotated UA=%s",
                            label, resp.status_code, url, rotated,
                        )
                        last_exc = RuntimeError(f"blocked HTTP {resp.status_code}")
                        continue
                    resp.raise_for_status()
                    resp.raw.decode_content = False
                    with gzip.GzipFile(fileobj=resp.raw) as gz_stream:
                        payload = json.load(gz_stream)
                    # Inside the try on purpose: a feed that is truncated at
                    # the source or replayed from an older build is a failed
                    # fetch, so it belongs to the retry ladder and the host
                    # failover, not to the caller as a thin success.
                    assert_feed_intact(payload, min_records)
                    assert_feed_fresh(payload, baseline_built_at)
                    return payload
            except (
                OSError,
                requests.RequestException,
                ValueError,
                urllib3.exceptions.HTTPError,
            ) as exc:
                last_exc = exc
                _log_request_error(label, attempt, max_attempts, url, exc)

        if attempt < max_attempts:
            delay = _retry_delay_seconds(last_exc, attempt, base_backoff, max_backoff)
            log.warning("%s retrying all hosts in %.1fs", label, delay)
            time.sleep(delay)

    raise RuntimeError(
        f"Feed fetch failed for {label} after {max_attempts} attempts: {last_exc}"
    ) from last_exc


def _fetch_api_page(
    crawler: Crawler,
    url: str,
    label: str,
) -> dict:
    last_exc = None
    for attempt in range(1, MAX_API_RETRIES + 1):
        try:
            resp = crawler.session.get(url, timeout=REQUEST_TIMEOUT)
            if looks_like_block(resp):
                rotated = crawler.rotate_user_agent()
                log.warning(
                    "%s appears blocked (HTTP %s); rotated UA=%s",
                    label, resp.status_code, rotated,
                )
                last_exc = RuntimeError(f"blocked HTTP {resp.status_code}")
            else:
                resp.raise_for_status()
                return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            _log_request_error(label, attempt, MAX_API_RETRIES, url, exc)

        if attempt < MAX_API_RETRIES:
            delay = _retry_delay_seconds(last_exc, attempt)
            log.warning("%s retrying in %.1fs", label, delay)
            time.sleep(delay)

    raise RuntimeError(f"API fetch failed for {label} after {MAX_API_RETRIES} attempts") from last_exc


class ApiDeadlineError(RuntimeError):
    """A bounded API call ran out of wall-clock budget."""


def _fetch_api_page_bounded(
    crawler: Crawler,
    url: str,
    params: dict,
    label: str,
    deadline: float,
) -> dict:
    """GET one API page, retrying until `deadline` (a time.monotonic() value).

    For API calls nothing depends on, the deadline is the only thing that
    matters: every request timeout and backoff is clipped to the time left,
    and the body is read against the deadline too (see _read_body_by), so the
    call returns or raises ApiDeadlineError within one request timeout of
    `deadline` however the API misbehaves -- including a response that keeps
    trickling bytes, which a socket timeout alone never ends.
    _fetch_api_page's ladder is for the year fallback, where the run genuinely
    needs the data.
    """
    attempt = 0
    last_exc: Exception | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            raise ApiDeadlineError(
                f"{label}: out of time after {attempt} attempt(s): {last_exc}"
            ) from last_exc
        attempt += 1
        try:
            resp = crawler.session.get(
                url,
                params=params,
                timeout=min(API_DELTA_REQUEST_TIMEOUT, remaining),
                stream=True,
            )
            try:
                if looks_like_block(resp):
                    # Not worth a UA rotation: the pool is shared with the
                    # feeds, which matter far more than this call.
                    last_exc = RuntimeError(f"blocked HTTP {resp.status_code}")
                    log.warning("%s attempt %s appears blocked (HTTP %s)", label, attempt, resp.status_code)
                else:
                    resp.raise_for_status()
                    data = json.loads(_read_body_by(resp, deadline, label))
                    if not isinstance(data, dict):
                        raise ValueError("API response is not a JSON object")
                    return data
            finally:
                resp.close()
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            log.warning("%s attempt %s %s: %s", label, attempt, type(exc).__name__, exc)
        delay = _retry_delay_seconds(
            last_exc, attempt, API_DELTA_BACKOFF_SECONDS, API_DELTA_BACKOFF_SECONDS * 8
        )
        time.sleep(max(0.0, min(delay, deadline - time.monotonic())))


def _read_body_by(resp: requests.Response, deadline: float, label: str) -> bytes:
    """Read a streamed response body, giving up at `deadline`.

    The request timeout only bounds each wait for the next byte, so a server
    that keeps a byte arriving every few seconds can hold a plain .json() call
    open indefinitely. Checking the clock between chunks caps that at the
    deadline plus one read timeout.
    """
    chunks = []
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        if time.monotonic() > deadline:
            raise ApiDeadlineError(f"{label}: out of time reading the response body")
        chunks.append(chunk)
    return b"".join(chunks)


def _api_page_delay(crawler: Crawler) -> float:
    # NVD's documented limits: 50 requests / 30s with a key, 5 without.
    return API_PAGE_DELAY_SECONDS if crawler.session.headers.get("apiKey") else 6.5


def _format_api_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def fetch_api_delta(
    crawler: Crawler,
    since: datetime,
    until: datetime,
    budget_seconds: float = API_DELTA_BUDGET_SECONDS,
) -> list[dict]:
    """Every CVE the API reports modified in [since, until], or raise.

    All or nothing: a partial delta raises rather than returning short, so
    the caller can say truthfully how current the published data is. Raises
    ApiDeadlineError when the budget runs out, RuntimeError on anything else.
    """
    if until - since > timedelta(days=API_MAX_WINDOW_DAYS):
        raise RuntimeError(
            f"delta window {since.isoformat()}..{until.isoformat()} exceeds the "
            f"API's {API_MAX_WINDOW_DAYS}-day limit"
        )
    deadline = time.monotonic() + budget_seconds
    params = {
        "lastModStartDate": _format_api_time(since),
        "lastModEndDate": _format_api_time(until),
        "resultsPerPage": PAGE_SIZE,
    }
    results: list[dict] = []
    total: int | None = None
    while total is None or len(results) < total:
        page_params = dict(params, startIndex=len(results))
        data = _fetch_api_page_bounded(
            crawler,
            NVD_API_BASE,
            page_params,
            f"API delta offset={len(results)}",
            deadline,
        )
        if total is None:
            try:
                total = int(data["totalResults"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError("API delta response has no usable totalResults") from exc
        page = data.get("vulnerabilities")
        if not isinstance(page, list):
            raise RuntimeError("API delta response has no vulnerabilities array")
        for item in page:
            if not isinstance(item, dict) or not (item.get("cve") or {}).get("id"):
                raise RuntimeError("API delta returned a record without a CVE id")
        if not page and len(results) < total:
            raise RuntimeError(
                f"API delta stopped at {len(results)} of {total} records"
            )
        results.extend(page)
        if len(results) < total:
            time.sleep(_api_page_delay(crawler))
    return results


def apply_api_delta(
    crawler: Crawler,
    overrides: dict[str, dict],
    since: datetime,
    until: datetime | None = None,
    budget_seconds: float = API_DELTA_BUDGET_SECONDS,
) -> dict:
    """Overlay the API's recent changes onto `overrides`; never raises.

    Returns a report for metadata.json. On failure `overrides` is untouched
    and the run publishes exactly what it would have without the delta.
    """
    until = until or datetime.now(timezone.utc)
    report = {"since": since.isoformat(), "until": until.isoformat()}
    started = time.monotonic()
    try:
        records = fetch_api_delta(crawler, since, until, budget_seconds)
    except (RuntimeError, requests.RequestException, ValueError) as exc:
        log.warning("API delta skipped, publishing feed data only: %s", exc)
        report.update(status="failed", error=str(exc)[:300])
        return report
    applied = 0
    for item in records:
        cve_id = cve_id_for_item(item)
        current = overrides.get(cve_id)
        if current is None or is_newer_record(item, current):
            overrides[cve_id] = item
            applied += 1
    log.info(
        "API delta %s..%s: %s records, %s applied in %.1fs",
        report["since"], report["until"], len(records), applied,
        time.monotonic() - started,
    )
    report.update(status="ok", records=len(records), applied=applied)
    return report


def fetch_total(crawler: Crawler, budget_seconds: float = API_TOTAL_BUDGET_SECONDS) -> int | None:
    """Return the API's reported total CVE count, or None if unavailable.

    Used only as a completeness sanity check; never fatal on its own, and
    bounded so that a dead API costs a minute rather than half an hour.
    """
    try:
        data = _fetch_api_page_bounded(
            crawler,
            NVD_API_BASE,
            {"resultsPerPage": 1, "startIndex": 0},
            "totalResults probe",
            time.monotonic() + budget_seconds,
        )
        return int(data.get("totalResults", 0))
    except (RuntimeError, ValueError, TypeError):
        return None


def _iter_year_windows(year: int):
    """Yield (start, end) datetimes covering `year` in <=120-day windows.

    The NVD API caps pubStartDate/pubEndDate ranges at 120 days, so a full
    calendar year must be split into several windows.
    """
    window = timedelta(days=API_MAX_WINDOW_DAYS)
    start = datetime(year, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    year_end = datetime(year, 12, 31, 23, 59, 59, 999000, tzinfo=timezone.utc)
    while start <= year_end:
        end = min(start + window - timedelta(milliseconds=1), year_end)
        yield start, end
        start = end + timedelta(milliseconds=1)


def _fetch_api_window(
    crawler: Crawler,
    year: int,
    win_start: datetime,
    win_end: datetime,
) -> list[dict]:
    pub_start = win_start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    pub_end = win_end.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    base_url = (
        f"{NVD_API_BASE}?pubStartDate={pub_start}&pubEndDate={pub_end}"
        f"&resultsPerPage={PAGE_SIZE}"
    )

    results: list[dict] = []
    start_index = 0
    total: int | None = None

    while True:
        url = f"{base_url}&startIndex={start_index}"
        label = f"API year={year} window={pub_start[:10]} offset={start_index}"
        data = _fetch_api_page(crawler, url, label)

        if total is None:
            total = int(data.get("totalResults", 0))

        page = data.get("vulnerabilities", [])
        results.extend(page)
        start_index += len(page)

        if not page or start_index >= total:
            break

        time.sleep(API_PAGE_DELAY_SECONDS)

    return results


def fetch_year_via_api(
    crawler: Crawler,
    year: int,
) -> list[dict]:
    """Paginate the REST API for one calendar year. Used when feeds fail.

    Splits the year into <=120-day windows to respect the API's range limit.
    Note: the API partitions by publication date, not CVE-ID year, so the
    result is not identical to the feed file for the same year. The caller's
    final dedup-by-ID absorbs the resulting overlap.
    """
    results: list[dict] = []
    for win_start, win_end in _iter_year_windows(year):
        window_items = _fetch_api_window(crawler, year, win_start, win_end)
        results.extend(window_items)
        log.info(
            "API fallback year=%s window=%s items=%s running_total=%s",
            year,
            win_start.strftime("%Y-%m-%d"),
            len(window_items),
            len(results),
        )
        time.sleep(API_PAGE_DELAY_SECONDS)

    log.info("API fallback year=%s complete total=%s", year, len(results))
    return results


def fetch_feed(
    crawler: Crawler,
    year: int,
) -> list[dict]:
    urls = feed_urls_for_year(year)
    min_records = feed_min_records(year, crawler.baseline_year_counts)
    log.info("Fetching feed year=%s (floor=%s)", year, min_records)
    try:
        payload = _load_gzip_json_from_urls(
            crawler,
            urls,
            f"feed year={year}",
            min_records=min_records,
            baseline_built_at=crawler.baseline_feed_timestamps.get(str(year)),
        )
        _record_feed_timestamp(crawler, str(year), payload)
        vulnerabilities = payload.get("vulnerabilities", [])
        log.info(
            "Fetched feed year=%s size=%s built=%s",
            year,
            len(vulnerabilities),
            crawler.feed_timestamps.get(str(year), "unknown"),
        )
        return vulnerabilities
    except RuntimeError as feed_exc:
        if not crawler.allow_api_fallback:
            raise RuntimeError(
                f"Feed fetch failed for year={year} and the REST API fallback is "
                f"disabled: the API partitions by publication date, not CVE-ID "
                f"year, so substituting it would silently drop every "
                f"CVE-{year}-* record published in a later year. Cause: {feed_exc}"
            ) from feed_exc
        log.warning(
            "Feed failed for year=%s (%s) -- falling back to REST API", year, feed_exc
        )
        crawler.years_via_api.append(year)
        return fetch_year_via_api(crawler, year)


def fetch_modified_feed(crawler: Crawler) -> list[dict]:
    urls = modified_feed_urls()
    log.info("Fetching modified feed snapshot")
    payload = _load_gzip_json_from_urls(
        crawler,
        urls,
        "modified feed",
        baseline_built_at=crawler.baseline_feed_timestamps.get("modified"),
    )
    _record_feed_timestamp(crawler, "modified", payload)
    vulnerabilities = payload.get("vulnerabilities", [])
    log.info(
        "Fetched modified feed size=%s built=%s",
        len(vulnerabilities),
        crawler.feed_timestamps.get("modified", "unknown"),
    )
    return vulnerabilities


def iter_feeds(
    crawler: Crawler,
    start_year: int,
    end_year: int,
    overrides: dict[str, dict] | None = None,
    request_delay_seconds: float = 0.0,
):
    """Yield each year feed's records, minus any CVE held in `overrides`.

    An overridden CVE is emitted once, from `overrides`, at the end -- but
    the overlay copy is not automatically the newer one. Year feeds rebuild at
    03:00 ET while the modified feed sits on its 01:00 build until 06:00, so
    for three runs a day a record changed in between is newer in its year
    feed. When the year copy is strictly newer it replaces the override in
    place, instead of being reverted to the older overlay copy.
    """
    overrides = overrides if overrides is not None else {}
    years = list(iter_feed_years(start_year, end_year))
    for index, year in enumerate(years):
        page = fetch_feed(crawler, year)
        if overrides:
            kept = []
            for item in page:
                cve_id = cve_id_for_item(item)
                current = overrides.get(cve_id)
                if current is None:
                    kept.append(item)
                elif is_newer_record(item, current):
                    overrides[cve_id] = item
            page = kept
        yield page

        if request_delay_seconds > 0 and index < len(years) - 1:
            time.sleep(request_delay_seconds)


def fetch_modified_overrides(
    crawler: Crawler,
) -> dict[str, dict]:
    overrides = {}
    for item in fetch_modified_feed(crawler):
        overrides[cve_id_for_item(item)] = item
    log.info("Fetched %s modified-feed override CVEs", len(overrides))
    return overrides


def iter_all_pages(
    crawler: Crawler,
    start_year: int,
    end_year: int,
    overrides: dict[str, dict],
    request_delay_seconds: float = 0.0,
):
    yield from iter_feeds(
        crawler,
        start_year,
        end_year,
        overrides=overrides,
        request_delay_seconds=request_delay_seconds,
    )

    if overrides:
        yield list(overrides.values())


def write_stream(pages, out_path: str, year_counts: dict[int, int] | None = None) -> int:
    """Stream an iterator of page-lists into a JSON array file.

    Dedups by CVE ID (keeping the first record seen) so that overlap between
    the feed partition (by ID year) and the API fallback partition (by
    publication date) cannot emit duplicate CVEs. Returns the unique count.

    If `year_counts` is provided it is populated in place with the number of
    unique CVEs per CVE-ID year, for the per-year coverage guard.
    """
    count = 0
    duplicates = 0
    seen: set[str] = set()
    with open(out_path, "w") as f:
        f.write("[")
        first = True
        for page in pages:
            for item in page:
                cve_id = cve_id_for_item(item)
                if cve_id in seen:
                    duplicates += 1
                    continue
                seen.add(cve_id)
                if year_counts is not None:
                    year = year_from_cve_id(cve_id)
                    if year is not None:
                        year_counts[year] = year_counts.get(year, 0) + 1
                if not first:
                    f.write(",")
                json.dump(item, f, separators=(",", ":"))
                first = False
                count += 1
        f.write("]")
    if duplicates:
        log.info("Skipped %s duplicate CVE records during write", duplicates)
    return count


def sha256_file(path: str, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Streaming SHA-256 of a file, published so consumers can validate the
    1.7 GB object without trusting the transfer."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_metadata(
    path: str,
    cve_count: int,
    started_at: datetime,
    finished_at: datetime,
    years_via_api: list[int],
    expected_total: int | None,
    year_counts: dict[int, int] | None = None,
    data_object_key: str = "nvd.json",
    data_bytes: int | None = None,
    data_sha256: str | None = None,
    feed_timestamps: dict[str, str] | None = None,
    data_current_through: str | None = None,
    api_delta: dict | None = None,
) -> None:
    completeness_ratio = None
    if expected_total:
        completeness_ratio = round(cve_count / expected_total, 4)
    metadata = {
        "last_run_iso": finished_at.isoformat(),
        "cve_count": cve_count,
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "commit_sha": os.environ.get("GITHUB_SHA", "local"),
        # Health signals so downstream consumers can tell a clean run from a
        # degraded one stitched together via the API fallback.
        "degraded": bool(years_via_api),
        "years_via_api": sorted(years_via_api),
        "expected_total": expected_total,
        "completeness_ratio": completeness_ratio,
        # Per-year CVE-ID counts. Published so the next run can diff against it
        # for the per-year drop check, and so consumers can spot a thin year.
        "year_counts": (
            {str(y): year_counts[y] for y in sorted(year_counts)} if year_counts else {}
        ),
        # Build timestamps of the NIST feeds this run consumed, keyed by feed
        # ("2026", "modified"). The next run compares against these to spot a
        # CDN edge handing back an older build -- valid JSON, hundreds of CVEs
        # short -- before it has fetched the rest of the corpus.
        "feed_timestamps": dict(sorted((feed_timestamps or {}).items())),
        # UTC instant up to which every NVD change is in this snapshot: the
        # end of the API delta when it ran, otherwise the newest change in the
        # modified feed. This, not last_run_iso, is how stale the data is.
        "data_current_through": data_current_through,
        # How the API delta went ("ok", "failed", "disabled"). "failed" is
        # not degraded -- it means feed-only, the pre-delta behaviour.
        "api_delta": api_delta or {"status": "disabled"},
        # Companion-manifest fields. Together with cve_count and year_counts
        # these let a consumer fetch ~2 KB, decide whether the 1.7 GB object is
        # worth downloading, and verify it end to end once it has.
        "schema_version": 2,
        "data_object_key": data_object_key,
        "bytes": data_bytes,
        "sha256": data_sha256,
    }
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


def fetch_baseline_metadata(url: str = BASELINE_METADATA_URL) -> dict | None:
    """Fetch the last published run's metadata, or None if it can't be read.

    None means the regression check has no baseline to compare against, which
    main() treats as fatal for a full-corpus run. The previous best-effort
    version returned {} on failure, which silently disabled the only guard
    standing between a short scrape and every downstream consumer.
    """
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.error("Baseline metadata unavailable at %s: %s", url, exc)
        return None
    if not isinstance(data, dict):
        log.error("Baseline metadata at %s is not a JSON object", url)
        return None
    return data


def baseline_year_counts(metadata: dict) -> dict[int, int]:
    """Extract {year -> count} from published metadata, or {} if absent.

    An empty result is legitimate for metadata predating per-year tracking;
    the caller still has the total and the empty-year floor.
    """
    raw = metadata.get("year_counts") or {}
    try:
        return {int(y): int(c) for y, c in raw.items()}
    except (AttributeError, TypeError, ValueError):
        log.warning("Baseline year_counts is malformed; treating it as absent")
        return {}


def verify_year_coverage(
    year_counts: dict[int, int],
    baseline: dict[int, int],
    current_year: int,
    cve_count: int | None = None,
    baseline_total: int | None = None,
) -> list[str]:
    """Return a list of coverage problems (empty list == OK).

    Three guards against a run that silently loses records while the global
    completeness ratio still looks fine:

      1. Empty-year floor: no complete historical year may have zero CVEs.
         This is the "1999 went missing" failure.
      2. Per-year non-regression: no year may fall below the last published
         run by more than a small allowance for genuine CVE rejections.
         Historical CVE-ID-year counts only grow (NVD keeps rejected CVEs as
         REJECT records), so a real shrink means dropped records.
      3. Total non-regression: the same rule on the corpus total, which
         catches a shortfall spread too thinly to trip any single year.
    """
    if not year_counts:
        return ["no per-year counts were computed"]

    problems: list[str] = []

    # Take the year range from the union of this run and the baseline. Deriving
    # `earliest` from year_counts alone made a year that vanished off the low
    # end invisible to this guard: lose all of 1999 and the floor simply starts
    # at 2000 instead.
    known_years = set(year_counts) | set(baseline)
    earliest = min(known_years)
    for year in range(earliest, current_year):
        if year_counts.get(year, 0) <= 0:
            problems.append(f"year {year} is empty (a complete historical year should not be)")

    for year, prev in sorted(baseline.items()):
        now = year_counts.get(year, 0)
        allowance = (
            CURRENT_YEAR_DROP_ALLOWANCE if year >= current_year else YEAR_DROP_ALLOWANCE
        )
        if now < prev - allowance:
            problems.append(
                f"year {year} shrank from {prev} to {now} "
                f"({prev - now} CVEs below the last published run, "
                f"allowance {allowance})"
            )

    if cve_count is not None and baseline_total and cve_count < baseline_total - TOTAL_DROP_ALLOWANCE:
        problems.append(
            f"corpus total shrank from {baseline_total} to {cve_count} "
            f"({baseline_total - cve_count} CVEs below the last published run, "
            f"allowance {TOTAL_DROP_ALLOWANCE})"
        )

    return problems


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "")
    started_at = datetime.now(timezone.utc)

    request_delay_seconds = float(os.environ.get("NVD_REQUEST_DELAY_SECONDS", "3"))
    start_year = int(os.environ.get("NVD_FEED_START_YEAR", "2002"))
    end_year = int(
        os.environ.get("NVD_FEED_END_YEAR", str(datetime.now(timezone.utc).year))
    )
    include_modified_overlay = os.environ.get("NVD_INCLUDE_MODIFIED_OVERLAY", "1") != "0"
    include_api_delta = os.environ.get("NVD_INCLUDE_API_DELTA", "1") != "0"
    api_delta_budget = float(
        os.environ.get("NVD_API_DELTA_BUDGET_SECONDS", str(API_DELTA_BUDGET_SECONDS))
    )

    if start_year > end_year:
        log.error("Invalid feed year range: %s > %s", start_year, end_year)
        return 2

    # The completeness gate compares against the API's global total, which is
    # only a valid expectation when crawling the entire corpus. A deliberately
    # restricted range is legitimately smaller, so don't fail it on that basis.
    current_year = datetime.now(timezone.utc).year
    full_corpus_run = start_year <= 2002 and end_year >= current_year

    # The REST API fallback is off for a full-corpus run: it partitions by
    # publication date rather than CVE-ID year, so it cannot stand in for a
    # year feed without dropping records. A restricted-range run may still
    # want it, and NVD_ALLOW_API_FALLBACK=1 forces it back on.
    allow_api_fallback = (
        not full_corpus_run or os.environ.get("NVD_ALLOW_API_FALLBACK", "").strip() == "1"
    )
    # Read the last published run's metadata before crawling anything. It
    # serves two purposes and both want it early: it is the reference for the
    # per-year coverage gate at the end, and it sets the per-feed sanity floor
    # applied as each year lands. Fetching it here also means a missing
    # baseline -- fatal for a full-corpus run -- costs a few seconds instead
    # of aborting after a completed 30-minute crawl.
    baseline_metadata: dict = {}
    if full_corpus_run:
        published = fetch_baseline_metadata()
        if published is not None:
            baseline_metadata = published
        elif os.environ.get("NVD_ALLOW_MISSING_BASELINE", "").strip() == "1":
            log.warning(
                "Baseline metadata unavailable; regression check disabled by "
                "NVD_ALLOW_MISSING_BASELINE"
            )
        else:
            log.error(
                "Aborting: baseline metadata unavailable, so a regression "
                "against the published snapshot cannot be ruled out"
            )
            log.error(
                "Set NVD_ALLOW_MISSING_BASELINE=1 to publish anyway (bootstrap only)"
            )
            return 8

    baseline = baseline_year_counts(baseline_metadata)
    # The same manifest also carries the build timestamp of every feed that run
    # consumed, which is what assert_feed_fresh compares against. Off switch is
    # separate from NVD_ALLOW_MISSING_BASELINE so that clearing a wedged
    # freshness check does not also stand down the coverage gate -- needed if
    # NIST ever republishes a feed with an earlier timestamp than the one we
    # already used, which would otherwise refuse that feed on every run.
    if os.environ.get("NVD_SKIP_FEED_FRESHNESS", "").strip() == "1":
        log.warning(
            "Feed freshness check disabled by NVD_SKIP_FEED_FRESHNESS -- a "
            "rolled-back feed will only be caught after the scrape, by the "
            "coverage gate"
        )
        baseline_builds: dict[str, datetime] = {}
    else:
        baseline_builds = baseline_feed_timestamps(baseline_metadata)
        if full_corpus_run:
            log.info(
                "Freshness baseline: %s feed build timestamps from the last "
                "published run",
                len(baseline_builds),
            )

    crawler = build_crawler(
        api_key,
        allow_api_fallback=allow_api_fallback,
        baseline_year_counts=baseline,
        baseline_feed_timestamps=baseline_builds,
    )

    log.info(
        "Fetching NVD feeds for years %s-%s (api_fallback=%s)",
        start_year,
        end_year,
        allow_api_fallback,
    )

    try:
        overrides = {}
        if include_modified_overlay:
            log.info("Fetching modified-feed overlay")
            try:
                overrides = fetch_modified_overrides(crawler)
            except RuntimeError as exc:
                # Fatal on purpose. The modified feed is the only source of
                # every CVE published since NIST's last daily year-feed
                # rebuild, so continuing without it publishes a snapshot that
                # is internally complete but hundreds of CVEs short at the
                # leading edge -- which is exactly what consumers saw as the
                # dataset "going backwards". Returning here leaves the
                # last-known-good object in R2 untouched.
                log.error("Modified-feed overlay unavailable: %s", exc)
                log.error("Aborting: refusing to publish without the leading edge")
                return 7

        # How current the data is, before any delta: the newest change the
        # modified feed carries. Taken now, before the year feeds can lift
        # individual overrides past it, because a newer year-feed record says
        # nothing about the changes around it.
        feed_high_water = newest_last_modified(overrides.values())
        data_current_through = feed_high_water.isoformat() if feed_high_water else None
        api_delta_report: dict = {"status": "disabled"}
        # The delta joins the overlay BEFORE the year feeds, not after. Year
        # pages are streamed to disk as they land, so a CVE the delta brought
        # in afterwards would already be written in its older year-feed copy,
        # and the writer's keep-first dedup would then drop the newer one.
        # Merging first lets iter_feeds' newer-wins rule settle every
        # collision. The cost is the crawl time in freshness, which
        # data_current_through reports honestly.
        if include_api_delta and overrides:
            if feed_high_water is None:
                api_delta_report = {
                    "status": "failed",
                    "error": "modified feed has no readable lastModified to start from",
                }
            else:
                api_delta_report = apply_api_delta(
                    crawler,
                    overrides,
                    feed_high_water - API_DELTA_OVERLAP,
                    budget_seconds=api_delta_budget,
                )
                if api_delta_report["status"] == "ok":
                    data_current_through = api_delta_report["until"]

        year_counts: dict[int, int] = {}
        cve_count = write_stream(
            iter_all_pages(
                crawler,
                start_year,
                end_year,
                overrides,
                request_delay_seconds=request_delay_seconds,
            ),
            "nvd.json",
            year_counts=year_counts,
        )
    except RuntimeError as exc:
        log.error("Scrape failed before completion: %s", exc)
        return 3

    if cve_count == 0:
        log.error("Scrape produced 0 CVEs -- aborting")
        return 4

    # Coverage gate: hard non-regression against the last published run, per
    # year and on the total (see YEAR_DROP_ALLOWANCE). Catches both a single
    # lost year that the global ratio can't see and a shortfall spread too
    # thinly to trip any one year. Only meaningful for a full-corpus run -- a
    # restricted range legitimately omits years. Failing here returns before
    # the upload step, so the last-known-good data in R2 is left untouched.
    #
    # Ordered ahead of the global completeness ratio deliberately. Both gates
    # would fail a short scrape, but this one says which years are short and by
    # how much, where the ratio only says "46.9%" -- which is what the
    # 2026-08-27 truncated-feed outage actually printed, leaving the affected
    # years to be picked out of 26 "Fetched feed" lines by hand. Neither gate
    # is weakened by the swap; both still run, and both still return before the
    # upload step.
    if full_corpus_run:
        baseline_total = baseline_metadata.get("cve_count")
        if not isinstance(baseline_total, int):
            baseline_total = None

        problems = verify_year_coverage(
            year_counts, baseline, current_year, cve_count, baseline_total
        )
        if problems:
            for problem in problems:
                log.error("Per-year coverage check failed: %s", problem)
            log.error("Aborting: per-year coverage regressed -- not publishing partial data")
            return 6
        log.info(
            "Coverage OK: %s years (%s-%s), none empty%s%s",
            len(year_counts),
            min(year_counts),
            max(year_counts),
            f", none shrinking vs {len(baseline)} baseline years" if baseline else "",
            f", total {cve_count} >= baseline {baseline_total}" if baseline_total else "",
        )

    # Completeness check: compare against the API's reported total. Only fails
    # on a gross shortfall, so a flaky probe (returns None) never blocks a run,
    # and only for a full-corpus run where the global total is the right
    # expectation.
    expected_total = fetch_total(crawler)
    if expected_total and full_corpus_run:
        ratio = cve_count / expected_total
        if ratio < COMPLETENESS_MIN_RATIO:
            log.error(
                "Scrape incomplete: got %s CVEs, API reports %s total (%.1f%%) -- aborting",
                cve_count,
                expected_total,
                100.0 * ratio,
            )
            return 5
        log.info(
            "Completeness: %s/%s CVEs (%.2f%%)", cve_count, expected_total, 100.0 * ratio
        )

    # Duplicate for consumer compatibility (see design §4)
    shutil.copyfile("nvd.json", "nvd.jsonl")

    finished_at = datetime.now(timezone.utc)
    data_bytes = os.path.getsize("nvd.json")
    data_sha256 = sha256_file("nvd.json")
    log.info("nvd.json bytes=%s sha256=%s", data_bytes, data_sha256)

    write_metadata(
        "metadata.json",
        cve_count,
        started_at,
        finished_at,
        crawler.years_via_api,
        # Only meaningful as an expectation for a full-corpus run.
        expected_total if full_corpus_run else None,
        year_counts,
        data_bytes=data_bytes,
        data_sha256=data_sha256,
        feed_timestamps=crawler.feed_timestamps,
        data_current_through=data_current_through,
        api_delta=api_delta_report,
    )

    if api_delta_report["status"] == "failed" and os.environ.get("GITHUB_ACTIONS") == "true":
        # Non-fatal by design, which also makes it easy to miss: surface it on
        # the run summary rather than only in the log.
        print(
            "::warning title=API delta skipped::Published feed data only "
            f"(current through {data_current_through}): "
            f"{api_delta_report.get('error', 'unknown error')}"
        )

    if crawler.years_via_api:
        log.warning(
            "Run degraded: years served via API fallback (may be incomplete): %s",
            sorted(crawler.years_via_api),
        )

    log.info(
        "Wrote %s CVEs to nvd.json / nvd.jsonl in %ss",
        cve_count,
        (finished_at - started_at).total_seconds(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
