"""NVD CVE scraper -- streams the full dataset to disk.

Reads `NVD_API_KEY` from the environment. Writes a JSON array to
`nvd.json` (and a byte-identical copy to `nvd.jsonl` for consumer
compatibility). Also writes `metadata.json` with run statistics.

Data path (fastest to slowest):
  1. Static gzip feed files from static.nvd.nist.gov / nvd.nist.gov,
     partitioned by CVE-ID year (nvdcve-2.0-<year>.json.gz holds every
     CVE-<year>-* record regardless of publication date).
  2. NVD REST API (services.nvd.nist.gov) -- per-year fallback when feeds
     fail. The API can only be queried by publication date, so the fallback
     returns a DIFFERENT partition than the feeds. The final write dedups by
     CVE ID to absorb the overlap; years served by the fallback are recorded
     in metadata as potentially incomplete (`years_via_api`).
"""

import json
import logging
import os
import shutil
import sys
import time
import gzip
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone

import requests
import urllib3.exceptions

NVD_FEED_BASES = [
    "https://static.nvd.nist.gov/feeds/json/cve/2.0",
    "https://nvd.nist.gov/feeds/json/cve/2.0",
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
# Feeds: fail fast (2 attempts), then fall back to REST API.
MAX_FEED_RETRIES = 2
# REST API: more patience since it's the last resort.
MAX_API_RETRIES = 5
RETRY_BACKOFF_SECONDS = 10
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
# Fail if a year drops more than this fraction below the last published run,
# ignoring shrink smaller than YEAR_DROP_MIN_ABS so a one-off reject on a tiny
# year doesn't trip the ratio.
YEAR_DROP_TOLERANCE = 0.02
YEAR_DROP_MIN_ABS = 5
# Last published run's metadata, read to get the previous per-year counts for
# the drop check. Set to empty to disable the drop check (the empty-year floor
# still applies). Defaults to the public feed this scraper publishes.
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


def build_crawler(api_key: str) -> Crawler:
    session = requests.Session()
    # An empty apiKey header makes the REST API return 404; only send it when
    # we actually have a key.
    if api_key:
        session.headers["apiKey"] = api_key
    crawler = Crawler(session=session, user_agents=resolve_user_agents())
    crawler.apply_user_agent()
    return crawler


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


def modified_feed_urls() -> list[str]:
    return [f"{base}/nvdcve-2.0-modified.json.gz" for base in NVD_FEED_BASES]


def cve_id_for_item(item: dict) -> str:
    return item["cve"]["id"]


def year_from_cve_id(cve_id: str) -> int | None:
    """Extract the numeric year from a CVE ID like 'CVE-1999-0001'."""
    parts = cve_id.split("-")
    if len(parts) >= 3:
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


def _retry_delay_seconds(exc: Exception, attempt: int) -> float:
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
    return float(RETRY_BACKOFF_SECONDS * attempt)


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
) -> dict:
    last_exc = None

    for attempt in range(1, MAX_FEED_RETRIES + 1):
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
                        return json.load(gz_stream)
            except (
                OSError,
                requests.RequestException,
                ValueError,
                urllib3.exceptions.HTTPError,
            ) as exc:
                last_exc = exc
                _log_request_error(label, attempt, MAX_FEED_RETRIES, url, exc)

        if attempt < MAX_FEED_RETRIES:
            delay = _retry_delay_seconds(last_exc, attempt)
            log.warning("%s retrying all hosts in %.1fs", label, delay)
            time.sleep(delay)

    raise RuntimeError(
        f"Feed fetch failed for {label} after {MAX_FEED_RETRIES} attempts"
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


def fetch_total(crawler: Crawler) -> int | None:
    """Return the API's reported total CVE count, or None if unavailable.

    Used only as a completeness sanity check; never fatal on its own.
    """
    url = f"{NVD_API_BASE}?resultsPerPage=1&startIndex=0"
    try:
        data = _fetch_api_page(crawler, url, "totalResults probe")
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
    log.info("Fetching feed year=%s", year)
    try:
        payload = _load_gzip_json_from_urls(crawler, urls, f"feed year={year}")
        vulnerabilities = payload.get("vulnerabilities", [])
        log.info("Fetched feed year=%s size=%s", year, len(vulnerabilities))
        return vulnerabilities
    except RuntimeError as feed_exc:
        log.warning(
            "Feed failed for year=%s (%s) -- falling back to REST API", year, feed_exc
        )
        crawler.years_via_api.append(year)
        return fetch_year_via_api(crawler, year)


def fetch_modified_feed(crawler: Crawler) -> list[dict]:
    urls = modified_feed_urls()
    log.info("Fetching modified feed snapshot")
    payload = _load_gzip_json_from_urls(crawler, urls, "modified feed")
    vulnerabilities = payload.get("vulnerabilities", [])
    log.info("Fetched modified feed size=%s", len(vulnerabilities))
    return vulnerabilities


def iter_feeds(
    crawler: Crawler,
    start_year: int,
    end_year: int,
    override_ids: set[str] | None = None,
    request_delay_seconds: float = 0.0,
):
    override_ids = override_ids or set()
    years = list(iter_feed_years(start_year, end_year))
    for index, year in enumerate(years):
        page = fetch_feed(crawler, year)
        if override_ids:
            page = [item for item in page if cve_id_for_item(item) not in override_ids]
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
    override_ids = set(overrides)

    yield from iter_feeds(
        crawler,
        start_year,
        end_year,
        override_ids=override_ids,
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


def write_metadata(
    path: str,
    cve_count: int,
    started_at: datetime,
    finished_at: datetime,
    years_via_api: list[int],
    expected_total: int | None,
    year_counts: dict[int, int] | None = None,
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
    }
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


def fetch_baseline_year_counts(url: str = BASELINE_METADATA_URL) -> dict[int, int]:
    """Best-effort fetch of the last published run's per-year counts.

    Returns {year -> count}, or {} if unavailable or the published metadata
    predates per-year tracking. Never raises: a missing baseline just means the
    drop check is skipped and only the empty-year floor applies.
    """
    if not url:
        return {}
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        raw = resp.json().get("year_counts") or {}
        return {int(y): int(c) for y, c in raw.items()}
    except (requests.RequestException, ValueError, TypeError) as exc:
        log.warning("Baseline year_counts unavailable (%s); skipping drop check", exc)
        return {}


def verify_year_coverage(
    year_counts: dict[int, int], baseline: dict[int, int], current_year: int
) -> list[str]:
    """Return a list of per-year coverage problems (empty list == OK).

    Two guards against a feed that silently loses a year's records while the
    global total still looks complete:

      1. Empty-year floor: no complete historical year (earliest..current-1)
         may have zero CVEs. This is the "1999 went missing" failure.
      2. Drop check: no year may shrink more than YEAR_DROP_TOLERANCE below the
         last published run. Historical CVE-ID-year counts only grow, so a real
         shrink means dropped records.
    """
    if not year_counts:
        return ["no per-year counts were computed"]

    problems: list[str] = []
    earliest = min(year_counts)
    for year in range(earliest, current_year):
        if year_counts.get(year, 0) <= 0:
            problems.append(f"year {year} is empty (a complete historical year should not be)")

    for year, prev in sorted(baseline.items()):
        now = year_counts.get(year, 0)
        drop = prev - now
        if drop > YEAR_DROP_MIN_ABS and now < prev * (1 - YEAR_DROP_TOLERANCE):
            problems.append(
                f"year {year} shrank from {prev} to {now} "
                f"({100.0 * drop / prev:.1f}% below the last published run)"
            )
    return problems


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "")
    crawler = build_crawler(api_key)
    started_at = datetime.now(timezone.utc)

    request_delay_seconds = float(os.environ.get("NVD_REQUEST_DELAY_SECONDS", "3"))
    start_year = int(os.environ.get("NVD_FEED_START_YEAR", "2002"))
    end_year = int(
        os.environ.get("NVD_FEED_END_YEAR", str(datetime.now(timezone.utc).year))
    )
    include_modified_overlay = os.environ.get("NVD_INCLUDE_MODIFIED_OVERLAY", "1") != "0"

    if start_year > end_year:
        log.error("Invalid feed year range: %s > %s", start_year, end_year)
        return 2

    # The completeness gate compares against the API's global total, which is
    # only a valid expectation when crawling the entire corpus. A deliberately
    # restricted range is legitimately smaller, so don't fail it on that basis.
    current_year = datetime.now(timezone.utc).year
    full_corpus_run = start_year <= 2002 and end_year >= current_year

    log.info("Fetching NVD feeds for years %s-%s", start_year, end_year)

    try:
        overrides = {}
        if include_modified_overlay:
            log.info("Fetching modified-feed overlay")
            try:
                overrides = fetch_modified_overrides(crawler)
            except RuntimeError as exc:
                log.warning("Skipping modified-feed overlay due to errors: %s", exc)
                overrides = {}

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

    # Per-year coverage gate: catches a single lost year that the global ratio
    # can't (see YEAR_DROP_TOLERANCE). Only meaningful for a full-corpus run --
    # a restricted range legitimately omits years. Failing here returns before
    # the upload step, so the last-known-good data in R2 is left untouched.
    if full_corpus_run:
        baseline = fetch_baseline_year_counts()
        problems = verify_year_coverage(year_counts, baseline, current_year)
        if problems:
            for problem in problems:
                log.error("Per-year coverage check failed: %s", problem)
            log.error("Aborting: per-year coverage regressed -- not publishing partial data")
            return 6
        log.info(
            "Per-year coverage OK: %s years (%s-%s), none empty%s",
            len(year_counts),
            min(year_counts),
            max(year_counts),
            f", none shrinking vs {len(baseline)} baseline years" if baseline else "",
        )

    # Duplicate for consumer compatibility (see design §4)
    shutil.copyfile("nvd.json", "nvd.jsonl")

    finished_at = datetime.now(timezone.utc)
    write_metadata(
        "metadata.json",
        cve_count,
        started_at,
        finished_at,
        crawler.years_via_api,
        # Only meaningful as an expectation for a full-corpus run.
        expected_total if full_corpus_run else None,
        year_counts,
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
