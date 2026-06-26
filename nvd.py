"""NVD CVE scraper -- streams the full dataset to disk.

Reads `NVD_API_KEY` from the environment. Writes a JSON array to
`nvd.json` (and a byte-identical copy to `nvd.jsonl` for consumer
compatibility). Also writes `metadata.json` with run statistics.

Data path (fastest to slowest):
  1. Static gzip feed files from static.nvd.nist.gov / nvd.nist.gov
  2. NVD REST API (services.nvd.nist.gov) -- per-year fallback when feeds fail
"""

import json
import logging
import os
import shutil
import sys
import time
import gzip
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

import requests
import urllib3.exceptions

NVD_FEED_BASES = [
    "https://static.nvd.nist.gov/feeds/json/cve/2.0",
    "https://nvd.nist.gov/feeds/json/cve/2.0",
]
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
# Feeds: fail fast (2 attempts), then fall back to REST API.
MAX_FEED_RETRIES = 2
# REST API: more patience since it's the last resort.
MAX_API_RETRIES = 5
RETRY_BACKOFF_SECONDS = 10
# NVD requires 6s between API requests without a key; with a key the limit is
# 50 requests per 30s. A 1s delay is conservative but keeps us well clear.
API_PAGE_DELAY_SECONDS = 1.0
REQUEST_TIMEOUT = 300

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("nvd")


def build_session() -> requests.Session:
    return requests.Session()


def build_headers(api_key: str) -> dict:
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/58.0.3029.110 Safari/537.3"
        ),
        "apiKey": api_key,
    }


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
    session: requests.Session,
    urls: list[str],
    label: str,
) -> dict:
    last_exc = None

    for attempt in range(1, MAX_FEED_RETRIES + 1):
        for url in urls:
            try:
                with session.get(url, timeout=REQUEST_TIMEOUT, stream=True) as resp:
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
    session: requests.Session,
    headers: dict,
    url: str,
    label: str,
) -> dict:
    last_exc = None
    for attempt in range(1, MAX_API_RETRIES + 1):
        try:
            resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            _log_request_error(label, attempt, MAX_API_RETRIES, url, exc)
            if attempt < MAX_API_RETRIES:
                delay = _retry_delay_seconds(exc, attempt)
                log.warning("%s retrying in %.1fs", label, delay)
                time.sleep(delay)

    raise RuntimeError(f"API fetch failed for {label} after {MAX_API_RETRIES} attempts") from last_exc


def fetch_year_via_api(
    session: requests.Session,
    headers: dict,
    year: int,
) -> list[dict]:
    """Paginate the REST API for one calendar year. Used when feeds fail."""
    pub_start = f"{year}-01-01T00:00:00.000"
    pub_end = f"{year}-12-31T23:59:59.999"
    base_url = (
        f"{NVD_API_BASE}?pubStartDate={pub_start}&pubEndDate={pub_end}"
        f"&resultsPerPage={PAGE_SIZE}"
    )

    results: list[dict] = []
    start_index = 0
    total: int | None = None

    while True:
        url = f"{base_url}&startIndex={start_index}"
        label = f"API year={year} offset={start_index}"
        data = _fetch_api_page(session, headers, url, label)

        if total is None:
            total = int(data.get("totalResults", 0))
            log.info("API fallback year=%s total=%s", year, total)

        page = data.get("vulnerabilities", [])
        results.extend(page)
        start_index += len(page)
        log.info("API fallback year=%s fetched=%s/%s", year, start_index, total)

        if not page or start_index >= total:
            break

        time.sleep(API_PAGE_DELAY_SECONDS)

    return results


def fetch_feed(
    session: requests.Session,
    headers: dict,
    year: int,
) -> list[dict]:
    urls = feed_urls_for_year(year)
    log.info("Fetching feed year=%s", year)
    try:
        payload = _load_gzip_json_from_urls(session, urls, f"feed year={year}")
        vulnerabilities = payload.get("vulnerabilities", [])
        log.info("Fetched feed year=%s size=%s", year, len(vulnerabilities))
        return vulnerabilities
    except RuntimeError as feed_exc:
        log.warning(
            "Feed failed for year=%s (%s) -- falling back to REST API", year, feed_exc
        )
        return fetch_year_via_api(session, headers, year)


def fetch_modified_feed(session: requests.Session) -> list[dict]:
    urls = modified_feed_urls()
    log.info("Fetching modified feed snapshot")
    payload = _load_gzip_json_from_urls(session, urls, "modified feed")
    vulnerabilities = payload.get("vulnerabilities", [])
    log.info("Fetched modified feed size=%s", len(vulnerabilities))
    return vulnerabilities


def iter_feeds(
    session: requests.Session,
    headers: dict,
    start_year: int,
    end_year: int,
    override_ids: set[str] | None = None,
    request_delay_seconds: float = 0.0,
):
    override_ids = override_ids or set()
    years = list(iter_feed_years(start_year, end_year))
    for index, year in enumerate(years):
        page = fetch_feed(session, headers, year)
        if override_ids:
            page = [item for item in page if cve_id_for_item(item) not in override_ids]
        yield page

        if request_delay_seconds > 0 and index < len(years) - 1:
            time.sleep(request_delay_seconds)


def fetch_modified_overrides(
    session: requests.Session,
) -> dict[str, dict]:
    overrides = {}
    for item in fetch_modified_feed(session):
        overrides[cve_id_for_item(item)] = item
    log.info("Fetched %s modified-feed override CVEs", len(overrides))
    return overrides


def iter_all_pages(
    session: requests.Session,
    headers: dict,
    start_year: int,
    end_year: int,
    overrides: dict[str, dict],
    request_delay_seconds: float = 0.0,
):
    override_ids = set(overrides)

    yield from iter_feeds(
        session,
        headers,
        start_year,
        end_year,
        override_ids=override_ids,
        request_delay_seconds=request_delay_seconds,
    )

    if overrides:
        yield list(overrides.values())


def write_stream(pages, out_path: str) -> int:
    """Stream an iterator of page-lists into a JSON array file. Returns the total CVE count."""
    count = 0
    with open(out_path, "w") as f:
        f.write("[")
        first = True
        for page in pages:
            for item in page:
                if not first:
                    f.write(",")
                json.dump(item, f, separators=(",", ":"))
                first = False
                count += 1
        f.write("]")
    return count


def write_metadata(
    path: str, cve_count: int, started_at: datetime, finished_at: datetime
) -> None:
    metadata = {
        "last_run_iso": finished_at.isoformat(),
        "cve_count": cve_count,
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "commit_sha": os.environ.get("GITHUB_SHA", "local"),
    }
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "")
    session = build_session()
    headers = build_headers(api_key)
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

    log.info("Fetching NVD feeds for years %s-%s", start_year, end_year)

    try:
        overrides = {}
        if include_modified_overlay:
            log.info("Fetching modified-feed overlay")
            try:
                overrides = fetch_modified_overrides(session)
            except RuntimeError as exc:
                log.warning("Skipping modified-feed overlay due to errors: %s", exc)
                overrides = {}

        cve_count = write_stream(
            iter_all_pages(
                session,
                headers,
                start_year,
                end_year,
                overrides,
                request_delay_seconds=request_delay_seconds,
            ),
            "nvd.json",
        )
    except RuntimeError as exc:
        log.error("Scrape failed before completion: %s", exc)
        return 3

    if cve_count == 0:
        log.error("Scrape produced 0 CVEs -- aborting")
        return 4

    # Duplicate for consumer compatibility (see design §4)
    shutil.copyfile("nvd.json", "nvd.jsonl")

    finished_at = datetime.now(timezone.utc)
    write_metadata("metadata.json", cve_count, started_at, finished_at)

    log.info(
        "Wrote %s CVEs to nvd.json / nvd.jsonl in %ss",
        cve_count,
        (finished_at - started_at).total_seconds(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
