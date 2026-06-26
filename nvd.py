"""NVD CVE scraper — streams the full dataset to disk.

Reads `NVD_API_KEY` from the environment. Writes a JSON array to
`nvd.json` (and a byte-identical copy to `nvd.jsonl` for consumer
compatibility). Also writes `metadata.json` with run statistics.
"""

import json
import logging
import os
import shutil
import sys
import time
import gzip
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone

import requests
import urllib3.exceptions

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
PAGE_SIZE = 2000
MAX_RETRIES_PER_PAGE = 5
RETRY_BACKOFF_SECONDS = 15
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


def fetch_total(session: requests.Session, headers: dict) -> int:
    url = f"{NVD_BASE}?startIndex=0&resultsPerPage=1"
    resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return int(resp.json().get("totalResults", 0))


def iter_feed_years(start_year: int = 2002, end_year: int | None = None):
    if end_year is None:
        end_year = datetime.now(timezone.utc).year

    for year in range(start_year, end_year + 1):
        yield year


def feed_url_for_year(year: int) -> str:
    return f"{NVD_FEED_BASE}/nvdcve-2.0-{year}.json.gz"


def cve_id_for_item(item: dict) -> str:
    return item["cve"]["id"]


def format_api_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def fetch_feed(session: requests.Session, year: int):
    url = feed_url_for_year(year)
    log.info("Fetching feed year=%s", year)

    for attempt in range(1, MAX_RETRIES_PER_PAGE + 1):
        try:
            with session.get(url, timeout=REQUEST_TIMEOUT, stream=True) as resp:
                resp.raise_for_status()
                resp.raw.decode_content = False
                with gzip.GzipFile(fileobj=resp.raw) as gz_stream:
                    payload = json.load(gz_stream)

            vulnerabilities = payload.get("vulnerabilities", [])
            log.info("Fetched feed year=%s size=%s", year, len(vulnerabilities))
            return vulnerabilities
        except (OSError, requests.RequestException, ValueError, urllib3.exceptions.HTTPError) as exc:
            if attempt == MAX_RETRIES_PER_PAGE:
                raise RuntimeError(
                    f"Failed to fetch feed year={year} after {MAX_RETRIES_PER_PAGE} attempts"
                ) from exc

            delay = _retry_delay_seconds(exc, attempt)
            log.warning(
                "Feed year=%s attempt %s/%s failed: %s; retrying in %.1fs",
                year,
                attempt,
                MAX_RETRIES_PER_PAGE,
                exc,
                delay,
            )
            time.sleep(delay)


def iter_feeds(
    session: requests.Session,
    start_year: int,
    end_year: int,
    override_ids: set[str] | None = None,
    request_delay_seconds: float = 0.0,
):
    override_ids = override_ids or set()
    years = list(iter_feed_years(start_year, end_year))
    for index, year in enumerate(years):
        page = fetch_feed(session, year)
        if override_ids:
            page = [item for item in page if cve_id_for_item(item) not in override_ids]
        yield page

        if request_delay_seconds > 0 and index < len(years) - 1:
            time.sleep(request_delay_seconds)


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


def iter_pages(
    session: requests.Session,
    headers: dict,
    total: int,
    request_delay_seconds: float = 0.0,
):
    """Yield lists of vulnerability dicts, one list per API page."""
    start = 0
    while start < total:
        url = f"{NVD_BASE}?resultsPerPage={PAGE_SIZE}&startIndex={start}"
        page_ok = False
        for attempt in range(1, MAX_RETRIES_PER_PAGE + 1):
            try:
                resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                vulns = resp.json().get("vulnerabilities", [])
                log.info("Fetched page start=%s size=%s", start, len(vulns))
                yield vulns
                page_ok = True
                break
            except (requests.RequestException, ValueError, urllib3.exceptions.HTTPError) as exc:
                if attempt == MAX_RETRIES_PER_PAGE:
                    raise RuntimeError(
                        f"Failed to fetch page startIndex={start} after "
                        f"{MAX_RETRIES_PER_PAGE} attempts"
                    ) from exc

                delay = _retry_delay_seconds(exc, attempt)
                log.warning(
                    "Page start=%s attempt %s/%s failed: %s; retrying in %.1fs",
                    start,
                    attempt,
                    MAX_RETRIES_PER_PAGE,
                    exc,
                    delay,
                )
                time.sleep(delay)

        if not page_ok:
            raise RuntimeError(f"Page fetch failed without success for startIndex={start}")

        if request_delay_seconds > 0 and start + PAGE_SIZE < total:
            time.sleep(request_delay_seconds)

        start += PAGE_SIZE


def iter_modified_pages(
    session: requests.Session,
    headers: dict,
    last_mod_start: datetime,
    last_mod_end: datetime,
    request_delay_seconds: float = 0.0,
):
    params = {
        "resultsPerPage": PAGE_SIZE,
        "lastModStartDate": format_api_datetime(last_mod_start),
        "lastModEndDate": format_api_datetime(last_mod_end),
    }
    start = 0
    total = None

    while total is None or start < total:
        page_ok = False
        for attempt in range(1, MAX_RETRIES_PER_PAGE + 1):
            try:
                resp = session.get(
                    NVD_BASE,
                    headers=headers,
                    params={**params, "startIndex": start},
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                payload = resp.json()
                total = int(payload.get("totalResults", 0))
                vulns = payload.get("vulnerabilities", [])
                log.info(
                    "Fetched modified page start=%s size=%s total=%s",
                    start,
                    len(vulns),
                    total,
                )
                yield vulns
                page_ok = True
                break
            except (requests.RequestException, ValueError, urllib3.exceptions.HTTPError) as exc:
                if attempt == MAX_RETRIES_PER_PAGE:
                    raise RuntimeError(
                        f"Failed to fetch modified page startIndex={start} after "
                        f"{MAX_RETRIES_PER_PAGE} attempts"
                    ) from exc

                delay = _retry_delay_seconds(exc, attempt)
                log.warning(
                    "Modified page start=%s attempt %s/%s failed: %s; retrying in %.1fs",
                    start,
                    attempt,
                    MAX_RETRIES_PER_PAGE,
                    exc,
                    delay,
                )
                time.sleep(delay)

        if not page_ok:
            raise RuntimeError(
                f"Modified page fetch failed without success for startIndex={start}"
            )

        if total == 0:
            break

        start += PAGE_SIZE

        if request_delay_seconds > 0 and start < total:
            time.sleep(request_delay_seconds)


def fetch_modified_overrides(
    session: requests.Session,
    headers: dict,
    last_mod_start: datetime,
    last_mod_end: datetime,
    request_delay_seconds: float = 0.0,
) -> dict[str, dict]:
    overrides = {}
    for page in iter_modified_pages(
        session,
        headers,
        last_mod_start,
        last_mod_end,
        request_delay_seconds=request_delay_seconds,
    ):
        for item in page:
            overrides[cve_id_for_item(item)] = item

    log.info("Fetched %s API override CVEs", len(overrides))
    return overrides


def iter_all_pages(
    session: requests.Session,
    start_year: int,
    end_year: int,
    overrides: dict[str, dict],
    request_delay_seconds: float = 0.0,
):
    override_ids = set(overrides)

    yield from iter_feeds(
        session,
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
    session = build_session()
    started_at = datetime.now(timezone.utc)
    api_key = os.environ.get("NVD_API_KEY")

    request_delay_seconds = float(os.environ.get("NVD_REQUEST_DELAY_SECONDS", "0"))
    start_year = int(os.environ.get("NVD_FEED_START_YEAR", "2002"))
    end_year = int(
        os.environ.get("NVD_FEED_END_YEAR", str(datetime.now(timezone.utc).year))
    )
    include_api_delta = os.environ.get("NVD_INCLUDE_API_DELTA", "1") != "0"
    delta_window_hours = int(os.environ.get("NVD_API_DELTA_WINDOW_HOURS", "48"))

    if start_year > end_year:
        log.error("Invalid feed year range: %s > %s", start_year, end_year)
        return 2

    log.info("Fetching NVD feeds for years %s-%s", start_year, end_year)

    try:
        overrides = {}
        if include_api_delta:
            delta_end = datetime.now(timezone.utc)
            delta_start = delta_end - timedelta(hours=delta_window_hours)
            log.info(
                "Fetching API delta for last-modified window %s to %s",
                format_api_datetime(delta_start),
                format_api_datetime(delta_end),
            )
            overrides = fetch_modified_overrides(
                session,
                build_headers(api_key) if api_key else {},
                delta_start,
                delta_end,
                request_delay_seconds=request_delay_seconds,
            )

        cve_count = write_stream(
            iter_all_pages(
                session,
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
        log.error("Scrape produced 0 CVEs — aborting")
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
