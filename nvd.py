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
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
PAGE_SIZE = 2000
MAX_RETRIES_PER_PAGE = 5
RETRY_BACKOFF_SECONDS = 15
REQUEST_TIMEOUT = 60

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
            except (requests.RequestException, ValueError) as exc:
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
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        log.error("NVD_API_KEY is not set")
        return 2

    session = build_session()
    headers = build_headers(api_key)
    started_at = datetime.now(timezone.utc)

    try:
        total = fetch_total(session, headers)
    except requests.RequestException as exc:
        log.error("Failed to fetch total CVE count: %s", exc)
        return 3

    if total == 0:
        log.error(
            "NVD returned totalResults=0 — aborting to avoid publishing an empty file"
        )
        return 4

    log.info("NVD reports %s total CVEs", total)

    request_delay_seconds = float(os.environ.get("NVD_REQUEST_DELAY_SECONDS", "0"))

    try:
        cve_count = write_stream(
            iter_pages(session, headers, total, request_delay_seconds=request_delay_seconds),
            "nvd.json",
        )
    except RuntimeError as exc:
        log.error("Scrape failed before completion: %s", exc)
        return 6

    if cve_count == 0:
        log.error("Scrape produced 0 CVEs but total was %s — aborting", total)
        return 5

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
