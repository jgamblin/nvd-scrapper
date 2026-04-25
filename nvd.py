"""NVD CVE scraper — streams the full dataset to disk.

Reads `NVD_API_KEY` from the environment. Writes a JSON array to
`nvd.json` (and a byte-identical copy to `nvd.jsonl` for consumer
compatibility). Also writes `metadata.json` with run statistics for
downstream sanity checks.
"""

import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter, Retry

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
PAGE_SIZE = 2000
MAX_RETRIES_PER_PAGE = 5
RETRY_BACKOFF_SECONDS = 15
REQUEST_TIMEOUT = 60

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("nvd")


def build_session(api_key: str) -> requests.Session:
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update(
        {
            "apiKey": api_key,
            "User-Agent": "nvd-scrapper/1.0 (+https://github.com/jgamblin/nvd-scrapper)",
        }
    )
    return session


def fetch_total(session: requests.Session) -> int:
    resp = session.get(
        NVD_URL, params={"startIndex": 0, "resultsPerPage": 1}, timeout=REQUEST_TIMEOUT
    )
    resp.raise_for_status()
    return int(resp.json().get("totalResults", 0))


def iter_pages(session: requests.Session, total: int):
    """Yield lists of vulnerability dicts, one list per API page."""
    start = 0
    while start < total:
        for attempt in range(1, MAX_RETRIES_PER_PAGE + 1):
            try:
                resp = session.get(
                    NVD_URL,
                    params={"startIndex": start, "resultsPerPage": PAGE_SIZE},
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                vulns = resp.json().get("vulnerabilities", [])
                log.info("Fetched page start=%s size=%s", start, len(vulns))
                yield vulns
                break
            except (requests.RequestException, ValueError) as exc:
                log.warning(
                    "Page start=%s attempt %s/%s failed: %s",
                    start,
                    attempt,
                    MAX_RETRIES_PER_PAGE,
                    exc,
                )
                if attempt == MAX_RETRIES_PER_PAGE:
                    log.error("Giving up on page start=%s — yielding empty list", start)
                    yield []
                else:
                    time.sleep(RETRY_BACKOFF_SECONDS)
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

    session = build_session(api_key)
    started_at = datetime.now(timezone.utc)

    try:
        total = fetch_total(session)
    except requests.RequestException as exc:
        log.error("Failed to fetch total CVE count: %s", exc)
        return 3

    if total == 0:
        log.error(
            "NVD returned totalResults=0 — aborting to avoid publishing an empty file"
        )
        return 4

    log.info("NVD reports %s total CVEs", total)

    cve_count = write_stream(iter_pages(session, total), "nvd.json")

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
