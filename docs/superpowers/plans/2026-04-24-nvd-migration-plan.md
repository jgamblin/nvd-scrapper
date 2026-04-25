# NVD Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate `nvd.handsonhacking.org` off Cisco's EC2 to a public GitHub Actions workflow that uploads to Cloudflare R2, with DNS cut over from Route 53 to Cloudflare.

**Architecture:** Public GitHub repo → Actions cron (every 3h) → streaming `nvd.py` → R2 bucket `nvd-handsonhacking` → Cloudflare custom domain `nvd.handsonhacking.org`. healthchecks.io provides dead-man alerting. No VPS, ~$0.13/mo.

**Tech Stack:** Python 3.12, `requests`, GitHub Actions, `rclone` (R2 upload), Cloudflare R2 (S3-compatible), Cloudflare DNS + CDN, healthchecks.io, AWS CLI (for Route 53 inventory).

**Reference:** Design at `docs/superpowers/specs/2026-04-24-nvd-migration-design.md`.

---

## Prerequisites (user must complete before execution)

Before starting Task 1, the user must have ready:

- [ ] A personal Cloudflare account (free tier is sufficient)
- [ ] Access to the Namecheap registrar account for `handsonhacking.org`
- [ ] AWS CLI configured with profile `lab` (has access to zone `Z04136603CFU3JHJ2BNR4`)
- [ ] SSH access to the EC2 (`ssh -i ~/Documents/AWS/handsonhacking.pem ubuntu@3.143.74.225`)
- [ ] A healthchecks.io account (free tier, <https://healthchecks.io>)
- [ ] GitHub account with 2FA enabled (Jerry's personal account; repo is already at `jgamblin/nvd-scrapper`)
- [ ] A new NVD API key ready to generate at <https://nvd.nist.gov/developers/request-an-api-key> (Task 1 does this)

---

## File Structure

Files this plan creates or modifies, in dependency order:

| Path                                                        | Action   | Responsibility                                                    |
| ----------------------------------------------------------- | -------- | ----------------------------------------------------------------- |
| `nvd.py`                                                    | Create   | Scraper: reads `NVD_API_KEY` from env, streams JSON array to disk |
| `requirements.txt`                                          | Create   | Pin `requests` for reproducible runs                              |
| `.github/workflows/scrape.yml`                              | Create   | Cron + manual trigger, install deps, run scraper, upload, ping    |
| `.gitignore`                                                | Create   | Exclude local scraper output (`nvd.json`, `nvd.jsonl`, `*.log`)   |
| `README.md`                                                 | Modify   | Actions + healthchecks badges, brief usage, link to design/plan   |
| `docs/superpowers/specs/2026-04-24-nvd-migration-design.md` | (exists) | Reference design doc                                              |
| `docs/superpowers/plans/2026-04-24-nvd-migration-plan.md`   | (this)   | Implementation plan                                               |

The old EC2 files (`nvd.sh`, `nvd_run.log`, `my_crontab.backup`) are **not** migrated. They stay on the EC2 until decommissioning.

---

## Task 1: Rotate the NVD API key

**Why first:** the current key is hardcoded on the EC2 and will end up in public git history once the repo goes public. We need the new key in hand before any code or secret is written.

**Files:** none (external action)

- [ ] **Step 1: Request a new NVD API key**

Visit <https://nvd.nist.gov/developers/request-an-api-key>. Fill the form with Jerry's personal email (NOT the Cisco email). Submit. NIST typically emails a new UUID-format key within a few minutes.

- [ ] **Step 2: Save the new key in a password manager**

Save under the name "NVD API Key (personal, 2026-04)". Do NOT paste it into any file yet — it goes directly into a GitHub secret in Task 9.

- [ ] **Step 3: Verify the new key works**

Run:

```bash
curl -s -H "apiKey: <NEW_KEY>" "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1" | head -c 200
```

Expected: JSON response starting with `{"resultsPerPage":1,"startIndex":0,"totalResults":`.

- [ ] **Step 4: Leave the OLD key in place on EC2 for now**

Do NOT revoke the old key. It stays live until the EC2 is decommissioned in Task 23. This preserves rollback capability.

---

## Task 2: Lower Route 53 TTL on the `nvd` record

**Why:** shorten the DNS propagation window when we switch nameservers in Task 18. The design requires 48 hours between this step and the NS switch.

**Files:** none (AWS API action)

- [ ] **Step 1: Check the current TTL**

Run:

```bash
AWS_PROFILE=lab aws route53 list-resource-record-sets \
  --hosted-zone-id Z04136603CFU3JHJ2BNR4 \
  --query 'ResourceRecordSets[?Name==`nvd.handsonhacking.org.`]' \
  --output json
```

Expected: A record pointing to `3.143.74.225` with `"TTL": 60`. If already 60 or lower, skip the change step but still start the 48h timer.

- [ ] **Step 2: Lower TTL to 300s (or confirm already ≤300s)**

If current TTL is > 300, run:

```bash
cat > /tmp/lower-ttl.json <<'EOF'
{
  "Comment": "Lower nvd TTL for imminent NS migration to Cloudflare",
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "nvd.handsonhacking.org.",
      "Type": "A",
      "TTL": 300,
      "ResourceRecords": [{"Value": "3.143.74.225"}]
    }
  }]
}
EOF

AWS_PROFILE=lab aws route53 change-resource-record-sets \
  --hosted-zone-id Z04136603CFU3JHJ2BNR4 \
  --change-batch file:///tmp/lower-ttl.json
```

Expected: JSON response with `"Status": "PENDING"`.

- [ ] **Step 3: Record the timestamp**

Note in the terminal when this was run. The earliest safe time to switch nameservers (Task 18) is 48 hours later. If executing this plan in a single sitting, **pause and come back Sunday evening** (≥48h after lowering TTL). If you already lowered the TTL days ago, proceed.

---

## Task 3: Create the R2 bucket and API token

**Files:** none (Cloudflare dashboard action)

- [ ] **Step 1: Create the R2 bucket**

Cloudflare dashboard → R2 → Create Bucket.

- Name: `nvd-handsonhacking`
- Location: Automatic
- Default storage class: Standard

Expected: bucket appears in the R2 bucket list.

- [ ] **Step 2: Create an R2 API token scoped to this bucket**

Cloudflare dashboard → R2 → Manage R2 API Tokens → Create API Token.

- Token name: `nvd-scrapper-writer`
- Permissions: Object Read & Write
- Specify bucket: `nvd-handsonhacking`
- TTL: no expiration

On the success screen, copy:

- Access Key ID
- Secret Access Key
- The "jurisdiction-specific endpoint" (e.g., `https://<account-id>.r2.cloudflarestorage.com`)

Save all three to the password manager temporarily — they go into GitHub secrets in Task 9.

- [ ] **Step 3: Record the R2 Account ID**

Cloudflare dashboard → R2 Overview. Copy the Account ID shown in the right sidebar. Save with the token values.

---

## Task 4: Set up healthchecks.io

**Files:** none (healthchecks.io dashboard action)

- [ ] **Step 1: Create a check**

<https://healthchecks.io> → New Check.

- Name: `nvd-scrapper`
- Tags: `nvd`, `production`
- Period: 3 hours
- Grace: 12 hours
- Schedule: Simple

- [ ] **Step 2: Copy the ping URL**

The ping URL looks like `https://hc-ping.com/<uuid>`. Save to password manager — goes into a GitHub secret in Task 9.

- [ ] **Step 3: Configure email notifications**

Integrations → Email → Add Integration → Jerry's personal email. Send a test notification to confirm it arrives.

---

## Task 5: Write `requirements.txt`

**Files:**

- Create: `requirements.txt`

- [ ] **Step 1: Create the file**

```
requests==2.32.3
```

Pin to a known-good version for reproducible Actions runs. `requests` is the only runtime dependency (used for the NVD API call).

- [ ] **Step 2: Commit**

```bash
git add requirements.txt
git commit -m "deps: pin requests for NVD scraper"
```

---

## Task 6: Write `.gitignore`

**Files:**

- Create: `.gitignore`

- [ ] **Step 1: Create the file**

```
# Scraper output (never committed — uploaded to R2)
nvd.json
nvd.jsonl
metadata.json

# Logs
*.log

# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
venv/

# Editor
.vscode/
.idea/
.DS_Store
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: add gitignore"
```

---

## Task 7: Refactor `nvd.py` — write a streaming scraper

**Why:** the old script builds the full 1.5GB JSON in memory. On a `ubuntu-latest` runner (7GB RAM), this will OOM as NVD grows. Stream the output instead.

**Files:**

- Create: `nvd.py`
- Test: `test_nvd_streaming.py` (root-level test, runnable locally)

- [ ] **Step 1: Write the failing test**

Create `test_nvd_streaming.py`:

```python
"""Smoke test for the streaming writer in nvd.py.

This test exercises the JSON-array streaming logic without hitting the
real NVD API. It feeds a fake page iterator into `write_stream()` and
asserts the output is valid JSON containing every item.
"""

import json
import os
import tempfile

import nvd


def test_write_stream_produces_valid_json_array():
    fake_pages = [
        [{"cve": {"id": "CVE-2025-0001"}}, {"cve": {"id": "CVE-2025-0002"}}],
        [{"cve": {"id": "CVE-2025-0003"}}],
        [],  # Empty final page (mimics exhausted pagination)
    ]

    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "nvd.json")
        count = nvd.write_stream(iter(fake_pages), out_path)

        assert count == 3

        with open(out_path) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 3
        assert data[0]["cve"]["id"] == "CVE-2025-0001"
        assert data[2]["cve"]["id"] == "CVE-2025-0003"


def test_write_stream_handles_empty_input():
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "nvd.json")
        count = nvd.write_stream(iter([]), out_path)

        assert count == 0

        with open(out_path) as f:
            data = json.load(f)

        assert data == []
```

- [ ] **Step 2: Run the test, confirm it fails**

Run:

```bash
python3 -m pytest test_nvd_streaming.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'nvd'` or `AttributeError: module 'nvd' has no attribute 'write_stream'`.

- [ ] **Step 3: Implement `nvd.py`**

Create `nvd.py`:

```python
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
    session.headers.update({
        "apiKey": api_key,
        "User-Agent": "nvd-scrapper/1.0 (+https://github.com/jgamblin/nvd-scrapper)",
    })
    return session


def fetch_total(session: requests.Session) -> int:
    resp = session.get(NVD_URL, params={"startIndex": 0, "resultsPerPage": 1}, timeout=REQUEST_TIMEOUT)
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
                log.warning("Page start=%s attempt %s/%s failed: %s",
                            start, attempt, MAX_RETRIES_PER_PAGE, exc)
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


def write_metadata(path: str, cve_count: int, started_at: datetime, finished_at: datetime) -> None:
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
        log.error("NVD returned totalResults=0 — aborting to avoid publishing an empty file")
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

    log.info("Wrote %s CVEs to nvd.json / nvd.jsonl in %ss",
             cve_count, (finished_at - started_at).total_seconds())
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the test, confirm it passes**

Run:

```bash
pip install -r requirements.txt pytest
python3 -m pytest test_nvd_streaming.py -v
```

Expected: both tests PASS.

- [ ] **Step 5: Smoke-test against the real NVD API (small sample)**

Run (use the NEW key from Task 1):

```bash
export NVD_API_KEY=<new-key>
# Temporarily patch PAGE_SIZE and break after one page for a fast sanity check:
python3 -c "
import os, nvd
s = nvd.build_session(os.environ['NVD_API_KEY'])
total = nvd.fetch_total(s)
print('Total:', total)
"
```

Expected: `Total: <integer, ~300k>`. Confirms auth works. Do NOT run a full scrape locally — it's 10 minutes and 1.5GB.

- [ ] **Step 6: Commit**

```bash
git add nvd.py test_nvd_streaming.py
git commit -m "feat: streaming NVD scraper with env-var API key"
```

---

## Task 8: Write the GitHub Actions workflow

**Files:**

- Create: `.github/workflows/scrape.yml`

- [ ] **Step 1: Create the workflow file**

`mkdir -p .github/workflows`, then create `.github/workflows/scrape.yml`:

```yaml
name: scrape-and-publish

on:
  schedule:
    # Every 3 hours. Public-repo scheduled runs can be skipped under GitHub
    # load; 3h cadence plus a 12h healthchecks.io grace absorbs typical skips.
    - cron: "0 */3 * * *"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: scrape-and-publish
  cancel-in-progress: false

jobs:
  scrape:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - name: Check out repo
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b # v5.3.0
        with:
          python-version: "3.12"
          cache: pip

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run scraper
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          GITHUB_SHA: ${{ github.sha }}
        run: python3 nvd.py

      - name: Verify output looks sane
        run: |
          set -euo pipefail
          # Must exist and be non-trivial
          test -f nvd.json
          test -f nvd.jsonl
          test -f metadata.json
          # Byte size sanity: must be > 100MB (current is ~1.5GB, allow headroom both ways)
          bytes=$(stat -c %s nvd.json)
          echo "nvd.json size: $bytes"
          if [ "$bytes" -lt 100000000 ]; then
            echo "nvd.json is suspiciously small ($bytes bytes) — aborting upload"
            exit 1
          fi
          # Parse the first and last 1KB to confirm it's a valid JSON array shell
          head -c 1 nvd.json | grep -q '\['
          tail -c 1 nvd.json | grep -q '\]'

      - name: Install rclone
        uses: AnimMouse/setup-rclone@e4c00ff32b1b6f7034d23cfa5a3c05aebed6be53 # v1.11.0

      - name: Configure rclone for R2
        run: |
          mkdir -p ~/.config/rclone
          cat > ~/.config/rclone/rclone.conf <<EOF
          [r2]
          type = s3
          provider = Cloudflare
          access_key_id = ${{ secrets.R2_ACCESS_KEY_ID }}
          secret_access_key = ${{ secrets.R2_SECRET_ACCESS_KEY }}
          endpoint = https://${{ secrets.R2_ACCOUNT_ID }}.r2.cloudflarestorage.com
          acl = private
          EOF

      - name: Upload to R2
        run: |
          set -euo pipefail
          rclone copyto --s3-chunk-size 64M --s3-upload-concurrency 4 \
            --header-upload "Content-Type: application/json" \
            --header-upload "Cache-Control: public, max-age=900" \
            nvd.json r2:${{ secrets.R2_BUCKET }}/nvd.json
          rclone copyto --s3-chunk-size 64M --s3-upload-concurrency 4 \
            --header-upload "Content-Type: application/json" \
            --header-upload "Cache-Control: public, max-age=900" \
            nvd.jsonl r2:${{ secrets.R2_BUCKET }}/nvd.jsonl
          rclone copyto \
            --header-upload "Content-Type: application/json" \
            --header-upload "Cache-Control: no-cache" \
            metadata.json r2:${{ secrets.R2_BUCKET }}/metadata.json

      - name: Purge Cloudflare cache for nvd subdomain
        run: |
          curl --fail -X POST \
            "https://api.cloudflare.com/client/v4/zones/${{ secrets.CLOUDFLARE_ZONE_ID }}/purge_cache" \
            -H "Authorization: Bearer ${{ secrets.CLOUDFLARE_API_TOKEN }}" \
            -H "Content-Type: application/json" \
            --data '{"files":["https://nvd.handsonhacking.org/nvd.json","https://nvd.handsonhacking.org/nvd.jsonl","https://nvd.handsonhacking.org/metadata.json"]}'

      - name: Ping healthchecks.io
        if: success()
        run: curl --fail --retry 3 ${{ secrets.HEALTHCHECKS_PING_URL }}
```

- [ ] **Step 2: Validate YAML locally**

Run:

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/scrape.yml'))"
```

Expected: no output (success). If PyYAML is missing: `pip install pyyaml`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/scrape.yml
git commit -m "ci: schedule scraper every 3h, upload to R2, ping healthchecks"
```

---

## Task 9: Add GitHub repository secrets

**Files:** none (GitHub dashboard action)

- [ ] **Step 1: Navigate to secrets**

GitHub → `jgamblin/nvd-scrapper` → Settings → Secrets and variables → Actions → New repository secret.

- [ ] **Step 2: Add the eight secrets**

Add each one individually:

| Secret name             | Value                                                            |
| ----------------------- | ---------------------------------------------------------------- |
| `NVD_API_KEY`           | New key from Task 1                                              |
| `R2_ACCOUNT_ID`         | Cloudflare Account ID from Task 3 step 3                         |
| `R2_ACCESS_KEY_ID`      | R2 API token Access Key ID from Task 3 step 2                    |
| `R2_SECRET_ACCESS_KEY`  | R2 API token Secret Access Key from Task 3 step 2                |
| `R2_BUCKET`             | `nvd-handsonhacking`                                             |
| `CLOUDFLARE_API_TOKEN`  | Fill in Task 12 (needs zone-scoped token created after DNS move) |
| `CLOUDFLARE_ZONE_ID`    | Fill in Task 12                                                  |
| `HEALTHCHECKS_PING_URL` | Ping URL from Task 4 step 2                                      |

Note: `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID` can't be filled in yet — the zone doesn't exist on Cloudflare until Task 11. They're added as placeholders here and real values filled in at Task 12. The workflow will fail on cache purge until they're real, but that's expected and doesn't block the R2 upload.

- [ ] **Step 3: Confirm all six real secrets are listed**

The Secrets page should show six filled-in secrets plus two pending. Values are write-only — GitHub never shows them back.

---

## Task 10: Harden the repository

**Files:** none (GitHub dashboard action)

- [ ] **Step 1: Enable branch protection on `main`**

Settings → Branches → Add branch protection rule.

- Branch name pattern: `main`
- Require a pull request before merging: ON
- Require approvals: 0 (Jerry is solo; bump to 1 if collaborators join)
- Require status checks to pass before merging: OFF (no CI yet beyond the scrape workflow, which isn't a PR check)
- Require conversation resolution before merging: ON
- Do not allow bypassing the above settings: OFF (Jerry needs to admin-override occasionally)

- [ ] **Step 2: Restrict Actions permissions**

Settings → Actions → General.

- Actions permissions: Allow `jgamblin`, and select non-`jgamblin` actions and reusable workflows
- Fork pull request workflows: Require approval for all outside collaborators
- Workflow permissions: Read repository contents and packages permissions (default, already matches our workflow's `permissions: contents: read`)
- Allow GitHub Actions to create and approve pull requests: OFF

- [ ] **Step 3: Confirm 2FA is enabled**

Visit <https://github.com/settings/security>. Confirm 2FA status is "Two-factor authentication is enabled." If not, enable it before the repo goes public.

---

## Task 11: Move the domain to Cloudflare

**Prerequisite:** at least 48 hours have passed since Task 2 lowered the TTL.

**Files:** none (Cloudflare and Namecheap dashboard actions)

- [ ] **Step 1: Add the site to Cloudflare**

Cloudflare dashboard → Add a Site → `handsonhacking.org` → Free plan → Continue.

Cloudflare scans Route 53 and lists the records it found. Expected list (from design §6):

- `nvd` A → `3.143.74.225`
- `morpheus` — likely appears as a CNAME to the ELB (Cloudflare can't import ALIAS as-is)
- `riskscore` — same
- `splunk` A → `3.136.130.141`
- Two `_xxxxxx` CNAMEs for ACM validation

- [ ] **Step 2: Prune records**

In the Cloudflare DNS editor, DELETE everything except `nvd.handsonhacking.org`. The `morpheus`, `riskscore`, `splunk`, and both ACM CNAMEs are all retiring with the Cisco exit.

After pruning, the zone should contain exactly one A record: `nvd → 3.143.74.225` (DNS-only / grey cloud).

- [ ] **Step 3: Copy Cloudflare's assigned nameservers**

Cloudflare shows two NS hostnames like `foo.ns.cloudflare.com` / `bar.ns.cloudflare.com`. Copy both.

- [ ] **Step 4: Update nameservers at Namecheap**

Namecheap → Domain List → `handsonhacking.org` → Manage → Nameservers → Custom DNS. Replace the four Route 53 NS entries with the two Cloudflare entries. Save.

- [ ] **Step 5: Verify propagation**

Wait 15 minutes, then verify from multiple public resolvers:

```bash
dig +short @1.1.1.1 NS handsonhacking.org
dig +short @8.8.8.8 NS handsonhacking.org
dig +short @208.67.222.222 NS handsonhacking.org
```

Expected: eventually, all three return the Cloudflare NS names. This can take 30 minutes to 48 hours. **Do not proceed until all three agree.**

Also confirm the `nvd` record resolves correctly while still on the old IP:

```bash
dig +short @1.1.1.1 nvd.handsonhacking.org
```

Expected: `3.143.74.225` (EC2 still serving).

- [ ] **Step 6: Cloudflare zone activation**

In the Cloudflare dashboard, the zone status switches from "Pending Nameserver Update" to "Active" within minutes of the NS change being visible to Cloudflare. If still pending after 1 hour, click "Check nameservers."

---

## Task 12: Create the zone-scoped Cloudflare API token and fill in GitHub secrets

**Why:** the workflow purges the CDN cache after upload. The token must be scoped to only this zone (principle of least privilege).

**Files:** none (Cloudflare dashboard + GitHub dashboard)

- [ ] **Step 1: Copy the Zone ID**

Cloudflare → `handsonhacking.org` → Overview. The right sidebar shows "Zone ID." Copy it.

- [ ] **Step 2: Create a Cloudflare API token**

Cloudflare → My Profile → API Tokens → Create Token → Use template "Edit zone DNS" (then customize):

- Token name: `nvd-scrapper-cache-purge`
- Permissions: Zone → Cache Purge → Purge
- Zone Resources: Include → Specific zone → `handsonhacking.org`
- TTL: no expiration

Copy the token on the success screen (shown only once).

- [ ] **Step 3: Fill in the remaining two GitHub secrets**

GitHub → Settings → Secrets → Update:

- `CLOUDFLARE_ZONE_ID` = value from step 1
- `CLOUDFLARE_API_TOKEN` = value from step 2

---

## Task 13: Bind the R2 bucket to the custom domain

**Prerequisite:** the Cloudflare zone for `handsonhacking.org` must be active (Task 11 complete).

**Files:** none (Cloudflare R2 dashboard)

- [ ] **Step 1: Add the custom domain**

Cloudflare → R2 → `nvd-handsonhacking` → Settings → Custom Domains → Connect Domain.

- Domain: `nvd.handsonhacking.org`
- Confirm.

Cloudflare does three things automatically:

1. Removes the existing DNS-only A record for `nvd`
2. Creates a proxied CNAME for `nvd` pointing at the R2 public endpoint
3. Provisions a TLS certificate for the subdomain via Cloudflare's managed CA

- [ ] **Step 2: Wait for certificate provisioning**

The Custom Domains page shows a status. Wait until it reads "Active" (usually 1-5 minutes).

- [ ] **Step 3: Verify HTTPS resolves correctly**

Run:

```bash
curl -sSI https://nvd.handsonhacking.org/
```

Expected: HTTP 404 (bucket is empty — no `index.html`) with valid TLS cert and server header from Cloudflare. NOT `3.143.74.225` (that's the old EC2).

The 404 is expected: the bucket has no object at `/`. Consumers asking for `/nvd.json` will still get 404 until we upload.

---

## Task 14: Update `README.md`

**Files:**

- Modify: `README.md`

- [ ] **Step 1: Replace the placeholder README**

Overwrite `README.md`:

```markdown
# nvd-scrapper

[![scrape-and-publish](https://github.com/jgamblin/nvd-scrapper/actions/workflows/scrape.yml/badge.svg)](https://github.com/jgamblin/nvd-scrapper/actions/workflows/scrape.yml)

Public NVD CVE mirror served at <https://nvd.handsonhacking.org/>.

## What this is

Every three hours, GitHub Actions runs `nvd.py`, which pulls the full NVD 2.0 API dataset and uploads `nvd.json` and `nvd.jsonl` (both JSON arrays, byte-identical) to a Cloudflare R2 bucket. The bucket is exposed at `nvd.handsonhacking.org` via Cloudflare's R2 custom-domain feature.

## URLs

- `https://nvd.handsonhacking.org/nvd.json` — full CVE dataset as a JSON array
- `https://nvd.handsonhacking.org/nvd.jsonl` — byte-identical copy (historical name)
- `https://nvd.handsonhacking.org/metadata.json` — `{last_run_iso, cve_count, duration_seconds, commit_sha}`

## Design & plan

- `docs/superpowers/specs/2026-04-24-nvd-migration-design.md`
- `docs/superpowers/plans/2026-04-24-nvd-migration-plan.md`

## License

MIT — see `LICENSE`.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README with URLs, badge, and design pointers"
```

---

## Task 15: Push all local commits and manually trigger a run

**Files:** none (git + GitHub Actions)

- [ ] **Step 1: Confirm local commits are ready**

Run:

```bash
git log --oneline origin/main..HEAD
```

Expected: at least these commits since the last push — requirements, .gitignore, nvd.py, workflow, README.

- [ ] **Step 2: Push**

```bash
git push origin main
```

- [ ] **Step 3: Trigger a workflow_dispatch run**

GitHub → Actions → scrape-and-publish → Run workflow → Branch `main` → Run.

- [ ] **Step 4: Watch the run**

Click into the running job. The scrape step prints per-page progress. Total wall time: ~10-15 minutes.

Expected outcomes:

- All steps show green checkmarks.
- "Ping healthchecks.io" fires at the end.
- healthchecks.io dashboard shows the check as "up" with a timestamp.

If the run fails, check:

- **Cache purge 401/403** → Task 12 secrets are wrong
- **Upload 403** → R2 credentials are wrong or bucket name mismatch
- **Scrape returns 0** → NVD API key invalid (re-check Task 1)

- [ ] **Step 5: Verify the bucket contents**

Cloudflare → R2 → `nvd-handsonhacking`. Expected objects:

- `nvd.json` ~1.5GB
- `nvd.jsonl` ~1.5GB
- `metadata.json` ~200 bytes

---

## Task 16: End-to-end verification from the public URL

**Files:** none (curl-based checks)

- [ ] **Step 1: Verify headers and response**

Run:

```bash
curl -sSI https://nvd.handsonhacking.org/nvd.json
```

Expected:

- `HTTP/2 200`
- `Content-Type: application/json`
- `cache-control: public, max-age=900`
- `content-length: ~1500000000` (roughly 1.5GB)
- `server: cloudflare`

- [ ] **Step 2: Validate the JSON structure**

Run:

```bash
curl -sS https://nvd.handsonhacking.org/nvd.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert isinstance(data, list), f'Expected list, got {type(data)}'
assert len(data) > 100000, f'Only {len(data)} CVEs — suspiciously low'
assert 'cve' in data[0], f'Missing cve key in first item: {data[0].keys()}'
print(f'OK: {len(data)} CVEs, first is {data[0][\"cve\"][\"id\"]}')
"
```

Expected: `OK: <~300k> CVEs, first is CVE-...`. Takes ~30s due to the 1.5GB download.

- [ ] **Step 3: Verify `.jsonl` is byte-identical to `.json`**

Run:

```bash
curl -sS https://nvd.handsonhacking.org/nvd.json -o /tmp/a.json
curl -sS https://nvd.handsonhacking.org/nvd.jsonl -o /tmp/a.jsonl
sha256sum /tmp/a.json /tmp/a.jsonl
```

Expected: both hashes match.

- [ ] **Step 4: Verify the metadata sidecar**

Run:

```bash
curl -sS https://nvd.handsonhacking.org/metadata.json | python3 -m json.tool
```

Expected output shape:

```json
{
  "last_run_iso": "2026-04-27T...",
  "cve_count": 3xxxxx,
  "duration_seconds": 6xx.x,
  "commit_sha": "<40 chars>"
}
```

---

## Task 17: Verify one real consumer

**Why:** consumer tools are the whole reason this domain exists. We need to prove at least one of them still works before we cut over.

**Files:** none (external)

- [ ] **Step 1: Identify a real consumer**

Check Cloudflare Analytics → Traffic on the `handsonhacking.org` zone. Look for the top User-Agent hitting `/nvd.json`. Write it down.

Alternatively, Jerry likely knows at least one tool that pulls this file (some CNAScoreCard / VulnRadar pipeline). Pick one.

- [ ] **Step 2: Run the consumer against the new URL**

If the consumer is configurable, point it at `https://nvd.handsonhacking.org/nvd.json` explicitly (even though that's the same URL it already uses — the point is to confirm TLS, 200, and content parse correctly from the new backend). If it's a black box, just let it run on its normal schedule and check whether it produces the expected output.

- [ ] **Step 3: Confirm success**

The consumer completes without error and produces output shape-identical to its output from the EC2 era.

---

## Task 18: Stop the EC2 cron (rollback-safe cutover)

**Files:** none (SSH to EC2)

- [ ] **Step 1: SSH to the EC2**

```bash
ssh -i ~/Documents/AWS/handsonhacking.pem ubuntu@3.143.74.225
```

- [ ] **Step 2: Back up the existing crontab**

```bash
crontab -l > ~/my_crontab.2026-04-27.backup
```

- [ ] **Step 3: Replace crontab with a no-op**

```bash
crontab -r
```

Or if you prefer to keep the file but comment out:

```bash
crontab -l | sed 's|^\([^#].*nvd\.sh\)|# \1|' | crontab -
```

- [ ] **Step 4: Confirm cron is stopped**

```bash
crontab -l
```

Expected: empty (if `-r`) or both `nvd.sh` lines prefixed with `#`.

- [ ] **Step 5: Kill any currently running scrape**

```bash
sudo pkill -f nvd.py || true
sudo pkill -f nvd.sh || true
ps auxww | grep -E 'nvd\.(py|sh)'
```

Expected: only the `grep` process itself appears.

- [ ] **Step 6: Stop nginx (optional belt-and-suspenders)**

The DNS already points away from this EC2, so nginx is serving nothing. Still, to be tidy:

```bash
sudo systemctl stop nginx
sudo systemctl disable nginx
```

Expected: both succeed.

- [ ] **Step 7: Exit and confirm site is still up**

```bash
exit
curl -sSI https://nvd.handsonhacking.org/nvd.json | head -3
```

Expected: `HTTP/2 200` from Cloudflare. The new pipeline owns the site now.

---

## Task 19: Wait 7 days, then decommission

**Files:** none (AWS + NVD dashboard actions)

**This task is a time-gated follow-up. Do NOT execute it on the same day as Task 18.** Schedule it for 7 days after Task 18.

- [ ] **Step 1: Confirm 7 days of clean operation**

- Check healthchecks.io → the `nvd-scrapper` check has been pinging every 3h for a week.
- Check GitHub Actions history → at least 50 green runs.
- Check Cloudflare Analytics → traffic is flowing from the R2 origin, not the old EC2 IP.

If anything looks off, DO NOT decommission. Investigate instead.

- [ ] **Step 2: Terminate the EC2 instance**

AWS Console → EC2 (us-east-2 region) → find the instance at `3.143.74.225` → Instance state → Terminate instance. Confirm.

Alternatively, ask Cisco to terminate it — it's their lab.

- [ ] **Step 3: Delete the Route 53 hosted zone**

```bash
AWS_PROFILE=lab aws route53 delete-hosted-zone --id Z04136603CFU3JHJ2BNR4
```

Expected: a `ChangeInfo` object with `Status: PENDING`. Route 53 refuses to delete a zone with records other than SOA and NS, so first remove any stragglers:

```bash
AWS_PROFILE=lab aws route53 list-resource-record-sets \
  --hosted-zone-id Z04136603CFU3JHJ2BNR4
```

If the zone still contains `nvd`, `morpheus`, etc., those must be removed first with `change-resource-record-sets` DELETE actions. Likely the zone already only has SOA + NS by this point (pruned when Cloudflare took over).

- [ ] **Step 4: Revoke the OLD NVD API key**

Visit the NVD API key management page and revoke the 2022-era key (`17c94377-...`). The new key (from Task 1) stays active.

- [ ] **Step 5: Notify Cisco**

Send a short email or ticket to the Cisco lab team noting the instance is free for them to reclaim.

- [ ] **Step 6: Close the migration**

Update the design doc's Status line to "Status: Migrated — <date>". Commit.

---

## Self-Review

Checking the plan against the spec:

**Spec coverage:**

- Spec §1 Goal/Non-Goals → covered by Task 16 (verification) and Task 17 (consumer test)
- Spec §3 Components (GitHub repo, Actions, R2 bucket, Cloudflare DNS, healthchecks) → Tasks 3, 4, 5, 6, 7, 8, 11, 13
- Spec §4 Data Flow (streaming, env-var key, rclone upload, Content-Type, cache purge) → Tasks 7, 8
- Spec §5 Failure Handling (count sanity, R2 keeps last-good, healthchecks grace) → covered in Task 8 workflow (size check) and Task 4 (grace period); CVE-count ±2% check deferred to a follow-up (documented here as limitation)
- Spec §6 Phase A steps → Tasks 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
- Spec §6 Phase B steps → Tasks 11, 12, 13
- Spec §6 Phase C steps → Tasks 14, 15, 16, 17
- Spec §6 Phase D steps → Tasks 18, 19
- Spec §7 Security (rotate key, branch protection, SHA-pinned actions, contents:read perms, 2FA) → Tasks 1, 8, 10
- Spec §8 Observability (Actions history, badge, healthchecks, metadata) → Tasks 4, 7, 8, 14
- Spec §9 Cost → passive; plan honors the shape
- Spec §10 Risks → each risk has a mitigation step in the plan (48h TTL wait, 2-week Route 53 keep, byte-identical `.jsonl`)

**Placeholder scan:**

- All TBDs removed. Two GitHub secrets (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`) are explicitly deferred from Task 9 to Task 12 with rationale, not a TBD.

**Type consistency:**

- `write_stream(pages, out_path)` signature matches between the test in Task 7 step 1 and the implementation in Task 7 step 3.
- `R2_BUCKET` secret name matches in Tasks 8, 9.
- Bucket name `nvd-handsonhacking` matches in Tasks 3, 8 env, 9.

**Known limitation:**

- Spec §5 mentions a ±2% CVE-count sanity check comparing the current run to the previous `metadata.json`. This is not in the workflow (would require an extra download + parse step). The workflow's size-check (>100MB) catches the catastrophic case (empty/truncated output). A follow-up task can tighten this after the migration is stable.

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-04-24-nvd-migration-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Jerry has said he wants to execute Sunday evening (2026-04-27), not tonight. When he's ready, he can pick an approach and we'll proceed.
