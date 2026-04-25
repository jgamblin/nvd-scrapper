# Migration Design: `nvd.handsonhacking.org` → GitHub Actions + Cloudflare R2

**Date:** 2026-04-24
**Status:** Design — pending user review
**Author:** Jerry Gamblin (with Claude)

## 1. Goal and Non-Goals

### Goal

Retire the Cisco test-lab EC2 instance currently hosting `nvd.handsonhacking.org`. Serve the same `nvd.json` and `nvd.jsonl` files from the same URL with identical observable behavior for all existing consumer tools (5–10 tools, pulling hourly to daily). Target: under $15/mo (actual projection: ~$0.13/mo). Minimize operational surface.

### Non-Goals

- No new features: no landing page, no archive history, no API, no authentication.
- No breaking changes to existing consumers. URLs, file names, and content remain drop-in compatible.
- No refactor of `nvd.py` beyond what's needed to (a) read the API key from env and (b) stream output instead of buffering in memory.

## 2. Current State

| Component          | Value                                                                                               |
| ------------------ | --------------------------------------------------------------------------------------------------- |
| Host               | EC2 Ubuntu 22.04, 4 vCPU, 16GB RAM, 78GB disk (Cisco test lab)                                      |
| Public IP          | 3.143.74.225                                                                                        |
| DNS                | Route 53 hosted zone for `handsonhacking.org`                                                       |
| Scrape script      | `~/nvd/nvd.py` — NVD API 2.0, pagesize=2000, builds full CVE list in memory, writes 1.5GB output    |
| Wrapper            | `~/nvd/nvd.sh` — runs Python, copies output to `/var/www/nvdhandsonhackingorg/html/`                |
| Schedule           | cron: `0 */6 * * *` and `@reboot`, runs via `sudo` inside `screen`                                  |
| Web server         | nginx + Let's Encrypt, serves `nvd.json` and `nvd.jsonl` (byte-identical files)                     |
| Recent reliability | ~20% of runs log `ERROR` (NVD API flakiness; script's internal retries often succeed on next cycle) |
| Hardcoded secret   | NVD API key in `nvd.py` (`17c94377-…`) — **must be rotated before making repo public**              |

## 3. Target Architecture

```
┌──────────────────────────────┐
│  GitHub Actions              │  cron: 0 */3 * * * (every 3h)
│  public repo, free runners   │  + workflow_dispatch
│                              │
│  python3 nvd.py  ─────────▶  │  streams pages as they arrive
│                              │  produces nvd.json (JSON array)
│                              │  and nvd.jsonl (copy — see §4)
│                              │
│  rclone copyto ──────────────┼────▶ Cloudflare R2 bucket
│                              │      nvd-handsonhacking/
│  healthchecks.io ping ───────┼──▶ alerting (free tier)
└──────────────────────────────┘
                                       │
                                       ▼
                        ┌──────────────────────────────┐
                        │  R2 custom domain:           │
                        │  nvd.handsonhacking.org      │
                        │  (Cloudflare edge, free)     │
                        └──────────────────────────────┘
                                       │
                                       ▼
                         existing 5–10 consumer tools
                         (curl / requests / wget)
                         — zero client changes
```

### Components

- **GitHub repo `nvd-scrapper` (public).** Holds `nvd.py`, `.github/workflows/scrape.yml`, `README.md` (with Actions status badge and healthchecks badge), and this design doc.
- **GitHub Actions workflow.** Cron every 3h plus `workflow_dispatch`. Runs on `ubuntu-latest`. Reads secrets, executes scrape, uploads to R2, purges Cloudflare cache, pings healthchecks.io.
- **Cloudflare R2 bucket `nvd-handsonhacking`.** Holds `nvd.json` and `nvd.jsonl`. Public access via custom domain binding. No Worker required for current requirements.
- **Cloudflare DNS.** `handsonhacking.org` moves from Route 53 to Cloudflare (nameserver change at Namecheap). `nvd` subdomain bound to R2 via Cloudflare's native R2 custom domain feature.
- **healthchecks.io.** Free tier. End-of-workflow ping with 12-hour grace period; alerts via email/Discord if no ping arrives.

## 4. Data Flow and Behavior

| Step           | Current (EC2)                                                   | New (GH Actions + R2)                                                                                                                                                    |
| -------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Schedule       | cron `0 */6 * * *` + `@reboot`                                  | GH Actions `cron: '0 */3 * * *'` + `workflow_dispatch`                                                                                                                   |
| API key        | hardcoded in `nvd.py`                                           | `NVD_API_KEY` env var from GH secret                                                                                                                                     |
| Scrape output  | Full list buffered in memory, then `json.dumps` to 1.5GB string | **Streaming:** write the JSON array to disk incrementally as pages arrive (open file, write `[`, emit each CVE with a comma, close with `]`). Memory stays flat (~50MB). |
| File semantics | `nvd.json` and `nvd.jsonl` byte-identical (JSON array in both)  | **Unchanged.** Both files remain byte-identical JSON arrays so every existing consumer keeps working. Switching to true JSONL is deferred (see §11 Out of Scope).        |
| Publish        | `cp` to `/var/www/.../html/`                                    | `rclone copyto` to R2 with 64MB chunks, explicit `Content-Type`                                                                                                          |
| Serve          | nginx + Let's Encrypt on EC2                                    | Cloudflare edge, TLS managed by Cloudflare                                                                                                                               |
| URLs           | `https://nvd.handsonhacking.org/nvd.json` and `/nvd.jsonl`      | **Identical URLs.** Custom domain bound to R2 bucket.                                                                                                                    |
| Cache behavior | nginx direct serve, no CDN                                      | Cloudflare edge cache; purged explicitly after each upload                                                                                                               |
| Observability  | `~/nvd/nvd_run.log` on EC2                                      | GH Actions run history + healthchecks.io alerts + Actions badge in README                                                                                                |

**Note on `nvd.jsonl`:** Today the file is named `.jsonl` but contains a JSON array. We preserve that exact shape so existing consumers (some of which likely do `json.load(f)` regardless of extension) keep working byte-for-byte. Switching to true newline-delimited JSON is a breaking change and is out of scope for this migration (see §11).

## 5. Failure Handling

| Failure                                                      | Current behavior                                                                                             | New behavior                                                                                                                                                                                                                                |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NVD API transient failure                                    | Script retries internally (5 attempts, 15s backoff). If exhausted, batch is skipped and file may be partial. | Same retry logic preserved. After upload, workflow verifies CVE count is within ±2% of previous run (fetched from R2 via `HEAD` + small JSON sidecar `metadata.json`); on mismatch, skip upload and fail the run so healthchecks.io alerts. |
| NVD API prolonged outage                                     | Silent — stale file remains served                                                                           | Same — R2 keeps last successful upload. healthchecks.io fires after 12h without a ping.                                                                                                                                                     |
| GH Actions cron skipped                                      | N/A                                                                                                          | Every-3h cadence absorbs skips; 12h silence threshold still gives multiple chances before alerting.                                                                                                                                         |
| R2 upload failure                                            | N/A                                                                                                          | Workflow step fails → run marked red → no healthchecks ping → alert after 12h. Previous object remains served.                                                                                                                              |
| Bad data published (e.g., empty array)                       | Possible today (no validation)                                                                               | ±2% count check catches large regressions before upload.                                                                                                                                                                                    |
| Schedule disabled after repo inactivity (GitHub 60-day rule) | N/A                                                                                                          | Every push resets the clock; the workflow itself commits nothing, but any README tweak or dependency bump keeps it live. Alert fires if runs stop.                                                                                          |

## 6. Migration Steps

Executed in order. Each step is verifiable before moving to the next.

**Phase A — Prepare (no user-visible changes)**

1. **Rotate NVD API key.** Request a new key from the NVD dashboard. Old key stays on EC2 and keeps working.
2. **Lower Route 53 TTLs to 300s** for all records. Wait 48h before any NS change.
3. **Inventory Route 53.** `aws route53 list-resource-record-sets --hosted-zone-id ...`. Save the full record list. Confirm with user what non-`nvd` records exist (MX, SPF/DKIM/DMARC, other subdomains).
4. **Create Cloudflare account** (if none). Add `handsonhacking.org` as a site. Let Cloudflare scan Route 53 and import records.
5. **Reconcile records.** Diff Cloudflare's imported set against the Route 53 inventory. Manually recreate anything missed. Do NOT proceed until every record is verified in the Cloudflare dashboard.
6. **Create R2 bucket** `nvd-handsonhacking`. Generate an R2 API token scoped to write access on that bucket.
7. **Refactor `nvd.py`** to read `NVD_API_KEY` from env and write the JSON array incrementally (streaming).
8. **Write `.github/workflows/scrape.yml`** with cron, secrets, rclone upload, cache purge, healthchecks ping.
9. **Add GitHub secrets:** `NVD_API_KEY`, `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`, `HEALTHCHECKS_PING_URL`.
10. **Enable branch protection** on `main` (PR review required). Set workflow permissions to `contents: read`. Confirm 2FA on GitHub account.

**Phase B — DNS cutover**

11. **Switch nameservers** at Namecheap from Route 53's NS to Cloudflare's. Verify with `dig @1.1.1.1`, `@8.8.8.8`, `@208.67.222.222` until all resolvers return Cloudflare's NS. Leave Route 53 zone live for 2 weeks as a safety net.
12. **Bind custom domain** `nvd.handsonhacking.org` to the R2 bucket (Cloudflare dashboard → R2 → Settings → Custom Domains). Requires Cloudflare-authoritative DNS, which is now true.

**Phase C — Activate new pipeline**

13. **Merge `nvd.py` + workflow PR** to main.
14. **Make repo public.**
15. **Trigger `workflow_dispatch`.** Confirm files land in R2; confirm `https://nvd.handsonhacking.org/nvd.json` returns 200 with correct `Content-Type` and byte count; parse-test the JSON.
16. **Verify one real consumer** end-to-end.

**Phase D — Decommission old pipeline**

17. **Run parallel for 24h.** EC2 keeps scraping (into its local nginx) while Actions scrapes into R2. Public DNS already points at R2 — EC2 is the rollback target.
18. **Stop EC2 cron** (`crontab -r` on the EC2). Leave the instance running another 7 days.
19. **Final teardown.** After 7 clean days: terminate EC2 instance, delete Route 53 hosted zone, revoke old NVD API key, notify Cisco the lab instance is free.

## 7. Security

| Concern                                               | Mitigation                                                                                                                                                                         |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Old NVD API key in git history once repo goes public  | Rotate before step 10 (making repo public). Old key can still sit on EC2 during parallel-run window.                                                                               |
| Malicious PR modifying workflow to exfiltrate secrets | GitHub setting: "Require approval for all outside contributors." Branch protection on `main` requires review. Workflow permissions set to `contents: read` only.                   |
| Third-party action supply-chain attack                | Every third-party action pinned to a full commit SHA, not a tag. Minimal action surface: only official `actions/checkout` and `actions/setup-python`, plus `rclone/rclone` pinned. |
| Compromised GH account force-pushes poisoned scraper  | Branch protection requires PR review. 2FA required on account. Optional: CODEOWNERS for `.github/workflows/`.                                                                      |
| Secrets leaked in logs                                | GitHub auto-masks secrets in logs. `set -x` explicitly disabled in workflow.                                                                                                       |

## 8. Observability

- **GitHub Actions run history.** Per-run logs, 90 days retention.
- **Actions status badge** in README (public, shows last run status at a glance).
- **healthchecks.io.** 3h cadence × 12h grace period. On failure, email alert. Upgrade path: add Discord/Slack webhook later.
- **Metadata sidecar.** Each successful run uploads `metadata.json` with `{last_run_iso, cve_count, commit_sha, duration_seconds}`. Consumers (and future me) can self-check.
- **Cloudflare Analytics.** Free tier shows request volume per path — useful for seeing if traffic matches expectations, and for identifying the 5–10 consumers empirically.

## 9. Cost Estimate

| Item                                                                                                                  | Cost                                       |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| GitHub Actions (public repo)                                                                                          | $0 (unlimited minutes on standard runners) |
| R2 storage (3GB × $0.015/GB-mo)                                                                                       | $0.045/mo                                  |
| R2 Class A ops (writes, multipart at 64MB chunks: ~26 parts × 2 objects × 8 runs/day × 30 days ≈ 12,500/mo × $4.50/M) | $0.06/mo                                   |
| R2 Class B ops (reads, estimate 50k/mo; $0.36/M)                                                                      | $0.02/mo                                   |
| Cloudflare DNS + CDN                                                                                                  | $0                                         |
| healthchecks.io                                                                                                       | $0 (free tier: 20 checks)                  |
| **Total**                                                                                                             | **~$0.13/mo**                              |

Effective cost is zero-ish. Even if consumer traffic is 10× my estimate, total stays well under $1/mo.

## 10. Risks and Open Questions

| Risk                                                                                      | Mitigation / Open question                                                                                                     |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| DNS migration breaks email (MX/SPF/DKIM/DMARC)                                            | Record inventory (step 3) is the gate. User confirms what email, if any, is on `handsonhacking.org`.                           |
| Route 53 → Cloudflare nameserver change takes longer than 48h to propagate                | Keep Route 53 zone live 2 weeks post-switch. Lower TTLs 48h ahead.                                                             |
| Some consumer expected the exact byte-for-byte JSON array shape of `nvd.jsonl`            | Keeping `.jsonl` file as a JSON array preserves compatibility. Reconsider true JSONL only after confirming no consumer breaks. |
| NVD API adds new rate-limiting or auth requirements                                       | Out of scope; would need a fix in the scraper regardless of hosting.                                                           |
| **Open question:** does `handsonhacking.org` host email or other services besides `nvd.`? | User to confirm before step 3. If yes, step 3's inventory becomes load-bearing.                                                |

## 11. Out of Scope (Explicit)

- Adding gzip/brotli compression to reduce bandwidth. (Not needed — R2 egress is free; consumers see the same 1.5GB they see today.)
- Splitting the scrape into incremental updates. (Possible future improvement; out of scope for drop-in migration.)
- Switching to a true JSONL format. (Breaking change for consumers; needs confirmation first.)
- Moving to a tiny VPS (Hetzner, Lightsail). (User explicitly chose no-VPS shape.)
- Rewriting `nvd.py` in a different language or framework. (YAGNI.)

## 12. Success Criteria

The migration is done when all of these are true:

1. `https://nvd.handsonhacking.org/nvd.json` returns a 200 with the full NVD dataset, served from R2.
2. `https://nvd.handsonhacking.org/nvd.jsonl` returns a 200 with the same content.
3. `Content-Type: application/json` is set on both responses.
4. At least one real consumer tool has been verified working end-to-end.
5. GitHub Actions workflow has completed ≥3 successful runs on schedule.
6. healthchecks.io is configured and has received ≥1 ping.
7. EC2 cron has been stopped and no production traffic has hit EC2 for ≥7 days.
8. Total monthly cost (Cloudflare + GitHub + healthchecks) is ≤ $5/mo.
9. NVD API key in the old (hardcoded) location has been revoked.
