# nvd-scrapper

[![scrape-and-publish](https://github.com/jgamblin/nvd-scrapper/actions/workflows/scrape.yml/badge.svg)](https://github.com/jgamblin/nvd-scrapper/actions/workflows/scrape.yml)
[![monitor-mirror](https://github.com/jgamblin/nvd-scrapper/actions/workflows/monitor.yml/badge.svg)](https://github.com/jgamblin/nvd-scrapper/actions/workflows/monitor.yml)

Public NVD CVE mirror served at <https://nvd.handsonhacking.org/>.

## What this is

Every three hours, GitHub Actions runs `nvd.py`, which pulls the full NVD 2.0 dataset and uploads `nvd.json` and `nvd.jsonl` (both JSON arrays, byte-identical) to a Cloudflare R2 bucket. The bucket is exposed at `nvd.handsonhacking.org` via Cloudflare's R2 custom-domain feature.

The dataset is assembled from two NIST sources:

- **Per-year feed files** (`nvdcve-2.0-<year>.json.gz`), partitioned by CVE-ID year. NIST rebuilds these roughly daily. They are the static backbone.
- **The `modified` feed**, a rolling window of recently changed records. This is the *only* source of every CVE published since NIST's last year-feed rebuild, so it supplies the entire leading edge of the dataset.

## URLs

- `https://nvd.handsonhacking.org/nvd.json` — full CVE dataset as a JSON array (~1.8 GB)
- `https://nvd.handsonhacking.org/nvd.jsonl` — byte-identical copy (historical name)
- `https://nvd.handsonhacking.org/metadata.json` — the manifest, described below

## The manifest

`metadata.json` is about 2 KB, served `Cache-Control: no-cache`, and uploaded **after** the data object, so it never describes a snapshot that is not yet live.

```json
{
  "schema_version": 2,
  "last_run_iso": "2026-08-17T21:25:41.854804+00:00",
  "data_object_key": "nvd.json",
  "bytes": 1787783421,
  "sha256": "…",
  "cve_count": 378606,
  "year_counts": { "1999": 1579, "…": 0 },
  "degraded": false,
  "years_via_api": [],
  "expected_total": 378675,
  "completeness_ratio": 0.9998,
  "duration_seconds": 610.7,
  "commit_sha": "…"
}
```

### For consumers

Fetch the manifest before the 1.8 GB object and refuse to ingest a snapshot that has gone backwards:

- `cve_count` and every entry in `year_counts` should be at or above the last values you accepted. Genuine CVE rejections move these by a handful of records; a drop of hundreds means a bad snapshot.
- `degraded` should be `false` and `years_via_api` empty.
- `sha256` and `bytes` let you verify the object end to end once you have it.

`check_mirror.py` in this repo does exactly that and can be run by anyone:

```bash
python3 check_mirror.py --state ~/.nvd-mirror-state.json
```

It tracks high-water marks, so a regression stays visible until the mirror actually recovers rather than only on the single step down. Exit codes: `0` healthy, `1` regression, `2` mirror unreachable.

Note that watching `Last-Modified` or `ETag` for non-monotonic movement does **not** work as a freshness check here. In every regression this mirror has shipped, the object was freshly published with a correctly advancing `Last-Modified` and simply contained fewer CVEs. Also note that `nvd.json` is far past Cloudflare's 512 MB cacheable-file limit, so it always serves `cf-cache-status: DYNAMIC` straight from R2; there is no edge cache to go stale.

## Publish safety

A run publishes only if every one of these holds. Any failure returns before the upload step, leaving the last-known-good object in R2 untouched.

| Check | Failure mode it catches | Exit |
|---|---|---|
| Baseline manifest readable | A silently skipped regression check | 8 |
| Modified feed fetched and intact | NIST 404s the feed mid-regeneration, or serves it truncated; publishing without it drops the whole leading edge | 7 |
| Year feeds fetched and intact, no REST API substitution | A missing or truncated year feed. No API substitution: the API partitions by publication date, not CVE-ID year, so it silently drops records published in a later year | 3 |
| Per-year and total non-regression vs the published snapshot | Any shrink beyond a small reject allowance | 6 |
| Completeness ratio vs the API's reported total | Gross shortfall the per-year gate somehow missed | 5 |
| `verify_manifest.py`: SHA-256, size vs manifest, array shape, `nvd.jsonl` matches, not degraded, above both the absolute and the relative size floor | A truncated or mismatched upload | 1 |

The baseline manifest is read first, before any crawling. It is the reference for the per-year gates below, so a run that cannot read it fails in seconds rather than after a completed 30-minute crawl.

Both feed kinds share one retry profile: 6 attempts over roughly 8 minutes. They fail the same way (502 from `static.nvd.nist.gov`, 404 from `nvd.nist.gov`) during the same NIST regeneration window, and both are fatal, so neither is less patient than the other. Only the first year that exhausts its retries aborts the run, so the wait is paid once rather than per file.

### Feed integrity

"Fetched" is not the same as "intact". On 2026-08-27 NIST served year feeds that were truncated at the source with no transport-level symptom at all: HTTP 200, a complete CRC-valid gzip stream, well-formed JSON, and a truthful envelope above a near-empty array. `nvdcve-2.0-2022.json.gz` declared `resultsPerPage: 27531` above a `vulnerabilities` array holding one record; six years and the modified feed were each serving 1-18 records. Nothing in the transport layer can see that, because nothing is broken -- the file contradicts itself.

That copy used to be logged as `Fetched feed year=2022 size=1`, an ordinary success, and the shortfall only surfaced 25 feeds later as a 46.9% aggregate ratio that named no years. Two floors now reject it as the failed fetch it is, which puts it on the existing retry ladder and host failover, and makes it fatal for that feed by name if it persists:

1. **The envelope's own count.** Exact, and needs no external reference -- the feed is compared against itself. Checked against `resultsPerPage` rather than `totalResults`, so a paginated year file would still pass.
2. **A sanity floor from the published baseline**, at `FEED_YEAR_MIN_RATIO` of that year's last-published count, applied as each year lands. This catches a feed that is internally consistent but grossly short -- the same failure with a header that has caught up -- which the envelope check is structurally unable to see. Gross shortfall only: the precise rule is the per-year non-regression gate, and this floor has to tolerate drift in the other direction, since a rejected CVE leaves the feed while staying in our snapshot. Note that `nvdcve-2.0-2002.json.gz` is not a single-year partition -- it holds every CVE-ID year up to and including 2002 -- so its floor sums the baseline's 2002-and-earlier years.

The per-year gate is ordered ahead of the global completeness ratio on purpose. Both would fail a short scrape, but the per-year gate says which years are short and by how much, where the ratio only says `46.9%`.

### Environment overrides

| Variable | Default | Effect |
|---|---|---|
| `NVD_API_KEY` | none | NVD REST API key |
| `NVD_FEED_START_YEAR` / `NVD_FEED_END_YEAR` | `2002` / current | Restrict the crawl range (disables full-corpus-only gates) |
| `NVD_INCLUDE_MODIFIED_OVERLAY` | `1` | Set `0` to skip the overlay. A full-corpus run will then fail the non-regression gate, because skipping the overlay is precisely the bug these gates exist to stop |
| `NVD_ALLOW_API_FALLBACK` | off for full-corpus runs | `1` re-enables the REST API fallback. A full-corpus run will still be stopped by the non-regression gate and by `verify_manifest.py`'s `degraded` check, so this is only useful with a restricted range |
| `NVD_ALLOW_MISSING_BASELINE` | unset | `1` publishes without a baseline (bootstrap only) |
| `BASELINE_METADATA_URL` | the public manifest | Where to read the previous run's counts |
| `NVD_USER_AGENT` | rotating pool | Override the User-Agent |

## Monitoring

Two watchdogs run hourly from `monitor.yml`, as separate jobs, because they answer different questions and want different responses.

| Script | Watches | Fails when |
|---|---|---|
| [`check_mirror.py`](check_mirror.py) | the snapshot we publish | `cve_count` or any per-year count drops below the best value ever observed, or the snapshot is flagged `degraded` |
| [`check_feeds.py`](check_feeds.py) | NIST's upstream feeds | a feed is served but holds far fewer records than it declares |

`check_feeds.py` exists because a healthy published snapshot looks identical whether NIST is fine or has been serving truncated feeds for a day -- the mirror watchdog stays green while every scrape run fails, which is correct but leaves "why" to be reconstructed from a failed run log. It opens its own `upstream-feeds` issue, distinct from `scrape-failure`, so a NIST fault is not read as a fault here.

It is cheap enough to run hourly: HEAD per year feed and one small GET for the modified feed, about 26 requests and no meaningful bandwidth. Year feeds are judged on gzipped bytes per expected record, which separates the two populations by three orders of magnitude (321-896 when healthy against 0.06-2.1 when truncated), and the modified feed -- which has no per-year baseline to size against, and matters most, being the sole source of the leading edge -- is fetched and checked against its own envelope with the same `nvd.assert_feed_intact` the scraper uses. An unreachable feed is reported but not failed on: NIST being *down* is what the scraper's retry ladder is for, and this watchdog is for feeds that are up and wrong.

```bash
python3 check_feeds.py
```

## Tests

```bash
python3 -m pytest
```

## Design & plan

- `docs/superpowers/specs/2026-04-24-nvd-migration-design.md`
- `docs/superpowers/plans/2026-04-24-nvd-migration-plan.md`

## License

MIT — see `LICENSE`.
