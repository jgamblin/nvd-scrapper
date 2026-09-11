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
  "feed_timestamps": { "2026": "2026-08-17T03:00:01+00:00", "modified": "…" },
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
- `feed_timestamps` records the build time of each NIST feed the run consumed. The next run refuses any feed built before these, which is how a CDN edge replaying an older build gets caught at fetch time rather than after the scrape.
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
| Modified feed fetched | NIST 404s the feed mid-regeneration; publishing without it drops the whole leading edge | 7 |
| Year feeds fetched, no REST API substitution | The API partitions by publication date, not CVE-ID year, so it silently drops records published in a later year | 3 |

Both feed kinds share one retry profile: 6 attempts over roughly 8 minutes. They fail the same way (502 from `static.nvd.nist.gov`, 404 from `nvd.nist.gov`) during the same NIST regeneration window, and both are fatal, so neither is less patient than the other. Only the first year that exhausts its retries aborts the run, so the wait is paid once rather than per file.
| Baseline manifest readable | A silently skipped regression check | 8 |
| Per-year and total non-regression vs the published snapshot | Any shrink beyond a small reject allowance | 6 |
| Completeness ratio vs the API's reported total | Gross shortfall | 5 |
| `verify_manifest.py`: SHA-256, size vs manifest, array shape, `nvd.jsonl` matches, not degraded, above both the absolute and the relative size floor | A truncated or mismatched upload | 1 |

### Environment overrides

| Variable | Default | Effect |
|---|---|---|
| `NVD_API_KEY` | none | NVD REST API key |
| `NVD_FEED_START_YEAR` / `NVD_FEED_END_YEAR` | `2002` / current | Restrict the crawl range (disables full-corpus-only gates) |
| `NVD_INCLUDE_MODIFIED_OVERLAY` | `1` | Set `0` to skip the overlay. A full-corpus run will then fail the non-regression gate, because skipping the overlay is precisely the bug these gates exist to stop |
| `NVD_ALLOW_API_FALLBACK` | off for full-corpus runs | `1` re-enables the REST API fallback. A full-corpus run will still be stopped by the non-regression gate and by `verify_manifest.py`'s `degraded` check, so this is only useful with a restricted range |
| `NVD_ALLOW_MISSING_BASELINE` | unset | `1` publishes without a baseline (bootstrap only) |
| `NVD_SKIP_FEED_FRESHNESS` | unset | `1` stops rejecting feeds built before the ones the last published run used. Only needed if NIST republishes a feed with an earlier timestamp, which would otherwise wedge every run. Leaves the coverage gate in place |
| `BASELINE_METADATA_URL` | the public manifest | Where to read the previous run's counts |
| `NVD_USER_AGENT` | rotating pool | Override the User-Agent |

## Tests

```bash
python3 -m pytest
```

## Design & plan

- `docs/superpowers/specs/2026-04-24-nvd-migration-design.md`
- `docs/superpowers/plans/2026-04-24-nvd-migration-plan.md`

## License

MIT — see `LICENSE`.
