# nvd-scrapper

[![scrape-and-publish](https://github.com/jgamblin/nvd-scrapper/actions/workflows/scrape.yml/badge.svg)](https://github.com/jgamblin/nvd-scrapper/actions/workflows/scrape.yml)

Public NVD CVE mirror served at <https://nvd.handsonhacking.org/>.

## What this is

Every three hours, GitHub Actions runs `nvd.py`, which pulls the full NVD 2.0 API dataset and uploads `nvd.json` and `nvd.jsonl` (both JSON arrays, byte-identical) to a Cloudflare R2 bucket. The bucket is exposed at `nvd.handsonhacking.org` via Cloudflare's R2 custom-domain feature.

## URLs

- `https://nvd.handsonhacking.org/nvd.json` — full CVE dataset as a JSON array
- `https://nvd.handsonhacking.org/nvd.jsonl` — byte-identical copy (historical name)
- `https://nvd.handsonhacking.org/metadata.json` — `{last_run_iso, cve_count, duration_seconds, commit_sha, degraded, years_via_api, expected_total, completeness_ratio, year_counts}` (`year_counts` maps each CVE-ID year to its count and powers the per-year coverage guard)

## Design & plan

- `docs/superpowers/specs/2026-04-24-nvd-migration-design.md`
- `docs/superpowers/plans/2026-04-24-nvd-migration-plan.md`

## License

MIT — see `LICENSE`.
