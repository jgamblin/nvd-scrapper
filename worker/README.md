# nvd-scrape-trigger

Cloudflare Worker whose cron (`38 * * * *`, UTC) calls GitHub's
`workflow_dispatch` API for `.github/workflows/scrape.yml`. It is the hourly
trigger for the scrape; GitHub's own cron is only a daily fallback.

## Token

Fine-grained PAT, resource owner `jgamblin`, repository access **only
`jgamblin/nvd-scrapper`**, repository permissions:

- **Actions: Read and write** (the dispatch endpoint needs this)
- Metadata: Read-only (added automatically)

Nothing else.

## Setup

    npm install
    npx wrangler secret put GITHUB_TOKEN   # paste the PAT
    npx wrangler deploy

## Test

Locally, against the real GitHub API (put `GITHUB_TOKEN=...` in `.dev.vars`,
which is gitignored):

    npx wrangler dev --test-scheduled
    curl "http://localhost:8787/__scheduled?cron=38+*+*+*+*"

After deploy, `npx wrangler tail` shows each invocation. A non-204 from
GitHub throws, so it shows up as a failed invocation in the Worker logs.
