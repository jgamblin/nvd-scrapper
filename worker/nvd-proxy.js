// Cloudflare Worker that proxies requests to the NVD API 2.0 endpoint.
//
// Why this exists:
//   NVD's WAF returns 404 to requests from GitHub Actions runner IPs,
//   even with a valid apiKey and browser-like User-Agent. Cloudflare
//   Workers have trusted egress IPs that NVD accepts.
//
// Deployment:
//   - Bound route / subdomain: nvd-proxy.jgamblin.workers.dev (or similar)
//   - Secret binding: NVD_API_KEY (set via `wrangler secret put` or the
//     dashboard "Settings -> Variables and Secrets" panel)
//   - No caching. No logging. Zero business logic. Just forward.
//
// Access control:
//   The caller must present the header `X-Proxy-Token` that matches the
//   Worker secret `PROXY_TOKEN`. Keeps the Worker private. (NVD API key
//   stays inside the Worker and never leaves.)
//
// Usage from the scraper:
//   GET https://<worker>/rest/json/cves/2.0/?startIndex=0&resultsPerPage=1
//   Headers:
//     X-Proxy-Token: <PROXY_TOKEN>
//   The Worker strips X-Proxy-Token, adds apiKey from its secret, and
//   forwards to services.nvd.nist.gov.

const NVD_ORIGIN = "https://services.nvd.nist.gov";

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/58.0.3029.110 Safari/537.3";

export default {
  async fetch(request, env) {
    // Auth: require shared secret on every request
    const token = request.headers.get("x-proxy-token");
    if (!token || token !== env.PROXY_TOKEN) {
      return new Response("forbidden", { status: 403 });
    }

    // Only GET is ever needed for NVD scraping
    if (request.method !== "GET") {
      return new Response("method not allowed", { status: 405 });
    }

    // Rebuild the URL against NVD's origin, preserving path and query
    const incoming = new URL(request.url);
    const target = new URL(incoming.pathname + incoming.search, NVD_ORIGIN);

    const upstream = await fetch(target.toString(), {
      method: "GET",
      headers: {
        "User-Agent": BROWSER_UA,
        apiKey: env.NVD_API_KEY,
        Accept: "application/json",
      },
      // Don't let the Worker cache — we want fresh data every call
      cf: { cacheTtl: 0, cacheEverything: false },
    });

    // Pass body + status through; drop hop-by-hop headers implicitly
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "Content-Type":
          upstream.headers.get("Content-Type") || "application/json",
      },
    });
  },
};
