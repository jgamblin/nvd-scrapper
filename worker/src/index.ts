export interface Env {
  GITHUB_TOKEN: string;
  GITHUB_REPO: string;
  WORKFLOW_FILE: string;
  WORKFLOW_REF: string;
}

export default {
  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    const url =
      `https://api.github.com/repos/${env.GITHUB_REPO}` +
      `/actions/workflows/${env.WORKFLOW_FILE}/dispatches`;

    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        // GitHub rejects API requests without a User-Agent, and Workers'
        // fetch does not send one by default.
        "User-Agent": "nvd-scrape-trigger (Cloudflare Worker)",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ref: env.WORKFLOW_REF }),
    });

    const body = await res.text();
    const scheduled = new Date(controller.scheduledTime).toISOString();
    console.log(
      `dispatch ${env.GITHUB_REPO}/${env.WORKFLOW_FILE}@${env.WORKFLOW_REF} ` +
        `(cron ${controller.cron}, scheduled ${scheduled}): HTTP ${res.status}`,
      body.slice(0, 500),
    );

    // 204 is the only success response. Throwing marks the invocation as
    // failed in Worker logs instead of passing it off as a quiet success.
    if (res.status !== 204) {
      throw new Error(`workflow dispatch failed: HTTP ${res.status}: ${body.slice(0, 500)}`);
    }
  },
} satisfies ExportedHandler<Env>;
