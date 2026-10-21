import type { Page } from "@playwright/test";

import sample from "../../src/mocks/analysis-result.json";

export const JOB_ID = "an_e2e_mock";

const status = (s: string, progress: number, message: string) => ({
  id: JOB_ID, status: s, stage: s, progress, message, incident_name: "E2E incident",
  filename: "synthetic_report.txt", created_at: "2026-10-12T10:00:00Z", updated_at: "2026-10-12T10:00:01Z", error: null,
});

/** Fake backend: upload -> 202, three status polls (encoding, aggregating, completed), result, exports. */
export async function mockApi(page: Page, { failWith }: { failWith?: string } = {}) {
  const sequence = failWith
    ? [{ ...status("failed", 0.1, "failed"), error: { code: failWith, message: "the PDF has no text layer" } }]
    : [status("encoding", 0.4, "Encoding sentences 6 / 14"), status("aggregating", 0.96, "Combining"), status("completed", 1, "done")];
  let polls = 0;
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace("/api/v1", "");
    const json = (body: unknown, code = 200) => route.fulfill({ status: code, contentType: "application/json", body: JSON.stringify(body) });
    if (path === "/analyses" && route.request().method() === "POST") {
      return json({ id: JOB_ID, status: "queued", created_at: "2026-10-12T10:00:00Z",
        links: { self: "", result: "", events: "" } }, 202);
    }
    if (path === "/analyses" && route.request().method() === "GET") return json({ items: [] });
    if (path === `/analyses/${JOB_ID}`) return json(sequence[Math.min(polls++, sequence.length - 1)]);
    if (path === `/analyses/${JOB_ID}/result`) return json({ ...sample, id: JOB_ID, incident_name: "E2E incident" });
    if (path === `/analyses/${JOB_ID}/export`) {
      return route.fulfill({ status: 200, contentType: "text/csv",
        headers: { "Content-Disposition": 'attachment; filename="e2e.csv"' }, body: "technique_id\nT1059\n" });
    }
    return json({ code: "not_found", detail: "mock: unknown path", status: 404 }, 404);
  });
}
