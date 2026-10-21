import type { Page } from "@playwright/test";

/** The report the mocked specs paste. */
export const REPORT =
  "The actor sent spear-phishing emails with a malicious attachment. A macro launched PowerShell.\n" +
  "The beacon called 10.0.0[.]1 every hour. Mimikatz dumped credentials from LSASS.";

/** What the hub returns for REPORT in stub mode (recorded from the real hub). */
export const HUB_ANSWER = {
  mode: "stub",
  sentences: [
    "The actor sent spear-phishing emails with a malicious attachment.",
    "A macro launched PowerShell.",
    "The beacon called 10.0.0[.]1 every hour.",
    "Mimikatz dumped credentials from LSASS.",
  ],
  ttps: [
    { technique_id: "T1566", score: 1.0, sentence_index: 0 },
    { technique_id: "T1059", score: 0.75, sentence_index: 1 },
    { technique_id: "T1003", score: 1.0, sentence_index: 3 },
  ],
  iocs: [{ type: "ipv4", value: "10.0.0.1", sentence_index: 2 }],
  cskg: null,
  attribution: null,
};

/** Fake hub: POST /api/analyze answers HUB_ANSWER, or a 503 naming a service that is down. */
export async function mockApi(page: Page, { serviceDown = false }: { serviceDown?: boolean } = {}) {
  await page.route("**/api/analyze", async (route) => {
    const body = serviceDown ? { detail: "ttp service unavailable: ConnectError: refused" } : HUB_ANSWER;
    await route.fulfill({ status: serviceDown ? 503 : 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}
