import { expect, test } from "@playwright/test";

// Full stack: browser -> Next.js proxy -> hub -> stubs or services. Skipped when the hub is not reachable.
// Works in stub and real mode: the keyword stub and the trained model both find these three techniques.
const REPORT =
  "The actor sent spear-phishing emails with a malicious attachment. A macro launched PowerShell.\n" +
  "Mimikatz dumped credentials from LSASS.";

test("@real analyse a report through the real hub", async ({ page, request }, info) => {
  test.skip(info.project.name !== "desktop-dark", "one real run is enough");
  const probe = await request.post("/api/analyze", { data: { text: "probe." } }).catch(() => null);
  test.skip(!probe || probe.status() !== 200, "hub not running (or a real-mode service is down)");

  await page.goto("/");
  await page.getByRole("button", { name: "New analysis" }).click();
  await page.getByLabel("Incident name").fill("Real hub E2E");
  await page.getByLabel("Report text").fill(REPORT);
  await page.getByRole("button", { name: /analyse report/i }).click();
  await expect(page).toHaveURL(/\/result$/);
  await expect(page.getByRole("heading", { name: "ATT&CK matrix" })).toBeVisible({ timeout: 120_000 });
  const ids = await page.locator(".data-table tbody td:nth-child(2) .mono").allTextContents();
  expect(ids).toEqual(expect.arrayContaining(["T1566", "T1059", "T1003"]));
});
