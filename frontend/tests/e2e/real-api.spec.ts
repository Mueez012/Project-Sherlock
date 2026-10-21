import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Full stack: browser -> Next.js proxy -> FastAPI -> real model. Skipped when the backend is down.
// The report is SYNTHETIC (Implementation/tests/data/synthetic_report.txt).
const REPORT = resolve(process.cwd(), "../Implementation/tests/data/synthetic_report.txt");   // run from frontend/

test("@real upload a synthetic report through the real API", async ({ page, request }, info) => {
  test.skip(info.project.name !== "desktop-dark", "one real run is enough");
  const health = await request.get("/api/v1/health").catch(() => null);
  test.skip(!health || health.status() !== 200, "backend not running or model not loaded");

  await page.goto("/");
  await page.getByRole("button", { name: "New analysis" }).click();
  await page.getByLabel("Incident name").fill("Real API E2E (synthetic)");
  await page.locator("input[type=file]").setInputFiles({ name: "synthetic_report.txt", mimeType: "text/plain", buffer: readFileSync(REPORT) });
  await page.getByRole("button", { name: /start analysis/i }).click();
  await expect(page).toHaveURL(/\/analyses\/an_/);
  await expect(page.getByRole("heading", { name: "ATT&CK matrix" })).toBeVisible({ timeout: 60_000 });
  const ids = await page.locator(".data-table tbody td:nth-child(2) .mono").allTextContents();
  expect(ids).toEqual(expect.arrayContaining(["T1566", "T1059", "T1003"]));

  const id = page.url().split("/").pop();
  for (const format of ["json", "csv", "navigator", "stix"]) {
    const response = await request.get(`/api/v1/analyses/${id}/export?format=${format}`);
    expect(response.status(), format).toBe(200);
    expect(response.headers()["content-disposition"], format).toContain(`${id}`);
  }
});
