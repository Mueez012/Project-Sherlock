import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { JOB_ID, mockApi } from "./mock-api";

const REPORT = Buffer.from(
  "The actor sent spearphishing emails with a malicious attachment. A macro launched PowerShell.\n\n" +
  "The loader created a scheduled task for persistence.");

test("upload -> progress -> results -> export (mocked API)", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Analyse a report" }).first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Incident name").fill("E2E incident");
  await dialog.locator("input[type=file]").setInputFiles({ name: "report.txt", mimeType: "text/plain", buffer: REPORT });
  await dialog.getByRole("button", { name: /start analysis/i }).click();

  await expect(page).toHaveURL(new RegExp(`/analyses/${JOB_ID}$`));
  await expect(page.getByRole("heading", { level: 1, name: "E2E incident" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole("heading", { name: "ATT&CK matrix" })).toBeVisible();

  // Technique table: the strongest row shows its number AND band label.
  const firstRow = page.locator(".data-table tbody tr").first();
  await expect(firstRow.locator(".confidence-badge")).toHaveText(/\d+%\s*High/);

  // "Show in report" highlights the evidence sentence.
  await page.getByRole("button", { name: "Show in report" }).first().click();
  await expect(page.locator("mark.sentence.focus").first()).toBeVisible();

  // Export links point at the API and download.
  const csv = page.getByRole("link", { name: "CSV" });
  await expect(csv).toHaveAttribute("href", `/api/v1/analyses/${JOB_ID}/export?format=csv`);
  const [download] = await Promise.all([page.waitForEvent("download"), csv.click()]);
  expect(download).toBeTruthy();   // the real filename header is checked in real-api.spec.ts

  // No horizontal page scroll at this width.
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("a failed job shows a readable error", async ({ page }) => {
  await mockApi(page, { failWith: "no_text_layer" });
  await page.goto(`/analyses/${JOB_ID}`);
  await expect(page.locator(".error-panel")).toContainText("no text layer");
  await expect(page.locator(".error-panel")).toHaveAttribute("role", "alert");
});

test("keyboard: open dialog, Esc closes it, focus returns to the trigger", async ({ page }, info) => {
  test.skip(info.project.name.startsWith("mobile"), "keyboard flow checked on desktop");
  await mockApi(page);
  await page.goto("/");
  const trigger = page.getByRole("button", { name: "New analysis" });
  await trigger.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByLabel("Incident name")).toBeFocused();
  // Tab stays inside the dialog.
  for (let i = 0; i < 12; i++) await page.keyboard.press("Tab");
  expect(await page.evaluate(() => !!document.activeElement?.closest("[role=dialog]"))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(trigger).toBeFocused();
});

for (const theme of ["dark", "light"] as const) {
  for (const path of ["/", "/sample", `/analyses/${JOB_ID}`]) {
    test(`axe: no serious or critical issues on ${path} (${theme})`, async ({ page }) => {
      await mockApi(page);
      await page.addInitScript((t) => { try { localStorage.setItem("theme", t); } catch { /* ignore */ } }, theme);
      await page.goto(path);
      if (path.startsWith("/analyses")) await expect(page.getByRole("heading", { name: "ATT&CK matrix" })).toBeVisible({ timeout: 15_000 });
      await page.waitForTimeout(800);   // let reveal animations finish
      const results = await new AxeBuilder({ page }).analyze();
      const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
      expect(bad.map((v) => `${v.id}: ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`)).toEqual([]);
    });
  }
}
