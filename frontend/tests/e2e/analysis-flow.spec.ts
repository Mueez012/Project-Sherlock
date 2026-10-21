import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { REPORT, mockApi } from "./mock-api";

/** Open the dialog, paste REPORT and analyse it. */
async function analyse(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Analyse a report" }).first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Incident name").fill("E2E incident");
  await dialog.getByLabel("Report text").fill(REPORT);
  await dialog.getByRole("button", { name: /analyse report/i }).click();
}

test("paste -> results (mocked hub)", async ({ page }) => {
  await mockApi(page);
  await analyse(page);

  await expect(page).toHaveURL(/\/result$/);
  await expect(page.getByRole("heading", { level: 1, name: "E2E incident" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "ATT&CK matrix" })).toBeVisible();
  await expect(page.getByText(/Stub mode/)).toBeVisible();

  // Technique table: the strongest row shows its number AND band label.
  const firstRow = page.locator(".data-table tbody tr").first();
  await expect(firstRow.locator(".confidence-badge")).toHaveText(/\d+%\s*High/);

  // "Show in report" highlights the evidence sentence.
  await page.getByRole("button", { name: "Show in report" }).first().click();
  await expect(page.locator("mark.sentence.focus").first()).toBeVisible();

  // Indicators are listed with their sentence number.
  await expect(page.getByRole("heading", { name: "Indicators" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "10.0.0.1" })).toBeVisible();

  // A refresh keeps the result (sessionStorage).
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "E2E incident" })).toBeVisible();

  // No horizontal page scroll at this width.
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("a service that is down shows the hub's reason", async ({ page }) => {
  await mockApi(page, { serviceDown: true });
  await analyse(page);
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("ttp service unavailable");
});

test("without an analysis, /result explains what to do", async ({ page }) => {
  await page.goto("/result");
  await expect(page.getByRole("heading", { name: "No analysis yet" })).toBeVisible();
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
  for (const path of ["/", "/sample", "/result"]) {
    test(`axe: no serious or critical issues on ${path} (${theme})`, async ({ page }) => {
      await mockApi(page);
      await page.addInitScript((t) => { try { localStorage.setItem("theme", t); } catch { /* ignore */ } }, theme);
      if (path === "/result") {
        await analyse(page);
        await expect(page.getByRole("heading", { name: "ATT&CK matrix" })).toBeVisible();
      } else {
        await page.goto(path);
      }
      await page.waitForTimeout(800);   // let reveal animations finish
      const results = await new AxeBuilder({ page }).analyze();
      const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
      expect(bad.map((v) => `${v.id}: ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`)).toEqual([]);
    });
  }
}
