// Usage: node scripts/screenshots.mjs <prefix> <path, "home" for /> [themes, e.g. dark,light]
// Saves full-page screenshots at 1440 and 390 px into docs/screenshots/.
import { chromium } from "@playwright/test";

const [prefix = "shot", rawPath = "home", themes = "dark"] = process.argv.slice(2);
const path = rawPath === "home" ? "/" : "/" + rawPath.split("/").filter(Boolean).join("/");
const base = process.env.BASE_URL ?? "http://localhost:3000";
const browser = await chromium.launch();
for (const theme of themes.split(",")) {
  for (const [label, width, height] of [["desktop", 1440, 900], ["mobile", 390, 844]]) {
    const page = await browser.newPage({ viewport: { width, height }, colorScheme: theme === "light" ? "light" : "dark" });
    await page.addInitScript((t) => { try { localStorage.setItem("theme", t); } catch {} }, theme);
    await page.goto(base + path, { waitUntil: "networkidle" });
    await page.waitForTimeout(1500);
    const file = `docs/screenshots/${prefix}-${theme}-${label}.png`;
    await page.screenshot({ path: file, fullPage: true });
    console.log(file);
    await page.close();
  }
}
await browser.close();
