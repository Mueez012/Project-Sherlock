// Print docs/report/report.html to docs/report/Sherklock_Honed_TTP_Report.pdf with Chromium.
//   node scripts/print-pdf.mjs      (from frontend/)
import { chromium } from "@playwright/test";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const src = resolve(process.cwd(), "../docs/report/report.html");
const out = resolve(process.cwd(), "../docs/report/Sherklock_Honed_TTP_Report.pdf");
const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto(pathToFileURL(src).href, { waitUntil: "load" });
await page.evaluate(async () => {
  await Promise.all([...document.images].map((img) => img.complete ? null : new Promise((r) => { img.onload = img.onerror = r; })));
});
await page.pdf({
  path: out, format: "A4", printBackground: true, preferCSSPageSize: true,
  displayHeaderFooter: true,
  headerTemplate: "<span></span>",
  footerTemplate: '<div style="font-size:8px;width:100%;text-align:center;color:#5d6b7d">Sherklock Honed: TTP extraction report · page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
});
await browser.close();
console.log(out);
