// End-to-end walkthrough of the REAL system (frontend :3000 -> proxy -> FastAPI :8001 -> model).
// Takes a screenshot at every step and records every API call and every server-side
// stage change with timestamps. Output: ../docs/walkthrough/{shots/*.png, steps.json, exports/}
//
//   node scripts/walkthrough.mjs
//
// Real public CISA advisories (eval_data/demo, kept outside the frontend repo) and synthetic test files.
import { chromium } from "@playwright/test";
import { mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const API = process.env.API_URL ?? "http://127.0.0.1:8001";
const OUT = resolve(process.cwd(), "../docs/walkthrough");
const DATA = resolve(process.cwd(), "../Implementation/tests/data");   // synthetic test files
const REAL = resolve(process.cwd(), "../eval_data/demo");               // real CISA advisories (ids removed from text)
rmSync(OUT, { recursive: true, force: true });
mkdirSync(`${OUT}/shots`, { recursive: true });
mkdirSync(`${OUT}/exports`, { recursive: true });

const t0 = Date.now();
const ms = () => Date.now() - t0;
const steps = [];
const network = [];
const serverTimeline = [];
let shotNo = 0;

async function shot(page, id, title, extra = {}, { fullPage = false, locator = null } = {}) {
  shotNo += 1;
  const file = `shots/${String(shotNo).padStart(2, "0")}-${id}.png`;
  if (locator) await locator.screenshot({ path: `${OUT}/${file}` });
  else await page.screenshot({ path: `${OUT}/${file}`, fullPage });
  steps.push({ n: shotNo, id, title, file, t_ms: ms(), url: page.url(), ...extra });
  console.log(`${String(shotNo).padStart(2, "0")} ${title}`);
}

async function pollServer(jobId, stopWhen) {
  // Independent 100 ms poll of the API, to log every stage change the server makes.
  let last = "";
  for (let i = 0; i < 1200; i++) {
    const r = await fetch(`${API}/api/v1/analyses/${jobId}`);
    const s = await r.json();
    const key = `${s.stage}|${s.message}`;
    if (key !== last) {
      serverTimeline.push({ t_ms: ms(), job: jobId, stage: s.stage, progress: s.progress, message: s.message });
      last = key;
    }
    if (stopWhen(s)) return s;
    await new Promise((r2) => setTimeout(r2, 100));
  }
  throw new Error("job did not finish");
}

const settle = (p, msDelay = 450) => p.waitForTimeout(msDelay);   // let 200 ms fades finish before a screenshot
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark", acceptDownloads: true });
const page = await context.newPage();
page.on("request", (req) => {
  if (req.url().includes("/api/v1/")) network.push({ t_ms: ms(), dir: "request", method: req.method(), url: req.url().replace(BASE, "") });
});
page.on("response", async (res) => {
  if (!res.url().includes("/api/v1/")) return;
  const entry = { t_ms: ms(), dir: "response", status: res.status(), url: res.url().replace(BASE, "") };
  try {
    const type = res.headers()["content-type"] ?? "";
    if (type.includes("json") && !res.url().includes("/result") && !res.url().includes("/export")) {
      const body = await res.json();
      entry.summary = body.stage ? `${body.stage} ${Math.round((body.progress ?? 0) * 100)}% "${body.message}"` : (body.id ? `id=${body.id} status=${body.status}` : undefined);
    }
  } catch { /* body not available */ }
  network.push(entry);
});

// ---------- 1. backend ready
const health = await (await fetch(`${API}/api/v1/health`)).json();
const model = await (await fetch(`${API}/api/v1/model`)).json();
await page.goto(`${API}/docs`);
await page.waitForSelector(".opblock", { timeout: 15000 });
await shot(page, "api-docs", "Backend: FastAPI interactive documentation (/docs)", { health, model: { version: model.version, run_id: model.run_id, model_type: model.model_type, threshold_mode: model.threshold_mode } });

// ---------- 2. landing
await page.goto(BASE + "/", { waitUntil: "networkidle" });
await page.waitForTimeout(800);
await shot(page, "landing", "Landing page (hero, sample result, call to action)");
await page.locator("#how").scrollIntoViewIfNeeded();
await page.waitForTimeout(900);
await shot(page, "how-it-works", "How it works: the four processing steps", {}, { locator: page.locator("#how") });

// ---------- 3. upload dialog
await page.getByRole("button", { name: "Analyse a report" }).first().click();
const dialog = page.getByRole("dialog");
await dialog.waitFor();
await settle(page);
await shot(page, "dialog-open", "Upload dialog opened (focus moves to the incident name)");
await dialog.getByRole("button", { name: /start analysis/i }).click();
await settle(page, 200);
await shot(page, "dialog-validation", "Client-side validation: empty name and missing file are reported before anything is sent");
await dialog.getByLabel("Incident name").fill("CISA AA24-109A: Akira ransomware");
await dialog.locator("input[type=file]").setInputFiles(`${REAL}/CISA-AA24-109A-Akira.stix.json`);
await shot(page, "dialog-filled", "Real report chosen: CISA advisory AA24-109A (Akira ransomware) as a STIX 2.1 bundle");
await dialog.getByText("Advanced options").click();
await settle(page, 200);
await shot(page, "dialog-advanced", "Advanced options: threshold mode, minimum evidence, tactic hierarchy");

// ---------- 4. submit and follow the job
const submitAt = ms();
await dialog.getByRole("button", { name: /start analysis/i }).click();
await page.waitForURL(/\/analyses\/an_/, { timeout: 30000 });
const jobId = page.url().split("/").pop();
const serverDone = pollServer(jobId, (s) => s.status === "completed" || s.status === "failed");
const seen = new Set();
for (let i = 0; i < 300; i++) {
  const done = await page.getByRole("heading", { name: "ATT&CK matrix" }).count();
  if (done) break;
  const label = (await page.locator(".progress-message").textContent().catch(() => null))?.split("·")[0].trim();
  const stage = await page.locator(".stage-list li.active").textContent().catch(() => null);
  const key = `${stage}|${label}`;
  if (label && !seen.has(key) && seen.size < 4) {
    seen.add(key);
    await shot(page, `progress-${seen.size}`, `Progress view: ${stage?.replace(/\(in progress\)/, "").trim() ?? "waiting"}`, { ui_message: label });
  }
  await page.waitForTimeout(150);
}
const final = await serverDone;
await page.getByRole("heading", { name: "ATT&CK matrix" }).waitFor({ timeout: 60000 });
await page.waitForTimeout(500);
const result = await (await fetch(`${API}/api/v1/analyses/${jobId}/result`)).json();
await shot(page, "results-top", "Results: summary, stage timings, export bar and warnings", { job: jobId, final_status: final.status, wall_ms: ms() - submitAt });
await shot(page, "results-full", "Results page, full length", {}, { fullPage: true });
const compare = page.locator("section[aria-labelledby=compare-title]");
await compare.scrollIntoViewIfNeeded();
await page.waitForTimeout(600);   // the panel loads the ATT&CK catalogue
await shot(page, "compare", "Model vs. the ATT&CK techniques CISA declared for this advisory", {}, { locator: compare });

// ---------- 5. matrix, table, evidence
await page.locator("#matrix-title").scrollIntoViewIfNeeded();
await shot(page, "matrix", "ATT&CK matrix: 14 tactics in kill-chain order, techniques as chips with confidence", {},
  { locator: page.locator("section[aria-labelledby=matrix-title]") });
const table = page.locator("section[aria-labelledby=table-title]");
await table.scrollIntoViewIfNeeded();
await table.locator("tbody tr").first().getByRole("button", { name: /show evidence/i }).click();
await shot(page, "table-evidence", "Technique table with the first row expanded: evidence sentences and their probabilities", {}, { locator: table });
await table.getByLabel("Confidence band").selectOption("medium");
await page.waitForTimeout(200);
await shot(page, "table-medium", "Filter: only medium-confidence techniques (passed the 0.6 threshold, below 80%)",
  { medium_count: await table.locator("tbody tr:not(.evidence-row)").count() }, { locator: table });
await table.getByLabel("Confidence band").selectOption("");
await table.getByRole("button", { name: "Show in report" }).first().click();
await page.waitForTimeout(1200);
await shot(page, "report-highlight", "\"Show in report\": the report viewer scrolls to and highlights the evidence sentence");
await page.locator("mark.sentence.focus").first().click();
await page.waitForTimeout(300);
await shot(page, "sentence-panel", "Clicking a highlighted sentence shows every label the model gave it",
  {}, { locator: page.locator("section[aria-labelledby=report-title]") });

// ---------- 6. exports
const exports = [];
for (const [label, format] of [["JSON", "json"], ["CSV", "csv"], ["Navigator layer", "navigator"], ["STIX 2.1", "stix"]]) {
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: label }).click()]);
  const path = `${OUT}/exports/${download.suggestedFilename()}`;
  await download.saveAs(path);
  exports.push({ format, file: download.suggestedFilename(), bytes: statSync(path).size });
}
await page.evaluate(() => window.scrollTo(0, 0));
await shot(page, "exports", "Export bar: JSON, CSV, ATT&CK Navigator layer and STIX 2.1 downloaded", { exports },
  { locator: page.locator(".export-menu") });

// ---------- 6b. a long pasted report, to see the progress view while the model is encoding
const longText = readFileSync(`${REAL}/CISA-AA24-038A-Volt-Typhoon.txt`, "utf8");
await page.getByRole("button", { name: "New analysis" }).click();
await page.getByLabel("Incident name").fill("CISA AA24-038A: Volt Typhoon (pasted text)");
await page.getByRole("tab", { name: /paste text/i }).click();
await page.getByRole("textbox", { name: "Report text" }).fill(longText);
await settle(page);
await shot(page, "paste-text", "Paste-text option: the long Volt Typhoon advisory (CISA AA24-038A) pasted as plain text");
const longStart = ms();
await page.getByRole("button", { name: /start analysis/i }).click();
await page.waitForURL((u) => /\/analyses\/an_/.test(u.pathname) && !u.pathname.endsWith(jobId), { timeout: 30000 });
const longJob = page.url().split("/").pop();
const longDone = pollServer(longJob, (s) => s.status === "completed" || s.status === "failed");
const seenLong = new Set();
for (let i = 0; i < 400; i++) {
  if (await page.getByRole("heading", { name: "ATT&CK matrix" }).count()) break;
  const label = (await page.locator(".progress-message").textContent().catch(() => null))?.split("·")[0].trim();
  if (label && label.startsWith("Encoding sentences") && !label.includes(" 0 /") && !seenLong.has(label) && seenLong.size < 2) {
    seenLong.add(label);
    await shot(page, `progress-encoding-${seenLong.size}`, "Progress view while the model encodes sentences batch by batch", { ui_message: label });
  }
  await page.waitForTimeout(120);
}
const longFinal = await longDone;
await page.getByRole("heading", { name: "ATT&CK matrix" }).waitFor({ timeout: 120000 });
const longResult = await (await fetch(`${API}/api/v1/analyses/${longJob}/result`)).json();
steps.push({ n: null, id: "long-job", title: "long job finished", t_ms: ms(), job: longJob, final_status: longFinal.status,
  wall_ms: ms() - longStart, sentences: longResult.document.n_sentences_analyzed, timings_ms: longResult.timings_ms });
await page.goto(`${BASE}/analyses/${jobId}`, { waitUntil: "networkidle" });
await page.getByRole("heading", { name: "ATT&CK matrix" }).waitFor();

// ---------- 7. themes and mobile
await page.evaluate(() => { localStorage.setItem("theme", "light"); document.documentElement.setAttribute("data-theme", "light"); });
await page.waitForTimeout(300);
await shot(page, "results-light", "Same result in the light theme (theme toggle in the header)");
const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, colorScheme: "dark" });
await mobile.goto(`${BASE}/analyses/${jobId}`, { waitUntil: "networkidle" });
await mobile.getByRole("heading", { name: "ATT&CK matrix" }).waitFor();
await shot(mobile, "results-mobile", "Mobile width (390 px): cards stack, matrix scrolls inside its box", {}, { fullPage: true });
await mobile.close();
await page.evaluate(() => { localStorage.setItem("theme", "dark"); document.documentElement.setAttribute("data-theme", "dark"); });

// ---------- 8. scanned PDF (OCR) and an unsupported file
await page.goto(BASE + "/");
await page.getByRole("button", { name: "New analysis" }).click();
await page.getByLabel("Incident name").fill("Scanned copy (OCR test)");
await page.locator("input[type=file]").setInputFiles(`${DATA}/synthetic_campaign_scanned.pdf`);
const ocrStart = ms();
await page.getByRole("button", { name: /start analysis/i }).click();
await page.waitForURL(/\/analyses\/an_/);
const ocrJob = page.url().split("/").pop();
await pollServer(ocrJob, (s) => s.status === "completed" || s.status === "failed");
await page.getByRole("heading", { name: "ATT&CK matrix" }).waitFor({ timeout: 60000 });
await page.waitForTimeout(400);
const ocrResult = await (await fetch(`${API}/api/v1/analyses/${ocrJob}/result`)).json();
await shot(page, "ocr-result", "Scanned PDF (no text layer): text read with OCR, warning shown", { job: ocrJob, wall_ms: ms() - ocrStart });

await page.getByRole("button", { name: "New analysis" }).click();
await page.getByLabel("Incident name").fill("Wrong file");
await page.locator("input[type=file]").setInputFiles({ name: "tool.exe", mimeType: "application/octet-stream", buffer: Buffer.from("MZ") });
await page.getByRole("button", { name: /start analysis/i }).click();
await settle(page);
await shot(page, "unsupported-file", "An .exe is rejected in the browser with a readable message");
const serverReject = await fetch(`${API}/api/v1/analyses`, { method: "POST", body: (() => { const f = new FormData(); f.append("file", new Blob(["MZ"]), "tool.exe"); return f; })() });
const rejectBody = await serverReject.json();
await page.keyboard.press("Escape");

// ---------- 9. history
await page.goto(BASE + "/#recent", { waitUntil: "networkidle" });
await page.waitForTimeout(800);
await shot(page, "recent", "Recent analyses (kept in SQLite, so they survive a server restart)", {},
  { locator: page.locator("#recent") });

await browser.close();

const summary = {
  generated_at: new Date().toISOString(),
  base: BASE, api: API, health, model,
  main_job: { id: jobId, document: { ...result.document, text: undefined }, summary: result.summary,
              timings_ms: result.timings_ms, processing_ms: result.processing_ms, warnings: result.warnings,
              techniques: result.techniques.map((t) => ({ id: t.id, name: t.name, confidence: t.confidence, band: t.band,
                tactics: t.tactic_ids, sentences: t.sentence_count, evidence: t.evidence[0]?.text })),
              tactics: result.tactics.map((t) => ({ id: t.id, name: t.name, confidence: t.confidence, source: t.source })) },
  ocr_job: { id: ocrJob, warnings: ocrResult.warnings, n_techniques: ocrResult.summary.n_techniques,
             timings_ms: ocrResult.timings_ms, sentences: ocrResult.document.n_sentences_analyzed },
  server_reject: { status: serverReject.status, body: rejectBody },
  exports, steps, network, serverTimeline,
};
writeFileSync(`${OUT}/steps.json`, JSON.stringify(summary, null, 2));
console.log(`done: ${shotNo} screenshots, ${network.length} API events -> ${OUT}`);
JSON.parse(readFileSync(`${OUT}/steps.json`, "utf8"));
