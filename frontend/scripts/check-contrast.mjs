// WCAG 2.x contrast check for src/styles/tokens.css (both themes).
// Text pairs must reach 4.5:1, control borders 3:1. Exits 1 on any failure.
// Run: npm run contrast
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../src/styles/tokens.css", import.meta.url), "utf8");

function block(selector) {
  const start = css.indexOf(selector + " {");
  if (start < 0) throw new Error(`selector not found: ${selector}`);
  const body = css.slice(start, css.indexOf("}", start));
  const vars = {};
  for (const m of body.matchAll(/(--[\w-]+):\s*([^;]+);/g)) vars[m[1]] = m[2].trim();
  return vars;
}

const dark = block(":root");
const light = { ...dark, ...block(':root[data-theme="light"]') };

function hex(value) {
  const h = value.replace("#", "");
  const full = h.length === 3 ? [...h].map((c) => c + c).join("") : h;
  return [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
}

function resolve(vars, name) {
  let value = vars[name];
  for (let i = 0; i < 10 && value?.startsWith("var("); i++) value = vars[value.slice(4, -1).trim()];
  const mix = value?.match(/color-mix\(in srgb, var\((--[\w-]+)\) (\d+)%, var\((--[\w-]+)\)\)/);
  if (mix) {
    const [a, b, w] = [resolve(vars, mix[1]), resolve(vars, mix[3]), Number(mix[2]) / 100];
    return a.map((x, k) => Math.round(x * w + b[k] * (1 - w)));
  }
  if (!value?.startsWith("#")) throw new Error(`${name} is not a hex colour: ${value}`);
  return hex(value);
}

function luminance([r, g, b]) {
  const f = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

const ratio = (a, b) => {
  const [l1, l2] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
};

const TEXT = 4.5, UI = 3;
const pairs = [
  ["--text", "--bg", TEXT], ["--text", "--surface", TEXT], ["--text", "--surface-raised", TEXT],
  ["--text-secondary", "--bg", TEXT], ["--text-secondary", "--surface", TEXT], ["--text-secondary", "--surface-raised", TEXT],
  ["--text-muted", "--bg", TEXT], ["--text-muted", "--surface", TEXT], ["--text-muted", "--surface-raised", TEXT],
  ["--accent-text", "--bg", TEXT], ["--accent-text", "--surface", TEXT], ["--accent-text", "--surface-raised", TEXT],
  ["--on-accent", "--accent", TEXT],
  ["--success", "--surface", TEXT], ["--warning", "--surface", TEXT], ["--danger", "--surface", TEXT],
  ["--success", "--bg", TEXT], ["--warning", "--bg", TEXT], ["--danger", "--bg", TEXT],
  ["--conf-high-text", "--conf-high-bg", TEXT], ["--conf-medium-text", "--conf-medium-bg", TEXT],
  ["--conf-low-text", "--conf-low-bg", TEXT],
  ["--border-control", "--surface", UI], ["--border-control", "--bg", UI], ["--accent", "--surface", UI],
  ["--accent", "--bg", UI],
];

let failures = 0;
for (const [theme, vars] of [["dark", dark], ["light", light]]) {
  console.log(`\n${theme}`);
  for (const [fg, bg, min] of pairs) {
    const r = ratio(resolve(vars, fg), resolve(vars, bg));
    const ok = r >= min;
    if (!ok) failures++;
    console.log(`  ${ok ? "ok  " : "FAIL"} ${fg.padEnd(20)} on ${bg.padEnd(18)} ${r.toFixed(2)}:1 (min ${min})`);
  }
}
console.log(failures ? `\n${failures} pair(s) below the minimum` : "\nall pairs pass");
process.exit(failures ? 1 : 0);
