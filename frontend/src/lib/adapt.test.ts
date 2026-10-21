import { describe, expect, it } from "vitest";

import type { AnalyzeResponse } from "@/types/analysis";

import { EVIDENCE_LIMIT, MIXED_WARNING, STUB_WARNING, locateSentences, toAnalysisResult } from "./adapt";

const TEXT = "Spear-phishing led to PowerShell.  C2 was 10.0.0[.]1.\nJ\nMimikatz dumped LSASS. The C2 host 10.0.0.1 again.";
const SENTENCES = ["Spear-phishing led to PowerShell.", "C2 was 10.0.0[.]1.", "J", "Mimikatz dumped LSASS.", "The C2 host 10.0.0.1 again."];

function response(overrides: Partial<AnalyzeResponse> = {}): AnalyzeResponse {
  return {
    mode: "real",
    sentences: SENTENCES,
    ttps: [
      { technique_id: "T1566", score: 0.93, sentence_index: 0 },
      { technique_id: "TA0001", score: 0.88, sentence_index: 0 },
      { technique_id: "T1059", score: 0.6, sentence_index: 0 },
      { technique_id: "T1071", score: 0.7, sentence_index: 1 },
      { technique_id: "T1071", score: 0.5, sentence_index: 4 },
      { technique_id: "T1003", score: 0.99, sentence_index: 3 },
    ],
    iocs: [
      { type: "ipv4", value: "10.0.0.1", sentence_index: 4 },
      { type: "ipv4", value: "10.0.0.1", sentence_index: 1 },
    ],
    cskg: null,
    attribution: null,
    ...overrides,
  };
}

const adapt = (r: AnalyzeResponse = response()) => toAnalysisResult({ text: TEXT, incidentName: "Op", response: r, processingMs: 1234 });

describe("locateSentences", () => {
  it("finds every sentence in order, including one-letter ones", () => {
    const { text, spans } = locateSentences(TEXT, SENTENCES);
    expect(text).toBe(TEXT);
    spans.forEach(([start, end], i) => expect(TEXT.slice(start, end)).toBe(SENTENCES[i]));
  });
  it("rebuilds the text when a sentence is not in it", () => {
    const { text, spans } = locateSentences("unrelated", ["A.", "B."]);
    expect(text).toBe("A.\nB.");
    expect(spans).toEqual([[0, 2], [3, 5]]);
  });
});

describe("toAnalysisResult", () => {
  it("aggregates each technique: best score, mean, sentence count, strongest evidence first", () => {
    const t1071 = adapt().techniques.find((t) => t.id === "T1071");
    expect(t1071).toMatchObject({ confidence: 0.7, band: "medium", mean_confidence: 0.6, sentence_count: 2, threshold: null });
    expect(t1071?.evidence.map((e) => e.sentence_index)).toEqual([1, 4]);
    expect(t1071?.evidence[0].text).toBe("C2 was 10.0.0[.]1.");
  });

  it("takes names, links and tactics from the catalog, and sorts techniques by confidence", () => {
    const { techniques } = adapt();
    expect(techniques.map((t) => t.id)).toEqual(["T1003", "T1566", "T1071", "T1059"]);
    expect(techniques[0]).toMatchObject({ name: "OS Credential Dumping", tactic_ids: ["TA0006"], url: "https://attack.mitre.org/techniques/T1003", band: "high" });
  });

  it("keeps a technique the catalog does not know, by its id", () => {
    const t = adapt(response({ ttps: [{ technique_id: "T9999", score: 0.5, sentence_index: 0 }] })).techniques[0];
    expect(t).toMatchObject({ id: "T9999", name: "T9999", tactic_ids: [] });
  });

  it("marks tactics predicted by the model and tactics implied by a found technique, in kill-chain order", () => {
    const { tactics } = adapt();
    const initial = tactics.find((t) => t.id === "TA0001");
    expect(initial).toMatchObject({ source: "model", confidence: 0.88, sentence_count: 1 });
    expect(initial?.technique_ids).toEqual(["T1566"]);
    const credential = tactics.find((t) => t.id === "TA0006");
    expect(credential).toMatchObject({ source: "implied_by_technique", confidence: 0.99, evidence: [] });
    const orders = tactics.map((t) => t.order ?? 99);
    expect(orders).toEqual([...orders].sort((a, b) => a - b));
  });

  it("gives every sentence its position and its labels, all passed", () => {
    const { sentences, document } = adapt();
    sentences.forEach((s) => expect(document.text.slice(s.char_start, s.char_end)).toBe(s.text));
    expect(sentences[0].labels.map((l) => l.id)).toEqual(["T1566", "TA0001", "T1059"]);
    expect(sentences[0].labels.every((l) => l.passed)).toBe(true);
    expect(sentences[2].labels).toEqual([]);
  });

  it("keeps every sentence an indicator appears in", () => {
    expect(adapt().indicators).toEqual([{ type: "ipv4", value: "10.0.0.1", sentence_indices: [1, 4] }]);
  });

  it("summarises counts, confidence bands and the strongest predicted tactic", () => {
    const r = adapt();
    expect(r.summary).toMatchObject({ n_techniques: 4, top_tactic: "TA0001", confidence_bands: { high: 2, medium: 2, low: 0 } });
    expect(r.document).toMatchObject({ filename: null, n_sentences: 5, n_sentences_analyzed: 5 });
    expect(r.processing_ms).toBe(1234);
    expect(r.incident_name).toBe("Op");
  });

  it("caps the evidence list", () => {
    const many = Array.from({ length: EVIDENCE_LIMIT + 3 }, (_, i) => `Sentence ${i}.`);
    const r = toAnalysisResult({
      text: many.join(" "), incidentName: "Op", processingMs: 1,
      response: response({ sentences: many, iocs: [], ttps: many.map((_, i) => ({ technique_id: "T1059", score: 0.5 + i / 100, sentence_index: i })) }),
    });
    expect(r.techniques[0].evidence).toHaveLength(EVIDENCE_LIMIT);
    expect(r.techniques[0].sentence_count).toBe(many.length);
  });

  it("warns when the hub ran stubs, and not in real mode", () => {
    expect(adapt().warnings).toEqual([]);
    expect(adapt(response({ mode: "stub" })).warnings).toEqual([STUB_WARNING]);
    expect(adapt(response({ mode: "mixed" })).warnings).toEqual([MIXED_WARNING]);
  });
});
