// Turns the hub's answer (POST /api/analyze) into the result screen's view model.
//
// The hub returns flat per-sentence hits: { technique_id, score, sentence_index } for techniques (T####) and
// tactics (TA####), and { type, value, sentence_index } for indicators. The result screen wants techniques
// with their confidence and evidence, tactics in kill-chain order, sentences with character positions, and
// indicators with every sentence they appear in. Names, links and technique-to-tactic mapping come from the
// bundled ATT&CK catalog.
import { TACTIC_INFO, TECHNIQUE } from "@/lib/attack";
import { bandOf } from "@/lib/confidence";
import type {
  AnalysisResult, AnalyzeResponse, ConfidenceBand, Evidence, Indicator, Sentence, Tactic, Technique,
} from "@/types/analysis";

/** How many supporting sentences a technique shows, strongest first. */
export const EVIDENCE_LIMIT = 5;

export const STUB_WARNING =
  "Stub mode: the techniques come from keyword rules and the indicators from regular expressions, " +
  "not from the trained models.";
export const MIXED_WARNING =
  "Mixed mode: some modules ran as stubs (keyword or regex baselines) instead of the trained models.";

/**
 * Find every sentence in the text, in order, so the report viewer can highlight it. The hub's splitter only
 * trims each piece, so each sentence occurs after the previous one. If any sentence cannot be found (for
 * example pre-split input that is not in the text), the text is rebuilt from the sentences, one per line.
 */
export function locateSentences(text: string, sentences: string[]): { text: string; spans: [number, number][] } {
  const spans: [number, number][] = [];
  let cursor = 0;
  for (const s of sentences) {
    const at = text.indexOf(s, cursor);
    if (at < 0) {
      const rebuilt = sentences.join("\n");
      return locateSentences(rebuilt, sentences);
    }
    cursor = at + s.length;
    spans.push([at, cursor]);
  }
  return { text, spans };
}

/** Highest score per (label, sentence): a sentence counts once per label. */
function bestPerSentence(hits: AnalyzeResponse["ttps"]): Map<string, Map<number, number>> {
  const byLabel = new Map<string, Map<number, number>>();
  for (const h of hits) {
    const sentences = byLabel.get(h.technique_id) ?? new Map<number, number>();
    sentences.set(h.sentence_index, Math.max(h.score, sentences.get(h.sentence_index) ?? 0));
    byLabel.set(h.technique_id, sentences);
  }
  return byLabel;
}

function evidenceFor(scores: Map<number, number>, sentences: Sentence[]): Evidence[] {
  return [...scores.entries()]
    .sort(([ia, pa], [ib, pb]) => pb - pa || ia - ib)
    .map(([index, p]) => {
      const s = sentences[index];
      return { sentence_index: index, text: s.text, probability: p, char_start: s.char_start, char_end: s.char_end, page: null };
    });
}

export interface AdaptInput {
  /** The text the user sent. */
  text: string;
  incidentName: string;
  response: AnalyzeResponse;
  /** Wall-clock time of the request, measured by the browser. */
  processingMs: number;
  id?: string;
}

export function toAnalysisResult({ text, incidentName, response, processingMs, id }: AdaptInput): AnalysisResult {
  const located = locateSentences(text, response.sentences);
  const byLabel = bestPerSentence(response.ttps);

  const sentences: Sentence[] = response.sentences.map((s, index) => ({
    index, text: s, char_start: located.spans[index][0], char_end: located.spans[index][1], page: null, skipped: null,
    labels: [],
  }));
  for (const [label, scores] of byLabel) {
    for (const [index, p] of scores) sentences[index]?.labels.push({ id: label, p, passed: true });
  }
  for (const s of sentences) s.labels.sort((a, b) => b.p - a.p || a.id.localeCompare(b.id));

  const techniques: Technique[] = [...byLabel.entries()]
    .filter(([label]) => /^T\d{4}$/.test(label))
    .map(([label, scores]) => {
      const values = [...scores.values()];
      const confidence = Math.max(...values);
      const known = TECHNIQUE[label];
      return {
        id: label,
        name: known?.name ?? label,
        tactic_ids: known?.tactic_ids ?? [],
        url: known?.url ?? `https://attack.mitre.org/techniques/${label}`,
        confidence,
        band: bandOf(confidence),
        mean_confidence: values.reduce((a, b) => a + b, 0) / values.length,
        sentence_count: values.length,
        threshold: null,
        evidence: evidenceFor(scores, sentences).slice(0, EVIDENCE_LIMIT),
      };
    })
    .sort((a, b) => b.confidence - a.confidence || a.id.localeCompare(b.id));

  const tacticIds = new Set<string>([
    ...[...byLabel.keys()].filter((label) => /^TA\d{4}$/.test(label)),
    ...techniques.flatMap((t) => t.tactic_ids),
  ]);
  const tactics: Tactic[] = [...tacticIds]
    .map((tid) => {
      const scores = byLabel.get(tid);
      const members = techniques.filter((t) => t.tactic_ids.includes(tid));
      const info = TACTIC_INFO[tid];
      return {
        id: tid,
        name: info?.name ?? tid,
        order: info?.order,
        url: info?.url,
        confidence: scores ? Math.max(...scores.values()) : Math.max(...members.map((t) => t.confidence)),
        source: scores ? "model" : "implied_by_technique",
        sentence_count: scores?.size ?? 0,
        technique_ids: members.map((t) => t.id),
        evidence: scores ? evidenceFor(scores, sentences).slice(0, EVIDENCE_LIMIT) : [],
      };
    })
    .sort((a, b) => (a.order ?? 99) - (b.order ?? 99) || a.id.localeCompare(b.id));

  const indicatorMap = new Map<string, Indicator>();
  for (const ioc of response.iocs) {
    const key = `${ioc.type}\u0000${ioc.value}`;
    const entry = indicatorMap.get(key) ?? { type: ioc.type, value: ioc.value, sentence_indices: [] };
    if (!entry.sentence_indices.includes(ioc.sentence_index)) entry.sentence_indices.push(ioc.sentence_index);
    indicatorMap.set(key, entry);
  }
  const indicators = [...indicatorMap.values()]
    .map((i) => ({ ...i, sentence_indices: [...i.sentence_indices].sort((a, b) => a - b) }))
    .sort((a, b) => a.sentence_indices[0] - b.sentence_indices[0] || a.type.localeCompare(b.type) || a.value.localeCompare(b.value));

  const bands: Partial<Record<ConfidenceBand, number>> = { high: 0, medium: 0, low: 0 };
  for (const t of techniques) bands[t.band] = (bands[t.band] ?? 0) + 1;
  const predicted = tactics.filter((t) => t.source === "model");
  const top = [...(predicted.length ? predicted : tactics)].sort((a, b) => b.confidence - a.confidence)[0];

  const warnings: string[] = [];
  if (response.mode === "stub") warnings.push(STUB_WARNING);
  else if (response.mode !== "real") warnings.push(MIXED_WARNING);

  return {
    id: id ?? `local-${Date.now()}`,
    incident_name: incidentName,
    processing_ms: processingMs,
    document: {
      filename: null,
      size_bytes: new TextEncoder().encode(located.text).length,
      pages: null,
      n_sentences: sentences.length,
      n_sentences_analyzed: sentences.length,
      text: located.text,
    },
    model: {
      name: "ThreatMAMBA hub",
      version: `${response.mode} mode`,
      threshold_mode: response.mode === "stub" ? "keyword baseline" : "set by the TTP service",
    },
    summary: { n_tactics: tactics.length, n_techniques: techniques.length, top_tactic: top?.id ?? null, confidence_bands: bands },
    tactics,
    techniques,
    sentences,
    indicators,
    warnings,
  };
}
