// Two kinds of types live here.
//
// 1. What the hub's HTTP API accepts and returns. These come from the hub's OpenAPI schema
//    (`npm run gen:api` regenerates src/lib/api/schema.d.ts); never edit them by hand.
// 2. The result screen's own view model (AnalysisResult and friends). src/lib/adapt.ts turns the
//    hub's answer into it, so the matrix, technique table and report viewer stay simple. The
//    offline sample in src/mocks/analysis-result.json has the same shape.
import type { components } from "@/lib/api/schema";

type Schemas = components["schemas"];

export type AnalyzeRequest = Schemas["AnalyzeRequest"];
export type AnalyzeResponse = Schemas["AnalyzeResponse"];
export type TTPHit = Schemas["TTPHit"];
export type HubIOC = Schemas["IOC"];

export type ConfidenceBand = "high" | "medium" | "low";

export interface SentenceLabel {
  id: string;
  p: number;
  passed: boolean;
}

export interface Sentence {
  index: number;
  text: string;
  char_start: number;
  char_end: number;
  page?: number | null;
  skipped?: string | null;
  labels: SentenceLabel[];
}

export interface Evidence {
  sentence_index: number;
  text: string;
  probability: number;
  char_start: number;
  char_end: number;
  page?: number | null;
}

export interface Technique {
  id: string;
  name: string;
  tactic_ids: string[];
  url: string;
  confidence: number;
  band: ConfidenceBand;
  mean_confidence: number;
  sentence_count: number;
  /** Only known when the service reports it; the hub does not pass thresholds on. */
  threshold?: number | null;
  evidence: Evidence[];
}

export interface Tactic {
  id: string;
  name: string;
  order?: number;
  url?: string;
  confidence: number;
  /** "model" when predicted directly, "implied_by_technique" when a found technique belongs to it. */
  source: string;
  sentence_count: number;
  technique_ids: string[];
  evidence: Evidence[];
}

/** One indicator of compromise with every sentence it appears in. */
export interface Indicator {
  type: string;
  value: string;
  sentence_indices: number[];
}

export interface DocumentInfo {
  filename?: string | null;
  size_bytes: number;
  pages?: number | null;
  n_sentences: number;
  n_sentences_analyzed: number;
  text: string;
}

export interface ModelInfo {
  name: string;
  version: string;
  threshold_mode: string;
}

export interface Summary {
  n_tactics: number;
  n_techniques: number;
  top_tactic?: string | null;
  confidence_bands: Partial<Record<ConfidenceBand, number>>;
}

export interface AnalysisResult {
  id: string;
  incident_name: string;
  processing_ms: number;
  timings_ms?: Record<string, number>;
  document: DocumentInfo;
  model: ModelInfo;
  summary: Summary;
  tactics: Tactic[];
  techniques: Technique[];
  sentences: Sentence[];
  indicators?: Indicator[];
  warnings: string[];
}

/** Labels for the stage timings some results carry (the offline sample does). */
export const STAGES: readonly { id: string; label: string }[] = [
  { id: "extracting_text", label: "Extracting text" },
  { id: "splitting", label: "Splitting into sentences" },
  { id: "encoding", label: "Encoding sentences" },
  { id: "classifying", label: "Applying thresholds" },
  { id: "aggregating", label: "Building the report" },
];
