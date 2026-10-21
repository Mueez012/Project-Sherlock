// Domain types, re-exported from the OpenAPI schema generated from the FastAPI backend
// (`npm run gen:api`). Do not edit the shapes here; change ttp_api/schemas.py instead.
import type { components } from "@/lib/api/schema";

type Schemas = components["schemas"];

export type AnalysisResult = Schemas["AnalysisResult"];
export type AnalysisOptions = Schemas["AnalysisOptions"];
/** What the client sends: every option is optional (the server fills in defaults). */
export type AnalysisOptionsInput = Partial<AnalysisOptions>;
export type Technique = Schemas["Technique"];
export type Tactic = Schemas["Tactic"];
export type Evidence = Schemas["Evidence"];
export type Sentence = Schemas["Sentence"];
export type SentenceLabel = Schemas["SentenceLabel"];
export type JobStatus = Schemas["JobStatusOut"];
export type JobCreated = Schemas["JobCreated"];
export type JobState = JobStatus["status"];
export type AttackCatalog = Schemas["AttackCatalog"];
export type AttackTactic = Schemas["AttackTactic"];
export type ConfidenceBand = Technique["band"];
export type ExportFormat = "json" | "csv" | "navigator" | "stix";
export type ThresholdMode = NonNullable<AnalysisOptions["threshold_mode"]>;

export const FINISHED: readonly JobState[] = ["completed", "failed"];

export const STAGES: readonly { id: JobState; label: string }[] = [
  { id: "queued", label: "Queued" },
  { id: "extracting_text", label: "Extracting text" },
  { id: "splitting", label: "Splitting into sentences" },
  { id: "encoding", label: "Encoding sentences" },
  { id: "classifying", label: "Applying thresholds" },
  { id: "aggregating", label: "Building the report" },
  { id: "completed", label: "Done" },
];
