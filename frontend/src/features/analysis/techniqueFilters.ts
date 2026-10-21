import type { ConfidenceBand, Technique } from "@/types/analysis";

export type SortKey = "confidence" | "sentence_count" | "id";
export type SortDir = "asc" | "desc";

export interface TechniqueFilter {
  query: string;
  tactic: string;           // "" = all
  band: ConfidenceBand | ""; // "" = all
  minConfidence: number;    // 0..1
}

export const NO_FILTER: TechniqueFilter = { query: "", tactic: "", band: "", minConfidence: 0 };

export function filterTechniques(list: Technique[], f: TechniqueFilter): Technique[] {
  const q = f.query.trim().toLowerCase();
  return list.filter((t) =>
    (!q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
      || t.evidence.some((e) => e.text.toLowerCase().includes(q)))
    && (!f.tactic || t.tactic_ids.includes(f.tactic))
    && (!f.band || t.band === f.band)
    && t.confidence >= f.minConfidence);
}

export function sortTechniques(list: Technique[], key: SortKey, dir: SortDir): Technique[] {
  const sign = dir === "asc" ? 1 : -1;
  return [...list].sort((a, b) => {
    const primary = key === "id" ? a.id.localeCompare(b.id) : a[key] - b[key];
    return sign * primary || b.confidence - a.confidence || a.id.localeCompare(b.id);
  });
}
