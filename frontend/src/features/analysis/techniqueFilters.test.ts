import { describe, expect, it } from "vitest";

import sample from "@/mocks/analysis-result.json";
import type { AnalysisResult } from "@/types/analysis";

import { NO_FILTER, filterTechniques, sortTechniques } from "./techniqueFilters";

const techniques = (sample as AnalysisResult).techniques;

describe("technique filters", () => {
  it("sorts by confidence, sentence count and id in both directions", () => {
    const desc = sortTechniques(techniques, "confidence", "desc").map((t) => t.confidence);
    expect(desc).toEqual([...desc].sort((a, b) => b - a));
    const ids = sortTechniques(techniques, "id", "asc").map((t) => t.id);
    expect(ids).toEqual([...ids].sort());
    const counts = sortTechniques(techniques, "sentence_count", "asc").map((t) => t.sentence_count);
    expect(counts).toEqual([...counts].sort((a, b) => a - b));
  });
  it("filters by tactic, band, search text and minimum confidence", () => {
    expect(filterTechniques(techniques, { ...NO_FILTER, tactic: "TA0003" }).every((t) => t.tactic_ids.includes("TA0003"))).toBe(true);
    expect(filterTechniques(techniques, { ...NO_FILTER, band: "medium" }).every((t) => t.band === "medium")).toBe(true);
    expect(filterTechniques(techniques, { ...NO_FILTER, query: "mimikatz" }).map((t) => t.id)).toContain("T1003");
    expect(filterTechniques(techniques, { ...NO_FILTER, minConfidence: 0.9 }).every((t) => t.confidence >= 0.9)).toBe(true);
    expect(filterTechniques(techniques, NO_FILTER)).toHaveLength(techniques.length);
  });
});
