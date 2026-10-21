import { describe, expect, it, vi } from "vitest";

import type { AnalysisResult } from "@/types/analysis";

import { RESULT_KEY, parseResult, readStoredResult, saveResult, subscribeToResult } from "./resultStore";

const result = { id: "local-1", incident_name: "Op" } as AnalysisResult;

describe("resultStore", () => {
  it("saves, reads back and notifies subscribers", () => {
    const listener = vi.fn();
    const unsubscribe = subscribeToResult(listener);
    saveResult(result);
    expect(listener).toHaveBeenCalledTimes(1);
    expect(parseResult(readStoredResult())).toEqual(result);
    unsubscribe();
    saveResult(result);
    expect(listener).toHaveBeenCalledTimes(1);
  });
  it("treats missing or broken data as no result", () => {
    expect(parseResult(null)).toBeNull();
    sessionStorage.setItem(RESULT_KEY, "{not json");
    expect(parseResult(readStoredResult())).toBeNull();
  });
});
