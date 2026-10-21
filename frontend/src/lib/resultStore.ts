// Keeps the latest analysis in sessionStorage, so the /result page survives a refresh and needs no server-side
// job store. Components read it with useSyncExternalStore (see useStoredResult in src/app/result/page.tsx).
import type { AnalysisResult } from "@/types/analysis";

export const RESULT_KEY = "sherklock:last-result";
const EVENT = "sherklock:result-saved";

export function saveResult(result: AnalysisResult): void {
  try {
    sessionStorage.setItem(RESULT_KEY, JSON.stringify(result));
  } catch {
    /* storage full or blocked: the result page then shows "no analysis yet" */
  }
  window.dispatchEvent(new Event(EVENT));
}

/** The stored JSON string (a stable value for useSyncExternalStore), or null. */
export function readStoredResult(): string | null {
  try {
    return sessionStorage.getItem(RESULT_KEY);
  } catch {
    return null;
  }
}

export function parseResult(raw: string | null): AnalysisResult | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AnalysisResult;
  } catch {
    return null;
  }
}

export function subscribeToResult(onChange: () => void): () => void {
  window.addEventListener(EVENT, onChange);
  window.addEventListener("storage", onChange);
  return () => {
    window.removeEventListener(EVENT, onChange);
    window.removeEventListener("storage", onChange);
  };
}
