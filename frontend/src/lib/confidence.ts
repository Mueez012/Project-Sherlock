import type { ConfidenceBand } from "@/types/analysis";

export const BAND_LABEL: Record<ConfidenceBand, string> = { high: "High", medium: "Medium", low: "Low" };

/** high >= 0.80, medium 0.50-0.79, low = passed its threshold but < 0.50 (same as the API). */
export function bandOf(confidence: number): ConfidenceBand {
  if (confidence >= 0.8) return "high";
  return confidence >= 0.5 ? "medium" : "low";
}

/**
 * Rounds DOWN and caps at 99%: a model probability of 0.9994 (or a float32 output that
 * saturates to exactly 1.0) shows as 99%, never as a certain-looking 100%.
 */
export function percent(p: number, digits = 0): string {
  const scale = 10 ** digits;
  const value = Math.min(Math.floor(p * 100 * scale + 1e-9) / scale, 100 - 1 / scale);
  return `${value.toFixed(digits)}%`;
}
