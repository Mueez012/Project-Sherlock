import type { Sentence } from "@/types/analysis";

export type Segment =
  | { kind: "text"; text: string; start: number }
  | { kind: "sentence"; text: string; start: number; sentence: Sentence };

/**
 * Cut the report text into plain stretches and sentence spans using the
 * sentences' char_start / char_end. Sentences must not overlap (the API
 * guarantees this); out-of-range or overlapping spans are skipped safely.
 */
export function segmentText(text: string, sentences: Sentence[]): Segment[] {
  const sorted = [...sentences].sort((a, b) => a.char_start - b.char_start);
  const segments: Segment[] = [];
  let cursor = 0;
  for (const s of sorted) {
    if (s.char_start < cursor || s.char_end > text.length || s.char_end <= s.char_start) continue;
    if (s.char_start > cursor) segments.push({ kind: "text", text: text.slice(cursor, s.char_start), start: cursor });
    segments.push({ kind: "sentence", text: text.slice(s.char_start, s.char_end), start: s.char_start, sentence: s });
    cursor = s.char_end;
  }
  if (cursor < text.length) segments.push({ kind: "text", text: text.slice(cursor), start: cursor });
  return segments;
}
