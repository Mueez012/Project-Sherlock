import { describe, expect, it } from "vitest";

import type { Sentence } from "@/types/analysis";

import { segmentText } from "./highlight";

const s = (index: number, char_start: number, char_end: number): Sentence =>
  ({ index, text: "", char_start, char_end, page: null, skipped: null, labels: [] });

describe("segmentText", () => {
  const text = "First one. Second one.\n\nThird.";
  it("cuts the text exactly at the offsets and loses nothing", () => {
    const segs = segmentText(text, [s(1, 11, 22), s(0, 0, 10), s(2, 24, 30)]);
    expect(segs.map((x) => x.text).join("")).toBe(text);
    const sentences = segs.filter((x) => x.kind === "sentence");
    expect(sentences.map((x) => x.text)).toEqual(["First one.", "Second one.", "Third."]);
  });
  it("skips overlapping or out-of-range spans", () => {
    const segs = segmentText(text, [s(0, 0, 10), s(1, 5, 12), s(2, 20, 99)]);
    expect(segs.filter((x) => x.kind === "sentence")).toHaveLength(1);
    expect(segs.map((x) => x.text).join("")).toBe(text);
  });
});
