import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import sample from "@/mocks/analysis-result.json";
import type { AnalysisResult } from "@/types/analysis";

import { ReportViewer } from "./ReportViewer";

const result = sample as AnalysisResult;

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
  window.matchMedia = vi.fn().mockReturnValue({ matches: true }) as unknown as typeof window.matchMedia;
});

describe("ReportViewer", () => {
  it("highlights exactly the evidence span given by char_start / char_end", () => {
    const technique = result.techniques.find((x) => x.id === "T1003");
    if (!technique) throw new Error("sample has no T1003");
    const { container } = render(<ReportViewer result={result} focusTechnique="T1003" focusNonce={1} />);
    const focused = [...container.querySelectorAll("mark.focus")].map((m) => m.textContent);
    const ev = technique.evidence[0];
    expect(focused).toContain(result.document.text.slice(ev.char_start, ev.char_end));
    // The whole text is shown once; only line breaks inside sentences become spaces.
    expect(container.querySelector(".report-text")?.textContent?.length).toBe(result.document.text.length);
  });

  it("shows a sentence's labels when it is selected", async () => {
    const user = userEvent.setup();
    render(<ReportViewer result={result} focusTechnique={null} focusNonce={0} />);
    await user.click(screen.getByText(/dump credentials from LSASS/));
    expect(screen.getByRole("heading", { name: /sentence/i })).toBeInTheDocument();
    expect(screen.getAllByText("T1003").length).toBeGreaterThan(0);
  });
});

describe("ReportViewer with indicators", () => {
  it("highlights a sentence that only has an indicator and lists it when selected", async () => {
    const { toAnalysisResult } = await import("@/lib/adapt");
    const adapted = toAnalysisResult({
      text: "Nothing here. The beacon went to 10.0.0.1 daily.", incidentName: "Op", processingMs: 1,
      response: {
        mode: "stub", sentences: ["Nothing here.", "The beacon went to 10.0.0.1 daily."], ttps: [],
        iocs: [{ type: "ipv4", value: "10.0.0.1", sentence_indices: [1], context: [], source: "regex stub" }],
        cskg: null, attribution: null,
      },
    });
    const user = userEvent.setup();
    render(<ReportViewer result={adapted} focusTechnique={null} focusNonce={0} />);
    await user.click(screen.getByText(/beacon went to/));
    expect(screen.getByRole("heading", { name: "Indicators in this sentence" })).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1", { selector: ".label-name" })).toBeInTheDocument();
  });
});
