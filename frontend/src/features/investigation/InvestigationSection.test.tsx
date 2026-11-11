import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Snapshot } from "@/lib/api/investigations";
import { readLink, saveLink } from "@/lib/investigationStore";
import type { AnalysisResult } from "@/types/analysis";

import { InvestigationSection } from "./InvestigationSection";
import { example, jsonResponse, routedFetch } from "./testFixtures";

const created = example<Snapshot>("create-response");
const result = {
  id: "analysis-1", incident_name: "Op Test",
  document: { filename: "report.pdf", text: "The loader contacted example.com for its configuration.", size_bytes: 10, n_sentences: 1, n_sentences_analyzed: 1 },
  indicators: [{ type: "domain", value: "example.com", sentence_indices: [0] }],
} as unknown as AnalysisResult;

beforeEach(() => sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

describe("InvestigationSection", () => {
  it("creates the investigation from the analysed text, once, and remembers it", async () => {
    const api = routedFetch((url, init) => (url === "/api/investigations" && init?.method === "POST" ? jsonResponse(created, 201) : undefined));
    vi.spyOn(globalThis, "fetch").mockImplementation(api.fn);
    const user = userEvent.setup();
    render(<InvestigationSection result={result} onShowSentences={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /investigate these 1 indicators/i }));
    expect(await screen.findByRole("group", { name: /indicator graph/i })).toBeInTheDocument();
    expect(JSON.parse(String(api.calls[0].init?.body))).toEqual({ text: result.document.text, source: "report.pdf" });
    expect(readLink(result.id)).toEqual({ runId: created.run.id });
  });

  it("reuses the creation key after a lost answer, so no second investigation is made", async () => {
    saveLink(result.id, { creationKey: "a".repeat(32) });
    const api = routedFetch((url, init) => (init?.method === "POST" ? jsonResponse(created, 200) : undefined));
    vi.spyOn(globalThis, "fetch").mockImplementation(api.fn);
    const user = userEvent.setup();
    render(<InvestigationSection result={result} onShowSentences={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /investigate/i }));
    await screen.findByRole("group", { name: /indicator graph/i });
    expect(new Headers(api.calls[0].init?.headers).get("Idempotency-Key")).toBe("a".repeat(32));
  });

  it("shows a report indicator's sentences in the report", async () => {
    saveLink(result.id, { runId: created.run.id });
    vi.spyOn(globalThis, "fetch").mockImplementation(routedFetch((url) => {
      if (url.endsWith(`/api/investigations/${created.run.id}`)) return jsonResponse(created);
      if (url.includes("/methods")) return jsonResponse(example("methods-response"));
      return undefined;
    }).fn);
    const onShow = vi.fn();
    const user = userEvent.setup();
    render(<InvestigationSection result={result} onShowSentences={onShow} />);
    await user.click(await screen.findByRole("button", { name: /example\.com, from the report/i }));
    await user.click(screen.getByRole("button", { name: /show in report/i }));
    expect(onShow).toHaveBeenCalledWith([0]);
  });

  it("offers nothing to investigate when the report has no indicators", () => {
    render(<InvestigationSection result={{ ...result, indicators: [] }} onShowSentences={vi.fn()} />);
    expect(screen.getByText(/no indicators to investigate/i)).toBeInTheDocument();
  });
});
