import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { parseResult, readStoredResult } from "@/lib/resultStore";

import { AnalyzeDialog } from "./AnalyzeDialog";

afterEach(() => { vi.restoreAllMocks(); sessionStorage.clear(); });

function setup() {
  const onClose = vi.fn();
  const user = userEvent.setup();
  render(<AnalyzeDialog open onClose={onClose} />);
  return { user, onClose };
}

const respond = (body: unknown, status: number) => new Response(JSON.stringify(body), { status });

async function fill(user: ReturnType<typeof userEvent.setup>, text = "Mimikatz dumped LSASS.") {
  await user.type(screen.getByLabelText(/incident name/i), "Op");
  await user.click(screen.getByRole("tab", { name: /paste text/i }));
  await user.type(screen.getByLabelText(/report text/i), text);
  await user.click(screen.getByRole("button", { name: /analyse report/i }));
}

describe("AnalyzeDialog", () => {
  it("shows validation errors and sends nothing when fields are missing", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: /analyse report/i }));
    expect(screen.getByText("Give the incident a name.")).toBeInTheDocument();
    expect(screen.getByText("Choose a report file.")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /paste text/i }));
    await user.click(screen.getByRole("button", { name: /analyse report/i }));
    expect(screen.getByText("Paste some report text first.")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uploads a report file, keeps its name and the pages, and closes", async () => {
    const text = "The actor ran Mimikatz on the host.";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(respond({
      mode: "stub", sentences: [text], ttps: [{ technique_id: "T1003", score: 1, sentence_index: 0 }], iocs: [],
      cskg: null, attribution: null, text, spans: [{ start: 0, end: text.length, page: 1 }], declared_ttps: [], warnings: [],
    }, 200));
    const { user, onClose } = setup();
    await user.type(screen.getByLabelText(/incident name/i), "Op");
    await user.upload(screen.getByLabelText(/drop a report here/i), new File(["%PDF"], "report.pdf", { type: "application/pdf" }));
    expect(screen.getByText("report.pdf")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /analyse report/i }));
    expect(fetchMock).toHaveBeenCalledWith("/api/analyze/file", expect.objectContaining({ method: "POST" }));
    expect(onClose).toHaveBeenCalled();
    const stored = parseResult(readStoredResult());
    expect(stored?.document).toMatchObject({ filename: "report.pdf", pages: 1, text });
  });

  it("refuses an unsupported file before sending it", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const user = userEvent.setup({ applyAccept: false });  // a dropped file skips the picker's type filter
    render(<AnalyzeDialog open onClose={vi.fn()} />);
    await user.type(screen.getByLabelText(/incident name/i), "Op");
    await user.upload(screen.getByLabelText(/drop a report here/i), new File(["MZ"], "tool.exe"));
    await user.click(screen.getByRole("button", { name: /analyse report/i }));
    expect(screen.getByText(/files are not supported/)).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends the text to the hub, stores the adapted result and closes", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(respond({
      mode: "stub", sentences: ["Mimikatz dumped LSASS."],
      ttps: [{ technique_id: "T1003", score: 1, sentence_index: 0 }], iocs: [], cskg: null, attribution: null,
    }, 200));
    const { user, onClose } = setup();
    await fill(user);
    expect(fetchMock).toHaveBeenCalledWith("/api/analyze", expect.objectContaining({ method: "POST" }));
    expect(onClose).toHaveBeenCalled();
    const stored = parseResult(readStoredResult());
    expect(stored?.incident_name).toBe("Op");
    expect(stored?.techniques.map((t) => t.id)).toEqual(["T1003"]);
  });

  it("shows the hub's reason when a service is down", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(respond({ detail: "ttp service unavailable: ConnectError" }, 503));
    const { user, onClose } = setup();
    await fill(user);
    expect(await screen.findByRole("alert")).toHaveTextContent(/ttp service unavailable/);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes on Escape", async () => {
    const { user, onClose } = setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });
});
