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
  await user.type(screen.getByLabelText(/report text/i), text);
  await user.click(screen.getByRole("button", { name: /analyse report/i }));
}

describe("AnalyzeDialog", () => {
  it("shows validation errors and sends nothing when fields are missing", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: /analyse report/i }));
    expect(screen.getByText("Give the incident a name.")).toBeInTheDocument();
    expect(screen.getByText("Paste some report text first.")).toBeInTheDocument();
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
