import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { UploadDialog } from "./UploadDialog";

afterEach(() => { vi.restoreAllMocks(); });

function setup(applyAccept = true) {
  const onCreated = vi.fn();
  const onClose = vi.fn();
  // applyAccept=false: let a file through that the browser picker would hide, to test our own check
  const user = userEvent.setup({ applyAccept });
  render(<UploadDialog open onClose={onClose} onCreated={onCreated} />);
  return { user, onCreated, onClose };
}

const respond = (body: unknown, status: number) => new Response(JSON.stringify(body), { status });

describe("UploadDialog", () => {
  it("shows validation errors and sends nothing when fields are missing", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const { user } = setup();
    await user.click(screen.getByRole("button", { name: /start analysis/i }));
    expect(screen.getByText("Give the incident a name.")).toBeInTheDocument();
    expect(screen.getByText("Choose a report file.")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an unsupported file type on the client", async () => {
    const { user } = setup(false);
    await user.type(screen.getByLabelText(/incident name/i), "Op");
    const input = document.querySelector<HTMLInputElement>("input[type=file]");
    if (!input) throw new Error("no file input");
    await user.upload(input, new File(["MZ"], "tool.exe"));
    await user.click(screen.getByRole("button", { name: /start analysis/i }));
    expect(screen.getByText(/files are not supported/)).toBeInTheDocument();
  });

  it("submits pasted text and reports the new job id", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      respond({ id: "an_42", status: "queued", created_at: "2026-01-01T00:00:00Z", links: {} }, 202));
    const { user, onCreated } = setup();
    await user.type(screen.getByLabelText(/incident name/i), "Op");
    await user.click(screen.getByRole("tab", { name: /paste text/i }));
    await user.type(screen.getByLabelText(/report text/i), "The actor used PowerShell.");
    await user.click(screen.getByRole("button", { name: /start analysis/i }));
    expect(onCreated).toHaveBeenCalledWith("an_42");
  });

  it("shows the friendly message for an API error code", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      respond({ code: "queue_full", detail: "10 analyses are already waiting", status: 429 }, 429));
    const { user } = setup();
    await user.type(screen.getByLabelText(/incident name/i), "Op");
    await user.click(screen.getByRole("tab", { name: /paste text/i }));
    await user.type(screen.getByLabelText(/report text/i), "Some text here.");
    await user.click(screen.getByRole("button", { name: /start analysis/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/queue is full/i);
  });

  it("closes on Escape", async () => {
    const { user, onClose } = setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });
});
