import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CreateStep, Snapshot } from "@/lib/api/investigations";
import { readPendingStep, savePendingStep } from "@/lib/investigationStore";

import { example, jsonResponse, routedFetch } from "./testFixtures";
import { Workspace } from "./Workspace";

const created = example<Snapshot>("create-response");
const RUN = created.run.id;
const domain = created.graph.nodes.find((n) => n.type === "domain")!;

beforeEach(() => sessionStorage.clear());
afterEach(() => vi.restoreAllMocks());

function backend(stepAnswer: () => Response) {
  return routedFetch((url, init) => {
    if (url.endsWith(`/nodes/${domain.id}/methods`)) return jsonResponse(example("methods-response"));
    if (url.endsWith(`/${RUN}/steps`) && init?.method === "POST") return stepAnswer();
    if (url.endsWith(`/api/investigations/${RUN}`)) return jsonResponse(example("snapshot-response"));
    return undefined;
  });
}

describe("Workspace", () => {
  it("runs a lookup on the selected indicator and grows the graph", async () => {
    const api = backend(() => jsonResponse(example("step-response"), 201));
    vi.spyOn(globalThis, "fetch").mockImplementation(api.fn);
    const user = userEvent.setup();
    render(<Workspace runId={RUN} initial={created} />);

    await user.click(screen.getByRole("button", { name: /example\.com, from the report/i }));
    const run = await screen.findByRole("button", { name: /run rapiddns domain to ipv4/i });
    expect(screen.getByRole("button", { name: /run alienvault otx domain to ipv4/i })).toBeDisabled();
    await user.click(run);

    expect(await screen.findByText(/added to the graph/i)).toBeInTheDocument();
    const post = api.calls.find((c) => c.init?.method === "POST")!;
    const body = JSON.parse(String(post.init?.body)) as CreateStep;
    expect(body).toMatchObject({ input_node_id: domain.id, method_id: "rapiddns.domain_to_ipv4", expected_graph_revision: 1 });
    expect(body.step_id).toMatch(/^[0-9a-f]{32}$/);
    expect(screen.getByRole("group", { name: /indicator graph: 4 indicators, 2 links/i })).toBeInTheDocument();
    expect(readPendingStep(RUN)).toBeNull();
  });

  it("explains a lookup whose results were not added", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(backend(() => jsonResponse(example("nonadmitted-step-response"), 201)).fn);
    const user = userEvent.setup();
    render(<Workspace runId={RUN} initial={created} />);
    await user.click(screen.getByRole("button", { name: /example\.com, from the report/i }));
    await user.click(await screen.findByRole("button", { name: /run rapiddns domain to ipv4/i }));
    expect(await screen.findByText(/no result links to an indicator that is already known/i)).toBeInTheDocument();
  });

  it("reloads when the graph changed in the meantime", async () => {
    const api = backend(() => jsonResponse(example("stale-revision-response"), 409));
    vi.spyOn(globalThis, "fetch").mockImplementation(api.fn);
    const user = userEvent.setup();
    render(<Workspace runId={RUN} initial={created} />);
    await user.click(screen.getByRole("button", { name: /example\.com, from the report/i }));
    await user.click(await screen.findByRole("button", { name: /run rapiddns domain to ipv4/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/graph changed/i);
    await waitFor(() => expect(api.calls.some((c) => c.url.endsWith(`/api/investigations/${RUN}`))).toBe(true));
    expect(readPendingStep(RUN)).toBeNull();
  });

  it("re-sends a lookup whose answer never arrived, with the same step id", async () => {
    const pending = { ...example<CreateStep>("step-request"), input_node_id: domain.id, expected_graph_revision: 1 };
    savePendingStep(RUN, pending);
    const api = backend(() => jsonResponse(example("step-replay-response"), 200));
    vi.spyOn(globalThis, "fetch").mockImplementation(api.fn);
    render(<Workspace runId={RUN} initial={created} />);
    await waitFor(() => expect(readPendingStep(RUN)).toBeNull());
    const post = api.calls.find((c) => c.init?.method === "POST")!;
    expect(JSON.parse(String(post.init?.body)).step_id).toBe(pending.step_id);
  });

  it("keeps the lookup for a safe retry when the connection drops", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      routedFetch((url, init) => {
        if (url.endsWith("/methods")) return jsonResponse(example("methods-response"));
        if (init?.method === "POST") throw new TypeError("network down");
        return undefined;
      }).fn,
    );
    const user = userEvent.setup();
    render(<Workspace runId={RUN} initial={created} />);
    await user.click(screen.getByRole("button", { name: /example\.com, from the report/i }));
    await user.click(await screen.findByRole("button", { name: /run rapiddns domain to ipv4/i }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("button", { name: /try again/i })).toBeInTheDocument();
    expect(readPendingStep(RUN)).not.toBeNull();
  });

  it("keeps a re-sent lookup that is still running, and gets its result on Try again", async () => {
    const pending = { ...example<CreateStep>("step-request"), input_node_id: domain.id, expected_graph_revision: 1 };
    savePendingStep(RUN, pending);
    let first = true;
    const api = backend(() => {
      if (first) {
        first = false;
        return jsonResponse({ error: { code: "step_in_progress", message: "This investigation operation is still executing." } }, 409);
      }
      return jsonResponse(example("step-replay-response"), 200);
    });
    vi.spyOn(globalThis, "fetch").mockImplementation(api.fn);
    const user = userEvent.setup();
    render(<Workspace runId={RUN} initial={created} />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/still running on the server/i);
    expect(readPendingStep(RUN)?.step_id).toBe(pending.step_id);
    await user.click(within(alert).getByRole("button", { name: /try again/i }));
    await waitFor(() => expect(readPendingStep(RUN)).toBeNull());
    const posts = api.calls.filter((c) => c.init?.method === "POST").map((c) => JSON.parse(String(c.init?.body)).step_id);
    expect(posts).toEqual([pending.step_id, pending.step_id]);
  });

  it("downloads the JSON through a link attached to the page, releasing the file later", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const create = vi.fn(() => "blob:investigation");
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const clicked: boolean[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(document.body.contains(this));
    });
    vi.spyOn(globalThis, "fetch").mockImplementation(routedFetch((url) =>
      url.endsWith("/export")
        ? jsonResponse(example("export-response"), 200, { "Content-Disposition": 'attachment; filename="investigation.json"' })
        : undefined).fn);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<Workspace runId={RUN} initial={created} />);
    await user.click(screen.getByRole("button", { name: /download json/i }));
    await waitFor(() => expect(clicked).toEqual([true]));
    expect(revoke).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30_000);
    expect(revoke).toHaveBeenCalledWith("blob:investigation");
    vi.useRealTimers();
  });
});
