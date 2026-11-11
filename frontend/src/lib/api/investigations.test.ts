import { afterEach, describe, expect, it, vi } from "vitest";

import { example, jsonResponse } from "@/features/investigation/testFixtures";

import {
  INVESTIGATION_ERRORS, createInvestigation, exportInvestigation, investigationError, newRequestId, runStep,
} from "./investigations";

afterEach(() => vi.restoreAllMocks());

describe("errors", () => {
  it("reads IOC Hunter's error format and the hub's own 503", () => {
    const stale = investigationError(409, example("stale-revision-response"));
    expect(stale.code).toBe("stale_graph_revision");
    expect(stale.message).toBe(INVESTIGATION_ERRORS.stale_graph_revision);
    const down = investigationError(503, example("service-unavailable-response"));
    expect(down.code).toBe("service_unavailable");
  });

  it("makes ids IOC Hunter accepts", () => {
    expect(newRequestId()).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("calls", () => {
  it("creates with the Idempotency-Key header and the report text", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(example("create-response"), 201));
    const key = newRequestId();
    const snapshot = await createInvestigation("The report.", "report.pdf", key);
    expect(snapshot.run.graph_revision).toBe(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/investigations");
    expect(new Headers(init?.headers).get("Idempotency-Key")).toBe(key);
    expect(JSON.parse(String(init?.body))).toEqual({ text: "The report.", source: "report.pdf" });
  });

  it("runs a step and returns the new graph", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(example("step-response"), 201));
    const request = example<Parameters<typeof runStep>[1]>("step-request");
    const result = await runStep("run", request);
    expect(result.step.admission?.accepted).toBe(true);
    expect(result.graph.edges.length).toBeGreaterThan(0);
  });

  it("downloads the export with the server's file name", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(example("export-response"), 200, { "Content-Disposition": 'attachment; filename="investigation-abc.json"' }),
    );
    const { filename, blob } = await exportInvestigation("abc");
    expect(filename).toBe("investigation-abc.json");
    expect(blob.size).toBeGreaterThan(0);
  });
});
