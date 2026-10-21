import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, ERROR_MESSAGES, analyze, errorFromResponse, messageFor } from "./client";

afterEach(() => { vi.restoreAllMocks(); });

const respond = (body: unknown, status: number) => new Response(JSON.stringify(body), { status });

describe("hub errors", () => {
  it("turns a 422 into the input message", () => {
    const err = errorFromResponse(422, { detail: [{ msg: "Value error, send text or sentences" }] });
    expect(err.code).toBe("invalid_input");
    expect(err.message).toBe(ERROR_MESSAGES.invalid_input);
  });
  it("turns a 503 into a message that names the service", () => {
    const err = errorFromResponse(503, { detail: "ttp service unavailable: ConnectError: refused" });
    expect(err.code).toBe("service_unavailable");
    expect(err.message).toContain("ttp service unavailable");
  });
  it("falls back to the HTTP status for anything else, even without a JSON body", () => {
    expect(errorFromResponse(502, null).code).toBe("http_502");
    expect(messageFor("weird", "something broke")).toBe("something broke");
  });
});

describe("analyze", () => {
  it("posts the text to /api/analyze and returns the hub's answer", async () => {
    const answer = { mode: "stub", sentences: ["A."], ttps: [], iocs: [], cskg: null, attribution: null };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(respond(answer, 200));
    await expect(analyze("A.")).resolves.toEqual(answer);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/analyze");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ text: "A." });
  });
  it("throws ApiError with the hub's detail on a 503", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(respond({ detail: "ioc service unavailable: not integrated" }, 503));
    await expect(analyze("A.")).rejects.toMatchObject({ code: "service_unavailable", status: 503 });
  });
  it("reports a network failure", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("failed to fetch"));
    const err = await analyze("A.").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("network");
  });
});
