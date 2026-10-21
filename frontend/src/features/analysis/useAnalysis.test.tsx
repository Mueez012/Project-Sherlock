import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import sample from "@/mocks/analysis-result.json";

import { POLL_FAST_MS, POLL_SLOW_MS, pollDelay, useAnalysis } from "./useAnalysis";

const status = (s: string, progress = 0.5) => ({
  id: "an_1", status: s, stage: s, progress, message: s, incident_name: "x", filename: null,
  created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", error: null,
});

const json = (body: unknown, code = 200) => Promise.resolve(new Response(JSON.stringify(body), { status: code }));

describe("pollDelay", () => {
  it("polls every second, then every 3 seconds after 30 s", () => {
    expect(pollDelay(0)).toBe(POLL_FAST_MS);
    expect(pollDelay(29_999)).toBe(POLL_FAST_MS);
    expect(pollDelay(30_000)).toBe(POLL_SLOW_MS);
  });
});

describe("useAnalysis", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  it("polls until completed, then fetches the result and stops", async () => {
    const replies = [status("encoding"), status("aggregating"), status("completed", 1)];
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((url) =>
      String(url).endsWith("/result") ? json(sample) : json(replies.shift()));
    const { result } = renderHook(() => useAnalysis("an_1"));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(result.current.status?.status).toBe("encoding");
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_FAST_MS); });
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_FAST_MS); });
    expect(result.current.result?.id).toBe("an_mock_synthetic");
    const calls = fetchMock.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(10 * POLL_SLOW_MS); });
    expect(fetchMock.mock.calls.length).toBe(calls);
  });

  it("stops on failed without fetching a result", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() =>
      json({ ...status("failed"), error: { code: "no_text_layer", message: "scanned" } }));
    const { result } = renderHook(() => useAnalysis("an_1"));
    await act(async () => { await vi.advanceTimersByTimeAsync(5 * POLL_FAST_MS); });
    expect(result.current.status?.error?.code).toBe("no_text_layer");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("backs off to 3 s after 30 s", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() => json(status("encoding")));
    renderHook(() => useAnalysis("an_1"));
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    const at30 = fetchMock.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(9_000); });
    expect(at30).toBeGreaterThanOrEqual(29);
    expect(fetchMock.mock.calls.length - at30).toBeLessThanOrEqual(4);
  });

  it("stops polling on unmount", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(() => json(status("encoding")));
    const { unmount } = renderHook(() => useAnalysis("an_1"));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    unmount();
    const calls = fetchMock.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(fetchMock.mock.calls.length).toBe(calls);
  });

  it("exposes a 404 as a typed error", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() => json({ code: "not_found", detail: "no" }, 404));
    const { result } = renderHook(() => useAnalysis("an_missing"));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(result.current.error?.code).toBe("not_found");
  });
});
