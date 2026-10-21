"use client";

import { useEffect, useState } from "react";

import { ApiError, getResult, getStatus } from "@/lib/api/client";
import { FINISHED, type AnalysisResult, type JobStatus } from "@/types/analysis";

export interface AnalysisState {
  status: JobStatus | null;
  result: AnalysisResult | null;
  error: ApiError | null;
  startedAt: number;
}

export const POLL_FAST_MS = 1000;
export const POLL_SLOW_MS = 3000;
export const BACKOFF_AFTER_MS = 30_000;

/** Delay before the next status poll: 1 s, then 3 s once the job has run for 30 s. */
export function pollDelay(elapsedMs: number): number {
  return elapsedMs >= BACKOFF_AFTER_MS ? POLL_SLOW_MS : POLL_FAST_MS;
}

/**
 * Poll the job status until it is completed or failed, then fetch the result.
 * Stops (and aborts in-flight requests) when the component unmounts. Render the
 * component that uses it with `key={id}` so a new id starts from a clean state.
 */
export function useAnalysis(id: string): AnalysisState {
  const [state, setState] = useState<AnalysisState>(() => ({
    status: null, result: null, error: null, startedAt: Date.now(),
  }));

  useEffect(() => {
    const controller = new AbortController();
    const started = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      try {
        const status = await getStatus(id, controller.signal);
        if (controller.signal.aborted) return;
        setState((s) => ({ ...s, status }));
        if (status.status === "completed") {
          const result = await getResult(id, controller.signal);
          if (!controller.signal.aborted) setState((s) => ({ ...s, result }));
          return;
        }
        if (FINISHED.includes(status.status)) return;
        timer = setTimeout(tick, pollDelay(Date.now() - started));
      } catch (error) {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError) setState((s) => ({ ...s, error }));
        else setState((s) => ({ ...s, error: new ApiError(0, "network", String(error)) }));
      }
    };
    void tick();
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [id]);

  return state;
}
