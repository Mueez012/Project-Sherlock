"use client";

import { ArrowLeft, Check, CircleNotch, WarningCircle } from "@phosphor-icons/react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { ProgressBar } from "@/components/ProgressBar";
import { messageFor } from "@/lib/api/client";
import { STAGES, type JobStatus } from "@/types/analysis";

function useElapsed(since: number, running: boolean): number {
  const [now, setNow] = useState(since);
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [running]);
  return Math.max(0, Math.round((now - since) / 1000));
}

export function AnalysisProgress({ status, startedAt }: { status: JobStatus | null; startedAt: number }) {
  const failed = status?.status === "failed";
  const elapsed = useElapsed(startedAt, !failed);
  const current = STAGES.findIndex((s) => s.id === (status?.stage ?? "queued"));
  // A failed job reports stage "failed"; show how far it got from the progress value instead.
  const reached = failed ? -1 : current;

  return (
    <section className="card progress-card" aria-labelledby="progress-title">
      <p className="eyebrow">{status?.incident_name ?? "Analysis"}</p>
      <h1 id="progress-title">{failed ? "The analysis failed" : "Analysing the report"}</h1>
      {status?.filename && <p className="muted mono-inline">{status.filename}</p>}

      {failed ? (
        <div className="error-panel" role="alert">
          <WarningCircle aria-hidden="true" weight="fill" size={22} />
          <div>
            <strong>{messageFor(status.error?.code ?? "model_error", status.error?.message)}</strong>
            {status.error?.message && <p className="muted">Server detail: {status.error.message}</p>}
          </div>
        </div>
      ) : (
        <>
          <ProgressBar value={status?.progress ?? 0} label="Analysis progress" />
          <p className="progress-message" aria-live="polite">
            {status?.message ?? "Connecting…"} <span className="muted">· {elapsed} s</span>
          </p>
          <ol className="stage-list">
            {STAGES.slice(0, -1).map((stage, i) => {
              const state = i < reached ? "done" : i === reached ? "active" : "todo";
              return (
                <li key={stage.id} className={state} aria-current={state === "active" ? "step" : undefined}>
                  <span className="stage-icon" aria-hidden="true">
                    {state === "done" ? <Check weight="bold" /> : state === "active" ? <CircleNotch className="spin" weight="bold" /> : null}
                  </span>
                  {stage.label}
                  <span className="sr-only">{state === "done" ? " (done)" : state === "active" ? " (in progress)" : ""}</span>
                </li>
              );
            })}
          </ol>
        </>
      )}
      <Link href="/" className="button ghost"><ArrowLeft aria-hidden="true" /> Back to start</Link>
    </section>
  );
}
