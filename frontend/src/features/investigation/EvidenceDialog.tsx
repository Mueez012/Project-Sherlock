"use client";

import { X } from "@phosphor-icons/react";
import { useEffect, useState } from "react";

import { Dialog } from "@/components/Dialog";
import { InvestigationError, stepDetail, type StepDetail } from "@/lib/api/investigations";

import { admissionLabel, outcomeLabel } from "./labels";

const MAX_BODY = 50_000;

/** A lookup's full receipt and the provider's raw pages, shown as plain text (never rendered as HTML). */
export function EvidenceDialog({ runId, stepId, onClose }: { runId: string; stepId: string | null; onClose: () => void }) {
  return (
    <Dialog open={!!stepId} onClose={onClose} labelledBy="evidence-title">
      {stepId && <EvidenceBody key={stepId} runId={runId} stepId={stepId} onClose={onClose} />}
    </Dialog>
  );
}

function EvidenceBody({ runId, stepId, onClose }: { runId: string; stepId: string; onClose: () => void }) {
  const [detail, setDetail] = useState<StepDetail | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    stepDetail(runId, stepId)
      .then((d) => { if (live) setDetail(d); })
      .catch((e) => { if (live) setError(e instanceof InvestigationError ? e.message : "The evidence could not be loaded."); });
    return () => { live = false; };
  }, [runId, stepId]);

  const lookup = detail?.step.lookup;
  return (
      <div className="evidence">
        <div className="sentence-panel-head">
          <h2 id="evidence-title">Lookup evidence</h2>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close evidence"><X aria-hidden="true" /></button>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        {!detail && !error && <p className="muted">Loading…</p>}
        {detail && (
          <>
            <dl className="evidence-facts">
              <dt>Method</dt><dd className="mono">{detail.step.method_id}</dd>
              <dt>Input</dt><dd className="mono indicator-value">{lookup?.input_ioc.value ?? "—"}</dd>
              <dt>Outcome</dt><dd>{outcomeLabel(detail.step.outcome_status)}{lookup?.outcome_reason ? ` — ${lookup.outcome_reason}` : ""}</dd>
              {detail.step.admission && <><dt>Graph</dt><dd>{admissionLabel(detail.step.admission.reason)}</dd></>}
              {lookup && <><dt>Cache</dt><dd>{lookup.cache_hit ? "Answered from the saved cache" : "Fetched from the provider"}</dd></>}
              {detail.step.error && <><dt>Error</dt><dd>{detail.step.error}</dd></>}
            </dl>
            {lookup && (
              <details open>
                <summary>Results ({lookup.outputs.length} found, {lookup.rejected.length} rejected)</summary>
                <pre className="evidence-pre">{JSON.stringify({ outputs: lookup.outputs, accepted: lookup.accepted, rejected: lookup.rejected, evidence: lookup.evidence, transport_errors: lookup.transport_errors }, null, 2)}</pre>
              </details>
            )}
            {Object.entries(detail.snapshots).map(([id, snap]) => (
              <details key={id}>
                <summary className="mono">{snap.url} · {snap.status_code}</summary>
                <pre className="evidence-pre">{snap.body.length > MAX_BODY ? `${snap.body.slice(0, MAX_BODY)}\n… (${snap.body.length - MAX_BODY} more characters in the JSON download)` : snap.body}</pre>
              </details>
            ))}
          </>
        )}
      </div>
  );
}
