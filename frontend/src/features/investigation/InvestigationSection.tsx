"use client";

import { Graph, WarningCircle } from "@phosphor-icons/react";
import Link from "next/link";
import { useState } from "react";

import { InvestigationError, createInvestigation, newRequestId, type GraphNode, type Snapshot } from "@/lib/api/investigations";
import { readLink, saveLink } from "@/lib/investigationStore";
import type { AnalysisResult } from "@/types/analysis";

import { Workspace } from "./Workspace";

interface Props {
  result: AnalysisResult;
  /** Highlight these timeline sentences in the report viewer below. */
  onShowSentences: (indices: number[]) => void;
}

/**
 * Investigate the analysed report's indicators, on the result page itself. The investigation is created from the
 * exact text the hub analysed (for a file, the text the hub read from it) and remembered with this analysis.
 */
export function InvestigationSection({ result, onShowSentences }: Props) {
  const [runId, setRunId] = useState<string | null>(() => readLink(result.id)?.runId ?? null);
  const [initial, setInitial] = useState<Snapshot | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const indicators = result.indicators ?? [];

  const start = async () => {
    setCreating(true);
    setError("");
    // Keep the key until the investigation exists: a retry after a lost answer returns the same investigation.
    const key = readLink(result.id)?.creationKey ?? newRequestId();
    saveLink(result.id, { creationKey: key });
    try {
      const source = result.document.filename || result.incident_name || "cti report";
      const snapshot = await createInvestigation(result.document.text, source, key);
      saveLink(result.id, { runId: snapshot.run.id });
      setInitial(snapshot);
      setRunId(snapshot.run.id);
    } catch (e) {
      setError(e instanceof InvestigationError ? e.message : "The investigation could not be started.");
    } finally {
      setCreating(false);
    }
  };

  const showInReport = (node: GraphNode) => {
    const match = indicators.find((i) => i.type === node.type && i.value === node.value);
    onShowSentences(match?.sentence_indices ?? []);
  };

  return (
    <section className="card investigation-card" aria-labelledby="investigation-title">
      <div className="card-head">
        <h2 id="investigation-title">Investigation</h2>
        <p className="muted">
          Look up the indicators in RapidDNS, AlienVault OTX and VirusTotal to find related infrastructure. Results that
          link back to the report&apos;s indicators grow the graph.
        </p>
      </div>
      {runId ? (
        <>
          <Workspace runId={runId} initial={initial} onShowInReport={showInReport} />
          <p className="small muted">Saved on the server. Reopen it any time from <Link href={`/investigations?run=${runId}`}>Investigations</Link>.</p>
        </>
      ) : indicators.length === 0 ? (
        <p className="empty-note">This report has no indicators to investigate.</p>
      ) : (
        <div className="investigation-start">
          <button type="button" className="button primary" disabled={creating} onClick={start}>
            <Graph aria-hidden="true" /> {creating ? "Starting…" : `Investigate these ${indicators.length} indicators`}
          </button>
          {error && <p className="form-error" role="alert"><WarningCircle aria-hidden="true" weight="fill" /> {error}</p>}
        </div>
      )}
    </section>
  );
}
