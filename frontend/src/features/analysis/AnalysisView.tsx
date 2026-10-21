"use client";

import { MagnifyingGlass, WarningCircle } from "@phosphor-icons/react";
import Link from "next/link";
import { useState } from "react";

import { messageFor } from "@/lib/api/client";
import type { AnalysisResult } from "@/types/analysis";

import { AnalysisProgress } from "./AnalysisProgress";
import { DeclaredComparison } from "./DeclaredComparison";
import { ExportMenu } from "./ExportMenu";
import { ReportViewer } from "./ReportViewer";
import { SummaryBar } from "./SummaryBar";
import { TacticMatrix } from "./TacticMatrix";
import { TechniqueTable } from "./TechniqueTable";
import { useAnalysis } from "./useAnalysis";

export function AnalysisView({ id, onNewAnalysis }: { id: string; onNewAnalysis: () => void }) {
  const { status, result, error, startedAt } = useAnalysis(id);

  if (error) {
    return (
      <section className="card progress-card" role="alert">
        <h1>Cannot show this analysis</h1>
        <div className="error-panel">
          <WarningCircle aria-hidden="true" weight="fill" size={22} />
          <strong>{messageFor(error.code, error.detail)}</strong>
        </div>
        <Link href="/" className="button ghost">Back to start</Link>
      </section>
    );
  }
  if (!result) return <AnalysisProgress status={status} startedAt={startedAt} />;
  return <ResultView result={result} onNewAnalysis={onNewAnalysis} />;
}

export function ResultView({ result, onNewAnalysis }: { result: AnalysisResult; onNewAnalysis: () => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const show = (techniqueId: string) => {
    setSelected(techniqueId);
    setNonce((n) => n + 1);
  };
  const declared = result.document.declared_ttps ?? [];

  return (
    <div className="result-stack">
      <SummaryBar result={result} />
      <ExportMenu id={result.id} />
      {result.warnings.length > 0 && (
        <ul className="notice-list" aria-label="Warnings">
          {result.warnings.map((w) => <li key={w}><WarningCircle aria-hidden="true" /> {w}</li>)}
        </ul>
      )}
      {declared.length > 0 && <DeclaredComparison result={result} />}
      {result.techniques.length === 0 ? (
        <section className="card empty-state">
          <MagnifyingGlass size={32} aria-hidden="true" />
          <h2>No techniques passed the threshold</h2>
          <p className="muted">
            The model read {result.document.n_sentences_analyzed} sentences but none scored high enough.
            Try again with a lower threshold under <em>Advanced options</em> (for example a fixed value of 0.3).
          </p>
          <button type="button" className="button primary" onClick={onNewAnalysis}>New analysis</button>
        </section>
      ) : (
        <>
          <TacticMatrix tactics={result.tactics} techniques={result.techniques} selected={selected} onSelect={show} />
          <TechniqueTable techniques={result.techniques} selected={selected} onShowInReport={show} />
        </>
      )}
      <ReportViewer result={result} focusTechnique={selected} focusNonce={nonce} />
    </div>
  );
}
