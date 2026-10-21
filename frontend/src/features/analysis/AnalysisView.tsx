"use client";

import { MagnifyingGlass, WarningCircle } from "@phosphor-icons/react";
import { useState } from "react";

import type { AnalysisResult } from "@/types/analysis";

import { IndicatorList } from "./IndicatorList";
import { ReportViewer } from "./ReportViewer";
import { SummaryBar } from "./SummaryBar";
import { TacticMatrix } from "./TacticMatrix";
import { TechniqueTable } from "./TechniqueTable";

export function ResultView({ result, onNewAnalysis }: { result: AnalysisResult; onNewAnalysis: () => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const show = (techniqueId: string) => {
    setSelected(techniqueId);
    setNonce((n) => n + 1);
  };

  return (
    <div className="result-stack">
      <SummaryBar result={result} />
      {result.warnings.length > 0 && (
        <ul className="notice-list" aria-label="Warnings">
          {result.warnings.map((w) => <li key={w}><WarningCircle aria-hidden="true" /> {w}</li>)}
        </ul>
      )}
      {result.techniques.length === 0 ? (
        <section className="card empty-state">
          <MagnifyingGlass size={32} aria-hidden="true" />
          <h2>No techniques found</h2>
          <p className="muted">
            The model read {result.document.n_sentences_analyzed} sentences but found no ATT&amp;CK technique in them.
          </p>
          <button type="button" className="button primary" onClick={onNewAnalysis}>New analysis</button>
        </section>
      ) : (
        <>
          <TacticMatrix tactics={result.tactics} techniques={result.techniques} selected={selected} onSelect={show} />
          <TechniqueTable techniques={result.techniques} selected={selected} onShowInReport={show} />
        </>
      )}
      {result.indicators && <IndicatorList indicators={result.indicators} />}
      <ReportViewer result={result} focusTechnique={selected} focusNonce={nonce} />
    </div>
  );
}
