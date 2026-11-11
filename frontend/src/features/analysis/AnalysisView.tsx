"use client";

import { MagnifyingGlass, WarningCircle } from "@phosphor-icons/react";
import { useState } from "react";

import type { AnalysisResult } from "@/types/analysis";

import { InvestigationSection } from "@/features/investigation/InvestigationSection";

import { IndicatorList } from "./IndicatorList";
import { ReportViewer } from "./ReportViewer";
import { SummaryBar } from "./SummaryBar";
import { TacticMatrix } from "./TacticMatrix";
import { TechniqueTable } from "./TechniqueTable";

interface ResultViewProps {
  result: AnalysisResult;
  onNewAnalysis: () => void;
  /** Offer the investigation of this report's indicators (not on the offline sample, which has no backend run). */
  investigable?: boolean;
}

export function ResultView({ result, onNewAnalysis, investigable = false }: ResultViewProps) {
  const [selected, setSelected] = useState<string | null>(null);
  const [sentences, setSentences] = useState<number[] | null>(null);
  const [nonce, setNonce] = useState(0);
  const show = (techniqueId: string) => {
    setSelected(techniqueId);
    setSentences(null);
    setNonce((n) => n + 1);
  };
  const showSentences = (indices: number[]) => {
    setSelected(null);
    setSentences(indices);
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
      {investigable && <InvestigationSection result={result} onShowSentences={showSentences} />}
      <ReportViewer result={result} focusTechnique={selected} focusSentences={sentences} focusNonce={nonce} />
    </div>
  );
}
