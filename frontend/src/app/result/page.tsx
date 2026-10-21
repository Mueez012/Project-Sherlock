"use client";

import { MagnifyingGlass } from "@phosphor-icons/react";
import Link from "next/link";
import { useMemo, useState, useSyncExternalStore } from "react";

import { SiteHeader } from "@/components/SiteHeader";
import { AnalyzeDialog } from "@/features/analysis/AnalyzeDialog";
import { ResultView } from "@/features/analysis/AnalysisView";
import { parseResult, readStoredResult, subscribeToResult } from "@/lib/resultStore";

/** The latest analysis of this browser tab (kept in sessionStorage by the analyse dialog). */
function useStoredResult() {
  const raw = useSyncExternalStore(subscribeToResult, readStoredResult, () => null);
  return useMemo(() => parseResult(raw), [raw]);
}

export default function ResultPage() {
  const result = useStoredResult();
  const [dialogOpen, setDialogOpen] = useState(false);
  const open = () => setDialogOpen(true);
  return (
    <>
      <SiteHeader onNewAnalysis={open} links={false} />
      <main className="app-main" id="main">
        {result ? (
          <ResultView key={result.id} result={result} onNewAnalysis={open} />
        ) : (
          <section className="card empty-state">
            <MagnifyingGlass size={32} aria-hidden="true" />
            <h1>No analysis yet</h1>
            <p className="muted">Analyse a report and its result appears here. Results are kept until this tab is closed.</p>
            <button type="button" className="button primary" onClick={open}>Analyse a report</button>
            <Link className="button ghost" href="/sample">See a sample result</Link>
          </section>
        )}
      </main>
      <AnalyzeDialog open={dialogOpen} onClose={() => setDialogOpen(false)} />
    </>
  );
}
