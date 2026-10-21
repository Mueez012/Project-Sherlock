"use client";

import { Flask } from "@phosphor-icons/react";
import { useState } from "react";

import { SiteHeader } from "@/components/SiteHeader";
import { ResultView } from "@/features/analysis/AnalysisView";
import { UploadDialog } from "@/features/analysis/UploadDialog";
import sample from "@/mocks/analysis-result.json";
import type { AnalysisResult } from "@/types/analysis";

// A real model output for a SYNTHETIC report (tests/data/synthetic_report.txt in the backend),
// stored in src/mocks so the result page can be shown without the backend running.
export default function SamplePage() {
  const [uploadOpen, setUploadOpen] = useState(false);
  return (
    <>
      <SiteHeader onNewAnalysis={() => setUploadOpen(true)} links={false} />
      <main className="app-main" id="main">
        <p className="notice"><Flask aria-hidden="true" weight="fill" /> Sample result: the report is synthetic and was written for testing. Export links need the backend.</p>
        <ResultView result={sample as AnalysisResult} onNewAnalysis={() => setUploadOpen(true)} />
      </main>
      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
    </>
  );
}
