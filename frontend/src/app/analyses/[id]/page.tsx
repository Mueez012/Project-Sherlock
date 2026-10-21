"use client";

import { use, useState } from "react";

import { SiteHeader } from "@/components/SiteHeader";
import { AnalysisView } from "@/features/analysis/AnalysisView";
import { UploadDialog } from "@/features/analysis/UploadDialog";

export default function AnalysisPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [uploadOpen, setUploadOpen] = useState(false);
  return (
    <>
      <SiteHeader onNewAnalysis={() => setUploadOpen(true)} links={false} />
      <main className="app-main" id="main">
        <AnalysisView key={id} id={id} onNewAnalysis={() => setUploadOpen(true)} />
      </main>
      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
    </>
  );
}
