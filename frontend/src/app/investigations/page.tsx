"use client";

import { ArrowLeft } from "@phosphor-icons/react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { SiteHeader } from "@/components/SiteHeader";
import { AnalyzeDialog } from "@/features/analysis/AnalyzeDialog";
import { InvestigationList } from "@/features/investigation/InvestigationList";
import { Workspace } from "@/features/investigation/Workspace";

/** /investigations lists every saved investigation; /investigations?run=<id> reopens one. */
function Investigations() {
  const run = useSearchParams().get("run");
  if (!run) return <InvestigationList />;
  return (
    <section className="card investigation-card" aria-labelledby="investigation-title">
      <div className="card-head">
        <Link href="/investigations" className="small"><ArrowLeft aria-hidden="true" /> All investigations</Link>
        <h1 id="investigation-title">Investigation</h1>
      </div>
      <Workspace key={run} runId={run} />
    </section>
  );
}

export default function InvestigationsPage() {
  const [dialogOpen, setDialogOpen] = useState(false);
  return (
    <>
      <SiteHeader onNewAnalysis={() => setDialogOpen(true)} links={false} />
      <main className="app-main" id="main">
        <Suspense fallback={<p className="muted">Loading…</p>}>
          <Investigations />
        </Suspense>
      </main>
      <AnalyzeDialog open={dialogOpen} onClose={() => setDialogOpen(false)} />
    </>
  );
}
