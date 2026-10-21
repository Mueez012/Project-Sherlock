"use client";

import { ArrowRight } from "@phosphor-icons/react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { listAnalyses } from "@/lib/api/client";
import type { JobStatus } from "@/types/analysis";

const STATUS_LABEL: Record<string, string> = { completed: "Completed", failed: "Failed" };

export function RecentAnalyses() {
  const [items, setItems] = useState<JobStatus[] | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let alive = true;
    listAnalyses(8)
      .then((r) => { if (alive) setItems(r.items); })
      .catch(() => { if (alive) setOffline(true); });
    return () => { alive = false; };
  }, []);

  if (offline) return <p className="muted">The analysis server is not reachable, so recent analyses cannot be listed. Start the backend (see README).</p>;
  if (!items) return <p className="muted">Loading…</p>;
  if (!items.length) return <p className="muted">No analyses yet. Upload a report to start. Jobs are kept in memory until the server restarts.</p>;
  return (
    <ul className="recent-list">
      {items.map((job) => (
        <li key={job.id}>
          <Link href={`/analyses/${job.id}`}>
            <span className="recent-name">{job.incident_name}</span>
            <span className="muted mono-inline">{job.filename ?? "pasted text"}</span>
            <span className={`status-pill status-${job.status}`}>{STATUS_LABEL[job.status] ?? "Running"}</span>
            <span className="muted tabular">{new Date(job.created_at).toLocaleString()}</span>
            <ArrowRight aria-hidden="true" />
          </Link>
        </li>
      ))}
    </ul>
  );
}
