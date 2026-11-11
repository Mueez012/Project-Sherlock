"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { InvestigationError, listInvestigations, type InvestigationListItem } from "@/lib/api/investigations";

import { stopLabel } from "./labels";

const PAGE = 50;
const STATUSES = ["", "ready", "completed", "cancelled", "failed"];

/** Every saved investigation, newest first, reopened in the same workspace. */
export function InvestigationList() {
  const [items, setItems] = useState<InvestigationListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    listInvestigations({ limit: PAGE, offset: 0, status })
      .then((page) => { if (live) { setItems(page.items); setTotal(page.total); setError(""); } })
      .catch((e) => { if (live) setError(e instanceof InvestigationError ? e.message : "The investigations could not be loaded."); })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [status]);

  const filter = (value: string) => {
    setLoading(true);
    setStatus(value);
  };

  const more = async () => {
    setLoading(true);
    try {
      const page = await listInvestigations({ limit: PAGE, offset: items.length, status });
      setItems((cur) => [...cur, ...page.items]);
      setTotal(page.total);
    } catch (e) {
      setError(e instanceof InvestigationError ? e.message : "The investigations could not be loaded.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="card" aria-labelledby="investigations-title">
      <div className="card-head">
        <h1 id="investigations-title">Investigations</h1>
        <p className="muted">Investigations are saved on the server. Start one from an analysis result.</p>
      </div>
      <div className="field inline-field">
        <label htmlFor="status-filter">Status</label>
        <select id="status-filter" value={status} onChange={(e) => filter(e.target.value)}>
          {STATUSES.map((s) => <option key={s} value={s}>{s ? stopLabel(s === "completed" ? "user_finished" : s === "cancelled" ? "user_cancelled" : s) : "All"}</option>)}
        </select>
      </div>
      {error && <p className="form-error" role="alert">{error}</p>}
      {!error && !loading && items.length === 0 && <p className="empty-note">No investigations yet.</p>}
      {items.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Report</th><th scope="col">Started</th><th scope="col">Status</th>
                <th scope="col" className="num">Indicators</th><th scope="col" className="num">Links</th><th scope="col" className="num">Lookups</th>
              </tr>
            </thead>
            <tbody>
              {items.map(({ run, report, counts }) => (
                <tr key={run.id}>
                  <td><Link href={`/investigations?run=${run.id}`}>{report.source || "cti report"}</Link></td>
                  <td className="tabular">{new Date(run.created_at).toLocaleString()}</td>
                  <td>{run.status === "ready" ? "Open" : stopLabel(run.stop_reason)}</td>
                  <td className="num tabular">{counts.nodes ?? 0}</td>
                  <td className="num tabular">{counts.edges ?? 0}</td>
                  <td className="num tabular">{counts.steps ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {items.length < total && (
        <button type="button" className="button secondary" disabled={loading} onClick={more}>Show more</button>
      )}
    </section>
  );
}
