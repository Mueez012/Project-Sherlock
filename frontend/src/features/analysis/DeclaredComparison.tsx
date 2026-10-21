"use client";

import { useEffect, useState } from "react";

import { getCatalog } from "@/lib/api/client";
import type { AnalysisResult } from "@/types/analysis";

/** Parent technique id (T1566.002 -> T1566). */
const parent = (id: string) => id.split(".")[0];

export interface Comparison {
  matched: string[];
  missed: string[];
  missedOutsideModel: string[];
  extra: string[];
  precision: number;
  recall: number;
  f1: number;
}

/**
 * Compare the ATT&CK ids a STIX upload already declared (never shown to the model) with the
 * techniques the model found. Ids the model cannot predict (outside its label set) are kept
 * apart and do not count as misses.
 */
export function compareDeclared(declared: string[], found: string[], modelLabels: Set<string> | null): Comparison {
  const gold = new Set(declared.map(parent));
  const pred = new Set(found.map(parent));
  const inSpace = (t: string) => !modelLabels || modelLabels.has(t);
  const matched = [...pred].filter((t) => gold.has(t)).sort();
  const missed = [...gold].filter((t) => !pred.has(t) && inSpace(t)).sort();
  const missedOutsideModel = [...gold].filter((t) => !pred.has(t) && !inSpace(t)).sort();
  const extra = [...pred].filter((t) => !gold.has(t)).sort();
  const precision = pred.size ? matched.length / pred.size : 0;
  const goldInSpace = matched.length + missed.length;
  const recall = goldInSpace ? matched.length / goldInSpace : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { matched, missed, missedOutsideModel, extra, precision, recall, f1 };
}

function Chips({ ids, names, kind }: { ids: string[]; names: Record<string, string>; kind: string }) {
  if (!ids.length) return <p className="muted small">None</p>;
  return (
    <ul className={`compare-chips ${kind}`}>
      {ids.map((id) => <li key={id}><span className="mono">{id}</span> {names[id] ?? ""}</li>)}
    </ul>
  );
}

export function DeclaredComparison({ result }: { result: AnalysisResult }) {
  const declared = result.document.declared_ttps ?? [];
  const [labels, setLabels] = useState<Set<string> | null>(null);
  const [names, setNames] = useState<Record<string, string>>({});

  useEffect(() => {
    let alive = true;
    getCatalog()
      .then((c) => {
        if (!alive) return;
        setLabels(new Set(c.techniques.map((t) => t.id)));
        setNames(Object.fromEntries(c.techniques.map((t) => [t.id, t.name])));
      })
      .catch(() => { /* offline: every declared id counts */ });
    return () => { alive = false; };
  }, []);

  if (!declared.length) return null;
  const c = compareDeclared(declared, result.techniques.map((t) => t.id), labels);
  const allNames = { ...names, ...Object.fromEntries(result.techniques.map((t) => [t.id, t.name])) };
  const pct = (x: number) => `${Math.round(x * 100)}%`;

  return (
    <section className="card compare" aria-labelledby="compare-title">
      <div className="card-head">
        <h2 id="compare-title">Model vs. techniques declared in the report</h2>
        <p className="muted">The uploaded STIX bundle listed {declared.length} ATT&amp;CK ids. They were not shown to the model.</p>
      </div>
      <dl className="metrics compare-metrics">
        <div><dt>Matched</dt><dd className="tabular">{c.matched.length}</dd></div>
        <div><dt>Missed</dt><dd className="tabular">{c.missed.length}</dd></div>
        <div><dt>Extra (not declared)</dt><dd className="tabular">{c.extra.length}</dd></div>
        <div><dt>Precision / recall</dt><dd className="tabular">{pct(c.precision)} / {pct(c.recall)}</dd></div>
        <div><dt>F1</dt><dd className="tabular">{pct(c.f1)}</dd></div>
      </dl>
      <div className="compare-grid">
        <div><h3>Matched ({c.matched.length})</h3><Chips ids={c.matched} names={allNames} kind="matched" /></div>
        <div><h3>Missed ({c.missed.length})</h3><Chips ids={c.missed} names={allNames} kind="missed" /></div>
        <div><h3>Extra ({c.extra.length})</h3><Chips ids={c.extra} names={allNames} kind="extra" /></div>
      </div>
      {c.missedOutsideModel.length > 0 && (
        <p className="muted small">Not counted: {c.missedOutsideModel.join(", ")} (outside the model&apos;s 189 techniques).</p>
      )}
    </section>
  );
}
