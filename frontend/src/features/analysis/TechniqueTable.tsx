"use client";

import { ArrowSquareOut, CaretDown, CaretRight, SortAscending, SortDescending, TextAlignLeft } from "@phosphor-icons/react";
import { Fragment, useId, useMemo, useState } from "react";

import { ConfidenceBadge } from "@/components/ConfidenceBadge";
import { ATTACK_TACTICS, TACTIC_NAME } from "@/lib/attack";
import { percent } from "@/lib/confidence";
import type { ConfidenceBand, Technique } from "@/types/analysis";

import { NO_FILTER, filterTechniques, sortTechniques, type SortDir, type SortKey, type TechniqueFilter } from "./techniqueFilters";

interface Props {
  techniques: Technique[];
  selected: string | null;
  onShowInReport: (techniqueId: string) => void;
}

const COLUMNS: { key: SortKey; label: string; numeric?: boolean }[] = [
  { key: "id", label: "Technique" },
  { key: "confidence", label: "Confidence", numeric: true },
  { key: "sentence_count", label: "Sentences", numeric: true },
];

export function TechniqueTable({ techniques, selected, onShowInReport }: Props) {
  const ids = useId();
  const [filter, setFilter] = useState<TechniqueFilter>(NO_FILTER);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: "confidence", dir: "desc" });
  const [open, setOpen] = useState<Set<string>>(new Set());

  const rows = useMemo(() => sortTechniques(filterTechniques(techniques, filter), sort.key, sort.dir),
    [techniques, filter, sort]);
  const update = (patch: Partial<TechniqueFilter>) => setFilter((f) => ({ ...f, ...patch }));
  const toggle = (id: string) => setOpen((s) => {
    const next = new Set(s);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const sortBy = (key: SortKey) => setSort((s) => ({ key, dir: s.key === key && s.dir === "desc" ? "asc" : "desc" }));

  return (
    <section className="card" aria-labelledby="table-title">
      <div className="card-head">
        <h2 id="table-title">Techniques</h2>
        <p className="muted" aria-live="polite">{rows.length} of {techniques.length} shown</p>
      </div>

      <div className="filters">
        <div className="field">
          <label htmlFor={`${ids}-q`}>Search</label>
          <input id={`${ids}-q`} type="search" value={filter.query} placeholder="ID, name or evidence text"
            onChange={(e) => update({ query: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor={`${ids}-tactic`}>Tactic</label>
          <select id={`${ids}-tactic`} value={filter.tactic} onChange={(e) => update({ tactic: e.target.value })}>
            <option value="">All tactics</option>
            {ATTACK_TACTICS.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${ids}-band`}>Confidence band</label>
          <select id={`${ids}-band`} value={filter.band} onChange={(e) => update({ band: e.target.value as ConfidenceBand | "" })}>
            <option value="">All bands</option>
            <option value="high">High (80% and above)</option>
            <option value="medium">Medium (50–79%)</option>
            <option value="low">Low (below 50%)</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${ids}-min`}>Minimum confidence: <span className="mono">{percent(filter.minConfidence)}</span></label>
          <input id={`${ids}-min`} type="range" min={0} max={1} step={0.05} value={filter.minConfidence}
            onChange={(e) => update({ minConfidence: Number(e.target.value) })} />
        </div>
      </div>

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col" className="col-expand"><span className="sr-only">Expand</span></th>
              {COLUMNS.map((c) => (
                <th key={c.key} scope="col" className={c.numeric ? "num" : ""}
                  aria-sort={sort.key === c.key ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
                  <button type="button" className="sort-button" onClick={() => sortBy(c.key)}>
                    {c.label}
                    {sort.key === c.key && (sort.dir === "asc" ? <SortAscending aria-hidden="true" /> : <SortDescending aria-hidden="true" />)}
                  </button>
                </th>
              ))}
              <th scope="col">Tactics</th>
              <th scope="col"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => {
              const expanded = open.has(t.id);
              return (
                <Fragment key={t.id}>
                  <tr className={selected === t.id ? "selected" : ""}>
                    <td className="col-expand">
                      <button type="button" className="icon-button" aria-expanded={expanded}
                        aria-controls={`${ids}-ev-${t.id}`} onClick={() => toggle(t.id)}
                        aria-label={`${expanded ? "Hide" : "Show"} evidence for ${t.id}`}>
                        {expanded ? <CaretDown aria-hidden="true" /> : <CaretRight aria-hidden="true" />}
                      </button>
                    </td>
                    <td>
                      <span className="mono">{t.id}</span> <span className="tech-name">{t.name}</span>
                    </td>
                    <td className="num"><ConfidenceBadge value={t.confidence} band={t.band} /></td>
                    <td className="num tabular">{t.sentence_count}</td>
                    <td className="tactic-cell">{t.tactic_ids.map((id) => TACTIC_NAME[id] ?? id).join(", ")}</td>
                    <td className="actions">
                      <button type="button" className="button ghost small" onClick={() => onShowInReport(t.id)}>
                        <TextAlignLeft aria-hidden="true" /> Show in report
                      </button>
                      <a className="icon-button" href={t.url} target="_blank" rel="noreferrer" aria-label={`${t.id} on attack.mitre.org (opens in a new tab)`}>
                        <ArrowSquareOut aria-hidden="true" />
                      </a>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="evidence-row" id={`${ids}-ev-${t.id}`}>
                      <td colSpan={6}>
                        <p className="muted small">
                          Strongest {t.evidence.length} of {t.sentence_count} supporting sentence{t.sentence_count === 1 ? "" : "s"} ·
                          mean confidence {percent(t.mean_confidence)} · threshold {percent(t.threshold)}
                        </p>
                        <ol className="evidence-list">
                          {t.evidence.map((e) => (
                            <li key={e.sentence_index}>
                              <span className="mono evidence-p">{percent(e.probability)}</span>
                              <q>{e.text}</q>
                              {e.page ? <span className="muted small"> (page {e.page})</span> : null}
                            </li>
                          ))}
                        </ol>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        {!rows.length && <p className="empty-note">No technique matches these filters.</p>}
      </div>
    </section>
  );
}
