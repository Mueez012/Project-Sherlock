"use client";

import { X } from "@phosphor-icons/react";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";

import { TACTIC_NAME } from "@/lib/attack";
import { percent } from "@/lib/confidence";
import { segmentText } from "@/lib/highlight";
import type { AnalysisResult, Sentence } from "@/types/analysis";

interface Props {
  result: AnalysisResult;
  /** Technique whose evidence sentences should be highlighted and scrolled to. */
  focusTechnique: string | null;
  /** Changes every time the user asks to show a technique, so the same one can pulse again. */
  focusNonce: number;
}

/** Line breaks INSIDE a sentence come from PDF line wrapping: show them as spaces.
 * Same length, so char_start / char_end offsets stay valid. */
const unwrap = (text: string) => text.replaceAll("\n", " ");

export function ReportViewer({ result, focusTechnique, focusNonce }: Props) {
  const [active, setActive] = useState<Sentence | null>(null);
  const container = useRef<HTMLDivElement>(null);
  const segments = useMemo(() => segmentText(result.document.text, result.sentences), [result]);
  const names = useMemo(() => {
    const map: Record<string, string> = { ...TACTIC_NAME };
    result.techniques.forEach((t) => { map[t.id] = t.name; });
    return map;
  }, [result]);
  const focusSet = useMemo(() => {
    const t = result.techniques.find((x) => x.id === focusTechnique);
    const fromSentences = result.sentences
      .filter((s) => s.labels.some((l) => l.id === focusTechnique && l.passed))
      .map((s) => s.index);
    return new Set([...(t?.evidence.map((e) => e.sentence_index) ?? []), ...fromSentences]);
  }, [result, focusTechnique]);

  useEffect(() => {
    if (!focusTechnique || !container.current) return;
    const first = container.current.querySelector<HTMLElement>(".sentence.focus");
    if (!first) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    first.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
    container.current.querySelectorAll<HTMLElement>(".sentence.focus").forEach((el) => {
      el.classList.remove("pulse");
      void el.offsetWidth;          // restart the CSS animation
      el.classList.add("pulse");
    });
  }, [focusTechnique, focusNonce]);

  const open = (s: Sentence) => setActive((cur) => (cur?.index === s.index ? null : s));
  const onKey = (event: KeyboardEvent, s: Sentence) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(s); }
  };

  return (
    <section className="card report-card" aria-labelledby="report-title">
      <div className="card-head">
        <h2 id="report-title">Report text</h2>
        <p className="muted">Highlighted sentences triggered at least one label. Select one to see its labels.</p>
      </div>
      <div className="report-layout">
        <div className="report-text" ref={container}>
          {segments.map((seg) => {
            if (seg.kind === "text") return <span key={`t${seg.start}`}>{seg.text}</span>;
            const s = seg.sentence;
            const hit = s.labels.some((l) => l.passed);
            if (!hit) return <span key={`s${s.index}`} className={s.skipped ? "sentence skipped" : "sentence"}>{unwrap(seg.text)}</span>;
            const classes = ["sentence", "hit", focusSet.has(s.index) ? "focus" : "", active?.index === s.index ? "active" : ""];
            return (
              <mark key={`s${s.index}`} className={classes.join(" ")} role="button" tabIndex={0}
                aria-pressed={active?.index === s.index} onClick={() => open(s)} onKeyDown={(e) => onKey(e, s)}>
                {unwrap(seg.text)}
              </mark>
            );
          })}
        </div>
        <aside className="sentence-panel" aria-live="polite">
          {active ? (
            <>
              <div className="sentence-panel-head">
                <h3>Sentence {active.index + 1}{active.page ? ` · page ${active.page}` : ""}</h3>
                <button type="button" className="icon-button" onClick={() => setActive(null)} aria-label="Close sentence details"><X aria-hidden="true" /></button>
              </div>
              <blockquote>{active.text}</blockquote>
              <ul className="label-list">
                {active.labels.map((l) => (
                  <li key={l.id} className={l.passed ? "passed" : ""}>
                    <span className="mono">{l.id}</span>
                    <span className="label-name">{names[l.id] ?? ""}</span>
                    <span className="mono tabular">{percent(l.p)}</span>
                    <span className="small muted">{l.passed ? "above threshold" : "below threshold"}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="muted">No sentence selected.</p>
          )}
        </aside>
      </div>
    </section>
  );
}
