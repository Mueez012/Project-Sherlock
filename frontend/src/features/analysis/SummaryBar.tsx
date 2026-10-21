import { TACTIC_NAME } from "@/lib/attack";
import { formatBytes } from "@/lib/format";
import { STAGES, type AnalysisResult } from "@/types/analysis";

const STAGE_LABEL: Record<string, string> = Object.fromEntries(STAGES.map((s) => [s.id, s.label]));

export function SummaryBar({ result }: { result: AnalysisResult }) {
  const { document: doc, summary, model } = result;
  const bands = summary.confidence_bands;
  const items: [string, string][] = [
    ["Tactics", String(summary.n_tactics)],
    ["Techniques", String(summary.n_techniques)],
    ["High / medium / low", `${bands.high ?? 0} / ${bands.medium ?? 0} / ${bands.low ?? 0}`],
    ["Sentences analysed", `${doc.n_sentences_analyzed} of ${doc.n_sentences}`],
    ["Processing time", `${(result.processing_ms / 1000).toFixed(1)} s`],
  ];
  return (
    <section className="summary" aria-label="Analysis summary">
      <div className="summary-head">
        <div>
          <p className="eyebrow">Analysis result</p>
          <h1>{result.incident_name}</h1>
          <p className="muted">
            <span className="mono-inline">{doc.filename ?? "Pasted text"}</span>
            {" · "}{formatBytes(doc.size_bytes)}
            {doc.pages ? ` · ${doc.pages} page${doc.pages === 1 ? "" : "s"}` : ""}
            {summary.top_tactic ? ` · strongest tactic: ${TACTIC_NAME[summary.top_tactic] ?? summary.top_tactic}` : ""}
          </p>
        </div>
        <p className="model-tag">
          {model.name} <span className="mono-inline">{model.version}</span>
          <span className="muted"> · thresholds: {model.threshold_mode.replaceAll("_", " ")}</span>
        </p>
      </div>
      {Object.keys(result.timings_ms ?? {}).length > 0 && (
        <p className="timings muted">
          Stage timings:{" "}
          {Object.entries(result.timings_ms ?? {}).map(([stage, ms], i) => (
            <span key={stage}>{i > 0 ? " → " : ""}{STAGE_LABEL[stage] ?? stage} <span className="mono-inline">{ms} ms</span></span>
          ))}
        </p>
      )}
      <dl className="metrics">
        {items.map(([label, value]) => (
          <div key={label}><dt>{label}</dt><dd className="tabular">{value}</dd></div>
        ))}
      </dl>
    </section>
  );
}
