import { ArrowRight, MagnifyingGlass } from "@phosphor-icons/react";

import type { GraphNode, MethodRow, NodeMethods, Snapshot, StepExecution } from "@/lib/api/investigations";

import { admissionLabel, isProblem, outcomeLabel, reasonLabel, sourceLabel, typeLabel } from "./labels";

interface Props {
  snapshot: Snapshot;
  node: GraphNode | null;
  methods: NodeMethods | null;
  loading: boolean;
  running: boolean;
  closed: boolean;
  onRun: (method: MethodRow) => void;
  /** Present on the analysis page: highlight the indicator's sentences in the report below. */
  onShowInReport?: (node: GraphNode) => void;
}

/** The selected indicator: where it comes from, and the lookups that can be run on it. */
export function NodePanel({ snapshot, node, methods, loading, running, closed, onRun, onShowInReport }: Props) {
  if (!node) {
    return (
      <div className="node-panel empty">
        <MagnifyingGlass size={24} aria-hidden="true" />
        <p className="muted">Select an indicator in the graph to see the lookups you can run on it.</p>
      </div>
    );
  }
  const passages = (snapshot.extraction?.passages ?? []).filter((p) => node.passage_ids.includes(p.id));
  const bySource = new Map<string, MethodRow[]>();
  (methods?.methods ?? []).filter((m) => m.implemented).forEach((m) => bySource.set(m.source, [...(bySource.get(m.source) ?? []), m]));
  const canRun = !!methods?.execution_allowed && !running && !closed;

  return (
    <div className="node-panel">
      <p className="eyebrow">{typeLabel(node.type)}</p>
      <h3 className="mono indicator-value">{node.value}</h3>
      <p className="small muted">
        {node.origin === "report" ? "From the report" : "Found by a lookup"}{node.used ? " · already looked up" : ""}
      </p>
      {node.origin === "report" && onShowInReport && (
        <button type="button" className="button ghost small-button" onClick={() => onShowInReport(node)}>Show in report</button>
      )}
      {node.origin === "report" && !onShowInReport && passages.length > 0 && (
        <details className="passages">
          <summary>Where it appears ({passages.length})</summary>
          <ul>{passages.map((p) => <li key={p.id}>{p.text}</li>)}</ul>
        </details>
      )}

      <h4 className="panel-subhead">Lookups</h4>
      {loading && <p className="muted small">Loading lookups…</p>}
      {!loading && methods && !methods.execution_allowed && !closed && methods.execution_block_reason && (
        <p className="notice small">{reasonLabel(methods.execution_block_reason)}</p>
      )}
      {!loading && methods && bySource.size === 0 && (
        <p className="muted small">No lookup methods exist for {typeLabel(node.type)} indicators yet.</p>
      )}
      {[...bySource.entries()].map(([source, rows]) => (
        <div key={source} className="method-group">
          <p className="small method-source">{sourceLabel(source)}</p>
          <ul className="method-list">
            {rows.map((m) => (
              <li key={m.id}>
                <div>
                  <span className="method-name">{typeLabel(m.input_type)} <ArrowRight aria-hidden="true" size={12} /> {typeLabel(m.output_type)}</span>
                  {!m.selectable && m.unavailable_reason && <span className="small muted">{reasonLabel(m.unavailable_reason)}</span>}
                </div>
                <button type="button" className="button secondary small-button" disabled={!canRun || !m.selectable}
                  onClick={() => onRun(m)} aria-label={`Run ${sourceLabel(source)} ${m.input_type} to ${m.output_type}`}>
                  Run
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

/** The last lookup's outcome, what it found, and whether the graph took it. */
export function StepResult({ result, nodes }: { result: StepExecution; nodes: Map<string, GraphNode> }) {
  const { step } = result;
  const outputs = step.lookup?.outputs ?? [];
  const added = step.admission?.accepted;
  return (
    <div className={`step-result${isProblem(step.outcome_status) ? " problem" : ""}`} role="status">
      <p className="small muted">
        Lookup {step.sequence}: {nodes.get(step.input_node_id)?.value ?? "indicator"} · <span className="mono">{step.method_id}</span>
      </p>
      <p><strong>{outcomeLabel(step.outcome_status)}</strong>{step.error ? ` (${step.error})` : ""}</p>
      {outputs.length > 0 && (
        <ul className="output-list">
          {outputs.slice(0, 12).map((o) => <li key={`${o.type}:${o.value}`}><span className="mono">{typeLabel(o.type)}</span> <span className="mono indicator-value">{o.value}</span></li>)}
          {outputs.length > 12 && <li className="muted small">and {outputs.length - 12} more</li>}
        </ul>
      )}
      {step.admission && <p className={added ? "admitted" : "muted"}>{admissionLabel(step.admission.reason)}</p>}
      {added && <p className="small muted">+{step.delta.new_nodes ?? 0} indicators, +{step.delta.new_edges ?? 0} links</p>}
    </div>
  );
}
