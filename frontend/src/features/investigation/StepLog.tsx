import type { GraphNode, StepSummary } from "@/lib/api/investigations";

import { isProblem, outcomeLabel } from "./labels";

/** Every lookup run in this investigation, newest first. */
export function StepLog({ steps, nodes, onEvidence }: { steps: StepSummary[]; nodes: Map<string, GraphNode>; onEvidence: (stepId: string) => void }) {
  if (!steps.length) return <p className="empty-note">No lookups yet. Select an indicator and run one.</p>;
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col" className="tabular">#</th>
            <th scope="col">Indicator</th>
            <th scope="col">Method</th>
            <th scope="col">Outcome</th>
            <th scope="col">Graph</th>
            <th scope="col"><span className="sr-only">Evidence</span></th>
          </tr>
        </thead>
        <tbody>
          {[...steps].sort((a, b) => b.sequence - a.sequence).map((s) => (
            <tr key={s.id}>
              <td className="tabular">{s.sequence}</td>
              <td className="mono indicator-value">{nodes.get(s.input_node_id)?.value ?? "—"}</td>
              <td className="mono">{s.method_id}</td>
              <td className={isProblem(s.outcome_status) ? "warn-text" : ""}>{outcomeLabel(s.outcome_status)}</td>
              <td>{s.admission?.accepted ? `+${s.delta.new_nodes ?? 0} / +${s.delta.new_edges ?? 0}` : s.status === "running" ? "—" : "Not added"}</td>
              <td><button type="button" className="link-button" onClick={() => onEvidence(s.id)}>Evidence</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
