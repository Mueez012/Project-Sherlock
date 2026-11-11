import type { Indicator } from "@/types/analysis";

/** Where an indicator outside every sentence appears: its table row or line (the first one, and how many more). */
function Passage({ context = [] }: { context?: string[] }) {
  if (!context.length) return <span className="muted">not in a sentence</span>;
  const first = context[0].length > 90 ? `${context[0].slice(0, 90)}…` : context[0];
  return <span className="passage" title={context.join("\n")}>{first}{context.length > 1 ? ` (+${context.length - 1} more)` : ""}</span>;
}

/** Every indicator of compromise found in the report, with the sentences it appears in. */
export function IndicatorList({ indicators }: { indicators: Indicator[] }) {
  return (
    <section className="card" aria-labelledby="indicators-title">
      <div className="card-head">
        <h2 id="indicators-title">Indicators</h2>
        <p className="muted">{indicators.length} found. Sentence numbers match the report text below; an indicator that is
          only in a table or list shows that row instead.</p>
      </div>
      {indicators.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Value</th>
                <th scope="col">Sentences</th>
              </tr>
            </thead>
            <tbody>
              {indicators.map((i) => (
                <tr key={`${i.type}:${i.value}`}>
                  <td className="mono">{i.type}</td>
                  <td className="mono indicator-value">{i.value}</td>
                  <td className="tabular">{i.sentence_indices.length ? i.sentence_indices.map((n) => n + 1).join(", ") : <Passage context={i.context} />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-note">No indicators were found in this report.</p>
      )}
    </section>
  );
}
