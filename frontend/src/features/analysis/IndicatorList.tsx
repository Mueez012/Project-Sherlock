import type { Indicator } from "@/types/analysis";

/** Every indicator of compromise found in the report, with the sentences it appears in. */
export function IndicatorList({ indicators }: { indicators: Indicator[] }) {
  return (
    <section className="card" aria-labelledby="indicators-title">
      <div className="card-head">
        <h2 id="indicators-title">Indicators</h2>
        <p className="muted">{indicators.length} found. Sentence numbers match the report text below.</p>
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
                  <td className="tabular">{i.sentence_indices.length ? i.sentence_indices.map((n) => n + 1).join(", ") : "not in the text"}</td>
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
