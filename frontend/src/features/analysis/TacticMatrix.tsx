import { ATTACK_TACTICS } from "@/lib/attack";
import { BAND_LABEL, percent } from "@/lib/confidence";
import type { Tactic, Technique } from "@/types/analysis";

interface Props {
  tactics: Tactic[];
  techniques: Technique[];
  selected: string | null;
  onSelect: (techniqueId: string) => void;
}

/** 14 ATT&CK tactics as columns in kill-chain order; found techniques sit under their tactics. */
export function TacticMatrix({ tactics, techniques, selected, onSelect }: Props) {
  const found = new Map(tactics.map((t) => [t.id, t]));
  return (
    <section className="card" aria-labelledby="matrix-title">
      <div className="card-head">
        <h2 id="matrix-title">ATT&amp;CK matrix</h2>
        <p className="muted">Kill-chain order, left to right. Greyed columns: no technique found.</p>
      </div>
      <div className="matrix-scroll" tabIndex={0} aria-label="Tactic matrix, scrolls horizontally">
        <div className="matrix" role="list">
          {ATTACK_TACTICS.map((tactic) => {
            const info = found.get(tactic.id);
            const items = techniques.filter((t) => t.tactic_ids.includes(tactic.id));
            return (
              <div key={tactic.id} role="listitem" className={`matrix-col ${info ? "" : "empty"}`}>
                <div className="matrix-head">
                  <span className="matrix-name">{tactic.name}</span>
                  <span className="mono-small">{tactic.id}</span>
                  {info ? (
                    <span className="matrix-meta">
                      {percent(info.confidence)}
                      {info.source === "implied_by_technique" && <span title="Not predicted directly; implied by a found technique"> · implied</span>}
                    </span>
                  ) : <span className="matrix-meta">None found</span>}
                </div>
                <ul className="chip-list">
                  {items.map((t) => (
                    <li key={t.id}>
                      <button type="button" className={`chip band-${t.band} ${selected === t.id ? "selected" : ""}`}
                        aria-pressed={selected === t.id} onClick={() => onSelect(t.id)}
                        aria-label={`${t.id} ${t.name}, ${BAND_LABEL[t.band]} confidence ${percent(t.confidence)}. Show evidence.`}>
                        <span className="chip-top"><span className="mono">{t.id}</span><span className="mono">{percent(t.confidence)}</span></span>
                        <span className="chip-name">{t.name}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
