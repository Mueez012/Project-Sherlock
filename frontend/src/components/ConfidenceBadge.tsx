import { BAND_LABEL, percent } from "@/lib/confidence";
import type { ConfidenceBand } from "@/types/analysis";

/** Confidence is never shown by colour alone: the number and the band name are always there. */
export function ConfidenceBadge({ value, band, compact = false }: { value: number; band: ConfidenceBand; compact?: boolean }) {
  return (
    <span className={`confidence-badge band-${band}`} data-band={band}
      aria-label={`${BAND_LABEL[band]} confidence, ${percent(value)}`}>
      <span className="mono">{percent(value)}</span>
      {!compact && <span className="band-label">{BAND_LABEL[band]}</span>}
    </span>
  );
}
