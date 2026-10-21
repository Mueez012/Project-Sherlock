import { DownloadSimple } from "@phosphor-icons/react";

import { exportUrl } from "@/lib/api/client";
import type { ExportFormat } from "@/types/analysis";

const FORMATS: { format: ExportFormat; label: string; hint: string }[] = [
  { format: "json", label: "JSON", hint: "full result" },
  { format: "csv", label: "CSV", hint: "one row per technique" },
  { format: "navigator", label: "Navigator layer", hint: "open in ATT&CK Navigator" },
  { format: "stix", label: "STIX 2.1", hint: "report + attack-patterns" },
];

export function ExportMenu({ id }: { id: string }) {
  return (
    <nav className="export-menu" aria-label="Export the result">
      <span className="export-label">Export</span>
      {FORMATS.map((f) => (
        <a key={f.format} className="button secondary small" href={exportUrl(id, f.format)} download title={f.hint}>
          <DownloadSimple aria-hidden="true" /> {f.label}
        </a>
      ))}
    </nav>
  );
}
