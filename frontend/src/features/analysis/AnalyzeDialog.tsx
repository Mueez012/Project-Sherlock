"use client";

import { ArrowRight, WarningCircle } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";

import { Dialog } from "@/components/Dialog";
import { toAnalysisResult } from "@/lib/adapt";
import { ApiError, MAX_TEXT_CHARS, analyze } from "@/lib/api/client";
import { saveResult } from "@/lib/resultStore";

export interface AnalyzeDialogProps {
  open: boolean;
  onClose: () => void;
}

/** Paste a report, send it to the hub, keep the result in the session and open /result. */
export function AnalyzeDialog({ open, onClose }: AnalyzeDialogProps) {
  return (
    <Dialog open={open} onClose={onClose} labelledBy="analyze-title">
      {open && <AnalyzeForm onClose={onClose} />}
    </Dialog>
  );
}

type Field = "incidentName" | "text" | "form";

function AnalyzeForm({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const ids = useId();
  const [incidentName, setIncidentName] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Partial<Record<Field, string>>>({});
  const controller = useRef<AbortController | null>(null);

  // Closing the dialog cancels a running request.
  useEffect(() => () => controller.current?.abort(), []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const found: Partial<Record<Field, string>> = {};
    if (!incidentName.trim()) found.incidentName = "Give the incident a name.";
    else if (incidentName.length > 200) found.incidentName = "Keep the name under 200 characters.";
    if (!text.trim()) found.text = "Paste some report text first.";
    else if (text.length > MAX_TEXT_CHARS) found.text = "The text is longer than 200,000 characters. Split it into parts.";
    setErrors(found);
    if (Object.keys(found).length) return;

    setBusy(true);
    controller.current = new AbortController();
    const started = performance.now();
    try {
      const response = await analyze(text, controller.current.signal);
      saveResult(toAnalysisResult({
        text, incidentName: incidentName.trim(), response, processingMs: Math.round(performance.now() - started),
      }));
      onClose();
      router.push("/result");
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setBusy(false);
      setErrors({ form: error instanceof ApiError ? error.message : "The analysis failed. Please try again." });
    }
  };

  return (
    <form onSubmit={submit} noValidate className="upload-form">
      <p className="eyebrow">New analysis</p>
      <h2 id="analyze-title">Extract ATT&amp;CK techniques and indicators from a report</h2>
      <p className="muted">The report is analysed sentence by sentence. Results show each technique with its confidence, every indicator, and the sentences behind them.</p>

      <div className="field">
        <label htmlFor={`${ids}-name`}>Incident name</label>
        <input id={`${ids}-name`} data-autofocus value={incidentName} disabled={busy} maxLength={200}
          placeholder="e.g. Operation Silent Current" onChange={(e) => setIncidentName(e.target.value)}
          aria-invalid={!!errors.incidentName} aria-describedby={errors.incidentName ? `${ids}-name-err` : undefined} />
        {errors.incidentName && <p id={`${ids}-name-err`} className="field-error">{errors.incidentName}</p>}
      </div>

      <div className="field">
        <label htmlFor={`${ids}-text`}>Report text</label>
        <textarea id={`${ids}-text`} rows={9} value={text} disabled={busy}
          placeholder="Paste the report text here (no real sensitive data in demos)."
          onChange={(e) => setText(e.target.value)} aria-invalid={!!errors.text}
          aria-describedby={errors.text ? `${ids}-text-err` : undefined} />
        {errors.text && <p id={`${ids}-text-err`} className="field-error">{errors.text}</p>}
      </div>

      {errors.form && (
        <p className="form-error" role="alert"><WarningCircle aria-hidden="true" weight="fill" /> {errors.form}</p>
      )}
      <p className="sr-only" aria-live="polite">{busy ? "Analysing the report. This can take up to a minute." : ""}</p>

      <div className="dialog-actions">
        <button type="submit" className="button primary" disabled={busy}>
          {busy ? "Analysing… (can take up to a minute)" : <>Analyse report <ArrowRight aria-hidden="true" weight="bold" /></>}
        </button>
      </div>
    </form>
  );
}
