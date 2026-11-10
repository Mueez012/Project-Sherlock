"use client";

import { ArrowRight, FileText, UploadSimple, WarningCircle } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState, type DragEvent, type FormEvent } from "react";

import { Dialog } from "@/components/Dialog";
import { toAnalysisResult } from "@/lib/adapt";
import { ApiError, MAX_TEXT_CHARS, analyze, analyzeFile } from "@/lib/api/client";
import { saveResult } from "@/lib/resultStore";
import { ACCEPT_ATTR, MAX_UPLOAD_MB, formatBytes, validateUpload } from "@/lib/upload";

export interface AnalyzeDialogProps {
  open: boolean;
  onClose: () => void;
}

/** Upload a report file or paste its text, send it to the hub, keep the result in the session and open /result. */
export function AnalyzeDialog({ open, onClose }: AnalyzeDialogProps) {
  return (
    <Dialog open={open} onClose={onClose} labelledBy="analyze-title">
      {open && <AnalyzeForm onClose={onClose} />}
    </Dialog>
  );
}

type Field = "incidentName" | "file" | "text" | "form";
type Source = "file" | "text";

function AnalyzeForm({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const ids = useId();
  const [source, setSource] = useState<Source>("file");
  const [incidentName, setIncidentName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState("");
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Partial<Record<Field, string>>>({});
  const controller = useRef<AbortController | null>(null);

  // Closing the dialog cancels a running request.
  useEffect(() => () => controller.current?.abort(), []);

  const pick = (picked: File | null) => {
    setFile(picked);
    setErrors((e) => ({ ...e, file: undefined, form: undefined }));
  };

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    if (!busy) pick(event.dataTransfer.files?.[0] ?? null);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const found: Partial<Record<Field, string>> =
      source === "file" ? validateUpload({ file, incidentName }) : {};
    if (source === "text") {
      if (!incidentName.trim()) found.incidentName = "Give the incident a name.";
      else if (incidentName.length > 200) found.incidentName = "Keep the name under 200 characters.";
      if (!text.trim()) found.text = "Paste some report text first.";
      else if (text.length > MAX_TEXT_CHARS) found.text = "The text is longer than 200,000 characters. Upload it as a file instead.";
    }
    setErrors(found);
    if (Object.keys(found).length) return;

    setBusy(true);
    controller.current = new AbortController();
    const started = performance.now();
    try {
      const response = source === "file" && file
        ? await analyzeFile(file, controller.current.signal)
        : await analyze(text, controller.current.signal);
      saveResult(toAnalysisResult({
        text, incidentName: incidentName.trim(), response, processingMs: Math.round(performance.now() - started),
        filename: source === "file" ? file?.name : null, sizeBytes: source === "file" ? file?.size : null,
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

      <div className="segmented" role="tablist" aria-label="Report source">
        {(["file", "text"] as const).map((s) => (
          <button key={s} type="button" role="tab" aria-selected={source === s} disabled={busy}
            className={source === s ? "active" : ""} onClick={() => { setSource(s); setErrors({}); }}>
            {s === "file" ? "Upload a file" : "Paste text"}
          </button>
        ))}
      </div>

      {source === "file" ? (
        <div className="field">
          <label htmlFor={`${ids}-file`} className={`drop-zone ${dragging ? "dragging" : ""} ${errors.file ? "invalid" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop}>
            {file ? <FileText size={28} aria-hidden="true" /> : <UploadSimple size={28} aria-hidden="true" />}
            <span>
              <strong>{file ? file.name : "Drop a report here, or choose a file"}</strong>
              <small>{file ? formatBytes(file.size) : `PDF, DOCX, HTML, Markdown, TXT or STIX 2.1 JSON, up to ${MAX_UPLOAD_MB} MB`}</small>
            </span>
          </label>
          <input id={`${ids}-file`} type="file" className="sr-only" accept={ACCEPT_ATTR} disabled={busy}
            onChange={(e) => pick(e.target.files?.[0] ?? null)}
            aria-invalid={!!errors.file} aria-describedby={errors.file ? `${ids}-file-err` : undefined} />
          {errors.file && <p id={`${ids}-file-err`} className="field-error">{errors.file}</p>}
        </div>
      ) : (
        <div className="field">
          <label htmlFor={`${ids}-text`}>Report text</label>
          <textarea id={`${ids}-text`} rows={9} value={text} disabled={busy}
            placeholder="Paste the report text here (no real sensitive data in demos)."
            onChange={(e) => setText(e.target.value)} aria-invalid={!!errors.text}
            aria-describedby={errors.text ? `${ids}-text-err` : undefined} />
          {errors.text && <p id={`${ids}-text-err`} className="field-error">{errors.text}</p>}
        </div>
      )}

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
