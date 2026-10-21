"use client";

import { ArrowRight, FileText, UploadSimple, WarningCircle } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import { useId, useState, type DragEvent, type FormEvent } from "react";

import { Dialog } from "@/components/Dialog";
import { ProgressBar } from "@/components/ProgressBar";
import { ApiError, createAnalysis, createTextAnalysis } from "@/lib/api/client";
import { ACCEPT_ATTR, MAX_UPLOAD_MB, formatBytes, validateUpload } from "@/lib/upload";
import type { AnalysisOptionsInput, ThresholdMode } from "@/types/analysis";

type Phase = "idle" | "uploading" | "queued";
type Source = "file" | "text";

export interface UploadDialogProps {
  open: boolean;
  onClose: () => void;
  /** Called with the new job id; defaults to navigating to /analyses/{id}. */
  onCreated?: (id: string) => void;
}

export function UploadDialog({ open, onClose, onCreated }: UploadDialogProps) {
  return (
    <Dialog open={open} onClose={onClose} labelledBy="upload-title">
      {open && <UploadForm onCreated={onCreated} />}
    </Dialog>
  );
}

function UploadForm({ onCreated }: Pick<UploadDialogProps, "onCreated">) {
  const router = useRouter();
  const ids = useId();
  const [source, setSource] = useState<Source>("file");
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState("");
  const [incidentName, setIncidentName] = useState("");
  const [mode, setMode] = useState<ThresholdMode | "default">("default");
  const [fixed, setFixed] = useState("0.5");
  const [minEvidence, setMinEvidence] = useState("1");
  const [hierarchy, setHierarchy] = useState(true);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState(0);
  const [errors, setErrors] = useState<Partial<Record<"file" | "incidentName" | "text" | "form", string>>>({});
  const [dragging, setDragging] = useState(false);
  const busy = phase !== "idle";

  const pick = (picked: File | null) => {
    setFile(picked);
    setErrors((e) => ({ ...e, file: undefined, form: undefined }));
  };

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    if (!busy) pick(event.dataTransfer.files?.[0] ?? null);
  };

  const options = (): AnalysisOptionsInput => {
    const opts: AnalysisOptionsInput = { apply_hierarchy: hierarchy, min_evidence_sentences: Number(minEvidence) || 1 };
    if (mode !== "default") opts.threshold_mode = mode;
    if (mode === "fixed") opts.fixed_threshold = Number(fixed);
    return opts;
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const found = source === "file"
      ? validateUpload({ file, incidentName })
      : { ...(text.trim() ? {} : { text: "Paste some report text first." }),
          ...(incidentName.trim() ? {} : { incidentName: "Give the incident a name." }) };
    if (mode === "fixed" && !(Number(fixed) > 0 && Number(fixed) < 1)) {
      Object.assign(found, { form: "The fixed threshold must be between 0.01 and 0.99." });
    }
    setErrors(found);
    if (Object.keys(found).length) return;
    setPhase("uploading");
    setProgress(0);
    try {
      const job = source === "file" && file
        ? await createAnalysis(file, incidentName.trim(), options(), setProgress)
        : await createTextAnalysis(text, incidentName.trim(), options());
      setPhase("queued");
      if (onCreated) onCreated(job.id);
      else router.push(`/analyses/${job.id}`);
    } catch (error) {
      setPhase("idle");
      setErrors({ form: error instanceof ApiError ? error.message : "Upload failed. Please try again." });
    }
  };

  const status = phase === "uploading"
    ? (source === "file" ? `Uploading ${Math.round(progress * 100)}%` : "Sending text")
    : phase === "queued" ? "Queued. Opening the analysis…" : "";

  return (
    <form onSubmit={submit} noValidate className="upload-form">
      <p className="eyebrow">New analysis</p>
      <h2 id="upload-title">Extract ATT&amp;CK techniques from a report</h2>
      <p className="muted">The report is analysed sentence by sentence. Results show each technique with its confidence and the sentences that support it.</p>

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
            className={source === s ? "active" : ""} onClick={() => setSource(s)}>
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
              <small>{file ? formatBytes(file.size) : `PDF, TXT, MD, HTML, DOCX or STIX 2.1 JSON · up to ${MAX_UPLOAD_MB} MB`}</small>
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
          <textarea id={`${ids}-text`} rows={7} value={text} disabled={busy}
            placeholder="Paste the report text here (no real sensitive data in demos)."
            onChange={(e) => setText(e.target.value)} aria-invalid={!!errors.text}
            aria-describedby={errors.text ? `${ids}-text-err` : undefined} />
          {errors.text && <p id={`${ids}-text-err`} className="field-error">{errors.text}</p>}
        </div>
      )}

      <details className="advanced">
        <summary>Advanced options</summary>
        <div className="advanced-grid">
          <div className="field">
            <label htmlFor={`${ids}-mode`}>Threshold mode</label>
            <select id={`${ids}-mode`} value={mode} disabled={busy} onChange={(e) => setMode(e.target.value as ThresholdMode | "default")}>
              <option value="default">Model default (report-tuned)</option>
              <option value="report_tuned">Report-tuned (validated on real CISA advisories)</option>
              <option value="fixed">Fixed value</option>
              <option value="per_slice">Per slice (tactics / techniques)</option>
              <option value="per_label">Per label (tuned on validation)</option>
            </select>
          </div>
          {mode === "fixed" && (
            <div className="field">
              <label htmlFor={`${ids}-fixed`}>Fixed threshold</label>
              <input id={`${ids}-fixed`} type="number" min={0.01} max={0.99} step={0.05} value={fixed} disabled={busy}
                onChange={(e) => setFixed(e.target.value)} />
            </div>
          )}
          <div className="field">
            <label htmlFor={`${ids}-min`}>Minimum evidence sentences</label>
            <input id={`${ids}-min`} type="number" min={1} max={20} value={minEvidence} disabled={busy}
              onChange={(e) => setMinEvidence(e.target.value)} />
          </div>
          <label className="check">
            <input type="checkbox" checked={hierarchy} disabled={busy} onChange={(e) => setHierarchy(e.target.checked)} />
            Add tactics implied by found techniques
          </label>
        </div>
        <p className="hint">Lower thresholds find more techniques but also more false positives.
          The default threshold was chosen on published CISA advisories with known ATT&amp;CK answers.</p>
      </details>

      {errors.form && (
        <p className="form-error" role="alert"><WarningCircle aria-hidden="true" weight="fill" /> {errors.form}</p>
      )}
      {phase === "uploading" && source === "file" && <ProgressBar value={progress} label="Upload progress" />}
      <p className="sr-only" aria-live="polite">{status}</p>

      <div className="dialog-actions">
        <button type="submit" className="button primary" disabled={busy}>
          {busy ? status : <>Start analysis <ArrowRight aria-hidden="true" weight="bold" /></>}
        </button>
      </div>
    </form>
  );
}
