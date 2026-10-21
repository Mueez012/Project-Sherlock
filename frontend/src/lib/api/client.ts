// Thin typed client for the TTP extraction API (proxied at /api/v1 by next.config.ts).
import type {
  AnalysisOptionsInput, AnalysisResult, AttackCatalog, ExportFormat, JobCreated, JobStatus,
} from "@/types/analysis";

export const API_BASE = "/api/v1";

/** Readable text for every machine error code the API can return. */
export const ERROR_MESSAGES: Record<string, string> = {
  file_too_large: "The file is too large. The limit is 20 MB.",
  unsupported_file: "This file type is not supported, or the content does not match its extension. Use PDF, TXT, MD, HTML, DOCX or a STIX 2.1 JSON bundle.",
  empty_file: "The file is empty.",
  empty_text: "Paste some report text first.",
  text_too_long: "The text is too long.",
  bad_options: "One of the advanced options is invalid.",
  queue_full: "The analysis queue is full. Please try again in a minute.",
  model_loading: "The model is still loading. Try again in a few seconds.",
  model_unavailable: "The model could not be loaded on the server.",
  not_found: "This analysis does not exist (it may have been deleted or the server restarted).",
  not_finished: "The analysis is still running.",
  job_failed: "The analysis failed.",
  no_text_layer: "This PDF has no text layer (it looks scanned). OCR is not supported yet; export the report as text instead.",
  no_text: "No readable text was found in the file.",
  too_many_sentences: "The report is too long (more than 3,000 sentences). Split it into parts.",
  model_error: "The model failed while analysing this report.",
  timeout: "The analysis took too long and was stopped.",
  network: "Cannot reach the analysis server. Is the backend running?",
};

export class ApiError extends Error {
  constructor(public status: number, public code: string, public detail: string) {
    super(ERROR_MESSAGES[code] ?? detail ?? "Unexpected error");
    this.name = "ApiError";
  }
}

export function messageFor(code: string, detail?: string): string {
  return ERROR_MESSAGES[code] ?? detail ?? "Unexpected error";
}

interface Problem { code?: string; detail?: string; status?: number }

export function parseProblem(status: number, body: unknown): ApiError {
  const problem = (body && typeof body === "object" ? body : {}) as Problem;
  return new ApiError(status, problem.code ?? `http_${status}`, problem.detail ?? `HTTP ${status}`);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(API_BASE + path, init);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "network", "network error");
  }
  const text = await response.text();
  let body: unknown = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  if (!response.ok) throw parseProblem(response.status, body);
  return body as T;
}

/**
 * Upload a report. XMLHttpRequest instead of fetch because only XHR reports
 * upload progress. onProgress receives 0..1.
 */
export function createAnalysis(
  file: File, incidentName: string, options: AnalysisOptionsInput | null,
  onProgress?: (fraction: number) => void, signal?: AbortSignal,
): Promise<JobCreated> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", file);
    form.append("incident_name", incidentName);
    if (options) form.append("options", JSON.stringify(options));
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}/analyses`);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress?.(e.loaded / e.total); };
    xhr.onload = () => {
      let body: unknown = null;
      try { body = JSON.parse(xhr.responseText); } catch { body = null; }
      if (xhr.status === 202) resolve(body as JobCreated);
      else reject(parseProblem(xhr.status, body));
    };
    xhr.onerror = () => reject(new ApiError(0, "network", "network error"));
    xhr.onabort = () => reject(new DOMException("aborted", "AbortError"));
    signal?.addEventListener("abort", () => xhr.abort());
    xhr.send(form);
  });
}

export function createTextAnalysis(text: string, incidentName: string, options: AnalysisOptionsInput | null) {
  return request<JobCreated>("/analyses/text", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, incident_name: incidentName, ...(options ? { options } : {}) }),
  });
}

export const getStatus = (id: string, signal?: AbortSignal) =>
  request<JobStatus>(`/analyses/${encodeURIComponent(id)}`, { signal });

export const getResult = (id: string, signal?: AbortSignal) =>
  request<AnalysisResult>(`/analyses/${encodeURIComponent(id)}/result`, { signal });

export const listAnalyses = (limit = 10) =>
  request<{ items: JobStatus[] }>(`/analyses?limit=${limit}`);

export const getCatalog = () => request<AttackCatalog>("/attack/techniques");

export const exportUrl = (id: string, format: ExportFormat) =>
  `${API_BASE}/analyses/${encodeURIComponent(id)}/export?format=${format}`;
