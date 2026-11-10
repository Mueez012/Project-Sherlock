// Typed client for the hub (proxied at /api by next.config.ts): POST /api/analyze (text) and
// POST /api/analyze/file (a report file).
import type { AnalyzeResponse } from "@/types/analysis";

export const ANALYZE_PATH = "/api/analyze";
export const ANALYZE_FILE_PATH = "/api/analyze/file";
/** The hub's limit (contracts.AnalyzeRequest.text). */
export const MAX_TEXT_CHARS = 200_000;

/** Readable text for every error the hub (or the network) can produce. */
export const ERROR_MESSAGES: Record<string, string> = {
  invalid_input: "The text is empty or longer than 200,000 characters.",
  service_unavailable: "A model service is not available, so the hub could not analyse the report.",
  network: "Cannot reach the hub. Is the backend running?",
  unsupported_file: "This file cannot be read. Use a PDF, DOCX, HTML, Markdown, TXT or STIX 2.1 JSON file.",
  no_text_layer: "This PDF has no text layer (it looks scanned), and scanned PDFs are not supported. Use a PDF with selectable text, or paste the text.",
  no_text: "No readable text was found in the file.",
  file_too_large: "The file is too large. The limit is 20 MB and 1,000,000 characters of text.",
};

export class ApiError extends Error {
  constructor(public status: number, public code: string, public detail: string) {
    super(messageFor(code, detail));
    this.name = "ApiError";
  }
}

/** The friendly message for a code; a 503 also shows the hub's own detail (which service, and why). */
export function messageFor(code: string, detail?: string): string {
  if (code === "service_unavailable" && detail) return `${ERROR_MESSAGES.service_unavailable} (${detail})`;
  return ERROR_MESSAGES[code] ?? detail ?? "Unexpected error";
}

/**
 * Hub errors: a 422 is either FastAPI's list of validation problems or, for a file, "<code>: <reason>";
 * a 413 is a file over the limits; a 503 is a plain string naming the service.
 */
export function errorFromResponse(status: number, body: unknown): ApiError {
  const raw = body && typeof body === "object" ? (body as { detail?: unknown }).detail : undefined;
  const detail = typeof raw === "string" ? raw : `HTTP ${status}`;
  if (status === 422) {
    const code = /^(unsupported_file|no_text_layer|no_text): /.exec(detail)?.[1];
    return new ApiError(status, code ?? "invalid_input", detail);
  }
  if (status === 413) return new ApiError(status, "file_too_large", detail);
  if (status === 503) return new ApiError(status, "service_unavailable", detail);
  return new ApiError(status, `http_${status}`, detail);
}

async function post(path: string, init: RequestInit, signal?: AbortSignal): Promise<AnalyzeResponse> {
  let response: Response;
  try {
    response = await fetch(path, { method: "POST", ...init, signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "network", "network error");
  }
  const raw = await response.text();
  let body: unknown = null;
  try { body = raw ? JSON.parse(raw) : null; } catch { body = null; }
  if (!response.ok) throw errorFromResponse(response.status, body);
  return body as AnalyzeResponse;
}

/** Send report text to the hub and return its answer. Throws ApiError (or AbortError if aborted). */
export function analyze(text: string, signal?: AbortSignal): Promise<AnalyzeResponse> {
  return post(ANALYZE_PATH, { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) }, signal);
}

/** Send a report file to the hub; it reads the file, so the answer carries the text it analysed. */
export function analyzeFile(file: File, signal?: AbortSignal): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append("file", file);
  return post(ANALYZE_FILE_PATH, { body: form }, signal);
}
