// Typed client for the hub (proxied at /api by next.config.ts). One call: POST /api/analyze.
import type { AnalyzeResponse } from "@/types/analysis";

export const ANALYZE_PATH = "/api/analyze";
/** The hub's limit (contracts.AnalyzeRequest.text). */
export const MAX_TEXT_CHARS = 200_000;

/** Readable text for every error the hub (or the network) can produce. */
export const ERROR_MESSAGES: Record<string, string> = {
  invalid_input: "The text is empty or longer than 200,000 characters.",
  service_unavailable: "A model service is not available, so the hub could not analyse the report.",
  network: "Cannot reach the hub. Is the backend running?",
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

/** FastAPI errors: 422 has a list of validation problems, 503 a plain string naming the service. */
export function errorFromResponse(status: number, body: unknown): ApiError {
  const raw = body && typeof body === "object" ? (body as { detail?: unknown }).detail : undefined;
  const detail = typeof raw === "string" ? raw : `HTTP ${status}`;
  if (status === 422) return new ApiError(status, "invalid_input", detail);
  if (status === 503) return new ApiError(status, "service_unavailable", detail);
  return new ApiError(status, `http_${status}`, detail);
}

/** Send report text to the hub and return its answer. Throws ApiError (or AbortError if aborted). */
export async function analyze(text: string, signal?: AbortSignal): Promise<AnalyzeResponse> {
  let response: Response;
  try {
    response = await fetch(ANALYZE_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal,
    });
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
