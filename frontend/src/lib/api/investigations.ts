// Client for saved IOC investigations: the hub forwards /api/investigations/* to IOC Hunter unchanged.
// Types come from IOC Hunter's own OpenAPI (npm run gen:investigations). Every call waits for the server to finish:
// creating extracts the report's indicators; a step runs one provider lookup (provider pacing makes it slow).
import type { components } from "./investigations.schema";

type S = components["schemas"];
export type Snapshot = S["InvestigationSnapshot"];
export type Run = S["RunMetadata"];
export type Graph = S["Graph"];
export type GraphNode = S["GraphNode"];
export type GraphEdge = S["GraphEdge"];
export type NodeMethods = S["NodeMethods"];
export type MethodRow = S["MethodRow"];
export type CreateStep = S["CreateStep"];
export type StepExecution = S["StepExecution"];
export type StepSummary = S["StepSummary"];
export type StepDetail = S["StepDetail"];
export type InvestigationList = S["InvestigationList"];
export type InvestigationListItem = S["InvestigationListItem"];

export const INVESTIGATIONS_PATH = "/api/investigations";

/** Plain words for IOC Hunter's error codes (and the hub's own 503). */
export const INVESTIGATION_ERRORS: Record<string, string> = {
  not_found: "This investigation (or the item in it) no longer exists.",
  stale_graph_revision: "The graph changed in the meantime (for example in another tab). It has been reloaded; choose again.",
  operation_in_progress: "A lookup is still running for this investigation. Wait for it to finish.",
  step_in_progress: "This lookup is still running on the server.",
  run_closed: "This investigation is closed, so nothing more can be run.",
  recovery_required: "A lookup was interrupted (the server restarted). Recover it before running another one.",
  limit_reached: "This investigation has reached its step or time limit and has stopped.",
  method_unavailable: "This lookup method is not available right now.",
  idempotency_conflict: "This request clashes with an earlier one. Reload the page and try again.",
  saved_configuration_unavailable: "This investigation's saved configuration can no longer be run here.",
  invalid_request: "The request was not accepted.",
  internal_error: "The server could not save the result.",
  service_unavailable: "The indicator service is not reachable right now.",
  network: "Cannot reach the hub. Is the backend running?",
};

export class InvestigationError extends Error {
  constructor(public status: number, public code: string, public detail: string) {
    super(INVESTIGATION_ERRORS[code] ?? (detail || `Request failed (${status})`));
    this.name = "InvestigationError";
  }
}

/** A new random key or step id: 32 lowercase hex characters, as IOC Hunter requires. */
export function newRequestId(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

/** IOC Hunter answers {"error": {code, message}}; the hub's own 503 (IOC Hunter unreachable) is {"detail": "..."}. */
export function investigationError(status: number, body: unknown): InvestigationError {
  const obj = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const error = obj.error && typeof obj.error === "object" ? (obj.error as Record<string, unknown>) : null;
  if (error && typeof error.code === "string") return new InvestigationError(status, error.code, String(error.message ?? ""));
  if (status === 503) return new InvestigationError(status, "service_unavailable", typeof obj.detail === "string" ? obj.detail : "");
  return new InvestigationError(status, `http_${status}`, typeof obj.detail === "string" ? obj.detail : "");
}

async function call<T>(path: string, init: RequestInit = {}): Promise<{ status: number; body: T; response: Response }> {
  let response: Response;
  try {
    response = await fetch(`${INVESTIGATIONS_PATH}${path}`, init);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new InvestigationError(0, "network", "network error");
  }
  if (!response.ok) {
    let body: unknown = null;
    try { body = await response.json(); } catch { body = null; }
    throw investigationError(response.status, body);
  }
  const isJson = (response.headers.get("content-type") ?? "").includes("json");
  return { status: response.status, body: (isJson ? await response.json() : null) as T, response };
}

const json = (body: unknown, extra: Record<string, string> = {}): RequestInit => ({
  method: "POST", headers: { "Content-Type": "application/json", ...extra }, body: JSON.stringify(body),
});

/** Create an investigation from report text. Reusing `key` after a lost answer returns the same investigation. */
export async function createInvestigation(text: string, source: string, key: string, signal?: AbortSignal) {
  const { body } = await call<Snapshot>("", { ...json({ text, source }, { "Idempotency-Key": key }), signal });
  return body;
}

export async function listInvestigations(params: { limit?: number; offset?: number; status?: string } = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== "") query.set(k, String(v)); });
  const { body } = await call<InvestigationList>(query.size ? `?${query}` : "");
  return body;
}

export async function readInvestigation(runId: string) {
  return (await call<Snapshot>(`/${encodeURIComponent(runId)}`)).body;
}

export async function nodeMethods(runId: string, nodeId: string) {
  return (await call<NodeMethods>(`/${encodeURIComponent(runId)}/nodes/${encodeURIComponent(nodeId)}/methods`)).body;
}

/** Run one lookup. Sending the same step_id again returns the saved result instead of looking up twice. */
export async function runStep(runId: string, step: CreateStep, signal?: AbortSignal) {
  return (await call<StepExecution>(`/${encodeURIComponent(runId)}/steps`, { ...json(step), signal })).body;
}

export async function stepDetail(runId: string, stepId: string, includeSnapshots = true) {
  const query = includeSnapshots ? "?include_snapshots=true" : "";
  return (await call<StepDetail>(`/${encodeURIComponent(runId)}/steps/${encodeURIComponent(stepId)}${query}`)).body;
}

export async function recoverInvestigation(runId: string) {
  return (await call<Snapshot>(`/${encodeURIComponent(runId)}/resume`, json({}))).body;
}

export async function closeInvestigation(runId: string, action: "finish" | "cancel") {
  return (await call<Snapshot>(`/${encodeURIComponent(runId)}/close`, json({ action }))).body;
}

/** The saved investigation as a JSON file (graph, steps and evidence). */
export async function exportInvestigation(runId: string): Promise<{ blob: Blob; filename: string }> {
  let response: Response;
  try {
    response = await fetch(`${INVESTIGATIONS_PATH}/${encodeURIComponent(runId)}/export`);
  } catch {
    throw new InvestigationError(0, "network", "network error");
  }
  if (!response.ok) {
    let body: unknown = null;
    try { body = await response.json(); } catch { body = null; }
    throw investigationError(response.status, body);
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = /filename="?([^";]+)"?/.exec(disposition)?.[1] ?? `investigation-${runId}.json`;
  return { blob: await response.blob(), filename };
}
