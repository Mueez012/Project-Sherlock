/**
 * Project Sherlock frontend API example. No framework or external dependencies.
 * Request/response types are defined in the accompanying OpenAPI specification.
 * This client does not invent identity credentials or automatically retry work.
 */

export function newRequestId() {
  return globalThis.crypto.randomUUID().replaceAll("-", "");
}

export class ApiError extends Error {
  constructor(status, payload) {
    super(payload?.error?.message || `API request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.code = payload?.error?.code || "http_error";
    this.payload = payload;
  }
}

export function createApiClient({ baseUrl = "", authorization, fetchImpl = globalThis.fetch } = {}) {
  const root = baseUrl.replace(/\/$/, "");
  const prefix = "/api/investigations";
  const segment = value => encodeURIComponent(value);
  const runPath = id => `${prefix}/${segment(id)}`;

  async function request(method, path, { body, key, signal, download = false } = {}) {
    const headers = new Headers();
    const identity = typeof authorization === "function" ? await authorization() : authorization;
    if (identity) headers.set("Authorization", identity);
    if (body !== undefined) headers.set("Content-Type", "application/json");
    if (key !== undefined) headers.set("Idempotency-Key", key);
    const response = await fetchImpl(root + path, {
      method, headers, signal,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      let payload;
      try { payload = await response.json(); } catch { payload = null; }
      throw new ApiError(response.status, payload);
    }
    if (download) {
      return {
        blob: await response.blob(),
        contentDisposition: response.headers.get("Content-Disposition"),
      };
    }
    return response.json();
  }

  return {
    createInvestigation(body, creationKey, { signal } = {}) {
      if (!creationKey) throw new TypeError("Retain and supply a creation key.");
      return request("POST", prefix, { body, key: creationKey, signal });
    },
    listInvestigations({ limit = 50, offset = 0, status, signal } = {}) {
      const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
      if (status !== undefined) query.set("status", status);
      return request("GET", `${prefix}?${query}`, { signal });
    },
    getInvestigation(runId, { signal } = {}) {
      return request("GET", runPath(runId), { signal });
    },
    getMethods(runId, nodeId, { signal } = {}) {
      return request("GET", `${runPath(runId)}/nodes/${segment(nodeId)}/methods`, { signal });
    },
    executeStep(runId, body, { signal } = {}) {
      return request("POST", `${runPath(runId)}/steps`, { body, signal });
    },
    getStep(runId, stepId, { includeSnapshots = false, signal } = {}) {
      const query = new URLSearchParams({ include_snapshots: String(includeSnapshots) });
      return request("GET", `${runPath(runId)}/steps/${segment(stepId)}?${query}`, { signal });
    },
    resumeInvestigation(runId, { signal } = {}) {
      return request("POST", `${runPath(runId)}/resume`, { body: {}, signal });
    },
    closeInvestigation(runId, action, { signal } = {}) {
      return request("POST", `${runPath(runId)}/close`, { body: { action }, signal });
    },
    exportInvestigation(runId, { includeEvidence = true, signal } = {}) {
      const query = new URLSearchParams({ include_evidence: String(includeEvidence) });
      return request("GET", `${runPath(runId)}/export?${query}`, { signal, download: true });
    },
  };
}

/** Resolve existing backend associations; do not re-extract or split text. */
export function sentenceIndicesForNode(snapshot, node) {
  if (!snapshot.extraction) return [];
  const passages = new Map(snapshot.extraction.passages.map(passage => [passage.id, passage]));
  const indices = node.passage_ids.map(id => {
    const passage = passages.get(id);
    if (!passage) throw new Error(`Saved passage not found: ${id}`);
    return passage.sentence_index;
  });
  return [...new Set(indices)].sort((a, b) => a - b);
}

/**
 * Locate retained native passages in the original report, skipping excluded
 * reference ranges. Returns JS UTF-16 positions; throws rather than silently
 * rewriting report text when an occurrence cannot be located.
 */
export function locateReportPassages(snapshot) {
  if (!snapshot.extraction) return [];
  const text = snapshot.report.original_text;
  const offsets = [0];
  for (const line of text.match(/[^\r\n]*(?:\r\n|\r|\n|$)/g) || []) {
    offsets.push(offsets[offsets.length - 1] + line.length);
  }
  const excluded = snapshot.extraction.excluded_sections.map(section => ({
    start: offsets[section.start_line - 1] ?? text.length,
    end: offsets[section.end_line] ?? text.length,
  }));
  let cursor = 0;
  return snapshot.extraction.passages.map(passage => {
    let start = text.indexOf(passage.text, cursor);
    while (start >= 0 && excluded.some(range => start < range.end && start + passage.text.length > range.start)) {
      start = text.indexOf(passage.text, start + 1);
    }
    if (start < 0) throw new Error(`Cannot locate retained passage: ${passage.id}`);
    const end = start + passage.text.length;
    cursor = end;
    return { passageId: passage.id, sentenceIndex: passage.sentence_index, start, end };
  });
}
