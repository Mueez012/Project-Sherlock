import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  ApiError, createApiClient, locateReportPassages, newRequestId, sentenceIndicesForNode,
} from "../docs/api/frontend-client.mjs";

const seen = [];
const api = createApiClient({ fetchImpl: async (url, options) => {
  seen.push({ url, options });
  if (url.includes("/export?")) {
    return new Response('{"version":1}', { headers: { "Content-Disposition": 'attachment; filename="run.json"' } });
  }
  return Response.json({ saved: true });
} });
const key = newRequestId();
assert.match(key, /^[0-9a-f]{32}$/);
await api.createInvestigation({ text: "report" }, key);
assert.equal(seen[0].url, "/api/investigations");
assert.equal(seen[0].options.headers.get("Idempotency-Key"), key);
assert.equal(seen[0].options.headers.has("Authorization"), false);
await api.listInvestigations({ status: "ready", offset: 2 });
await api.getInvestigation("run");
await api.getMethods("run", "node");
await api.executeStep("run", { step_id: key });
await api.getStep("run", "step", { includeSnapshots: true });
await api.resumeInvestigation("run");
assert.equal(seen.at(-1).options.body, "{}");
await api.closeInvestigation("run", "finish");
const download = await api.exportInvestigation("run", { includeEvidence: false });
assert.equal(await download.blob.text(), '{"version":1}');
assert.ok(seen.at(-1).url.endsWith("include_evidence=false"));
assert.equal(seen.length, 9);

const failing = createApiClient({ fetchImpl: async () => Response.json({
  error: { code: "stale_graph_revision", message: "Reload first" },
}, { status: 409 }) });
await assert.rejects(failing.getInvestigation("run"), error =>
  error instanceof ApiError && error.status === 409 && error.code === "stale_graph_revision");

const snapshot = JSON.parse(await readFile(new URL("../docs/api/examples/snapshot-response.json", import.meta.url)));
for (const node of snapshot.graph.nodes) {
  const indices = sentenceIndicesForNode(snapshot, node);
  assert.ok(indices.every(index => index >= 0 && index < snapshot.extraction.sentences.length));
}
const spans = locateReportPassages(snapshot);
for (const span of spans) {
  assert.equal(snapshot.report.original_text.slice(span.start, span.end), snapshot.extraction.sentences[span.sentenceIndex]);
}
const repeated = {
  report: { original_text: "Intro 😀\r\nReferences\r\nRepeated sentence.\r\nAppendix\r\nRepeated sentence." },
  extraction: {
    excluded_sections: [{ start_line: 2, end_line: 3 }],
    passages: [
      { id: "intro", text: "Intro 😀", sentence_index: 0 },
      { id: "repeat", text: "Repeated sentence.", sentence_index: 1 },
    ],
  },
};
const repeatedSpans = locateReportPassages(repeated);
assert.equal(repeatedSpans[1].start, repeated.report.original_text.lastIndexOf("Repeated sentence."));
console.log("Verified all nine client operations, retry headers, error handling, downloads and report highlighting.");
