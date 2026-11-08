# Project Sherlock: Frontend API Reference

**Implemented API · Audience: frontend developers**

Use this reference to build report submission, IOC review, method selection,
lookup execution, evidence inspection, investigation history, reopening and JSON
export. It describes the implemented API, not a proposed interface.

The system has one investigation engine and one database, in the IOC container's
`ioc-data` volume. Terminal runs inside the container (`docker compose exec ioc
ioc-hunter ...`) and browser operations access the same saved investigations. Within
an investigation, IOC Hunter's saved sentences and passages are the source of truth
for highlighting that investigation's report. There are no users and no login.

## 1. Files in this handoff

| File | Use |
| --- | --- |
| `index.html` | Readable offline reference with a searchable table of contents; open in a browser |
| `FRONTEND_API_REFERENCE.md` | Markdown copy of this reference |
| `openapi.json` | Machine-readable API, including request and response schemas (IOC Hunter's schemas at the Hub's paths) |
| `frontend-client.mjs` | Dependency-free JavaScript client and highlight helpers |
| `examples/manifest.json` | HTTP methods, paths, statuses and headers for every captured example |
| `examples/*-request.json` | Complete request bodies |
| `examples/*-response.json` | Complete example responses |

All example responses were generated offline through the actual Hub and IOC
HTTP routes using synthetic fixtures. No external provider was contacted. Sample
`mode: "replay"` and method fixture availability are specific to these examples;
normal API creation uses the server's configured live mode. The export example
replaces its absolute server fixture path with a neutral example path. No other
response fields are shortened or redacted.

## 2. Connection

### Browser address

Browser clients use **`/api/investigations` on the Hub**, normally through the
frontend's same-origin proxy:

```text
Browser -> frontend /api proxy -> FastAPI Hub -> IOC HTTP service -> shared workflow/database
```

| Development surface | Example address |
| --- | --- |
| Existing Next.js frontend/proxy | `http://localhost:3000/api/investigations` |
| Direct Hub API | `http://localhost:8000/api/investigations` |
| Hub Swagger UI | `http://localhost:8000/docs` |
| Hub OpenAPI | `http://localhost:8000/openapi.json` |

Ports are deployment configuration; obtain the actual Hub address from the
backend owner. In the existing frontend, use relative `/api/...` URLs. Next.js
forwards them using its configured `API_ORIGIN`. A different frontend development
server needs an equivalent proxy. The Hub currently has no CORS middleware, so
cross-origin browser requests are not automatically enabled.

The Hub forwards every `/api/investigations` request unchanged to IOC Hunter's
`/v1/investigations` route of the same name and returns its answer unchanged.
Frontend code should use the public `/api/investigations` routes throughout this
document. The Hub's `/docs` lists these routes without field details; this
reference and `openapi.json` have the full models. The existing frontend proxy
only forwards `/api/*`.

Provider credentials such as VirusTotal/OTX keys are server configuration and
are not fields in these frontend requests.

### Request conventions

- Use JSON and `Content-Type: application/json` for all POST requests.
- GET requests have no body. Boolean query values are `true` or `false`.
- The create operation requires an `Idempotency-Key` header.
- Generate new creation keys and step IDs as **32 lowercase hexadecimal
  characters**, for example `crypto.randomUUID().replaceAll("-", "")`.
- Retain those IDs across retries. Generate a new ID only for deliberate new work.
- Treat server run/node IDs as opaque. Do not calculate node IDs from IOC values.
- Caller-supplied `sentences`, graph nodes, store paths, replay paths
  and unknown POST body fields are rejected.
- Service-generated timestamps use ISO 8601 UTC. Pending `finished_at` is `""`.
  Provider `observed_at` can be empty, date-only, epoch text or another source
  representation; it is not guaranteed to be an ISO timestamp.

## 3. Frontend workflow

1. Submit the original report text to **POST `/api/investigations`**. Keep the
   creation key until a run ID is known. This creates the saved run and extracts
   its IOCs once.
2. Store `run.id` in the route URL. Render the report, saved native sentences,
   graph nodes and extraction diagnostics from the returned snapshot.
3. Selecting an IOC calls its **GET `/nodes/{node_id}/methods`** route.
4. Enable a method action only when both `execution_allowed` and that method's
   `selectable` are true.
5. Generate a step ID and POST the selected node/method plus the viewed graph
   revision. Retain the complete request until its outcome is known.
6. Update run/graph state from the step response. Display provider outcome,
   observations, rejected candidates, admission and graph changes separately.
7. Leaving the page requires no save request. Reopen with GET by run ID.
8. Use explicit recovery only for interrupted server work. Finish/cancel closes
   an idle investigation; export downloads its saved JSON.

Different investigations can progress concurrently. Competing mutations of the
same investigation are coordinated by the backend. Shared provider pacing can
delay or block a particular acquisition without mixing investigation results.

### What the API currently supports

| Supported | Not currently provided |
| --- | --- |
| Report text in JSON, saved extraction and graph | Multipart PDF/DOCX/binary upload or conversion |
| Manual node/method selection | Automatic Algorithm 1 ranking or LLM selection |
| Saved steps, receipts, evidence and raw response inspection | Percentage progress, SSE or WebSocket updates |
| History, reopening, explicit recovery, close and JSON export | Delete, rename, clone, CSV/STIX export or hard in-flight cancellation endpoints |
| Synchronous request/response execution | A `202` background-job submission contract |

A successful POST waits for extraction or lookup completion. `201` is not a
queued-job acknowledgment. A browser timeout or aborted fetch does not prove that
the server worker stopped.

## 4. Endpoint index

In this table, `I` means `/api/investigations/{run_id}`.

| Method and path | Success body | HTTP success |
| --- | --- | --- |
| POST `/api/investigations` | `InvestigationSnapshot` | 201 new; 200 identical creation retry |
| GET `/api/investigations` | `InvestigationList` | 200 |
| GET `I` | `InvestigationSnapshot` | 200 |
| GET `I/nodes/{node_id}/methods` | `NodeMethods` | 200 |
| POST `I/steps` | `StepExecution` | 201 new saved step; 200 completed retry |
| GET `I/steps/{step_id}` | `StepDetail` | 200 |
| POST `I/resume` | `InvestigationSnapshot` | 200 |
| POST `I/close` | `InvestigationSnapshot` | 200 |
| GET `I/export` | Native investigation export JSON attachment | 200 |

The generated model reference below and `openapi.json` define all public fields.

## 5. Create an investigation

**POST `/api/investigations`**

Required header: `Idempotency-Key: <retained 32-character lowercase hex key>`.

```json
{
  "text": "This synthetic CTI report is an offline workflow example, not a real incident.\nThe loader contacted example.com for its configuration.\nThe report also lists 192.0.2.10 as an observed address.\nThe sample SHA256 is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.\n\nReferences\nhttps://publisher.example/reference\n",
  "source": "synthetic-example.txt",
  "include_references": false,
  "extended_types": false,
  "limits": {
    "max_steps": 20,
    "max_nodes": 1000,
    "max_seconds": 600,
    "max_pages": 2,
    "max_outputs": 1000
  }
}
```

| Request field | Required | Default / constraints |
| --- | --- | --- |
| `text` | Yes | Nonblank string; at most 2,000,000 characters |
| `source` | No | `"cti report"`; string at most 2,000 characters; suitable for a report/file label |
| `include_references` | No | `false`; retain reference sections when true |
| `extended_types` | No | `false`; adds email/CVE extraction |
| `limits` | No | Object below; each field can be omitted independently |

| Limit | Default | Constraint / meaning |
| --- | --- | --- |
| `max_steps` | 20 | Positive integer; counts failed/interrupted attempts too |
| `max_nodes` | 1000 | Positive integer; canonical admitted graph nodes |
| `max_seconds` | 600 | Finite positive number; accumulated extraction/acquisition time |
| `max_pages` | 2 | Positive integer; pages per lookup |
| `max_outputs` | 1000 | Positive integer; retained unique validated outputs per lookup |

Booleans are rejected for integer limits. Limits are persisted and retained when
reopening. Active-time checks happen between steps; they do not immediately
cancel a request already in flight. Human reading time is not accumulated.

**Response:** `201 InvestigationSnapshot`, with `Location:
/api/investigations/{run_id}`. Usually `run.status` is `ready`, revision is 1,
graph nodes are extracted IOCs, and edges/steps are empty. All usable extracted
IOCs remain visible, including types with no implemented methods.

A saved extraction failure or initial-node-limit failure also returns a created
resource: inspect `run.status: "failed"`, `stop_reason` and `diagnostics`.
An initial-node-limit failure preserves extraction results but does not publish
a truncated graph. Zero usable IOCs can still be a ready run with `no_iocs`
diagnostics. HTTP success alone does not imply an actionable investigation.

An identical creation key returns `200` and the same investigation's
**current** state, including a closed state if it has since closed. A changed
effective request with that key returns `409 idempotency_conflict`. A key whose
extraction is still active returns `409 creation_in_progress`.

Complete examples: [new snapshot](examples/create-response.json),
[identical creation retry](examples/creation-replay-response.json),
[saved initial-node-limit failure](examples/failed-create-response.json).

## 6. List investigations

**GET `/api/investigations?limit=50&offset=0&status=ready`**

| Query | Default | Constraint |
| --- | --- | --- |
| `limit` | 50 | Integer 1–200 |
| `offset` | 0 | Nonnegative integer |
| `status` | Omitted | `extracting`, `ready`, `running`, `completed`, `cancelled` or `failed` |

**Response:** `200 InvestigationList`, containing `items`, `limit`, `offset` and
`total`. Each item has run metadata, report `{id, source, sha256}`, and counts
`{nodes, edges, steps}`.
Sort is updated time descending, then run ID ascending for ties. Offset pages
can move when investigations update; the list is not an immutable cursor view.

Complete example: [history](examples/history-response.json).

## 7. Read or reopen an investigation

**GET `/api/investigations/{run_id}`**

**Response:** `200 InvestigationSnapshot`:

| Field | Content |
| --- | --- |
| `version` | Public snapshot format version, currently 1 |
| `run` | Status, settings, revision, timings, stop reason and diagnostics |
| `report` | Saved original text, report ID, source, digest and ingestion time |
| `extraction` | Native sentences, matches, retained/excluded text, IOCs and passages; null when no extraction result exists; a failed run can still retain extraction |
| `graph` | Canonical nodes and admitted undirected method-labelled edges |
| `steps` | Ordered summaries; no full lookup receipt in this list |

This call is read-only. It never resumes, extracts or calls providers. Load it
on refresh or reopening. Use the run ID from the URL and the returned state as
authority; browser/session storage is only a cache. Separate caches by run.

Complete example: [saved snapshot](examples/snapshot-response.json).

## 8. Discover methods for a saved IOC

**GET `/api/investigations/{run_id}/nodes/{node_id}/methods`**

Use a node ID from this investigation's `graph.nodes`, not a typed IOC string.

**Response:** `200 NodeMethods` with `run_id`, `node_id`, `execution_allowed`,
`execution_block_reason`, and `methods`.

Each method contains `id`, input/output types, provider `source`, operation,
description, baseline/implementation flags, availability, `selectable` and
`unavailable_reason`.

| Field | Frontend interpretation |
| --- | --- |
| `execution_allowed` | The current run can start another step at the time of this query |
| `execution_block_reason` | Empty or a run-level reason: closed, extracting, active operation, unavailable saved configuration, recovery required, step/time limit |
| `methods[].selectable` | Eligibility of this particular method for the saved live/replay configuration |
| `availability.live_access` | Currently `"not_checked"`; do not label it online/verified |
| `availability.browser_library_installed` | Python package presence only; not proof of a working browser binary |
| `availability.api_key_configured` | Configuration boolean; no key value is returned |
| `availability.fixture_available` | Optional replay-only eligibility information |

Enable an action only when **both** run execution and method selection are
allowed. The POST rechecks state; GET eligibility is not a reservation.
Methodless IOCs return `methods: []`, not an error. A used node can be selected
again; `used` records history and participates in admission rather than banning
future selection.

Complete examples: [compatible methods](examples/methods-response.json),
[methodless hash](examples/methodless-response.json).

## 9. Execute a selected lookup

**POST `/api/investigations/{run_id}/steps`**

```json
{
  "step_id": "8187db04c3b846b2bba78b4a837dc4c3",
  "input_node_id": "e124110e6ed903393fb178c54d8b0b56",
  "method_id": "rapiddns.domain_to_ipv4",
  "expected_graph_revision": 1
}
```

| Field | Required / constraints |
| --- | --- |
| `step_id` | Required 32 lowercase hex characters; generate once and retain across retries |
| `input_node_id` | Required server-issued graph node ID, 32 lowercase hex characters |
| `method_id` | Required nonempty string, at most 200 characters; use a returned method ID |
| `expected_graph_revision` | Required nonnegative integer from the viewed snapshot |

The backend loads IOC value, type, context and source from its saved node.
Clients do not submit output IOCs, graph edges, evidence, lookup IDs or admission
decisions.

**Response:** `201 StepExecution` for a newly saved step; `200` with
`replayed: true` for a completed identical step ID. The result has:

| Field | Content |
| --- | --- |
| `step` | Full saved attempt, exact receipt, outcome, admission and delta |
| `run` | Current run metadata |
| `graph` | Current admitted graph; use this for the next selectable nodes |
| `replayed` | Whether the already completed step was returned without acquisition |

The returned observations are **`step.lookup.outputs`**. A completed step can
have zero outputs, rejected candidates or an operational error. Inspect these
three independent dimensions:

| Dimension | Field | Examples |
| --- | --- | --- |
| Attempt lifecycle | `step.status` | `running`, `completed` |
| Provider/acquisition outcome | `step.outcome_status` | `ok`, `empty`, `partial`, `challenge`, `login_required`, `rate_limited`, `browser_binary_missing`, `interrupted_unknown` |
| Graph admission/change | `step.admission`, `step.delta` | Accepted/rejected batch and actual counts of new nodes, edges and evidence links |

Provider outcome strings are extensible. A provider challenge or login failure
normally returns **HTTP 201 with a saved completed step**, not an HTTP 429/502.
Show its error/diagnostics and preserve its history. `lookup.complete` alone is
not a success flag; interpret `outcome_status` and the receipt status.

Admission follows the existing paper rule: after marking the selected input
used, at least one validated result must match a known unused IOC. A passing
batch admits all supported outputs/edges within graph limits. A non-admitted
batch retains its observations and evidence without graph additions. Do not
append every `lookup.outputs` item to the displayed admitted graph yourself.
Reward remains null / `not_evaluated`.

The revision increases on extraction publication and every completed step,
including steps that add no graph data. It does not increase for every status
or used-flag change, so it is not a complete HTTP ETag or progress signal.

Complete examples: [admitted step](examples/step-response.json),
[valid observations without graph admission](examples/nonadmitted-step-response.json),
[provider failure saved as HTTP 201](examples/provider-failure-response.json),
[completed retry](examples/step-replay-response.json).

The replayed step is immutable, but its accompanying run/graph are current.
Reusing a completed ID works even after the run closes; it does not reopen it.
A new intentional attempt needs a new step ID. A step ID reused for another
node/method is a conflict.

## 10. Inspect step evidence

**GET `/api/investigations/{run_id}/steps/{step_id}?include_snapshots=true`**

`include_snapshots` defaults to false. **Response:** `200 StepDetail` with
`step` and `snapshots`.

The full receipt, evidence, accepted/rejected mappings and transport diagnostics
are already inside `step.lookup`, even when `include_snapshots=false`.
The flag controls original provider response documents in the separate snapshots
map. With false, that map is `{}`.

`step.lookup_id` identifies this attempt's exact receipt. It matches
`step.lookup.id` when a receipt exists. Do not query or infer a "latest" lookup.
Pending or recovered unknown attempts can have `lookup: null`. Pending steps
also have `admission: null`, `outcome_status: "pending"`, `finished_at: ""` and
`delta: {}`; render them without dereferencing missing admission/receipt fields.

Treat provider excerpts and HTML/JSON response bodies as untrusted display text.
Render them in escaped code/text views rather than inserting raw provider HTML
into the application DOM.

Complete example: [receipt and raw snapshots](examples/step-detail-response.json).

## 11. Recover interrupted server work

**POST `/api/investigations/{run_id}/resume`** with body **`{}`**.

**Response:** `200 InvestigationSnapshot` after recovery.

| Saved situation | Behavior |
| --- | --- |
| Ready and no unfinished step | Returns saved state |
| Completed/cancelled/failed | Remains closed |
| Actual worker still running | 409; do not force recovery |
| Abandoned step has its exact saved receipt | Apply that receipt without another provider request |
| Abandoned step has no receipt | Complete as `interrupted_unknown`; require deliberate new attempt to retry |
| Extraction was interrupted | Preserve report and mark failed with `interrupted_extraction`; no automatic re-extraction |

Page reopening is a GET. Do not automatically call resume every time a page
loads or a request takes longer than expected. Resume does not change a saved
mode, reset budgets or reopen a closed run.

Complete example: [resume of an already ready run](examples/resume-response.json).

## 12. Finish or cancel

**POST `/api/investigations/{run_id}/close`**

```json
{
  "action": "finish"
}
```

`action` must be `finish` or `cancel`. **Response:** `200 InvestigationSnapshot`.
Finish records `completed` / `user_finished`; cancel records `cancelled` /
`user_cancelled`. Evidence is retained.

An active operation returns 409. An interrupted unfinished operation requires
explicit recovery first. Repeating finish on completed or cancel on cancelled
is idempotent. A different closure or a failed run returns `409 run_closed`.
Cancel does not terminate an in-flight transport. There is no separate pause,
save or hard-cancel endpoint.

Complete examples: [finish](examples/close-response.json),
[cancel](examples/cancel-response.json).

## 13. Download JSON

**GET `/api/investigations/{run_id}/export?include_evidence=true`**

Response is a JSON attachment with `Content-Disposition`. Read it as a Blob for
browser download. `include_evidence` defaults to true.

The download uses the terminal's **native export format**, not the compact read
snapshot. It includes top-level `version`, `mode`, `policy`, full `run`, `report`,
`extraction`, `graph`, and full `steps`. The raw run repeats report/extraction for
compatibility and replay runs can include replay metadata. With evidence enabled,
`evidence.lookups` and `evidence.snapshots` are also included.

With false, the separate evidence object is omitted; full steps still contain
their saved receipts and receipt evidence. This is not a completely evidence-free
or redacted export. There is no CSV/STIX or server-filesystem path option.
Open, closed and failed investigations can all be exported. Export does not
finalize active work.

Complete example: [native export](examples/export-response.json). Its absolute
server fixture path is replaced with a neutral example path for sharing.

## 14. Highlighting and graph rendering

Use saved IOC Hunter sentences. The reference is:

```text
graph.nodes[].passage_ids
    -> extraction.passages[].id
    -> passage.sentence_index
    -> extraction.sentences[sentence_index]
```

Sentence indices are zero-based. Do not parse the passage ID suffix for an
index. Native passages carry their explicit index. Do not split the report
again, use the older Hub regex splitter, or rerun an IOC matcher in the browser.
The packaged JavaScript client includes helpers to resolve these associations.

Preserve `report.original_text` in the report viewer, including reference
sections. Only retained passages should highlight. Position them sequentially
while skipping the saved excluded-section line ranges so repeated text in
References does not get selected instead. Those line ranges are one-based and
inclusive; JS string positions are UTF-16 code units. The API does not provide
character offsets. Do not silently replace the original report with joined
sentence text when positioning fails.

Lookup-only nodes have no report passages/highlights. Rediscovery of a report
node retains its original report links. Keep nodes without implemented methods
visible and explain the empty methods list.

Edges use `left` and `right`, not `src`/`dst`. They are undirected, with sorted
endpoints and a method label. Lookup direction belongs to the selected input
node/method recorded on the step. Two nodes sharing a report do not automatically
have an edge. Different retrieval methods can have separate labelled edges
between the same endpoints.

Canonical node IDs can match across investigations. Cache graph objects within
their run rather than treating a node ID as one global mutable application node.

## 15. HTTP errors and frontend recovery

IOC Hunter's investigation routes use this error envelope, and the Hub returns it
unchanged:

```json
{
  "error": {
    "code": "stale_graph_revision",
    "message": "Reload the investigation before another lookup.",
    "run_id": "54acd8b3d9e94c0bba48cdc285fe69b2",
    "step_id": null,
    "details": {
      "expected_graph_revision": 1,
      "current_graph_revision": 3
    }
  }
}
```

`error.run_id` and `error.step_id` can be null. In particular POST `/steps`
errors currently have no step ID in the URL, so the error body may omit that
correlation value even though the frontend knows it. Retain your request IDs.

| HTTP / code | Frontend action |
| --- | --- |
| 404 `not_found` | Unknown resource; reload the history rather than guessing another ID |
| 409 `creation_in_progress` | Retry the same creation request/key later; do not create another key |
| 409 `step_in_progress`, `operation_in_progress` | Read the known run/step; another mutation is active on this run |
| 409 `idempotency_conflict` | Do not reuse that key for a different request/selection |
| 409 `stale_graph_revision` | GET the latest state, require a current user selection, then start deliberate new work |
| 409 `recovery_required` | Explicit recovery is needed for abandoned unfinished work |
| 409 `run_closed` | Render read-only; a new investigation needs a new creation key |
| 409 `method_unavailable`, `saved_configuration_unavailable` | Refresh eligibility; show the server's configuration/fixture explanation |
| 409 `limit_reached` | Reload; the run has durably stopped at its step/time limit |
| 422 `invalid_request` | Correct the body, query or creation header; display validation details |
| 500 `internal_error` | Preserve IDs and inspect saved state; never invent success or automatically repeat acquisition |
| 503 with `{"detail": "ioc service unavailable: ..."}` | The Hub cannot reach IOC Hunter (the Hub's own format, the only answer it writes itself); retain IDs and inspect/retry safely after connectivity returns |

To show an error message for either format, read `body.error?.message ?? body.detail`.

Distinguish HTTP errors from provider outcomes stored inside HTTP 201 step
results. Provider `outcome_status: "not_found"` is not an HTTP 404 for the step.
Clients should preserve/display unknown future outcome codes.

### Timeout or aborted fetch

1. Preserve the original creation key or step ID and selection.
2. If the run ID is known, GET it and the known step. A running worker continues.
3. An identical completed POST retry returns 200 without another acquisition.
4. If creation's response was lost, retry the identical create request/key; this
   discovers the same saved run once the creation claim is no longer active.
5. Use explicit resume only when server execution is abandoned. A busy conflict
   means keep inspecting/waiting rather than treating the operation as dead.

Do not automatically recover simply because a request exceeded a frontend
timer. A modest read polling interval is a UI choice; no server push or progress
percentage is defined. A revision alone is insufficient to skip state updates.

## 16. Client example

`frontend-client.mjs` is a dependency-free example using fetch. Import it from
your application and supply a base origin only when a same-origin proxy is not
being used.

```javascript
import { createApiClient, newRequestId } from "./frontend-client.mjs";

const api = createApiClient(); // relative /api/... URLs through the frontend proxy
const creationKey = newRequestId(); // retain across retries
const snapshot = await api.createInvestigation({
  text: reportText,
  source: fileName || "pasted report"
}, creationKey);

// Save snapshot.run.id in the page URL, then let the user select a graph node.
const choices = await api.getMethods(snapshot.run.id, selectedNode.id);
const method = choices.methods.find(row => row.id === selectedMethodId);
if (choices.execution_allowed && method?.selectable) {
  const stepId = newRequestId(); // retain this entire request until outcome is known
  const result = await api.executeStep(snapshot.run.id, {
    step_id: stepId,
    input_node_id: selectedNode.id,
    method_id: method.id,
    expected_graph_revision: snapshot.run.graph_revision
  });
  // Replace current run/graph from result. Inspect result.step.outcome_status
  // and result.step.admission independently before choosing the next action.
}
```

The example does not auto-retry POSTs, queue work or resolve interrupted attempts
on your behalf. Route/user state, intentional retry choices and UI rendering
belong to the frontend. Runtime errors include both HTTP status and parsed
backend error payload when available. Network/aborted-fetch errors can have no
HTTP response or status; preserve request identity and inspect saved state when
connectivity returns.

## 17. Existing analysis endpoint and boundaries

`POST /api/analyze` is a separate compatibility analysis endpoint. It accepts
`text` (up to 200,000 characters) or pre-split `sentences` (up to 20,000 entries)
and returns `mode`, `sentences`, `ttps`, flat `iocs`, `cskg` and `attribution`.
The Hub splits the text into sentences with its one splitter (the one the D2 dataset
was built with), and both TTP and IOC work on those sentences, so `sentences` and
every sentence index match D2. Stub mode remains a baseline. Current graph/attribution
outputs are null.

It does not create a saved investigation or provide workflow node IDs. Do not
submit through `/api/analyze` and try to use its flat IOC list as a saved graph.
For the new investigation frontend, start at POST `/api/investigations`.

Investigation snapshots currently contain IOC workflow results, not persisted
TTP predictions. Full TTP restoration or a combined saved analysis response
requires a separate backend integration. There are no frontend APIs for model
training, actor attribution or background job scheduling in this handoff.

## 18. Generated model reference

These tables are generated from IOC Hunter's implemented OpenAPI. Requiredness is
the schema contract. Unknown provider-specific diagnostic/evidence fields should
be retained rather than treated as a closed enum. Full machine schemas are in
`openapi.json`; complete concrete payloads are in `examples/`.

### Schema: CreateInvestigation

Unknown fields are rejected.

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `text` | `string` | Yes | min length 1; max length 2000000 |
| `source` | `string` | No | default "cti report"; max length 2000 |
| `include_references` | `boolean` | No | default false |
| `extended_types` | `boolean` | No | default false |
| `limits` | `Limits` | No | — |

### Schema: Limits

Unknown fields are rejected.

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `max_steps` | `integer` | No | default 20; greater than 0.0 |
| `max_nodes` | `integer` | No | default 1000; greater than 0.0 |
| `max_seconds` | `number` | No | default 600.0; greater than 0.0 |
| `max_pages` | `integer` | No | default 2; greater than 0.0 |
| `max_outputs` | `integer` | No | default 1000; greater than 0.0 |

### Schema: CreateStep

Unknown fields are rejected.

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `step_id` | `string` | Yes | pattern ^[0-9a-f]{32}$ |
| `input_node_id` | `string` | Yes | pattern ^[0-9a-f]{32}$ |
| `method_id` | `string` | Yes | min length 1; max length 200 |
| `expected_graph_revision` | `integer` | Yes | minimum 0.0 |

### Schema: CloseInvestigation

Unknown fields are rejected.

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `action` | `"finish" / "cancel"` | Yes | — |

### Schema: EmptyRequest

Unknown fields are rejected.

Empty JSON object `{}`.

### Schema: InvestigationSnapshot

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `version` | `1` | Yes | — |
| `run` | `RunMetadata` | Yes | — |
| `report` | `Report` | Yes | — |
| `extraction` | `Extraction or null` | Yes | — |
| `graph` | `Graph` | Yes | — |
| `steps` | `Array<StepSummary>` | Yes | — |

### Schema: RunMetadata

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `status` | `"extracting" / "ready" / "running" / "completed" / "cancelled" / "failed"` | Yes | — |
| `mode` | `"live" / "replay"` | Yes | — |
| `policy` | `string` | Yes | — |
| `config` | `RunConfig` | Yes | — |
| `graph_revision` | `integer` | Yes | — |
| `created_at` | `string` | Yes | — |
| `updated_at` | `string` | Yes | — |
| `elapsed_seconds` | `number` | Yes | — |
| `stop_reason` | `string` | Yes | — |
| `diagnostics` | `Array<object>` | Yes | — |
| `extraction_options` | `Record<string, boolean>` | Yes | — |

### Schema: RunConfig

Unknown fields are rejected.

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `max_steps` | `integer` | No | default 20; greater than 0.0 |
| `max_nodes` | `integer` | No | default 1000; greater than 0.0 |
| `max_seconds` | `number` | No | default 600.0; greater than 0.0 |
| `max_pages` | `integer` | No | default 2; greater than 0.0 |
| `max_outputs` | `integer` | No | default 1000; greater than 0.0 |
| `mode` | `"live" / "replay"` | Yes | — |

### Schema: Report

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `source` | `string` | Yes | — |
| `original_text` | `string` | Yes | — |
| `sha256` | `string` | Yes | — |
| `ingested_at` | `string` | Yes | — |

### Schema: Extraction

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `source` | `string` | Yes | — |
| `original_text` | `string` | Yes | — |
| `retained_text` | `string` | Yes | — |
| `excluded_sections` | `Array<object>` | Yes | — |
| `sentences` | `Array<string>` | Yes | — |
| `matches` | `Array<Array<[string, string]>>` | Yes | — |
| `iocs` | `Array<IOC>` | Yes | — |
| `passages` | `Array<Passage>` | Yes | — |

### Schema: IOC

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `value` | `string` | Yes | — |
| `type` | `string` | Yes | — |
| `context` | `Array<string>` | Yes | — |
| `source` | `string` | Yes | — |

### Schema: Passage

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `text` | `string` | Yes | — |
| `sentence_index` | `integer` | Yes | — |

### Schema: Graph

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `nodes` | `Array<GraphNode>` | Yes | — |
| `edges` | `Array<GraphEdge>` | Yes | — |

### Schema: GraphNode

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `type` | `string` | Yes | — |
| `value` | `string` | Yes | — |
| `context` | `Array<string>` | Yes | — |
| `sources` | `Array<string>` | Yes | — |
| `passage_ids` | `Array<string>` | Yes | — |
| `evidence_ids` | `Array<string>` | Yes | — |
| `lookup_ids` | `Array<string>` | Yes | — |
| `origin` | `"report" / "lookup"` | Yes | — |
| `used` | `boolean` | Yes | — |

### Schema: GraphEdge

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `left` | `string` | Yes | — |
| `right` | `string` | Yes | — |
| `method_id` | `string` | Yes | — |
| `ontology_label` | `string` | Yes | — |
| `evidence_ids` | `Array<string>` | Yes | — |
| `lookup_ids` | `Array<string>` | Yes | — |

### Schema: Admission

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `accepted` | `boolean` | Yes | — |
| `reason` | `string` | Yes | — |
| `overlap_ids` | `Array<string>` | Yes | — |
| `reward` | `null` | No | — |
| `reward_status` | `"not_evaluated"` | Yes | — |

### Schema: StepSummary

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `sequence` | `integer` | Yes | — |
| `input_node_id` | `string` | Yes | — |
| `method_id` | `string` | Yes | — |
| `lookup_id` | `string` | Yes | — |
| `status` | `"running" / "completed"` | Yes | — |
| `started_at` | `string` | Yes | — |
| `finished_at` | `string` | Yes | — |
| `outcome_status` | `string` | Yes | — |
| `admission` | `Admission or null` | Yes | — |
| `delta` | `Record<string, integer>` | Yes | — |
| `error` | `string` | Yes | — |

### Schema: Step

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `sequence` | `integer` | Yes | — |
| `input_node_id` | `string` | Yes | — |
| `method_id` | `string` | Yes | — |
| `lookup_id` | `string` | Yes | — |
| `status` | `"running" / "completed"` | Yes | — |
| `started_at` | `string` | Yes | — |
| `finished_at` | `string` | Yes | — |
| `outcome_status` | `string` | Yes | — |
| `admission` | `Admission or null` | Yes | — |
| `delta` | `Record<string, integer>` | Yes | — |
| `error` | `string` | Yes | — |
| `run_id` | `string` | Yes | — |
| `lookup` | `LookupRecord or null` | Yes | — |

### Schema: LookupRecord

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `method_id` | `string` | Yes | — |
| `input_ioc` | `IOC` | Yes | — |
| `status` | `string` | Yes | — |
| `outputs` | `Array<IOC>` | Yes | — |
| `evidence` | `Array<object>` | Yes | — |
| `accepted` | `Array<object>` | Yes | — |
| `rejected` | `Array<object>` | Yes | — |
| `responses` | `Array<object>` | Yes | — |
| `transport_errors` | `Array<object>` | Yes | — |
| `cache_hit` | `boolean` | Yes | — |
| `complete` | `boolean` | Yes | — |
| `error` | `string` | Yes | — |
| `outcome_reason` | `string` | Yes | — |
| `partial_reasons` | `Array<string>` | Yes | — |
| `started_at` | `string` | Yes | — |
| `finished_at` | `string` | Yes | — |

### Schema: InvestigationList

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `items` | `Array<InvestigationListItem>` | Yes | — |
| `limit` | `integer` | Yes | — |
| `offset` | `integer` | Yes | — |
| `total` | `integer` | Yes | — |

### Schema: InvestigationListItem

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `run` | `RunMetadata` | Yes | — |
| `report` | `Record<string, string>` | Yes | — |
| `counts` | `Record<string, integer>` | Yes | — |

### Schema: NodeMethods

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `run_id` | `string` | Yes | — |
| `node_id` | `string` | Yes | — |
| `execution_allowed` | `boolean` | Yes | — |
| `execution_block_reason` | `string` | Yes | — |
| `methods` | `Array<MethodRow>` | Yes | — |

### Schema: MethodRow

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `id` | `string` | Yes | — |
| `input_type` | `string` | Yes | — |
| `output_type` | `string` | Yes | — |
| `source` | `string` | Yes | — |
| `operation` | `string` | Yes | — |
| `unavailable_reason` | `string` | Yes | — |
| `baseline` | `boolean` | Yes | — |
| `implemented` | `boolean` | Yes | — |
| `description` | `string` | Yes | — |
| `availability` | `object` | Yes | — |
| `selectable` | `boolean` | Yes | — |

### Schema: StepExecution

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `step` | `Step` | Yes | — |
| `run` | `RunMetadata` | Yes | — |
| `graph` | `Graph` | Yes | — |
| `replayed` | `boolean` | Yes | — |

### Schema: StepDetail

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `step` | `Step` | Yes | — |
| `snapshots` | `Record<string, SourceSnapshot>` | Yes | — |

### Schema: SourceSnapshot

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `url` | `string` | Yes | — |
| `body` | `string` | Yes | — |
| `format` | `string` | Yes | — |
| `transport` | `string` | Yes | — |
| `fetched_at` | `string` | Yes | — |
| `status_code` | `integer` | Yes | — |
| `diagnostics` | `object` | Yes | — |

### Schema: ApiError

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `error` | `ErrorDetail` | Yes | — |

### Schema: ErrorDetail

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `code` | `string` | Yes | — |
| `message` | `string` | Yes | — |
| `run_id` | `string or null` | Yes | — |
| `step_id` | `string or null` | Yes | — |
| `details` | `object` | Yes | — |

### Schema: HubUnavailable

| Field | JSON type / model | Required | Default / constraints |
| --- | --- | --- | --- |
| `detail` | `string` | Yes | — |


## 19. Receipt evidence details

`LookupRecord.evidence` entries currently contain the following fields even
though the transport schema permits extensible JSON objects:

| Field | Type / meaning |
| --- | --- |
| `id` | String; deterministic evidence identity |
| `source` | Provider identifier |
| `query_type`, `query_value` | Queried IOC identity |
| `operation` | Provider operation |
| `page_url` | Source page/response URL |
| `locator` | Location of the supporting record within the response |
| `excerpt` | Captured supporting text/record |
| `fact_type` | Relationship-proof kind, such as `dns_record` |
| `facts` | Parsed relationship fields; DNS commonly uses domain, IP and record type |
| `response_sha256` | Digest of response body; not the whole-document snapshot ID |
| `retrieved_at` | Retrieval timestamp |
| `observed_at` | Raw provider observation time string, possibly empty |

Accepted mappings contain `type`, `value`, `method_id`, `ontology_label`,
`evidence_id` and `validation`. Normal rejected mappings contain type/value,
machine-readable `reason`, explanatory `message`, structured `details` and
evidence ID. Some rejections instead record context-generation failure with
`error`; do not assume every rejection has the same required fields.

Receipt `responses` references original documents by `snapshot_id`, URL and
transport. Raw documents contain URL, body, format, transport, fetched time,
status code and diagnostics. A snapshot ID and a response-body digest are
different hashes. A raw HTTP status alone need not describe an operation's
browser/XHR outcome; use the receipt's final status and diagnostics.

## 20. Frontend acceptance checklist

- Submit report text once and retain the creation key/run ID.
- Render ready, extracting, running, failed and closed states distinctly.
- Highlight native passages without changing the original report.
- Keep methodless IOCs visible; require run and method eligibility before POST.
- Retain step identity/revision and handle stale/busy conflicts.
- Show provider outcome, evidence/rejections and graph admission separately.
- Render pending/null receipt and admission fields without crashing.
- Reopen using GET, and recover explicitly without duplicate provider requests.
- Support independent per-investigation caches and the history list.
- Close without deleting evidence; download native JSON as an attachment.
- Explain the IOC-unavailable error.
- Do not add UI actions for unsupported upload, deletion, auto-selection or hard cancellation APIs.
