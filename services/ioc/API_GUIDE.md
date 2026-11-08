# Saved investigation APIs

The terminal and HTTP adapters now use the same `InvestigationService`, native
IOC Hunter sentences, repository and SQLite collection. The Hub forwards the
investigation endpoints; it does not maintain another graph or database.

## Start locally

Run from this service checkout with the extraction and API extras installed.
The existing Windows workspace can reuse its IOC environment:

```powershell
$env:PYTHONPATH = (Get-Location).Path
$iocPython = 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe'
& $iocPython -m uvicorn ioc_hunter.http_api:app --host 127.0.0.1 --port 8002
```

The Hub uses `TM_IOC_URL=http://127.0.0.1:8002` outside Compose. Start the Hub
using the root README's environment. IOC OpenAPI is at `/openapi.json` and its
interactive reference is `/docs`; the Hub's `/docs` lists the forwarded routes
without field details. The frontend reference is [docs/api](docs/api/README.md).

Default storage is `services/ioc/output/investigations/lookups.sqlite3` in this
checkout. Explicit `--store`/injected stores take precedence, then
`IOC_HUNTER_STORE`, then this default. Relative environment paths resolve from
the service root; explicit CLI paths resolve from the current directory.

In Compose the store is the `ioc-data` volume at `/data` (`IOC_HUNTER_STORE=/data`).
Use the terminal inside the container to work on the same saved investigations,
for example `docker compose exec ioc ioc-hunter runs`. To bring investigations
saved on a host into the volume, copy that store's files into it, for example
`docker compose cp output/investigations/. ioc:/data/`.

## No users

There are no users, accounts or login, and no `Authorization` header. Every
investigation belongs to one built-in owner, so history lists every saved
investigation. The database keeps its owner tables unchanged, so existing stores
keep working and a later multi-user decision needs no migration. Unknown
resources return 404. Creation keys are global and step IDs are run-scoped.
Different runs may execute concurrently; a competing mutation of the same run
returns 409. Provider pacing and daily budgets are shared. The old
extraction/catalogue/one-call lookup routes remain compatibility primitives and
do not list saved investigations.

## Endpoints

The browser calls the Hub prefix `/api/investigations`. The Hub forwards to
`/v1/investigations` on IOC Hunter. Below, `I` means the latter prefix plus
`/{run_id}`. Requests and results use the [typed schemas](ioc_hunter/api/schemas.py).

| Method and path | Input | Success |
| --- | --- | --- |
| `POST /v1/investigations` | Text, source, extraction options, optional limits; required `Idempotency-Key` | 201 snapshot; identical creation retry 200 |
| `GET /v1/investigations` | `limit=50`, `offset=0`, optional status | History/counts of every saved investigation |
| `GET I` | None | Saved report, native extraction/passages, graph and step summaries |
| `GET I/nodes/{node_id}/methods` | None | Compatible methods, availability, per-run execution eligibility |
| `POST I/steps` | Node ID, method ID, step ID, expected graph revision | 201 completed saved step; identical completed retry 200 |
| `GET I/steps/{step_id}` | Optional `include_snapshots=true` | Exact receipt/evidence; optional original response documents |
| `POST I/resume` | `{}` | Explicit interruption recovery |
| `POST I/close` | `{"action":"finish"}` or `{"action":"cancel"}` | Closed run with evidence preserved |
| `GET I/export` | `include_evidence=true` by default | JSON attachment in the same native format as terminal export |

Execution is synchronous request/response. A 201 step response is saved and
finished, not queued. Client disconnect or timeout does not mean its worker
stopped: GET the known step/run before retrying or recovering. The lock remains
owned by the actual worker. Reads never trigger recovery or provider calls.

## Create and hunt

Illustrative request; obtain a fresh UUID without hyphens for each deliberate
new creation, and retain it across retries:

```http
POST /v1/investigations
Idempotency-Key: 7bb68acbad2c48f1bd6aa9bbec9817f3
Content-Type: application/json
```

```json
{
  "text": "The loader contacted example.com. The report also lists 192.0.2.10.",
  "source": "report.txt",
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

All limits are optional and default to the values above. Text is nonblank and
limited to 2,000,000 characters. Caller-supplied sentence lists, graph
nodes, replay paths and unknown fields are rejected. API replay is a test/server
configuration, never an arbitrary client filesystem path.

The snapshot returns `run`, `report`, `extraction`, `graph` and step summaries.
Use `run.id` to reopen it and graph node IDs to select IOCs. The graph begins
with isolated report nodes. Derive highlighting through:

```text
node.passage_ids -> extraction.passages -> sentence_index -> extraction.sentences
```

Use the returned IDs in a step request (the values below are illustrative):

```json
{
  "step_id": "74035f8c43164fe8a6dfda01ca84057e",
  "input_node_id": "74c069891ca94b56bec1670b8955c924",
  "method_id": "rapiddns.domain_to_ipv4",
  "expected_graph_revision": 1
}
```

The result includes `step`, current `run`, current `graph` and `replayed`.
Outputs are `step.lookup.outputs`; the receipt ID is `step.lookup_id` and
matches `step.lookup.id`. The provider outcome, relationship rejections, paper
admission decision and actual graph delta are separate fields. A login,
challenge or other provider failure is still a saved completed step with its
diagnostics, normally HTTP 201. Repeating its completed ID returns that step
without another acquisition. A deliberate retry uses a new step ID.

The paper's known-unused overlap admission condition remains unchanged. Valid
but non-admitted outputs stay in the receipt; they are not selectable graph
nodes. Rewards remain unevaluated. Method availability is local configuration,
not a live provider health certification.

## Reopen, recover and close

Leaving the terminal/page requires no save request. Every operation persists.
GET restores the saved native sentences, graph, used flags, settings and steps.
After a server interruption, POST resume either applies its exact saved receipt
without acquisition or finalizes a missing-receipt attempt as
`interrupted_unknown`. It never automatically retries an uncertain request.
Interrupted extraction retains the original report and becomes failed.

Resume/close cannot interfere with a still-running worker. Closing an orphaned
attempt requires recovery first. `finish` makes the run completed; `cancel`
makes it cancelled. Neither deletes evidence or cancels an in-flight transport.
Closed runs remain readable/exportable and cannot be reopened for more steps.

New-route errors contain `error.code`, `error.message`, nullable `error.run_id`
and `error.step_id`, and an `error.details` object. Validation is 422, unknown/foreign records
404, conflicting state/revision/request identity 409, and internal invariant
failures 500. Legacy primitives retain their existing error contracts.

## Code organization

| Location | Responsibility |
| --- | --- |
| `http_api.py` | Existing ASGI entry point and compatibility primitives |
| `api/schemas.py`, `api/investigations.py`, `api/dependencies.py`, `api/errors.py` | Wire contracts, thin routes, injected service, HTTP error mapping |
| `workflow/service.py` | Shared commands/queries and idempotency |
| `workflow/coordination.py` | Per-run thread/process execution ownership |
| `workflow/adapters.py` | Existing terminal protocol backed by the shared service |
| `workflow/runner.py`, `workflow/repository.py` | Extraction/lookup/admission and transactional durable state |
| Hub `api/investigations.py`, `clients/investigations.py` | Plain pass-through routes and transport; no models, rules or storage |

Schema version 2 migrates old workflow step keys to `(run_id, id)` while
preserving existing rows and lookup tables. Owner/key records are additional
tables in the same file (one built-in owner). No existing report/evidence database is deleted.

The Hub's `/api/analyze` is separate: it splits with the Hub's one splitter (the
one D2 was built with) and sends those sentences to both TTP and IOC Hunter's
`/v1/extract`, so its sentence indices match D2. Investigations use IOC Hunter's
own sentences; their graph links IOCs by value, not by sentence index.
Persisting complete TTP analysis results is separate later work.
