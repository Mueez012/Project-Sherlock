# Complete workflow implementation plan

## Current status: 4 November 2026

The terminal report-to-investigation workflow is now implemented in
`ioc_hunter/workflow/`, exposed through `investigate`, `runs` and `export`.
It saves the report and extracted graph nodes, executes a manually selected
IOC/method lookup, retains its exact receipt and accepted evidence associations,
and transactionally commits admitted graph changes with step state. Resume,
offline fixtures and evidence-inclusive JSON export use the same runner.

The implemented policy is **manual selection with the paper's admission gate**:
the selected IOC is used before the candidate-overlap test; a pass admits all
validated outputs and supported edges within limits. Validated but non-admitted
outputs remain in receipts. Reward is unevaluated. Full Algorithm 1 ranking,
coverage/tried counters, repeated rounds and LLM selection remain future work,
along with Hub/web investigation integration and SecureBERT encoding.

Use [the workflow guide](WORKFLOW_GUIDE.md) for current behavior and commands,
and [the handoff](WORKFLOW_HANDOFF.md) for the integration boundary. The plan
below preserves the 14 October design and acceptance criteria as historical
context. Its missing-feature tables, proposed commands and manual-policy choice
describe that earlier plan, not the current implementation. The current paper
admission gate supersedes its proposed unconditional manual edge admission.

## Historical plan: 14 October 2026

Status: proposed implementation plan, refined 14 October 2026. No workflow or algorithm
has been implemented by this document. Companion: [organization plan](CODEBASE_ORGANIZATION_PLAN.md).

14 October handoff: [WORKFLOW_HANDOFF.md](WORKFLOW_HANDOFF.md) records the current
implementation boundary; [METHODS_TODO.md](METHODS_TODO.md) tracks future method
sprints. The repair baseline is 90 offline tests passed, 17 methods live-positive
in iterative checks, three completed with no applicable data and one unresolved.
See [current evidence and limitations](METHOD_RELIABILITY_RESULTS.md).

Organization milestone update (13 October): the provider/transport split and
non-interactive extraction interface are implemented. The complete runner,
investigation graph, policies and web integration described below remain planned.

## First complete outcome

Run one report through extraction, choose a seed IOC and a supported method,
retrieve and validate candidates, save the resulting IOC graph with evidence,
and reopen/export the investigation. First demonstrate this deterministically
from the terminal, then connect the existing web app, then run Algorithm 1 through
the same orchestration.

The first complete path covers IOC enrichment. TTP extraction, temporal graph
construction, model training and actor attribution are separate integrations.
Do not display the frontend's synthetic attribution scores as live run outputs.

## What exists and what is missing

| Requirement | Existing implementation | Work needed |
| --- | --- | --- |
| Report ingestion | CSV/XLSX dataset loader requiring `cti_content` | Stable report ID; raw text input; selected-row adapter; persisted report metadata |
| IOC extraction | Filtering, sentences, IOCFinder, deduplication, original context and non-interactive `extract_report()` | Persist report/passage associations with stable identifiers |
| IOC identity | Four-field IOC and type normalization | Stable graph IDs; handle extraction/lookup normalization differences explicitly |
| Method discovery | 21 implemented definitions and 39 disabled candidates | Runnable method filtering and explicit provider readiness |
| Retrieval | HTTP/browser adapters, fallback, limits, cache | Reuse; bound each run; mark unavailable/partial routes accurately |
| Relationship validation | Independent checks and rejection receipts | Clear diagnostic details and accepted-evidence references per proposed edge |
| Lookup provenance | Immutable receipts and raw snapshots in SQLite | Link each workflow step to its exact lookup ID; retain provenance through graph merge |
| Graph | Ontology and an edge-key helper | Node/edge persistence, merge rules, evidence associations, transactional updates |
| Run orchestration | No complete runner | Configuration, state machine, manual plan, checkpointing, progress and cancellation |
| Expansion evaluation | Documented intent only | Separate policy implementation and graph-state tests |
| Web interface | Next.js synthetic investigation/evidence/graph views | Backend API, worker, live data repository, revised graph/evidence types |
| Repeatable demonstration | Provider fixtures and lookup tests | End-to-end offline fixture run using the real extraction/validation/graph path |

Existing verification evidence: 62 tests passed at the original foundation
milestone; 35 lookup tests were rerun successfully on 13 October. Historical live
domain-to-IPv4 checks returned results for RapidDNS and VirusTotal, both partial;
OTX returned a loading page. Do not treat all 21 definitions as live-verified.

## Entry point and reusable workflow

### Concrete first implementation

The first deliverable is a persisted report-to-IOC graph using an explicit,
bounded manual lookup plan. All canonically valid extracted IOCs become initial
nodes, including types without implemented lookup methods. Preserve report
passages and extraction diagnostics. A normalization failure stays visible as
an ingestion diagnostic rather than silently disappearing or crashing the run.
Co-occurrence in a report does not establish an ontology relationship: initial
nodes may be isolated. Extracting relationships from report prose is separate,
future work; initial graph edges come from validated provider observations.

Implement in this dependency order:

1. **Call-scoped lookup result.** Add an internal detailed execution interface
   that returns the exact receipt and outputs together. Keep existing `lookup()`
   and callable method behavior compatible with `list[IOC]`. Persist accepted
   relationship records linking canonical input/output identities, method ID,
   ontology label, evidence ID and validation outcome. Only outputs actually
   admitted by lookup limits may become graph proposals. The current receipt
   stores evidence and rejections but not this explicit accepted mapping.
2. **Graph contracts and repository.** Use a new `ioc_hunter/graph/` package for
   models, merge rules and SQLite persistence. Keep lookup evidence storage in
   its current module. Add versioned workflow/graph tables without rewriting old
   receipts. Nodes are unique per investigation and canonical IOC identity;
   edges follow the method-labelled identity described below. Repeated evidence
   adds provenance, not duplicate nodes or duplicate same-method edges.
3. **Workflow contracts and runner.** Add `ioc_hunter/workflow/` for run/step
   models, orchestration and policies. Persist the report, extraction result,
   selected plan and progress. Manual policy chooses finite explicit steps and
   accepts validated graph proposals within budgets; algorithm reward remains
   unevaluated. Start with report-seed lookups, without automatically scheduling
   every discovered output. Add dependent manual steps once this path works.
4. **Recovery and export.** Persist lookup-attempt IDs before acquisition so a
   resumed step can find its receipt without a "latest" query. If a completed
   receipt exists, resume graph processing from it; if acquisition was interrupted
   before a receipt was saved, record the uncertain attempt and apply an explicit
   retry rule. Graph changes and step completion commit together. A repeated
   commit is a no-op. Export nodes, method-labelled edges, evidence references,
   lookup/step outcomes and run mode; support an evidence-inclusive export so
   consumers do not depend on a local database path.
5. **CLI and end-to-end demonstration.** Extend existing `main.py` to invoke the
   runner. Prove replay mode cannot access the network, then run the same service
   with one verified live method and strict budgets. Reuse the existing CTI
   report seed for comparison; compare provenance and behavior, not exact live
   IP counts that can change over time.

Proposed minimal responsibilities (filenames may be adjusted during implementation):

```text
ioc_hunter/graph/models.py         Node, edge, evidence association, graph delta
ioc_hunter/graph/repository.py     SQLite merge, transactions, read/export queries
ioc_hunter/workflow/models.py      Report, run configuration/state, step results
ioc_hunter/workflow/runner.py      Extraction -> selected lookup -> graph commit
ioc_hunter/workflow/policies.py    Manual selection/commit; later Algorithm 1
ioc_hunter/main.py                 CLI wiring to those services
```

For the initial manual policy, a partial lookup may contribute its validated
outputs while retaining its partial reasons. An empty lookup adds no edges; a
provider failure produces a failed step and permits independent planned steps
to continue, subject to provider cooldowns and run budgets. Distinguish new
nodes, new method-labelled edges and additional supporting evidence in the step
summary. Do not label all three as "successful expansion."

Use an explicit live-method allowlist and one shared lookup client initially;
`implemented=True` alone is insufficient readiness. Keep the unresolved
VirusTotal domain-to-URL route outside the default live plan. Limits include
logical steps, graph size, provider pages/outputs and elapsed time. Check run
deadlines between bounded requests; do not promise immediate interruption of
an in-flight browser request.

The first graph can be inspected through exported data before a web renderer is
connected. After offline and bounded-live acceptance, Algorithm 1 and web
integration can be separate milestones over the same runner; neither should
require another extraction or retrieval pipeline.

`main.py` is appropriate as the visible starting point. It should parse input,
construct dependencies, and call `WorkflowRunner`, rather than contain every
stage's implementation. `python -m ioc_hunter` continues through `__main__.py`.

```text
CLI main.py / future web job / optional MCP workflow tool
                          |
                    WorkflowRunner
                          |
         report -> extraction -> seed IOC records
                          |
             policy selects (IOC, method)
                          |
            LookupClient -> validated list[IOC]
                          |            + exact lookup receipt
             policy evaluates the result
                          |
             commit graph changes and step state
                          |
                progress events / run result
```

The runner should expose operations such as `create_run`, `extract`,
`execute_step`, `run`, `resume`, and `export_result` only as needed by milestones.
All entry points use these operations; the web layer does not invoke shell
commands to run the CLI.

Proposed commands below do not exist yet:

```text
python -m ioc_hunter run --report report.txt --policy manual --plan plan.json --mode replay
python -m ioc_hunter run --report report.txt --policy manual --plan plan.json --mode live
python -m ioc_hunter run --resume RUN_ID
python -m ioc_hunter export RUN_ID --output result.json
```

A manual plan explicitly names the seed IOC and method, with finite steps.
Replay mode injects fixture-backed transports into the real lookup pipeline;
it must never silently fall back to network access. Live mode uses the existing
provider transports. Store the mode in every run and exported result.

## Shared data contracts

- `Report`: ID, original text, source/dataset row, ingestion time, content digest.
  PDF/DOCX conversion is deferred; initially support raw text and existing datasets.
- `ExtractionResult`: report ID, retained/excluded passages, IOC candidates and
  passage associations, warnings and options. Preserve original source text.
  Sentence IDs are sufficient initially; do not invent original character offsets
  after filtering or defanging.
- `RunConfig`: policy/version, replay/live mode, selected methods and seeds,
  provider settings references, lookup/node/step/time budgets.
- `RunState`: status, known/used IOC identities, pending plan, completed steps,
  graph revision, policy state, timestamps and stop reason.
- `StepRecord`: selected IOC/method, exact lookup ID, retrieval outcome,
  validated candidates, policy decision, committed changes and timings.
- `GraphNode`: stable ID based on canonical IOC identity, with associations to
  original report passages and subsequent provider evidence.
- `GraphEdge`: stable undirected endpoint pair plus hunting method ID, ontology
  relationship label and a set of supporting evidence/lookup IDs. Reverse lookup
  methods remain distinct evidence-labelled edges; the UI may group them visually.
- `RunResult`: summary and graph references, new-node/new-edge counts, failures,
  rejected-row counts, partial-source notices and stop reason.

Keep `IOC` and method `list[IOC]` outputs compatible. Add an internal execution
result or call-scoped receipt mechanism so the runner gets the exact receipt
atomically; do not rely on querying "latest" after another caller can run the
same method/IOC. Accepted evidence should be explicitly associated with graph
proposals, including the validation outcome, rather than guessed from context text.

## Three different decisions

| Decision | Owner | Question |
| --- | --- | --- |
| Retrieval outcome | Lookup layer | Did the provider return interpretable complete/partial/empty results or an error? |
| Relationship acceptance | Validator | Does evidence support this ontology-permitted connection? |
| Expansion decision | Workflow policy | Given investigation state, what is committed and how is the method rewarded? |

Do not combine these into one `success` boolean. An accepted relationship is not
a maliciousness assessment. A valid lookup may add no new information, and an
operational failure is different from a valid empty response.

For the initial manual policy, commit explicitly requested, validated edges and
report graph changes. Mark Algorithm 1 reward as not evaluated. This permits a
complete workflow without pretending the research algorithm exists.

Later, `Algorithm1Policy` owns IOC/method selection, used sets, history, ranking,
reward and commit decisions. The runner executes those decisions and persists
them. Provider methods remain unaware of algorithm state.

The current research notes describe the paper's condition as
`bool(valid_output_ids & (known_ioc_ids - used_ioc_ids))`, with the current IOC
already used and graph updates gated by the condition. Re-check the original
pseudocode before implementing selection/scoring formulas and freeze that
interpretation in tests. This is not equivalent to "any new edge was created."
Record graph additions separately from paper reward. If product behavior should
reward new edges, provide an explicitly named alternative policy rather than
silently changing the paper implementation.

## Persistence and execution requirements

Start with the existing SQLite approach, adding investigation/run/graph storage
through a repository boundary. A separate graph server is not required for the
first workflow. Use schema versions and migrations; preserve existing lookup data.

Commit graph changes and completed-step state in one transaction. Make replaying
a saved step idempotent: no duplicate nodes, edges, evidence links or rewards.
If a process stops after fetching but before committing, resume from the retained
receipt. Preserve immutable evidence even when the response cache expires.

Persist statuses such as `created`, `extracting`, `ready`, `running`, `completed`,
`failed`, and `cancelled`; keep partial retrieval as a separate property. Define
failure, no-output, budget exhaustion and cancellation behavior before automation.
Check cancellation between bounded operations and report that an in-flight
provider request may finish before the worker stops.

For the local web milestone use one background worker sharing source limits and
lookup clients, with durable job records and progress polling. Current per-client
rate limiters are not sufficient for multiple independent workers. Expand to
multiple workers only with shared coordination and job ownership/leases.

## Milestones and acceptance criteria

### 1. Organize and expose extraction

Completed foundation: provider/transport organization and non-interactive
extraction are implemented. Preserve existing extraction outputs and default
seven-type behavior while adding persisted report/passage associations. Excluded
reference sections and unusable candidates remain visible as diagnostics.

### 2. Complete offline terminal workflow

Add main/runner, manual policy, graph repository, receipts and JSON export.
Use a small synthetic report and existing provider-shaped fixtures. Demonstrate:

- Extraction supplies the requested seed and preserves its source passage.
- An exact-host DNS row creates a supported domain-IP edge.
- A subdomain-only row is rejected with expected and observed hostname details.
- A hash or other IOC with no runnable method remains visible and is skipped
  explicitly, not sent through an unsupported lookup.
- Repeated discoveries merge provenance without duplicate graph elements.
- The saved run reopens; resuming a completed step does not duplicate changes.
- Export contains graph/evidence and clearly identifies replay mode.

### 3. Execute the same workflow live

Switch transport configuration, not workflow logic. Start with one seed and one
RapidDNS method, then a supported VirusTotal route. Verify partial results,
access failures, cache use and run budgets. OTX failure must remain visible and
must not prevent the workflow from handling successful independent steps.

### 4. Connect the existing web app

Add a backend API and background worker using the same runner. Minimum API
capabilities: create investigation/report, start a run, read progress/results,
list compatible methods, inspect evidence/rejections, cancel and export.

Replace the live route's synthetic repository with a backend data adapter.
Existing frontend types need deliberate changes: edges currently lack method and
evidence IDs; graph nodes require authored positions; evidence assumes a report
passage; cases require a template; progress assumes five fixed checkpoints.
Support provider evidence independently of passages, calculated graph layout,
real run stages and optional attribution. Keep demo and live mode clearly separate.

Local single-user operation is the first target. Shared deployment adds user
authentication, investigation ownership/access checks and deployment configuration.
Upload limits and input validation belong to the initial API, not a later cleanup.

Acceptance: upload/paste a report, see extracted IOCs, select one and a method,
run enrichment, inspect a supported edge and a rejected candidate's explanation,
reload the investigation, and export it. UI graph/evidence views must derive from
the same saved run; no synthetic actor scores appear in live investigations.

### 5. Integrate Algorithm 1

Implement the policy through the already working runner. Test candidate/used-set
transitions, selection, ranking and reward formulas against hand-calculated
examples. Include accepted but unrewarded results, valid empty results, provider
failures, cached repeats, partial results, duplicate edges, budgets and restart.
Operational retry accounting must be distinct from logical method attempts and
documented before using it in scores.

Acceptance: manual and algorithm policies share extraction, lookup, validation,
storage, graph presentation and APIs. Selecting the algorithm changes scheduling
and expansion decisions; it does not require another retrieval pipeline.

## Recommended order and deferred work

Perform organization work first, then the offline complete path, then live and
web integration, then Algorithm 1. Define the policy contract while building the
manual path so the algorithm has an explicit integration point from the start.

Do not block this path on implementing all 39 candidate methods, MISP integration,
an LLM context provider, a distributed queue, a graph database server, or the
attribution model. Those can be independent additions after one trustworthy
report-to-enrichment investigation works end to end.
