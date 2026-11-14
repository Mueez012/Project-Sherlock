# Algorithm 1 and incremental D2 dataset implementation plan

Date: 11 November 2026. Status: implementation started; the package now provides the offline baseline, dataset preparation, shared provider limits and resumable execution. This document records the design and acceptance criteria. See [the operating guide](README.md) for implemented commands and configuration.

Build a reusable IOC dataset from D2's existing sentences, then run the paper's Algorithm 1 against those extracted candidates. Save each report independently and reuse the existing workflow's lookup receipts, graph transactions and recovery. Restarting the same build must preserve completed reports and continue the current investigation from its last durable state.

This plan is for the IOC implementation owner and the teammate producing TTP annotations. It defines the package boundaries, data contracts, algorithm decisions, statistics, implementation order and acceptance checks.

## 1. Scope and implementation decisions

The first implementation includes:

- A separate `ioc_hunter/workflow/algorithm/` package.
- D2 JSONL input using the saved sentence arrays, without another sentence splitter.
- Report-level IOC entities, sentence associations and source positions.
- Algorithm 1's five rounds per IOC, compatible-method ranking, LLM method selection, batch admission and per-method counters.
- Direct model API selection with recorded model and prompt configuration.
- Incremental extraction artifacts and saved investigation graphs.
- Statistics derived from saved decisions and lookup receipts.
- Per-run records of isolated report IOCs, graph participation and validated discoveries that never entered the graph.
- One sequential batch process, atomic report exports and continuation through the existing workflow.

The first implementation does not require a worker queue, another database, distributed scheduling, an event-sourcing framework, a new provider abstraction, automatic CSKG construction or frontend pages. Existing manual investigations continue to use their current policy. The later provisional-frontier research policy is outside the baseline described here.

Initial execution is through the CLI and shared application service. HTTP/OpenAPI contracts must remain compatible where shared records gain algorithm fields; automatic HTTP controls and a dashboard can follow the working CLI.

### 1.1 Baseline and conventions

| Item | Planned behavior | Basis |
| --- | --- | --- |
| Candidate set | Unique canonical report IOCs, enlarged only by passing batches | Algorithm 1 |
| Used set | Mark the active IOC used before ranking or LLM selection; never reset it within the report | Algorithm 1 |
| Rounds | Five rounds for each selected IOC; a round may execute several methods | Algorithm 1 |
| Histories | Per-method tried and coverage counts; reset for each report | Algorithm 1 |
| Ranking | Printed UCT-inspired formula, descending; up to 50 compatible methods | Algorithm 1 |
| Selector | LLM chooses an ordered subset of the supplied shortlist | Algorithm 1 plus explicit response ordering |
| Admission | Require overlap with known unused candidates; admit the entire retained validated batch on a pass | Algorithm 1 and existing validator/workflow |
| Repeated calls | The same IOC/method may be selected in later rounds; cached calls remain logical calls | Algorithm 1 has no pair exclusion |
| IOC order | Seeds by first sentence index then canonical `(type, value)`; discoveries by admitting step then canonical `(type, value)` | Reproduction convention; paper does not specify an order |
| Ranking ties | Method ID ascending | Reproduction convention |
| Cold start | If the compatible invocation total is zero, assign equal finite ranking scores and record `cold_start=true`; let the selector choose | Reproduction convention for the paper's undefined `log(0)` |
| Exploration weight | Require a finite, nonnegative `alpha` in experiment configuration; do not invent a published default | Paper leaves the numeric value unspecified |
| Failures | Finalized failed or interrupted logical attempts count once in tried and zero in coverage; known local blocks before execution are deferred without counter changes | Operational convention; paper does not define exceptions |
| Bounded run | Record the exact limiting condition and incomplete algorithm outcome | Existing operational safeguards |

Using another model preserves the control flow but is a recorded model substitution. The model identifier must name the actual endpoint/checkpoint, rather than assuming that a generic model name reproduces the paper's abbreviated `DeepSeek-R1-70B` deployment.

## 2. Current substrate and changes to reuse it

The inspected registry contains 48 implemented methods and 20 disabled candidates. A method's implementation flag is capability metadata, not a guarantee of current provider access.

| Existing module | Reuse | Small required change |
| --- | --- | --- |
| `extraction/pipeline.py` | IOCFinder matching, reference-heading rules, version suppression, IOC assembly | Add a pre-split extraction entry point that preserves the supplied sentence array and indices |
| `models.py` and workflow identities | Canonical IOC values and stable node/edge IDs | Keep the four-field IOC object unchanged; attach dataset positions through separate records |
| `methods.py` | Implemented methods and discovery | Freeze the experiment's actual method set and declarations; keep disabled candidates out |
| `lookup.py` | Acquisition, validation, cache, pagination, follow-ups, retries and exact receipts | Add small acquisition counters where current receipts cannot support honest statistics |
| `workflow/policies.py` | `PaperAdmissionPolicy` overlap gate | Reuse the rule; automatic counter feedback belongs to the algorithm package |
| `workflow/runner.py` | One selected lookup and receipt application | Accept prepared extraction; add one narrow algorithm completion hook before committing a step |
| `workflow/repository.py` | SQLite transactions, graph merge, snapshots and recovery records | Add an atomic algorithm transition for operations that perform no lookup |
| `workflow/service.py` | Ownership, execution coordination and runner construction | Construct the correct automatic runner/policy from saved configuration; expose shared CLI operations |
| `workflow/coordination.py` | Existing thread/OS claims | Reuse the run claim and one batch claim; do not add another locking system |
| `workflow/replay.py` | Offline acquisition fixtures | Reuse for algorithm tests; missing fixture actions remain missing data |
| `api/schemas.py` and Hub mirror | Shared response contracts | Preserve manual null rewards and allow automatic numeric rewards/state without losing fields |
| `main.py` | CLI entry and store resolution | Add dataset preparation, hunting, continuation and statistics commands |

Both `InvestigationService._runner()` and `build_runner()` currently construct the manual default. They must restore saved automatic configuration, otherwise automatic runs cannot be reopened correctly.

## 3. Package layout and dependency direction

The implementation follows this package layout.

```text
ioc_hunter/workflow/algorithm/
    __init__.py             Public preparation and execution entry points
    models.py               Config, cursor, histories and decision record types
    scoring.py              Pure scoring, cold start and deterministic ranking
    selector.py             Selector contract and one configured model API adapter
    controller.py           One-report Algorithm 1 loop and receipt feedback
    dataset.py              D2 records, identities, preparation and portable exports
    batch.py                Sequential report traversal and incremental continuation
    statistics.py           Metric definitions, summaries and terminal progress data
    IMPLEMENTATION_PLAN.md   This document
```

Shared source-position logic belongs under `ioc_hunter/extraction/positions.py`, because it is useful independently of automatic selection. `extraction/pipeline.py` supplies pre-split matching; the algorithm package composes its output into the D2 record format.

The controller chooses actions through a workflow execution interface. The workflow executes lookups and commits their results. Providers and validators do not import the algorithm package. The controller does not parse provider responses or write graph SQL.

Use the existing repository with a narrow transition method and a completion callback. Avoid introducing a general plugin pipeline or repository framework for these two hooks.

## 4. D2 input and sentence coordinate system

### 4.1 Source release

Read `datasets/d2_model_ready/train.jsonl`, `valid.jsonl`, `test.jsonl` and `groups.json` from the repository root.

The inspected release contains:

| Split | Reports | Saved sentences |
| --- | ---: | ---: |
| Train | 2,660 | 133,817 |
| Validation | 296 | 13,183 |
| Test | 329 | 16,749 |
| Total | 3,285 | 163,749 |

Twenty-four reports have `cut_by_excel=true`. Preserve that flag. Keep group labels and original splits unchanged, but exclude actor group/label from selector prompts and ranking inputs.

D2 `report_id` is the report's starting line in the original raw CSV. It is not an IOC occurrence location. Do not use a JSONL row number as report identity.

Record SHA-256 hashes of source files, schema version, extraction options and implementation/package versions in the build manifest. Input files remain unchanged. A changed source release or extraction configuration creates a different build identity.

### 4.2 Frozen sentences

Use D2's existing `sentences` exactly as stored. Do not call spaCy, NLTK or the Hub's native extraction path to split the report again.

Both IOC extraction and TTP extraction identify a sentence using:

`report_id + sentence_index`

These references are scoped to the D2 release named in the dataset manifest. An optional readable `sentence_id`, such as `1683:s12`, combines report ID 1683 with sentence index 12. No sentence hash or sentence-array hash is required.

Use zero-based indices internally and display `sentence_index + 1`. Preserve empty/excluded decisions as flags; never close index gaps by renumbering. Keep the source-file integrity checks at build level and compare supplied sentence lists with the saved D2 arrays when validating input.

The existing TTP indexed-sentence predict interface can consume this list without splitting. The current real-mode Hub `/api/analyze` calls IOC-native extraction and can resegment supplied input; the batch path must bypass that behavior.

### 4.3 Original-text spans

Offsets refer to the exact D2 `text`: zero-based Unicode code points, end exclusive. Record the offset unit in the manifest. Convert explicitly for a UTF-16 browser client when needed.

Recover sentence spans by aligning the saved sentences monotonically through the original text, then verify every recovered slice. Identical sentences at different positions receive different sentence IDs. Repeated text must not be aligned repeatedly to its first appearance.

Reference exclusion reuses current heading detection. Convert original-text line ranges into exclusion spans and mark the affected saved sentences. Do not compute source positions against shortened `retained_text`. If a saved sentence crosses a section boundary, retain its identity and restrict matching to its allowed source spans rather than silently changing the sentence list.

If alignment cannot be established, retain the sentence index, record `position_status=unavailable` and a diagnostic, and leave offsets null. Do not guess a span or silently switch splitters. Such reports remain usable for sentence proximity, while highlighting and exclusion coverage limitations stay visible.

## 5. Dataset records and portable structure

### 5.1 Separate extraction builds from experiments

An extraction build fixes source text, sentence basis, extraction options and extraction version. An experiment fixes Algorithm 1 settings, selected methods, selector model/prompt and acquisition limits. Several experiments may reuse one extraction build.

Proposed generated location, already covered by the service's ignored output directory:

```text
services/ioc/output/d2-ioc/<build_id>/
    manifest.json
    reports/<report_key>.json
    experiments/<experiment_id>/
        experiment.json
        progress.json
        reports/<report_key>.json
        summaries/reports.csv
        summaries/methods.csv
        summaries/corpus.json
    exports/reports.jsonl
```

The normal workflow store remains `output/investigations/lookups.sqlite3`, or the caller's existing `--store` location. It is the authority for active investigations. The generated files are portable records and restartable exports; they do not replace workflow transactions.

`manifest.json` describes the build. `experiment.json` describes immutable experiment configuration. `progress.json` is a replaceable index/cache derived from artifacts and workflow state, not the only checkpoint.

### 5.2 Identities

Use the existing SHA-based `stable_id` convention with explicit namespaces; never use Python's process-dependent `hash()`.

| Identity | Inputs |
| --- | --- |
| `build_id` | Source release hashes, extraction settings/version, sentence-basis convention |
| `report_key` | Source release ID and original D2 report ID |
| `extraction_id` | Build ID, report key and text hash |
| `sentence_id` | Optional readable `<report_id>:s<sentence_index>`, scoped to the D2 release; no sentence hashing |
| `ioc_id` | Existing canonical workflow node identity `(type, normalized value)` |
| `association_id` | Extraction ID, IOC ID and sentence ID |
| `occurrence_id` | Association ID, source span and location kind |
| `run_id` | Namespace, build ID, explicit experiment ID and report key |
| `decision_id` | Run ID, active node ID and round index |
| `step_id` | Decision ID and index in its saved selected-method list |

An explicit experiment ID allows repeating the same configuration intentionally. Resuming the same experiment reuses its run IDs. Separate report graphs remain scoped by run even when their canonical IOC IDs coincide.

Sentence identity stays stable when only IOC extraction options or its locator version change. Associations/occurrences remain scoped to the extraction version, so the teammate's unchanged TTP annotations can join to either extraction. Existing hashed workflow IDs and build/source integrity checks remain separate from this simple sentence reference.

### 5.3 Extraction artifact

Each `reports/<report_key>.json` is a complete extraction artifact with:

| Field | Contents |
| --- | --- |
| `schema_version`, `build_id`, `extraction_id` | Record and extraction identity |
| `report` | Original D2 ID, split, group, label, truncation flag, source filename and optional source row for navigation |
| `text`, `text_sha256` | Original report text and its exact digest |
| `sentence_basis` | `d2_saved_sentences`, index base and offset unit; source release comes from the manifest |
| `sentences` | ID, index, exact text, nullable character range, position status, IOC exclusion flags/reasons |
| `iocs` | Unique canonical entities with type/value and report membership |
| `associations` | IOC-to-sentence links, context references, extraction provenance and location status |
| `occurrences` | Verified source mentions/components with raw spelling, spans and association ID |
| `extraction` | Options, source/library/code versions, status, timestamps and diagnostics |
| `statistics` | Extraction summary using the definitions in section 9 |

The unchanged four-field IOC objects can be assembled for the workflow from these records. Positions do not need to be inserted into the IOC dataclass.

### 5.4 Associations and exact occurrences

Sentence association is required. Exact mention span is nullable and must be truthful.

The installed IOCFinder observed during review is 8.1.0. Its public value result does not supply occurrence spans. Current matching also deduplicates `(type, value)` within each sentence. A normalized/refanged value may not literally appear in the original source, and some values are derived from URL/email components or CIDRs.

The first dataset milestone therefore guarantees one association per IOC and sentence. Add verified occurrences with a small tested locator that preserves source spelling and checks recovered values against the matcher output. Keep unresolved associations when exact location cannot be recovered.

An occurrence stores `raw_value`, `char_start`, `char_end`, `location_kind` (`literal` or `derived_component`), and `association_id`. Preserve overlapping URL/domain or email/domain components as distinct typed associations. Do not turn a component into an invented standalone mention.

Repeated identical IOCs in one sentence need multiple verified occurrences. Software-version suppression must also be checked at occurrence scope where exact occurrences are emitted: a version-shaped number is not made into an address occurrence merely because an actual address with the same value appears elsewhere in the sentence.

Do not call association counts total mention counts. Export `located_occurrences`, `associations_with_locations` and `unlocated_associations` separately. Future locator improvements create a new extraction version without losing the first usable sentence-level corpus.

### 5.5 Experiment report and evidence exports

Each experiment report links to its extraction artifact and contains:

- Experiment/run identity, configuration fingerprint and export revision.
- Current algorithm phase, completion classification and stop reason.
- Original seed node IDs and current graph nodes/edges.
- Step summaries, round decisions and per-method histories.
- Graph deltas and computed statistics.
- An `ioc_participation` record for every extracted report IOC and every unique retained validated lookup output, including isolated and non-admitted cases.
- Exact receipt IDs and a relative evidence export reference.

Use the existing consistent workflow snapshot/export path. The initial implementation embeds exact lookup receipts and retained source snapshots in each experiment report, including observations that failed graph admission. Replacing one report file therefore publishes graph and evidence at one consistent revision. A separate blob packaging system is deferred. A future graph-only export must explicitly state that raw evidence is not bundled. Do not export credentials, authentication headers or browser storage state.

Keep snapshot content, observation time and retrieval time distinct. Replaying a saved snapshot does not make it a new provider observation. Missing replay actions are unavailable data, not empty results.

#### Per-run IOC participation

Keep all original report IOCs as graph nodes even if their final neighbor count is zero. They also remain in the base extraction dataset. A graph export must not discard isolated nodes to make the result appear cleaner.

Build `ioc_participation` from the union of the report's extracted IOCs and retained validated lookup outputs. Reuse canonical IOC identity to merge repeated appearances within this run. Non-admitted outputs stay in these analysis records and receipts; recording them does not admit them to the graph or make them eligible for automatic exploration.

| Field | Meaning |
| --- | --- |
| `ioc_id`, `type`, `value`, `origin` | Identity and report/lookup provenance |
| `sentence_indices` | Actual report positions; empty for lookup-only discoveries |
| `in_graph` | Whether the IOC is present in the admitted graph at this export revision |
| `neighbor_count` | Distinct adjacent IOC identities, ignoring multiple method labels; null if outside the graph |
| `component_report_seed_count` | Number of original report IOCs in the same connected component; null if outside the graph |
| `attempts_as_input`, `admissions_as_input` | Finalized calls on this IOC and its passing batches; these do not determine whether it is isolated |
| `reason_codes` | Recorded operational/admission explanations, with multiple reasons allowed |
| `step_ids`, `lookup_ids` | Supporting selections, attempts and returned-output receipts, including non-admitted observations |

Use the experiment report's existing export revision, run outcome and stop reason to identify the scope of this assessment. An interrupted or limited result describes participation observed so far. No separate participation database or mutable classification ledger is needed.

Expose these views, whose reason-based groups may overlap:

- **Isolated report IOCs:** original seeds with `in_graph=true` and `neighbor_count=0`.
- **Graph-connected IOCs:** admitted nodes with at least one neighbor; the component seed count shows whether other report IOCs are connected through a path.
- **Validated but non-admitted discoveries:** retained validated outputs with `in_graph=false`, accompanied by the exact admission reason and receipt references.
- **Unresolved investigation coverage:** IOCs not processed or not meaningfully acquired because of no compatible method, no LLM selection, a rate/access block, failure, interruption or a run budget. These may also be isolated or connected by someone else's lookup.

Reason codes reuse existing outcomes where possible, for example `no_matching_records`, `all_candidates_rejected`, `no_known_unused_overlap`, `node_limit`, `rate_limited`, `access_denied` and `interrupted_unknown`. Add explicit coverage reasons such as `no_compatible_methods`, `not_selected`, `not_yet_processed` and `budget_stopped_before_attempt` when supported by the saved decisions/cursor. Do not infer that all methods were attempted from a used flag or an empty output list.

Zero admissions from an IOC's own lookups does not imply isolation: another IOC's lookup may have created an incident edge. Likewise, a lack of connections in this run is not proof that an IOC is unrelated to the incident. Preserve an empty provider response separately from an unavailable or unattempted lookup.

Recompute participation at export time and after resume. An output rejected by an earlier admission gate may enter the graph through a later passing batch. Its current membership must change while its earlier receipts and reasons remain inspectable.

### 5.6 Future TTP/CSKG join

The teammate's TTP record needs `report_id` and `sentence_index` from the same D2 release, plus ATT&CK label, score and model version. It may also include the readable sentence ID. The join does not require a sentence hash. Sentence classification uses `span_scope=sentence`; a precise technique phrase span is optional and must be supported by that extractor.

Later CSKG linking can rank annotations by absolute sentence-index distance for each IOC association, apply the declared nearest-three/tie convention, and preserve the association/annotation IDs and distance on each link. Sentence distance is a documented interpretation of textual proximity, not a claim that the paper defined that exact distance measure.

Provider-only IOC discoveries have no report association or source sentence. Store their lookup ancestry and existing graph edges. Never copy the parent's sentence number onto a discovered IOC. If that IOC also occurs in the report, its genuine associations supply its positions.

TTP extraction and CSKG edge creation are later consumers; the IOC builder does not need to run the TTP model now.

## 6. Algorithm configuration, state and model selection

### 6.1 Immutable experiment configuration

Persist an `algorithm1-v1` policy/version plus:

- `rounds_per_ioc=5`, `shortlist_size=50`, formula/cold-start/ordering versions and required `alpha`.
- The selected method IDs and metadata snapshot, with a catalogue fingerprint.
- Explicit excluded methods and their reasons. In live mode honor the current unresolved VirusTotal domain-to-URL exclusion. Freeze the actual resulting method set; do not describe all declared methods as live-tested.
- Model endpoint family, actual model ID/revision when available, prompt version, generation settings, context limits and request timeout.
- Selection validation/retry convention.
- Workflow step/node/time/page/output limits, existing follow-up limits and cache/acquisition settings relevant to reproduction.
- Source/extraction identities and replay manifest identity where applicable.

Require explicit model/API configuration for live selection. Do not default silently to a different model or use actor labels as context. Store secret-free configuration only.

A changed source, extraction, method set, prompt/model or algorithm setting requires a new build or experiment. Output paths and display formatting may change without changing scientific settings. Record code/library versions; incompatible saved-state versions fail clearly instead of being silently reinterpreted.

### 6.2 Minimal state inside the existing run JSON

```text
algorithm.version
algorithm.config_fingerprint
algorithm.phase
algorithm.active_node_id
algorithm.round_index
algorithm.current_decision_id
algorithm.next_method_index
algorithm.pending_step_id
algorithm.method_history[method_id] = {tried, coverage}
algorithm.initial_seed_ids
algorithm.decisions
dataset.build_id / extraction_id / report_key / artifact_hash
```

The current decision contains the saved selected-method order. A pending step references its existing workflow ID. Round decisions retain compatible candidates, rankings, pre-selection counters, model attempt metadata, selected IDs and short reasons.

Do not duplicate mutable `O`, `O_used` or `E` in another store. They come from workflow nodes, their `used` flags, and method-labelled edges. Derive an unused queue using stable graph insertion order. Persist the active IOC so its used flag does not cause a resumed controller to skip its unfinished rounds.

Use five explicit phases: `choose_ioc`, `select_methods`, `execute_methods`, `finish_round` and `finished`. The round index is zero-based; indices 0-4 represent the five rounds. Reaching the end of the saved selected-method list enters `finish_round`; one no-lookup transition advances the round or clears the active IOC. A round decision has its own `pending`, `selected` or `failed` status, so a partially completed selector call does not require another scheduler state.

The automatic policy has a distinct saved name, `algorithm1/paper-admission-v1`, and delegates the overlap calculation to the existing paper admission rule. The final receipt feedback supplies numeric reward after validation and operational bounds. The manual policy name and null reward behavior remain unchanged.

### 6.3 Selector behavior

The selector interface takes one IOC with source context and the ranked shortlist. It returns an ordered method selection and short justifications. The model does not calculate counters, fetch providers, validate relationships or update the graph.

Validate structured output before execution: list shape, valid IDs, membership in the saved shortlist and compatible input types. Reject unsupported IDs and malformed responses as a selection failure; do not partially execute an invalid response. Deduplicate duplicate IDs within one response while preserving first order and record that normalization. Selecting the same ID in later rounds remains allowed.

Use a bounded selector timeout and one validation retry for the first implementation. Save failed attempts and timings. After failure, leave the run at the selection boundary with a diagnostic; stop the current batch so a global model configuration problem does not fail thousands of reports. Restart can retry the same unsaved decision. No deterministic fallback silently substitutes for the LLM baseline.

An empty valid selection advances the round. With no compatible methods, record an empty round without contacting the model. Both are explicit conventions and consume no lookup step.

Prompts include exact IOC type/value and complete method metadata. Context clipping, if needed, is deterministic, recorded and versioned. Return concise selection explanations; do not require private reasoning traces. Treat source excerpts as data.

## 7. One-report execution flow

1. Load or prepare the immutable extraction artifact. Initialize a workflow investigation directly from that prepared result, without splitting or provider calls.
2. Recover any pending workflow step before making another selection. Restore the active IOC/round and saved decision if present.
3. If no IOC is active, choose the next unused candidate. If none exists, finish with `candidate_exhausted`.
4. Atomically mark that candidate used and set its active round to zero before ranking or LLM work.
5. At the round boundary, filter the fixed method set by input type. Compute the compatible invocation total across that set. Apply the declared cold-start rule or printed formula, tie-break by ID, and shortlist up to 50.
6. Persist the ranking and pending decision before calling the selector. Save and validate its response before executing any selected method.
7. Execute the saved method list sequentially through the workflow. Preserve one `step_id` and reserved `lookup_id` per selected action.
8. After each finalized receipt, use the existing accepted-evidence revalidation and paper overlap gate. Apply a passing full batch to the graph. Increment tried once, increment coverage by one on admitted batch success, and advance the method cursor in the same step commit.
9. After the selected list finishes, advance the round in a no-lookup transition. Recompute rankings for the next round; do not rerank midway through the already selected list.
10. After five rounds, clear the active IOC and choose the next unused graph candidate. New discoveries enter this traversal only after passing admission.
11. Stop at candidate exhaustion, cancellation or an operational limit. Export the current graph and statistics with a truthful completion classification.

The score for positive compatible total is:

```text
score(m) = C_m / (T_m + 1e-6)
           + alpha * sqrt(ln(sum(T_n for compatible n)) / (T_m + 1e-6))
```

Counters update after each method, but ranking is recomputed at round boundaries. Coverage is binary per passing batch even if its graph identities already exist. The graph merges duplicate identities and preserves new evidence links rather than inserting duplicate copies of the same method-labelled edge.

### 7.1 Outcomes and bounds

| Outcome | Graph/counter handling | Continuation |
| --- | --- | --- |
| Usable result with known-unused overlap | Whole retained validated batch admitted; tried +1, coverage +1 | Next selected method |
| Usable result without overlap, including empty result | No graph insertion; tried +1, coverage unchanged | Next selected method |
| Partial result | Use retained validated outputs and retain partial reasons; same overlap rule | Next method subject to source stop conditions |
| Finalized failure | No insertion; tried +1, coverage unchanged; keep exact failure | Continue only if source/batch conditions allow |
| Interrupted acquisition with unknown completion | Preserve unknown outcome; tried +1 once, no coverage | Advance that action after existing recovery; no automatic reissue |
| Known local cooldown/quota before execution | Keep action pending; no graph update and no tried/coverage increment | Wait or exit with a saved next eligible time |
| Valid empty selection/no compatible method | Record empty round; no tried/coverage increments | Advance round |
| Selector failure after bounded retry | Save diagnostic; no lookup counters | Stop batch; resume selection on restart |
| Batch would exceed graph node limit | Preserve receipt and raw overlap; no partial batch insertion; tried +1, coverage unchanged | Stop report as limited |

The node limit is an operational truncation of the paper trajectory: retain `paper_overlap_pass` separately from actual `admitted` so it is clear why a passing overlap did not earn admitted coverage. Do not claim this budget-truncated event reproduces an unlimited graph update.

Check workflow budgets before each selector call and lookup and after each saved result. Existing `max_seconds` accounts mainly for extraction/acquisition; add measured selector time once when saving the selection outcome. Exclude process downtime. Keep extraction, selector and acquisition durations separately available.

Freeze the configured limits. Existing budget-closed runs are terminal. Restart skips them as `limited`; a larger-budget experiment is a new run rather than a hidden change to the original run.

For a source-wide cooldown or daily acquisition budget exhaustion, finalize selected action `k` and atomically save its counters and `next_method_index=k+1`, then stop the hunting batch with a recoverable diagnostic. Restart continues the remaining selection, rather than repeating the failed or unknown action. Do not march through thousands of remaining actions generating predictable failures. The extraction stage remains independently usable. Acquisition limits stay in the existing lookup layer rather than becoming a second algorithm rate limiter.

This action advancement applies when a logical action actually ran and produced a finalized outcome. A known local preflight block leaves action `k` pending and its counters unchanged. A race can also reveal a local block after a workflow step is reserved: keep that step running with a deferred receipt, then reserve a fresh immutable receipt ID for the same logical step when eligible. Do not turn that deferral into a completed step or repeatedly replay it without making progress.

### 7.2 Shared provider limits, caching and waiting

All D2 reports use the same workflow/evidence store. Its provider gate applies across methods and clients; starting a new report does not reset quota or cooldown. Keep one configured profile per provider with minimum interval, local daily acquisition cap, initial fallback backoff and maximum fallback backoff.

The current defaults are 15 seconds, 500 local attempts per UTC day, 60 seconds initial fallback and 3,600 seconds maximum fallback. They are application safeguards, not verified entitlements for all providers or browser/API routes. Configure profiles from actual account/route constraints and a small training-report pilot.

Check captured evidence and the normal response cache before network gates. Every uncached page, follow-up, retry and transport fetch uses the shared provider gate. Track logical calls separately from top-level fetch attempts and browser background XHR. A mixed cached/live method is not a zero-request lookup merely because its cache flag is true.

For dataset experiments, optional frozen caching reuses the captured logical result within the build, including completed multi-page results. Scope it by canonical query, method, limits, route/integration version, transport, credentials/access state and build namespace. Each reuse receives a new receipt and its own graph admission decision; original observation timestamps and supporting snapshots are preserved. Current cached data from another report does not imply graph membership in this one.

On a real provider 429, honor `Retry-After`; when absent, use bounded exponential fallback. Persist the next eligible time. Keep the current report's selected-method order. A short wait happens in the acquisition gate; a longer wait checkpoints and either returns `in_progress` or waits automatically when CLI `--wait` is enabled. Ctrl+C saves the available state, and a later invocation continues it. No job queue or separate scheduler is required.

Measure known pacing/cooldown waits separately and exclude them from the active-processing budget. Time spent with the program closed is not counted as active work or measured running wait. The controller checkpoints its measured long waits in the existing run state, including on graceful interruption.

Distinguish a 429 from the required response/bootstrap or navigation from an unrelated page widget. A completed required response may remain usable with an optional-widget warning. If the requested operation never completes and throttle scope is uncertain, retain the conservative block. Do not change routes/accounts to evade a provider restriction.

The scale estimate uses uncached reads per provider, not only report count. Prepare D2 offline first, pilot approximately 10-20 training reports, inspect per-method follow-up/page counts and cache reuse, then project collection against the actual quota profiles. Full D2 enrichment may require collection over many days; progress and partial outcomes remain useful throughout.

## 8. Minimal persistence and continuation

### 8.1 Prepared run creation

Add a workflow entry point for a prepared extraction result and its dataset metadata. Build and validate seed graph data first, then reuse `WorkflowRepository.create_run(run, nodes)` to publish a ready run and its seed nodes in one transaction. The already saved extraction artifact preserves the source if initialization fails.

Use the artifact's stable sentence IDs as the prepared run's passage IDs, retaining the original zero-based indices and sentence-basis metadata. Do not generate unrelated random report/sentence identities on this path: graph `passage_ids` must join directly to the dataset and future TTP annotations. Keep the existing manual passage identity convention for manual runs.

If the initial seed graph exceeds the node budget, preserve the extraction and publish a clear failed/limited initialization outcome with `initial_node_limit`; do not silently drop seed nodes or report an empty successful investigation.

Use the deterministic run ID under the existing run claim. On restart, look it up before creating it. A crash after SQLite creation but before `progress.json` is updated therefore finds the same run. No second corpus mapping table is required.

Keep the manual report-ingestion route and its preserved-failure behavior unchanged. The new prepared-result entry point avoids leaving a pre-extracted dataset run half-initialized in `extracting` state.

### 8.2 Two checkpoint hooks

**No-lookup transition.** Add a repository method that loads/checks the current run revision and expected algorithm phase, optionally marks the selected node used, saves algorithm state/decision and increments `graph_revision` in one transaction. Use it for IOC selection, rankings, accepted model selection, empty rounds, round advancement and termination.

Reuse the existing revision as the saved investigation revision; no-edge workflow commits already increment it. Document the expanded meaning. Current `save_run()` only checks the revision, so it cannot provide this transition by itself. An expected phase/decision/method cursor guards against applying an advancement twice; no new generic transition log is necessary.

**Lookup completion.** Add one optional algorithm feedback hook to the receipt application path immediately before `commit_step()`. It updates histories, numeric reward and the saved method cursor. The existing commit saves graph, receipt-bearing completed step and updated run JSON together. Already-completed steps must bypass feedback and never increment counters again.

Invoke feedback after the runner computes its normal elapsed time and step/time budget status, so later runner assignments cannot overwrite algorithm termination. On `node_limit`, the hook also saves workflow `status=completed`, `stop_reason=node_limit` and algorithm outcome `limited` in that same commit. A separate controller termination afterward would leave a crash window. Existing terminal step/time limits take precedence when a source pause or another limit happens simultaneously.

The no-receipt branch of `resume()` must use the same feedback path for its synthetic `interrupted_unknown` completion. Otherwise recovered unknown attempts would not advance the algorithm cursor or would retain manual-only null reward fields. Deferred receipts are a different, known zero-dispatch condition: they keep the pending logical step and selected-method position until retry is permitted.

Use existing execution claims around controller operations. Do not call a public service method that reacquires an already-held nonreentrant run claim; expose/reuse one internal execution path under that claim. Prevent manual `execute` calls from injecting unrelated actions into an automatic run. Read/export operations remain available.

### 8.3 Batch continuation and exports

Run one sequential process in two independently restartable stages:

1. `prepare`: validate each selected D2 record, extract from its saved sentences and atomically save one base report artifact. A completed matching artifact is reused. An interrupted current extraction is inexpensive local work and can be redone.
2. `hunt`: reuse those artifacts, open/create the deterministic per-report workflow run, recover it and continue Algorithm 1. Save a report graph/statistics export when it stops. Previously completed matching runs are skipped.

Persist through normal SQLite step commits while the report is active. Per-report export after every lookup is unnecessary. On a graceful interruption, also attempt an export of the current saved state. After a hard halt, regenerate that export from SQLite on restart.

Write files to a temporary sibling and replace the destination atomically on the same filesystem. Export first, then refresh the progress index. Ignore incomplete temporary files. Rebuild consolidated JSONL/CSV summaries from committed artifacts/state; do not append to them as the only progress ledger.

| Halt point | Restart behavior |
| --- | --- |
| Before extraction artifact replacement | Redo only that report's local extraction |
| After extraction artifact replacement | Load it and skip repeated extraction |
| After run creation, before progress-index update | Find the deterministic run ID in SQLite |
| During selector call before validated selection is saved | Repeat the unsaved selection; the earlier request may have incurred unknown cost |
| After selection is saved | Reuse its selected IDs/order and next-method position |
| During lookup with a saved receipt | Existing workflow recovers and applies that exact receipt |
| During local throttle deferral | Keep the same action and logical step pending; use a fresh immutable receipt on retry and leave counters unchanged |
| During lookup without a saved receipt | Existing unknown-outcome recovery; finalize once and advance without auto-refetch |
| After graph/counter commit, before export | Regenerate export; no counter change or lookup repetition |
| During file export | Replace the incomplete temporary output from the saved snapshot |
| After report completion | Skip it, or regenerate a missing/stale export |

Resume promises reuse of saved work. It cannot promise exactly-once remote requests when the process died before a receipt was saved. Preserve that existing limitation instead of adding acquisition replay machinery.

### 8.4 Progress and failure classifications

Keep workflow status compatible and derive a dataset-facing result:

| Dataset outcome | Meaning |
| --- | --- |
| `prepared` | Base extraction saved; hunting not started |
| `in_progress` | Automatic run is open or recoverable |
| `complete` | Candidate set exhausted, including a report with no extracted candidates |
| `limited` | Workflow budget ended the investigation before exhaustion |
| `failed` | A report-specific extraction/state error prevented completion |
| `cancelled` | Explicitly closed by the user |

Record `stop_reason` independently. A selector/source-wide pause leaves the current run open with a diagnostic; it is not a completed algorithm result. On restart, resume that report before moving on.

| Algorithm condition | Existing workflow status |
| --- | --- |
| Between selections/rounds | `ready` with the saved algorithm phase |
| Lookup acquisition active | `running` with a pending workflow step |
| Selector/source pause | `ready` with a recoverable diagnostic and saved cursor |
| Candidate set exhausted | `completed`, `stop_reason=candidate_exhausted` |
| Step/time/node budget reached | `completed` with the explicit limit reason and dataset outcome `limited` |
| Explicit cancellation | `cancelled` |

A process can hold the execution claim during selector work even though the workflow status is `ready`; the algorithm phase/decision explains the current activity. Ordinary close/execute operations must honor that claim. No interruptible remote-call cancellation system is required for the first implementation.

Malformed input or report-specific extraction errors are recorded per report and do not erase prior work. Continue other reports by default. Retrying failed input items is explicit. Cancellation is distinct from Ctrl+C: Ctrl+C stops the process and leaves work resumable; explicit cancellation closes the run.

Hold one existing-style batch resource claim while mutating a build/experiment index so two processes cannot unintentionally process the same batch. Parallel corpus scheduling is deferred.

## 9. Statistics and display

Statistics come from saved extraction artifacts, decisions, steps and graph snapshots. Rendering or recomputing a summary never changes counters. Store `metrics_version`, numerator/denominator where applicable and snapshot revision. Summary files are derived and replaceable.

### 9.1 Extraction and corpus progress

| Metric | Definition |
| --- | --- |
| Reports by split/outcome | Total selected, prepared, complete, limited, in progress, failed and cancelled |
| Unique IOC entities | Count of canonical IOC identities in each report; also by type |
| IOC-sentence associations | Unique `(report, IOC, sentence)` links |
| Located occurrences | Count of verified spans; literal and derived components distinguished |
| Unlocated associations | Associations without a verified occurrence location; not a count of missing mentions |
| Sentence extraction coverage | Total, eligible and reference-excluded sentence counts |
| Data quality | Truncated reports, unavailable sentence spans, extraction diagnostics, no-IOC reports |

Corpus-wide distinct IOC identities and the sum of per-report IOC counts are different metrics; label both explicitly. Preserve split-level summaries.

### 9.2 Algorithm and selection

| Metric | Definition |
| --- | --- |
| `T_m` | Finalized logical method attempts, including declared failed/unknown convention |
| `C_m` | Actually admitted qualifying batches; zero or one per attempt |
| Paper batch rate | `C_m / T_m`; null when `T_m=0` |
| Admission among usable lookups | Admitted batches / `ok+empty+partial` lookups, with denominator named |
| Method exposure | Rounds in which a method was compatible and shortlisted |
| Selection rate | Rounds selecting a method / rounds exposing it |
| Round trace | Active IOC, round, score inputs, ranking, selected order and short reasons |
| Selector usage | Calls, failed/invalid responses, known tokens/cost, latency, model/prompt configuration |
| Traversal progress | Used/unused candidates, active IOC, completed rounds and current action |

Keep raw overlap, actual admission and provider usability separate. Do not rename all three as success. Counters reset per report; corpus method summaries aggregate completed histories without feeding them back into the next report's baseline initialization.

### 9.3 Lookup operations and graph

| Metric | Definition |
| --- | --- |
| Provider outcomes | Separate `ok`, `empty`, `partial`, rate/access/schema/network failures and unknown interruption |
| Outputs | Retained unique validated outputs, rejected observations and rejection reasons |
| Non-admitted data | Validated outputs retained in receipts whose batches did not enter the graph |
| IOC participation | Per-run records and counts of isolated report IOCs, connected IOCs, validated outputs outside the graph and unresolved investigation coverage |
| Own-query outcome | Per-IOC attempted and admitted batch counts, kept separate from incident-edge participation |
| Graph delta | New nodes, method-labelled edges and evidence links per step |
| Origin | Original report seeds versus lookup-discovered nodes |
| Connectivity | Components, isolated original seeds, seed-containing components and original seeds in the largest component |
| Effort | Logical attempts, parsed pages, follow-ups, retries, actual top-level fetch attempts and cache reads |
| Timing | Extraction, selector, acquisition and total measured processing time; downtime excluded |
| Limits | Partial reasons, stop reasons, budget usage and unfinished rounds/candidates |

For comparable efficiency summaries, report admitted batches and new edges per logical attempt and per known top-level fetch attempt. Return null for an unavailable/zero denominator. Graph connectivity and growth are diagnostics, not incident-relevance precision or actor-attribution accuracy.

For aggregates, show totals and per-report median/p90 times and graph sizes, counts of included reports, and complete/limited outcomes separately. Distinguish pooled rates from averages of per-report rates.

### 9.4 Small receipt instrumentation

The current `cache_hit` means at least one read used cache. A composed method can mix a cached root response and live follow-ups. It must not be reported as zero external requests.

Add backward-compatible acquisition accounting to lookup receipts:

- Count actual `client.fetch()` invocations, including failed attempts, by transport.
- Count cache reads separately and annotate response entries with cached/live origin where known.
- Count parsed pages, scheduled/executed follow-ups and additional retry attempts.
- Mark accounting as unknown for old receipts without these fields.

A browser navigation/fetch invocation is not a count of every page asset/XHR, provider quota unit or billed request. Export this accounting scope explicitly. Model token/cost fields are null when the endpoint does not supply them; an unknown interrupted request is not assigned zero cost.

### 9.5 Initial terminal presentation

Show one concise progress view with dataset report number/key, outcome counts, active IOC/round/method, latest selector/admission reason, tried/coverage counters, graph delta, elapsed processing time and remaining budgets. Offer structured JSON and report/method CSV summaries for analysis.

Refresh from committed state after selection, each lookup and report completion. Include an inspectable list of isolated/unresolved IOCs with their sentence positions, attempted methods, reasons and receipt references. A later dashboard reads the same saved summaries; it does not recreate the algorithm in the frontend.

## 10. Proposed CLI and compatibility

Command names below describe the intended interface; they are not implemented yet.

| Command | Purpose |
| --- | --- |
| `dataset prepare` | Read D2, preserve saved sentences and incrementally write base extraction artifacts |
| `algorithm run` | Hunt a selected prepared report or report subset with explicit experiment configuration |
| `algorithm resume` | Reopen the same build/experiment and continue its first unfinished report |
| `algorithm stats` | Read saved state and print report/method/corpus statistics |
| `dataset export` | Regenerate portable JSONL and graph/evidence/CSV exports without provider/model calls |

Provide explicit source/build/experiment/store paths, split and report-ID filters, and a pilot `max_reports` option. Traverse splits and report IDs deterministically. Starting a live hunting experiment requires selector and acquisition configuration; preparing D2 alone makes no model/provider calls.

Resume uses saved scientific configuration. A changed model/method set/budget does not silently replace it. Portable exports are readable on another machine without credentials. Continuing acquisition requires the saved SQLite store and original configuration; importing portable artifacts into a new active store is deferred.

Preserve existing manual CLI commands. Automatic-run manual mutation is rejected clearly so a terminal selection cannot change the saved round trajectory. The service factory restores the proper policy and feedback hook for all resume paths.

Update both IOC-service and Hub mirrored reward/state response schemas when shared records are extended. Manual/historical records retain `reward=null` and `not_evaluated`; automatic finalized attempts expose reward 0/1 with the declared evaluated status. Add optional algorithm/dataset metadata without requiring old runs to invent it. Regenerate API reference artifacts only when those wire contracts change.

## 11. Implementation milestones and verification

### Milestone 1: frozen D2 extraction dataset

Implement source validation/fingerprints, stable identities, sentence alignment, pre-split extraction and atomic base-report artifacts. Reuse one matcher/sentencizer-independent extraction setup for batch work. Reference filtering preserves all sentence indices.

Acceptance: a small train/validation/test sample preserves every D2 `(report_id, sentence_index)` and exact saved sentence; a second preparation run skips matching artifacts; no splitter, provider or model is invoked. Verify repeated sentences, exclusion boundaries, normalized/defanged values, component associations and nullable locations. No sentence or sentence-array hash is introduced.

### Milestone 2: pure algorithm logic and selector contract

Implement state/config types, scoring, stable ordering, five-round transitions and selector request/response validation. Use a deterministic fake selector for offline tests. Validate required `alpha` and finite scores; never serialize NaN/infinity.

Acceptance: compatible-type totals, cold start, rank ties, top-50 behavior with a synthetic larger catalogue, empty lists and repeated later-round method calls match the declared policy. Selector tests reject invented IDs and actor labels never enter the prompt.

### Milestone 3: workflow integration and current-report resume

Implement prepared-run creation, no-lookup transitions, one receipt feedback hook, automatic factory restoration and shared reward/schema compatibility. Reuse existing evidence revalidation and graph commit.

Acceptance: known-unused overlap admits the entire validated batch; new-only/used-only batches do not. A repeated admitted batch may add no new graph identity while increasing coverage. Saved-selection reuse, empty rounds, active-IOC resume, receipt recovery and duplicate step completion preserve counters exactly once.

### Milestone 4: incremental report traversal

Implement the sequential batch, deterministic run IDs, atomic report/evidence exports and derived progress/summary regeneration. Integrate source-wide pause, report-level failure and terminal limited outcomes.

Acceptance: halt and restart at each persistence boundary in section 8.3. Completed reports are skipped, current graph work is reused, missing exports are rebuilt, and repeated resumes do not duplicate report runs or JSONL rows.

Rate-specific acceptance: a preflight cooldown creates no attempted step; a reserved-step deferral remains one pending logical step; a real 429 advances exactly once and pauses; `--wait` resumes without reselection; provider profiles/cache are shared across clients; intentional waits do not exhaust the active-time limit; frozen fixture/replay content cannot change between reports under one experiment ID.

### Milestone 5: statistics and usable terminal analysis

Implement metric definitions, small acquisition instrumentation and progress/JSON/CSV outputs. Include model usage and graph connectivity summaries with clear denominators and unknown values.

Acceptance: a mixed cached/live composed lookup has truthful fetch counts; old receipts show unknown accounting; failures and empty results remain distinct; recomputing summaries does not modify investigation state. Every report IOC is exported even when isolated, and validated outputs that never entered the graph remain inspectable.

Verify participation with seeds `A, B, C`: `A -> {Y}` fails admission because Y is new, then `B -> {C, A, X}` passes through unused C. A is graph-connected despite its own zero admissions; X is admitted; Y stays validated but non-admitted. A separate untouched/unsupported seed remains as a degree-zero node with its coverage reason. Also verify a rate-limited IOC is unresolved rather than declared unrelated, and an initially non-admitted output changes membership if later admitted. Repeat export after resume and confirm these records update without duplicating attempts or dropping isolated nodes.

### Milestone 6: bounded integration pilot

Use replay fixtures and a fake/API-mocked selector first. After offline acceptance, run an explicitly configured small live report subset, inspect decisions/evidence, stop/restart it and export the resulting dataset. Record actual provider limits separately from logical algorithm steps. Do not launch all 3,285 live investigations as an implicit test.

Run the existing extraction, workflow, repository, service, terminal and API regression checks appropriate to the touched interfaces. Broaden testing when failures or changes justify it. Actual selector/provider availability is a separately recorded live result, not established by fixture tests.

## 12. Completion criteria and configuration still required

The implementation is ready when:

1. D2 saved sentence IDs survive preparation and join directly with indexed TTP output.
2. Every extracted IOC has truthful sentence associations; exact spans and their limitations are explicit.
3. Report extraction is reusable independently of model/provider availability.
4. Automatic logic lives under `workflow/algorithm/`; existing lookup/provider responsibilities remain intact.
5. Five-round scheduling, scoring, selection, full-batch admission and histories follow the documented baseline/conventions.
6. A halted batch resumes through its saved workflow run, preserving completed reports and committed counters.
7. Graph/statistics exports can be regenerated after an interruption without rerunning acquisition.
8. Terminal/CSV/JSON statistics distinguish operational outcomes, paper coverage and graph growth.
9. Source/selector/configuration fingerprints support reproducible comparisons without overwriting prior experiments.
10. Existing manual investigations and historical receipts remain readable and functional.
11. Sentence references use report ID/index without sentence hashes, and future TTP annotations can join directly on those fields.
12. Every run retains and exports isolated/non-admitted IOC participation with evidence-based reasons; zero own-query coverage is not treated as proof of no relationship.

Before a live experiment, supply the selector endpoint/model, its supported structured-response format, generation settings, numerical `alpha` and an explicit budget profile. These are configuration inputs, not reasons to delay building the offline dataset and fake-selector baseline.

The initial implementation includes an explicit replay selector/example, a direct chat-completion-compatible HTTP selector adapter, atomic per-report preparation, automatic workflow hooks, per-run/corpus statistics and the deferred waiting cases above. Live selector/provider compatibility and a complete D2 acquisition are separate verification steps; they have not been established by offline tests.

## 13. Local implementation references

- [Current service overview](../../../README.md)
- [Settled admission rule](../../../IOC_INCLUSION_REFERENCE.md)
- [Existing workflow guide](../../../WORKFLOW_GUIDE.md)
- [Existing workflow design](../../../WORKFLOW_EXPLAINED.md)
- [Current method verification](../../../METHODS_VERIFICATION_20261110.md)
- [Workflow runner](../runner.py)
- [Workflow repository](../repository.py)
- [Shared investigation service](../service.py)
- [Extraction pipeline](../../extraction/pipeline.py)
- [Lookup client](../../lookup.py)
- [D2 source contract](../../../../../src/threatmamba/contracts.py)
- [D2 sentence splitter used to create the saved arrays](../../../../../src/threatmamba/text.py)
- [Indexed TTP prediction route](../../../../ttp/ttp_api/routes/predict.py)

The local ThreatMAMBA paper, Algorithm 1 on PDF page 6 / IEEE page 4391 and the IOC section on PDF pages 3-4, supplies the baseline. This plan does not adopt the separate algorithm-improvement research proposal.
