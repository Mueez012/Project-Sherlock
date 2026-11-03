# Codebase organization plan

Status: organization implementation completed, 13 October 2026. The plan below
records the design and scope. Companion: [complete workflow plan](ioc-hunter/WORKFLOW_IMPLEMENTATION_PLAN.md).

## Implementation outcome

- Provider code and implemented method declarations now live together in separate
  RapidDNS, AlienVault and VirusTotal modules. `methods.py` collects them; disabled
  research candidates live separately. The same 60 definitions / 21 implementations
  are preserved.
- HTTP/browser transports are separate modules with compatible public imports.
- `extract_report()` provides structured non-interactive extraction. Existing
  interactive review still uses the shared stages and retains its prompts.
- `main.py` owns CLI dispatch; `__main__.py` delegates. New `extract`,
  `methods --candidates` and `--availability` interfaces expose these services.
- Rejections include messages and expected/observed DNS details. Old receipts
  remain readable; the acceptance policy and SQLite schema are unchanged.
- Method tables are generated; see the [code guide](ioc-hunter/README.md).
- Verification: 72 tests pass; the 60-entry registry and fixture request/evidence
  results for all 21 implemented methods match the pre-refactor code. Package
  discovery and dependency checks pass. Live provider checks were not repeated.
- Workflow, graph, algorithm and web-service modules remain deferred to the
  companion plan. They were not created as empty placeholders.

## Objective

Make it straightforward to trace one lookup and one investigation from entry
point to persisted result. Preserve working extraction and provider behavior
while separating terminal interaction, provider parsing, validation, and workflow
decisions. Organize the existing code before adding new providers or algorithms.

## Current findings

- `interactive_extraction.py` combines dataset loading, reusable extraction,
  console presentation, and `input()` prompts. `review_report()` returns a boolean,
  not a reusable extraction result.
- `providers.py` combines request construction and parsing for all three sources.
- `transport.py` combines shared request/response types, errors, rate limiting,
  HTTP retrieval, and browser retrieval. These are separate concerns, but do not
  require one file per class.
- `methods.py` generates ontology-compatible candidates and enables supported
  methods in the same registry. `implemented` currently means an operation is
  assigned; it does not establish current provider availability.
- `lookup.py` already provides the useful public `IOC -> list[IOC]` interface.
  Validation is already independent and should remain so.
- `storage.py` stores lookup snapshots, receipts, cache, and budgets only. It is
  not an investigation or graph repository.
- `__main__.py` already provides a CLI. A new `main.py` should become its thin
  application entry point, not introduce a competing workflow implementation.
- The frontend is a separate synthetic demonstration. Reorganization must not
  imply that its graph or attribution currently comes from Python.

## Proposed layout

Keep the existing project boundaries. Add directories where there are several
related implementations; keep small domain modules easy to find.

```text
ioc-hunter/
  ioc_hunter/
    __init__.py                 # Stable public Python imports
    __main__.py                 # Delegates to main.main()
    main.py                     # Arguments, dependency setup, workflow invocation
    models.py                   # IOC identity and normalization
    ontology.py                 # Permitted relationship types
    evidence.py                 # Provider evidence and lookup receipts
    validation.py               # Independent relationship checks
    context.py                  # Optional evidence-cited context generation
    metadata.py                 # Explicit structured metadata extraction
    methods.py                  # Supported method registry and discovery
    method_spec.py              # Shared metadata without registry dependencies
    method_candidates.py        # Disabled research candidates, separate listing
    lookup.py                   # Public lookup orchestration and list-return API
    storage.py                  # Existing lookup evidence/cache storage
    extraction/
      pipeline.py               # Callable extraction result, no console prompts
      datasets.py               # CSV/XLSX adapters
    providers/
      base.py                   # Small adapter contract and ParsedPage
      rapiddns.py
      alienvault.py
      virustotal.py
      common.py                 # Only genuinely shared parsing helpers
    transport/
      models.py                 # FetchRequest, Document, LookupError
      http.py
      browser.py
      limits.py
    interactive_extraction.py   # Existing review command, wrapping extraction
    mcp_server.py               # Optional interface over the same services
    workflow.py                 # New reusable investigation orchestration
    workflow_models.py         # Run configuration, state, events, result
    graph.py                   # New graph identity, merge and persistence rules
    investigation_store.py     # New reports, runs, graph, checkpoint persistence
    policies/
      manual.py                # New bounded explicit plan
      algorithm1.py            # Added after manual workflow works
  tests/
    ...                        # Group by capability as implementation proceeds
  output/                      # Ignored runtime data
```

The workflow, graph, and policy modules are additions from the companion plan,
not existing functionality. HTTP API and worker modules are added at the web
integration milestone. Do not create empty packages merely to match this tree.

## Rules that keep the structure simple

1. `main.py`, the web API, and MCP delegate to reusable Python services. They do
   not contain extraction, parser, graph, or scoring rules.
2. Each provider implements request construction and response parsing. Shared
   lookup orchestration handles caching, fallback, validation, and receipts.
3. Methods continue returning `list[IOC]`. Evidence remains separately accessible
   through an immutable receipt tied to the exact call.
4. Validation depends on IOC identity, ontology, method metadata, and evidence;
   it must not import the workflow, transport implementation, or graph store.
5. The workflow owns graph updates and algorithm state. Providers and validators
   never decide expansion reward or candidate scheduling.
6. Use explicit method registration with keyword arguments. Avoid replacing the
   small current registry with a dynamic plugin framework.
7. Keep credentials and paths in explicit configuration. Preserve environment
   variable support; never store secrets in method definitions or exported runs.

## Refactor sequence

| Step | Change | Completion check |
| --- | --- | --- |
| 1 | Establish import/CLI and fixture behavior baseline | Existing extraction, lookup, browser-interception, and MCP tests pass |
| 2 | Extract report processing from interactive presentation | Same IOC values and context; callable extraction performs no `input()` or printing |
| 3 | Split provider request/parsing implementations | Same fixtures produce equivalent candidates, evidence, accepted outputs and pagination states |
| 4 | Separate transport implementations | Same timeout, fallback, rate-limit and access-error behavior; browser tests still pass |
| 5 | Separate supported methods from research candidates | 21 current implemented definitions preserved; 39 candidates separately discoverable and never auto-scheduled |
| 6 | Improve validation diagnostics | Domain mismatch reports expected/observed host and evidence ID without weakening acceptance rules |
| 7 | Consolidate entry points, config and documentation | Existing commands/imports still work; one documented route from CLI to service |

Preserve `from ioc_hunter import IOC, LookupClient, ...`, the current CLI commands,
method IDs, and interactive extraction entry point. Preserve package-level
provider/transport imports through re-exports during migration. Update tests that
patch implementation internals intentionally. Replace `providers.py` and
`transport.py` atomically with their packages; do not leave both forms in place.

Keep default `list_methods()` behavior compatible initially; add an explicit
runnable-only discovery path for the workflow/UI. Distinguish candidate,
implemented, configured, and live-verified states. A live-verification timestamp
is historical evidence, not a guarantee of current availability.

Retain machine-readable rejection codes; add structured details and plain-language
messages. For example, `dns_domain_mismatch` should include `expected_domain`,
`observed_domain`, and `evidence_id`. Old receipts remain readable, including the
old `relationship_not_supported_by_fields` code.

Do not delete runtime databases, fixtures, environments or the dataset during
cleanup. Avoid an unrelated normalization or ontology change while moving code.
If schema changes are needed for new functionality, version and migrate them
explicitly instead of silently resetting user data.

## Documentation and checks

- Provide a short root README with setup, extraction, lookup, complete-run and
  evidence-inspection examples as those commands become available.
- Generate the method tables from registry data. Display disabled candidates in
  a separate table with `not implemented / retrieval route unconfirmed` wording.
- Document how to add one provider and one field-proof validator.
- Separate deterministic offline tests from opt-in live checks. A refactor must
  not require external provider availability to pass.
- Add regression coverage for understandable rejection details and old receipt
  compatibility. Reuse existing tests rather than duplicating implementation.

## Scope boundary

This plan changes organization and clarity. It does not enable the 39 candidates,
change the strict ontology, configure an LLM, replace provider access policies,
or implement Algorithm 1. New workflow behavior belongs to the companion plan.
