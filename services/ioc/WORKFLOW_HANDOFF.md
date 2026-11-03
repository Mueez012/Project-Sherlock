# Workflow implementation handoff

Updated: 14 October 2026. Start a fresh session here, then read
[the workflow plan](WORKFLOW_IMPLEMENTATION_PLAN.md) and applicable repository
instructions before changing code.

## Next objective

Implement the first complete report-to-graph workflow. Code organization and
method reliability repairs are complete to the documented baseline; do not
restart those refactors. Future enrichment work is tracked in
[METHODS_TODO.md](METHODS_TODO.md). The user requested this handoff and backlog
before moving on; this document does not claim the workflow is implemented.

## Existing pieces and boundaries

- `ioc_hunter/extraction/pipeline.py`: non-interactive `extract_report()` returns
  extracted IOC objects and original report context.
- `ioc_hunter/methods.py`, `method_spec.py`, `method_candidates.py`: 21 implemented
  methods and 39 disabled candidates. Local availability is not live readiness.
- `ioc_hunter/providers/`: separate RapidDNS, AlienVault OTX and VirusTotal
  adapters. Paper website/report-page interfaces are primary; official APIs are
  optional credentialed fallbacks. Browser-generated JSON capture is supported.
- `ioc_hunter/lookup.py`: retrieval, cache, parsing and independent validation;
  methods accept an IOC and return `list[IOC]`.
- `ioc_hunter/validation.py`: deterministic evidence and ontology checks.
- `ioc_hunter/storage.py`: SQLite lookup receipts, snapshots, cache and budgets;
  it is not an investigation graph repository.
- `ioc_hunter/main.py` and `__main__.py`: existing CLI entry points to extend.
  Keep orchestration in reusable services rather than putting all logic in CLI.

Keep the strict ontology: graph connections are undirected; lookup methods are
directional. Provider adapters must not select the next IOC, assign algorithm
reward or mutate graph state. Preserve rejected candidates and partial outcomes.

## Missing complete path

The reusable runner, persistent investigation graph, run/step state, manual
policy, expansion evaluation, Algorithm 1 and backend/web integration remain
planned. Start with a deterministic offline manual workflow using the real
extractor, lookup and validator with injected fixture transports. Then add a
bounded live run, followed by web integration and Algorithm 1 through the same
runner. Re-read the original paper pseudocode before implementing its reward
formula; graph additions and paper reward must be recorded separately.

First milestone acceptance:

1. Extract a report, select an actual extracted seed and an explicit method.
2. Execute lookup and attach its exact call-scoped receipt and accepted evidence
   to proposed graph changes; avoid a concurrent "latest receipt" lookup.
3. Persist canonical nodes, ontology-supported edges, provenance and completed
   step state transactionally. Repeated/resumed steps must be idempotent.
4. Retain unsupported IOCs, rejections, empty/error/partial outcomes and limits.
5. Reopen/export the saved investigation with its replay/live mode explicit.
6. Demonstrate the complete path offline before provider-dependent validation.

## Verification baseline and limitations

[METHOD_RELIABILITY_RESULTS.md](METHOD_RELIABILITY_RESULTS.md) is the current
evidence summary: 90 offline tests passed; 17 methods live-positive in iterative
repair checks, three completed with no applicable data, one unresolved
(VirusTotal domain-to-URL). This is not repeated final-version certification.
VirusTotal pagination remains partial and official API fallbacks remain untested
without credentials. OTX domain-to-URL pagination has a verified two-page UI test.

[CTI_REPORT_LOOKUP_TEST.md](CTI_REPORT_LOOKUP_TEST.md) records extraction from
dataset row 670 (MageCart), selecting `mypiltow.com`, and running all eight
domain-input methods. It produced 29 distinct validated IPv4 outputs across
sources; there is no persisted investigation graph or Algorithm 1 reward yet.
Raw bodies, receipts and report context are linked in that document.

## Local commands

Workspace: `D:\SEMESTERS\FYP\code`; run these from `ioc-hunter` in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m ioc_hunter --help
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Live tests are opt-in and need provider network access. Preserve existing audit
outputs; use a new output directory for reruns. No provider credentials or
authenticated browser state were used in the reported repair checks.

Suggested fresh-chat instruction:

> Read ioc-hunter/WORKFLOW_HANDOFF.md, METHODS_TODO.md and
> WORKFLOW_IMPLEMENTATION_PLAN.md. Implement the first complete offline manual
> workflow, keeping extraction, lookup, validation and algorithm policy separate.
> Preserve the existing interfaces and evidence. Verify persistence, resume and
> export before moving to a bounded live demonstration.
