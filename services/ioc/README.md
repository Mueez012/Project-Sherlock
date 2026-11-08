# IOC Hunter

Submit a report, inspect extracted IOCs, choose a lookup method and save the
resulting investigation from the terminal. The workflow persists report context,
validated observations, graph admission decisions, evidence and resumable steps.
See the [terminal workflow guide](WORKFLOW_GUIDE.md) for a complete offline example.

The [saved investigation API guide](API_GUIDE.md) describes the implemented HTTP
routes, shared terminal/backend service, native sentence identity and common
store. There are no users or login.

Selection is manual. Graph admission uses Algorithm 1's candidate-overlap
condition; automatic ranking, coverage/tried counters, LLM selection, SecureBERT
encoding and frontend investigation controls remain future work. Existing methods
still take an `IOC` and return `list[IOC]`.

See the [repair verification results](METHOD_RELIABILITY_RESULTS.md): 17 of 21
methods returned validated outputs during the repair checks, three completed with
no applicable data, and VirusTotal domain-to-URL remains unresolved. Raw responses and intermediate
failures are linked there. The [13 October audit](LIVE_METHODS_AUDIT.md) retains
the earlier baseline.

The paper's report-page routes remain primary; official APIs are optional
fallbacks. See the [provider implementation guide](PROVIDER_IMPLEMENTATION_GUIDE.md)
for future methods and the [repair plan](METHOD_RELIABILITY_REPAIR_PLAN.md) for
the roadmap and remaining pagination/access work.

The [real CTI report test](CTI_REPORT_LOOKUP_TEST.md) passes an IOC extracted from
a MageCart report to all eight domain-input methods. It returned 29 distinct
validated IPv4 outputs, with the report context and raw evidence retained.

Future enrichment sprints are tracked in [the methods backlog](METHODS_TODO.md).
For the current implementation boundary and next steps, start with
[the workflow handoff](WORKFLOW_HANDOFF.md).

The [IOC inclusion reference](IOC_INCLUSION_REFERENCE.md) records our settled
reading of the paper's batch-admission rule and the observed workflow behavior.
The separate [algorithm improvement research](ALGORITHM_IMPROVEMENT_RESEARCH.md)
compares prior work and proposes an experimental extension; it does not describe
an implemented policy change.

## Setup and commands

Run from `dev/Project-Sherlock/services/ioc`. In the current Windows workspace,
reuse the existing environment while importing this service checkout:

```powershell
$env:PYTHONPATH = (Get-Location).Path
$iocPython = 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe'
& $iocPython -m ioc_hunter --help
```

For a separate environment, install the service and its optional dependencies:

```powershell
python -m venv .venv
$iocPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
& $iocPython -m pip install -e ".[extraction,browser,mcp]"
& $iocPython -m playwright install chromium --only-shell
```

For WSL, run the setup from the repository root using the Linux environment:

```bash
cd /mnt/d/SEMESTERS/FYP/dev/Project-Sherlock
uv pip install --python .venv/bin/python -e './services/ioc[extraction,browser]'
.venv/bin/python -m playwright install --with-deps chromium --only-shell
```

Playwright's Python package and its browser executable are separate installations.
The browser must match the Playwright version in this Linux environment; a
Windows installation does not supply the WSL executable. `--with-deps` also
installs required Linux libraries and can request sudo. After installing or
upgrading Playwright, use that same interpreter for its browser installation.

This offline launch check verifies the browser runtime without contacting a provider:

```bash
.venv/bin/python -c 'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(headless=True); print("Chromium launch OK"); b.close(); p.stop()'
```

New lookup receipts identify missing browser binaries as `browser_binary_missing`
and missing system libraries as `browser_dependencies_missing`. Existing receipts
remain unchanged, including older generic `browser_error` messages. Resume an
open investigation and select a method again to create a new attempt after fixing
the runtime.

Start the synthetic offline investigation:

```powershell
& $iocPython -m ioc_hunter investigate examples/manual-workflow/report.txt --mode replay --replay examples/manual-workflow/replay.json --store output/demo
```

Choose `example.com`, then `rapiddns.domain_to_ipv4`. The fixture includes a
known unused address, a new address and a subdomain mismatch so the result shows
graph additions and a rejected relationship. Enter `back`, then `save` to leave
the investigation resumable. These fixtures do not represent a live incident.

Extract a UTF-8 text report without terminal prompts:

```powershell
& $iocPython -m ioc_hunter extract report.txt
```

The result includes original and retained text, excluded sections, sentences,
matches and IOC objects. The default seven types are unchanged; use
`--extended-types` for email/CVE and `--include-references` to retain reference
sections. The existing interactive CSV/XLSX review still works:

```powershell
& $iocPython -m ioc_hunter.interactive_extraction --row 1
```

Inspect methods, run a lookup, and inspect its receipt:

```powershell
& $iocPython -m ioc_hunter methods --implemented --availability
& $iocPython -m ioc_hunter methods --candidates
& $iocPython -m ioc_hunter lookup example.com --type domain --method rapiddns.domain_to_ipv4
& $iocPython -m ioc_hunter evidence LOOKUP_ID
```

`--availability` reports local configuration, not a live connectivity test.
Provider credentials use `OTX_API_KEY` and `VT_API_KEY`; they are optional and do
not guarantee access to every provider feature. Source routes remain website-first.

Lookup output is a JSON list; the lookup ID and retrieval status go to stderr.
Use `--store DIRECTORY` on both lookup and evidence commands to choose a separate
store. One-call lookup defaults to `output/lookups/lookups.sqlite3`; investigations
default to `output/investigations/lookups.sqlite3`. Use the same `--store` when
resuming, listing or exporting an investigation. Existing receipts and snapshots
remain readable. See [lookup details](LOOKUP_FOUNDATION.md) for
cache, partial results, source access and evidence limitations.

## Code map

```text
main.py                         CLI arguments and service invocation
__main__.py                     python -m ioc_hunter compatibility entry point
extraction/pipeline.py          Non-interactive extraction and reusable stages
extraction/datasets.py          CSV/XLSX report loading
interactive_extraction.py       Existing step-by-step console presentation
workflow/runner.py             Report ingestion, selected steps, recovery and export
workflow/repository.py         Versioned SQLite runs, steps, nodes and edges
workflow/policies.py           Paper candidate-overlap graph admission
workflow/replay.py             Explicit offline fixture transport
workflow/terminal.py           Interactive IOC/method and evidence inspection
workflow/models.py             Workflow limits and stable graph identities
providers/rapiddns.py           RapidDNS methods, request routes, result mapping
providers/alienvault.py         OTX methods, request routes, result mapping
providers/virustotal.py         VirusTotal methods, request routes, result mapping
providers/common.py            Shared field parsing and evidence construction
providers/base.py              Provider interface and ParsedPage
methods.py                     Collect supported definitions and expose discovery
method_candidates.py           Unconfirmed ontology-compatible research candidates
method_spec.py                 Shared method metadata, without registry dependencies
transport/http.py              HTTP retrieval
transport/browser.py           Playwright retrieval and response capture
transport/limits.py            Source pacing/cooldowns
transport/models.py            Request/response types, errors and host restrictions
lookup.py                      Cache -> retrieve -> parse -> validate -> return list
validation.py                  Independent relationship checks and explanations
storage.py                     Immutable receipts, snapshots, cache and budgets
models.py / ontology.py         IOC identity and allowed type connections
evidence.py / context.py        Evidence records and optional cited LLM context
metadata.py                    Extraction of explicitly labelled metadata fields
config.py                      Default paths and credential environment settings
mcp_server.py                  Optional MCP interface over the same Python services
```

Provider modules own `METHODS`, `requests_for()` and `parse_document()`. Their
shared helpers contain no source-selection branches. The public imports from
`ioc_hunter.providers`, `ioc_hunter.transport` and `ioc_hunter.methods` continue
to work. `interactive_extraction` re-exports its original extraction helpers.

## Python use

```python
from ioc_hunter import extract_report, LookupClient, list_runnable_methods

extracted = extract_report("The report names example.com.", source="report-1")
client = LookupClient()
domains = [ioc for ioc in extracted.iocs if ioc.type == "domain"]
if domains:
    # This call uses live provider transports.
    receipt = client.lookup_detailed(domains[0], "rapiddns.domain_to_ipv4")
    outputs = receipt.outputs
    lookup_id = receipt.id
    accepted_relationships = receipt.accepted
```

`extract_report()` does not print, prompt, query providers or modify a graph.
Pass `nlp=create_sentencizer()` from `ioc_hunter.extraction` to reuse a sentence
processor across reports. `lookup_detailed()` returns the exact call's receipt,
including accepted evidence associations; no subsequent "latest" query is needed.
`lookup()` and `client.method(...)(ioc)` retain their `list[IOC]` interface.
For saved investigations, use `WorkflowRunner` through the CLI or Python; see
[the workflow guide](WORKFLOW_GUIDE.md).

## Validation messages

New rejected candidates include a machine-readable `reason`, a plain-language
`message`, structured `details` and their evidence ID. For example:

```json
{
  "reason": "dns_domain_mismatch",
  "message": "Expected DNS evidence for example.com, but this record belongs to www.example.com.",
  "details": {"expected_domain": "example.com", "observed_domain": "www.example.com"}
}
```

This rejects the proposed connection, not the IP's validity. Older receipts can
still contain `relationship_not_supported_by_fields`; they are not rewritten.
Acceptance rules and the strict ontology are unchanged.

## Extending and checking the code

To add a provider:

1. Add a source module with `source`, `PRIMARY_TRANSPORT`, `API_KEY_ENV`, explicit
   `METHODS`, `requests_for()` and `parse_document()` matching `providers.base.Provider`.
2. Register the module in `providers/__init__.py`, and its allowed HTTPS hosts in
   `transport/models.py`. Source locks and credential discovery use that registry.
3. Return `ParsedPage` observations with source field evidence; reuse shared
   parsing helpers where they fit. Add explicit handling for any new access route.
4. Cover valid, unrelated, malformed, empty and partial responses with fixtures.
   Label synthetic fixtures clearly. Live checks stay opt-in.

For a new relationship proof, add a deterministic branch to `validate_edge()`
using trusted parser fields and ontology membership. Supply rejection messages
and details, plus positive and conflicting-evidence tests. Do not make the
validator query providers, ask an LLM, update a graph or evaluate expansion reward.

The existing workspace environment includes pytest. For a separate test
environment, install `pytest` and the optional `api` dependencies to run the HTTP
tests as well:

```powershell
& $iocPython -m pip install pytest ".[api]"
& $iocPython -W ignore::DeprecationWarning -m pytest tests
& $iocPython tools/generate_catalogue.py
& $iocPython tests/live_lookup_smoke.py rapiddns
```

The installation command is only needed when preparing that separate test
environment. The last command contacts a provider; the test suite uses
fixtures/intercepted browser requests. Browser and MCP tests need their optional
dependencies. Use pytest for the complete suite: unittest discovery alone does
not execute the pytest-style workflow and HTTP tests.

See [generated method catalogue](ONTOLOGY_METHODS.md),
[organization plan](CODEBASE_ORGANIZATION_PLAN.md) and
[historical workflow plan](WORKFLOW_IMPLEMENTATION_PLAN.md).
