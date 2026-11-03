# IOC Hunter

Report IOC extraction and evidence-validated enrichment. Methods take an `IOC`
and return `list[IOC]`. Algorithm 1, a persistent investigation graph and the
complete web workflow are planned, not implemented here yet.

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
For the next implementation session, start with [the workflow handoff](WORKFLOW_HANDOFF.md).

## Setup and commands

Run from `ioc-hunter` using its Python environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[extraction,browser,mcp]"
.\.venv\Scripts\python.exe -m playwright install chromium --only-shell
.\.venv\Scripts\python.exe -m ioc_hunter --help
```

Extract a UTF-8 text report without terminal prompts:

```powershell
.\.venv\Scripts\python.exe -m ioc_hunter extract report.txt
```

The result includes original and retained text, excluded sections, sentences,
matches and IOC objects. The default seven types are unchanged; use
`--extended-types` for email/CVE and `--include-references` to retain reference
sections. The existing interactive CSV/XLSX review still works:

```powershell
.\.venv\Scripts\python.exe -m ioc_hunter.interactive_extraction --row 1
```

Inspect methods, run a lookup, and inspect its receipt:

```powershell
.\.venv\Scripts\python.exe -m ioc_hunter methods --implemented --availability
.\.venv\Scripts\python.exe -m ioc_hunter methods --candidates
.\.venv\Scripts\python.exe -m ioc_hunter lookup example.com --type domain --method rapiddns.domain_to_ipv4
.\.venv\Scripts\python.exe -m ioc_hunter evidence LOOKUP_ID
```

`--availability` reports local configuration, not a live connectivity test.
Provider credentials use `OTX_API_KEY` and `VT_API_KEY`; they are optional and do
not guarantee access to every provider feature. Source routes remain website-first.

Lookup output is a JSON list; the lookup ID and retrieval status go to stderr.
Use `--store DIRECTORY` on both lookup and evidence commands to choose a separate
store. Default storage remains `output/lookups/lookups.sqlite3`. Existing receipts
and snapshots remain readable. See [lookup details](LOOKUP_FOUNDATION.md) for
cache, partial results, source access and evidence limitations.

## Code map

```text
main.py                         CLI arguments and service invocation
__main__.py                     python -m ioc_hunter compatibility entry point
extraction/pipeline.py          Non-interactive extraction and reusable stages
extraction/datasets.py          CSV/XLSX report loading
interactive_extraction.py       Existing step-by-step console presentation
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
    outputs = client.method("rapiddns.domain_to_ipv4")(domains[0])
    receipt = client.latest_record(domains[0], "rapiddns.domain_to_ipv4")
```

`extract_report()` does not print, prompt, query providers or modify a graph.
Pass `nlp=create_sentencizer()` from `ioc_hunter.extraction` to reuse a sentence
processor across reports. There is no complete-run command yet; the example
shows the available service boundary for the next workflow milestone.

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

```powershell
.\.venv\Scripts\python.exe -W ignore::DeprecationWarning -m unittest discover -s tests
.\.venv\Scripts\python.exe tools/generate_catalogue.py
.\.venv\Scripts\python.exe tests/live_lookup_smoke.py rapiddns
```

The last command contacts a provider; the test suite uses fixtures/intercepted
browser requests. Browser and MCP tests need their optional dependencies.

See [generated method catalogue](ONTOLOGY_METHODS.md),
[organization plan](CODEBASE_ORGANIZATION_PLAN.md) and
[next workflow plan](WORKFLOW_IMPLEMENTATION_PLAN.md).
