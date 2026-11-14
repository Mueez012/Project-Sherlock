# Hybrid Analysis implementation plan

Final 10 November checkpoint: this plan's code and the additional five OTX
methods are implemented; 445 tests and 252 subtests passed. See
[the verification report](METHODS_VERIFICATION_20261110.md) for actual live
successes, the fixed script-readiness defect and remaining HA access/search gaps.
Earlier deferred-testing statements below describe the planning checkpoint.

Date: **10 November 2026**. Status: **authorized batch coded; testing deferred**.
The user authorized eight HA methods and eight original candidates, then asked
for discussion of five more original candidates before tests. See
[the implementation checkpoint](SIXTEEN_METHODS_IMPLEMENTATION.md) for actual
code, source-access gaps and deferred verification. The design below preserves
the proposal and does not claim live success.

## Objective and retained scope

Add Hybrid Analysis as an additional provider in `dev/Project-Sherlock/services/ioc`.
Preserve the existing VirusTotal provider, implemented methods and unimplemented
candidates. Focus this batch on HA; keep its source identity distinct from VT.
Use the strict existing ontology and public `IOC -> list[IOC]` interface.

Current catalogue: **27 implemented / 33 candidates / 60 total**.
Eight additional, fully implemented HA methods would yield **35 implemented /
33 original candidates / 68 total**. The three HA hash methods add provider
alternatives for existing directions; Registry supplies the new IOC family.

The expanded proposal also selects **eight of the 33 original candidates** below.
Completing those and all eight HA targets would yield **43 implemented /
25 original candidates / 68 total**. These are implementation targets, not a
claim that all acquisition paths have already passed live verification.

## Target methods and order

| Phase | Proposed method | Acquisition and extraction | Current dependency |
| --- | --- | --- | --- |
| Core | `hybridanalysis.md5_to_command_api` | Hash discovery/report navigation; extract recorded process command lines and explicit called API fields when present | Verify a positive hash navigation and completed report capture |
| Core | `hybridanalysis.sha1_to_command_api` | Same shared hash operation | Same |
| Core | `hybridanalysis.sha256_to_command_api` | Same shared hash operation | Same |
| Core | `hybridanalysis.filename_to_command_api` | Native filename search, then requested command/API fields from returned reports | Verify positive filename discovery with a suitable search time window |
| Core | `hybridanalysis.filename_to_registry` | Same filename discovery; extract recorded registry-operation fields | Same discovery; registry data already observed in a public report |
| Conditional | `hybridanalysis.filename_to_url` | Filename discovery; extract explicit file source/download URL observations | A suitable report field has not yet been observed |
| Conditional | `hybridanalysis.registry_to_filename` | Supported registry/content discovery; extract source-reported file names | Basic account/content discovery and usable source data |
| Conditional | `hybridanalysis.command_api_to_registry` | Discover reports, read actual called/executed command/API data and registry modifications for that file/report | Basic discovery and called-function/registry-change fields, not static strings alone |

All eight are implementation targets. A method becomes implemented only when a
functional acquisition operation, source parser and relevant tests exist. An
unresolved source route or absent output contract remains a candidate. The
implementation report will distinguish code completion, account configuration
and positive live validation.

## Additional eight original candidates proposed for confirmation

These methods reuse existing input routes and the bounded follow-up executor
already needed for HA. The lookup returns concrete source observations; the
workflow owns relationship admission. In particular, DNS-discovered addresses
must not be described as evidence of IP-to-IP communication.

| Order | Original method | Acquisition and extraction plan |
| --- | --- | --- |
| 1 | `rapiddns.ipv4_to_ipv4` | Existing reverse-IP lookup -> discovered domains -> existing domain DNS lookup; emit returned IPv4 addresses |
| 2 | `rapiddns.ipv4_to_ipv6` | Same discovery operation; emit returned IPv6 addresses |
| 3 | `rapiddns.ipv6_to_ipv4` | Existing IPv6 reverse-IP route -> domain DNS lookup; emit returned IPv4 addresses |
| 4 | `rapiddns.ipv6_to_ipv6` | Same discovery operation; emit returned IPv6 addresses |
| 5 | `rapiddns.url_to_domain` | Extract the URL hostname as query preparation, use the existing domain lookup, and emit domains actually returned in source rows |
| 6 | `alienvault.ipv4_to_ipv4` | Existing IP passive-DNS lookup -> discovered domains -> existing domain passive-DNS lookup; emit returned IPv4 addresses |
| 7 | `virustotal.ipv4_to_command_api` | IP report's communicating-files discovery -> existing shared file-behavior extraction; emit recorded commands/APIs |
| 8 | `virustotal.ipv4_to_ipv4` | Same file discovery -> recorded behavior network fields; emit concrete IPv4 observations |

The DNS routes already exist in the provider adapters. The composition, output
selection and method-correctness checks are new. Preserve the actual source
fields and query steps in evidence without adding graph-admission logic.
Exclude the starting IP from its own returned IP discoveries and deduplicate
repeated observations through the existing client behavior.

For URL input, hostname extraction is input preparation, not a source result.
Only provider-returned domain rows become outputs. Unsupported hostname inputs
and empty DNS results must have explicit outcomes.

The two VirusTotal targets need a fresh browser check of communicating-file
navigation and actual output fields before implementation is declared complete.
They do not depend on the deferred Intelligence filename/registry/command search
plan. An inaccessible discovery route remains an unresolved candidate; do not
claim the final 43/25 count solely because a parser or method declaration exists.

These eight original methods add lookup directions and provider coverage within
already covered IOC families. Registry coverage comes from the HA batch.

## 1. Confirm source contracts before wiring methods

Use the [saved research](HYBRID_ANALYSIS_RESEARCH.md) and fresh read-only browser
observations to establish:

- Positive MD5, SHA-1 and SHA-256 navigation for a known existing report.
- Positive filename search, including a date window that contains the positive
  control. The old default last-hour empty search is not sufficient evidence.
- Request method, page-generated response path, query/body parameters and
  pagination controls. Capture only the fields needed for query binding; do not
  export authentication or CSRF tokens.
- Completed sample-page structure, actual report data and access/error states.
- Whether Basic-account methods can run with the available session. Anonymous,
  Basic and Vetted access must remain distinct.

Read existing reports only. No file/URL analysis submission, sample download or
account creation is part of this plan. Normal browser session support may use
the existing configured storage state; live access must be tested rather than
inferred from a state file or API-key presence.

## 2. Add the complete source adapter

Proposed source-local modules:

| File | Responsibility |
| --- | --- |
| `ioc_hunter/providers/hybridanalysis.py` | Source metadata, explicit method declarations, operations, request construction and parser dispatch |
| `ioc_hunter/providers/ha_search.py` | Escaped HAQL query construction and parsing search results into concrete fields/report references |
| `ioc_hunter/providers/ha_report.py` | Parse completed HTML/report data and extract commands, registry entries, filenames and supported URLs |

Register the provider through `providers/__init__.py` and add its exact allowed
hosts in `transport/models.py`. Reuse the current credential discovery,
source-scoped pacing/budgets, cache isolation, evidence store and entry points.
Configure optional API access only for verified routes and actual privileges.

Keep planned HA entries explicit. Do not add a broad inventory to `SOURCE_TYPES`
that generates speculative Cartesian method pairs. If all eight are introduced
as candidates first, the intermediate catalogue is 27 implemented / 41
candidates / 68 total; implementing the core five changes it to 32 / 36 / 68.
All eight completed gives 35 / 33 / 68.

## 3. Implement HA transport integration using shared execution

HA's current search page loads search JSON, while the sample page includes
server-rendered report data. Both need deliberate support.

- Add an optional provider-declared HTML capture mode and completed-page
  readiness marker to the shared request/browser contract. Check readiness in
  the normal polling loop; do not wait for the old DNS-table timeout heuristic.
- Preserve current behavior for all existing provider requests by default.
- Strengthen search-response matching for the actual query and, if relevant,
  request-body fields. Matching a generic search path alone is insufficient.
- Let the normal browser execute the site's requests and session handling.
  Page-generated POST searches do not require direct private-endpoint calls.
- Add shared HTTP request-method/body support only if a verified, authorized
  API route actually needs it. Include those request properties in cache and
  replay identities if introduced.
- Reuse the existing response-size limits, provider-host checks, redirect
  handling, source pacing, budgets and error categories.

This is complete HA-specific acquisition support built on the existing network
engines, rather than a second transport engine or nested provider HTTP client.

## 4. Parse source data without executing source code

The captured HA sample page contains a structured `initialData` report object in
escaped server-rendered fragments. Its observed schema includes metadata,
activity, detections and report identifiers.

Use source-local, JSON-only decoding of those known fragments, in document
order, or stable completed DOM fields where appropriate. Do not evaluate the
page's JavaScript or build a general application-framework parser. Test split
fragments, quoted strings and referenced values against the captured source.
Malformed or incomplete report data must not become a successful empty result.
Unresolved rendering references, such as `$4f`, must never become IOC values.
Prefer the observed plain structured fields for the core methods; resolve
referenced text only when a conditional method actually requires it.

Extract concrete values through the existing ObservationBuilder and IOC models:

- Commands: recorded command lines and explicit called API fields where present.
- Registry: concrete source-listed operation paths/keys, preserving source scope.
- Filenames: names provided by returned results/reports.
- URLs: the explicitly supported file-source/download fields, when established.

No extra exact-filename equality gate, API-name whitelist, ownership scoring or
confidence filter is introduced. Retain ordinary query, report, source-field and
format correctness checks. A static imported API or raw content string is not
relabeled as a runtime call.

For command/API-to-registry, follow the user's definition: the file/report
records the supplied command/API as called/executed and records registry changes.
Do not introduce a universal per-call causal, handle-resolution or PID-tracing
framework. Do not claim a specific call caused a particular key change unless
the source actually says so.

## 5. Support bounded search-to-report follow-ups

The current `requests_for()` list contains fallback alternatives, and
`ParsedPage.next_url` means same-operation pagination. Neither should be reused
as an implicit dependency chain.

Add a small optional follow-up acquisition contract beside ParsedPage. The
source parser returns report references and the minimum context needed for the
next extraction. LookupClient executes those requests through its existing
`_fetch()` and snapshot path. Provider parsers remain network-free.

The executor must:

- Bound search pages, followed reports and total acquisitions.
- Reuse existing fallback, retry, pacing, cache and output-limit mechanisms.
- Capture every acquired response in the normal receipt.
- Preserve successful outputs if a later report fails, with an explicit partial
  outcome; distinguish discovery failure from completed no-data results.
- Keep search pagination, required report reads and transport fallbacks separate.
- Preserve old receipts and replay fixtures. Add optional fields only when the
  concrete implementation needs them; do not add an alias ledger or graph store.

Search results that already contain the requested output fields can emit them
directly. Report reads are needed only for missing destination data.

## 6. Integrate with existing lookup and workflow boundaries

Add narrowly scoped method/source field checks to `validate_edge()` for the new
facts. This function remains in LookupClient as a method-correctness guard.
The workflow continues to own its overlap gate, graph updates and recovery.

Keep initial CTI-text extraction separate from provider-response extraction.
The new HA helpers introduce lookup outputs; they do not silently add arbitrary
command/registry/filename recognition to the report-text extractor.

Extend existing method discovery, CLI/API availability, offline replay and live
audit inputs to support HA and filename/registry/command examples. Mark HA
methods as additions beyond Table I and update the catalogue generator's current
IPv6-only wording for that flag. The ontology's entity pairs remain unchanged.

## 7. Verification and deliverables

Required verification:

1. Captured search/HTML/report parser fixtures with source provenance.
2. Positive, empty, malformed, incomplete, login-required and restricted-field
   cases; search date-window and query-binding checks.
3. Bounded multi-report acquisition, pacing, cache isolation, partial failures,
   deduplication and immutable receipts.
4. Offline saved-workflow replay, including outputs retained separately from
   graph admission and save/reopen/export compatibility.
5. Regression coverage for the existing OTX, RapidDNS and VirusTotal methods.
6. Fresh live checks with `cache_ttl=0`, fresh browser contexts and inspectable
   source responses. Offline passing tests and live successes remain separate.

Deliver the adapter, transport integration, source parsers, supported methods,
tests/fixtures and a dated live verification report. Update the research,
foundation, implementation map, README and generated catalogue with actual
completion/access results. Report any conditional method that remains unresolved
instead of representing it as working to meet the numerical target.

Implementation of the sixteen-method batch was authorized and is now coded.
Further implementation and testing await the requested five-method discussion.
