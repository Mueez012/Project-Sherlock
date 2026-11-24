# Hybrid Analysis provider research

Latest implementation/testing: [10 November report](METHODS_VERIFICATION_20261110.md).
The report records an uncached SHA-256 success after fixing script readiness;
historical search and account-dependent directions remain unverified live.
The source observations below retain their original research dates.

Reviewed: **9 November 2026**. The observations below predate implementation.
10 November: eight HA methods now have code and are registered; testing is
deferred. See [the implementation checkpoint](SIXTEEN_METHODS_IMPLEMENTATION.md).

## Finding

Hybrid Analysis is a useful additional provider for the strict paper ontology,
especially native filename/hash discovery followed by existing public sample
reports. It is not an unrestricted anonymous substitute for every advanced
VirusTotal search. The live documentation distinguishes Free, Basic and Vetted
access, and the current API differs from older `/api/v2` examples.

The [31 August 2026 release announcement](https://hybrid-analysis.blogspot.com/2026/08/hybrid-analysis-reengineered.html)
describes HAQL, unified sample overviews and retained sandbox analysis. Current
[search documentation](https://hybrid-analysis.com/docs) and the
[FAQ](https://hybrid-analysis.com/faq) were inspected through a fresh browser.
The FAQ warns that some articles are being updated; the live field catalogue is
the stronger evidence for current search-field permissions.

## Actual observations

No accounts were created, no samples or URLs submitted, no samples downloaded,
and no API keys were used. Each observation used a fresh anonymous context.

| Observation | Evidence |
| --- | --- |
| Public home and current HAQL documentation loaded | [First observation](output/research-hybrid-analysis/20261109T183103Z/home/metadata.json) |
| The documentation loaded an 86-field catalogue for tier `free` | [Rendered documentation](output/research-hybrid-analysis/20261109T183103Z/docs/metadata.json), [actual field catalogue](output/research-hybrid-analysis/20261109T183103Z/docs/raw-02.json) |
| An existing public sample report loaded anonymously | [Report observation](output/research-hybrid-analysis/20261109T183103Z/sample/metadata.json), [source HTML](output/research-hybrid-analysis/20261109T183103Z/sample/page.html) |
| Current account tiers and restricted public API were described in the FAQ | [FAQ capture](output/research-hybrid-analysis/20261109T183353Z/faq/metadata.json) |
| An initial filename search returned no results with the UI showing its default last-hour window | [Initial search](output/research-hybrid-analysis/20261109T183750Z/filename-search/metadata.json) |

The old sample is historical, so the initial default-window search is not a
valid positive control or a demonstration that filename search is unsupported.
The [follow-up time-control observation](output/research-hybrid-analysis/20261109T184026Z/filename-search/metadata.json)
also remained on the last-hour view and returned no records. There is therefore
no positive end-to-end filename-discovery claim from these observations. Free
filename search is established by the current field catalogue, while successful
discovery still needs a suitable positive control and applicable time window.

## Search access

The [live field catalogue](output/research-hybrid-analysis/20261109T183103Z/docs/raw-02.json)
reported the following permissions:

| Capability | Current tier | Consequence |
| --- | --- | --- |
| `name`, `filename`, MD5, SHA-1, SHA-256 | Free | Best discovery inputs for the first provider operations |
| File type/size, first/last seen, verdict, score | Free | Optional query filters, not additional IOC relationships |
| Raw-byte `content`, `content_fuzzy`, YARA | Basic | Requires a registered account; a string hit is not an observed runtime call |
| IP/domain/URL, contacted hosts/domains, DNS and artifact network fields | Vetted | Do not advertise as anonymous search routes |
| Generic `sandbox_reports`, imported DLL and behavior-tag search | Vetted | Does not establish support for arbitrary nested registry/API queries |
| Dedicated command/API, registry-key, port/protocol or CVE input fields | Not present in the 86-field catalogue | Need another supported discovery route; do not invent field names |

The current FAQ describes Free as anonymous, Basic as a free registered account
awaiting vetting, and Vetted as approved registered users. Vetting is not
described as purchasing a premium plan. Registered users can generate a
restricted public API key. This does not mean every endpoint or detailed trace
is available to that key. The official
[current MCP project](https://github.com/hybrid-analysis/hybrid-analysis-mcp-server)
confirms keyed integration and quota validation; this project does not require
using that MCP server.

## Report data actually observed

The existing public sample from the release announcement was
`2e7aa640b2da6d9350afba1b8ad0b65bc85ac335dde42f08cd540da8580e2a78`.
Its source page included:

- A filename and all three supported file hashes.
- A process command line, process name, PID/PPID, path, UID and executable hash.
- Registry changes, including 46 created-key entries attributed to a sandbox
  report. Some source paths contain duplicated hive prefixes and need careful
  formatting treatment rather than invented replacements.
- Written file paths, extracted file names/hashes and DNS/embedded domains.
- Behavioral indicators and report/source identifiers.

This sample did not establish a runtime API-function call list, per-call registry
arguments, concrete port/protocol values, resolved DNS IP tuples or CVE output.
Its contacted-host and HTTP-request activity fields were empty. Those absences
are limitations of the inspected sample, not universal platform limitations.

The field catalogue governs search/projection permissions. It does not imply
that every public sample's detailed page is inaccessible: this report supplied
activity data in its page response. Conversely, reading one report does not
prove arbitrary reverse-search access.

## Proposed method shortlist

| Proposed provider method | Priority / prerequisite |
| --- | --- |
| `hybridanalysis.md5_to_command_api` | First group: Free hash discovery, explicit observed command-line extraction |
| `hybridanalysis.sha1_to_command_api` | Same shared operation |
| `hybridanalysis.sha256_to_command_api` | Same shared operation |
| `hybridanalysis.filename_to_command_api` | First group: native filename search, then commands/APIs actually present in returned reports |
| `hybridanalysis.filename_to_registry` | First group: native filename search, then concrete registry-operation fields |
| `hybridanalysis.filename_to_url` | Conditional: find explicit source/download URL data; an arbitrary contacted URL is insufficient to define this scope |
| `hybridanalysis.registry_to_filename` | Conditional: Basic content or another verified registry discovery route, then source-reported filenames |
| `hybridanalysis.command_api_to_registry` | Conditional: supported discovery, the supplied command/API actually called/executed in the returned file report, and registry modifications recorded for that file/report |

The last method follows the user's stated definition: find a file that called
the specific command/API and changed registry data, then extract those registry
IOCs. It does not require a new universal process-trace or handle-resolution
framework. A static imported name or raw-byte string alone is not evidence of a
runtime call. An API-to-specific-key causal mapping must not be claimed when the
source only supplies file/report-level observations. Existing workflow admission
remains separate from extraction.

The two strongest new directions are filename-to-command/API and
filename-to-registry. The three hash methods are optional alternative-provider
routes for functionality already present in VirusTotal; they should not be
presented as new ontology coverage. The other three directions remain
conditional, rather than eight methods certified ready for implementation.

No exact filename equality gate, API-name whitelist, ownership scoring or
confidence filter is proposed. Search result references are navigation handles,
and ordinary source excerpts/receipts identify where each extracted value came
from.

## Broader candidates

Network report sections also warrant research for domain-to-URL, URL-to-domain,
IP-to-domain, command/API-to-IP/port and port-to-protocol. Native network-input
search currently requires Vetted access, and usable network tuples or command
fields still need actual report examples. No standalone protocol-input or CVE
search operation was established. Generic IOC-looking numbers, static imports
and independent aggregate lists should not be relabelled as observed events.

The strict ontology remains unchanged. Hash-to-registry, hash-to-IP and
filename-to-hash can be internal acquisition steps where useful, but are not new
public methods under the current ontology.

## Modularity and counting

A future adapter would use `providers/hybridanalysis.py`, small source-local
parsers, the existing browser/HTTP transports, shared LookupClient execution,
ObservationBuilder, receipts and workflow. Required search-to-report follow-ups
need a bounded shared execution extension; fallback routes and pagination remain
different concepts. Any POST search support must be distinguished from sample
submission, since the current HTTP transport is GET-only.

The catalogue currently has **27 implemented / 33 candidates / 60 total**.
Method IDs include the provider. Adding eight HA methods without retiring any
original source-specific entries yields **35 implemented / 33 candidates / 68
total**, not 35/25/60. The first three proposed hash methods are provider
alternatives for existing directions, not new ontology-family coverage.
Replanning the original catalogue around replacement providers would need to be
recorded explicitly; HA output must not be labelled as a VirusTotal method.
