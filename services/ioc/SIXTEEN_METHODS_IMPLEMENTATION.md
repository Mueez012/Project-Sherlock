# Sixteen-method implementation checkpoint

Superseded by [the final verification report](METHODS_VERIFICATION_20261110.md):
the additional five OTX methods are now implemented; counts are 48/20/68, with
445 tests and 252 subtests passed. The earlier paused-testing checkpoint below
is retained as history. Full live coverage remains limited by source access.

Date: **10 November 2026**. Status: **code added; testing deferred at the user's request**.

Eight HA methods plus eight original catalogue candidates now have acquisition
and parser code: **43 implemented / 25 disabled candidates / 68 total**.
Implemented does not mean tested or live verified. The prior 307-test result
predates this batch and does not validate these changes.

## Methods

| Methods | Acquisition and extraction |
| --- | --- |
| `hybridanalysis.md5_to_command_api`, `hybridanalysis.sha1_to_command_api`, `hybridanalysis.sha256_to_command_api` | Native hash search or direct SHA-256 sample navigation; recorded process commands/names and explicit runtime call fields |
| `hybridanalysis.filename_to_command_api` | Filename search -> reports -> commands/APIs |
| `hybridanalysis.filename_to_registry` | Same discovery -> registry creation/modification/deletion observations |
| `hybridanalysis.filename_to_url` | Same discovery -> explicit recorded HTTP URLs or labelled source/download URLs; no command-string/arbitrary-link mining |
| `hybridanalysis.registry_to_filename` | Native content search -> source-reported sample filename |
| `hybridanalysis.command_api_to_registry` | Content discovery; require actual runtime command/API observation in that report, then return its recorded registry modifications |
| `rapiddns.ipv4_to_ipv4`, `rapiddns.ipv4_to_ipv6`, `rapiddns.ipv6_to_ipv4`, `rapiddns.ipv6_to_ipv6` | Existing reverse-IP lookup -> domains -> existing domain DNS lookup -> other addresses of the selected type |
| `rapiddns.url_to_domain` | URL hostname prepares the existing domain query; only domains in source DNS rows become outputs |
| `alienvault.ipv4_to_ipv4` | Existing OTX IP passive DNS -> domains -> domain passive DNS -> other IPv4 addresses |
| `virustotal.ipv4_to_command_api`, `virustotal.ipv4_to_ipv4` | IP communicating files -> existing file-behavior operation -> commands/APIs or structured network addresses |

New source helpers are `providers/hybridanalysis.py`, `ha_search.py`,
`ha_report.py`, `dns_discovery.py` and `vt_network.py`. The existing adapters own
their declarations/routes/dispatch; common observation emission remains shared.

## Shared execution and boundaries

`ParsedPage.followups` describes required source reads. `FollowUp` accepts
explicit source navigation or a typed source operation. LookupClient resolves
typed operations with configured credentials, preserving existing API backups
without passing secrets into parsers. Parsers remain network-free.

LookupClient retains pacing, retries, cache, snapshots, receipts and output
assembly. Transport alternatives, pagination and required report reads remain
separate. Terminal source blocks stop queued reads while retaining gathered
outputs. Nonterminal report failures after discovery produce a partial result
with `followup_failed` and retain any successful outputs.

`max_pages` is a **per-stage pagination limit**. `max_followups=10` permits ten
additional stages: with the default five pages, up to 55 successfully parsed
pages, plus alternatives/retries. Daily budgets still apply. Limits produce
partial receipts. Cache identities include stage and response/readiness fields.

BrowserTransport supports provider-declared HTML readiness, including attached
data scripts, plus optional method/query/body response binding. HA uses rendered
search HTML because its request body was not captured; no private POST contract
was invented. Reports are decoded as JSON text without evaluating scripts.

`validate_edge()` checks method/source/query/output-field correctness. Workflow
graph admission is unchanged. DNS co-resolution returns discovery data without
claiming IP communication. Hash variants share operations; no hash-alias ledger,
API-name whitelist or filename/report equality investigation was introduced.

## Gaps requiring the deferred checks

| Area | Current limit |
| --- | --- |
| HA search time window | Saved searches defaulted to Last 1 hour. Limited/unknown coverage is partial. Historical hash/filename discovery still needs a suitable working window and positive control. |
| HA registry/command discovery | Content search requires Basic-account access. Existing browser storage state can be supplied; no account is created and entitlement is not assumed. |
| HA runtime APIs | Process commands/names and registry fields were observed. Optional per-process API-call fields have no saved positive. Static imports/raw-content hits are not runtime calls. |
| HA filename -> URL | The saved sample has no positive explicit HTTP/source/download URL. Parser support lacks a real positive output example. |
| VT communicating files | The relationship is documented; the new browser discovery and end-to-end outputs remain live-unverified. |
| DNS composition | Existing routes are the baseline. The new multi-stage methods have not been executed. |

Research captures predate production implementation; see
`HYBRID_ANALYSIS_RESEARCH.md`. They are not executions of these methods.

## Testing handoff

Regression sources are prepared for HA, DNS, shared follow-ups and VT IP
behavior. Captured and synthetic data are distinguished. Existing catalogue
expectations are updated to 43/25/68. The live audit accepts filename, registry
and command inputs, source-specific HA hashes, existing browser state and a
follow-up cap. It keeps **cache_ttl=0** and a fresh context for each lookup.

**No tests, replay runs, compilation checks or live lookups have run for this
batch.** Catalogue generation is documentation output, not verification.
The user requested a discussion of five more methods **from the original 25**
before testing. Those five are not approved or implemented. After that decision,
run the agreed checks on everything implemented and report route/access gaps
separately from parser/regression results.

## Five original candidates for the next discussion

The user rejected advanced-search-dependent additions. The replacement
selection is five ordinary OTX pulse-discovery methods:
`alienvault.email_to_domain`, `alienvault.email_to_email`,
`alienvault.geo_location_to_ipv4`, `alienvault.port_to_protocol` and
`alienvault.protocol_to_port`. See [the replacement plan](ADDITIONAL_FIVE_METHODS_PLAN.md)
for actual extraction scope, URL-only port/protocol coverage and unverified
browser access. These are selected for discussion, not implemented. Tests stay
paused. Counts remain 43/25/68; completion would give 48/20/68.

### Superseded VT shortlist, retained as deferred work

The most reusable next five share VT discovery and the new follow-up mechanism:

| Candidate | Additional work |
| --- | --- |
| `virustotal.filename_to_command_api` | Filename discovery -> existing file-behavior command extraction |
| `virustotal.filename_to_registry` | Same discovery -> new small registry-field parser |
| `virustotal.command_api_to_md5` | Command/behavior discovery -> explicit returned file hash metadata |
| `virustotal.command_api_to_sha1` | Same shared discovery/extraction, selecting SHA-1 |
| `virustotal.command_api_to_sha256` | Same shared discovery/extraction, selecting SHA-256 |

All five depend on advanced search access that was previously deferred. A
documented premium API path does not establish browser access; saved anonymous
HTTP 200 empty search responses are not positive evidence. They are a
conditional investigation shortlist, **not five confirmed free capabilities**.
Keeping VT advanced search deferred means these five remain candidates. Do not
implement declarations alone or route a VT-labelled method through HA.

No five original candidates had established free acquisition routes
in the saved direct-indicator baseline. The replacement plan now investigates
ordinary OTX pulse keyword discovery from the official SDK and user guide.
Two earlier possible OTX email-input adaptations would first
use the mailbox domain and existing DNS/WHOIS lookups; they are domain-scoped
expansions, not native reverse-email searches, and are not selected silently.

Completing five original candidates would produce **48 implemented / 20
candidates / 68 total**. No new HA entries are included in that calculation.
