# IOC method feasibility matrix

Latest 10 November result: **48 implemented / 20 candidates / 68 total** after
the five ordinary OTX pulse methods. 445 tests and 252 subtests passed.
See [executed verification and source limits](METHODS_VERIFICATION_20261110.md).
The earlier 43/25 checkpoint and assessment rows below are historical.

10 November checkpoint: code now declares **43 implemented / 25 candidates /
68 total**, including eight new HA entries and eight promoted original
candidates. **This batch is untested.** See
[implementation/access gaps](SIXTEEN_METHODS_IMPLEMENTATION.md).
The older H/C rows below preserve an earlier planning snapshot; do not use their
communication/actor-proof requirements to override the settled extraction-only
lookup boundary. DNS composition now returns concrete discovered addresses;
the workflow owns relationship admission.

Reassessed: **9 November 2026**, against Project-Sherlock commit `d000b6d`.
Implementation target: `dev/Project-Sherlock/services/ioc`.

Implementation update, 9 November: all four initial targets are implemented.
The three hash methods share one browser-first behavior operation accepting
MD5, SHA-1 or SHA-256; URL-to-filename reuses URL-details response headers.
The next straightforward batch adds OTX domain-to-email and URL-to-URL through
observed WHOIS and HTTP-scan page responses. The current registry is
**27 implemented / 33 candidates**. The assessment counts
below preserve the preceding 21/39 planning snapshot. No hash alias ledger or
mandatory metadata-to-behavior chain is required for the implemented operation.

Terminology clarification: `validate_edge()` checks method/result correctness
(types, ontology, queried identity and source fields); it does not apply graph
admission, evaluate confidence or inspect known/used investigation IOCs. The
workflow owns those graph decisions. References below to field proof describe
whether a result fits its method, not a replacement for the overlap policy.

This assessment uses the implemented providers, HTTP/browser transports,
page-generated responses and configured official API fallbacks as the baseline.
The paper's Table I source/input/output mapping and strict Figure 3 ontology
remain the specification. New functionality should extend the existing owner of
each decision; see the [implementation map](METHOD_IMPLEMENTATION_MAP.md).

## Current first-four implementation

| Method | Implementation | Access / verification boundary |
| --- | --- | --- |
| `virustotal.md5_to_command_api` | Shared `file_behavior` operation and parser | Existing file-report browser route; no API key required; optional keyed summary fallback |
| `virustotal.sha1_to_command_api` | Same shared operation using the supplied SHA-1 | Browser handles the file's canonical page; no separate hash conversion |
| `virustotal.sha256_to_command_api` | Same shared operation using the supplied SHA-256 | Same browser-first acquisition; no alias ledger |
| `virustotal.url_to_filename` | Existing `url_details` request/cache plus explicit response-header filename parsing | Missing optional filename is `filename_unavailable`; no URL-basename guessing |

See [verification results](FIRST_FOUR_METHODS_VERIFICATION.md) for offline tests
and separately labelled live attempts. These four are registered, with 35
candidates still disabled; the generated [catalogue](ONTOLOGY_METHODS.md) is the
current implementation inventory.

The next two OTX methods are `alienvault.domain_to_email` (`whois`) and
`alienvault.url_to_url` (`http_scans`). WHOIS emits explicitly listed contact
emails, including privacy relay addresses, without an ownership or mailbox-host
filter. URL-to-URL reads an explicit 3xx Location header from a stored scan. Both
use the existing browser pipeline; see the [next-method verification report](NEXT_METHODS_VERIFICATION.md).

## Pre-implementation assessment (historical)

| Provider | Implemented | Remaining | P: feasible data contract | C: conditional | H: unsupported by established baseline contract |
| --- | ---: | ---: | ---: | ---: | ---: |
| RapidDNS | 4 | 7 | 0 | 0 | 7 |
| AlienVault / OTX | 8 | 9 | 0 | 3 | 6 |
| VirusTotal | 9 | 23 | 4 | 17 | 2 |
| **Total** | **21** | **39** | **4** | **20** | **15** |

- **Four concrete implementation targets:** VirusTotal's MD5/SHA-1/SHA-256 to
  command/API methods, plus a narrow URL-to-filename case using an explicit
  filename stored in the URL's response headers.
- **Eleven conditional methods have documented VirusTotal discovery/data paths:**
  reverse command-to-hash, filename-to-command/registry/URL,
  registry-to-filename, country-to-IPv4, IP-to-IP and narrow process invocation/file
  cases. They need the stated access, identity and shared acquisition work.
- **Nine conditional methods still need a route or exact field-proof contract:**
  six VirusTotal command/endpoint/registry directions and three OTX email/URL
  directions. The matrix names each unresolved requirement.
- **Fifteen cannot be defensibly implemented from the established baseline
  contracts:** seven RapidDNS methods, six OTX methods and two VirusTotal
  command/CVE directions. They remain in the paper-derived mapping; H is a scoped
  data/query limitation, not a claim of permanent impossibility.

P/C/H are planning labels introduced here, not terms from the paper or runtime
states. **P** means the data contract supports an implementation; it does not mean
already implemented or live-tested. **C** means possible only if the named
prerequisite is satisfied. **H** means the inspected baseline does not establish
the required query or relationship proof. A new documented/captured contract can
change a verdict.

The main classification change is **VirusTotal IPv4-to-IPv4: H -> C**. Its
communicating-files relationship can lead to individual sandbox reports with an
explicit source/destination IP alert tuple. This is a supported conditional
connection path, unlike shared DNS or common-sample inference. [V-IP], [V-BEH]

The API review also makes hash-to-command/API a documented provider operation,
identifies a non-premium-dependent narrow URL-filename case, and strengthens the
OTX WHOIS/URL-analysis leads. These are meaningful changes in the acquisition
and implementation evidence, not just label changes.

### What using the existing code as the baseline means

**Reuse existing mechanisms; add missing source operations deliberately.** The
current four operation families cannot serve all 39 methods merely by enabling
registry entries. For example, the current VirusTotal route builder sends every
non-domain/non-URL input to an IP object. File behavior needs an explicit new
operation in the same VirusTotal adapter and v3 interface.

Where the exact current response already contains a suitable field, reuse that
request, cache and parser path. Where another operation in the same provider API
is required, declare it in the provider and run it through the shared acquisition
code. A required sequence of requests is different from the existing fallback
list and needs the small shared extension explained below. No additional provider,
replacement pipeline, ontology change or runtime implementation is introduced by
this documentation update.

This is a source-contract/code feasibility review, not a live account-access
certification. Official API credentials and entitlements were not tested. API
classification as Everyone still requires the documented key and applicable
quota; it does not mean anonymous access.

## Paper mapping and acquisition baseline

### Strict paper ontology

Use Table I on PDF page 4 and Figure 3 on PDF page 5 of the
[local paper](../../../../ThreatMamba.pdf), together with
[ontology.py](ioc_hunter/ontology.py). A method is a directional
`(source, input_type, output_type)` lookup; IOC graph edges are undirected and
retain the method ID. Reverse lookups require their own acquisition contract.

Table I is the starting specification. Its columns are **Hunting Source**,
**Enabled Searching Objects** and **Source/API**. The entries labelled Source/API
are website URL templates in this table. The surrounding paper text assigns a
dedicated retrieval method to each individual IOC pair within a given source.

| Hunting source | Table I enabled searching objects | Paper's Source/API template |
| --- | --- | --- |
| RapidDNS | Domain, IPv4, IPv6, URL, Time | `https://rapiddns.io/s/[IOC-Value]#result` |
| AlienVault | IPv4, Domain, URL, WHOIS, Geo-location, Email, HASH, Port, Protocol | `https://otx.alienvault.com/indicators/[IOC-Type]/[IOC-Value]` |
| VirusTotal | URL, HASH, Domain, IPv4, Geo-location, File, Port, CVE, CMD/API, Registry | `https://www.virustotal.com/gui/[IOC-Type]/[IOC-Value]/details` |

The repository turns that specification into the mapping in this order:

1. Map each Table I source's enabled objects to concrete code types, including
   HASH to MD5/SHA-1/SHA-256 and File to filename.
2. Enumerate directional input/output pairs for that source.
3. Retain Figure 3-compatible IOC relationships.
4. Overlay implemented provider declarations onto the resulting catalogue.

The catalogue includes six implemented OTX/VirusTotal IPv6 additions beyond
their Table I inventories, bringing 54 baseline entries to 60. See
[method_candidates.py](ioc_hunter/method_candidates.py) and the provider
declarations. In code, the remaining 39 are labelled disabled research candidates
because their acquisition/parser implementations are missing. Here that label
describes their implementation state, not an independently invented method list.

The acquisition detail still has to be established for each mapped direction:
exact request/response or page/tab, field semantics, identity binding, pagination
and access state. For example, the active adapters use OTX's observed singular
`/indicator/` route and RapidDNS's domain/reverse-IP pages rather than assuming
the paper's generic URL templates are complete operation-specific contracts.

Preserve the existing ontology. For example, hash-to-IP/domain/URL,
domain-to-domain and IP-to-port are outside the present IOC ontology. An internal
report-navigation step may pass through a file hash or another object without
adding a forbidden graph edge. Every emitted input-output edge must itself have
direct, permitted relationship evidence.

### Implemented acquisition baseline

Use the actual `requests_for()` implementations and LookupClient's route handling
as the baseline. Retain the existing primary routes, browser-generated response
capture and configured official API backups. HTML/DOM and structured responses
are both valid acquisition formats. No blanket HTML-only restriction applies.

| Provider | Primary route in current code | Existing backup / response handling |
| --- | --- | --- |
| [RapidDNS](ioc_hunter/providers/rapiddns.py) | HTTP HTML from `https://rapiddns.io/subdomain/{value}?page=1` for domains or `/sameip/{value}?page=1` for IPs | Browser fallback opens the same result page and can capture its `/api/search/{value}` response. No credentialed official API fallback is declared. |
| [AlienVault / OTX](ioc_hunter/providers/alienvault.py) | Browser report at `https://otx.alienvault.com/indicator/{ui_kind}/{ui_value}`; matches page-generated `/otxapi/indicators/{kind}/{section}/{value}` responses and observed encoding variants | With a configured key, HTTP backup uses `https://otx.alienvault.com/api/v1/indicators/{api_kind}/{value}/{section}` with `X-OTX-API-KEY`. |
| [VirusTotal](ioc_hunter/providers/virustotal.py) | Browser report at `https://www.virustotal.com/gui/{ui_kind}/{ui_id}/relations` or `/details`; matches the declared `/ui/`, `/api-proxy/ui/` and `/api/v3/` response paths | With a configured key, HTTP backup uses `https://www.virustotal.com/api/v3/{kind}/{object_id}{suffix}` with `x-apikey`, except the `urls` operation, which has no API backup in this adapter. |

These are parameterized route families, not interchangeable object identifiers.
The adapters own type mapping, IPv6/URL escaping and response identity checks.
OTX maps `dns`, `urls`, `geo` and `url_details` to `passive_dns`, `url_list`, `geo`
and `general` sections. VirusTotal uses `/resolutions` for DNS, `/urls` for domain
URL lists and the base object for country/URL details. Its URL GUI ID and official
API object ID have different encodings. Preserve those source-specific rules.

BrowserTransport captures completed responses generated by the opened page,
commonly JSON, and can fall back to rendered HTML. A captured response path is
not automatically a separately permitted direct request: preserve the adapter's
declared HTTP/browser route distinction. Likewise, browser continuation uses
verified UI controls; HTTP/API continuation follows the existing checked rules.

LookupClient reads API keys from configuration/environment unless explicitly
supplied. A configured key makes a declared backup eligible; it does not prove
access or entitlement. A successful parsed primary route, including a completed
empty result, ends route selection. A later-page failure with observations
retains partial results. Rate limits, exhausted budgets and unsafe routing stop
the lookup rather than switching routes. Preserve this existing behavior.

Build on these same providers, interface families and shared mechanisms. Distinguish
an operation already declared in code from an additional operation in the same
provider API. File behavior and Intelligence search are documented VirusTotal v3
operations, but the current adapter does not request them. They require explicit
source-local routing and parsing, not a replacement architecture. No additional
provider, runtime route or credential setting is introduced by this document.

Keep shared pacing, cooldowns, bounded retries, cache and truthful access
outcomes for every route. The original website research's access findings apply
to those particular routes: RapidDNS documents guest/account coverage differences,
and VirusTotal restricts programmatic use of its search interface. They do not
exclude the API fallback routes already present in code.
[RapidDNS access plans][R3], [VirusTotal Searching][V1].


## Documented operations needed for the reassessment

The table separates **already declared routes** from **new operations within
existing provider interfaces**. Paths are API contracts for implementation
planning; this review did not execute them. Preserve the existing provider route
priority and fallback rules; do not invent unobserved browser response paths.

| Key | Operation / fields | Present in current adapter? | Access and feasibility use |
| --- | --- | --- | --- |
| O-W | OTX domain WHOIS in `/api/v1/indicators/domain/{value}/{section}`; reverse-WHOIS historically advertised | No explicit WHOIS operation | Official static documentation mentions WHOIS, but section enums/SDK differ. Historical reverse-WHOIS does not establish a current email endpoint. [O-API], [O-WHOIS], [O-TYPES] |
| O-U | OTX URL-input `url_list` analysis section | Current `url_details` uses `general`; `urls` is domain-input | Add a separate URL-analysis mapping only after inspecting exact nested link/redirect fields. Reuse existing URL-link proof where appropriate. [O-API] |
| V-U | `GET /api/v3/urls/{id}`; stored response headers/body hash | Yes, for URL details and key-conditioned fallback | Can support an explicit response-filename subset without assuming premium downloaded-file history. Header presence is data-dependent. [V-URL] |
| V-F | `GET /api/v3/files/{hash}`; digest aliases and names | No | New source-local operation for canonical file identity. Filename aliases must retain their scope. [V-FILE] |
| V-BS | `GET /api/v3/files/{hash}/behaviour_summary` | No | Accepts MD5/SHA-1/SHA-256; merged sandbox data can provide sample-level commands/API observations. Avoid cross-sandbox event correlations. [V-SUM] |
| V-B | `GET /api/v3/files/{hash}/behaviours`; individual behavior report objects | No | Documented file relationship is Everyone; report availability varies. Individual sandbox records retain identity and scope needed for correlations. [V-FILES], [V-REPORT] |
| V-IC | `GET /api/v3/ip_addresses/{ip}/communicating_files` | No | Documented as Everyone; supplies candidate file identities without Intelligence search. It does not itself prove a command or peer-IP edge. [V-IP] |
| V-S | `GET /api/v3/intelligence/search?query=...` | No | Premium privileges. Results may be files, IPs or other typed objects; exact query/result binding and field verification are required. [V-SEARCH] |
| V-UD | `GET /api/v3/urls/{id}/downloaded_files` | No | Premium relationship. Can supply URL-file identities and reported names for a richer scoped relation. [V-DOWN] |
| V-FU | `GET /api/v3/files/{hash}/itw_urls` | No | Premium download-source URL relationship, useful after exact filename/sample identification. [V-ITW] |

The field-level restrictions in the candidate tables are implementation proof
requirements, not extra ontology edges or new rules attributed to the paper.
File-level observations can support a named-sample relation when that is the
source's attribution. A command-specific relation needs command-specific proof;
a sample-wide list cannot establish every command's actions.

## Original 39-method assessment (four now implemented)

The route keys above apply to the following historical assessment tables. The
four P rows are now implemented as described above; the other 35 remain disabled.
For C rows, "documented conditional path" means the discovery and relevant data
are documented; "evidence-dependent" means discovery exists but the needed exact
actor/event relation is not universally present in standard fields.

### RapidDNS: 7 candidates

| Method ID | Verdict | Baseline operation/data | What is possible and what is missing | Implementation location / prerequisite |
| --- | --- | --- | --- | --- |
| `rapiddns.domain_to_url` | H | Existing DNS pages/captured search responses | No URL ownership field in the established DNS contract. Do not fabricate a URL from a hostname. | No implementation until a source contract supplies the missing fact. |
| `rapiddns.ipv4_to_ipv4` | H | Existing reverse-IP/DNS data | No direct communication tuple. Shared domains, resolver, subnet or hosting do not establish connect. | Keep disabled; composing DNS lookups cannot fix the proof gap. |
| `rapiddns.ipv4_to_ipv6` | H | Existing A/AAAA records | Two address records for a hostname establish domain-IP facts, not IP-IP communication. | Keep disabled pending direct connection data. |
| `rapiddns.ipv6_to_ipv4` | H | Existing reverse-IP/DNS data | Same communication gap; the reverse retrieval direction also needs query-bound proof. | Keep disabled pending direct connection data. |
| `rapiddns.ipv6_to_ipv6` | H | Existing reverse-IP/DNS data | No connection between two distinct IPv6 identities is established by co-resolving records. | Keep disabled pending direct connection data. |
| `rapiddns.url_to_domain` | H | Local URL-host extraction is possible | The input itself can supply a host, but current RapidDNS responses do not provide a URL relationship. A local derivation cannot be labelled newly retrieved RapidDNS evidence. | Could be a separately identified local derivation; not this source-backed method under the current proof contract. |
| `rapiddns.url_to_url` | H | Existing DNS data | No outgoing-link or direct-redirect observation. DNS/API access changes do not supply that missing fact. | Keep disabled pending URL relationship data. |

### AlienVault / OTX: 9 candidates

| Method ID | Verdict | Baseline operation/data | What is possible and what is missing | Implementation location / prerequisite |
| --- | --- | --- | --- | --- |
| `alienvault.domain_to_email` | C (historical; now implemented) | Observed domain-page WHOIS response | The current lookup emits explicit source-listed email contacts, including privacy relay addresses, without mailbox-host or ownership filtering. Workflow owns relationship admission. | Implemented in alienvault.py and otx_whois.py; current results are in NEXT_METHODS_VERIFICATION.md. |
| `alienvault.email_to_domain` | C | O-W historical reverse-WHOIS; email route unconfirmed | Current SDK recognizes email but declares no supported email API sections. Do not invent an email endpoint from the template. Verify an actual route and ownership fields; input mailbox-host parsing alone is local derivation. | alienvault adapter plus new email proof after contract verification. Unconfirmed acquisition dependency. |
| `alienvault.email_to_email` | H | Recognized email indicator/pulse content | No established message/forwarding/direct connection query or proof. Shared pulse/WHOIS membership is insufficient. | No defensible implementation from inspected baseline fields. |
| `alienvault.geo_location_to_ipv4` | H | Existing IP-to-geo section | No established country-input IP enumeration contract. Pulse target-country tags do not reverse IP-country evidence. | No country-input operation established in this baseline. |
| `alienvault.ipv4_to_ipv4` | H | IP enrichment, malware/URL/DNS sections | These relationships do not themselves give a direct queried-IP/peer-IP traffic tuple. Common sample membership is insufficient. | No direct connection contract established in inspected OTX baseline. |
| `alienvault.port_to_protocol` | H | Existing indicator families | No port-input enrichment operation or bound observed protocol-use proof identified. | Do not substitute default-port tables or another product's endpoint. |
| `alienvault.protocol_to_port` | H | Existing indicator families | No protocol-input observed port-use operation identified. | No supported baseline query/proof established. |
| `alienvault.protocol_to_protocol` | H | Existing indicator families | Neither standalone query nor explicit encapsulation fields established. | No supported baseline query/proof established. |
| `alienvault.url_to_url` | C (historical; now implemented) | Observed URL-page http_scans response | The current lookup extracts explicit 3xx Location destinations from query-bound stored HTTP header rows. | Implemented in alienvault.py and otx_http.py using the existing url_link method-correctness check; see NEXT_METHODS_VERIFICATION.md. |

### VirusTotal: 23 candidates

| Method ID | Verdict | Baseline operation/data | What is possible and what is missing | Implementation location / prerequisite |
| --- | --- | --- | --- | --- |
| `virustotal.command_api_to_command_api` | C | V-S -> V-B; premium discovery or trusted existing sample provenance | Individual processes_tree.children supplies a creation relation, subject to exact command identity. A process name does not always identify a full command; API-to-API invocation remains a separate subset. | Documented conditional path: query-bound search/dependent acquisition; source process parser and invocation proof. |
| `virustotal.command_api_to_cve` | H | CVE-tag/behavior discovery can find samples | Standard sample CVE tags and command lists do not identify which command scans/uses the CVE. No general direct action contract established. | Not implementable from the established standard fields; an explicit exploit/action trace would require reassessment. |
| `virustotal.command_api_to_filename` | C | V-S -> V-B, or authoritative command/sample provenance | An explicit process executable name or command-bound file action can support a narrow relation. Unrelated report filenames cannot be returned. | Documented conditional path for process/file-action subsets; dependent acquisition and new proof. |
| `virustotal.command_api_to_ipv4` | C | V-S -> V-B/detail context | Ordinary ip_traffic gives endpoints without a universal command actor. Need an actual command-correlated event; aggregate command/IP lists cannot prove it. | Evidence-dependent: implement only an observed exact actor/endpoint subset, not a general Cartesian join. |
| `virustotal.command_api_to_md5` | C | V-S -> V-B + V-F | Premium search discovers files; exact command/API occurrence and identity-bound sample MD5 must be verified. | Documented conditional path: search query binding, bounded stages, file/command proof. |
| `virustotal.command_api_to_port` | C | V-S -> V-B/detail context | Need exact command/API send/receive/listen evidence. Sample-level destination ports alone omit the actor. | Evidence-dependent; new actor/endpoint proof after a positive trace contract. |
| `virustotal.command_api_to_registry` | C | V-S -> V-B/detail context | Registry key lists omit a universal command actor. Need exact event attribution or a separately specified bounded command parser. | Evidence-dependent; no aggregate-list shortcut. |
| `virustotal.command_api_to_sha1` | C | V-S -> V-B + V-F | Same exact observed-command/sample relation, returning the verified SHA-1. Search match alone is insufficient. | Documented conditional path; reuse the command-to-file operation and proof with a different output digest. |
| `virustotal.command_api_to_sha256` | C | V-S -> V-B + V-F | Same exact relation, returning the sample SHA-256. | Documented conditional path; share acquisition/parser logic with the other digest outputs. |
| `virustotal.cve_to_command_api` | H | Premium CVE sample search exists | Finding a sample tagged with a CVE does not prove every command in that sample scans/uses it. No general exact exploit-action mapping established. | Not implementable from established standard fields; preserve the mapped method for future direct evidence. |
| `virustotal.filename_to_command_api` | C | V-S exact-name filtering -> V-F -> V-B | Filename search is not unique identity and may match substrings. Bind the exact name to the selected sample and its command/API records. | Documented conditional path; premium discovery plus bounded dependent acquisition and identity proof. |
| `virustotal.filename_to_registry` | C | V-S -> V-F/V-B | Explicit registry operations attributed to the exact named sample can support use. Retain child/sandbox context; the ontology does not itself impose an extra universal process-trace requirement. | Documented conditional path; exact sample/name binding and file-registry proof. |
| `virustotal.filename_to_url` | C | V-S -> V-FU | Exact-name sample identification followed by explicit in-the-wild/download-source URL relation. Both discovery and FU have access dependencies. | Documented conditional path; premium operations and compound identity evidence. |
| `virustotal.geo_location_to_ipv4` | C | V-S with entity:ip and country filter | Premium IP search can discover candidates. Verify each returned IPv4's own country and retain incomplete/capped results. | Documented conditional path; pure ip_country inverse proof, search query binding and bounded coverage. |
| `virustotal.ipv4_to_command_api` | C | V-IC -> V-B/detail context | Communicating-files discovery is documented without Intelligence search. Exact command-to-IP actor correlation remains unresolved in ordinary aggregate fields. | Evidence-dependent; shared dependent acquisition needed, plus an observed actor/endpoint proof. |
| `virustotal.ipv4_to_ipv4` | C | V-IC -> individual V-B IDS alert context | Accept only an alert_context with explicit src_ip/dest_ip and the queried IP as an endpoint. Related-file membership alone is insufficient. Such an alert may be absent. | Documented conditional path; bounded dependent acquisition and ip_connection proof. Upgraded from H. |
| `virustotal.md5_to_command_api` | P | V-F binding -> V-B or V-BS | API accepts MD5; command_executions/calls_highlighted/invokes provide explicit sample observations. Preserve canonical SHA-256 alias proof rather than pretending a behavior-only excerpt proves MD5. | Feasible data contract; VT file operation/parser + new sample-command proof, dependent identity binding where necessary. |
| `virustotal.port_to_command_api` | C | V-S network discovery -> V-B/detail context | A port must bind to the exact command actor/action. No standalone general port object route or universal correlation is established. | Evidence-dependent; search access alone does not solve attribution. |
| `virustotal.registry_to_command_api` | C | V-S registry discovery -> V-B/detail context | Need an exact registry event identifying the acting command/API. A matching file's full command list is insufficient. | Evidence-dependent; direct trace/parser contract still required. |
| `virustotal.registry_to_filename` | C | V-S registry discovery -> V-F/V-B | Verify exact registry action and the named sample identity. File-level behavior attribution is acceptable when it is the declared proof, with scope retained. | Documented conditional path; premium discovery, compound provenance and file-registry proof. |
| `virustotal.sha1_to_command_api` | P | V-F binding -> V-B or V-BS | API accepts SHA-1; emit explicit sample command/API records, retaining the SHA-1/canonical-file binding. | Feasible data contract; share file acquisition/parser/proof with MD5 and SHA-256. |
| `virustotal.sha256_to_command_api` | P | V-B or V-BS; V-F only if needed | SHA-256 can bind directly to the per-sandbox file identity. Explicit command/API fields support the association; distinguish execution, highlighted calls and reflection. | Feasible data contract; best first file-behavior implementation. |
| `virustotal.url_to_filename` | P | Existing V-U object; richer V-UD optional | Narrow direct case: stored Content-Disposition explicitly names a file. Do not guess from URL basename. Premium downloaded_files is a richer option. Body hash -> file names needs compound proof and does not prove the actual delivery name. | Feasible narrow case reusing url_details request/cache; new header parser and URL-filename proof. Richer chain is conditional. |

## Earlier 21-method repair baseline (historical)

These rows describe existing declarations and **14 October 2026 repair evidence**,
not new availability certification. Positive means at least one validated output
in those iterative samples. Empty means completed with no applicable data for
that input. Many positive responses were partial. Source:
[METHOD_RELIABILITY_RESULTS.md](METHOD_RELIABILITY_RESULTS.md).

| Method ID | Existing website section | Recorded repair outcome |
| --- | --- | --- |
| `rapiddns.domain_to_ipv4` | Domain DNS result table | Positive; partial guest coverage |
| `rapiddns.domain_to_ipv6` | Domain DNS result table | Positive; partial guest coverage |
| `rapiddns.ipv4_to_domain` | Reverse-IP DNS result table | Positive; partial guest coverage |
| `rapiddns.ipv6_to_domain` | Reverse-IP DNS result table | Positive; partial guest coverage |
| `alienvault.domain_to_ipv4` | Domain / Passive DNS | Positive after follow-up |
| `alienvault.domain_to_ipv6` | Domain / Passive DNS | Positive |
| `alienvault.domain_to_url` | Domain / URLs | Positive; two-page UI check, partial |
| `alienvault.ipv4_to_domain` | IP / Passive DNS | Positive |
| `alienvault.ipv4_to_geo_location` | IP geographic fields | Positive |
| `alienvault.ipv6_to_domain` | IP / Passive DNS | Completed empty for tested input |
| `alienvault.ipv6_to_geo_location` | IP geographic fields | Positive through corrected GUI alias |
| `alienvault.url_to_domain` | URL details | Positive after encoding correction |
| `virustotal.domain_to_ipv4` | Domain / Relations / resolutions | Positive; partial |
| `virustotal.domain_to_ipv6` | Domain / Relations / resolutions | Positive; partial |
| `virustotal.domain_to_url` | Domain / Relations | Unresolved response; excluded from saved live selection |
| `virustotal.ipv4_to_domain` | IP / Relations / resolutions | Positive; partial |
| `virustotal.ipv4_to_geo_location` | IP / Details / country | Country unavailable for tested input |
| `virustotal.ipv6_to_domain` | IP / Relations / resolutions | Positive |
| `virustotal.ipv6_to_geo_location` | IP / Details / country | Country unavailable for tested input |
| `virustotal.url_to_domain` | URL / Details | Positive |
| `virustotal.url_to_url` | URL details with explicit links/redirect evidence | Positive |

Totals: **17 positive, three completed no-data, one unresolved** in the recorded
repair samples. Browser pagination remains incompletely verified outside the
documented OTX URL pagination path. Existing implementations still need present-day
verification across their primary/configured fallback routes and readiness
reporting.

## Paper entities without clear lookup methods

Figure 3 contains **15 IOC families, Time, Tactic and Technique**. The figure's
printed numbering skips a number; its largest number is not its entity count.
The following table reflects the current **27 implemented / 33 candidate**
registry after both batches. It covers all 15 IOC families. Counts are
registry rows with that family as input/output, not unique relationships.
Summing the input column alone or output column alone gives the method count;
adding both counts double-counts each method.

Current methods touch **8 of 15 IOC families**: four as inputs, seven as outputs.
If all 60 mapped methods were implemented, they would touch **12 of 15**, as
both inputs and outputs. MAC address, Account and Header have no mapped methods.
Time also has none; including this separate temporal entity gives **8 of 16**
covered now and **12 of 16** potentially covered by the full catalogue. These
counts describe type coverage, not complete coverage of every ontology edge or
a guarantee that all remaining candidates have feasible acquisition routes.

| Figure 3 IOC family | Code representation | Implemented input / output | Candidate input / output | Lookup coverage and missing contract |
| --- | --- | ---: | ---: | --- |
| IP address | `ipv4`, `ipv6` -> `ip` | 10 / 6 | 7 / 9 | DNS and country paths exist. Direct communication and command-linked network events remain unconfirmed. |
| Geo location | `geo_location` | 0 / 4 | 2 / 0 | Output is currently a two-letter country code. No implemented reverse lookup; arbitrary city/coordinate input is unsupported. |
| **MAC address** | `mac` | **0 / 0** | **0 / 0** | **No candidate or source route.** IP-MAC and MAC-location relations require host/local-network observations absent from the established lookup contracts. |
| Port | `port` | 0 / 0 | 2 / 2 | Candidate directions only. A bare port lacks endpoint, protocol and event context; no clear general lookup contract. |
| Protocol | `protocol` | 0 / 0 | 2 / 2 | Candidate directions only. Need explicit port-use or encapsulation observations; protocol names alone do not identify an incident. |
| Filename | `filename` | 0 / 1 | 3 / 2 | URL-to-filename emits explicit stored Content-Disposition filenames. Filename-input methods remain candidates. |
| Vulnerability | `cve` | 0 / 0 | 1 / 1 | Only command/API directions are candidates. No exact exploit/use contract established. Current identity supports CVEs, not every vulnerability naming scheme. |
| **Account** | `account` | **0 / 0** | **0 / 0** | **No candidate or source route.** Needs account namespace/system and explicit email, command or header association. A provider community profile is not automatically this entity. |
| Command/API | `command_api` | 0 / 3 | 9 / 6 | The three hash methods emit observed command/API fields. Command/API-input methods remain candidates. |
| Fingerprint/signature | `md5`, `sha1`, `sha256` -> `fingerprint` | 3 / 0 | 0 / 3 | All three hashes can start a behavior lookup. Returning hashes remains a candidate operation; non-hash signatures have no mapped concrete implementation. |
| Domain | `domain` | 9 / 8 | 1 / 2 | DNS, URL and WHOIS contact-email output directions exist. Reverse email lookup and RapidDNS domain-URL remain candidates. |
| Registry | `registry` | 0 / 0 | 2 / 2 | Candidate directions only. Need exact key/value identity, system/sample context and actor-bound operation evidence. |
| **Header** | `header` | **0 / 0** | **0 / 0** | **No candidate or source route.** Need the header kind, originating message/session and exact source/target/cookie fields. An arbitrary HTTP header list does not cover every paper header relation. |
| URL/path | `url`; `path` aliases to its ontology family | 5 / 4 | 2 / 3 | Existing lookups accept network URLs, including URL-to-filename and OTX stored-scan redirects. Arbitrary filesystem paths have no implemented lookup; the alias does not supply one. |
| Email | `email` | 0 / 1 | 2 / 1 | OTX WHOIS emits explicitly listed contact addresses. Email-input and email-to-email acquisition remain candidates. Workflow owns relationship admission. |

Other paper terms need separate treatment:

| Paper term | Current interpretation | Consequence |
| --- | --- | --- |
| **Time** | `time`; only temporal edges in the current ontology | Zero implemented/candidate IOC methods. RapidDNS lists Time in Table I, but dates should remain evidence attributes until temporal construction is implemented. Do not invent a Time hunting method to fill the count. |
| Tactic / Technique | `tactic`, `technique`; TTP-category edges | Separate TTP extraction and CSKG work, outside this provider-method backlog. |
| WHOIS | Table I report/search object and Figure 3 IP-location relationship label; not a separate Figure 3 node | Inspect WHOIS as source metadata where useful. Do not introduce a new `whois` IOC kind. |
| File | Table I object mapped to `filename` by the source inventory | A report identified by a digest and a filename string are different identity levels. Preserve the sample binding when reporting file relationships. |

The default extractor supports seven concrete types: domain, IPv4, IPv6, URL,
MD5, SHA-1 and SHA-256. Extended extraction adds email/CVE. Metadata extraction
accepts explicitly labelled filename, country, port and protocol fields as well,
but creates no relationships. Recognizing a model type does not establish its
extraction, normalization or lookup contract.

## Reuse and implementation placement

The [implementation map](METHOD_IMPLEMENTATION_MAP.md) traces the actual functions,
shared extension needed for dependent requests, evidence implications and test
locations. Its central rule is to extend the existing owner of a decision.

| Work | Existing owner to extend | What to keep reusable |
| --- | --- | --- |
| Source methods, routes, access conditions and response containers | `providers/<source>.py`: METHODS, requests_for, parse_document | Explicit source-local operations; no network calls inside parsers |
| Field conversion and evidence construction | `providers/common.py`: ObservationBuilder and relevant helpers | Normalize/emit using the existing IOC/evidence format |
| GET/browser execution, cache, pacing, retries and snapshots | `lookup.py` with existing transports/storage | Every new acquisition uses shared execution and retains a snapshot |
| Exact relationship proof | `validation.py`: validate_edge | Pure deterministic checks, separate from acquisition and graph state |
| Dependent request stages and compound identity evidence | Small optional shared contract beside Provider/ParsedPage, executed by LookupClient | Reuse the current single-response path; keep fallback, pagination and dependency distinct |
| Search-query identity | `transport/models.py`, browser.response_matches, source parsers | Bind the actual query as well as path and result type |
| Method discovery, graph admission, saved runs and API | Existing registry/workflow/application services | New supported methods flow through existing discovery; graph policy remains unchanged |

Three concrete reuse decisions reduce work:

1. **URL-to-filename's narrow header case** can reuse VirusTotal's existing
   `url_details` request and response/cache. Add explicit header-to-filename
   mapping and a new URL-filename proof; a second downloader is unnecessary.
2. **OTX URL-to-URL**, if the source returns the right fields, can reuse the shared
   direct-link/redirect helper and current `url_link` proof. It still needs the
   actual OTX operation/container mapping.
3. **The three hash-to-command outputs** share one file/behavior acquisition and
   proof family, with hash-specific identity binding. They do not need three
   independent scrapers. Start with SHA-256 and add alias-bound MD5/SHA-1 support.

## Implementation order

1. Implement the narrow existing-response URL-filename proof and source mapping;
   capture positive and absent/malformed header cases. Keep its scope explicit.
2. Add the SHA-256 file-behavior operation/parser and sample-command proof using
   the existing transports, ObservationBuilder and receipt pipeline.
3. Add the smallest shared dependent-acquisition/compound-provenance capability
   when a concrete method needs it; use it for MD5/SHA-1 alias binding and later
   report chains. Do not put hidden HTTP calls in provider parsers.
4. Add query-bound search and bounded fan-out only for methods with available
   access and a documented direct proof. Prioritize IP-to-IP as a separate
   communicating-file/alert-tuple chain where data exists.
5. Verify OTX WHOIS/email and URL-analysis contracts. Keep route/schema and
   ownership/link semantics explicit before promotion.
6. Keep the 15 H methods disabled until a source contract supplies their missing
   query/evidence. Do not manufacture relationships to complete a numeric target.

Before promotion retain source access mode, request/page identity, every stage's
snapshot, proof fields, fixture provenance and partial/error behavior. Test
positive cases against real confounders: wrong query/sample/hash, unrelated
process/key, shared DNS without communication, missing required stage and access
failure. Keep offline fixtures and dated live verification separate. A validated
result still goes through the existing paper admission policy.

## Research and verification

On 9 November, the reassessment inspected official OTX v1 documentation/SDK and
VirusTotal v3 objects, relationship access tables and behavior/search operations,
then traced them against the active source. It did not call provider lookup APIs,
submit scans or test credentials. Documentation can establish a supported
operation/data shape; it cannot establish present-day account access or data for
every IOC.

Offline inspection of all 21 implemented `requests_for()` declarations confirmed:
RapidDNS has HTTP/browser alternatives for all four methods; OTX adds an official
API route for all eight with a supplied placeholder key; VirusTotal adds one for
eight of nine, excluding its domain-URL operation. No transports were invoked.
The full method tables are checked against the registry, and local links and
patch whitespace are checked. Historical repair outcomes remain dated evidence.

Primary sources checked 9 November 2026:

- [RapidDNS DNS/API scope][R-API].
- [OTX static indicator API documentation][O-API], [official indicator definitions][O-TYPES]
  and [SDK implementation][O-SDK]. WHOIS prose and enumerations differ, and email
  is not a supported SDK API type; this keeps reverse email acquisition conditional.
- [OTX WHOIS/reverse-WHOIS announcement][O-WHOIS] (17 August 2017): historical
  capability context, not a current route/access verification.
- [VirusTotal file report][V-FILE], [file object/relationship access][V-FILES],
  [merged behavior summary][V-SUM] and [individual behavior reports][V-REPORT].
- [VirusTotal behavior fields][V-BEH] and [process tree structure][V-TREE].
- [VirusTotal URL object][V-URL], [downloaded files][V-DOWN] and
  [download-source URLs][V-ITW].
- [VirusTotal IP object/relationship access][V-IP], [Intelligence search][V-SEARCH],
  [file-search modifiers][V-MOD] and [IP-search modifiers][V-IPMOD].

Repository references: [catalogue](ONTOLOGY_METHODS.md),
[provider guide](PROVIDER_IMPLEMENTATION_GUIDE.md),
[implementation map](METHOD_IMPLEMENTATION_MAP.md),
[historical repair results](METHOD_RELIABILITY_RESULTS.md) and
[graph admission](IOC_INCLUSION_REFERENCE.md).

[R-API]: https://rapiddns.io/help/api
[R3]: https://rapiddns.io/pricing
[V1]: https://docs.virustotal.com/docs/searching
[O-API]: https://otx.alienvault.com/assets/static/external_api.html
[O-TYPES]: https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/IndicatorTypes.py
[O-SDK]: https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/OTXv2.py
[O-WHOIS]: https://www.levelblue.com/blogs/levelblue-blog/the-upgraded-alienvault-otx-api-ways-to-score-swag
[V-FILE]: https://docs.virustotal.com/reference/file-info
[V-FILES]: https://docs.virustotal.com/reference/files
[V-SUM]: https://docs.virustotal.com/reference/file-all-behaviours-summary
[V-REPORT]: https://docs.virustotal.com/reference/get-all-behavior-reports-for-a-file
[V-BEH]: https://docs.virustotal.com/reference/file-behaviour-summary
[V-TREE]: https://docs.virustotal.com/reference/process
[V-URL]: https://docs.virustotal.com/reference/url-object
[V-DOWN]: https://docs.virustotal.com/reference/url-object-downloaded-files
[V-ITW]: https://docs.virustotal.com/reference/file-object-files-itw-urls
[V-IP]: https://docs.virustotal.com/reference/ip-object
[V-SEARCH]: https://docs.virustotal.com/reference/intelligence-search
[V-MOD]: https://docs.virustotal.com/docs/file-search-modifiers
[V-IPMOD]: https://docs.virustotal.com/docs/ip-address-search-modifiers
