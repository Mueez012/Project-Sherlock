# Method implementation map

Latest implementation: `providers/otx_pulses.py` owns the five ordinary OTX
search/extraction methods, reusing FollowUp execution and configured API backups.
Shared HTML readiness uses declared `ready_text` against DOM `textContent` for
script data. Current counts and executed checks are in
[the final report](METHODS_VERIFICATION_20261110.md): 48/20/68; 445 tests and
252 subtests passed. Earlier checkpoint counts below are historical.

10 November extension: the sixteen-method batch is coded but **untested**.
`providers/base.py` now declares bounded follow-ups; LookupClient executes them
using its existing cache, pacing, receipts and configured fallbacks. HA search
and report parsing, DNS composition and VT network extraction remain small
provider helpers. See [the checkpoint](SIXTEEN_METHODS_IMPLEMENTATION.md) for
the complete ownership map and access gaps. Earlier slices below are historical.

Reviewed: **9 November 2026**, Project-Sherlock commit `d000b6d`.
Scope: extend the IOC service's existing modular implementation for the methods
in the [reassessed feasibility matrix](METHODS_FEASIBILITY_MATRIX.md).
This is an implementation reference; no runtime change is made here.

9 November clarification: the current `validate_edge()` call in LookupClient is
a method/result correctness guard. It checks the method, ontology and consistency
of the provider fields; the workflow separately applies graph admission. That
boundary is retained. The three hash methods now share one browser-first behavior lookup
accepting any supported digest; they do not require a hash-alias provenance system.

## Design rule

For every new behavior, first find the existing module that owns that decision.
Extend that owner or a small helper in the same boundary. Reuse the current
provider protocol, IOC objects, transports, lookup client, evidence store,
validator, registry and investigation service. A provider parser must not become
a second lookup engine.

Preserve the public `IOC -> list[IOC]` interface. Detailed results continue to use
`lookup_detailed()` and its exact immutable receipt. Preserve the strict ontology
and paper graph admission. New source operations do not select the next graph
node, award reward or insert edges.

## Current implementation slice: the first four methods

The authorized slice is the three VirusTotal hash-to-command/API methods and
the narrow URL-to-filename method. They fit the existing single-response path:

| Methods | Provider work | Existing mechanisms reused |
| --- | --- | --- |
| `virustotal.md5_to_command_api`, `virustotal.sha1_to_command_api`, `virustotal.sha256_to_command_api` | One `file_behavior` operation opens `/gui/file/{input_hash}/behavior` and captures `/ui/files/{report_hash}/behaviours`. The configured API fallback is `/api/v3/files/{input_hash}/behaviour_summary`. Parse only command_executions, calls_highlighted and invokes. | Provider METHODS/requests_for/parse_document, BrowserTransport/HTTPTransport, ObservationBuilder, hash normalization, validate_edge, normal receipts/cache/limits |
| `virustotal.url_to_filename` | Read an explicit usable Content-Disposition filename from the stored URL response headers. Reuse URL-details acquisition rather than another download or the premium downloaded-files relationship. | Existing URL report route and configured API fallback, response cache, filename normalization, source-field evidence and a URL-filename validator branch |

The hash operation accepts the original supported digest directly. Browser
acquisition is primary; the API fallback is added only with a configured key.
A missing key does not disable the report page, and a supplied key does not
prove API entitlement or live success. MD5/SHA-1/SHA-256 share code while
retaining their separate typed IOC identities. They need no alias ledger or
extra metadata round trip.

The provider supplies `page_identity_pattern` to the existing browser request
contract. It matches the actual current file-report page after provider
navigation, allowing BrowserTransport to expand the exact expected response
path when VirusTotal canonicalizes a digest to a SHA-256 report. The transport
does not bind a file by taking an arbitrary hash from background requests.

This slice does not need a generic dependent-acquisition framework, new
observation/relationship-status fields, another evidence store or a new API
receipt format. Use the existing accepted/rejected source-evidence associations.
The later search/report-chain discussion below is a future consideration, not
a prerequisite for these four methods.

## Next implementation slice: two OTX methods

| Method | Acquisition and source-local owner | Shared mechanisms retained |
| --- | --- | --- |
| `alienvault.domain_to_email` | The domain page's WHOIS JSON; [otx_whois.py](ioc_hunter/providers/otx_whois.py) parses labelled email rows | alienvault METHODS/routes/dispatch, BrowserTransport, ObservationBuilder, email normalization, validate_edge, ordinary receipts/cache/limits |
| `alienvault.url_to_url` | The URL page's http_scans JSON; [otx_http.py](ioc_hunter/providers/otx_http.py) parses a stored 3xx header's Location | Existing provider/executor boundary, URL normalization, source-backed redirect evidence, ordinary receipts and separate graph admission |

Keep the helpers source-local: they understand OTX's `{data, count}` rows and
field names; common.py remains the owner of generic observation/evidence emission.
The helpers do not execute requests, call the graph or create a second registry.
The adapter owns explicit operations, routes and dispatch to those parsers.

The WHOIS contract returns concrete contact emails explicitly supplied for the
queried domain. Its `whois_email` facts contain domain, email and field. Do not
require mailbox-host equality or add ownership/confidence scoring. The source
can legitimately list a registrar/privacy-service mailbox. Method correctness
is source/query/type/field consistency; graph admission remains the workflow's
candidate-overlap decision.

The HTTP helper accepts the stored scan's 3xx Location target only. It does not
extract arbitrary URLs from scan bodies, certificates or unrelated indicator
sections and never visits the input website or target. Preserve the source
header record and locator instead of inventing an outgoing-link relation.

These two operations use browser capture only because their official API paths
have not been verified. Do not extend the old OTX API-section template to them
merely because credentials exist. Existing DNS, domain-URL, geo and URL-details
API backups remain unchanged. No dependent-acquisition framework is introduced.
Current executed checks and access conditions belong in
[NEXT_METHODS_VERIFICATION.md](NEXT_METHODS_VERIFICATION.md); earlier four-method
results retain their own dated report.

## Current execution path

1. `methods.py` collects each provider's METHODS and overlays implemented entries
   onto the Table I/Figure 3 candidate catalogue.
2. `LookupClient._lookup_detailed()` binds the method/input identity, creates the
   receipt, rejects disabled methods, enters a browser session and calls `_run()`.
3. The source's `requests_for()` returns ordered alternative acquisition routes.
4. `_run()` calls `_fetch()`, snapshots the returned Document, parses it through
   the provider and follows bounded pagination where supported.
5. The provider returns ParsedPage observations. ObservationBuilder emits typed
   IOCs and field-derived Evidence without acquiring data or changing a graph.
6. `validate_edge()` independently checks method/source correctness: concrete
   types, ontology membership, source/query/operation and the fields supporting
   the proposed output. Lookup retains accepted/rejected mappings and
   deduplicates outputs without losing evidence.
7. The workflow obtains that exact receipt, revalidates accepted mappings, applies
   the separate paper admission condition, and commits graph/run state.

The validator does not know the graph's used candidates, compute reward or
admit a batch. The workflow's paper candidate-overlap test makes that later
decision. Preserve the existing lookup validation and workflow admission order.

## Where each decision belongs

| New behavior / decision | Existing owner | Reuse or extension |
| --- | --- | --- |
| Which source/input/output method exists | `providers/<source>.py` METHODS; [methods.py](ioc_hunter/methods.py) | Add a supported declaration only with a working operation. Registry discovery and ontology checks already exist. |
| Which URL/API operation, section or object type to request | Source `requests_for()` | Add explicit source-local route mapping. Do not rely on VirusTotal's current non-domain/non-URL -> IP fallback for new input kinds. |
| Whether a source route requires a key/access mode | Source `requests_for()`, [config.py](ioc_hunter/config.py), [methods.py](ioc_hunter/methods.py) method_status | Preserve configured backup conditions. Report local configuration separately from tested access; a key is not proof of entitlement. |
| Route fallback and stopping behavior | [lookup.py](ioc_hunter/lookup.py) `LookupClient._run()` | Preserve sequential alternatives, empty/partial semantics and hard-stop outcomes. A new API is not a reason to clone fallback logic in a provider. |
| Network GET, redirects and response size | [transport/http.py](ioc_hunter/transport/http.py) `HTTPTransport.fetch()` | Reuse provider-host checks, headers, bounded text bodies and status classification. |
| Browser session/navigation, tab activation and completed capture | [transport/browser.py](ioc_hunter/transport/browser.py) `session()`, `fetch()` | Reuse the current per-lookup session and declarative FetchRequest. Add only genuinely generic acquisition behavior here. |
| Expected response identity and query binding | [transport/models.py](ioc_hunter/transport/models.py) FetchRequest; browser `response_matches()`; provider parser | Keep source path declarations local; strengthen shared matching for new search query parameters and check typed response identities. |
| Provider envelope, field names and source schema | Source `parse_document()` | Add explicit file/behavior/search/WHOIS/URL-analysis containers. Preserve malformed versus empty results. |
| Convert a source field into a normalized IOC/evidence record | [providers/common.py](ioc_hunter/providers/common.py) `ObservationBuilder.emit()` | Reuse normalization, source excerpts, locators and evidence construction. Share additional converters only when the fact format is genuinely shared. |
| Identity normalization | [models.py](ioc_hunter/models.py) `normalize()`, `identity()` | Reuse existing concrete types. Retain full paths/command arguments/API qualifiers in evidence. Basename and digest aliases need explicit source binding. |
| Method/source correctness proof | [validation.py](ioc_hunter/validation.py) `validate_edge()` | Add deterministic source-field checks for new method outputs; no network, storage, LLM or graph dependency. Keep this check in lookup, distinct from workflow admission. |
| Source pacing, cooldown and quota accounting | [lookup.py](ioc_hunter/lookup.py) `_fetch()`, [transport/limits.py](ioc_hunter/transport/limits.py), [storage.py](ioc_hunter/storage.py) | Route every required acquisition through the shared path. Source cooldowns and budgets must cover new stages. |
| Cache scope/version and source snapshots | [storage.py](ioc_hunter/storage.py) `cache_key()`, `snapshot()`; FetchRequest integration_version | Reuse request/access-scoped caches. Distinguish changed request/stage semantics and retain every proof-supporting response. |
| Lookup outcome, partial reasons and immutable receipt | [lookup.py](ioc_hunter/lookup.py), [evidence.py](ioc_hunter/evidence.py) | Extend existing diagnostics and accepted evidence links; do not make failures look like no-data results. |
| Selectable methods for a saved IOC | [workflow/runner.py](ioc_hunter/workflow/runner.py) `list_methods()` | Existing registry/type discovery applies. Preserve live/replay eligibility and unresolved-route controls. |
| Used flags, admission, graph merge and recovery | Workflow runner/repository/policies | Keep these decisions outside providers and transport. Reuse exact receipt IDs and transactional commits. |
| HTTP/application delivery | Existing application service, [api/schemas.py](ioc_hunter/api/schemas.py) and [Hub mirror schemas](../../src/threatmamba/api/investigation_models.py) | Expose the same saved result. Propagate new top-level wire fields through both schemas; avoid another graph store or method implementation in API handlers. |

## What the shared contracts support today

[Provider/ParsedPage](ioc_hunter/providers/base.py) define a small module-oriented
contract: source metadata, METHODS, `requests_for()`, `parse_document()`, and
observations/continuation/completeness/reason. There is no need for a new plugin
framework or one class per method.

Current single-response operations can be extended using that path:

- Add the source request/envelope mapping.
- Emit field-backed observations through ObservationBuilder.
- Reuse an existing validator branch when its semantics fit; otherwise add a
  narrowly defined new fact contract.
- Let lookup handle cache, limits, fallback, snapshots and receipts.

For example, a confirmed OTX direct URL link can use the existing `url_link`
proof. VirusTotal's explicit response filename can reuse the existing URL-details
request/cache through `content_disposition_filename()` and `url_filename()` in
providers/common.py, plus its URL-filename validator branch. The three hash
methods use one operation with browser and API envelope mappings. Missing filename
data is `filename_unavailable`; malformed or ambiguous headers remain errors.

The HTML fallback currently recognizes DNS and URL-list tables. Detail cards,
process trees and behavior lists need deliberate source parsers if they are
obtained from DOM. A regex over every IOC-looking string on a page would discard
the existing evidence boundary.

## Future scope only: dependent acquisition

Neither the hash-family report operation nor the URL response-header method
needs this extension. Some later methods may require multiple stages, for example:

- Exact-name/command search -> identified file -> relevant behavior/relationship.
- IP -> communicating files -> an individual sandbox's source/destination tuple.

The existing contracts do not yet express these joins:

- `requests_for()` is an ordered list of fallback alternatives. A successfully
  parsed first route ends selection; it does not schedule the next route.
- Browser `response_paths` are alternative acceptable responses. `fetch()`
  returns the first completed match, not a bundle of metadata and behavior.
- `parse_document()` receives one Document with no previous stage context.
- `ParsedPage.next_url` is pagination. `finish_page()` intentionally restricts
  it to the same endpoint path; a jump from search to a file is not pagination.

If a later authorized method actually needs those stages, consider a small
shared contract beside Provider/ParsedPage, executed by LookupClient. Choose its
shape from that concrete method. Do not introduce it for the current four-method
slice or duplicate lookup execution in providers.

The extension needs only responsibilities that existing mechanisms cannot
already express:

1. A provider declares or derives required/optional follow-up requests and their
   expected object/identity bindings. Provider code still does not execute them.
2. The shared executor calls the existing `_fetch()` for each acquisition, then
   snapshots the successful Document just as `_run()` does now. Failed captures
   retain existing diagnostics. Cache, pacing, budgets and retries stay shared.
3. Keep per-stage fallback alternatives separate from required dependency edges
   and same-endpoint pagination. A successful empty discovery may end a method;
   a failed mandatory identity stage must not be reported as completed empty.
4. Bound stages, candidate samples, total requests and fan-out/depth as needed by
   that plan. Existing max_pages/max_outputs and workflow max_steps do not alone
   bound a search-to-many-files chain.
5. Retain stage IDs, parent bindings, source snapshots and partial reasons in the
   exact lookup receipt. Do not hide nested work in recursive LookupClient calls.

Do not implement this by issuing requests inside `parse_document()`, calling
Playwright from a provider helper or bypassing the shared client for a special
method. Those approaches lose the common execution/accounting boundary.

## Supporting evidence and identity

Current Evidence anchors one response digest, excerpt and locator. These normal
receipts are sufficient for the first four methods: the file behavior response
is bound to the requested provider report and actual page identity, and URL
response-header evidence is bound to the URL report. Keep the existing validator
and accepted/rejected associations.

The hash-family implementation supplies the original supported digest to the
browser report and optional behavior-summary API. The browser can use the file
identity in the actual provider page for response matching. It needs no
intermediate metadata request or separate hash-provenance tracking. A different
future method may genuinely depend on
multiple responses; for example, URL body hash -> file names is not itself proof
that an alias was the filename delivered by that URL.

If a different future method genuinely requires a multi-response proof, review
its evidence needs then. The first four introduce no such format extension.
Keep older receipts readable; added JSON metadata alone would not require
replacing the database, while a genuine schema change needs versioned handling.

JSON persistence does not eliminate serialization compatibility work.
LookupRecord.from_dict constructs dataclasses from stored dictionaries, so new
receipt/evidence fields need explicit compatible models/defaults. New top-level
receipt fields also need the service and Hub Pydantic schemas updated; otherwise
the wire response can omit them. Metadata nested inside existing evidence/facts/
responses dictionaries is already carried generically where that representation
fits. Test old receipt restoration and actual service-to-Hub propagation.

Keep sample/run attribution precise. Merged behavior summaries are useful for
sample-level observations, but numeric process IDs must not be joined across
sandboxes. Use individual reports for process/event correlations. A command list
and a registry/IP list from one sample do not automatically relate every pair.
For filename-registry, a source's explicitly attributed named-sample behavior can
be a valid contract; do not attribute an extra process-trace requirement to the
paper itself.

## Search identity and operation dispatch

Current browser matching checks the expected path and pagination cursor/page,
but does not bind arbitrary search expressions. Before capturing generic search
responses, extend FetchRequest/matching to verify expected query parameters.
Provider parsers must also check query context and result types. Two different
searches sharing `/search` must not be interchangeable evidence.

VirusTotal dispatches the shared file_behavior operation before its existing
domain/URL/IP report mapping. Other future input kinds also need explicit source
operations rather than falling through to an IP object. OTX maps four fixed
operations to sections; RapidDNS selects domain or reverse-IP pages. Registering
new methods before their mappings exist would produce incorrect requests or
parser errors.

The generic transports already support bounded HTTPS GETs and JSON/text bodies.
Do not add POST/scan submission, archive downloads or another transport merely
because external documentation describes them. Start with the source operations
actually needed for the chosen method and baseline access mode.

## Verification placement

The hash-family test owner is
[test_hash_behaviour.py](tests/test_hash_behaviour.py). Checks for the browser-first
revision must cover shared digest-family routing, actual page-identity expansion,
access modes, wrong hash/host/operation, malformed fields, empty data,
deduplication and ordinary accepted evidence receipts.
The scoped header implementation is covered by
[test_url_filename.py](tests/test_url_filename.py), including usable plain/extended
filenames, absent optional data, malformed/ambiguous headers and URL identity.
These are synthetic source-shaped tests, not live verification. The remaining
rows identify relevant verification locations; a separate dated test report
records executed results.

| Concern | Existing test location to extend | Meaningful cases |
| --- | --- | --- |
| Provider output and deterministic proof | [test_lookup.py](tests/test_lookup.py), including its validator cases, and source-shaped fixtures | Positive field proof versus wrong query/sample, unrelated command/key and malformed containers; metadata co-occurrence must fail. |
| Browser response/query identity and UI completion | [test_browser_transport.py](tests/test_browser_transport.py), [test_reliability.py](tests/test_reliability.py) | Wrong search expression, delayed required response, prefetch, challenge/access outcomes and observed encoding variants. |
| Future dependent acquisition, only when needed | A focused addition alongside existing lookup tests | Correct stage order, mandatory-stage failure, cache/pacing/budget reuse, bounded fan-out, retained stage snapshots and interrupted acquisition. |
| Exact receipts and backward readability | [test_lookup_details.py](tests/test_lookup_details.py) | Compound supporting evidence, accepted/rejected mappings, partial stage outcomes and old receipt restoration. |
| Discovery and compatibility | [test_organization.py](tests/test_organization.py) | Provider declarations agree with discovery; disabled methods still make no request. Update count assertions deliberately when methods are promoted. |
| End-to-end saved result | [test_workflow.py](tests/test_workflow.py), [test_workflow_service.py](tests/test_workflow_service.py) | Output/evidence survives save/reopen/export and unchanged paper admission. No provider access in offline tests. |

[ReplayTransport](ioc_hunter/workflow/replay.py) currently checks initial route
availability. Dependent plans must not claim replay readiness just because the
search response is present while mandatory sample/behavior fixtures are absent.
Keep replay fail-closed and use the real shared lookup path.

This document records implementation scope and ownership. It does not turn
published route documentation or synthetic fixtures into live provider evidence.
The historical audit remains dated; current test/live results are recorded in the
[first-four verification report](FIRST_FOUR_METHODS_VERIFICATION.md),
[next-method verification report](NEXT_METHODS_VERIFICATION.md) and ordinary
lookup receipts.
