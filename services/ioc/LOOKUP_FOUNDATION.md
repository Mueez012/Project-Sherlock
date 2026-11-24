# Lookup foundation

Latest 10 November result: **48 implemented / 20 candidates / 68 total**;
445 tests and 252 subtests passed. The five OTX additions use one shared pulse
helper and the existing execution/evidence boundaries. Uncached live coverage
and external rate/access limits are recorded in
[the verification report](METHODS_VERIFICATION_20261110.md). The earlier
sixteen-method checkpoint below has been superseded.

10 November checkpoint: **43 implemented / 25 candidates / 68 total** after the
eight HA methods and eight original candidates were coded. **Tests and live
lookups are deferred at the user's request.** See
[the sixteen-method checkpoint](SIXTEEN_METHODS_IMPLEMENTATION.md) for module
owners, per-stage/follow-up limits and unresolved source-access/coverage gaps.
The historical execution results below do not verify this batch.

The lookup layer implements one-call IOC enrichment for ThreatMAMBA Algorithm 1.
It does **not** implement the algorithm, evaluate expansion success, increment
coverage/tried-time counters, or insert nodes/edges.

The code organization was updated on 13 October 2026. Start with
[README.md](README.md) for the current module map. Each source now owns its
method declarations, routes and result mappings in `ioc_hunter/providers/`;
HTTP and browser execution live in `ioc_hunter/transport/`. Existing public
imports and lookup commands remain compatible. `main.py` is the CLI entry point;
the integrated service also has a persisted, manually selected investigation
runner. Automatic method ranking and the remaining Algorithm 1 exploration
logic are separate work; see [WORKFLOW_HANDOFF.md](WORKFLOW_HANDOFF.md).

Historical live verification: [14 October repair results](METHOD_RELIABILITY_RESULTS.md).
During iterative checks, 17 methods returned validated outputs, three completed
with no applicable data, and VirusTotal domain-to-URL remains unresolved. The original
[13 October audit](LIVE_METHODS_AUDIT.md) is preserved. Future integrations should
follow [PROVIDER_IMPLEMENTATION_GUIDE.md](PROVIDER_IMPLEMENTATION_GUIDE.md).
Those dated checks covered the earlier 21-method implementation. They do not
establish live success for the four-method extension described below.
Current executed checks and access limits are recorded in the
[first-four verification report](FIRST_FOUR_METHODS_VERIFICATION.md).
The next OTX extension and its executed checks are tracked separately in
[NEXT_METHODS_VERIFICATION.md](NEXT_METHODS_VERIFICATION.md); it does not alter
the dates or results of the earlier audits.

## Responsibilities and graph direction

- **Method:** a directed (input type, output type, source) operation returning
  exactly a Python list of IOC objects.
- **Validator:** a separate deterministic module checking the ontology and
  relationship-specific source evidence. The lookup pipeline calls it before
  returning an IOC. This is a method/source correctness check: the selected
  method must support these concrete input/output types, and its provider fields
  must back those exact values. It can also be called independently.
- **Algorithm 1:** owns O, O_used, graph updates, history, method ranking and the
  success condition. Its chosen paper-reproduction test remains
  bool(valid_output_ids & (known_ioc_ids - used_ioc_ids)). The current IOC belongs
  in used_ioc_ids before this test. This is a candidate-overlap test, not a cycle
  detector. If reproducing the pseudocode literally, its graph updates are also
  inside that condition.

`validate_edge()` does not inspect known/used candidate sets, choose the next
method, calculate reward or admit a returned batch to the graph. The workflow's
candidate-overlap policy makes that later decision. Keeping the validator in the
lookup pipeline preserves the existing method boundary.

The paper describes **IOC–IOC edges as undirected**, labelled by their hunting
method. Domain-to-IP and IP-to-domain remain distinct retrieval methods. The
complete CSKG also contains directed temporal/TTP structure; it is not correct
to call the entire heterogeneous graph undirected. Figure 3 labels are preserved
as ontology metadata. The implementation preserves the figure's unusual spelling
of labels such as blinded and sended instead of interpreting them as new semantics.

## Use

From this directory:

~~~powershell
.\.venv\Scripts\python.exe -m pip install -e ".[extraction,browser,mcp]"
.\.venv\Scripts\python.exe -m playwright install chromium --only-shell
.\.venv\Scripts\python.exe -m ioc_hunter methods --type domain --implemented
.\.venv\Scripts\python.exe -m ioc_hunter lookup example.com --type domain --method rapiddns.domain_to_ipv4
.\.venv\Scripts\python.exe -m ioc_hunter evidence LOOKUP_ID
.\.venv\Scripts\python.exe -m ioc_hunter mcp
~~~

~~~python
from ioc_hunter import IOC, LookupClient, LookupError

client = LookupClient()
query = IOC("example.com", "domain", ["Original report passage"], "cti report")
method = client.method("rapiddns.domain_to_ipv4")
try:
    outputs = method(query)  # list[IOC], not a graph update or success score
    receipt = client.latest_record(query, method.spec.id)
    # Algorithm 1 consumes outputs and decides whether/how to update its graph.
except LookupError as error:
    receipt = client.store.get_record(error.lookup_id)
    # The algorithm decides its retry/accounting policy using receipt["status"].
~~~

An empty list is a parsed lookup with no accepted outputs. Network, authentication,
challenge, schema, unsupported-method and quota failures raise LookupError with
status and lookup_id. Check the receipt's complete flag: a list may be partial.
The receipt's `outcome_reason` distinguishes `country_unavailable`,
`all_candidates_rejected` and `no_matching_records`; `partial_reasons` explains
page/output limits, source limits and unverified browser pagination.
get_latest_lookup is a convenience for serial callers; retain the lookup ID before
starting another call for the same IOC/method. The stored receipt is immutable.

## Source adapters and limits

| Source | Implemented operation families | Access |
| --- | --- | --- |
| RapidDNS | Domain ↔ IPv4/IPv6 | Public HTML result tables, browser fallback |
| OTX / AlienVault existing operations | Domain ↔ IPv4/IPv6; Domain → URL; URL → Domain; IP → country | Browser response capture, configured official API fallback with OTX_API_KEY |
| OTX / AlienVault WHOIS and HTTP scans | Domain → email; URL → URL from a stored redirect header | Browser response capture only; official API equivalents for these two sections have not been verified |
| VirusTotal report operations | Domain ↔ IPv4/IPv6; Domain → URL; URL → Domain; IP → country; URL → URL; narrow URL → filename | Browser response capture; configured official API fallback with VT_API_KEY, except the domain-URL operation |
| VirusTotal file behavior | MD5/SHA-1/SHA-256 → command/API | Browser file behavior report and its captured per-sandbox response; optional official behavior-summary API fallback with VT_API_KEY |

Implemented means an adapter and parser exist; it does not guarantee that a source
is currently reachable or that an account has access. IPv6 methods on OTX/VT are
current documented capabilities beyond the types explicitly listed in Table I;
the catalogue marks those baseline=False. Unimplemented candidates have an explicit
unavailable_reason and cannot issue a request. The catalogue is in ONTOLOGY_METHODS.md.

Implemented definitions and disabled research candidates are listed separately.
`methods --candidates` shows the latter; `methods --implemented --availability`
reports implementation and local credential/dependency configuration without
querying providers. `live_access: not_checked` is intentional. Use
`list_runnable_methods()` when selecting implemented operations, while remembering
that installation and credentials alone do not establish live source access.

VT's domain-to-URL API relationship is documented as premium: this method uses
its website route only. The hash-family operation uses the existing browser-first,
configured-API-fallback model. A key is optional for the browser route; a supplied
key does not prove access to behavior-summary API data. The provider's account
entitlements and limits remain authoritative; credentials are supplied by the
caller/environment, not embedded in the implementation.

Default limits: 15-second source pacing coordinated across clients/processes
sharing the application store, 500 top-level retrieval attempts/source/UTC day in
that store, 25-second HTTP waits, a 30-second browser launch timeout
and separate 60-second page/result deadline, 5 pages, 1,000 unique
outputs and 5 MB/response. Browser asset/XHR traffic is not individually counted
by this local budget. Provider limits remain authoritative. HTTP network/server
failures get at most two retries; Retry-After establishes a source cooldown.
Browser result deadlines get at most one retry, with the failed capture retained.
Explicit not-found, schema and access failures are not retried as slow pages.
Browser pagination not safely exposed by a supported result route is reported
as partial. HTTP/API pagination follows same-endpoint next links within the limits.
OTX domain-to-URL supports its verified UI Next control in the original browser
session. These multi-page GUI reads start live; single-page reads may use cache.

Positive responses are cached for 24 hours; zero-observation responses are capped
at five minutes. Integration version, request credentials and a browser access-state
fingerprint isolate caches without exporting secrets. Different output methods can reuse a single DNS
response. Each logical call still receives its own receipt. Authentication failures,
loading shells and unrecognized result pages are never cached as empty results.
The integrated service defaults to output/investigations/lookups.sqlite3.
An explicit store directory or IOC_HUNTER_STORE changes that location. Existing
lookup receipts and source snapshots remain readable; the workflow repository
has its own versioned schema. The four-method extension uses the ordinary
receipt/evidence format and does not need a new store or hash-alias ledger.

Only provider URLs are opened, never the IOC's own URL. The implementation looks
up existing reports; it does not submit files, trigger scans, solve challenges,
or assume private UI endpoints grant premium access. An existing Playwright
storage-state file can be supplied to BrowserTransport(storage_state=...). Keep
that file in the ignored output directory; do not put cookies in source control.

## Validation and extraction

The validator in ioc_hunter/validation.py has no dependency on network clients,
LLMs, graph state, storage, or scheduling. It takes an input IOC, output IOC,
MethodSpec and parser-produced Evidence and returns accepted/reason/provenance.
The method registry's direction is checked independently of undirected ontology
membership. Merely mentioning two IOCs on the same page is never sufficient.

Supported field proofs include DNS records, URL host membership, explicitly bound
IP country fields, explicit URL links/direct redirects, file behavior command/API
fields, the scoped URL response-filename case, labelled OTX WHOIS emails and
stored HTTP-scan redirect headers. They reject parent
versus subdomain mismatches, A/AAAA mismatches, query echoes, wrong sources/queries,
unrelated pulse indicators, and relationships outside Figure 3. DNS MX records
are not email addresses. A redirect chain A→B→C supports the direct A–B edge when
querying A, rather than inventing A–C. These are relationships between observables,
not classifications of maliciousness or actor attribution.

New rejected-candidate entries include `message` and `details` alongside their
reason and evidence ID. DNS mismatches distinguish `dns_domain_mismatch`,
`dns_ip_mismatch` and `dns_record_type_mismatch`. A domain mismatch names the
expected and observed domain. Existing receipts retain their original codes and
remain readable without a migration.

Provider parsers form the trust boundary: Evidence.facts must come from their
field mappings, not arbitrary caller/LLM claims. The response digest, original
snapshot, scoped excerpt, locator, source and retrieval time support auditing.
The validator checks facts against the proposed endpoints; it is not a cryptographic
attestation of a remote provider or a general natural-language fact checker.

IOC keeps its four fields: value, type, context and source. Original input objects
are not modified. Evidence is stored separately so the future algorithm can merge
multi-source discoveries without discarding the original CTI context. Structured
records can be serialized as context; their full original response remains in the
snapshot. Provider observation dates are evidence attributes, not new Time nodes.

The existing report extractor still defaults to its original seven types.
--extended-types adds email and CVE using IOCFinder. extract_metadata() accepts
explicitly labelled email, filename, CVE, country_code, port and protocol fields;
these values do not automatically create graph relationships. It does not guess
filenames from arbitrary prose or turn arbitrary numbers into ports.

`extract_report(text, source=..., include_references=False, extended_types=False)`
is the non-interactive extraction API. It returns an `ExtractionResult` containing
original/retained text, excluded sections, sentences, matches and IOC objects.
It does not print or prompt. The interactive review command wraps the same
extraction stages and retains its original step-by-step behavior.

## First four methods: 9 November 2026 scope

The first extension covers these VirusTotal methods:

| Method | Source operation and output scope |
| --- | --- |
| `virustotal.md5_to_command_api` | File behavior report using the supplied MD5; configured API fallback |
| `virustotal.sha1_to_command_api` | The same operation using the supplied SHA-1 |
| `virustotal.sha256_to_command_api` | The same operation using the supplied SHA-256 |
| `virustotal.url_to_filename` | Explicit Content-Disposition filename in the stored URL response headers |

The three hash methods share one `file_behavior` implementation in the existing
VirusTotal adapter. The primary route opens
`https://www.virustotal.com/gui/file/{input_hash}/behavior` and captures its
`/ui/files/{report_hash}/behaviours` response. That response contains per-sandbox
records. With a configured `VT_API_KEY`, the ordered fallback is
`GET https://www.virustotal.com/api/v3/files/{input_hash}/behaviour_summary`.

The provider may canonicalize the file report to a SHA-256 page after navigation.
A provider-supplied `page_identity_pattern` lets BrowserTransport obtain the
hash from the actual current provider report page and expand the exact expected
response path. This does not mean accepting an arbitrary hash seen in background
traffic. The original input IOC retains its type and digest in the receipt.
There is no extra metadata GET, alias ledger or dependent-request framework.

Only the documented `command_executions`, `calls_highlighted` and `invokes`
fields supply command/API outputs. Evidence retains which field supplied each
value and sandbox record where applicable. Highlighted API calls and reflection
invocations are not relabelled as executed command lines. Empty/absent fields can
produce a completed empty response; malformed containers are parse errors. An
absent key does not disable browser acquisition. Browser failures retain their
real status; they are not reclassified as successful empty results.

An unauthenticated 9 November probe observed the SHA-256 behavior-page route and
its structured response for one sample; the capture is
[hash browser probe raw-09](output/hash-browser-probe-20261109/raw-09.json).
That route observation is separate from final production-method test results and
does not establish live success for every digest type or sample. See the
[verification report](FIRST_FOUR_METHODS_VERIFICATION.md) for the current result.

URL-to-filename reuses the existing URL-details acquisition and response cache.
Its scope is an explicit usable filename in Content-Disposition returned among
VirusTotal's stored URL response headers. It does not infer a filename from a
URL path, body hash, unrelated file alias or arbitrary report text, and does not
request the premium downloaded-files relationship or visit the input URL.
Missing optional filename data produces `filename_unavailable`; malformed,
ambiguous or path-bearing header values remain parse errors. The parser accepts
an explicit plain filename or supported extended filename encoding, preserving
its source header and locator in the normal evidence record.

Both families use the existing ObservationBuilder, IOC normalization,
`validate_edge()`, LookupClient limits/cache/retries, source snapshots and
accepted/rejected evidence receipts. The workflow still performs its separate
candidate-overlap admission test. No lookup/graph boundary is moved.

The family-specific offline contracts are in
[test_hash_behaviour.py](tests/test_hash_behaviour.py) and
[test_url_filename.py](tests/test_url_filename.py). Synthetic fixtures and
offline assertions establish implementation behavior, not live provider access.
The historical October audit counts above remain unchanged; a new dated receipt
is required before claiming live success for any of these four methods.

## Next two methods: OTX WHOIS and stored HTTP scans

The next batch uses two additional sections of the existing OTX indicator pages:

| Method | Source scope | Source-local parsing owner |
| --- | --- | --- |
| `alienvault.domain_to_email` | Concrete contact email values explicitly listed in the queried domain's WHOIS rows | [otx_whois.py](ioc_hunter/providers/otx_whois.py) |
| `alienvault.url_to_url` | A stored scan's 3xx HTTP response and its Location target for the queried URL | [otx_http.py](ioc_hunter/providers/otx_http.py) |

WHOIS acquisition captures the domain page's
`/otxapi/indicators/domain/whois/{domain}` JSON. The parser reads labelled
`email`/`emails` rows from its `data` array, retaining the domain, exact source
field, value, locator and response digest. It ignores unrelated fields and the
separate related-domains collection. Redacted or malformed individual mailbox
values are not concrete IOC outputs.

The output contract is the source's listed WHOIS contact association. A contact
mailbox does not need to use the queried domain as its email host. The lookup
does not add ownership, maliciousness or confidence filters: contacts at a
registrar or privacy service remain valid outputs when explicitly listed in the
queried WHOIS response. The validator checks method/source correctness against
those fields; the workflow makes its existing separate graph admission decision.

URL-to-URL uses the URL indicator page's `http_scans` response. Its source-local
helper parses only a stored HTTP header record with a 3xx status and a Location
value. Body URLs, certificate links, pulse indicators and arbitrary page links
are outside that operation. It does not visit the input URL or redirect target.

Both new sections are browser-primary with no declared official API backup.
Their API equivalents have not been verified, so an OTX key does not cause the
adapter to guess new API endpoints. The four established OTX operations keep
their existing configured API fallbacks.

Routes and envelope dispatch remain in `alienvault.py`; source-specific WHOIS
and HTTP parsing live in the two small helpers above. They reuse ObservationBuilder,
IOC normalization, the existing validator, transports, limits, cache and normal
receipts. No generic acquisition framework or graph-policy change is needed.
See [NEXT_METHODS_VERIFICATION.md](NEXT_METHODS_VERIFICATION.md) for recorded test
and live outcomes; source probes alone do not establish production readiness.

## Optional LLM-generated context

Pass a context_generator callback to LookupClient. It receives the target IOC and
only its already-validated evidence excerpts, and must return ContextDraft with
text and Citation(evidence_id, exact_quote) entries. The generated annotation is
labelled separately and appended to the raw evidence context. Unsupported citations
are rejected; model failures retain the validated IOC and its raw context.

The callback type is Callable[[dict], ContextDraft]; it can wrap the model client
you choose without coupling the validator to that provider.

Exact citations prove traceability, not the truth of every generated sentence.
LLM text never changes the ontology, validates an edge, or rewards a method.
No model client is configured or called by default. Method outputs are useful
without an LLM. The MCP interface enables an external model to read evidence too.

## MCP

The optional MCP SDK is pinned to its v1 API family (mcp>=1.12,<2). The stdio server
registers list_methods, lookup_ioc, get_latest_lookup and get_lookup_evidence.
lookup_ioc returns the same list as direct Python calls. Evidence/diagnostics are
retrieved separately rather than changing method output shape. MCP is a transport
wrapper, not the scraper or validator. Start it with python -m ioc_hunter.mcp_server.

## Validation evidence (10 October 2026)

All 62 tests pass, including the original extraction regressions, standalone
validation, parsing, caching, error handling, an actual MCP stdio handshake, and
Chromium tests with intercepted network responses. pip check also passes. Tests
use explicitly synthetic fixtures matching documented response shapes, plus a
captured public RapidDNS table. These do not establish that all account-dependent
routes currently work. Live smoke checks are opt-in:

~~~powershell
.\.venv\Scripts\python.exe -W ignore::DeprecationWarning -m unittest discover -s tests
.\.venv\Scripts\python.exe tests/live_lookup_smoke.py rapiddns
.\.venv\Scripts\python.exe tests/live_lookup_smoke.py alienvault
.\.venv\Scripts\python.exe tests/live_lookup_smoke.py virustotal
~~~

Live RapidDNS domain→IPv4 returned 21 unique values for example.com and rejected
subdomain rows. It reported partial because of the guest-access restriction.
After adding support for the current website response route, anonymous VirusTotal
domain→IPv4 returned 6 validated values; it also reported partial because more
results were available beyond the captured page. These checks verify those two
method routes, not every method in either source. OTX still returned a loading
page and raised loading_page rather than returning an empty success. Its website
route remains unverified. API-key fallback routes have not been live-tested.
Do not present the synthetic fixtures as provider-success evidence.

Reliability verification (14 October 2026): all 90 tests pass. See
[repair results](METHOD_RELIABILITY_RESULTS.md) for the live evidence and remaining
work. Organization verification (13 October 2026): all 72 tests passed, including the
existing extraction, lookup, intercepted-browser and MCP stdio checks plus the
new extraction/discovery/diagnostic compatibility cases. A comparison with the
pre-refactor code preserved all 60 method definitions and request/parsed-evidence
results for fixtures covering the 21 implemented methods. Package discovery and
`pip check` pass. No new live provider check was made for this refactor.

## References

- Local ThreatMamba.pdf, pages 3–6: MCP, Table I, Figure 3 and Algorithm 1.
- https://rapiddns.io/help/api
- https://docs.virustotal.com/reference/public-vs-premium-api
- https://docs.virustotal.com/reference/domains-object
- https://docs.virustotal.com/reference/resolution-object
- https://docs.virustotal.com/reference/url-object
- https://docs.virustotal.com/reference/ip-object
- https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/IndicatorTypes.py
- https://playwright.dev/python/docs/network
- https://github.com/modelcontextprotocol/python-sdk/tree/v1.x
- https://docs.strangebee.com/cortex/api/how-to-create-an-analyzer/
- https://www.misp-project.org/tools/
