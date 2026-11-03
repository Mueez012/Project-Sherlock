# Method reliability: findings and repair plan

Date: 14 October 2026. Status update: core acquisition, parsing, classification,
cache and diagnostic fixes have been applied. See [verification results](METHOD_RELIABILITY_RESULTS.md)
for live outcomes and explicit remaining work, and [the provider guide](PROVIDER_IMPLEMENTATION_GUIDE.md)
for future implementation practices. The original analysis and broader sequence
below are retained; OTX URL pagination is now implemented and live-verified.
Remaining work includes VirusTotal pagination and its unresolved domain-to-URL
access route. A [real CTI extraction-to-lookup test](CTI_REPORT_LOOKUP_TEST.md)
also verifies the path with a report-derived IOC.

The main problem is a combination of incorrect response matching, premature page readiness, incomplete provider parsing, and access/error classification. Increasing the browser timeout alone will not repair these routes. This plan preserves website-first lookup, separate evidence validation, and algorithm-owned expansion evaluation.

## What is actually verified

The [13 October audit](LIVE_METHODS_AUDIT.md) tested all 21 implemented methods: 10 returned validated outputs for at least one input (RapidDNS 4, VirusTotal 6, OTX 0). The 72 passing offline tests demonstrate behavior on existing fixtures, not reliable compatibility with current websites. The other 39 catalogue entries remain disabled candidates.

For this investigation, five report pages were traced independently of production readiness logic, using anonymous browser sessions and a 60-second observation window after navigation. VirusTotal IPv6 was repeated to verify response bodies. These are diagnostic samples, not a rerun certifying all 21 methods. Existing reports were read; no scans were submitted or IOC websites visited.

Artifacts: [diagnostic index](output/route-analysis-2026-10-14/README.md), [diagnostic script](output/route-analysis-2026-10-14/trace_routes.py). API-key fallbacks remain untested.

## Findings and evidence

| Finding | Evidence and confidence | Consequence |
| --- | --- | --- |
| Browser stops for an unrelated table | Confirmed in `transport/browser.py`: any `table tbody tr` ends the wait. OTX captures contain WHOIS rows while DNS/URLs are still loading. | We can capture an unfinished requested section. This does not explain every failed method. |
| OTX website responses do not match our listener | Confirmed live for domain URLs: expected `/api/v1/indicators/domain/example.com/url_list`; received HTTP 200 from `/otxapi/indicators/domain/url_list/example.com` around 21 seconds after starting the diagnostic. | The desired JSON arrives but is ignored. Public API and website routes need distinct definitions. Other operations require their own verified mappings. |
| OTX HTML can report a false empty | Confirmed code defect and previous capture: spinner outside the table, zero rows and “No Entries Found” coexist. The parser only detects loading text inside rows. | The algorithm could incorrectly treat an unfinished request as no useful result. |
| OTX DNS HTML headers differ | Confirmed saved header is `Query Type`; parser accepts only `Type` / `Record Type`. | A fully rendered DNS table can still fail recognition. |
| VirusTotal IPv6 path encoding differs | Confirmed live: UI sends `/ui/ip_addresses/2606:4700:4700::1111/resolutions`, while our listener expects `%3A` in place of colons. HTTP 200 responses arrived and did not match. The same encoding issue applies to the base-object path used by country lookup. | Waiting longer does not make an exact string comparison match. Canonicalize the typed object identity, keeping host and operation checks strict. |
| VirusTotal domain-to-URL remains unverified | In the longer trace, resolutions and other relationships loaded, but no `/urls` response was observed. | Could require a different UI action or unavailable feature. Do not declare it a timeout bug or invent an empty result. |
| Some “loading” cases hide rate limiting | Subsequent OTX IPv6 and URL pages received HTTP 429 from `/otxapi/env`; URL general also returned 429. Our listener ignores endpoints outside its expected result paths. | A blocked bootstrap can prevent rendering while our receipt says loading. These samples do not prove whether the underlying enrichment operation works. |
| OTX URL encoding needs a separate test | URL trace issued `.../url/general/http%253A%252F%252Fexample.com%252F` from the currently encoded GUI URL; response was 429. | Double encoding is observable, but correctness cannot be decided from a rate-limited response. Test the GUI routing contract after cooldown. |
| Country may be absent | Previous VirusTotal `1.1.1.1` response was HTTP 200 with no country field; `8.8.8.8` had supported country data. The new `2606:4700:4700::1111` IP object also lacks country. | Fixing IPv6 response matching does not guarantee a country output. Missing enrichment and malformed response schema need different outcomes. Do not manufacture a country. |
| Pagination/completeness is incomplete | `lookup.py` stops when a browser response has a next page, even with `max_pages > 1`. Generic HTML parsing only recognizes a narrow next-link pattern. | Available relationships may be omitted. OTX's loaded 10-row HTML was incorrectly marked complete by a replay, despite lacking a verified end-of-results signal. |
| Browser error detail is lost | Matching HTTP errors retain only status, dropping `Retry-After`; response-body exceptions are swallowed. Bootstrap failures are not classified. | Retry/cooldown decisions and diagnosis are unreliable. |
| Cache can perpetuate the wrong result | Cache is populated after parsing, including falsely empty HTML. Cache identity lacks provider/parser version and authenticated browser context identity. | Fixed logic needs cache-version isolation; guest and authenticated results must not mix. Preserve old audit snapshots. |

Replaying the newly loaded OTX domain-URL HTML through the existing parser and validator produced **10 candidate URLs, of which 4 passed validation** for the exact `example.com` hostname. The other URLs named subdomains. This supports the feasibility of the route, but does not mark the unchanged production method as repaired. These returned URLs were not visited.

Replaying the verified VirusTotal IPv6 DNS JSON produced **two validated domains** for `2606:4700:4700::1111`. Replaying its base IP object for country still raised `Missing country field`. These two outcomes show why acquisition repair and missing-data classification are separate tasks. The diagnostic index discloses an initial exporter filename collision; ambiguous body files were excluded from schema assertions and the IPv6 capture was repeated with corrected filenames.

An additional evidence-quality review is needed for URL redirects. `url_details()` currently falls back from an absent/empty redirect chain to `last_final_url`. A final destination alone does not establish that it is the immediate next hop. Verify the intended ontology semantics and provider chain ordering; retain only relationships justified by the fields. VirusTotal documents the chain and final destination separately. [VirusTotal URL schema](https://docs.virustotal.com/reference/url-object)

## What established tools suggest

- **Source-specific structured enrichment:** MISP's VirusTotal module uses `vt.Client`, object-specific parsers and bounded relationship iterators, then maps fields into MISP objects/references. We should adopt explicit field mappings and limits while retaining our own ontology. [MISP VirusTotal module](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/virustotal_public.py)
- **Website endpoints are a separate integration:** MISP's OTX module contains `/otxapi/indicator/...` calls. Our current live trace uses `/otxapi/indicators/...` and different route ordering. The useful lesson is structured provider data; copying old endpoint strings would introduce another compatibility problem. [MISP OTX module](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/otx.py)
- **Wait for the requested result:** Playwright supports observing responses and registering a response wait before the triggering action. Its documentation discourages using `networkidle` as a readiness test. Register listeners first, then wait for the relevant completed response or verified section state. [Network events](https://playwright.dev/python/docs/network), [page load states](https://playwright.dev/python/docs/api/class-page#page-wait-for-load-state)
- **Capabilities and access must be explicit:** The OTX SDK enumerates valid sections by IOC type. VirusTotal documents domain `resolutions` as available to everyone and domain `urls` as Enterprise-only through the documented relationship API. That does not establish the anonymous GUI's behavior; test and label that independently. [OTX indicator definitions](https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/IndicatorTypes.py), [VirusTotal domain relationships](https://docs.virustotal.com/reference/domains-object)

Recommendation: keep website-first acquisition for this project. Prefer the relevant JSON response emitted by the UI, with a section-specific HTML fallback. Keep official API fallback optional and credential/entitlement-aware. MCP remains an interface to the lookup service; it does not solve loading, parsing or access failures.

## Proposed implementation sequence

### 1. Describe and verify each source's acquisition contract

Keep method declarations and source-specific logic in `providers/alienvault.py`, `providers/virustotal.py`, and `providers/rapiddns.py`. Each operation should define:

- GUI URL and any required section activation.
- Accepted website response routes, separately from official API routes.
- Typed IOC identity and response schema checks.
- Result container, loading/empty/error indicators, and pagination mechanism.
- Supported access mode and an integration version.

Match provider host, operation, HTTP method, IOC identity and relevant page/cursor. Canonicalize IPv6 identities using the IP parser. Do not globally decode arbitrary URL paths or accept a broad `**/api/**` match. A 401 from VirusTotal `/ui/me` is normal in an anonymous session and must not invalidate an independently accessible DNS response.

Start with the confirmed OTX domain-URL and VirusTotal IPv6 defects. Then trace OTX DNS, IPv4/IPv6 country and URL details individually after the source cooldown. Explicitly resolve OTX URL encoding and section activation. Do not guess all eight OTX mappings from one working example.

### 2. Replace generic readiness with a bounded result lifecycle

Keep browser mechanics in `transport/browser.py`; providers supply readiness rules through a small extension to `FetchRequest` or a provider browser adapter.

```text
register response listener -> open report -> activate requested section
    -> relevant response completes -> schema/identity validation -> parse
    -> scoped HTML is conclusively ready -> parse that section
    -> explicit blocked/error state -> classified failure
    -> deadline expires -> incomplete/timeout, never successful empty
```

Use a configurable overall deadline (initial proposal: 60 seconds), with every navigation, click and body read bounded by remaining time. Return promptly when ready. The diagnostic's fixed wait is for investigation, not the production design. Do not replace the current bug with an unconditional sleep or whole-page network-idle wait.

HTML emptiness requires a verified requested section, absence of its loading state, and a provider-specific completed-empty signal. If this cannot be proved, classify the capture as incomplete. Detect relevant bootstrap failures, while ignoring unrelated optional widgets.

### 3. Normalize provider responses without weakening validation

Provider adapters should translate their supported UI/API schemas into existing observations with exact locators and raw provenance. Shared helpers remain for normalization; avoid adding every site's UI detail to `common.py`.

Fix OTX's DNS header mapping and restrict HTML parsing to the requested section. Distinguish:

| Outcome | Meaning for the caller |
| --- | --- |
| Data returned | Provider returned records; candidates still require validation. |
| Confirmed no data | The requested operation completed with no applicable records or an explicitly absent optional attribute. |
| All candidates rejected | Retrieval completed, but none proved the exact proposed relationship; keep reasons/counts. |
| Partial | Some verified data is available; additional results may exist or a later page failed. |
| Loading/timeout, schema error, access denied, rate limited | Retrieval did not establish a successful empty answer. |

Preserve `IOC -> list[IOC]` for method callers, with these distinctions in the lookup receipt and existing error mechanism. Country omission becomes a named no-data reason only after validating the IP object and identity; a missing object envelope remains a schema error. Review redirect semantics and correct evidence locators alongside the response mappings.

`validation.py` remains independent. It checks ontology and evidence; the algorithm later decides whether a validated result adds a new graph edge. Repeated evidence for an existing edge is not automatically a successful expansion.

### 4. Make retries, cooldowns and diagnostics trustworthy

Record requested operation, expected/observed route, timings, terminal state, body-read errors, response status, attempt number and raw snapshot references. Retain useful failed-page captures, with credentials/cookies excluded from exported diagnostics.

Use at most one additional attempt for classified transient loading/network failures initially. Do not retry schema mismatches, confirmed emptiness, login requirements or forbidden operations as though they were slow pages. Preserve `Retry-After`; a 429 sets a shared source cooldown and stops the current source batch. Apply an overall attempt/time budget so fetch retries and route fallback cannot multiply without bound.

One GUI navigation can generate many provider requests. Existing local budgets count logical fetches, not all website XHRs; document this and measure request volume. Reuse a source session within a bounded batch where appropriate. Sharing a captured domain report between IPv4 and IPv6 parsing should be versioned and access-scoped, with separate method receipts.

### 5. Retrieve additional pages and correct completeness/cache behavior

Implement each provider's next-page action in the same browser session, with a listener installed before the action. Support only observed, permitted navigation. Follow documented API pagination for authorized API routes.

Keep page/output/time limits, deduplication and strict IOC/endpoint checks. Repeated cursors, disabled next controls, failed later pages and access caps need explicit handling. Hitting any limit produces `partial`, with the reason. A first page containing rows does not establish completeness.

Version cache keys by acquisition/parser contract and isolate access contexts without storing secrets. Cache only verified usable results; use a shorter TTL for confirmed no-data. Keep historical receipts/snapshots intact and ensure old ambiguous entries are not served under the new version.

### 6. Verify before enabling automatic expansion

Add meaningful regressions using minimized, sanitized copies of the observed responses and browser-controlled delayed responses:

- WHOIS appears before DNS/URLs; requested data arrives later.
- Spinner plus empty placeholder never produces confirmed empty.
- Actual OTX website paths and `Query Type` headers.
- IPv6 encoded/unencoded paths match the same IP, but another IP or operation is rejected.
- Completed empty, missing country, malformed object, all-rejected candidates and partial pagination remain distinct.
- Bootstrap 429 and result 429 preserve cooldown; unrelated anonymous `/ui/me` 401 does not block accessible data.
- Multi-page deduplication, bounded retries, stale cache isolation, and direct versus multi-hop redirect evidence.

Then rerun all 21 methods with fresh cache and retained raw outputs. For each accessible route use at least two distinct relevant inputs, repeat on separate runs, and exercise positive and no-data behavior where the provider supports those samples. Record failures rather than retrying silently until one passes. Use controlled browser tests for rare failure states; no need to provoke live rate limits deliberately.

Publish a per-method matrix separating **implemented**, **offline tested**, **live positive**, **live confirmed empty**, **partial**, **access blocked**, and **unverified**, including access mode, date, inputs, attempts and evidence links. API fallbacks are a separate test matrix when credentials are available.

Acceptance is not “every call returns an IOC.” It is: supported routes return evidence-backed data or a truthful terminal outcome; no false empties; no unrelated response accepted; pagination/access limits are visible; regressions pass. Mark a route ready for automatic use only within its verified access mode. Keep inaccessible/unverified routes excluded until resolved.

## Expected effect on the graph and remaining limits

Correct OTX acquisition and VirusTotal IPv6 matching should recover relationships currently missed; pagination should increase coverage where access permits. The new OTX HTML replay already demonstrates additional valid candidates without relaxing validation. Exact graph growth remains unknown until repaired routes pass the live matrix.

RapidDNS's rejected subdomain rows are not a retrieval bug: they do not prove an edge for the exact queried domain. Keep those rejections. New IOC types, the 39 candidate methods, algorithm selection/reward, graph persistence and the web workflow remain separate work.

We can repair our code, but cannot guarantee anonymous access to all 21 methods. VirusTotal domain-URL access and unresolved OTX routes must be settled by current evidence, not by promising that a longer wait will work. Proceed to the workflow using the verified set, with explicit handling for unavailable providers.
