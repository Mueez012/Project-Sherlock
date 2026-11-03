# Method reliability and coverage backlog

Updated: 14 October 2026. These are future tasks, not completed features.
This backlog covers provider lookup, parsing and relationship validation after
report IOC extraction. Workflow and Algorithm 1 work have a separate
[implementation plan](WORKFLOW_IMPLEMENTATION_PLAN.md).

## Current baseline

- 21 implemented methods; 39 disabled research candidates.
- 17 methods returned validated outputs during iterative live repair checks.
- Three completed with no applicable data for the tested inputs: OTX
  IPv6-to-domain and VirusTotal IPv4/IPv6-to-country. Positive enrichment remains
  unconfirmed in this repair sample for these three methods.
- VirusTotal domain-to-URL remains unresolved. Do not automatically select it
  as a verified live route.
- 90 offline tests passed after the functional repairs. This is not a live
  reliability percentage or a repeated final-version certification.
- The real CTI report test exercised all eight domain-input methods using the
  actual extracted `mypiltow.com` IOC: 38 method-specific validated connections,
  representing 29 distinct IPv4 outputs. No persistent graph was created.

Evidence: [repair results](METHOD_RELIABILITY_RESULTS.md),
[CTI report test](CTI_REPORT_LOOKUP_TEST.md). Keep original failed receipts.

## Sprint 1: Readiness and repeatable verification

- [ ] Add per-method readiness records separate from `implemented` and local
  configuration checks. Record integration version, access mode, checked time,
  input, receipt IDs, positive/empty/error outcomes and coverage limitations.
  **Done when:** workflow selection can distinguish verified, unconfirmed and
  unavailable routes, and a stale result is not presented as current access.
- [ ] Build a small fixed regression set from real CTI reports containing
  domains, IPv4, IPv6 and URLs, preserving extraction context and report digests.
  Include positive controls and legitimate empty cases; do not invent expected
  current provider data from historical report claims.
  **Done when:** every implemented direction has documented test inputs and an
  explicit gap where no suitable positive control has been found.
- [ ] Run the accessible method matrix on the same final code version in
  multiple paced sessions. Retain every attempt, including retries and failures.
  **Done when:** a report lists per-method attempts, validated outputs, completed
  empties, errors, latency and partial coverage, with raw evidence links and a
  clear denominator for any success rate.
- [ ] Verify positive examples for OTX IPv6-to-domain and both VirusTotal
  country methods where provider data exists.
  **Done when:** captured evidence demonstrates positive mapping, or readiness
  records explicitly retain the lack of positive confirmation.

## Sprint 2: Remaining routes and result coverage

- [ ] Investigate VirusTotal domain-to-URL through the paper's GUI route:
  required tab interaction, response paths and access restrictions.
  **Done when:** either a live positive result has supporting regression tests,
  or the route has an evidence-backed unavailable/unconfirmed classification.
  Do not infer GUI access from the official API subscription requirement alone.
- [ ] Verify VirusTotal pagination through observed UI controls in the same
  browser session; test page identity, duplicates, limits and later-page failure.
  **Done when:** verified pages contribute outputs and incomplete coverage always
  remains partial. Do not request captured private next URLs directly.
- [ ] Inventory pagination and guest limits for every operation, including
  RapidDNS. Extend OTX URL pagination checks to final-page completion and failure.
  **Done when:** each operation documents its reachable coverage, stopping rule
  and explicit partial reason; restricted data is not represented as exhaustive.
- [ ] Test optional official API fallbacks when credentials are available.
  **Done when:** authentication, permissions, schema mapping, fallback order,
  pagination and rate-limit behavior are tested and access modes are reported
  separately. Website routes remain primary; lack of credentials stays visible
  as untested, not failed or verified.

## Sprint 3: Reliability for sustained workflow use

- [ ] Coordinate provider pacing and cooldowns across lookup clients/workers
  before enabling independent concurrent workers.
  **Done when:** a provider 429 pauses all relevant work for its cooldown and
  retries cannot multiply requests across clients. Begin the workflow with one
  worker and shared clients/limits.
- [ ] Extend regression coverage for observed challenge/login pages, schema
  drift, interrupted bodies, transient errors and later-page failures.
  **Done when:** each has a bounded, inspectable outcome; unknown pages never
  become successful empty results. Preserve the existing timeout/429 tests.
- [ ] Add opt-in, paced provider contract checks with versioned captured fixtures.
  **Done when:** route/schema changes produce an actionable readiness change and
  diagnostic receipt without rewriting historical evidence or silently relaxing
  relationship validation.
- [ ] Define freshness and revalidation rules for method readiness and cached
  observations; report retrieval time separately from provider observation time.
  **Done when:** historical DNS evidence is not presented as current DNS or as
  proof of involvement in the original incident.

## Later sprints: New methods

- [ ] Prioritize the 39 disabled candidates by ontology support, available
  source fields, access requirements and usefulness to investigations.
- [ ] Implement one source/operation at a time using the
  [provider implementation guide](PROVIDER_IMPLEMENTATION_GUIDE.md).
- [ ] Require request/response identity binding, deterministic relationship proof,
  malformed/unrelated/empty/partial fixtures and retained live evidence before
  promoting a candidate to verified readiness.

These candidates are research possibilities, not 39 proven provider features.
Do not enable them merely because their IOC type pair is ontology-compatible.

## Boundary with the upcoming workflow

The backlog does not block a deterministic offline workflow or a bounded live
pilot with explicitly selected, previously verified methods. Selection must
still handle present-day access failures and partial results. An automatic
runner needs readiness filtering; multiple workers need shared rate controls.
Method outputs remain `list[IOC]`, validation remains separate, and expansion
evaluation and graph updates belong to workflow policy. An accepted relationship
is neither a maliciousness verdict nor proof that a new graph edge was added.
