# IOCHunter Algorithm 1: limitations and practical improvements

Research date: **6 November 2026**. Status: **proposal for evaluation; not implemented or adopted**.

## Recommendation

Start with **bounded exploration of provisional IOCs and reconsideration of their
saved evidence when later queries connect them to report IOCs**. Then investigate
delayed credit for the queries that supplied those useful paths. This addresses
a specific restriction in Algorithm 1: a new-only batch cannot make its returned
IOCs eligible for exploration. A later qualifying batch could still admit them.
The optional credit phase would
replace the single batch-hit signal with a more selective measure of what the
queries contributed.

**Uniqueness is not required for this project decision.** Adapting an established
method is worthwhile if it fixes a concrete restriction and performs better on
our investigations. The practical goal is more useful evidence per acquisition
budget, with understandable admission decisions.

This is a plausible project improvement, **not an established novelty claim**.
Bandit-based threat hunting, guided graph expansion, temporal filtering,
provenance and adaptive infrastructure pivoting already have close precedents.
The research opportunity is the precise admission and credit policy, and whether
it improves results under a fixed acquisition budget. The literature review below
did not establish that nobody has proposed the same policy.

Keep the literal paper policy as a reproducible baseline. The settled reading and
historical implementation example are in
[IOC_INCLUSION_REFERENCE.md](IOC_INCLUSION_REFERENCE.md).

### Practical implementation priorities

| Priority | Improvement | Why it comes here |
| --- | --- | --- |
| First | Bounded provisional frontier and reconsideration of previously validated observations | Directly addresses the new-only exploration restriction, without immediately admitting every neighbor. Start with deterministic selection. |
| Alongside the first experiment | Incident-time checks and shared-infrastructure ambiguity flags | Addresses the risk of expanding old hosting associations into a large current co-hosting graph. Unknown dates remain visible. |
| Next | Availability-aware selection and actual request-cost accounting | Avoids repeatedly choosing an unavailable or rate-limited route and makes comparisons fair. This is useful engineering even without a new learning algorithm. |
| Optional research phase | Delayed path credit driving automatic method selection | Tests whether a finer reward improves selection beyond the simpler frontier. It adds complexity and is not necessary to start the practical improvement. |

The detailed proposal below includes the optional phase so the intended
algorithm and evaluation remain reviewable. It is not a requirement to build all
of it at once. The multi-anchor limitation applies to the path-credit objective;
bounded provisional exploration itself can also operate in a single-seed case.

## Baseline and scope

The primary local source is [ThreatMAMBA](../../../../ThreatMamba.pdf), especially
Algorithm 1 on PDF page 6 / IEEE page 4391. Its relevant behavior is:

1. Start with report IOCs in a mutable candidate set `O`.
2. Mark the current IOC used before looking it up.
3. Rank compatible methods from their coverage/tried histories, shortlist up to
   50, and ask IOCHunter-LLM to select methods. Allow five rounds per selected IOC.
4. For each selected method, obtain `O_prime`.
5. If `O_prime` contains any member of `O - O_used`, add **all** of `O_prime` and
   every input-output edge. Increment that method's coverage counter by one.
6. Increment its tried counter irrespective of that overlap condition.

Coverage is therefore a count of successful batch-overlap events, not a count of
independently corroborated edges, relevant discoveries or correctly attributed
actors. The algorithm does not perform reciprocal confirmation or cycle
detection.

Our current terminal workflow implements manual selection and that admission
gate, with a separate provider-field validator and persistent receipts. It does
**not** implement the automatic method ranking, LLM selection or coverage/tried
counters. The current `reward: null` is deliberate. None of the proposed policy,
reward, graph views or data fields below exist merely because they are described
here.

The observations below concern the **IOC acquisition/admission algorithm**.
ThreatMAMBA has temporal and semantic machinery elsewhere; this is not a claim
that its complete attribution framework ignores time or context.

## Specific shortcomings worth testing

### 1. New-only results can hide an evidence path

Suppose the report contains `A` and `B`:

```text
query A -> {X}       X is new, so the batch fails the overlap gate
query X -> {B}       this query is unreachable through the printed candidate set
```

There could be a supported `A--X--B` path, but the first observation cannot open
the next investigation step. Even `query B -> {X}` would fail if X never entered
`O`. This follows from the set condition; it does not require a failed live
provider or prove that the paper's implementation is incorrect.

There is also a case requiring no extra pivot: saved lookups `A -> {X}` and
`B -> {X}` can jointly support the candidate path `A--X--B`, even though neither
batch admitted X. Reconsidering saved observations can expose that structure
without a new provider request. Incident relevance still needs the safeguards
below; shared-IP identity alone does not establish a common attack.

The gate also excludes previously used endpoints. Query order can therefore
affect admission even when the same observable relationship is available. Used
state is a sensible scheduling device, but it is not evidence that a relationship
is false.

### 2. One overlap admits every other output

For `query A -> {B, X, Y, Z}`, known-unused B opens the gate for all four
relationships. Evidence may validly support every relationship, while X, Y and Z
still have little relevance to the incident. Valid DNS association, incident
relevance and actor ownership are different claims.

The investigation's `.holiday` example demonstrates this distinction: one
report-IP overlap admitted three other addresses, including historical addresses.
This was the specified baseline behavior, not proof of a wrong relationship.
Subsequent reverse-IP results from a historical address were large and did not
match the current graph. Those observations motivate time and shared-hosting
controls; they do not establish that every result was irrelevant or malicious.

### 3. Binary coverage provides coarse method feedback

Algorithm 1 awards one coverage increment to a passing batch, whether it creates
one useful connection or brings in a large amount of unrelated infrastructure.
It gives no delayed credit when an earlier new-only result later becomes useful.
Its per-method history is global rather than a learned estimate conditioned on
the individual input's incident context or infrastructure characteristics.

This is an objective mismatch to investigate, not evidence that a contextual
learner will automatically outperform the paper.

### 4. Acquisition quality and cost need explicit treatment

The printed gate does not specify how rate limits, missing browser runtimes,
partial pages, cached repeats or unequal provider-request costs should affect
learning. A 429 is not a confirmed empty relationship set; a capped reverse lookup
is not exhaustive; replaying the same snapshot is not fresh corroboration.

The current workflow already retains operational outcomes and provenance. The
remaining research issue is how an automatic policy uses them. Comparing methods
by logical lookup count alone can hide different page, retry, latency and quota
costs. These are engineering and evaluation gaps in the abbreviated pseudocode,
not proof that the authors mishandled their experiments.

### 5. Literal reproduction needs a documented cold start

The exploration term contains `log(sum(T_n))`. At initialization every tried
counter is zero. The denominator's `1e-6` does not define `log(0)`. A reproduction
must state its initialization rule, such as sampling each available method first
or using a documented finite initialization. It must also state the exploration
coefficient and deterministic tie-breaking. These are reproducibility details,
not the proposed research contribution.

## What existing research already covers

The distinctions in the last column are our reading of the sources, not claims
that each paper exhaustively rules out a related extension.

| Primary source | Relevant established idea | Consequence for our proposal |
| --- | --- | --- |
| [MABAT, TIFS 2023; published online October 2022][mabat] | Budgeted targeted threat-hunting collection with shared-arm bandits and information shared across attack hypotheses. Section VII-B assumes unit cost for each pull. | Applying a bandit to threat hunting is already established. Our provider frontier, evidence admission and unequal acquisition costs would need their own definition. |
| [Bandit on the Hunt, April 2025 preprint][threatcrawl] | Uses SBERT relevance and UCB1 to adapt CTI document crawling across search strategies. | Adaptive exploration plus semantic relevance is not sufficient novelty. Its search objects are documents, rather than the exact IOC relationships admitted here. |
| [MANTIS, February 2025 preprint / S&P 2025][mantis] | Guided passive-DNS graph expansion addresses shared hosting and selects recent resolutions; its design evaluates graph depth and expansion rate. | Bounded DNS expansion and time-aware noise reduction have direct precedent. Its main task is malicious-domain detection, rather than recovering report-anchor paths through provider queries. |
| [TITAN, November 2024 preprint][titan] | Dynamic CTI graphs use relationship decay, expiration/pruning and reputation propagation. | Time decay and weighted graph propagation alone would be weak novelty claims. |
| [CARIOCA, March 2025][carioca] | Prioritizes MISP IoCs using source reliability, report quality and freshness. | A weighted confidence/context/age score is already closely covered; this work ranks collected indicators rather than controlling our acquisition frontier. |
| [FeedRank, CyCon 2018][feedrank] | Ranks CTI feeds using their contributions and correlation structure. | Source overlap and reuse have existing research treatment. Two providers must not be assumed independent simply because their names differ. |
| [PhishLumos, IEEE Access, May 2026][phishlumos] | Adaptive infrastructure pivots, a property-graph knowledge base and provenance support campaign investigation; its published description includes bounded orchestration. | Adaptive pivots, auditable merging and infrastructure-based campaign discovery are especially close prior art. A separate [author preprint][phishlumos-preprint] also describes correlated evidence and an inconclusive classification. |
| [Selective Harvesting over Networks / D3TS, March 2017 preprint][d3ts] | Selects queries on a partially observed graph frontier under a budget, using bandits and classifier diversity to mitigate exploration bias. | Frontier search and bandit-guided discovery are not new in themselves, including outside cybersecurity. |
| [Contextual Bandits with Knapsacks, COLT 2016][cbwk] | Context-dependent rewards and multiple resource budgets are established bandit formulations. | Adding query cost or input context to a UCB-like score is not a new learning principle. |
| [Online Learning under Delayed Feedback, ICML 2013][delayed] | Studies learning when feedback arrives after the originating decisions. | Delayed feedback is established. Our candidate contribution is the particular graph-derived credit assignment, not the general idea of delayed rewards. |

The 2025 *Bandit on the Hunt* paper and the earlier
[2023 ThreatCrawl preprint][threatcrawl-earlier] are distinct records. The dates
above identify the specific versions consulted, not claims about the first
appearance of every underlying idea.

## Proposed mechanism

### Separate observations, exploration and admission

Use the existing field-level evidence validator as the first gate. An output
that fails the exact endpoint, operation or provenance checks never becomes an
exploration edge. An accepted provider observation still does not establish
maliciousness or common ownership.

Define three separate objects for the experimental policy:

| Object | Contents and purpose |
| --- | --- |
| Observation graph | All retained, field-validated relationships within acquisition limits, including those not admitted to the case graph. Each edge links to its immutable receipt and snapshot. This view can be derived from stored receipts; it need not duplicate raw evidence. |
| Bounded frontier | Eligible `(IOC, method)` actions on newly observed candidates, with depth, query history and budget restrictions. Entries can expire from scheduling while their evidence remains preserved. |
| Admitted case graph | Report seed nodes plus the particular supported paths that pass the experimental admission rules. Membership expresses investigation relevance under this policy, not an actor or maliciousness label. |

Keep the original report seed set `S` immutable. Record origin separately from
maliciousness: reports can contain legitimate reference infrastructure too.
For the pilot, annotate investigative versus reference roles from the report
before running policies, use the same role information for all variants, and
restrict bridge credit to investigative anchors. Do not silently count every
extracted reference as an incident anchor or use later test labels to choose it.
Where a report covers several incidents, preserve its event grouping too. Do not
interpret an ungrouped structural bridge as a confirmed common campaign.
Keep the currently implemented paper graph as a separate baseline run/view; do
not silently reinterpret its old admission decisions.

### Give new-only discoveries a small exploration allowance

Permit a configured fraction of the acquisition budget to query provisional
candidates even when their parent batch has no overlap. Bound the frontier size,
maximum path depth, outputs retained per lookup and per-candidate query attempts.
Reserve the rest for original/admitted candidates. A deterministic breadth-first
queue is sufficient for the first experiment.

For a pilot, depth two or three and a small exploration fraction are reasonable
**hyperparameters to compare**, not validated settings or paper requirements.
Choose them using held-out validation reports and publish sensitivity results.
Avoid an unrestricted reverse-DNS crawl.

Use `(canonical IOC, method, relevant time window, source-snapshot freshness)`
to distinguish a genuinely new acquisition from a duplicate. Do not ban all later
methods on an IOC just because it was selected once. Conversely, looking up a
duplicate snapshot cannot repeatedly earn discovery credit. The frontier is
bounded independently of how long receipts are retained.

### Admit supported paths, without automatic batch spillover

Search the observation graph for short, simple paths that connect **different
current case-graph components containing original investigative anchors**. Previously
queried endpoints remain eligible to participate in paths.

For each proposed path:

1. Require accepted evidence for every constituent edge and retain its exact
   query/snapshot provenance. Never infer a missing edge from co-occurrence.
2. Check the observations against the report's incident window using a declared,
   relationship-specific temporal rule. Return `compatible`, `incompatible` or
   `unknown`; unknown timing is not a false observation.
3. Flag ambiguous shared-infrastructure-only paths. A CDN or crowded-IP bridge
   needs explicit report evidence or additional, more specific relationship
   evidence before automatic case admission. Otherwise retain it for review.
   Record the reason; do not label all high-degree infrastructure benign.
4. Promote only the qualifying path's edges and endpoints. Other outputs from
   the same batch stay observable/provisional unless they qualify separately.

An initial automatic experiment should promote only paths with compatible timing
and a passing shared-infrastructure check. Unknown-time or ambiguous-hub paths
remain provisional unless an analyst records a reasoned override. The exact
time tolerance, hub threshold, accepted corroboration types and path cap must be
fixed before the test set. Missing fields may reduce coverage; measure that
limitation explicitly. Do not call this an independently proven relevance test.

When several paths qualify, choose deterministically by evidence-rule result,
then length, then canonical IDs, with a fixed per-step cap. Recompute components
after each admission. Connecting already connected seeds adds no new bridge
reward, although the observation may still be useful evidence. This deliberately
favors connecting the report's evidence over collecting many loosely associated
neighbors.

For example:

```text
report seeds: A, B
lookup q1: A -> {X, Y}       keep A--X and A--Y as validated observations
bounded exploration: query X
lookup q2: X -> {B}          now A--X--B is a candidate supported path
if the path passes the declared relevance safeguards:
    admit A--X and X--B
    give q1 and q2 delayed contribution credit
    leave A--Y provisional unless it qualifies separately
```

This is an alternative to the paper's rule. It is not a claim that reciprocal
lookup is required or that the user previously approved this policy.

### Credit the queries that supplied the path

For a first measurable rule, award one unit when an admitted path merges two
previously separate components containing investigative anchors. Count only
components containing at least one investigative anchor; absorbing an isolated
reference node does not create another unit of utility. Split the credit equally
among the distinct acquisition receipts supplying the path's admission witness.
Credit earlier receipts when the bridge is completed, rather than rewarding only
the last query. If a path merges more than two components, count the number of
component merges, rather than all newly connected seed pairs.

The admission witness is a deterministic sufficient set of evidence for every
edge **and every required temporal or infrastructure-ambiguity check**. It may
include several observations for one relationship when corroboration is required.
Prefer the original acquisition for identical cached evidence. Keep the full
alternative evidence list for auditing. A later provider can receive credit for
genuinely new required corroboration, but not simply for copying the same
evidence. Unknown upstream dependence must be declared.

For `q1` and `q2` above, each receives `0.5` credit. Total awarded credit is one,
not two. Across a run initialized with isolated seeds, total component-merge
credit cannot exceed the number of investigative anchors minus one. This prevents
repeated credit for the same connectivity gain. It also means this objective
eventually saturates.

This is a **structural utility proxy**, not a probability, actor label, or ground
truth that the path is attack-related. Manual relevance assessment is a separate
evaluation target. Do not assign an early, still-provisional query a final
irrelevance label just because no bridge has yet appeared. Retain a pending
credit state through the configured exploration horizon or run termination;
timeouts are censored outcomes, not proven negatives.

First evaluate this credit ledger with fixed scheduling. If it helps, use the
credit as feedback for method selection, with distinct handling for unavailable
providers, partial acquisitions and pending feedback. Log actual source requests,
pages, retries, elapsed acquisition time and quota units where known. A cached
lookup has zero external-request cost but earns no fresh discovery reward.

This staged approach avoids attributing a gain to an adaptive score when the
real gain came only from allowing a previously forbidden query. Existing bandit
theory does not automatically justify a UCB formula for these evolving actions,
delayed graph rewards and partial observations. No regret or optimality bound is
claimed here.

In particular, this credit is produced partly by **later chosen actions**, rather
than merely revealing an earlier fixed reward after a delay. It is sequential
credit assignment, not automatically the standard delayed-feedback model.
Bridge completion can also have increasing marginal value: the first edge alone
gives zero bridge gain, and a later edge makes the earlier one useful. Therefore,
guarantees from [adaptive submodularity][adaptive-submodularity] cannot be assumed;
their diminishing-returns condition would need to be established for the actual
objective.

### Experimental pseudocode

This describes the proposal, not current executable behavior:

```text
S = immutable canonical report seeds
A = investigative anchors identified from original report roles
observations = empty evidence graph
case_graph = isolated nodes S
frontier = compatible seed actions
ledger = empty query / pending-credit / acquisition-cost records

while an eligible action fits the remaining acquisition budgets:
    action = choose_action(frontier, reserved provisional-exploration budget)
    receipt = acquire_and_validate(action)
    save immutable receipt, exact status, completeness and actual costs

    if receipt has no usable accepted observations:
        record operational result; update availability/backoff state
        continue

    merge accepted evidence into observations idempotently
    enqueue eligible discovered actions within depth/frontier/attempt limits

    for path in bounded_deterministic_path_search(observations, case_graph, A):
        if path joins different anchor-containing components:
            decision = check_every_edge_time_and_infrastructure_ambiguity(path)
            save the decision and evidence used
            if decision is admissible:
                witnesses = choose_witnesses_for_edges_and_required_guards(path)
                merges = anchor_component_count_before - anchor_component_count_after_merge
                admit only this path to case_graph
                split merges units among distinct contributing query receipts
                apply delayed ledger updates once, including earlier queries

    expire scheduling entries outside the configured exploration horizon
    retain receipts and observations for audit

return case_graph, observations, provisional_frontier_summary, credit_ledger
```

`anchor_component_count_after_merge` is computed for the proposed merge before
its atomic application. Both counts include only components containing at least
one member of `A`. Ledger updates and admission need idempotent transaction keys
so resuming a run cannot award the same bridge twice.

## What this proposal cannot solve by itself

**Single-seed reports:** a bridge between distinct original anchors requires at
least two investigative anchors. For one anchor, or several with no real common
infrastructure,
this reward may remain zero. The bounded frontier can still collect observations,
but the experiment must report zero bridge opportunity rather than manufacture
a second anchor. Independent analyst relevance labels or another objective would
be needed for a general single-seed discovery policy. Defer that extension until
the narrower mechanism is evaluated.

**Temporal ambiguity:** first/last-seen timestamps do not prove uninterrupted
occupancy between those dates. Use observation semantics rather than assuming
continuous DNS coverage. Compare evidence to incident time, not simply to today's
date. A missing timestamp must stay unknown. Provider collection time is not
necessarily relationship observation time.

**Incomplete infrastructure visibility:** a top-100 or top-500 reverse response
only reveals observed degree under that provider's window and cap. It is not true
IP degree or simultaneous co-hosting count. Two non-overlapping results from
different dates need not contradict each other.

**Poisoning and misleading seeds:** valid provider observations or a connection
to two report IOCs can still describe shared legitimate infrastructure. Path
checks reduce obvious contamination; they do not establish attribution. Keep
original report context, explicit role and provenance available for review.
Investigative anchors from the same report may also belong to different events.
Use report-defined event groups to restrict eligible pairs where available;
without them, all-pair bridge utility remains a structural proxy for independent
review, not an event-identity label.

**Exploration cost:** the method deliberately spends some requests on candidates
that may never help. The benefit must exceed this cost in experiments. A correct
outcome can be that strict admission is more efficient for some report classes.

## Evaluation needed before claiming improvement

### Separate the two scientific questions

First test **inclusion and exploration** with identical deterministic scheduling,
validators, provider-shaped responses and budgets:

| Policy | What it isolates |
| --- | --- |
| Literal paper gate | The settled `known - used` full-batch baseline. |
| Admit every validated output, with the same global limits | Whether broad expansion simply adds noise. |
| Bounded provisional frontier with simple breadth-first selection | Benefit from access to new-only candidates alone. |
| Proposed path admission and delayed credit ledger | Whether selective admission improves utility/noise over the same frontier. |

The ledger cannot improve acquisition decisions under fixed scheduling. Its
first-stage value is auditable credit and a possible training signal; do not
claim query efficiency from credit assignment alone.

Then test **adaptive selection**. Implement and document the original method
ranking/cold start as a comparator. Hold frontier eligibility and admission rules
fixed while comparing the original binary coverage signal with delayed path
credit. Keep any LLM prompt, model version and shortlist logic fixed, or disable
the LLM in all controlled variants. If it remains stochastic, repeat runs and
report variation. Label this a controlled adaptation of the ranking when frontier
eligibility differs from the original algorithm.

Use actual external-request budgets for the main cost comparison, with latency
and quota reported separately. Keep logical-step and output limits equal too;
one logical step can cause multiple source requests. Test sensitivity to the
frontier share, depth and observation completeness. Ablate delayed credit and
the provisional exploration allowance separately; optionally ablate time/hub
guards after the core comparison is stable.

### Data and labels

Start with frozen, offline provider-shaped replay fixtures covering a new-only
two-hop bridge, a reconnection to a used IOC, same-batch unrelated neighbors,
shared hosting, incompatible/unknown times, duplicated snapshots, rate limits,
partial pagination and no real bridge. Include single-seed reports as an explicit
limitation case. Synthetic fixtures establish mechanism correctness, not
real-world superiority.

For the real evaluation, use a fixed set of CTI reports with explicit incident
windows and preserved contextual roles. Use historical evidence available at the
chosen investigation time. Provider observations or threat labels that appeared
later must not leak into historical query responses or scheduler inputs. Split
by time and related campaign/infrastructure groups so near-duplicate reports do
not leak across tuning and test sets.

Preserve evidence for all compared candidate actions in a sufficiently broad
frozen reference collection. Today's investigation history contains only queried
actions; it cannot fairly simulate a policy choosing unobserved actions. Mark
missing replay actions as unavailable data, not empty results. A live prospective
comparison is an alternative, but needs repeated runs and explicit provider/time
variation controls.

Maintain separate labels for **relationship support**, **incident relevance**
and **actor attribution**. Do not derive every relevance label from the same
provider overlap used as the policy's reward. Use independently documented report
relationships and, where feasible, reviewer assessment with disagreements and
unknowns recorded. Unlabelled observations are not automatically false positives.
Report the fraction for which relevance can actually be assessed.

### Measurements and success criterion

Measure relevant supported paths recovered, seed-pair connectivity recall where
a reference exists, relevance precision among assessed admitted edges, unrelated
admitted-edge burden, observation/frontier growth, and bridge discoveries per
external request. Also report latency, requests/pages/retries, 429s, cache hits,
partial/unknown outcomes and reviewer workload. Show per-report results and
uncertainty across reports, not only one aggregate graph count.

Before testing, choose a minimum useful recall gain and an acceptable relevance
precision loss using project needs and validation data. The proposal succeeds
only if it recovers more independently assessed relevant structure at the same
request budget without an unacceptable contamination increase. More nodes or
more edges alone do not establish improvement. Do not infer better actor
attribution without evaluating the downstream attribution task separately.

## Feasible next steps and claim boundary

1. Preserve the current policy and receipts. Finish a reproducible Algorithm 1
   comparator with explicit initialization and acquisition accounting.
2. Build the separate observation/frontier views and a deterministic bounded
   exploration experiment. No new embedding model is required.
3. Add path decisions and the delayed credit ledger; validate the mechanism on
   frozen fixtures before using it for ranking.
4. Compare the inclusion policies, then compare reward-driven selection. Search
   citations and recent literature around the closest systems before writing a
   thesis or paper novelty claim.

A defensible provisional contribution statement is:

> We evaluate a bounded provisional-exploration extension to IOCHunter that
> assigns delayed credit to the acquisitions completing evidence-supported paths
> between report seeds, under explicit acquisition budgets and noise controls.

This states a testable mechanism. It does not claim the first use of bandits,
temporal graphs, provenance or adaptive pivoting, nor promise performance.
If a closer prior method is found, frame the work as its adaptation and evaluation
for IOCHunter instead of claiming a new algorithm.

SecureBERT remains outside the current implementation scope. Preserving IOC
occurrences, sentences, report roles and external-source context would support
later semantic features; encoding isolated IOC strings would not supply all that
context. That future representation work is separate from this proposal.

## Research coverage and sources

This was a targeted public-web review using primary papers, publisher pages,
author copies and preprints, checked on 6 November 2026. Searches covered
IOCHunter/ThreatMAMBA, bandit threat hunting, adaptive CTI crawling, passive-DNS
expansion, shared hosting, time-aware CTI graphs, provider/source dependence,
budgeted contextual bandits and delayed graph credit. It was not an exhaustive
systematic review, patent search or proof of uniqueness. No new live provider
queries were needed for this review, and no algorithm change was made.

For PhishLumos, the review used the publisher's indexed description and the
readable author preprint. Direct publisher access was intermittently blocked;
reconciling the complete journal method and implementation remains part of a
deeper comparison. This access limit does not prevent adapting a useful idea,
but it does limit any assertion of distinctness from that system.

[mabat]: https://us-isr-energycenter.org/energy_cyber/papers/MABAT_A_Multi-Armed_Bandit_Approach_for_Threat-Hunting.pdf
[threatcrawl]: https://arxiv.org/html/2504.18375v1
[threatcrawl-earlier]: https://arxiv.org/abs/2304.11960
[mantis]: https://arxiv.org/html/2502.09788v1
[titan]: https://arxiv.org/html/2411.06239v1
[carioca]: https://link.springer.com/article/10.1007/s10207-025-01006-2
[feedrank]: https://nsg.ee.ethz.ch/publications/2018-07-09-feedrank-a-tamper-resistant-method-for-the-ranking-of-cyber-threat-intelligence-feeds-20-500-11850-281732/
[phishlumos]: https://doi.org/10.1109/ACCESS.2026.3696597
[phishlumos-preprint]: https://arxiv.org/html/2509.21772v3
[cbwk]: https://proceedings.mlr.press/v49/agrawal16.html
[delayed]: https://proceedings.mlr.press/v28/joulani13.html
[d3ts]: https://arxiv.org/abs/1703.05082
[adaptive-submodularity]: https://authors.library.caltech.edu/records/dn297-7wr20
