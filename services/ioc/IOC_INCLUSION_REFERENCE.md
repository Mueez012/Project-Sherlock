# IOC inclusion: settled paper interpretation and implementation baseline

Reference date: **6 November 2026**. This records the settled interpretation of
IOC inclusion for future implementation and research. It describes the current
baseline; it does not authorize or implement an algorithm change.

## Conclusion

The paper specifies **conditional batch admission**. A lookup must return at
least one IOC that is already known and unused. When that condition passes,
the algorithm adds **all returned IOCs and their corresponding edges**, including
new IOCs absent from the original report. It does not retain only the overlapping
outputs. If the condition fails, the printed algorithm does not enlarge its
candidate set or add those relationships.

The current implementation follows that admission condition after independently
validating provider evidence and applying workflow limits. Selection remains
manual. The baseline is `manual-selection/paper-admission-v1` in
[PaperAdmissionPolicy](ioc_hunter/workflow/policies.py).

This is neither an original-report-only graph nor unrestricted exploration.
The earlier proposal to admit every validated discovery was discussed as an
alternative manual policy and **was not adopted**. No separate candidate pool,
reciprocal-confirmation policy or cycle detector has been introduced.

## What the original paper establishes

The primary source is the local [ThreatMAMBA paper](../../../../ThreatMamba.pdf).
The relevant passages are PDF pages 3–4 and Algorithm 1 on PDF page 6; their
printed IEEE page numbers are 4388–4389 and 4391.

| Source | What it establishes |
| --- | --- |
| Page 3, IOC subgraph construction | The text distinguishes contexts of IOCs extracted from CTI from contexts of IOCs obtained through external hunting. Externally retrieved IOCs are part of the described framework. |
| Page 3, Figure 1 | The architecture depicts original IOC nodes and additional dotted IOC nodes in the resulting event graph. This supports the prose; the pseudocode supplies the explicit insertion rule. |
| Page 4, IOC subgraph construction | Successful expansion is described in terms of connecting new child IOCs to existing candidates. The discussion uses closed-loop language, but does not define a graph-cycle or reciprocal-confirmation procedure. |
| Page 6, Algorithm 1 input | `O` starts as the original candidate IOCs. That describes its initial contents, not an immutable set. |
| Algorithm 1, line 11 | The current input `o` enters `O_used` before its methods are executed. |
| Algorithm 1, lines 25–26 | A method returns `O_prime`; admission tests whether `O_prime` intersects `O - O_used`. |
| Algorithm 1, line 28 | On a pass, `O` is updated with the full `O_prime`, not just the intersection. |
| Algorithm 1, lines 29–31 | The edge-insertion loop visits every output in `O_prime`. |
| Algorithm 1, lines 5 and 42 | The outer loop uses the mutable candidate set; the returned graph contains the resulting `O` and edges. |

No original-IOC-only filter on method outputs is specified in this IOC section,
Table I, Figure 2 or Algorithm 1. Reading the input label as a permanent
restriction would require an additional rule that is not stated, and would
conflict with the explicit candidate-set update.

The clearest supported interpretation is therefore conditional expansion
anchored by a known unused IOC. The paper does not specify unlimited exploration
of every new observation. Its broader prose does not justify silently changing
the printed insertion condition or asserting a different author intention.

## Exact baseline rule

For the current implementation:

- `known` contains the canonical IOC identities already in the investigation graph.
- `used` contains known IOCs previously selected for lookup, including the current input.
- `outputs` contains the current lookup's retained, independently validated outputs.

The runner computes the sets before merging this lookup's outputs:

```text
mark the selected input used
overlap = outputs INTERSECT (known MINUS used)

if the lookup has a usable final outcome
   and all retained outputs have accepted evidence
   and overlap is nonempty
   and the whole proposed batch fits the node limit:
       merge ALL validated outputs into the graph
       add each supported input-output edge
else:
       do not add this batch's nodes or edges
       retain the exact lookup receipt and decision
```

Usable outcomes are `ok`, `empty` and `partial`; an empty result has no overlap.
Failures and interrupted acquisitions cannot admit graph data. Node limits
apply to the whole proposed batch, rather than admitting an arbitrary prefix.
Source-page and output limits remain visible in the lookup's partial-result
diagnostics.

The selected IOC's used flag, step outcome and graph revision remain saved even
when the batch adds no nodes or edges. In contrast to the paper's abbreviated
pseudocode, our receipt store also retains non-admitted outputs, provider
evidence, rejection explanations and operational outcomes for inspection.

## Evidence validation is separate from batch admission

[validate_edge()](ioc_hunter/validation.py) runs automatically for each parsed
candidate inside the [lookup pipeline](ioc_hunter/lookup.py). The
[runner](ioc_hunter/workflow/runner.py) verifies the exact receipt association
and rechecks finalized accepted evidence mappings before graph admission.

This deterministic field-level validator is an engineering safeguard in our
implementation; it is not a separate procedure explicitly prescribed by
Algorithm 1. It checks the method, exact queried IOC, ontology-permitted types,
source provenance and relationship-specific fields such as exact DNS endpoints.

Suppose a lookup of `A` returns known-unused `X` and new `Y`. Provider evidence
must separately support **A–X** and **A–Y**. `X` makes the batch eligible; it does
not prove a relationship between `X` and `Y`. The admitted relationships are
A–X and A–Y, with their own supporting evidence. The workflow does not infer X–Y
from batch membership.

An IOC's origin in the report or a lookup is provenance, not a maliciousness
classification. Validating an observable relationship does not identify an
attacker. Lookup operations are directional; IOC graph edges are undirected and
labelled by method ID. Reverse retrieval methods retain distinct provenance and
can have separate method-labelled edges between the same endpoints.

## Worked synthetic cases

Assume the graph initially knows `A` and `B`, and neither has been used. Selecting
`A` makes the unused-known set `{B}` before admission is evaluated.

| Lookup result after evidence validation | Baseline result |
| --- | --- |
| `A` returns `{B, X}`, where `X` is new | Admit the whole batch: add X and the supported A–B and A–X edges. No reverse lookup is required. |
| `A` returns only new `{X}` | Do not enlarge the candidate graph or add A–X. Retain X and its evidence in the receipt. |
| A later lookup of `B` also returns only `{X}` after the previous row | Admission still fails because X never entered the known candidate graph. Both observations remain inspectable in receipts. |
| An available `X` returns only already-used `{A}` | Admission fails because A is excluded by the used set, even if the return lookup supports the same relationship. |

The third case exposes the exploration restriction: evidence may support an
A–X–B path without that path entering the admitted graph. This is a path, not
necessarily a cycle. It is a real limitation relative to a workflow intended
to investigate every discovery, but it does not prove that the paper contains
a bug or that the implemented overlap condition was transcribed incorrectly.
Growth remains possible when a batch also reaches a known unused candidate.

## Historical observed example: america250.holiday

On **5 November 2026, approximately 01:23 Asia/Karachi** (4 November at 20:23 UTC),
step 14 of investigation `7a1cc79e69a044b3a2e4c0a3bc67c771` queried
`america250.holiday` using `alienvault.domain_to_ipv4`.

| Retained validated output | Identity before this step |
| --- | --- |
| `192.121.46.25` | Existing unused report IOC; this supplied the overlap |
| `104.21.83.226` | New IOC |
| `172.67.182.100` | New IOC |
| `2.57.91.91` | New IOC |

The saved admission reason is `known_unused_overlap`. The batch added **three
new nodes and four method-labelled edges**, one edge from the queried domain to
each validated output. Its stored delta is:

```json
{"new_nodes": 3, "new_edges": 4, "evidence_links": 4}
```

This is historical evidence of the implementation's behavior, not an independent
proof of the paper authors' intent or a claim about the run's current totals.
It also does not classify any returned address as malicious.

Exact local evidence references:

- Store: [output/live/lookups.sqlite3](output/live/lookups.sqlite3).
- Workflow step ID: `d0be3f5ee2ea47acaa966cedbf246dff`.
- Lookup receipt ID: `2c5937f9fda148fbbd597e8c9ca6c7ec`.
- Response snapshot ID: `48f1681ffd8c6df5bbac516cf881100b755df378f4caab927a925a38323703bb`.
- Queried provider response: `https://otx.alienvault.com/otxapi/indicators/domain/passive_dns/america250.holiday`.

The database is local runtime data and may not accompany a fresh clone. The IDs
identify the original saved evidence when that store is available; they are
not new provider queries or a claim of present-day provider contents.

## Interpretations that were not adopted

**Original-only graph:** unsupported by the mutable `O`, full-batch insertion
and explicit discussion of externally hunted IOCs.

**Reciprocal confirmation:** the printed rule neither requires nor implements
A→X followed by X→A. New-only X is not admitted for selection; if A was already
queried, it is excluded from the overlap set when returned later. Conversely,
a batch containing a known-unused anchor admits its supported new relationships
without a reverse lookup.

**Cycle detection:** the policy checks candidate-set membership, not existing
graph paths, connected components or cycle closure. The paper's closed-loop
description should not be substituted for a different executable condition.

**Admit every validated discovery:** this was proposed as an alternative manual
policy to improve exploration. It is not the current baseline. A separate
candidate pool or evidence-graph view was also discussed; none is implemented
by the present inclusion rule. Such changes need an explicit policy definition,
separate evaluation and a clear distinction from literal paper reproduction.

## Current scope and future research

The [workflow configuration](ioc_hunter/workflow/models.py) defaults to 20 lookup
steps, 1,000 graph nodes, 600 seconds of accumulated extraction/acquisition time,
two pages per lookup and 1,000 unique validated outputs per lookup. These are
workflow safeguards, not the paper's five rounds per selected IOC.

Only manual IOC/method selection and the paper's admission condition are
implemented here. Automatic ranking, five-round scheduling, LLM selection and
coverage/tried counters remain future work. Saved admission records use
`reward: null` and `reward_status: not_evaluated`; node/edge additions are not
reported as Algorithm 1 reward.

The [algorithm improvement research](ALGORITHM_IMPROVEMENT_RESEARCH.md) should
treat this document as the baseline definition. Research may examine a separate
candidate pool, evidence graph, admitted graph or another scheduling/reward
policy, but should not present those proposals as existing behavior. Preserve
the literal policy as a reproducibility baseline when comparing alternatives.

For operating instructions, see [the workflow guide](WORKFLOW_GUIDE.md). For
the implementation diagrams and data model, see
[the workflow explanation](WORKFLOW_EXPLAINED.md).
