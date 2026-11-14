# Automatic IOC hunting and D2 preparation

Prepare D2 once using its saved sentence arrays, then run Algorithm 1 against the extracted IOCs. Each report has an independent saved investigation. Completed extraction files and workflow steps are reused after interruption.

The implementation separates preparation, selection, lookup execution and graph admission. Method counters reset for each report. Provider quotas and captured evidence are shared through the existing store across reports.

## Run the offline example

Run these commands from `dev/Project-Sherlock/services/ioc` with the service's installed Python environment. The example uses synthetic report/provider data and a fixture selector; it makes no provider or model calls.

```powershell
$iocPython = 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe'
& $iocPython -B -m ioc_hunter dataset prepare --source examples/algorithm/d2 --output output/algorithm-demo
& $iocPython -B -m ioc_hunter algorithm run --build output/algorithm-demo --experiment offline-v1 --config examples/algorithm/replay-config.json --store output/algorithm-demo-store
& $iocPython -B -m ioc_hunter algorithm stats --build output/algorithm-demo --experiment offline-v1
& $iocPython -B -m ioc_hunter algorithm resume --build output/algorithm-demo --experiment offline-v1 --store output/algorithm-demo-store
```

Expect one complete report. Its domain executes five lookup rounds; repeated passing batches increase coverage even when they add no new graph identities. The SHA-256 seed remains isolated and is included in `statistics.ioc_participation`. The reference URL remains an excluded sentence with its original index. The second invocation reuses the completed report and does not select or acquire again.

The example's `alpha=1.0` is an explicit demonstration setting, not a value established by the paper.

## Prepare the real D2 reports

```powershell
& $iocPython -B -m ioc_hunter dataset prepare --source ../../../datasets/d2_model_ready --output output/d2-ioc-v1
& $iocPython -B -m ioc_hunter dataset export --build output/d2-ioc-v1 --output output/d2-ioc-v1/exports/reports.jsonl
```

Preparation makes no online lookups. Use `--split train --max-reports 20` for a bounded preparation sample or repeat `--report-id` to select reports. Rerunning preparation reuses matching artifacts. Remove `--max-reports` to extend a pilot to all reports; that option bounds selected source records for preparation, not new work across invocations.

Sentence references are `(report_id, sentence_index)`, optionally rendered as `1683:s12`. No sentence hash is used. Preserve the original D2 sentence array when supplying it to the TTP service. Exact mention positions are reported only where source spelling can be verified; an unavailable exact position does not remove the sentence association.

## Configure a model-backed experiment

The configuration file accepts these fields:

| Field | Meaning |
| --- | --- |
| `alpha` | Required finite nonnegative exploration weight |
| `method_ids` | Optional fixed list of implemented methods; omitted means the current implemented catalogue with known unresolved live routes excluded |
| `selector` | Model API settings described below |
| `provider_limits` | Shared per-provider rate/budget profiles |
| `frozen_cache` | Reuse captured logical lookup evidence within this D2 build; default false |
| `limits` | Existing workflow `max_steps`, `max_nodes`, `max_seconds`, `max_pages`, `max_outputs` |
| `mode`, `replay` | Live by default; explicit replay manifest for offline acquisitions |

A model selector uses `kind=api`, an explicit `endpoint` ending at the server's chat-completion route, and an explicit `model` ID. Optional fields are `api_key_env`, `timeout` (default 120 seconds), `temperature` (default zero) and `max_tokens` (default 2048). Keys come from the named environment variable; do not put secret values in the configuration. Endpoint query parameters and redirects are rejected. The server must accept the configured chat-completion JSON format and return JSON selection text in `choices[0].message.content`.

The response text must have the form `{"methods":[{"method_id":"rapiddns.domain_to_ipv4","reason":"Relevant DNS history"}]}`. IDs must belong to the supplied shortlist; an empty list is allowed. A failed selection gets one bounded retry, then leaves the report resumable at that decision. No alternative model or deterministic selection is silently substituted.

Only the model's configured identity and returned explanation are saved; the software does not verify that a server is actually serving that checkpoint. Live selector compatibility and provider access require a separate bounded verification. This implementation has been verified offline and does not download a 70B model.

Relative fixture/replay paths resolve against the configuration file's directory. Experiments freeze configuration, method declarations and fixture/replay content. Use a new experiment ID when any of them changes.

## Shared limits and durable waiting

`provider_limits` is a provider-to-profile mapping. Supported provider names are `rapiddns`, `alienvault`, `virustotal` and `hybridanalysis`. Each profile accepts:

| Profile field | Default | Scope |
| --- | ---: | --- |
| `interval` | 15 seconds | Minimum spacing between uncached top-level acquisition attempts |
| `daily_limit` | 500 | Local attempts per provider per UTC day |
| `backoff_seconds` | 60 | Initial cooldown when a 429 lacks Retry-After |
| `max_backoff_seconds` | 3600 | Ceiling for the fallback exponential cooldown |

These defaults are local safeguards, not provider entitlements. Set profiles according to the route/account in use and measured pilot behavior. Profiles, budgets and cooldowns live in the existing SQLite store, so restarting a report or creating another client does not reset them. All reports and manual clients must share the same store to coordinate.

Cached reads happen before provider gating. Pagination, follow-ups and retries cross the same gate. Frozen evidence also covers captured multi-page logical results and remains isolated by build, query, method, limits, transport/access state and integration route. It is a reproducible captured observation, not a fresh provider query. Each logical call still gets its own receipt and paper admission decision.

Known local cooldown/quota blocks keep the selected action pending and leave tried/coverage unchanged. A real dispatched request returning 429 is recorded once before pausing. Partial validated results retain the normal admission rule and a completeness warning. Long waits are saved with the next eligible time.

By default, a long wait returns a resumable `in_progress` result. Add `--wait` to keep the CLI running and automatically continue after cooldowns:

```powershell
& $iocPython -B -m ioc_hunter algorithm resume --build output/d2-ioc-v1 --experiment collection-v1 --store output/investigations --wait
```

Ctrl+C preserves saved work and exits. Waiting time is tracked separately from the active-processing budget. If a halt leaves an actual acquisition's completion unknown, the workflow preserves that unknown outcome and does not automatically repeat that action.

`--max-reports` on hunting bounds unfinished reports processed in that invocation. Completed reports are skipped without consuming that count. A budget-closed report is exported as `limited`; increasing its budget requires a new experiment.

## Outputs and analysis

The build contains `manifest.json` and one extraction record under `reports/`. Each experiment adds:

- `experiment.json`: saved settings, source fingerprints and original store location.
- `progress.json`: replaceable progress index; SQLite remains authoritative.
- `reports/<report_id>.json`: a self-contained graph, decisions, steps, evidence snapshots and statistics at one saved revision.
- `summaries/reports.csv`, `methods.csv` and `corpus.json`: derived analysis summaries.

The report snapshot embeds raw evidence so replacing one file publishes a consistent report. Large production releases may later separate snapshot blobs; a separate evidence packaging subsystem is not needed for the first version.

`statistics.ioc_participation` retains every report seed and every retained validated output. It distinguishes isolated graph nodes, connected nodes, validated outputs outside the graph, own-query attempt/admission counts and unresolved reasons such as rate limits or missing methods. Zero own-query coverage does not prove isolation or incident irrelevance.

Use `algorithm stats RUN_ID --store STORE` for a current saved investigation, or `algorithm stats --build BUILD --experiment ID` to rebuild portable corpus summaries. Corpus statistics read the last committed per-report exports; recover an interrupted report first to refresh its export from SQLite. Rebuilding summaries makes no model/provider calls and never changes counters.

Provider request metrics count top-level acquisition attempts, not all browser XHRs or billed quota units. Unknown historical accounting remains null. Model usage is reported only when supplied by the endpoint. Reference filtering and method/source coverage limitations remain visible in the records.

See [the implementation plan](IMPLEMENTATION_PLAN.md) for the baseline, conventions and acceptance criteria.
