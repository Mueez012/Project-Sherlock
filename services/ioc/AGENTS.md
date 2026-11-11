# Development rules for AI agents working on IOC Hunter

Status: 8 November 2026, after patch 12 was merged into `develop`.
Applies to: every AI coding agent that changes Project Sherlock for the IOC module (`services/ioc/`).
Suggested location in the repo: `services/ioc/AGENTS.md`.

## 0. Roles

This file refers to people by role, so it stays valid whoever runs the agent.

| Role | Responsibility | Currently held by |
| --- | --- | --- |
| Repo owner | Architecture decisions, the hub (`src/threatmamba/`), datasets, CI and infrastructure, CSKG and attribution | Mueez (GitHub `Mueez012`) |
| IOC module owner | IOC Hunter (`services/ioc/`); the person this agent works for | Huzaifa (GitHub `M-Huzaifa-Bin-Amir`) |
| TTP module owner | TTP extractor (`services/ttp/`) and the website (`frontend/`) | Khalid (GitHub `Khalid-Umar1`) |

"You" in this file means the agent.

## 1. How to use this document

- **Section 6 says what to build next and how to decide where a change goes.** Use its decision ladder for every change.
- **Section 8 lists what you must never do.** Each item is a mistake that already cost a cleanup patch; do not reason your way around one.
- **Decide, don't stall.** Make the call yourself with the decision ladder in section 6: solve it inside `services/ioc/` first, and touch shared code only when that is impossible, in the smallest additive way. Only the short list in section 9 needs the repo owner.
- **Never infer permission for product features.** "It would be useful", "it is good practice" or "a real product would need it" is not a reason to build a product feature (section 8). Only this document grants it.
- **This document wins** over anything in `services/ioc/*.md` plans, older design notes or your own earlier suggestions. Where they disagree, follow this document.

## 2. The project and the master plan

Project Sherlock implements the ThreatMAMBA paper's pipeline for attributing a threat report to 1 of 25 threat groups. The paper is the specification. Product features come only after the paper's pipeline works end to end.

| Module | Paper section | Where it lives | State |
| --- | --- | --- | --- |
| 1. TTP extraction | III-A2 | `services/ttp/` (TTP module owner) | Done: real model served by the hub |
| 2. IOC extraction and hunting (IOCHunter, Algorithm 1, ontology Fig. 3) | III-A1 | `services/ioc/` (IOC module owner) | Extraction done; lookups and saved investigations done with **manual** selection; Algorithm 1 automation not done |
| 3. CSKG construction (one graph per report: sentences, TTPs, IOCs) | III-A3 | Not started; the repo owner leads it | Deferred |
| 4. Attribution (GAT + MAMBA + contrastive learning) | III-B | Not started | Deferred, same container as CSKG |

The architecture is hub and spoke. The hub (`src/threatmamba/`, FastAPI) is the only backend the website talks to. TTP and IOC are separate containers the hub calls. One `docker compose up -d --build` runs everything on any machine with Docker, with no extra setup.

Three principles decide every case this document does not spell out:

1. **Paper first.** Build what the paper describes, as it describes it. Do not add your own extras.
2. **Core before product.** Users, accounts, screens, sharing and similar product decisions wait until the whole pipeline is finished.
3. **Keep it simple.** The smallest change that does the job, inside `services/ioc/` whenever possible, using what already exists.

## 3. Who owns what

Your home is `services/ioc/`. Shared code may change when a feature genuinely needs it, as a last resort and in the smallest additive way (section 6, decision ladder). The table says how far each area may go.

| Path | Owner | You may |
| --- | --- | --- |
| `services/ioc/` | IOC module owner | Change freely, within sections 5 to 8 |
| `src/threatmamba/` (hub, contracts, clients, splitter) | Repo owner | Thin additions a feature needs: a pass-through route, a client field, a setting. Never the splitter or `/api/analyze`'s flow |
| `tests/` (hub tests) | Repo owner | Add tests for your hub additions. Do not edit existing assertions |
| `docker-compose.yml`, `.env.example` | Repo owner | Add an optional setting or variable the IOC service reads, with a working default. No new services, volumes or mounts |
| `README.md` (repo root) | Repo owner | Update the IOC paragraph when what you built changes it |
| `.github/workflows/ci.yml` | Repo owner | Only the `ioc` job, to install or run IOC tests |
| `scripts/`, `pyproject.toml`, `uv.lock`, `Dockerfile`, `VERSION`, `docker-compose.gpu.yml`, `infra/`, `.pre-commit-config.yaml` | Repo owner | Ask first (section 9) |
| `datasets/`, `models/` | Repo owner | Do not change |
| `services/ttp/` | TTP module owner | Do not change |
| `frontend/` | TTP module owner | Do not change |

Inside `services/ioc/`, everything has one home. Put new things there, never in a new folder:

| What | Where |
| --- | --- |
| Code | `services/ioc/ioc_hunter/` (its existing subpackages: `api/`, `workflow/`, `providers/`, `transport/`, `extraction/`) |
| Tests | `services/ioc/tests/` |
| Docs | `services/ioc/*.md` (existing files) and `services/ioc/docs/` (the frontend API reference is `services/ioc/docs/api/`) |
| Helper scripts | `services/ioc/scripts/` (the docs generator and its templates are there) and `services/ioc/tools/` |
| Fixtures and sample reports | `services/ioc/examples/` |
| Container | `services/ioc/Dockerfile`, `services/ioc/pyproject.toml` |
| Local run output (never committed; git ignores it) | `services/ioc/output/` |

## 4. What is done right now

The following works end to end. Do not rebuild, move or redesign any of it.

| Piece | Where | What it does |
| --- | --- | --- |
| Hub `/api/analyze`, `/api/analyze/file` | `src/threatmamba/api/main.py`, `src/threatmamba/documents.py` | Reads text or a report file (PDF, DOCX, HTML, Markdown, TXT, STIX), cuts it with the hub's one splitter, sends the timeline sentences to TTP and every unit to IOC `/v1/extract`, returns the timeline, TTPs, IOCs and sentence positions |
| Hub `/api/investigations/*` | `src/threatmamba/api/investigations.py` | Plain pass-through: forwards each request unchanged to `/v1/investigations/*` and returns the answer unchanged |
| IOC extraction | `ioc_hunter/extraction/`, `POST /v1/extract` | Finds IOCs, applies its filters, and reports which hub sentence each IOC is in |
| IOC one-call lookup | `ioc_hunter/lookup.py`, `POST /v1/lookup`, `GET /v1/methods` | RapidDNS, OTX, VirusTotal lookups with receipts, cache, 15 s pacing, daily budgets |
| Saved investigations | `ioc_hunter/workflow/`, `ioc_hunter/api/`, `/v1/investigations/*` | Manual IOC and method selection, steps, Algorithm 1 admission gate, graph, resume, close, export |
| Terminal workflow | `ioc-hunter investigate / runs / export` | Same saved investigations, run inside the container: `docker compose exec ioc ioc-hunter runs` |
| Storage | `ioc-data` Docker volume at `/data` | One SQLite store for investigations, lookups and evidence |
| Frontend API reference | `services/ioc/docs/api/`, built by `services/ioc/scripts/build_frontend_api_docs.py` | Examples captured through the real hub and service |
| CI | `.github/workflows/ci.yml`, job `ioc` | Installs `.[extraction,api]` and runs `pytest -q tests` in `services/ioc/` |

These decisions are settled. Do not reopen them in code or in docs:

- **One sentence splitter**, the hub's (`src/threatmamba/text.py`: NLTK punkt, pinned, with its English data stored in the repo), the one D2 is built with. IOC Hunter uses a byte-identical copy (`ioc_hunter/text.py`); never edit the copy on its own.
- **D2 records carry `spans`**: the exact position of every stored sentence in the report text (`text[start:end]`, character positions, end exclusive), checked by CI. Use them instead of searching for sentence text; about 2% of stored sentences are not verbatim substrings (whitespace is normalised and wrapped lines are joined).
- **An indicator belongs to exactly the sentences it appears in.** D2 sentences are real sentences only, so indicators in tables, lists or headings are in no stored sentence: they still count, are found by reading the whole report text, and have no sentence number. Never give an indicator a sentence it does not appear in. Only real sentences form the timeline; headings, label lines, indicator lists and fragments are left out, and an indicator found in them belongs to the nearest sentence before it. `/api/analyze` and every dataset-scale run use it. Pre-split sentences are used unchanged.
- **No users.** No accounts, login, owners or `Authorization`. Every investigation belongs to one built-in owner (`OWNER = "local"` in `workflow/service.py`). The owner tables stay in the database, unused, for a later decision by the repo owner.
- **Manual selection stays.** The person picks the IOC and the method. Automation is added beside it, never in place of it (section 6).
- **Storage is the `ioc-data` volume.** No host-folder mounts.
- **The hub stays thin.** It forwards investigation requests without models, validation or rules of its own.
- **Two error formats, each in its own place.** The hub's own errors are `{"detail": ...}`. The IOC investigation routes answer `{"error": {"code", "message", ...}}`.
- **Runs anywhere.** CPU by default, no required setup, no secrets needed to start.
- **Emails and CVEs are off by default** (`extended_types=false`).

## 5. Contracts you must keep stable

Other code depends on these exact shapes. You may **add** optional request fields with defaults and **add** response fields, on your own judgement. Renaming, removing or retyping anything below breaks an existing caller, so that is a section 9 item.

**`GET /health`** answers 200 while the service is up. The hub uses it for `/health`.

**`POST /v1/extract`** is what `/api/analyze` calls.

- Request: `{"text": "<report>", "sentences": ["<hub unit 0>", ...], "extended_types": false}`.
- The `sentences` are the hub's units of the report, in order: the timeline sentences and the lines left out of the timeline. The hub maps the answer onto its timeline itself. Never re-split them, merge them, drop any or reorder them.
- Response fields the hub reads: `iocs` (each `{type, value, context, source}`), `excluded_sections` (each `{heading, text}`), and `sentence_matches`.
- `sentence_matches` has exactly one entry per request sentence, in the same order. Each entry is a list of `[type, value]` pairs found in that sentence.
- Errors keep FastAPI's `{"detail": ...}` format on this route.

**`POST /v1/lookup` and `GET /v1/methods`** keep their current request and answer fields and the `{"detail": ...}` error format.

**`/v1/investigations/*`** keep their current paths, methods, request bodies, `Idempotency-Key` rule and answer models (`api/schemas.py`), and the `{"error": {...}}` format. The hub forwards them unchanged to `/api/investigations/*`. That means:

- A new investigation route needs a matching hub route. Add it only if it conforms to the current architecture: one more pass-through function in `src/threatmamba/api/investigations.py` (copy an existing one; no models, validation or logic) plus a forwarding test in `tests/unit/test_investigation_proxy.py`.
- Any change to these models must be regenerated into `services/ioc/docs/api/` (section 7).

**Inside the IOC graph, nodes are identified by IOC (type, value).** CSKG will join the IOC graph to report sentences by IOC value, not by the investigation's sentence numbers. Keep node identity, edge method labels, and the evidence link on every admitted edge.

**The container** stays `python:3.12-slim-bookworm`, user `ioc` (uid 10001), port 8002, store `IOC_HUNTER_STORE=/data`, Chromium for browser lookups. It must start with no environment variables set; `OTX_API_KEY` and `VT_API_KEY` stay optional.

## 6. What to do

Work on these, in this order. Almost all of it happens inside `services/ioc/` and keeps every contract in section 5. Decide where each change goes with the decision ladder below; you do not need to ask the repo owner unless it lands on step 4.

1. **Algorithm 1 automation (the paper's IOCHunter).** Implement the parts the paper has and the code does not: method ranking, coverage and tried counters, used sets and history, the five-round scheduling, and LLM-based selection, checked against hand-calculated examples.
   - Build it as a second selection policy beside the manual one (for example `Algorithm1Policy` in `ioc_hunter/workflow/`), using the same runner, admission gate, repository and receipts.
   - Manual selection must behave exactly as it does now. Automation is chosen explicitly (a CLI flag, or a run setting with manual as the default), never switched on silently.
   - An LLM provider must be optional: with no key configured, the service starts and manual mode works.
   - To expose automation over HTTP, add an optional `/v1/investigations` field or a new route (ladder steps 2 and 3) without changing existing ones.
2. **Method reliability.** Work through `METHODS_TODO.md` and `METHOD_RELIABILITY_REPAIR_PLAN.md`: more of the 39 candidate methods, the VirusTotal domain-to-URL issue, readiness records. One provider or method per change, each with offline fixture tests.
3. **Dataset-scale readiness for CSKG.** CSKG will run IOC extraction and hunting over the 3,338 D2 reports. Make that possible within the 15 s pacing and 500-calls-per-day budgets: reuse the cache, cap work per report, resume after interruption.
   - A batch command takes the report text **and D2's own `sentences`** and keeps them unchanged, like `/v1/extract` does.
   - Its output feeds CSKG, which the repo owner leads, so agree the output format with the repo owner before building it (section 9). The batch machinery itself (caching, caps, resuming) needs no approval.
4. **Keep the graph CSKG-ready.** IOC nodes keyed by (type, value), edges labelled with the method, evidence on every admitted edge, admission decisions recorded. Fix gaps here; do not add other node kinds (TTPs, sentences, groups). CSKG adds those.
5. **Tests and docs for everything above,** in the existing places (section 3).

### Decision ladder

Take the first step that can do the job. Going down a step needs a reason you can state in one line.

1. **Inside `services/ioc/` only.** Most work ends here: new methods, policies, fields in IOC answers, docs, tests. Push to `develop`.
2. **Additive change to the IOC service's own contract.** A new optional request field with a default, a new response field, or a new `/v1/...` route. Existing callers keep working unchanged. Push to `develop`.
3. **Thin change to shared code, as a last resort.** Only when steps 1 and 2 cannot do it: one pass-through route in the hub, one optional setting, one client field. Copy the existing pattern, put no IOC logic in the hub, add a hub test, keep stub mode and the defaults working. Use the scope `hub` in the commit (for example `feat(hub): forward the investigation policy route`), push to `develop` once CI is green, and tell the repo owner in one line afterwards. No need to wait.
4. **Ask the repo owner first.** Only for the short list in section 9: breaking changes, the splitter, infrastructure, paper deviations by default, the CSKG output format, and other people's modules.

Three checks before you go down a step:

- **Can the IOC service do it?** If the hub would only pass data through, pass it through; do not compute in the hub.
- **Does anything that works today change?** If yes, make it optional or additive. If it cannot be, it is step 4.
- **Is it paper work or product work?** Product work (section 8, items 11 to 16) waits, whichever step it would land on.

How to build each kind of change:

| Change | Do it like this |
| --- | --- |
| New lookup method or provider | `ioc_hunter/providers/` plus the methods registry; offline fixture tests in `tests/`; live checks stay in `tests/live_*` and skip themselves without network |
| Selection or admission logic | `ioc_hunter/workflow/`; a policy beside the manual one; unit tests with hand-calculated expected values |
| A field on an existing route | Optional with a default, added to `api/schemas.py`; regenerate `docs/api/`; existing answers unchanged |
| A new route, or a change to an existing one | New route: build it in `api/investigations.py`, add the matching hub pass-through and its test (ladder step 3), regenerate `docs/api/`. Existing route: add, never rename or remove; a breaking change is section 9 |
| A new dependency | Only in `services/ioc/pyproject.toml`, under an existing extra; must install on slim Debian without GPU or system services |
| A deviation from the paper you believe improves it | Off by default, behind an explicit option, written up in `ALGORITHM_IMPROVEMENT_RESEARCH.md` as a deviation; the default path stays the paper's |

## 7. How to work

Work that stays inside `services/ioc/` or follows the decision ladder goes straight to `develop` once CI is green. Only section 9 items wait for the repo owner.

1. Start from the latest code: `git switch develop && git pull`.
2. Work in `services/ioc/`. If the ladder took you to step 3, also run the hub checks from the repo root: `uv run pre-commit run --all-files` and `uv run pytest -q`.
3. Run the same tests CI runs, from `services/ioc/`: `python -m pytest -q tests`. They must pass offline. Browser tests may skip without Chromium; nothing may call a live provider.
4. If you changed anything in `api/schemas.py` or `api/investigations.py`, regenerate and check the reference from the repo root:
   - `python services/ioc/scripts/build_frontend_api_docs.py`
   - `node services/ioc/scripts/verify_frontend_api_client.mjs`
5. Update the existing doc that describes what you changed (usually `API_GUIDE.md`, `WORKFLOW_GUIDE.md` or `METHODS_TODO.md`). Keep it to what exists; plans for unapproved work do not go in.
6. Commit with a conventional message scoped to IOC, for example `feat(ioc): add OTX passive DNS paging`. Allowed types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.
7. Push to `develop`, then check that CI goes green. If it fails, fix it before starting anything else.

Use a separate branch (named after the work, for example `ioc-cskg-output`) only for a section 9 item, and send the repo owner the short proposal from section 9 with it. Everything else goes to `develop`; do not hold finished work back waiting for review.

## 8. What NOT to do

Each item below is a mistake that has already cost a cleanup patch. Do not make them, whatever the reason. Anything not listed here is your call, made with the decision ladder (section 6).

**Files and folders**

1. Do not create top-level folders (no `docs/`, `tools/`, `api/` or similar at the repo root).
2. Do not create a new folder for something that already has one (section 3, second table). Docs go in `services/ioc/docs/` or the existing `.md` files, scripts in `services/ioc/scripts/`, tests in `services/ioc/tests/`.
3. Do not commit generated or local files: zips, `*.egg-info`, `build/`, `output/`, SQLite databases, caches, virtual environments, browser profiles, screenshots of runs.
4. Do not commit secrets: no API keys, tokens or cookies, not even in examples or tests.

**The hub and the pipeline**

5. Do not change how `/api/analyze` splits, orders or numbers sentences, or make it use IOC Hunter's splitter or call IOC first.
6. Do not re-split, merge, drop or reorder sentences a caller sends. Pre-split sentences are used unchanged.
7. Do not change which sentence an IOC is reported in, or add a new filter on top of the existing extraction filters, without approval.
8. Do not put models, validation, rules, storage or IOC logic in the hub. Hub additions stay thin: forwarding, an optional setting, a client field.
9. Do not edit existing hub test assertions to make a change pass. A failing existing hub test means a contract broke. Adding hub tests for your own additions is expected.
10. Do not rename, remove or retype any field, route or error format in section 5.

**Product and UX features (not before the paper is done)**

11. No users, accounts, login, owners, roles, permissions, sharing or teams. No `Authorization` header, tokens, sessions or identity providers. Do not reintroduce `ioc_hunter/access/`, `IOC_HUNTER_LOCAL_ACTOR` or `IOC_HUNTER_ACTOR_ID`.
12. No frontend work: no website screens, no frontend handoff packages for others to build from, no CORS, no JavaScript beyond the existing reference client in `docs/api/`.
13. No job queues, background workers, schedulers, distributed locks across machines, websockets or progress streaming.
14. No new storage: no Postgres, Redis, graph databases or object stores. One SQLite store in `/data`.
15. No notifications, emails, webhooks, admin panels, dashboards or audit-log features.
16. No multi-tenant settings, feature flags for customers, billing or per-user rate limiting.

**The paper and the other modules**

17. Do not change the default behaviour of Algorithm 1's admission gate, the ontology checks or manual selection. Improvements are optional and off by default (section 6).
18. Do not replace manual selection with automation. Automation is added beside it.
19. Do not add TTP predictions, sentence nodes, threat-group labels or embeddings to the IOC graph, and do not start CSKG or attribution work. Those belong to other modules.
20. Do not turn emails and CVEs on by default.
21. Do not write long design documents for unapproved features (for example a 1,000-line API design or a frontend specification). Proposals are short (section 9).

**Running and deployment**

22. Do not change how the container stores data: no host-folder mounts, no new `/data` layout that breaks existing stores, no migration that deletes data.
23. Do not add a required environment variable, a required API key, or any setup step before `docker compose up` works.
24. Do not require a GPU, a specific operating system, or anything beyond slim Debian bookworm. Keep the base image, uid 10001 and port 8002.

**Process**

25. Do not push to `develop` a change that breaks an existing caller (a renamed or removed field, route or error format, or changed sentence handling). Those are section 9 items, on a branch. The same goes for changes to areas the section 3 table marks "ask first" or "do not change". Never edit outside `services/ioc/` beyond what the ladder allows.
26. Do not merge a section 9 branch into `develop` before the repo owner agrees, force-push, or rewrite shared history.
27. Do not skip, delete or weaken tests, mark failing tests as expected failures, or turn off CI jobs to make a push pass.
28. Do not make live provider calls in tests that CI runs.
29. Do not stall when this document is silent, and do not stretch it either: decide with the three principles and the ladder, and keep product features (items 11 to 16) out.

## 9. Before every push, and the few things to ask first

Run this check before every push. One "no" means fix it first, or, if it is an ask-first item, do not push to `develop`.

- [ ] Files outside `services/ioc/` (see `git diff --name-only origin/develop`) changed only through ladder step 3, and each one is needed for this feature.
- [ ] No new folders outside the homes in section 3, and no generated or secret files staged.
- [ ] The work fits section 6 and makes none of the mistakes in section 8.
- [ ] Existing callers keep working: section 5 contracts only gained optional fields, new fields or new routes.
- [ ] Manual selection and the default admission behaviour work exactly as before.
- [ ] `python -m pytest -q tests` passes offline in `services/ioc/`; after a hub change, `uv run pre-commit run --all-files` and `uv run pytest -q` pass at the repo root.
- [ ] If the API changed, `docs/api/` was regenerated and the client check passes.
- [ ] The container still starts with no environment variables and no setup.
- [ ] The commit message is conventional, scoped `(ioc)`, or `(hub)` for a step 3 change; the repo owner is told about `(hub)` commits in one line.

Ask the repo owner first only for these. Everything else is your call.

1. A change that breaks an existing caller: renaming, removing or retyping a field, route or error format in section 5.
2. Anything about the sentence splitter, sentence numbering or the flow of `/api/analyze`.
3. Infrastructure: new containers, volumes or mounts in compose, the base image, CI beyond the `ioc` job, the root `pyproject.toml` or `uv.lock`.
4. Making a deviation from the paper the default behaviour.
5. The output format CSKG will consume.
6. Any change in `datasets/`, `models/`, `services/ttp/` or `frontend/`.

For these, put the work on its own branch and give the IOC module owner this proposal to pass to the repo owner. Keep it under 15 lines and do not commit it:

```text
Proposal for the repo owner: <one-line title>
Why (paper section or problem): <one or two lines>
What changes inside services/ioc/: <files>
What would change outside services/ioc/: <files, or "nothing">
Contract changes (section 5): <field/route, old -> new, or "none">
Default behaviour after the change: <unchanged, or what differs>
How it is tested: <tests>
```

Merge it once the repo owner agrees; a one-line yes is enough. Nothing outside this list needs to wait, including thin step 3 changes to shared code that keep existing callers and defaults working.

## 10. What patch 12 changed in the earlier IOC version, and what to run instead

Patch 12 kept the investigation engine whole and changed three things around it. When asked how to do something the earlier version did, answer from this section.

### 10.1 `/api/analyze` no longer uses IOC Hunter's sentences

**Before:** in real IOC mode the hub sent the text to IOC Hunter first, took IOC Hunter's spaCy sentences and passed those to TTP. Pre-split input was joined with newlines and split again.

**Now:** the hub cuts the report with its own splitter (NLTK punkt, the one D2 is built with; real sentences only), sends the timeline sentences to TTP, and sends every unit to `/v1/extract`, which reports each IOC's units in `sentence_matches`; the hub places each IOC on the timeline. Pre-split input comes back unchanged.

**Why:** CSKG and attribution train on D2, so every sentence index the pipeline produces must match D2's. On all 3,285 D2 reports the hub splitter cuts none of 7,862 indicator tokens, whereas spaCy glued headings onto the next sentence and lost indicators.

**What it means:** for the same report, sentence 5 in `/api/analyze` and sentence 5 in an investigation can be different sentences. So:

- Inside an investigation, keep using the investigation's own sentences and passages for highlighting. Nothing changes there.
- To connect an investigation to an analysis, or later to CSKG, join on the IOC (type, value), never on a sentence number.
- If an IOC must be placed in D2/hub numbering, call `/v1/extract` with the report text and the hub's units and read `sentence_matches`. Do not change `/api/analyze` or the splitter for this (section 9, item 2).
- IOC Hunter now cuts reports with `ioc_hunter/text.py`, a byte-identical copy of the hub's splitter and its data (tests on both sides fail if they differ; change the hub's and copy it, never edit the copy alone). An investigation's sentences and passages are the hub's units of the report; the hub's timeline is the units of kind "sentence". An IOC found only outside a sentence takes the nearest sentence before it as its context, the paper's "original text passage".

### 10.2 Users and accounts were removed

**Before:** every investigation had an owner, requests carried an `Authorization` header, and the routes answered 503 unless `IOC_HUNTER_LOCAL_ACTOR=local` was set.

**Now:** no users, no login, no header, no setting. Every investigation belongs to the one built-in owner, and history lists all of them. The owner tables are still in the database, unused, so adding users later needs no migration. That decision comes after the paper is done (section 8, item 11).

### 10.3 The database lives in the `ioc-data` volume, not a host folder

**Before:** compose mounted `services/ioc/output/investigations` from the host at `/data`, so the terminal on the host and the container shared one database. On Linux that folder was not writable by the container's user (uid 10001), and it left the old volume's data behind.

**Now:** the stack's database is in the `ioc-data` volume at `/data`. The `ioc-hunter` terminal command is installed in the container and uses `/data` by default, so run it inside the container to work on the same investigations the website and API see. Run these from the repo root, with the stack up (`docker compose up -d`).

| To do this | Run |
| --- | --- |
| List saved investigations | `docker compose exec ioc ioc-hunter runs` |
| Start an investigation by pasting the report | `docker compose exec ioc ioc-hunter investigate --paste` (end the text with a line `.done`) |
| Start one from a report file on the host | `docker compose cp report.txt ioc:/tmp/report.txt` then `docker compose exec ioc ioc-hunter investigate /tmp/report.txt` |
| Continue a saved investigation | `docker compose exec ioc ioc-hunter investigate --resume <RUN_ID>` |
| Export one to the host | `docker compose exec ioc ioc-hunter export <RUN_ID> --output /tmp/<RUN_ID>.json` then `docker compose cp ioc:/tmp/<RUN_ID>.json .` |
| Back up the whole database | `docker compose cp ioc:/data ./ioc-data-backup` |

**Moving investigations saved in the old host folder into the volume (once):**

1. Back up what the volume holds now: `docker compose cp ioc:/data ./ioc-data-backup`.
2. Copy the old folder in. This replaces the volume's database files with the host's, so do it only if the volume holds nothing still needed: `docker compose cp services/ioc/output/investigations/. ioc:/data/`.
3. Give the files back to the container's user, because copied files arrive owned by root: `docker compose exec -u root ioc chown -R ioc:ioc /data`.
4. Restart the service and check: `docker compose restart ioc` then `docker compose exec ioc ioc-hunter runs`.

**Working outside Docker** (development only): running `ioc-hunter` from `services/ioc/` on the host still works and uses `services/ioc/output/investigations/` by default. That is a separate database from the stack's. Do not mount it into the container again (section 8, item 22); move data with the steps above instead.
