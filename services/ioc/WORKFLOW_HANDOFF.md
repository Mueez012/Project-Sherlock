# Workflow implementation handoff

7 November update: [saved investigation APIs](API_GUIDE.md) are implemented over
the same application service used by the terminal. IOC Hunter sentences are
canonical, storage defaults are shared, execution is coordinated per run, and
identity/access is a separate pluggable module. The older notes below preserve
the terminal milestone and its dated verification; frontend investigation UI,
full account management and background job scheduling remain separate work.

Updated: 4 November 2026. The saved terminal workflow is implemented. Start with
[the workflow guide](WORKFLOW_GUIDE.md) for commands, graph admission and recovery;
the [14 October plan](WORKFLOW_IMPLEMENTATION_PLAN.md) remains a historical design
record. Read applicable repository instructions before changing code.

## Next objective

Use the working terminal path as the integration boundary: submit report text,
review extracted IOCs, choose an IOC/method, inspect its evidence and admission,
then save, resume or export the investigation. Follow with Hub integration and
full Algorithm 1 through the same runner. SecureBERT encoding and downstream
attribution are separate later work. Method additions remain in
[METHODS_TODO.md](METHODS_TODO.md); do not restart the completed provider refactor.

## Existing pieces and boundaries

- `ioc_hunter/extraction/pipeline.py`: non-interactive `extract_report()` returns
  extracted IOC objects and original report context.
- `ioc_hunter/methods.py`, `method_spec.py`, `method_candidates.py`: 21 implemented
  methods and 39 disabled candidates. Local availability is not live readiness.
- `ioc_hunter/providers/`: separate RapidDNS, AlienVault OTX and VirusTotal
  adapters. Paper website/report-page interfaces are primary; official APIs are
  optional credentialed fallbacks. Browser-generated JSON capture is supported.
- `ioc_hunter/lookup.py`: retrieval, cache, parsing and independent validation;
  methods retain `IOC -> list[IOC]`. `lookup_detailed()` returns the exact
  call-scoped receipt and accepted relationship/evidence associations.
- `ioc_hunter/validation.py`: deterministic evidence and ontology checks.
- `ioc_hunter/storage.py`: SQLite lookup receipts, snapshots, cache and budgets;
  existing lookup tables remain intact.
- `ioc_hunter/workflow/repository.py`: versioned `wf_*` tables in the same
  SQLite database for report/run state, steps and canonical graph records.
- `ioc_hunter/workflow/runner.py`: extraction, selected lookup execution,
  receipt-based recovery, transactional graph commits and export.
- `ioc_hunter/workflow/policies.py`: manual selection with the paper's
  candidate-overlap admission condition; reward is not evaluated.
- `ioc_hunter/workflow/replay.py`: fixture-backed HTTP/browser transport.
- `ioc_hunter/workflow/terminal.py`: interactive IOC/method selection, outcomes
  and evidence inspection; `main.py` exposes `investigate`, `runs` and `export`.

Keep the strict ontology: graph connections are undirected; lookup methods are
directional. Provider adapters must not select the next IOC, assign algorithm
reward or mutate graph state. Preserve rejected candidates and partial outcomes.

## Admission boundary and remaining work

The selected input IOC becomes used before evaluating
`bool(valid_output_ids & (known_ioc_ids - used_ioc_ids))`. A pass admits all
validated outputs and supported edges within graph limits. A failure preserves
the receipt and validated observations without graph additions. This reproduces
the paper's candidate-overlap gate; it is not a graph-cycle detector. Evidence
validation remains independent of this admission decision.

The policy does not implement method ranking, coverage/tried counters, five-round
scheduling or LLM selection. Its reward remains unevaluated. Future Algorithm 1
work must define cold-start scoring, retries/cache accounting and LLM output
validation against the original pseudocode before enabling automation.

The existing HTTP extraction/lookup door does not expose investigation jobs.
Hub/web integration should call the reusable runner, retain exact receipt IDs,
and display real run/evidence state. The terminal currently assumes one worker;
distributed jobs need ownership and shared coordination. Preserve separate
manual selection and algorithm policy boundaries.

## Persistence and recovery

The report is saved before extraction. Initial graph publication and extraction
state commit together. A lookup step reserves its lookup ID and marks its seed
used before acquisition; graph changes and completed-step state commit in one
transaction. Replaying a completed step is idempotent. If an interrupted step
has a saved receipt, resume uses it without another acquisition. Without a
receipt, resume records `interrupted_unknown` and requires an explicit retry.

Use the same `--store` to reopen an investigation. `save` leaves it open;
`finish` and `cancel` close it without deleting evidence. Modes are persisted,
replay fixture contents are checked on resume, and JSON export includes receipts
and source snapshots. Keep synthetic fixture results separate from live audits.

## Verification strategy and historical limitations

WSL investigation audit, 4 November 2026: run
`7a1cc79e69a044b3a2e4c0a3bc67c771` contains eight steps. Six ended with a generic
browser error before producing provider evidence. A local browser launch without
navigation confirmed that the Linux Playwright headless Chromium executable was
missing. No WSL software was installed by the agent. See the WSL setup in the
README; new receipts now distinguish `browser_binary_missing` and
`browser_dependencies_missing` with commands for the same Python environment.

The same audit found a RapidDNS reverse-lookup response with an exact queried
IP, scoped `Total: 0`, an empty DNS table and guest limits. It was previously
classified as loading. A conservative provider-specific empty-result proof now
recognizes it as partial empty, while rejecting wrong-query, nonzero, loading
and challenge/login-gated templates. Reprocessing the original saved snapshot
returns zero observations with incomplete guest coverage. Existing investigation
records and lookup receipts were not rewritten. Its two RapidDNS domain-to-IP
steps each retained 19 validated outputs but added no edges because the paper's
known-unused overlap condition failed.
After these repairs, the complete offline service suite passed **166 tests and
33 subtests**. This does not certify live browser access before the missing WSL
runtime is installed.

On 4 November 2026, the complete service suite passed **150 tests and 17
subtests**. A scripted invocation of the actual terminal CLI also saved and
exported the synthetic example with four IOC nodes, two admitted edges, one
rejected candidate and its source snapshot. This is offline workflow evidence,
not a current availability certification for all providers.

A bounded live run also used the real dataset row 670, extracted `mypiltow.com`
and executed RapidDNS through `WorkflowRunner.execute_step()`. HTTP acquisition
timed out and the browser route encountered an external-login redirect. The
saved step has `outcome_status: login_required`, retains its transport failures
and adds no graph edges. Repeating outside the sandbox had the same final
outcome. No positive live-provider result is claimed for this check. Local
evidence: `output/workflow-live-verified-20261104-140437/summary.json` and its
evidence-inclusive `investigation.json`.

[Workflow tests](tests/test_workflow.py),
[repository tests](tests/test_workflow_repository.py) and
[terminal tests](tests/test_workflow_terminal.py) cover the connected offline
path, admission, exact evidence, partial/error outcomes, limits, rollback,
resume and export. Run the suite for current results; no new live-provider
certification is implied by this implementation.

[METHOD_RELIABILITY_RESULTS.md](METHOD_RELIABILITY_RESULTS.md) records the
14 October baseline: 90 offline tests passed; 17 methods live-positive in iterative
repair checks, three completed with no applicable data, one unresolved
(VirusTotal domain-to-URL). This is not repeated final-version certification.
VirusTotal pagination remains partial and official API fallbacks remain untested
without credentials. OTX domain-to-URL pagination has a verified two-page UI test.

[CTI_REPORT_LOOKUP_TEST.md](CTI_REPORT_LOOKUP_TEST.md) records extraction from
dataset row 670 (MageCart), selecting `mypiltow.com`, and running all eight
domain-input methods. It produced 29 distinct validated IPv4 outputs across
sources. That historical test predates the saved investigation workflow and
does not evaluate Algorithm 1 reward.
Raw bodies, receipts and report context are linked in that document.

## Local commands

Run from `D:\SEMESTERS\FYP\dev\Project-Sherlock\services\ioc` in PowerShell.
The existing environment is under the original standalone checkout:

```powershell
$env:PYTHONPATH = (Get-Location).Path
$iocPython = 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe'
& $iocPython -m ioc_hunter investigate examples/manual-workflow/report.txt --mode replay --replay examples/manual-workflow/replay.json --store output/demo
& $iocPython -m pytest tests -v
```

Live tests are opt-in and need provider network access. Preserve existing audit
outputs; use a new output directory for reruns. No provider credentials or
authenticated browser state were used in the reported repair checks.

Suggested fresh-chat instruction:

> Read services/ioc/WORKFLOW_HANDOFF.md and WORKFLOW_GUIDE.md, then inspect the
> existing workflow runner and tests. Continue from the saved terminal workflow.
> Keep extraction, evidence validation, paper admission and future method
> selection/accounting separate. Preserve existing lookup interfaces, saved data
> and historical audit evidence while preparing Hub integration.
