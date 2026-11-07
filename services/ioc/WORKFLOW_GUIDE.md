# Run a saved IOC investigation

The terminal workflow takes a report through extraction, a manually selected
lookup, relationship validation and persistent graph admission. You can inspect
the exact evidence, reopen the investigation and export a self-contained JSON
result. All canonically valid extracted IOCs become initial graph nodes, including
IOCs without implemented lookup methods. Sharing a report does not create an edge.

This guide uses the synthetic fixtures in `examples/manual-workflow/`. They
exercise the real extractor, parser, validator and repository without contacting
providers. They are examples, not observations from a real incident.

## Prepare the environment

Run commands from `dev/Project-Sherlock/services/ioc`, with this service importable
and its extraction dependencies installed. Follow [the README setup](README.md#setup-and-commands)
to select an interpreter. The examples below use `python`; in the existing
Windows environment, replace it with `& $iocPython` after the README setup.
Replay does not require credentials or a browser. Live browser routes need
Playwright and its Chromium installation.

Use a dedicated `--store` directory for each demonstration or live investigation
collection. Runs, lookup receipts and response snapshots share its
`lookups.sqlite3` database. The investigation default is `output/investigations`;
the standalone `lookup` command has a separate default, `output/lookups`.

## Start the offline example

```powershell
python -m ioc_hunter investigate examples/manual-workflow/report.txt --mode replay --replay examples/manual-workflow/replay.json --store output/demo
```

The terminal displays a saved run ID, its mode, extracted IOCs and method
availability. Reference sections are excluded by default and preserved in
extraction diagnostics. The example contains `example.com`, `192.0.2.10` and a
SHA256 hash. The hash remains visible even though it has no implemented lookup.

1. Select `example.com` by its displayed number or full node ID.
2. Select `rapiddns.domain_to_ipv4` by number or method ID.
3. Inspect the summary, then enter `back` to return to the IOC list.
4. Enter `details 1` to read the complete step, evidence and rejection fields.

The fixture provides DNS records for `example.com` at `192.0.2.10` and
`192.0.2.12`. Because `192.0.2.10` is an existing unused candidate, graph admission
passes: both validated addresses receive method-labelled edges, and `192.0.2.12`
becomes a new node. A record for `sub.example.com` is rejected for the exact-host
mismatch. Repeated records merge evidence instead of duplicating graph elements.

To inspect a validated result that does not enter the graph, select the newly
added `192.0.2.12`, then `rapiddns.ipv4_to_domain`. Its fixture returns the already
used `example.com`. The relationship is valid, but the overlap condition fails;
the step retains its validated output and evidence without adding an edge.

## Inspect, save and close an investigation

| Terminal command | Result |
| --- | --- |
| IOC number or full ID | Show compatible methods for that IOC |
| `ioc NUMBER` | Print the IOC's complete saved fields |
| `iocs` or `iocs START_NUMBER` | Show the first page or another page of IOCs |
| `steps` | List completed lookup steps and admission outcomes |
| `details` or `details STEP_NUMBER` | Print the latest step or a selected step with its receipt |
| `export PATH` | Write the run, graph, steps, receipts and source snapshots as JSON |
| `save` | Leave the investigation open for later lookups |
| `finish` | Mark the investigation completed |
| `cancel` | Mark the investigation cancelled |
| `help` | Show command guidance |

At a method prompt, use `back` to return to the IOC list, or `all` to inspect
methods that are unavailable for this mode. Implemented/configured status does
not certify current provider access. VirusTotal domain-to-URL remains unavailable
for live selection because its route is unresolved.

State is saved as operations complete. `save` exits without closing the run;
`finish` and `cancel` preserve evidence but prevent further lookup steps in that
run. Closed runs remain available through `runs` and `export`.

```powershell
python -m ioc_hunter runs --store output/demo
python -m ioc_hunter investigate --resume RUN_ID --store output/demo
python -m ioc_hunter export RUN_ID --store output/demo --output output/demo/investigation.json
```

Replace `RUN_ID` with the printed ID. Resuming retains the saved limits,
extraction options and mode. Replay runs also retain their manifest location and
fixture digest; keep the original manifest and body files available. Changed
fixtures or an explicit different mode are rejected. A closed run can be
exported without its replay files.

## Submit your own report

Input is either a UTF-8 text file, pasted text or one explicit CSV/XLSX data row:

```powershell
python -m ioc_hunter investigate report.txt --mode live --store output/live
python -m ioc_hunter investigate --paste --mode live --store output/live
python -m ioc_hunter investigate --dataset reports.csv --row 670 --mode live --store output/live
```

End pasted text with `.done` on a line by itself; blank lines remain part of the
report. Datasets require a `cti_content` column. `--row` counts data rows from 1,
excluding the header, and does not refer to a dataset's `index` column. The
workflow requires the dataset path explicitly. `IOC_HUNTER_DATASET` remains an
option for the older interactive extraction command.

New investigations default to live mode unless `--replay` selects replay mode.
Live lookups contact the selected provider and may return partial, empty or
failed outcomes. `OTX_API_KEY` and `VT_API_KEY` remain optional fallback
credentials. No live availability is implied by the offline example or by
earlier provider audits. PDF/DOCX conversion is outside this terminal milestone.

`--include-references` retains reference sections during extraction;
`--extended-types` adds email/CVE to the default seven IOC types. Reports are
limited to 2,000,000 characters.

## Understand graph admission

The policy name is `manual-selection/paper-admission-v1`. You select the IOC and
method. The runner then applies Algorithm 1, line 26:

```python
admitted = bool(valid_output_ids & (known_ioc_ids - used_ioc_ids))
```

The selected input is marked used before the test. The sets describe the graph
before returned outputs are added. If at least one validated output matches a
known unused candidate, the runner admits all validated outputs and their
supported edges, within the node limit. Otherwise, it keeps the receipt and
validated observations without changing the graph.

This is candidate overlap, not graph-cycle detection. Evidence validation asks
whether source fields support each exact relationship; admission asks whether
the result batch passes the paper's condition. A valid relationship, an admitted
edge and a rewarded method are distinct outcomes. Paper reward remains
`null` with `reward_status: not_evaluated`; full Algorithm 1 ranking, counters,
five-round scheduling and LLM selection are not implemented by this policy.

IOC graph edges are undirected and identified by their endpoints and method.
Reverse retrieval methods retain separate edges and provenance. Rediscovered
nodes merge contexts, sources, passages and evidence links; report-origin nodes
retain their report origin. The export preserves rejected candidates,
non-admitted outputs, partial reasons and operational failures.

## Limits and recovery

| Option | Default | Scope |
| --- | --- | --- |
| `--max-steps` | 20 | Lookup steps, including failed/interrupted attempts |
| `--max-nodes` | 1000 | Canonical nodes in the admitted graph |
| `--max-seconds` | 600 | Accumulated extraction and lookup acquisition time |
| `--max-pages` | 2 | Pages per lookup |
| `--max-outputs` | 1000 | Unique validated outputs per lookup |

Limits must be positive. The active-time budget excludes time spent reading
terminal prompts and is checked between steps. An in-flight provider request is
bounded by transport deadlines and can finish before the run stops. This is not
an immediate request-cancellation mechanism. Partial lookups can contribute
validated outputs if admission passes; failures remain visible and do not
prevent a later independent manual lookup while limits permit.

The repository records a step and its reserved lookup ID before acquisition.
If acquisition saved a receipt before interruption, resume commits from that
receipt without repeating the provider request. If no receipt exists, resume
records `interrupted_unknown` and requires another explicit selection to retry.
Completed-step replay does not duplicate nodes, edges or evidence links. An
interrupted extraction retains the submitted report and becomes failed on
resume; submit the report again to start a new extraction.

Use one terminal worker at a time. Revision
checks and a single active-step rule protect commits; they do not provide
distributed job ownership or a multiworker queue.

## Replay manifest reference

A manifest declares version 1 and provider-shaped responses. This example
loads a synthetic HTML fixture from the manifest's directory:

```json
{
  "version": 1,
  "description": "Synthetic offline DNS response; not a live observation.",
  "documents": [
    {
      "source": "rapiddns",
      "request_url": "https://rapiddns.io/subdomain/example.com?page=1",
      "operation": "dns",
      "body_file": "rapiddns.html",
      "format": "html",
      "retrieved_at": "2026-01-04T00:00:00+00:00"
    }
  ]
}
```

Each entry matches the provider source, request URL and operation. Instead of
`body_file`, use an inline `body` string. Body files must remain inside the
manifest directory. An `error_status` with optional `error` text simulates a
provider failure without a response body. Requests must target configured
provider hosts; missing fixture mappings fail without network fallback. The
transport is injected for both HTTP and browser routes. The persisted digest
covers fixture contents as well as the manifest fields.

## Verification and next integration

The offline tests exercise real extraction and validation, exact receipt
association, overlap admission, rejected and non-admitted results, persistence,
rollback, idempotence, interrupted-step recovery, limits and terminal interaction.
The existing workspace environment includes pytest. If preparing a separate test
environment, install it with `python -m pip install pytest`. Run the focused
checks from the service directory:

```powershell
python -m pytest tests/test_workflow.py tests/test_workflow_repository.py tests/test_workflow_terminal.py tests/test_lookup_details.py -v
```

Use `python -m pytest tests` for the full suite, including provider fixtures,
HTTP API tests and intercepted browser tests; its optional dependencies are
described in the README. unittest discovery does not execute the pytest-style
workflow and HTTP tests.
Provider-dependent checks remain opt-in; the historical
[method reliability results](METHOD_RELIABILITY_RESULTS.md) are dated evidence.

The [saved investigation APIs](API_GUIDE.md) now expose the shared application
used by the terminal through the Hub. Frontend investigation controls, durable
background jobs and full Algorithm 1 selection/accounting remain later work.
SecureBERT context embeddings and downstream attribution remain separate work.
