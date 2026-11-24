# First four method implementation and verification

Date: **9 November 2026**. Target: `dev/Project-Sherlock/services/ioc`.

The following four methods were implemented and registered in the first batch,
bringing the catalogue to **25 implemented methods and 35 disabled candidates**
at that stage. The later OTX batch is recorded separately in the
[next-method verification report](NEXT_METHODS_VERIFICATION.md).

| Method | Implementation | Current access requirement |
| --- | --- | --- |
| `virustotal.md5_to_command_api` | Shared file-report browser operation | No API key; optional keyed API fallback |
| `virustotal.sha1_to_command_api` | Same operation with the supplied SHA-1 | No API key; optional keyed API fallback |
| `virustotal.sha256_to_command_api` | Same operation with the supplied SHA-256 | No API key; optional keyed API fallback |
| `virustotal.url_to_filename` | Existing URL-details response/cache; explicit Content-Disposition filename | Existing browser report route, with configured official API fallback |

## Implementation boundary

All methods retain `IOC -> list[IOC]`, the existing `LookupClient`, source
adapters, method-correctness validator, ordinary receipts and snapshots. The
workflow still owns its known/used IOC sets, overlap gate, graph updates and
recovery. No confidence ranking, graph-admission change, hash-alias ledger,
metadata round trip or dependent-acquisition framework was added.

The hash methods share one source operation/parser and accept any of the three
supported digest types directly. The existing browser transport opens
`/gui/file/{inputhash}/behavior` and captures the page-generated
`/ui/files/{reporthash}/behaviours` list. VirusTotal can navigate from MD5/SHA-1 to
the canonical SHA-256 page itself. A provider-declared `page_identity_pattern`
lets the transport match the exact actual file-page hash, keeping the original
request/page URLs in normal diagnostics. There is no separate metadata request.
If configured, the official keyed `/api/v3/files/{inputhash}/behaviour_summary`
route remains a fallback. Both source schemas share the same field extractor.
They extract only documented
`command_executions`, `calls_highlighted` and `invokes` fields, retaining which
field supplied each value. A highlighted API or reflected invocation is not
relabeled as an executed shell command.

URL-to-filename uses a filename explicitly present in the source's stored HTTP
response header. It supports quoted and extended encoded filenames, checks the
queried URL and rejects ambiguous/malformed header data, paths and controls.
An absent optional filename is a completed `filename_unavailable` result. It
never guesses a filename from the URL path or downloads the referenced file.

## Offline verification

The corrected browser-first revision passed the complete service suite:
**270 tests and 155 subtests**. This includes actual captured behavior-data
regressions for all three hash inputs, intercepted browser navigation/response
tests, browser/API fallback cases and saved-workflow replay. Positive
filename/header controls remain explicitly synthetic; hash behavior also has
captured and live positives.

Relevant tests:

- [Hash-family routing, source schemas, cache and errors](tests/test_hash_behaviour.py).
- [Content-Disposition syntax and source-field evidence](tests/test_url_filename.py).
- [Exact current-file page matching and canonical navigation](tests/test_hash_browser_transport.py).
- [Registered lookup, cache reuse, malformed/empty responses, raw JSON duplicate
  keys and all-four saved workflow replay](tests/test_first_four_methods.py).
- Existing extraction, provider, browser, API, registry, workflow and recovery
  regressions were included in the full suite.

The saved-workflow test runs all four without real credentials using the existing
fixture-only transport. No credential substitute or special replay routing is
needed. Real API-key configuration remains false. It proves no network access, exact receipts,
save/reopen/export and unchanged graph admission: valid lookup outputs can be
retained even when no known-unused overlap exists.

## Live checks and limitations

No VirusTotal API key was configured. All three corrected hash methods completed
through the normal browser transport with uncached live responses:

| Hash input | Actual provider outcome |
| --- | --- |
| MD5 `c438b19e627b1c1e9cb8970f2fe5f929` | `ok`, 17 returned command/API IOCs, 17 accepted evidence rows, no rejected rows or transport errors |
| SHA-1 `f9e903e70baf8a3cece4bf554ce3d6fae63c1805` | Same outcome |
| SHA-256 `f55fe457929044e4c4cdc62b4ad0a4955bd2faac2b642318649beede66086eb4` | Same outcome |

Each input refers to the same file. The source response contains nine sandbox
reports, with sixteen command-execution entries and one highlighted API call.
MD5 and SHA-1 navigation reached the canonical SHA-256 report page. The normal
lookup receipts retain the requested input and actual browser response/page.
These results establish this sample's browser acquisition; they do not guarantee
every hash has stored behavior data or that provider access will never change.

At the user's request, the relevant URL check used a domain other than the
placeholder domain:

| Input | Actual provider outcome | Meaning |
| --- | --- | --- |
| `https://download.sysinternals.com/files/ProcessExplorer.zip` | Completed `empty`, reason `filename_unavailable` | VirusTotal returned the bound URL report and stored HTTP headers, without a Content-Disposition filename. No filename was invented from the path. |
| `https://github.com/python/cpython/archive/refs/tags/v3.12.0.zip` | `not_found` | The requested VirusTotal report returned 404. This does not describe whether the original download URL works. |

The source snapshot for Sysinternals contains the exact URL and twenty stored
header names, without Content-Disposition. Receipt ID:
`018b27eb0fe9418ca43c71ff2e5eeb65`. Source snapshot ID:
`4b88c1f32113204a5b66323f31c77d9e419d3df1fdce012cbe19cc9fe2a46dda`.

Artifacts:

- [Keyless live audit of all three hash methods](output/live-methods-20261109T085645Z/REPORT.md),
  including raw responses, returned IOC objects, exact receipts and a manifest
  recording no configured API keys.
- [Initial SHA-256 browser-route observation](output/hash-browser-probe-20261109/metadata.json)
  and [MD5 canonical-navigation observation](output/hash-browser-probe-20261109/c438b19e627b1c1e9cb8970f2fe5f929/metadata.json).
- [Sysinternals live audit](output/live-methods-20261109T083000Z/REPORT.md),
  [exact receipt](output/live-methods-20261109T083000Z/virustotal.url_to_filename/receipt.json)
  and [raw source JSON](output/live-methods-20261109T083000Z/virustotal.url_to_filename/raw-01.json).
- [GitHub report-not-found attempt](output/live-methods-20261109T082848Z/REPORT.md).
- The initial API-only revision's missing-key outcomes are superseded by the
  keyless browser results above. Sandbox-blocked navigation was not treated as
  provider availability evidence; live checks used approved network access.
- [Curated captured Sysinternals fixture](tests/fixtures/vt_url_filename_sysinternals_captured.json)
  retains the source URL identity and header fields for offline regression;
  [fixture provenance](tests/fixtures/README.md) distinguishes it from synthetic
  positive controls. It is a subset, not the full original response.
- [Captured behavior-data subset](tests/fixtures/vt_file_behaviours_ui_captured.json)
  retains all nine report identities and the original command/API fields.

No files, URLs or scans were submitted and no destination download was visited.
The source reports were read through the provider route. All three hash methods
have live-positive outputs. URL acquisition completed without an applicable
filename. The optional keyed hash fallback remains covered offline, without a
live-key access claim.

## Reproduce

Run from the IOC service directory with the existing Python environment and use
a fresh audit output directory. The audit supports explicit hash inputs as well
as domain/IP/URL inputs. Hash browser acquisition does not need VT_API_KEY.

```powershell
& 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe' -B -m pytest tests -q --disable-warnings
& 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe' -B tests/live_methods_audit.py --source virustotal --method virustotal.url_to_filename --max-pages 1 --url https://download.sysinternals.com/files/ProcessExplorer.zip
& 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe' -B tests/live_methods_audit.py --source virustotal --method virustotal.md5_to_command_api --method virustotal.sha1_to_command_api --method virustotal.sha256_to_command_api --max-pages 1
```

The historical [13 October audit](LIVE_METHODS_AUDIT.md) and
[14 October repair results](METHOD_RELIABILITY_RESULTS.md) are unchanged and do
not certify these four additions. See [lookup foundation](LOOKUP_FOUNDATION.md),
[implementation map](METHOD_IMPLEMENTATION_MAP.md) and
[current catalogue](ONTOLOGY_METHODS.md).
