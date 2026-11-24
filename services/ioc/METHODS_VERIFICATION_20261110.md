# Implementation and verification: 10 November 2026

The five additional OTX methods are implemented. The catalogue contains
**48 implemented methods / 20 disabled candidates / 68 total**.
This includes the preceding eight HA additions and eight original candidates.

## Five OTX methods

| Method | Implemented extraction |
| --- | --- |
| `alienvault.email_to_domain` | Ordinary email-text pulse search -> listed domain/hostname indicators |
| `alienvault.email_to_email` | Same discovery -> other listed email indicators |
| `alienvault.geo_location_to_ipv4` | Country-code pulse search -> listed IPv4 indicators |
| `alienvault.port_to_protocol` | Pulse URL indicators with the queried explicit port -> HTTP/HTTPS/FTP scheme |
| `alienvault.protocol_to_port` | Pulse URLs with the queried HTTP/HTTPS/FTP scheme -> explicitly written ports |

`providers/otx_pulses.py` owns the source search/indicator contract and extraction.
`alienvault.py` owns method registration and dispatch. Both stages use the shared
FollowUp executor; ordinary configured OTX API backups remain available. Pulse
IDs are private navigation references, not additional public ontology IOC types.
`validation.py` checks source/query/type/field correctness. The workflow's
relationship admission remains unchanged.

Country lookup is topic discovery from country-related pulses, not IP-country
enumeration. Protocol/port coverage is the explicit URL subset; no default ports
or inferred transport protocol are emitted. Country input retains the existing
two-letter country-code convention.

## Actual source contracts

Fresh anonymous browser observations established both current website responses:

- Search: `/otxapi/pulses/?limit=20&page=1&sort=-modified&q=8080`.
- Indicators: `/otxapi/pulses/{24-hex-id}/indicators/?sort=-created&limit=10&page=1`.

The adapter captures those responses through the normal browser pages. Raw
captures are in [the search/pulse observation](output/research-otx-pulses/20261110T044652Z/metadata.json).
Minimized source fixtures retain actual count/next fields and are explicitly
partial. Five-method positive replay cases are synthetic and labelled as such.

## Automated verification

Final command, run after the production changes:

```powershell
& 'D:\SEMESTERS\FYP\code\ioc-hunter\.venv\Scripts\python.exe' -B -m pytest tests -q --disable-warnings
```

**445 passed; 252 subtests passed**, in 118.02 seconds. The run reported 5,842
warnings. `git diff --check` passed; Git also reported existing CRLF/LF notices.

Coverage includes all new methods through the real lookup/validation/receipt
pipeline, source query and pulse identity checks, malformed/access/empty cases,
explicit URL components, API fallbacks and credential isolation, bounded reads,
cache isolation, provider-stop policies, workflow/API compatibility and replay.
The OTX-specific suite has 37 passing tests. Test results are not live-access
guarantees.

Live testing exposed an HA transport defect: Playwright's `:has-text()` selector
does not match script contents. Shared HTML readiness now checks a declared
literal marker against DOM `textContent`. An actual local-browser regression
reproduces the old failure and verifies the fix. The fixed live SHA-256 method
returned two command/name observations in 3.51 seconds.

## Uncached live results

Every retained production live attempt used **cache_ttl=0** and a fresh browser
context. The summary tool independently checked manifest values and every
receipt's `cache_hit: false`, including required follow-up reads.

| Provider | Implemented | Distinct methods attempted live | Methods with positive outputs |
| --- | ---: | ---: | ---: |
| RapidDNS | 9 | 9 | 9 |
| OTX | 16 | 2 | 1 |
| VirusTotal | 15 | 3 | 2 |
| Hybrid Analysis | 8 | 8 | 1 |
| **Total** | **48** | **22** | **13** |

There are **27 retained production live attempts** across these methods. Partial
results count as positive only when concrete outputs were actually returned.
There are **26 methods without a completed live attempt in this run**. All 48
remain covered by the automated suite; this table does not imply 48 successful
live lookups.

Positive examples:

- RapidDNS returned outputs for all nine methods. The IPv4 discovery follow-up
  returned 16 other IPv4 and 10 IPv6 addresses from a Python.org address.
- VT's new IPv4 -> command/API returned **24** outputs. IPv4 -> IPv4 returned
  **130** outputs. Both used source-derived input `204.79.197.203` and were partial
  because discovery/follow-up scope was capped.
- OTX domain -> email returned **2** contacts for `python.org`.
- HA SHA-256 -> command/API returned **2** observations after the readiness fix.

### External limits and unverified cases

- **The OTX browser encountered HTTP 429** during the second audit method, with
  `Retry-After: 2305` seconds. A later diagnostics review established that the
  first throttled request was the optional comments endpoint; analysis/scans/
  malware widgets also returned 429, while general/geo/WHOIS/URL-list requests
  returned 200. The requested passive-DNS response was not observed before
  acquisition stopped. The current browser transport escalates any provider XHR
  429 to a source-wide cooldown. **This does not prove the DNS operation, or all
  OTX methods, required a 38-minute cooldown.** The throttle's actual scope is
  unresolved. The audit stopped under that conservative client policy. The five
  new OTX methods passed their automated pipeline tests but **were not live
  executed** during this blocked audit.
- **VT domain -> IPv4 returned HTTP 429**, including a later paced retry. Its
  retry interval was respected. The two new VT methods subsequently succeeded;
  twelve other VT methods remain without a live attempt in this run.
- **HA search coverage remains limited** by the observed default last-hour
  filter. Historical MD5/SHA-1 and filename searches returned partial empty
  results or access errors. Command/registry content searches did not produce
  usable completed responses. Account access and historical discovery remain
  unresolved; the SHA-256 report success does not validate those directions.
- Ordinary `/sample/{MD5}` and `/sample/{SHA1}` navigation was also inspected.
  Both returned HTTP 200 pages without unified report data. Those unverified
  alias routes were not added to production as a workaround.

Earlier sandbox-denied attempts are retained separately and excluded from the
live provider counts above. No source block triggered credential rotation,
transport switching around a rate limit, scan submission or sample download.

## Inspectable artifacts

- [Machine-readable live summary with all receipts](output/verification-20261110/live-summary.json)
- [RapidDNS initial audit](output/live-rapiddns-all-20261110/REPORT.md) and
  [additional positive controls](output/live-rapiddns-positive-20261110/REPORT.md)
- [OTX audit and rate-limit receipt](output/live-otx-final-20261110/REPORT.md)
- [VT new-method positives](output/live-vt-new-methods-20261110/REPORT.md),
  [initial rate limit](output/live-vt-final-20261110/REPORT.md) and
  [paced retry](output/live-vt-remaining-20261110/REPORT.md)
- [HA initial audit](output/live-ha-final-20261110/REPORT.md) and
  [fixed report-readiness check](output/live-ha-readiness-fixed-20261110/REPORT.md)

No successful live claim is made for an empty result, blocked source or synthetic
fixture. Completing live coverage requires source access/cooldown availability;
remaining research candidates stay disabled.
