# Live method audit — 13 October 2026

Historical baseline. See [14 October repair verification](METHOD_RELIABILITY_RESULTS.md)
for the changed implementation: 17 positive live methods, three completed no-data
results, and one unresolved route during the repair checks.

**10 of 21 implemented methods returned validated outputs for at least one tested input.**
The other 11 are not confirmed working by this audit. This is sample-based live
verification, not a claim that every input, provider page or API fallback works.

All 72 offline tests passed. All 39 disabled research candidates returned
`unsupported_method` without a network call. No production lookup, parsing or
validation code was changed during this audit.

## Conditions

- Initial pass: all 21 implemented methods, using `example.com`, `1.1.1.1`,
  `2606:4700:4700::1111`, and `http://example.com/`.
- Follow-up: five inconclusive VirusTotal methods, using the same domain,
  `8.8.8.8` and `2001:4860:4860::8888` for the IP methods.
- Fresh network retrieval per method (`cache_ttl=0`), one page maximum, normal
  15-second source pacing, no API keys and no supplied authenticated browser state.
- Only existing provider reports were queried. No files, URLs or scans were submitted.
- An earlier sandbox-restricted attempt was stopped after confirming
  `ERR_NETWORK_ACCESS_DENIED`. It is excluded from provider results below.
- Times in manifests and receipts are UTC. The report date is 13 October 2026
  in Asia/Karachi, as supplied by the client.

## Results for every implemented method

Numbers are unique accepted output IOCs. `P` means partial: guest access,
pagination or the one-page audit limit prevents exhaustive coverage. A dash is
not an implemented method for that source.

| Input → output | RapidDNS | AlienVault / OTX | VirusTotal |
| --- | --- | --- | --- |
| Domain → IPv4 | 21 (P) | Loading page | 6 (P), follow-up |
| Domain → IPv6 | 32 (P) | Loading page | 4 (P) |
| IPv4 → domain | 100 (P) | Loading page | 10 (P) |
| IPv6 → domain | 98 (P) | Loading page | Loading page on both tested inputs |
| Domain → URL | — | Unconfirmed empty; loading indicator present | Loading page on both attempts |
| URL → domain | — | Loading page | 1 |
| IPv4 → country | — | Loading page | 1 for 8.8.8.8; missing country field for 1.1.1.1 |
| IPv6 → country | — | Loading page | Loading page on both tested inputs |
| URL → URL | — | — | 2 |

Successful method counts: **RapidDNS 4/4, OTX 0/8, VirusTotal 6/9**.
The first pass alone returned positive results from 8 methods. The five follow-up
calls confirmed two additional methods; original failures are retained.

## Findings that matter before the workflow

1. **OTX's reported empty URL result is not trustworthy as confirmed no data.**
   The actual receipt says `empty`, but the associated-URLs section in the saved
   HTML contains a `class="loading ..."` element and spinner alongside an empty
   table / “No Entries Found” placeholder. The parser only checks loading text
   inside table rows. This is a false-empty risk, not a successful positive test.
2. **Browser readiness is too broad.** `BrowserTransport` stops waiting when any
   `table tbody tr` appears, even if it belongs to an unrelated section. It needs
   source/operation-specific readiness and loading checks. This is a plausible
   contributor to the captured loading pages; the audit does not prove it is the
   only cause of every failure. Domain→IPv4 on VirusTotal failed first and worked
   on the next attempt, demonstrating that it is not consistently successful.
3. **Country is not always present.** VirusTotal returned HTTP 200 JSON for
   `1.1.1.1`, but `data.attributes` contained no `country` or `country_code` field.
   The current parser raises `parse_error: Missing country field`. For `8.8.8.8`
   it returned a supported country. Do not derive a location from unrelated WHOIS
   text simply to produce an output. A documented optional-field/no-data policy
   and additional captured-response tests are needed.
4. **Fixtures proved parser behavior, not live compatibility.** OTX website
   loading and current field availability are not covered by synthetic success
   responses. Retain these captures as evidence for targeted fixes and regression
   tests before declaring all implemented routes ready.
5. **Validation rejections are relationship-specific.** RapidDNS domain→IPv4
   accepted 21 unique IPs and rejected 13 rows for other hostnames. Domain→IPv6
   accepted 32 and rejected 14 rows. These are not claims that the IPs themselves
   are invalid or malicious.

The working RapidDNS routes are sufficient for a limited first workflow slice.
Before enabling every implemented method in an automatic runner, address the
false-empty and browser-readiness issues and verify the unresolved routes again.
API-key fallback routes remain untested because no keys were configured.

### Follow-up analysis: 14 October

The [method reliability repair plan](METHOD_RELIABILITY_REPAIR_PLAN.md) and
[new diagnostic captures](output/route-analysis-2026-10-14/README.md) establish
OTX website/API path mismatches and VirusTotal IPv6 encoding mismatches. Direct
replay of loaded OTX URL HTML accepted four exact-host URLs; replay of the
captured VirusTotal IPv6 DNS JSON accepted two domains. These bypassed production
acquisition and do not change this audit's 10-of-21 production baseline.
Further OTX traces encountered HTTP 429, and the captured VirusTotal IPv6 object
lacked country. Production repair and a new complete live audit are still needed.

## Raw responses, output lists and receipts

- [Initial 21-method report with per-method artifact links](output/live-methods-2026-10-13-network/REPORT.md)
- [Five-method follow-up report](output/live-methods-2026-10-13-followup/REPORT.md)
- [Initial machine-readable results](output/live-methods-2026-10-13-network/results.json)
- [Follow-up machine-readable results](output/live-methods-2026-10-13-followup/results.json)
- [Disabled-candidate results](output/live-methods-2026-10-13-network/disabled-candidates.json)
- [Offline test log](output/live-methods-2026-10-13-network/offline-tests.log)

Examples to open directly in the editor:

- [RapidDNS raw HTML](output/live-methods-2026-10-13-network/rapiddns.domain_to_ipv4/raw-01.html)
  and [its accepted IP objects](output/live-methods-2026-10-13-network/rapiddns.domain_to_ipv4/outputs.json).
- [VirusTotal raw URL JSON](output/live-methods-2026-10-13-network/virustotal.url_to_url/raw-01.json)
  and [its two accepted URLs](output/live-methods-2026-10-13-network/virustotal.url_to_url/outputs.json).
- [VirusTotal response missing country](output/live-methods-2026-10-13-network/virustotal.ipv4_to_geo_location/raw-01.json)
  and [successful alternative-input output](output/live-methods-2026-10-13-followup/virustotal.ipv4_to_geo_location/outputs.json).
- [OTX HTML with loading/empty ambiguity](output/live-methods-2026-10-13-network/alienvault.domain_to_url/raw-01.html).

Each method directory contains `outputs.json`, `receipt.json`, `summary.json`,
and retained raw bodies plus metadata. Raw files preserve the exact decoded
response retained by our transport, before parsing; they are not original
compressed network bytes. Browser JSON is the captured website response; browser
HTML is the rendered DOM. Open raw HTML as text for inspection.

The VirusTotal URL→URL method returned `https://iana.org/help/example-domains`
as an outgoing link and `https://example.com/` as a redirect target. Neither
target was visited by the lookup module.

## Reproduce

These commands contact live providers and create a new timestamped output folder:

```powershell
.\.venv\Scripts\python.exe tests/live_methods_audit.py
.\.venv\Scripts\python.exe tests/live_methods_audit.py --method virustotal.ipv4_to_geo_location --ipv4 8.8.8.8
```

Use `--source rapiddns` to limit the audit to a source or repeated `--method`
arguments to select methods. Results can change with provider data and access.
