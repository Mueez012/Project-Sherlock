# Real CTI report → extraction → lookup → validation

Date: 14 October 2026. This test used the actual extractor and live provider report pages, with no API keys or synthetic responses.

## Report and extracted seed

- Dataset: `ThreatMamba-Datasets/ThreatMAMBA-main/cleaned_CTI2Attacker(main).csv`.
- Data row: **670**, dataset index **1635**, dataset group label **MageCart**.
- Subject: malicious checkout scripts targeting MyPillow and Amerisleep.
- Extraction: **13 IOC objects**, 55 retained sentences, one excluded reference section.
- Selected IOC: **`mypiltow.com`**, type `domain`, selected from the extractor's returned list.

Its retained context includes:

> The first attack detected by RiskIQ took place in October 2018 when attackers registered a domain mypiltow.com and then injected scripts from the domain into Mypillow.com as shown below.

The selected object retains two original context passages and its dataset row/index source. That exact object was passed to each lookup; every receipt's input was checked against the extraction output. No seed object was manually substituted.

## All eight implemented domain-input methods

| Method | Accepted | Outcome |
| --- | ---: | --- |
| RapidDNS domain → IPv4 | 4 | Partial provider coverage |
| RapidDNS domain → IPv6 | 0 | Partial; absence of IPv6 is not established |
| OTX domain → IPv4 | 24 | Completed response with validated outputs |
| OTX domain → IPv6 | 0 | Completed DNS response with no matching IPv6 records |
| OTX domain → URL | 0 | Completed empty URL array, `has_next: false` |
| VirusTotal domain → IPv4 | 10 | Partial; browser pagination remains unverified |
| VirusTotal domain → IPv6 | 0 | Partial; no IPv6 output in the retrieved page |
| VirusTotal domain → URL | 0 | Requested response not observed within two bounded attempts |

The positive methods returned **38 method-specific validated connections to 29 distinct IPv4 addresses**. Some IPs were returned by multiple sources. RapidDNS rejected three candidate rows and OTX rejected one; the receipts retain the exact reasons.

This verifies extraction through lookup and validation using a real report IOC. It does not run Algorithm 1, insert a graph or evaluate expansion success. Provider DNS observations can be historical or newer than the report; they do not establish that every returned IP participated in the original attack.

## Raw outputs and provenance

- [Report text used](output/cti-report-lookup-2026-10-14/report.txt).
- [Full extraction, all 13 IOCs and contexts](output/cti-report-lookup-2026-10-14/extraction.json).
- [Selected IOC](output/cti-report-lookup-2026-10-14/selected-ioc.json).
- [Dataset identity and report digest](output/cti-report-lookup-2026-10-14/manifest.json).
- [All eight results, raw responses and receipts](output/cti-report-lookup-2026-10-14/REPORT.md).
- [The 38 validated method/input/output combinations](output/cti-report-lookup-2026-10-14/validated-connections.json).
- Accepted IP objects: [RapidDNS](output/cti-report-lookup-2026-10-14/rapiddns.domain_to_ipv4/outputs.json), [OTX](output/cti-report-lookup-2026-10-14/alienvault.domain_to_ipv4/outputs.json), [VirusTotal](output/cti-report-lookup-2026-10-14/virustotal.domain_to_ipv4/outputs.json).

Evidence digests were checked against retained raw bodies. Requests used fresh retrieval, a two-page ceiling, normal source pacing, anonymous access and provider sites only.

## Reproduce

From `ioc-hunter`, choose a new output folder:

```powershell
.\.venv\Scripts\python.exe tests/live_report_lookup.py --row 670 --type domain --value mypiltow.com --max-pages 2 --output output/cti-report-lookup-rerun
```

The script refuses lookup if the IOC is not returned by `extract_report`. It saves extraction before contacting providers. Use `--source rapiddns` (or another source) to restrict the run. A source batch stops on rate limiting. This demonstration explicitly supplies no API keys so it tests the paper's primary website routes.
