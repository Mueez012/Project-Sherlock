# Provider fixtures

The original otx_dns.json, otx_urls.json, vt_dns.json, vt_geo.json, vt_url.json and rapiddns.html are **synthetic**, using documentation-address ranges. They exercise response schemas and adversarial unrelated rows; they do not prove current provider access.

rapiddns-captured-table.html contains the unchanged table element captured from https://rapiddns.io/subdomain/example.com?page=1 on 10 October 2026. Only the public table is retained here. The complete response and guest-limit notice were preserved locally in output/live-smoke. The captured table supports 21 exact-host IPv4 outputs and includes subdomain rows that must be rejected.

Added 14 October 2026:

- `otx_ui_dns_captured.json`: two unchanged records selected from the actual OTX website response for example.com, one exact-host A record and one www subdomain A record. The fixture's count is reduced to two. Full source: `output/repaired-otx-followup-2026-10-14/alienvault.domain_to_ipv4/raw-01.json`.
- `vt_ipv6_ui_captured.json`: unchanged decoded VirusTotal website DNS response for 2606:4700:4700::1111. Full source: `output/repaired-vt-2026-10-14/virustotal.ipv6_to_domain/raw-01.json`.

These freeze observed schemas for offline regressions. They do not make a test a live lookup, and the captured values need not remain current. No credentials/cookies are included.
