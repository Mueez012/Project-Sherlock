# Provider fixtures

The original otx_dns.json, otx_urls.json, vt_dns.json, vt_geo.json, vt_url.json and rapiddns.html are **synthetic**, using documentation-address ranges. They exercise response schemas and adversarial unrelated rows; they do not prove current provider access.

rapiddns-captured-table.html contains the unchanged table element captured from https://rapiddns.io/subdomain/example.com?page=1 on 10 October 2026. Only the public table is retained here. The complete response and guest-limit notice were preserved locally in output/live-smoke. The captured table supports 21 exact-host IPv4 outputs and includes subdomain rows that must be rejected.

Added 14 October 2026:

- `otx_ui_dns_captured.json`: two unchanged records selected from the actual OTX website response for example.com, one exact-host A record and one www subdomain A record. The fixture's count is reduced to two. Full source: `output/repaired-otx-followup-2026-10-14/alienvault.domain_to_ipv4/raw-01.json`.
- `vt_ipv6_ui_captured.json`: unchanged decoded VirusTotal website DNS response for 2606:4700:4700::1111. Full source: `output/repaired-vt-2026-10-14/virustotal.ipv6_to_domain/raw-01.json`.

These freeze observed schemas for offline regressions. They do not make a test a live lookup, and the captured values need not remain current. No credentials/cookies are included.

Added 9 November 2026:

- `vt_url_filename_sysinternals_captured.json`: a curated subset of the actual
  VirusTotal website response for
  `https://download.sysinternals.com/files/ProcessExplorer.zip`, retaining its
  object identity, URL and stored HTTP response headers. No Content-Disposition
  header was present; it is a completed-empty regression, not a positive filename
  control. Full decoded source:
  `output/live-methods-20261109T083000Z/virustotal.url_to_filename/raw-01.json`;
  snapshot `4b88c1f32113204a5b66323f31c77d9e419d3df1fdce012cbe19cc9fe2a46dda`.
  The positive filename/header cases in the new tests are explicitly synthetic.

- `vt_file_behaviours_ui_captured.json`: a curated subset of the unauthenticated
  VirusTotal file-report browser response for SHA-256
  `f55fe457929044e4c4cdc62b4ad0a4955bd2faac2b642318649beede66086eb4`.
  It retains all nine sandbox report identities and the original
  `command_executions`, `calls_highlighted` and `invokes` fields, along with
  the source links/count. There are seventeen command/API entries. Full decoded
  source: `output/hash-browser-probe-20261109/raw-09.json`; navigation metadata:
  `output/hash-browser-probe-20261109/metadata.json`. A separate MD5 navigation
  reached the same canonical SHA-256 page and behavior response; its artifacts
  are in `output/hash-browser-probe-20261109/c438b19e627b1c1e9cb8970f2fe5f929/`.
  Fixture replay is an offline regression, not a new live request.

Next OTX batch, 9 November 2026:

- `otx_whois_python_captured.json`: all 21 WHOIS rows and the original count from
  the public OTX `python.org` report. The unrelated-domain list is omitted.
  Two `emails` rows contain concrete privacy relay contact addresses; this does
  not establish ownership or current validity. Full source:
  `output/next-methods-probe/python.org/raw-05.json`; navigation metadata is
  in the same directory.
- `otx_http_github_captured.json`: unchanged stored HTTP scan response for the
  OTX URL report `http://github.com/`, containing one explicit HTTP 301 header
  with `Location: https://github.com/`. Full source:
  `output/next-methods-probe/url-793a92a45980/raw-02.json`.

Both are source-response fixtures for offline regression. Neither test visits
the input website, and replay is not represented as a fresh live lookup.

Added 10 November 2026:

- `vt_file_network_ui_captured.json`: unchanged selected network rows from the
  public VT file-behavior response captured on 9 November at
  `output/hash-browser-probe-20261109/raw-09.json`. It retains the first three
  `ip_traffic` and `dns_lookups` rows per sandbox where those fields exist,
  with original report identity/type and analysis date. Five sandbox records
  remain; the fixture count is adjusted to that selection. IPv4 and IPv6 values
  are preserved, including repeated resolved addresses. This is a minimized
  field selection, not a complete original response. No samples are downloaded.
  The corresponding IP-method regression uses **synthetic communicating-file
  discovery** followed by these captured report fields; it does not establish
  current discovery access or represent a fresh live lookup.
