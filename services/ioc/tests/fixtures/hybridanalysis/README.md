# Hybrid Analysis fixtures

`unified_report_captured_minimized.json` contains **actual field values** from
the public sample page captured on **9 November 2026**:

https://hybrid-analysis.com/sample/2e7aa640b2da6d9350afba1b8ad0b65bc85ac335dde42f08cd540da8580e2a78

Original local capture:
`output/research-hybrid-analysis/20261109T183353Z/sample/page.html`.

The fixture retains the report identity, three hashes, filename, first recorded
process, first two created-registry rows, and absent HTTP data. Other activity,
detections and page furniture were omitted. This is a minimized field selection,
not a complete original response. No authentication headers, cookies, CSRF data,
JavaScript bundles or sample binaries are included.

Tests wrap these captured fields in a **reconstructed Next-flight envelope** and
split the JSON text into fragments to exercise decoding. Other report/search
builders in `test_hybridanalysis.py` are explicitly **synthetic**. In particular,
synthetic API-call, HTTP URL, search-result and access-error cases are regression
fixtures; they do not establish positive live access or observed source fields.

Tests were originally prepared before execution. The user authorized the
regression and uncached live checks on 10 November 2026; their actual results
are reported separately from fixture provenance.

Added after authorization to test on 10 November 2026:

`unified_report_flight_captured.html` preserves the **unchanged Next flight
script containing initialData** from the same full public capture. Only a
minimal HTML/script envelope is added. Its Next JSON text is not regenerated,
truncated or re-escaped. Other page scripts, headers, cookies and navigation are
excluded. The retained script has no CSRF, authorization, access/session-token
or cookie fields. The regression checks the actual transport encoding, all 46
source registry rows, the two command/name observations and absent explicit URLs.
