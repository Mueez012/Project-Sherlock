# Ordinary OTX pulse fixtures

These minimized fixtures retain actual source fields captured on 10 November
2026 through OTX's normal public browser pages. No API keys, cookies, headers,
account details or source-page scripts are included.

- `search_8080_captured_minimized.json`: first two pulse references and their
  original indicator counts from
  `output/research-otx-pulses/20261110T044652Z/raw-01.json`.
  Response: `/otxapi/pulses/?limit=20&page=1&sort=-modified&q=8080`.
- `indicators_captured_minimized.json`: first two domain indicator rows from
  `output/research-otx-pulses/20261110T044652Z/raw-05.json` for pulse
  `69c08867316c564ade394c69`. Response:
  `/otxapi/pulses/69c08867316c564ade394c69/indicators/?sort=-created&limit=10&page=1`.

The original count/next fields are retained, so these are intentionally partial
subsets. Tests do not present them as complete source responses. The source
capture establishes browser paths and field shapes, not positive email/country
discovery or positive port/protocol extraction. All five-method end-to-end
positives in `test_otx_pulses.py` are explicitly synthetic offline replay cases.
