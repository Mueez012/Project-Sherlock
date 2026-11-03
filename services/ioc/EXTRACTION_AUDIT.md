# IOC extraction audit — 10 October 2026

Audited 12 randomly selected reports from all 1,207 rows of
`cleaned_CTI2Attacker(main).csv`, using Python `random.Random(20261010).sample`.
Added six targeted reports to inspect reference formats and the previously
discussed Google Play contexts. Row numbers below are 1-based data rows, not the
dataset's `index` column. No dataset content was changed.

## Findings and fixes

- **Reference-section pollution:** references, sources, bibliography, further or
  additional reading, external links, and related-content sections are excluded
  before extraction. The dataset's repeated `References <citation>` format is
  recognized as well. Filtering is based on explicit headings, not a publisher
  domain blacklist. A domain appearing in the report body remains eligible even
  if it also appears in references.
- **Evidence after references:** extraction resumes at explicit IOC/technical
  appendix headings or a new Markdown heading. Tests cover both cases.
- **Software version mistaken for an IPv4:** random row 805 contained Flash
  Player ActiveX `28.0.0.137`. Local version/build wording now suppresses such
  matches. Explicit IPs, ambiguous numbers, and real addresses in the same
  sentence are retained. If a value appears as both version and address, it is
  retained.
- **Overlong contexts:** random row 478 attached a 4,644-character domain list
  to nearly every entry. Standalone IOC rows are now split separately; its
  longest extracted context is 191 characters, with all 192 indicators retained.
  Ordinary soft-wrapped prose is still processed as a sentence. URLs at line
  endings no longer absorb the following paragraph.
- **Moved-file integration:** fixed the default dataset path and test import to
  match the extractor's current location under `ioc_hunter/`.

The four IOC fields are unchanged: `value`, `type`, `context`, `source`.
The source remains `cti report`. Interactive pauses remain in place. Step 1
shows the original report; step 2 lists excluded sections and original line
numbers. `--include-references` is available for comparison or manual override.

## Before/after results

| Dataset row | Dataset index | Selection | Before | After |
| --- | --- | --- | ---: | ---: |
| 2 | 9 | Targeted bibliography | 10 | 0 |
| 3 | 18 | Targeted repeated URL context | 6 | 6 |
| 4 | 19 | Targeted references | 27 | 4 |
| 10 | 77 | Targeted references | 18 | 0 |
| 13 | 110 | Targeted sources | 2 | 0 |
| 25 | 424 | Targeted references plus body IOCs | 73 | 68 |
| 87 | 570 | Random | 2 | 2 |
| 341 | 1050 | Random | 0 | 0 |
| 356 | 1079 | Random | 0 | 0 |
| 478 | 1297 | Random | 192 | 192 |
| 520 | 1380 | Random | 0 | 0 |
| 527 | 1397 | Random | 0 | 0 |
| 670 | 1635 | Random | 13 | 13 |
| 675 | 1644 | Random | 1 | 1 |
| 718 | 1722 | Random | 0 | 0 |
| 731 | 1750 | Random | 0 | 0 |
| 805 | 2543 | Random | 1 | 0 |
| 823 | 2628 | Random | 0 | 0 |

Counts are unique `(type, value)` pairs per report, not globally deduplicated
indicators or confirmed malicious infrastructure. Totals: 345 before, 286 after.
The 59 removed entries comprise 58 reference-only indicators and one software
version. No new indicator identities were introduced in this sample.

Inspected all extracted type/value lists and the before/after changes, reference
tails, and representative contexts. Automated invariants verify unique identities,
nonempty context, `cti report` sources, and that every retained context is an exact
substring of the original report. This is a sampled audit, not a labelled
precision/recall evaluation.

## Verification and reproduction

All 23 regression tests pass, including original extraction/interaction tests,
CSV/XLSX input, headings, reference overrides, post-reference appendices, version
disambiguation, and list/paragraph boundaries. A CLI smoke check on row 4 verified
the default path, visible reference exclusion, and stopping before IOC extraction.

From the `ioc-hunter` directory, using its Python environment:

```powershell
.\.venv\Scripts\python.exe -W ignore::DeprecationWarning -m unittest discover -s tests -p test_interactive_extraction.py -v
.\.venv\Scripts\python.exe tests/audit_extraction_sample.py --label after --extra-rows 2 3 4 10 13 25
.\.venv\Scripts\python.exe -m ioc_hunter.interactive_extraction --row 4
```

Detailed local artifacts: `output/extraction-audit-before.json` and
`output/extraction-audit-after.json`. They contain extracted objects/contexts,
sample row IDs, timings, and excluded sections. The output folder is git-ignored.

## Limits requiring contextual judgement

- Unlabelled inline citation URLs are not automatically removed. For example,
  the exploit-db link in the body of row 4 remains an extracted observable.
- Known reference headings are handled heuristically. An unrecognized plain-text
  heading after a bibliography may need an additional resume rule; the original
  report and exclusion line ranges remain visible for review.
- Extraction does not classify every observable as malicious. Victim domains in
  row 478 and email-provider domains remain in the body extraction. Removing
  those requires role/context classification, not blanket domain exclusions.
- URL punctuation and malformed/flattened report formatting can still require
  manual review. No claim is made that the sample covers every report format.
