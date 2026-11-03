r"""Interactive CTI -> sentences -> IOC matches -> IOC dataclass objects.

Run from any directory with this project's Python environment:
    .venv\Scripts\python.exe -m ioc_hunter.interactive_extraction

Uses spaCy (text processing), not Scapy (packet processing). No language-model
download, LLM, external intelligence calls, or existing hunter code is needed.
The context contains only original sentences that produced this IOC. URL
punctuation follows IOCFinder's output; review the displayed matches because
a terminal period can be ambiguous between prose and a legitimate URL path.
"""

from __future__ import annotations
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from .models import IOC
from .config import DATASET_DIRECTORY, DEFAULT_DATASET
from .extraction.datasets import load_reports
# Re-export original helpers for existing callers and review scripts.
from .extraction.pipeline import (
    IOC_TYPES, REFERENCE_TITLES, TECHNICAL_TITLES, create_sentencizer,
    heading_text, filter_report_sections, is_indicator_list_line, split_sentences,
    is_software_version, canonical_value, find_sentence_iocs, build_iocs,
    extract_report, ExtractionResult,
)

def pause(next_step: str) -> bool:
    while True:
        answer = input(f"\n{next_step}? [Enter/y = continue, q/n = stop]: ").strip().lower()
        if answer in {"", "y", "yes"}:
            return True
        if answer in {"q", "quit", "n", "no"}:
            return False
        print("Please press Enter to continue, or type q to stop.")

def show_stage(title: str):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")

def review_report(row: dict, row_number: int, dataset: Path, nlp, *, include_references: bool = False, extended_types: bool = False) -> bool:
    """False means the user stopped; no later processing happens in that case."""
    report = row.get("cti_content")
    if not isinstance(report, str) or not report.strip():
        print(f"Report row {row_number} has no non-empty text in cti_content.")
        return True
    dataset_index = row.get("index", "unknown")
    source = "cti report"

    show_stage("STEP 1/4 - ORIGINAL CTI REPORT")
    print(f"Dataset row: {row_number} | index: {dataset_index}")
    print(f"Group: {row.get('group_name', '')} | group_id: {row.get('group_id', '')}")
    print(f"Source: {source}\n\n{report}")
    if not pause("Split this report into sentences"):
        return False

    body, excluded = (report, []) if include_references else filter_report_sections(report)
    sentences = split_sentences(body, nlp)
    show_stage(f"STEP 2/4 - SENTENCE SPLITS ({len(sentences)})")
    for section in excluded:
        print(f"Excluded reference/navigation section: {section['heading']} "
              f"(original lines {section['start_line']}-{section['end_line']})")
    if not sentences:
        print("No report-body text remains after filtering.")
    for number, sentence in enumerate(sentences, 1):
        print(f"\n[{number}] {sentence}")
    if not pause("Run IOCFinder on these sentences"):
        return False

    matches = find_sentence_iocs(sentences, extended=extended_types)
    hit_count = sum(bool(match) for match in matches)
    show_stage(f"STEP 3/4 - IOC-CONTAINING SENTENCES ({hit_count}/{len(sentences)})")
    # Text markers remain readable even when ANSI colors are unavailable.
    for number, (sentence, sentence_matches) in enumerate(zip(sentences, matches), 1):
        marker = ">>> IOC FOUND" if sentence_matches else "--- no IOC"
        print(f"\n[{number}] {marker}: {sentence}")
        for kind, value in sentence_matches:
            print(f"    {kind}: {value}")
    if not pause("Create and display the IOC dataclass objects"):
        return False

    objects = build_iocs(sentences, matches, source)
    show_stage(f"STEP 4/4 - IOC OBJECTS ({len(objects)} unique indicators)")
    print(json.dumps([asdict(ioc) for ioc in objects], indent=2, ensure_ascii=False))
    return True

def main() -> int:
    # Windows terminals can otherwise fail when printing Unicode report content.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET, help="CSV or XLSX path")
    parser.add_argument("--row", type=int, help="1-based data-row number, excluding the header (not the index column)")
    parser.add_argument("--include-references", action="store_true", help="Include reference/navigation sections for comparison")
    parser.add_argument("--extended-types", action="store_true", help="Also extract email addresses and CVEs")
    args = parser.parse_args()
    try:
        reports = load_reports(args.dataset)
        if not reports:
            raise ValueError("The dataset contains no report rows.")
        print(f"Dataset: {args.dataset.resolve()}\nReports: {len(reports)}")
        row_number = args.row
        if row_number is None:
            while True:
                selection = input(f"Choose report row [1-{len(reports)}, Enter = 1, q = quit]: ").strip()
                if selection.lower() == "q":
                    return 0
                try:
                    row_number = int(selection or "1")
                    if 1 <= row_number <= len(reports):
                        break
                except ValueError:
                    pass
                print(f"Enter a whole number between 1 and {len(reports)}.")
        if not 1 <= row_number <= len(reports):
            raise ValueError(f"--row must be between 1 and {len(reports)}.")
        nlp = create_sentencizer()
        while row_number <= len(reports):
            if not review_report(reports[row_number - 1], row_number, args.dataset, nlp,
                                 include_references=args.include_references, extended_types=args.extended_types):
                print("Stopped. No later steps were run.")
                return 0
            if row_number == len(reports) or not pause(f"Display the next report (row {row_number + 1})"):
                return 0
            row_number += 1
    except (EOFError, KeyboardInterrupt):
        print("\nStopped.")
        return 0
    except ImportError as exc:
        print(f"Missing dependency: {exc.name}. Install extraction-requirements.txt with this Python interpreter.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
