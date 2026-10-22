"""One analysis job: file -> text -> sentences -> probabilities -> report TTPs.

All ML logic lives in ttp_extraction.inference; this module only runs the
stages in order, reports progress on the job and turns failures into error codes.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from ttp_api.jobs import JobStore, now
from ttp_extraction.inference.aggregate import AggregateOptions, aggregate
from ttp_extraction.inference.document import Document, DocumentError, extract_text, from_text
from ttp_extraction.inference.segment import split_with_offsets

log = logging.getLogger("ttp_api.pipeline")


class JobFailed(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def model_info(predictor, threshold_mode: str) -> dict:
    m = predictor.manifest
    return {"name": m.get("name", "ThreatMAMBA-TTP"), "version": m.get("version", "unknown"),
            "run_id": m.get("run_id", "unknown"), "model_type": m.get("model_type", "frozen_head"),
            "encoder": m.get("encoder", "ehsanaghaei/SecureBERT"), "threshold_mode": threshold_mode,
            "label_space": {"tactics": predictor.n_tactics,
                            "techniques": len(predictor.labels) - predictor.n_tactics}}


def run_analysis(job_id: str, store: JobStore, predictor, catalog: dict, settings,
                 text: str | None = None) -> None:
    job = store.get(job_id)
    started = time.perf_counter()
    deadline = started + settings.job_timeout_s
    timings: dict[str, float] = {}

    def stage(name: str, progress: float, message: str) -> None:
        if time.perf_counter() > deadline:
            raise JobFailed("timeout", f"the analysis took longer than {settings.job_timeout_s:.0f} s")
        if store.update(job_id, status=name, stage=name, progress=progress, message=message) is None:
            raise JobFailed("cancelled", "the job was deleted")
        timings[name] = time.perf_counter()
        log.info("job %s stage %s", job_id, name)

    try:
        # a. text
        stage("extracting_text", 0.02, "Extracting text")
        if text is not None:
            doc = from_text(text)
        else:
            doc = extract_text(Path(job.temp_path).read_bytes(), job.filename or "upload.txt")
        if not doc.text.strip():
            raise JobFailed("no_text", "no readable text was found")

        # b. sentences
        stage("splitting", 0.06, "Splitting into sentences")
        sentences = split_with_offsets(doc.text, doc.page_of)
        analysed = [s for s in sentences if s.skip_reason is None]
        if not sentences:
            raise JobFailed("no_text", "no sentences were found in the text")
        if len(analysed) > settings.max_sentences:
            raise JobFailed("too_many_sentences",
                            f"{len(analysed)} sentences to analyse; the limit is {settings.max_sentences}")
        warnings = list(doc.warnings)
        skipped = {r: sum(s.skip_reason == r for s in sentences) for r in ("short", "ioc_list", "heading")}
        if skipped["ioc_list"]:
            warnings.append(f"{skipped['ioc_list']} sentence(s) skipped: mostly hashes, IPs, URLs or paths")
        if skipped["short"]:
            warnings.append(f"{skipped['short']} sentence(s) skipped: fewer than 4 words")
        if skipped["heading"]:
            warnings.append(f"{skipped['heading']} heading/title line(s) skipped")
        texts = [s.text for s in analysed]
        if texts:
            too_long = sum(n > predictor.max_length for n in predictor.token_lengths(texts))
            if too_long:
                warnings.append(f"{too_long} sentence(s) longer than {predictor.max_length} tokens were truncated")

        # c. + d. SecureBERT and the TTP head run batch by batch
        total = len(texts)
        stage("encoding", 0.1, f"Encoding sentences 0 / {total}")

        def progress(done: int, n: int) -> None:
            if time.perf_counter() > deadline:
                raise JobFailed("timeout", f"the analysis took longer than {settings.job_timeout_s:.0f} s")
            if store.update(job_id, progress=0.1 + 0.8 * done / max(n, 1),
                            message=f"Encoding sentences {done} / {n}") is None:
                raise JobFailed("cancelled", "the job was deleted")

        try:
            probs = predictor.predict(texts, batch_size=settings.batch_size, progress_cb=progress)
        except JobFailed:
            raise
        except Exception as exc:
            log.exception("job %s: model error", job_id)
            raise JobFailed("model_error", f"the model failed ({exc.__class__.__name__})")
        encode_s = time.perf_counter() - timings["encoding"]

        stage("classifying", 0.92, "Applying decision thresholds")
        options = job.options
        mode = options.get("threshold_mode") or predictor.thresholds.default_mode
        fixed = options.get("fixed_threshold")
        thresholds = predictor.thresholds.get(mode, fixed if mode == "fixed" else None, len(predictor.labels))

        # e. report level
        stage("aggregating", 0.96, "Combining sentence predictions")
        agg = aggregate(sentences, probs, predictor.labels, predictor.n_tactics, thresholds,
                        predictor.technique_to_tactics, catalog,
                        AggregateOptions(min_evidence_sentences=options.get("min_evidence_sentences", 1),
                                         strong_threshold=options.get("strong_threshold", 0.8),
                                         include_sentences=options.get("include_sentences", True),
                                         apply_hierarchy=options.get("apply_hierarchy", True)))
        end = time.perf_counter()
        processing_ms = int(1000 * (end - started))
        names = list(timings)
        stage_ms = {n: int(1000 * ((timings[names[i + 1]] if i + 1 < len(names) else end) - timings[n]))
                    for i, n in enumerate(names)}
        finished = now()
        result = {
            "id": job_id, "status": "completed", "incident_name": job.incident_name,
            "created_at": job.created_at.isoformat(), "completed_at": finished.isoformat(),
            "processing_ms": processing_ms, "timings_ms": stage_ms,
            "options": {**options, "threshold_mode": mode},
            "document": document_info(job, doc, len(sentences), len(analysed)),
            "model": model_info(predictor, mode),
            **agg,
            "warnings": warnings,
        }
        store.update(job_id, status="completed", stage="completed", progress=1.0,
                     message="Analysis complete", completed_at=finished, result=result)
        log.info("job %s completed: %d sentences (%d analysed), %d techniques, %.0f ms total, "
                 "%.1f ms/sentence", job_id, len(sentences), total, agg["summary"]["n_techniques"],
                 processing_ms, 1000 * encode_s / max(total, 1))
    except (JobFailed, DocumentError) as exc:
        code = exc.code
        message = exc.message if isinstance(exc, JobFailed) else str(exc)
        if code == "cancelled":
            log.info("job %s cancelled", job_id)
            return
        store.update(job_id, status="failed", stage="failed", completed_at=now(),
                     message=message, error={"code": code, "message": message})
        log.info("job %s failed: %s (%s)", job_id, code, message)


def document_info(job, doc: Document, n_sentences: int, n_analysed: int) -> dict:
    return {"filename": job.filename, "media_type": doc.media_type, "size_bytes": job.size_bytes,
            "sha256": job.sha256, "pages": doc.pages, "n_characters": len(doc.text),
            "n_sentences": n_sentences, "n_sentences_analyzed": n_analysed, "language": "en",
            "text": doc.text, "declared_ttps": doc.declared_ttps}

