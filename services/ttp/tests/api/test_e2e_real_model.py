"""One synthetic report through the REAL model bundle (CPU). Marked slow (~40 s).

  python -m pytest tests/api/test_e2e_real_model.py -m slow -s
"""
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ttp_api.config import Settings
from ttp_api.main import create_app

REPORT = Path(__file__).resolve().parents[1] / "data" / "synthetic_report.txt"
BUNDLE = Path(__file__).resolve().parents[4] / "models" / "ttp-v3" / "manifest.json"   # final ensemble, repo-root models/


@pytest.mark.slow
@pytest.mark.skipif(not BUNDLE.exists(), reason="no model bundle")
def test_synthetic_report_real_model():
    from ttp_extraction.inference.predictor import TTPPredictor

    predictor = TTPPredictor.load(BUNDLE.parent, device="cpu", num_threads=min(8, os.cpu_count() or 1))
    with TestClient(create_app(Settings(load_model=False, job_store="memory"), predictor=predictor)) as client:
        job = client.post("/api/v1/analyses", files={"file": ("synthetic.txt", REPORT.read_bytes())},
                          data={"incident_name": "Synthetic"}).json()
        for _ in range(600):
            status = client.get(f"/api/v1/analyses/{job['id']}").json()
            if status["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)
        assert status["status"] == "completed", status
        result = client.get(f"/api/v1/analyses/{job['id']}/result").json()
    found = {t["id"] for t in result["techniques"]}
    # Techniques the synthetic text describes in plain words; the model should find most of them.
    expected = {"T1566", "T1059", "T1053", "T1003", "T1021", "T1560", "T1071", "T1486"}
    assert len(found & expected) >= 6, found
    n = result["document"]["n_sentences_analyzed"]
    print(f"\nreal model: {n} sentences in {result['processing_ms']} ms "
          f"({result['processing_ms'] / n:.1f} ms/sentence incl. overhead); found {sorted(found)}")
