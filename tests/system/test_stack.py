"""Run against the started container: TM_BASE_URL=http://localhost:8000 pytest -m system tests/system"""

import os

import httpx
import pytest

pytestmark = pytest.mark.system
BASE = os.environ.get("TM_BASE_URL", "http://localhost:8000")


def test_health():
    r = httpx.get(f"{BASE}/health", timeout=10)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_analyze_end_to_end():
    r = httpx.post(f"{BASE}/api/analyze", json={"text": "Spear-phishing email. Mimikatz dumped LSASS."}, timeout=30)
    assert r.status_code == 200
    assert {"T1566", "T1003"} <= {t["technique_id"] for t in r.json()["ttps"]}


def test_interface_page():
    r = httpx.get(f"{BASE}/", timeout=10)
    assert r.status_code == 200
    assert "<title>ThreatMAMBA</title>" in r.text
