"""The HTTP door the hub calls. Offline extraction and lookup validation."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("ioc_finder")

from fastapi.testclient import TestClient  # noqa: E402

from ioc_hunter import http_api  # noqa: E402
from ioc_hunter.http_api import app  # noqa: E402

client = TestClient(app)
REPORT = (
    "The loader beaconed to 185.220.101[.]4 every hour.\n"
    "It ran on Adobe Flash Player 11.2.202.228 and later versions.\n"
    "References\n"
    "https://www.vendor-blog.com/analysis/report.html\n"
)


@pytest.fixture(autouse=True)
def isolated_lookup_store(tmp_path, monkeypatch):
    """Use a temporary evidence store instead of the container's /data path."""
    monkeypatch.setenv("IOC_HUNTER_STORE", str(tmp_path))
    monkeypatch.setattr(http_api, "_client", None)


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_extract_returns_extract_report_unchanged():
    body = client.post("/v1/extract", json={"text": REPORT}).json()
    assert set(body) == {
        "source",
        "original_text",
        "retained_text",
        "excluded_sections",
        "sentences",
        "matches",
        "iocs",
    }
    assert {(i["type"], i["value"]) for i in body["iocs"]} == {
        ("ipv4", "185.220.101.4")
    }
    assert body["excluded_sections"][0]["heading"] == "References"


def test_extract_matches_the_hubs_sentences_one_list_each():
    sentences = REPORT.strip().split("\n")
    body = client.post(
        "/v1/extract", json={"text": REPORT, "sentences": sentences}
    ).json()
    assert len(body["sentence_matches"]) == len(sentences)
    assert body["sentence_matches"][0] == [["ipv4", "185.220.101.4"]]
    assert body["sentence_matches"][1] == []  # A software version, not an IP.


def test_bad_input_is_422(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("Invalid lookup input must not make a provider request")

    monkeypatch.setattr(http_api.LookupClient, "_run", unexpected_request)
    assert client.post("/v1/extract", json={"text": 5}).status_code == 422
    wrong_type = {
        "value": "evil.com",
        "type": "ipv4",
        "method": "rapiddns.domain_to_ipv4",
    }
    assert client.post("/v1/lookup", json=wrong_type).status_code == 422


def test_methods_lists_the_catalogue():
    ids = {
        m["id"]
        for m in client.get(
            "/v1/methods", params={"implemented_only": True}
        ).json()
    }
    assert "rapiddns.domain_to_ipv4" in ids
