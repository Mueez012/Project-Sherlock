"""POST /api/v1/predict, the hub's call, with the fake predictor (keyword rules, real 203-label vocabulary)."""
import pytest

from tests.api.test_analyses import make_client


@pytest.fixture
def client(tmp_path):
    c, _, _ = make_client(tmp_path)
    with c:
        yield c


def test_predict_keeps_indices_and_returns_label_shape(client):
    r = client.post("/api/v1/predict", json={"sentences": [
        {"index": 5, "text": "Mimikatz dumped credentials from LSASS."},
        {"index": 7, "text": "Nothing here."},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert [s["index"] for s in body["sentences"]] == [5, 7]
    for s in body["sentences"]:
        for label in s["labels"]:
            assert set(label) == {"id", "p", "passed"}
            assert 0.0 <= label["p"] <= 1.0


def test_predict_returns_passed_tactics_and_techniques(client):
    body = client.post("/api/v1/predict", json={"sentences": [
        {"index": 0, "text": "The actor sent spearphishing emails."}]}).json()
    passed = {label["id"] for label in body["sentences"][0]["labels"] if label["passed"]}
    assert {"T1566", "TA0001"} <= passed              # techniques and tactics both come back
    assert all(len(i.split(".")) == 1 for i in passed)  # never a sub-technique


def test_predict_marks_labels_below_threshold_as_not_passed(client):
    body = client.post("/api/v1/predict", json={"sentences": [
        {"index": 0, "text": "Files were compressed."}]}).json()
    labels = {label["id"]: label for label in body["sentences"][0]["labels"]}
    assert labels["T1560"]["passed"] is False        # 0.42 is under the 0.5 threshold, but above the floor
    assert "T1003" not in labels                      # 0.01 is under the floor and left out


def test_predict_with_no_sentences(client):
    assert client.post("/api/v1/predict", json={"sentences": []}).json()["sentences"] == []


def test_predict_rejects_negative_index(client):
    r = client.post("/api/v1/predict", json={"sentences": [{"index": -1, "text": "x"}]})
    assert r.status_code == 400                       # this API reports validation errors as problem+json 400
    assert r.json()["code"] == "bad_request"
