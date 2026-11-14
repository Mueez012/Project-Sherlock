"""Paper score and selector protocol contracts; no model requests."""
import json
import math
from unittest.mock import patch

import pytest

from ioc_hunter.workflow.algorithm.models import AlgorithmConfig
from ioc_hunter.workflow.algorithm.scoring import rank_methods
from ioc_hunter.workflow.algorithm.selector import APISelector, selection_request, validate_selection


def test_cold_start_score_and_type_filtered_invocation_total():
    methods = [{"id": "b", "input_type": "domain"}, {"id": "a", "input_type": "domain"},
               {"id": "ip", "input_type": "ipv4"}]
    history = {m["id"]: {"tried": 0, "coverage": 0} for m in methods}
    assert [m["id"] for m in rank_methods(methods, history, "domain", 1)] == ["a", "b"]
    history.update(a={"tried": 4, "coverage": 2}, b={"tried": 2, "coverage": 0},
                   ip={"tried": 10000, "coverage": 10000})
    ranked = {m["id"]: m for m in rank_methods(methods, history, "domain", .5)}
    assert ranked["a"]["score"] == pytest.approx(2 / (4 + 1e-6) + .5 * math.sqrt(math.log(6) / (4 + 1e-6)))
    assert not ranked["a"]["cold_start"]


def test_top50_and_configuration_validation():
    methods = [{"id": f"m{i:03}", "input_type": "url"} for i in range(80)]
    histories = {m["id"]: {"tried": 0, "coverage": 0} for m in methods}
    assert len(rank_methods(methods, histories, "url", 1)) == 50
    for value in (float("nan"), float("inf"), -1, True):
        with pytest.raises(ValueError):
            AlgorithmConfig(alpha=value)
    with pytest.raises(ValueError):
        AlgorithmConfig(alpha=1, rounds_per_ioc=6)


def test_selection_membership_empty_duplicates_and_context_scope():
    shortlist = [{"id": "m", "input_type": "domain"}]
    assert validate_selection({"methods": []}, shortlist) == []
    assert len(validate_selection({"methods": [{"method_id": "m"}, {"method_id": "m"}]}, shortlist)) == 1
    for response in ({"methods": [{"method_id": "invented"}]}, [], {"methods": "m"}):
        with pytest.raises(ValueError):
            validate_selection(response, shortlist)
    request = selection_request({"type": "domain", "value": "example.com", "context": ["x" * 20],
                                 "group": "ground-truth-actor"}, shortlist, context_chars=5)
    assert request["ioc"]["context"] == "xxxxx"
    assert "ground-truth-actor" not in json.dumps(request)


def test_api_selector_uses_environment_key_without_serializing_it(monkeypatch):
    monkeypatch.setenv("TEST_SELECTOR_SECRET", "private-token")
    selector = APISelector({"endpoint": "https://model.example/v1/chat/completions", "model": "chosen-model",
                            "api_key_env": "TEST_SELECTOR_SECRET"})
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, count):
            return json.dumps({"choices": [{"message": {"content": '{"methods": []}'}}],
                               "usage": {"total_tokens": 15}}).encode()
    with patch("ioc_hunter.workflow.algorithm.selector.urlopen", return_value=Response()) as call:
        result = selector.select(selection_request({"type": "domain", "value": "example.com"}, []))
    assert result["selection"] == {"methods": []}
    request = call.call_args.args[0]
    assert request.get_header("Authorization") == "Bearer private-token"
    assert "private-token" not in request.data.decode()
    assert "private-token" not in json.dumps(result)
