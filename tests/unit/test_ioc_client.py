"""The IOC client against an answer recorded from the real IOC-hunter door (tests/fixtures/ioc_extract_response.json).

The report in that fixture has a defanged IP mentioned twice, a software version that looks like an IP, an
indicator-list section and a References section; IOC-hunter's own splitter merges the title with the next line.
"""

import json
from pathlib import Path

import httpx
import pytest

from threatmamba.clients import IOCServiceExtractor, ServiceError

FIXTURE = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "ioc_extract_response.json").read_text(encoding="utf-8")
)
TEXT, SENTENCES = FIXTURE["request"]["text"], FIXTURE["request"]["sentences"]
ANSWER = FIXTURE["response"]


def _client(handler):
    return IOCServiceExtractor("http://ioc:8002", transport=httpx.MockTransport(handler))


def _extract(answer=ANSWER, text=TEXT, sentences=SENTENCES):
    return _client(lambda request: httpx.Response(200, json=answer)).extract(sentences, text=text)


def test_every_indicator_gets_every_hub_sentence_it_appears_in():
    found = {(i.type, i.value): i.sentence_indices for i in _extract()}
    assert found == {
        ("domain", "evil-mail.com"): [1, 5],
        ("domain", "update-check.net"): [2],
        ("ipv4", "185.220.101.4"): [2, 7],
        ("url", "http://update-check.net/a.bin."): [2],
        ("md5", "d41d8cd98f00b204e9800998ecf8427e"): [6],
    }


def test_ioc_hunters_filters_stay_in_force():
    values = {i.value for i in _extract()}
    assert "11.2.202.228" not in values  # software version, suppressed by IOC-hunter
    assert "www.vendor-blog.com" not in values  # only in the References section IOC-hunter excluded


def test_ioc_hunters_values_order_context_and_source_are_unchanged():
    iocs = _extract()
    assert [(i.type, i.value) for i in iocs] == [(n["type"], n["value"]) for n in ANSWER["iocs"]]
    assert [i.context for i in iocs] == [n["context"] for n in ANSWER["iocs"]]
    assert {i.source for i in iocs} == {"cti report"}


def test_a_hub_sentence_inside_an_excluded_section_is_not_counted():
    answer = json.loads(json.dumps(ANSWER))
    answer["sentence_matches"][9].append(["ipv4", "185.220.101.4"])  # pretend the bibliography repeats the IP
    found = {i.value: i.sentence_indices for i in _extract(answer)}
    assert found["185.220.101.4"] == [2, 7]


def test_sends_the_original_text_and_the_hub_sentences():
    seen = {}

    def handler(request):
        seen["path"], seen["body"] = request.url.path, json.loads(request.content)
        return httpx.Response(200, json=ANSWER)

    _client(handler).extract(SENTENCES, text=TEXT)
    assert seen == {"path": "/v1/extract", "body": {"text": TEXT, "sentences": SENTENCES}}


def test_pre_split_input_is_sent_one_sentence_per_line():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"iocs": [], "sentence_matches": [[], []]})

    assert _client(handler).extract(["A.", "B."]) == []
    assert seen["body"] == {"text": "A.\nB.", "sentences": ["A.", "B."]}


def test_an_indicator_found_in_no_hub_sentence_is_kept_with_no_index():
    answer = {
        "iocs": [{"value": "evil.com", "type": "domain", "context": ["x"], "source": "s"}],
        "sentence_matches": [[]],
    }
    [ioc] = _extract(answer, text="x", sentences=["x"])
    assert (ioc.value, ioc.sentence_indices) == ("evil.com", [])


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={"detail": "boom"}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"iocs": []}),
        httpx.Response(200, json={"iocs": [], "sentence_matches": [[]]}),
        httpx.Response(200, json={"iocs": [{"value": "x", "type": "planet"}], "sentence_matches": [[]] * 10}),
    ],
    ids=["http-500", "not-json", "no-sentence-matches", "wrong-number-of-sentences", "unknown-type"],
)
def test_any_bad_answer_is_a_service_error(response):
    with pytest.raises(ServiceError) as e:
        _client(lambda request: response).extract(SENTENCES, text=TEXT)
    assert e.value.service == "ioc"


def test_unreachable_service_is_a_service_error():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(ServiceError):
        _client(handler).extract(["x"], text="x")


def test_health_reports_ok_or_down():
    assert _client(lambda r: httpx.Response(200, json={"status": "ok"})).health() == "ok"
    assert _client(lambda r: httpx.Response(503)).health() == "down"
