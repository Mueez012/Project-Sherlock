import pytest
from pydantic import ValidationError

from threatmamba.contracts import CSKG, D2Report, TTPHit

RECORD = {
    "report_id": 2,
    "group": "Waterbug",
    "label": 1,
    "cut_by_excel": False,
    "text": "I was doing a penetration test. One tool I liked is Nishang.",
    "sentences": [
        "I was recently doing an external penetration test.",
        "One among them that I really liked is Nishang.",
    ],
}


def test_d2_record_parses():
    r = D2Report.model_validate(RECORD)
    assert (r.group, r.label, len(r.sentences)) == ("Waterbug", 1, 2)


@pytest.mark.parametrize("field,bad", [("label", 25), ("report_id", 0), ("text", ""), ("sentences", [])])
def test_d2_record_rejects_bad_values(field, bad):
    with pytest.raises(ValidationError):
        D2Report.model_validate({**RECORD, field: bad})


@pytest.mark.parametrize("label_id", ["T1566", "TA0001"])
def test_ttp_hit_accepts_techniques_and_tactics(label_id):
    assert TTPHit(technique_id=label_id, score=0.5, sentence_index=0).technique_id == label_id


@pytest.mark.parametrize("label_id", ["T1566.001", "TA001", "X1566"])
def test_ttp_hit_rejects_sub_techniques_and_junk(label_id):
    with pytest.raises(ValidationError):
        TTPHit(technique_id=label_id, score=0.5, sentence_index=0)


def test_cskg_matches_phase2_return_format():
    g = CSKG.model_validate(
        {
            "doc_id": "d2_29a45b3381cd",
            "nodes": [{"id": "s0", "type": "SEQ"}, {"id": "T1566", "type": "TTP"}],
            "edges": [{"src": "s0", "dst": "T1566", "rel": "dependency"}],
        }
    )
    assert [n.type.value for n in g.nodes] == ["SEQ", "TTP"]
