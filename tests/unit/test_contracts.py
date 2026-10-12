import pytest
from pydantic import ValidationError

from threatmamba.contracts import CSKG, HandoffReport, TTPHit

RECORD = {
    "doc_id": "d2_29a45b3381cd",
    "split": "train",
    "label": 1,
    "group_name": "Waterbug",
    "group_alias": "Waterbug",
    "text": "...",
    "meta": {"group_id": "39", "n_chars": 10291, "truncated_at_excel_limit": False, "source": "CTI2Attacker.csv"},
}


def test_handoff_record_parses():
    assert HandoffReport.model_validate(RECORD).label == 1


@pytest.mark.parametrize("field,bad", [("doc_id", "d2_XYZ"), ("label", 25), ("split", "dev")])
def test_handoff_record_rejects_bad_values(field, bad):
    with pytest.raises(ValidationError):
        HandoffReport.model_validate({**RECORD, field: bad})


def test_ttp_hit_requires_technique_id_format():
    with pytest.raises(ValidationError):
        TTPHit(technique_id="T1566.001", score=0.5, sentence_index=0)


def test_cskg_matches_phase2_return_format():
    g = CSKG.model_validate(
        {
            "doc_id": "d2_29a45b3381cd",
            "nodes": [{"id": "s0", "type": "SEQ"}, {"id": "T1566", "type": "TTP"}],
            "edges": [{"src": "s0", "dst": "T1566", "rel": "dependency"}],
        }
    )
    assert [n.type.value for n in g.nodes] == ["SEQ", "TTP"]
