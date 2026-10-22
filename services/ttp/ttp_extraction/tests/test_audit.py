import pandas as pd

from ttp_extraction.data.audit import classify_columns, roll_up


def test_classify_columns():
    groups = classify_columns(["Text", "TA0001", "T1566", "T1566.001"])
    assert groups == {
        "tactics": ["TA0001"],
        "techniques": ["T1566"],
        "subtechniques": ["T1566.001"],
        "other": ["Text"],
    }


def test_roll_up_sets_parent_from_sub():
    labels = pd.DataFrame({
        "T1566": [0, 1, 0],
        "T1566.001": [1, 0, 0]
    })

    rolled = roll_up(labels, ["T1566"], ["T1566.001"])

    assert rolled["T1566"].tolist() == [1, 1, 0]