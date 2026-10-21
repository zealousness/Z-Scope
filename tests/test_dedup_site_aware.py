"""Site-aware dedup guard tests.

A destructive merge must not swallow a distant second truth that merely
shares a root-cause token with the surviving representative.  The guard is
unconditional: distant sites always stay independent occurrences.
"""

from zscope.common.issue_identity import (
    _same_defect_site,
    deduplicate_issues,
)


def _issue(iid, line, *, root="numeric_size_calculation", sink=None):
    return {
        "id": iid,
        "category": "integer_overflow",
        "rule": "clang_cfg_size_addition_without_overflow_guard",
        "file": "src/lifecycle.c",
        "location": f"src/lifecycle.c:{line}",
        "function": "_lifecycle_resize_metrics",
        "root_cause_key": root,
        "sink": sink,
        "final_score": 0.6,
    }


def test_same_defect_site_helper():
    a = _issue("A", 100)
    b = _issue("B", 106)
    far = _issue("C", 2600)
    assert _same_defect_site(a, b) is True
    assert _same_defect_site(a, far) is False
    no_line = {"id": "X", "location": "src/lifecycle.c"}
    assert _same_defect_site(a, no_line) is True  # unknown line -> fallback


def test_distant_second_truth_is_kept():
    issues = [_issue("TP_REP", 300), _issue("SECOND", 2600)]
    kept = deduplicate_issues([dict(i) for i in issues])
    ids = sorted(i["id"] for i in kept)
    assert ids == ["SECOND", "TP_REP"]
    keys = {i["id"]: i["dedup_key"] for i in kept}
    assert keys["TP_REP"] != keys["SECOND"]


def test_same_site_still_merges():
    issues = [_issue("A", 300), _issue("B", 305)]
    kept = deduplicate_issues([dict(i) for i in issues])
    assert len(kept) == 1


def test_unknown_line_falls_back_to_equivalence():
    issues = [_issue("A", 300), _issue("B", 305)]
    for i in issues:
        i.pop("location")
    kept = deduplicate_issues([dict(i) for i in issues])
    assert len(kept) == 1
