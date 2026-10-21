"""Storage changes must preserve report values, isolation and scoring."""

from copy import deepcopy
import json
import pytest
from zscope.reporting.shared_objects import ObjectEncoder, ObjectDecoder
from zscope.reporting.json_io import read_report, write_report_atomic, write_json_atomic


def test_shared_report_roundtrip_and_independent_mutation(tmp_path):
    evidence = {"code": "complete source" * 1000, "facts": [{"line": 9, "value": 2**80}]}
    original = {
        "issues": [{"id": "a", "evidence": evidence}, {"id": "b", "evidence": deepcopy(evidence)}],
        "ref": ["ref", "ordinary user data"],
    }
    path = tmp_path / "report.json"
    write_report_atomic(path, original)
    raw = json.loads(path.read_text())
    assert sum(node == ["value", evidence["code"]] for node in raw["objects"].values()) == 1
    result = read_report(path)
    assert result == original
    assert original == result
    assert json.loads(json.dumps(result)) == original
    assert dict(result)["issues"] == original["issues"]
    copied = deepcopy(result)
    result["issues"][0]["evidence"]["facts"][0]["line"] = 17
    assert result["issues"][1]["evidence"]["facts"][0]["line"] == 9
    assert copied == original
    export = tmp_path / "legacy.json"
    write_json_atomic(export, copied)
    assert json.loads(export.read_text()) == original


def test_missing_and_corrupt_references_are_rejected():
    encoded = ObjectEncoder().envelope({"a": [1, 2]})
    corrupt = deepcopy(encoded)
    corrupt["objects"].pop(corrupt["root"][1])
    with pytest.raises(ValueError, match="missing"):
        ObjectDecoder(corrupt)
    encoded["objects"][encoded["root"][1]][1].append(["x", ["value", 4]])
    with pytest.raises(ValueError, match="integrity"):
        ObjectDecoder(encoded)


def test_legacy_json_remains_readable(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text('{"storage_schema":"user-data","value":-0.0}')
    assert read_report(path) == {"storage_schema": "user-data", "value": -0.0}


def test_checkpoint_objects_commit_once_and_corruption_fails_closed(tmp_path):
    from zscope.core.validation.review_checkpoint import ReviewCheckpointStore
    import sqlite3

    store = ReviewCheckpointStore(tmp_path)
    facts = {"complete": [{"source": "unchanged" * 1000, "uid": "fact-1"}]}
    one = store.save({"id": "a"}, stage="validation", facts=facts, runtime={})
    two = store.save({"id": "b"}, stage="validation", facts=deepcopy(facts), runtime={})
    db_path = tmp_path / "evidence/objects.sqlite3"
    with sqlite3.connect(db_path) as db:
        raw = [json.loads(row[0]) for row in db.execute("SELECT node FROM objects")]
        assert sum(node == ["value", facts["complete"][0]["source"]] for node in raw) == 1
    a, b = store.load(one), store.load(two)
    a["facts"]["complete"][0]["uid"] = "changed"
    assert b["facts"]["complete"][0]["uid"] == "fact-1"
    with sqlite3.connect(db_path) as db:
        db.execute("DELETE FROM objects WHERE digest=?", (one[3:],))
    with pytest.raises(ValueError, match="missing"):
        store.load(one)
    assert store.load(two)["candidate"]["id"] == "b"
