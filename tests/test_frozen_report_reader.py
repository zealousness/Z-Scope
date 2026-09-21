from copy import deepcopy
import json

import pytest

from zscope.benchmarking.protocol import score_report_views
from zscope.reporting.frozen_objects import frozen_view
from zscope.reporting.json_io import read_report, write_report_atomic, write_json_atomic
from zscope.reporting.shared_objects import ObjectEncoder


def test_readonly_references_share_containers_but_mutable_copies_are_isolated(tmp_path):
    evidence = {"facts": [{"line": 9, "code": "complete evidence"}], "paths": [1, 2, 3]}
    value = {"issues": [{"evidence": evidence} for _ in range(1000)]}
    path = tmp_path / "report.json"
    write_report_atomic(path, value)
    actual = read_report(path, immutable=True)
    assert actual == value
    assert actual["issues"][0] is actual["issues"][999]
    assert len(actual._decoder._decoded) <= len(actual._decoder.objects)
    assert ObjectEncoder().envelope(actual)["root"] == ObjectEncoder().envelope(value)["root"]
    modified = deepcopy(actual)
    modified["issues"][0]["evidence"]["facts"][0]["line"] = 99
    assert modified["issues"][1]["evidence"]["facts"][0]["line"] == 9
    assert actual["issues"][0]["evidence"]["facts"][0]["line"] == 9
    original = read_report(path)
    original["issues"][0]["evidence"]["paths"].append(4)
    assert original["issues"][1]["evidence"]["paths"] == [1, 2, 3]


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.__setitem__("x", 2),
        lambda value: value.pop("x"),
        lambda value: value.update(x=2),
        lambda value: value.clear(),
        lambda value: value.setdefault("y", 3),
        lambda value: value["items"].append(4),
        lambda value: value["items"].__setitem__(0, 4),
        lambda value: value["items"].reverse(),
        lambda value: value["items"].sort(),
    ],
)
def test_immutable_consumers_cannot_change_shared_evidence(change):
    value = frozen_view({"x": 1, "items": [1, 2]})
    with pytest.raises(TypeError, match="deepcopy"):
        change(value)
    assert value == {"x": 1, "items": [1, 2]}


def test_legacy_and_shared_readers_keep_original_matcher_values(tmp_path):
    issue = {
        "id": "one",
        "function": "inspect",
        "category": "null_deref",
        "location": "sample.c:9",
        "description": "Dereference null pointer",
        "evidence": {"source": [{"line": 9, "code": "*p = 1;"}]},
        "validation_status": "confirmed",
    }
    report = {
        "issues": [issue],
        "report_views": {"default": {"issues": [issue]}, "with_needs_review": {"issues": [issue]}},
    }
    truth = {
        "vulnerabilities": [
            {
                "id": "sample",
                "function": "inspect",
                "file": "sample.c",
                "line": 9,
                "category": "null_deref",
                "cwe": "CWE-476",
            }
        ]
    }
    shared, legacy = tmp_path / "shared.json", tmp_path / "legacy.json"
    write_report_atomic(shared, report)
    write_json_atomic(legacy, report)
    expected = score_report_views(report, truth)
    for path in (shared, legacy):
        actual = read_report(path, strict=True, immutable=True)
        assert json.loads(json.dumps(actual)) == report
        assert score_report_views(actual, truth) == expected


@pytest.mark.parametrize("input_format", ["shared", "legacy"])
def test_legacy_export_reuses_readonly_objects_and_preserves_all_values(
    tmp_path, monkeypatch, input_format
):
    import sys
    from zscope.cli import report_export

    evidence = {
        "source": [{"line": 7, "code": "whole evidence"}],
        "values": [None, False, 0, 1.25, "中文"],
    }
    value = {"issues": [{"evidence": evidence, "state": "needs_review"} for _ in range(400)]}
    original, exported = tmp_path / "input.json", tmp_path / "output.json"
    (write_report_atomic if input_format == "shared" else write_json_atomic)(original, value)
    input_bytes = original.read_bytes()
    observations = []

    def capture_read(path, **kwargs):
        actual = read_report(path, **kwargs)
        observations.append((kwargs, actual))
        return actual

    monkeypatch.setattr(report_export, "read_report", capture_read)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "zscope-report",
            "export",
            "--input",
            str(original),
            "--output",
            str(exported),
            "--format",
            "legacy-json",
        ],
    )
    report_export.main()
    assert json.loads(exported.read_text()) == value
    assert original.read_bytes() == input_bytes
    assert observations[0][0] == {"immutable": True}
    decoded = observations[0][1]
    assert decoded["issues"][0] is decoded["issues"][399]
    assert len(decoded._decoder._decoded) < 30
