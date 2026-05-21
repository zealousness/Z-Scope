import json
from pathlib import Path

from zscope.reporting.sarif_exporter import save_sarif_report


def test_save_sarif_report_exports_zscope_issue(tmp_path: Path) -> None:
    report = {
        "issues": [
            {
                "id": "ISSUE_1",
                "candidate_id": "RULE_DEMO",
                "dedup_key": "demo|src/demo.c|42",
                "location": "src/demo.c:42",
                "defect_class": "memory_leak",
                "rule": "same_function_allocation_not_released",
                "cwe": "CWE-401",
                "description": "demo leak",
                "impact_level": "medium",
                "validation_status": "validated",
                "candidate_source": "regex_local_rule",
                "baseline_match_strategy": "stable_fingerprint",
                "positive_evidence": ["allocation without release"],
                "evidence_pack": {
                    "source": {"file": "src/demo.c", "line": 40, "expression": "malloc"},
                    "sink": {"file": "src/demo.c", "line": 42, "operation": "return"},
                },
            }
        ]
    }
    output = tmp_path / "zscope.sarif"

    save_sarif_report(report, output, source_root=tmp_path)

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    result = data["runs"][0]["results"][0]
    assert result["ruleId"] == "CWE-401:same_function_allocation_not_released"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/demo.c"
    assert result["properties"]["zscope"]["candidate_id"] == "RULE_DEMO"
    assert result["properties"]["zscope"]["candidate_source"] == "regex_local_rule"
    assert result["properties"]["zscope"]["baseline_match_strategy"] == "stable_fingerprint"
    assert result["properties"]["zscope"]["stable_fingerprint"]
    assert "zscopeStableIssueFingerprint" in result["partialFingerprints"]
    assert result["codeFlows"]


def test_sarif_stable_fingerprint_survives_line_shift(tmp_path: Path) -> None:
    first = {
        "issues": [
            {
                "id": "A",
                "location": "src/demo.c:42",
                "category": "memory_leak",
                "function": "open_handle",
                "rule": "missing_close",
                "source": "SHM_FileOpen",
                "sink": "return",
                "description": "handle returned without close",
            }
        ]
    }
    second = json.loads(json.dumps(first))
    second["issues"][0]["location"] = "src/demo.c:57"

    first_path = save_sarif_report(first, tmp_path / "first.sarif", source_root=tmp_path)
    second_path = save_sarif_report(second, tmp_path / "second.sarif", source_root=tmp_path)

    first_fp = json.loads(first_path.read_text(encoding="utf-8"))["runs"][0]["results"][0][
        "partialFingerprints"
    ]["zscopeStableIssueFingerprint"]
    second_fp = json.loads(second_path.read_text(encoding="utf-8"))["runs"][0]["results"][0][
        "partialFingerprints"
    ]["zscopeStableIssueFingerprint"]

    assert first_fp == second_fp
