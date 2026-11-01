import json
from pathlib import Path

from zscope.reporting.sarif_exporter import report_to_sarif, save_sarif_report


def test_sarif_parses_windows_location_with_column() -> None:
    report = {"issues": [{"location": r"C:\src\demo.c:42:7"}]}
    result = report_to_sarif(report)["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "C:/src/demo.c"
    assert physical["region"]["startLine"] == 42


def test_sarif_preserves_legacy_line_range_locations() -> None:
    report = {
        "issues": [
            {"location": "src/demo.c:10-20"},
            {"location": r"C:\src\demo.c:30-40"},
        ]
    }
    results = report_to_sarif(report)["runs"][0]["results"]
    physical = [result["locations"][0]["physicalLocation"] for result in results]
    assert [item["artifactLocation"]["uri"] for item in physical] == [
        "src/demo.c", "C:/src/demo.c"
    ]
    assert [item["region"]["startLine"] for item in physical] == [10, 30]


def test_sarif_prefers_structured_coordinates_over_display_location() -> None:
    report = {
        "issues": [
            {"file_path": "src/current.c", "line": 23, "location": "src/stale.c:99"}
        ]
    }
    result = report_to_sarif(report)["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/current.c"
    assert physical["region"]["startLine"] == 23


def test_sarif_encodes_reserved_characters_in_source_paths() -> None:
    report = {"issues": [{"location": "src/a #1%?.c:8"}]}
    result = report_to_sarif(report)["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/a%20%231%25%3F.c"


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
    assert result["ruleId"] == "same_function_allocation_not_released"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/demo.c"
    assert result["properties"]["zscope"]["candidate_id"] == "RULE_DEMO"
    assert result["properties"]["zscope"]["candidate_source"] == "regex_local_rule"
    assert result["properties"]["zscope"]["baseline_match_strategy"] == "stable_fingerprint"
    assert result["properties"]["zscope"]["stable_fingerprint"]
    assert "zscopeStableIssueFingerprint" in result["partialFingerprints"]
    assert result["codeFlows"]
    descriptor = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert descriptor["id"] == "same_function_allocation_not_released"
    assert descriptor["properties"]["cwe"] == "CWE-401"
    assert "CWE-401" in descriptor["properties"]["tags"]
    assert (
        descriptor["properties"]["legacyRuleId"] == "CWE-401:same_function_allocation_not_released"
    )


def test_sarif_prefers_canonical_rule_id_and_exports_rule_metadata(tmp_path: Path) -> None:
    report = {
        "issues": [
            {
                "id": "ISSUE_1",
                "location": "src/demo.c:42",
                "rule_id": "clang_cfg_use_after_release",
                "rule": "legacy_use_after_release",
                "defect_class": "use_after_free",
                "cwe": "CWE-416",
                "rule_engine": "cpp_clang_cfg",
                "rule_revision": 3,
                "skill": "temporal_memory",
                "rule_catalog_sha256": "catalog-sha256",
                "description": "released object is used",
            }
        ]
    }

    path = save_sarif_report(report, tmp_path / "canonical.sarif")
    run = json.loads(path.read_text(encoding="utf-8"))["runs"][0]
    result = run["results"][0]
    descriptor = run["tool"]["driver"]["rules"][0]

    assert result["ruleId"] == "clang_cfg_use_after_release"
    assert descriptor["id"] == "clang_cfg_use_after_release"
    assert descriptor["properties"] == {
        "tags": ["security", "use-after-free", "CWE-416"],
        "legacyRuleId": "CWE-416:legacy_use_after_release",
        "cwe": "CWE-416",
        "cwes": ["CWE-416"],
        "rule_engine": "cpp_clang_cfg",
        "rule_revision": 3,
        "skill": "temporal_memory",
        "rule_catalog_sha256": "catalog-sha256",
    }


def test_sarif_reads_rule_metadata_from_evidence_descriptor(tmp_path: Path) -> None:
    report = {
        "issues": [
            {
                "location": "src/Demo.java:7",
                "rule_id": "java_sql_statement_execute",
                "rule": "java_sql_statement_execute",
                "defect_class": "sql_injection",
                "cwe": "CWE-89",
                "evidence_pack": {
                    "rule_descriptor": {
                        "rule_engine": "java_local",
                        "rule_revision": 2,
                        "skill": "java_injection",
                        "rule_catalog_sha256": "java-catalog-sha256",
                    }
                },
            }
        ]
    }

    path = save_sarif_report(report, tmp_path / "nested-metadata.sarif")
    descriptor = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["tool"]["driver"]["rules"][
        0
    ]

    assert descriptor["properties"]["rule_engine"] == "java_local"
    assert descriptor["properties"]["rule_revision"] == 2
    assert descriptor["properties"]["skill"] == "java_injection"
    assert descriptor["properties"]["rule_catalog_sha256"] == "java-catalog-sha256"


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


def test_sarif_does_not_export_operational_obligations(tmp_path: Path) -> None:
    report = {
        "issues": [
            {
                "id": "ENGINE_FAILURE",
                "record_role": "operational_obligation",
                "candidate_disposition": "engine_failed",
                "location": "src/demo.c:1",
                "category": "engine_failure",
                "description": "SVF timed out",
            }
        ]
    }

    path = save_sarif_report(report, tmp_path / "operational.sarif")
    results = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"]

    assert results == []
