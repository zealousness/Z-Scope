from __future__ import annotations

import hashlib
import json
import re
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.e0_review_governance import (
    E0GovernanceError,
    PACKET_SCHEMA_VERSION,
    sha256_file,
    sha256_value,
)
from scripts.generate_range_v16_safe_pairs import (
    AUTHOR_CHECKPOINT_SCHEMA_VERSION,
    AUTHOR_DIAGNOSTIC_SCHEMA_VERSION,
    AUTHOR_FAILURE_SCHEMA_VERSION,
    AUTHOR_MODEL,
    AUTHOR_REQUEST_SCHEMA_VERSION,
    AUTHOR_SCHEMA_VERSION,
    RAW_AUTHOR_SCHEMA_VERSION,
    _REPAIRABLE_AUTHOR_VALIDATION_CLASSES,
    _author_one,
    _author_request,
    _author_schema,
    _c_tokens,
    _contract_repair_failure_message,
    _contract_repair_failure_projection,
    _has_preprocessor_directive,
    _main_definition_count,
    _parser,
    _source_identifiers,
    _write_failure_manifest,
    author_pairs,
    build_author_checkpoint,
    diagnose_author_checkpoint,
    materialize_pairs,
    validate_author_run,
    validate_author_record,
)
from scripts.run_e0_reviewers import (
    _assert_codex_transport_schema,
    _codex_arguments,
    _codex_transport_schema,
)
from tests.test_range_v16_truth import _normalized


def _dump(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _confirmable_normalized() -> dict:
    value = _normalized()
    record = value["records"][0]
    record["packet_sha256"] = _packet(record)["packet_sha256"]
    record["final_decision"]["contract_kind"] = "concrete_trigger"
    record["final_decision"]["disposition"] = "keep"
    record["final_decision_sha256"] = sha256_value(record["final_decision"])
    unsigned_record = dict(record)
    unsigned_record.pop("normalized_record_sha256")
    record["normalized_record_sha256"] = sha256_value(unsigned_record)
    unsigned = dict(value)
    unsigned.pop("content_sha256")
    value["content_sha256"] = sha256_value(unsigned)
    return value


def _packet(record: dict) -> dict:
    truth_id = record["truth_id"]
    content = "int project_specific_function(void) { return 0; }"
    packet = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "packet_uid": f"range-v16:{truth_id}",
        "source_truth_sha256": "e" * 64,
        "truth_record": {"id": truth_id, "function": "project_specific_function"},
        "code_windows": [
            {
                "path": "src/demo.c",
                "start_line": 1,
                "end_line": 1,
                "content": content,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        ],
        "threat_assumptions": ["The caller may invoke the function."],
        "safe_pair_candidate": {"kind": "fixed"},
    }
    packet["packet_sha256"] = sha256_value(packet)
    return packet


def _author(record: dict) -> dict:
    recommendation = record["final_decision"]["safe_pair_recommendation"]
    return {
        "schema_version": AUTHOR_SCHEMA_VERSION,
        "truth_id": record["truth_id"],
        "packet_sha256": record["packet_sha256"],
        "final_decision_sha256": record["final_decision_sha256"],
        "author_role": "safe_pair_author",
        "author_model": AUTHOR_MODEL,
        "kind": recommendation["kind"],
        "invariant_summary": recommendation["invariant_summary"],
        "vulnerable_source": (
            "int read_item(const int *p, int n) { (void)n; return p[1]; }\n"
            "int main(void) { int a[1] = {0}; return read_item(a, 1); }\n"
        ),
        "fixed_or_near_miss_source": (
            "int read_item(const int *p, int n) { return n > 1 ? p[1] : 0; }\n"
            "int main(void) { int a[1] = {0}; return read_item(a, 1); }\n"
        ),
    }


def _recommendation_bindings(record: dict) -> dict[str, str]:
    recommendation = record["final_decision"]["safe_pair_recommendation"]
    return {
        "expected_kind": str(recommendation["kind"]),
        "expected_invariant_summary": str(recommendation["invariant_summary"]),
    }


def _raw_author(record: dict, author: dict) -> dict:
    packet = _packet(record)
    request = _author_request(packet, record)
    forbidden = _source_identifiers(packet, str(record["truth_id"]))
    contract_schema = _author_schema(
        forbidden,
        truth_id=str(record["truth_id"]),
        packet_sha256=str(record["packet_sha256"]),
        final_decision_sha256=str(record["final_decision_sha256"]),
        expected_kind=str(request["safe_pair_recommendation"]["kind"]),
        expected_invariant_summary=str(request["safe_pair_recommendation"]["invariant_summary"]),
    )
    return {
        "schema_version": RAW_AUTHOR_SCHEMA_VERSION,
        "truth_id": record["truth_id"],
        "packet_sha256": record["packet_sha256"],
        "final_decision_sha256": record["final_decision_sha256"],
        "author_model": AUTHOR_MODEL,
        "command_identity": [
            "codex",
            *_codex_arguments(output_schema="author-schema.json"),
        ],
        "output_schema_sha256": sha256_value(_codex_transport_schema(contract_schema)),
        "contract_schema_sha256": sha256_value(contract_schema),
        "author_request_schema_version": AUTHOR_REQUEST_SCHEMA_VERSION,
        "author_request_sha256": sha256_value(request),
        "attempts": [
            {
                "attempt": 1,
                "kind": "initial",
                "exit_code": 0,
                "stdout": json.dumps(author),
                "stderr_sha256": sha256_value(""),
                "validation_class": None,
            }
        ],
        "accepted_attempt": 1,
    }


def _answer_free_failure_record(*, truth_id: str, failure_code: str, error_sha256: str) -> dict:
    return {
        "truth_id": truth_id,
        "failure_code": failure_code,
        "error_sha256": error_sha256,
        "initial_exit_code": None,
        "initial_stdout_sha256": None,
        "initial_stdout_retained": False,
        "initial_stderr_sha256": None,
        "retry_exit_code": None,
        "retry_stdout_sha256": None,
        "retry_stdout_retained": False,
        "retry_stderr_sha256": None,
        "answer_material_present": False,
    }


def _diagnostic_checkpoint_with_failure(
    root: Path,
    *,
    failure_code: str,
    error_sha256: str,
) -> Path:
    checkpoint = root / "checkpoint"
    checkpoint.mkdir()
    truth_id = "CASE-FAILURE-SECRET"
    manifest = {
        "schema_version": AUTHOR_CHECKPOINT_SCHEMA_VERSION,
        "author_model": AUTHOR_MODEL,
        "packet_source_sha": "a" * 40,
        "retained_source_sha": "a" * 40,
        "workflow_run_id": "33138014332",
        "normalized_decisions_sha256": "b" * 64,
        "expected_record_count": 1,
        "verified_record_count": 0,
        "verified_records": [],
        "invalid_records": [],
        "incomplete_records": [
            {"truth_id": truth_id, "author_present": False, "raw_present": True}
        ],
        "failure_records": [
            _answer_free_failure_record(
                truth_id=truth_id,
                failure_code=failure_code,
                error_sha256=error_sha256,
            )
        ],
        "checkpoint_contains_author_material": False,
        "diagnostic_answer_material_present": False,
        "requires_resume_revalidation": True,
    }
    manifest["content_sha256"] = sha256_value(manifest)
    _dump(checkpoint / "checkpoint-manifest.json", manifest)
    return checkpoint


def test_safe_pair_checkpoint_diagnostic_projects_only_fixed_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    checkpoint = tmp_path / "checkpoint"
    checkpoint.mkdir()
    failure_record = {
        "truth_id": "CASE-FAILURE-SECRET",
        "failure_code": "author_contract_failure",
        "error_sha256": "7" * 64,
        "initial_exit_code": None,
        "initial_stdout_sha256": None,
        "initial_stdout_retained": False,
        "initial_stderr_sha256": None,
        "retry_exit_code": None,
        "retry_stdout_sha256": None,
        "retry_stdout_retained": False,
        "retry_stderr_sha256": None,
        "answer_material_present": False,
    }
    manifest = {
        "schema_version": AUTHOR_CHECKPOINT_SCHEMA_VERSION,
        "author_model": AUTHOR_MODEL,
        "packet_source_sha": "a" * 40,
        "retained_source_sha": "a" * 40,
        "workflow_run_id": "33138014332",
        "normalized_decisions_sha256": "b" * 64,
        "expected_record_count": 136,
        "verified_record_count": 1,
        "verified_records": [{"truth_id": "CASE-VERIFIED-SECRET"}],
        "invalid_records": [],
        "incomplete_records": [
            {
                "truth_id": "CASE-FAILURE-SECRET",
                "author_present": False,
                "raw_present": True,
            }
        ],
        "failure_records": [failure_record],
        "checkpoint_contains_author_material": True,
        "diagnostic_answer_material_present": False,
        "requires_resume_revalidation": True,
    }
    manifest["content_sha256"] = sha256_value(manifest)
    _dump(checkpoint / "checkpoint-manifest.json", manifest)
    output = tmp_path / "diagnostic.json"
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    assert (
        diagnose_author_checkpoint(
            SimpleNamespace(
                checkpoint_dir=checkpoint,
                expected_source_sha="a" * 40,
                expected_workflow_run_id="33138014332",
                output=output,
            )
        )
        == 0
    )

    diagnostic = json.loads(output.read_text(encoding="utf-8"))
    assert diagnostic["schema_version"] == AUTHOR_DIAGNOSTIC_SCHEMA_VERSION
    assert diagnostic["diagnostic_status"] == "classified"
    assert diagnostic["diagnostic_failure_code"] is None
    assert diagnostic["failure_classes"] == [
        {"failure_code": "author_contract_failure", "count": 1}
    ]
    assert diagnostic["contract_repair_classes"] == []
    assert diagnostic["verified_record_count"] == 1
    assert diagnostic["incomplete_record_count"] == 1
    assert diagnostic["failure_record_count"] == 1
    assert diagnostic["diagnostic_answer_material_present"] is False
    serialized = json.dumps(diagnostic)
    assert "CASE-FAILURE-SECRET" not in serialized
    assert "CASE-VERIFIED-SECRET" not in serialized
    assert "7" * 64 not in serialized
    emitted = capsys.readouterr().out
    assert (
        "::notice title=Range v16 safe-pair author diagnostic::"
        "diagnostic_status=classified; "
        "failure_classes=author_contract_failure:1; "
        "contract_repair_classes=none; invalid_records=0; "
        "incomplete_records=1" in emitted
    )
    assert "CASE-FAILURE-SECRET" not in emitted
    assert "CASE-VERIFIED-SECRET" not in emitted
    assert "7" * 64 not in emitted


def test_contract_repair_failure_projection_covers_the_finite_vocabulary() -> None:
    expected_validation_classes = {
        "independent_compile_failure",
        "decision_identity_mismatch",
        "fields_or_schema_invalid",
        "forbidden_c_facilities",
        "invariant_missing",
        "kind_invalid",
        "main_contract_invalid",
        "model_identity_mismatch",
        "packet_identity_mismatch",
        "source_invalid",
        "source_not_anonymous",
        "sources_identical",
    }
    assert _REPAIRABLE_AUTHOR_VALIDATION_CLASSES == expected_validation_classes
    projections: dict[str, tuple[str, str]] = {}
    outcomes = {
        "process_nonzero": expected_validation_classes,
        "validation_exhausted": expected_validation_classes | {"unclassified_validation_failure"},
    }
    for repair_outcome, validation_classes in outcomes.items():
        for validation_class in validation_classes:
            digest = str(
                sha256_value(_contract_repair_failure_message(repair_outcome, validation_class))
            )
            projection = (repair_outcome, validation_class)
            assert digest not in projections
            projections[digest] = projection
            assert _contract_repair_failure_projection(digest) == projection

    assert len(projections) == len(expected_validation_classes) * 2 + 1
    assert _contract_repair_failure_projection("0" * 64) is None
    assert _contract_repair_failure_projection(
        str(sha256_value("safe-pair author contract repair failed: source_invalid"))
    ) == ("process_nonzero", "source_invalid")
    assert _contract_repair_failure_projection(
        str(sha256_value("safe-pair author contract repair exhausted: forbidden_c_facilities"))
    ) == ("validation_exhausted", "forbidden_c_facilities")


def test_historical_contract_repair_checkpoint_projects_answer_free_subclass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    digest = str(sha256_value("safe-pair author contract repair exhausted: forbidden_c_facilities"))
    checkpoint = _diagnostic_checkpoint_with_failure(
        tmp_path,
        failure_code="contract_repair_failure",
        error_sha256=digest,
    )
    output = tmp_path / "diagnostic.json"
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    assert (
        diagnose_author_checkpoint(
            SimpleNamespace(
                checkpoint_dir=checkpoint,
                expected_source_sha="a" * 40,
                expected_workflow_run_id="33138014332",
                output=output,
            )
        )
        == 0
    )

    diagnostic = json.loads(output.read_text(encoding="utf-8"))
    assert diagnostic["schema_version"] == AUTHOR_DIAGNOSTIC_SCHEMA_VERSION
    assert diagnostic["failure_classes"] == [
        {"failure_code": "contract_repair_failure", "count": 1}
    ]
    assert diagnostic["contract_repair_classes"] == [
        {
            "repair_outcome": "validation_exhausted",
            "validation_class": "forbidden_c_facilities",
            "count": 1,
        }
    ]
    serialized = json.dumps(diagnostic)
    assert "CASE-FAILURE-SECRET" not in serialized
    assert digest not in serialized
    emitted = capsys.readouterr().out
    assert "contract_repair_classes=" "validation_exhausted.forbidden_c_facilities:1" in emitted
    assert "CASE-FAILURE-SECRET" not in emitted
    assert digest not in emitted


def test_unknown_contract_repair_failure_projection_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint = _diagnostic_checkpoint_with_failure(
        tmp_path,
        failure_code="contract_repair_failure",
        error_sha256="0" * 64,
    )
    output = tmp_path / "diagnostic.json"
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")

    assert (
        diagnose_author_checkpoint(
            SimpleNamespace(
                checkpoint_dir=checkpoint,
                expected_source_sha="a" * 40,
                expected_workflow_run_id="33138014332",
                output=output,
            )
        )
        == 0
    )
    diagnostic = json.loads(output.read_text(encoding="utf-8"))
    assert diagnostic["diagnostic_status"] == "rejected"
    assert diagnostic["diagnostic_failure_code"] == "checkpoint_failure_record_projection_invalid"
    assert "CASE-FAILURE-SECRET" not in json.dumps(diagnostic)
    assert "0" * 64 not in json.dumps(diagnostic)


def test_safe_pair_checkpoint_diagnostic_projects_fixed_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    checkpoint = tmp_path / "checkpoint"
    checkpoint.mkdir()
    manifest = {
        "schema_version": AUTHOR_CHECKPOINT_SCHEMA_VERSION,
        "author_model": AUTHOR_MODEL,
        "packet_source_sha": "a" * 40,
        "retained_source_sha": "a" * 40,
        "workflow_run_id": "33138014332",
        "normalized_decisions_sha256": "b" * 64,
        "expected_record_count": 1,
        "verified_record_count": 1,
        "verified_records": [{"truth_id": "CASE-VERIFIED-SECRET"}],
        "invalid_records": [],
        "incomplete_records": [],
        "failure_records": [],
        "checkpoint_contains_author_material": True,
        "diagnostic_answer_material_present": False,
        "requires_resume_revalidation": True,
    }
    manifest["content_sha256"] = sha256_value(manifest)
    _dump(checkpoint / "checkpoint-manifest.json", manifest)
    output = tmp_path / "diagnostic.json"
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    assert (
        diagnose_author_checkpoint(
            SimpleNamespace(
                checkpoint_dir=checkpoint,
                expected_source_sha="a" * 40,
                expected_workflow_run_id="33138014332",
                output=output,
            )
        )
        == 0
    )

    diagnostic = json.loads(output.read_text(encoding="utf-8"))
    assert diagnostic == {
        "schema_version": AUTHOR_DIAGNOSTIC_SCHEMA_VERSION,
        "diagnostic_status": "rejected",
        "diagnostic_failure_code": "checkpoint_without_diagnostic_signal",
        "checkpoint_workflow_run_id": "33138014332",
        "checkpoint_packet_source_sha": "a" * 40,
        "diagnostic_answer_material_present": False,
        "content_sha256": diagnostic["content_sha256"],
    }
    assert "CASE-VERIFIED-SECRET" not in json.dumps(diagnostic)
    emitted = capsys.readouterr().out
    assert (
        "::notice title=Range v16 safe-pair author diagnostic::"
        "diagnostic_status=rejected; "
        "diagnostic_failure_code=checkpoint_without_diagnostic_signal" in emitted
    )
    assert "CASE-VERIFIED-SECRET" not in emitted


def test_safe_pair_checkpoint_diagnostic_cannot_write_into_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint = tmp_path / "checkpoint"
    checkpoint.mkdir()
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")

    with pytest.raises(ValueError, match="cannot modify the checkpoint"):
        diagnose_author_checkpoint(
            SimpleNamespace(
                checkpoint_dir=checkpoint,
                expected_source_sha="a" * 40,
                expected_workflow_run_id="33138014332",
                output=checkpoint / "diagnostic.json",
            )
        )


def test_safe_pair_codex_schema_preserves_strict_local_contract() -> None:
    strict = _author_schema(
        {"project_specific_function"},
        truth_id="PAIR-001",
        packet_sha256="a" * 64,
        final_decision_sha256="b" * 64,
    )
    original = json.loads(json.dumps(strict))
    projected = _codex_transport_schema(strict)

    assert strict == original
    for field in ("vulnerable_source", "fixed_or_near_miss_source"):
        assert strict["properties"][field]["minLength"] == 1
        assert strict["properties"][field]["maxLength"] == 32768
        assert "(?" in strict["properties"][field]["pattern"]
        assert "minLength" not in projected["properties"][field]
        assert "maxLength" not in projected["properties"][field]
        assert "pattern" not in projected["properties"][field]
    assert projected["properties"]["packet_sha256"]["pattern"] == "^[0-9a-f]{64}$"
    _assert_codex_transport_schema(projected)


def test_safe_pair_author_request_projects_only_frozen_contract() -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)

    request = _author_request(packet, record)

    assert request == {
        "schema_version": AUTHOR_REQUEST_SCHEMA_VERSION,
        "truth_id": record["truth_id"],
        "packet_uid": record["packet_uid"],
        "packet_sha256": record["packet_sha256"],
        "final_decision_sha256": record["final_decision_sha256"],
        "contract_kind": record["final_decision"]["contract_kind"],
        "safe_pair_recommendation": record["final_decision"]["safe_pair_recommendation"],
    }
    serialized = json.dumps(request)
    assert "code_windows" not in serialized
    assert "project_specific_function" not in serialized


def test_safe_pair_author_rejects_project_specific_identifiers() -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    author = _author(record)
    validate_author_record(
        author,
        truth_id=record["truth_id"],
        packet_sha256=record["packet_sha256"],
        final_decision_sha256=record["final_decision_sha256"],
        forbidden_identifiers={"project_specific_function", record["truth_id"]},
        **_recommendation_bindings(record),
    )
    author["vulnerable_source"] += "int project_specific_function(void) { return 0; }\n"
    with pytest.raises(ValueError, match="not anonymous"):
        validate_author_record(
            author,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers={"project_specific_function", record["truth_id"]},
            **_recommendation_bindings(record),
        )

    missing_main = _author(record)
    missing_main["fixed_or_near_miss_source"] = "int read_item(int n) { return n; }\n"
    with pytest.raises(ValueError, match="exactly one C11 main"):
        validate_author_record(
            missing_main,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers=set(),
            **_recommendation_bindings(record),
        )


def test_safe_pair_main_contract_requires_a_real_definition() -> None:
    assert _main_definition_count("int main ( void ) { return 0; }") == 1
    assert _main_definition_count("/* int main(void) { */ int helper(void) { return 0; }") == 0
    assert _main_definition_count("int main(void); int helper(void) { return 0; }") == 0
    assert (
        _main_definition_count("#define FAKE int main(void) {\nint helper(void) { return 0; }") == 0
    )
    assert (
        _main_definition_count(
            "#define FAKE \\\nint main(void) { return 1; }\n" "int helper(void) { return 0; }"
        )
        == 0
    )
    comment_prefixed = (
        "/* marker */ #define FAKE int main(void) { return 1; }\n" "int helper(void) { return 0; }"
    )
    assert _has_preprocessor_directive(comment_prefixed)
    assert _main_definition_count(comment_prefixed) == 0
    assert _has_preprocessor_directive("%:define FAKE int main(void) { return 1; }")
    assert _has_preprocessor_directive("??=define FAKE int main(void) { return 1; }")
    assert _has_preprocessor_directive("\f#include <stddef.h>")
    assert _has_preprocessor_directive("\v%:include <stddef.h>")
    assert _has_preprocessor_directive("int value;\r#include <stddef.h>")
    assert _has_preprocessor_directive("\ufeff#include <stddef.h>")
    assert _has_preprocessor_directive("/\\\n* marker */ #include <stddef.h>")
    assert _has_preprocessor_directive("??/\n??=include <stddef.h>")
    assert not _has_preprocessor_directive('const char *value = "#if 0";')
    assert not _has_preprocessor_directive("int value = '#';")
    assert not _has_preprocessor_directive('const char *value = "%:include";')
    assert not _has_preprocessor_directive('const char *value = "??=include";')
    assert _main_definition_count("int main(void) { return 0; } int main(void) { return 1; }") == 2


def test_safe_pair_source_projection_ignores_only_comments_and_whitespace() -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    author = _author(record)
    author["fixed_or_near_miss_source"] = "/* cosmetic */\n" + author["vulnerable_source"].replace(
        " ", "  "
    )
    with pytest.raises(ValueError, match="sources are identical"):
        validate_author_record(
            author,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers=set(),
            **_recommendation_bindings(record),
        )

    assert _c_tokens('const char *value = "/*";') != _c_tokens('const char *value = "//";')


def test_safe_pair_author_anonymity_matches_complete_c_identifiers() -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    author = _author(record)
    author["vulnerable_source"] = author["vulnerable_source"].replace(
        "read_item", "project_entry_count"
    )
    author["fixed_or_near_miss_source"] = author["fixed_or_near_miss_source"].replace(
        "read_item", "project_entry_count"
    )
    validate_author_record(
        author,
        truth_id=record["truth_id"],
        packet_sha256=record["packet_sha256"],
        final_decision_sha256=record["final_decision_sha256"],
        forbidden_identifiers={"project_entry", record["truth_id"]},
        **_recommendation_bindings(record),
    )

    author["vulnerable_source"] += "int project_entry(void) { return 0; }\n"
    with pytest.raises(ValueError, match="not anonymous"):
        validate_author_record(
            author,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers={"project_entry", record["truth_id"]},
            **_recommendation_bindings(record),
        )


def test_safe_pair_author_schema_enforces_complete_anonymity_catalog() -> None:
    pattern = _author_schema({"project_entry", "CASE-1"})["properties"]["vulnerable_source"][
        "pattern"
    ]
    assert r"\-" not in pattern
    assert re.search(pattern, "int project_entry_count(void) { return 0; }\n")
    assert not re.search(pattern, "int project_entry(void) { return 0; }\n")
    assert not re.search(pattern, "int main(void) { /* CASE-1 */ return 0; }\n")
    assert not re.search(pattern, 'int main(void) { return "CASE-1"[0]; }\n')


def test_safe_pair_author_schema_binds_all_frozen_identity_fields() -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    recommendation = record["final_decision"]["safe_pair_recommendation"]
    schema = _author_schema(
        {"project_entry", str(record["truth_id"])},
        truth_id=str(record["truth_id"]),
        packet_sha256=str(record["packet_sha256"]),
        final_decision_sha256=str(record["final_decision_sha256"]),
        expected_kind=str(recommendation["kind"]),
        expected_invariant_summary=str(recommendation["invariant_summary"]),
    )
    properties = schema["properties"]
    assert properties["truth_id"] == {"type": "string", "const": record["truth_id"]}
    assert properties["packet_sha256"] == {
        "type": "string",
        "const": record["packet_sha256"],
        "pattern": "^[0-9a-f]{64}$",
    }
    assert properties["final_decision_sha256"] == {
        "type": "string",
        "const": record["final_decision_sha256"],
        "pattern": "^[0-9a-f]{64}$",
    }
    assert properties["kind"] == {
        "type": "string",
        "const": recommendation["kind"],
    }
    assert properties["invariant_summary"] == {
        "type": "string",
        "const": recommendation["invariant_summary"],
    }

    with pytest.raises(ValueError, match="identity must be fully bound"):
        _author_schema({"project_entry"}, truth_id=str(record["truth_id"]))
    with pytest.raises(ValueError, match="recommendation must be fully bound"):
        _author_schema({"project_entry"}, expected_kind=str(recommendation["kind"]))


def test_safe_pair_author_schema_types_all_const_and_enum_nodes() -> None:
    schema = _author_schema(
        {"project_entry", "CASE-1"},
        truth_id="CASE-1",
        packet_sha256="1" * 64,
        final_decision_sha256="2" * 64,
    )
    pending: list[object] = [schema]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "const" in node or "enum" in node:
                assert "type" in node
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)


def test_safe_pair_anonymity_includes_packet_functions_and_macros() -> None:
    identifiers = _source_identifiers(
        {
            "truth_record": {"id": "CASE-1", "function": "project_entry"},
            "code_windows": [
                {
                    "content": (
                        "#define PROJECT_PRIVATE_LIMIT 16\n"
                        "static int project_helper(int value) {\n"
                        "  for (int i = 0; i < 1; ++i) { value += i; }\n"
                        "  return (value);\n"
                        "}\n"
                        "int project_entry(void) { return project_helper(PROJECT_PRIVATE_LIMIT); }"
                    )
                }
            ],
        },
        "CASE-1",
    )
    assert {
        "CASE-1",
        "project_entry",
        "project_helper",
        "PROJECT_PRIVATE_LIMIT",
    }.issubset(identifiers)
    assert {"for", "return"}.isdisjoint(identifiers)


def test_safe_pair_author_uses_one_bounded_contract_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["vulnerable_source"] = "#include <stddef.h>\n" + invalid["vulnerable_source"]
    repaired = _author(record)
    responses = [invalid, repaired]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        author = responses.pop(0)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(author),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(packet, record, output=tmp_path / "author", resume=False)
    assert result["status"] == "authored"
    assert len(prompts) == 2
    assert '"validation_class": "forbidden_c_facilities"' in prompts[1]
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["schema_version"] == RAW_AUTHOR_SCHEMA_VERSION
    assert raw["accepted_attempt"] == 2
    assert [attempt["kind"] for attempt in raw["attempts"]] == [
        "initial",
        "contract_repair",
    ]
    assert raw["attempts"][0]["validation_class"] == "forbidden_c_facilities"
    assert raw["attempts"][1]["validation_class"] is None
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", packet)
    _dump(
        tmp_path / "author" / "manifest.json",
        {
            "schema_version": "zscope.range-v16-safe-pair-author-run.v1",
            "author_model": AUTHOR_MODEL,
            "record_count": 1,
            "normalized_decisions_sha256": sha256_file(normalized_path),
            "records": [result],
            "content_sha256": sha256_value([result]),
        },
    )
    assert validate_author_run(
        author_root=tmp_path / "author",
        normalized_path=normalized_path,
        expected_records={record["truth_id"]: record},
        packet_dir=packet_dir,
    ) == {record["truth_id"]: result}


def test_safe_pair_missing_and_unexpected_fields_receive_complete_repair_feedback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["schema_version"] = "unsupported"
    invalid.pop("kind")
    invalid["unexpected"] = True
    responses = [invalid, _author(record)]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    assert (
        _author_one(packet, record, output=tmp_path / "author", resume=False)["status"]
        == "authored"
    )
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    assert repair_request["deterministic_constraints"]["detected_validation_classes"] == [
        "fields_or_schema_invalid",
        "kind_invalid",
    ]
    fields = repair_request["deterministic_constraints"]["constraints_by_validation_class"][
        "fields_or_schema_invalid"
    ]
    assert fields["missing_fields"] == ["kind"]
    assert fields["unexpected_fields"] == ["unexpected"]
    assert fields["schema_version_mismatch"] is True


def test_safe_pair_author_binds_recommendation_and_repairs_both_mismatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    recommendation = record["final_decision"]["safe_pair_recommendation"]
    invalid = _author(record)
    invalid["kind"] = "fixed" if recommendation["kind"] == "near_miss" else "near_miss"
    invalid["invariant_summary"] = "A different but nonempty invariant."
    responses = [invalid, _author(record)]
    prompts: list[str] = []
    schemas: list[dict] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        schemas.append(
            json.loads(
                (Path(str(kwargs["cwd"])) / "author-schema.json").read_text(encoding="utf-8")
            )
        )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(packet, record, output=tmp_path / "author", resume=False)

    assert result["status"] == "authored"
    assert len(prompts) == 2
    assert schemas[0] == schemas[1]
    assert schemas[0]["properties"]["kind"] == {
        "type": "string",
        "const": recommendation["kind"],
    }
    assert schemas[0]["properties"]["invariant_summary"] == {
        "type": "string",
        "const": recommendation["invariant_summary"],
    }
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    constraints = repair_request["deterministic_constraints"]
    assert constraints["detected_validation_classes"] == [
        "kind_invalid",
        "invariant_missing",
    ]
    assert set(constraints["constraints_by_validation_class"]) == {
        "kind_invalid",
        "invariant_missing",
    }
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["attempts"][0]["validation_class"] == "kind_invalid"
    assert raw["attempts"][1]["validation_class"] is None


def test_safe_pair_author_one_repair_receives_every_detected_contract_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["vulnerable_source"] = "#include <stddef.h>\n" + invalid["vulnerable_source"]
    invalid["fixed_or_near_miss_source"] = invalid["vulnerable_source"]
    repaired = _author(record)
    responses = [invalid, repaired]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(packet, record, output=tmp_path / "author", resume=False)

    assert result["status"] == "authored"
    assert len(prompts) == 2
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    assert repair_request["validation_class"] == "forbidden_c_facilities"
    constraints = repair_request["deterministic_constraints"]
    assert constraints["detected_validation_classes"] == [
        "forbidden_c_facilities",
        "sources_identical",
    ]
    assert list(constraints["constraints_by_validation_class"]) == [
        "forbidden_c_facilities",
        "sources_identical",
    ]
    assert constraints["failing_source_fields"] == [
        "vulnerable_source",
        "fixed_or_near_miss_source",
    ]
    assert constraints["baseline_postconditions"] == {
        "compiler_contract": {
            "language": "c",
            "standard": "c11",
            "compiler": "cc",
            "arguments": ["-Werror", "-Wall", "-Wextra", "-c"],
        },
        "source_fields": ["vulnerable_source", "fixed_or_near_miss_source"],
        "each_source_has_exactly_one_main_definition": True,
        "preprocessor_or_forbidden_facility_present": False,
        "forbidden_identifier_matches_present": False,
        "sources_have_distinct_comment_whitespace_free_token_projections": True,
    }
    assert (
        constraints["constraints_by_validation_class"]["sources_identical"]["detected_condition"]
        == "sources_equal_after_newline_normalization"
    )
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["schema_version"] == RAW_AUTHOR_SCHEMA_VERSION
    assert raw["accepted_attempt"] == 2
    assert raw["attempts"][0]["validation_class"] == "forbidden_c_facilities"
    assert raw["attempts"][1]["validation_class"] is None


def test_safe_pair_invalid_strings_still_report_safe_deterministic_latent_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    source = (
        "#include <stddef.h>\n"
        "int project_specific_function(void) { return 0; }\n"
        "int main(void) { return 0; }\n\x00"
    )
    invalid["vulnerable_source"] = source
    invalid["fixed_or_near_miss_source"] = source
    responses = [invalid, _author(record)]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    assert (
        _author_one(packet, record, output=tmp_path / "author", resume=False)["status"]
        == "authored"
    )
    assert len(prompts) == 2
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    assert repair_request["deterministic_constraints"]["detected_validation_classes"] == [
        "source_invalid",
        "forbidden_c_facilities",
        "source_not_anonymous",
        "sources_identical",
    ]


def test_safe_pair_repair_classes_preserve_validator_order_and_deduplicate_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["vulnerable_source"] = "int project_specific_function(int value) { return value; }\n"
    invalid["fixed_or_near_miss_source"] = (
        "int project_specific_function(int value) { return value + 1; }\n"
    )
    responses = [invalid, _author(record)]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    assert (
        _author_one(packet, record, output=tmp_path / "author", resume=False)["status"]
        == "authored"
    )

    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    constraints = repair_request["deterministic_constraints"]
    assert constraints["detected_validation_classes"] == [
        "source_not_anonymous",
        "main_contract_invalid",
    ]
    by_class = constraints["constraints_by_validation_class"]
    assert set(by_class) == {"source_not_anonymous", "main_contract_invalid"}
    assert set(by_class["source_not_anonymous"]["detected_conflicts_by_source_field"]) == {
        "vulnerable_source",
        "fixed_or_near_miss_source",
    }
    assert by_class["main_contract_invalid"]["detected_main_counts_by_source_field"] == {
        "vulnerable_source": 0,
        "fixed_or_near_miss_source": 0,
    }


def test_safe_pair_repair_plan_does_not_recompile_the_rejected_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["fixed_or_near_miss_source"] = invalid["vulnerable_source"]
    repaired = _author(record)
    responses = [invalid, repaired]
    compiled_candidates: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_compile(value: dict, *, compiler: str) -> tuple[str, ...]:
        del compiler
        candidate = str(sha256_value(dict(value)))
        compiled_candidates.append(candidate)
        return (
            ("fixed_or_near_miss_source",)
            if value["vulnerable_source"] == value["fixed_or_near_miss_source"]
            else ()
        )

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._compile_author_source_fields",
        fake_compile,
    )

    prompts: list[str] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    assert (
        _author_one(
            packet,
            record,
            output=tmp_path / "author",
            resume=False,
            compiler="cc",
        )["status"]
        == "authored"
    )

    rejected_hash = str(sha256_value(invalid))
    repaired_hash = str(sha256_value(repaired))
    assert compiled_candidates.count(rejected_hash) == 1
    assert compiled_candidates.count(repaired_hash) == 1
    assert len(compiled_candidates) == 2
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    assert repair_request["deterministic_constraints"]["detected_validation_classes"] == [
        "sources_identical",
        "independent_compile_failure",
    ]


def test_safe_pair_forbidden_source_is_never_sent_to_the_compiler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    author = _author(record)
    author["vulnerable_source"] = "#include <stddef.h>\n" + author["vulnerable_source"]
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._compile_author_source_fields",
        lambda *_args, **_kwargs: pytest.fail("forbidden source must not reach the compiler"),
    )

    with pytest.raises(ValueError, match="forbidden C facilities"):
        validate_author_record(
            author,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers=set(),
            compiler="cc",
            **_recommendation_bindings(record),
        )

    digraph = _author(record)
    digraph["vulnerable_source"] = "%:include <stddef.h>\nint main(void) { return 0; }\n"
    with pytest.raises(ValueError, match="forbidden C facilities"):
        validate_author_record(
            digraph,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers=set(),
            compiler="cc",
            **_recommendation_bindings(record),
        )

    conditional = _author(record)
    conditional["vulnerable_source"] = (
        "#if 0\nint main(void) { return 0; }\n#endif\n" "int helper(void) { return 0; }\n"
    )
    with pytest.raises(ValueError, match="forbidden C facilities"):
        validate_author_record(
            conditional,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers=set(),
            compiler="cc",
            **_recommendation_bindings(record),
        )


@pytest.mark.parametrize(
    "forbidden_source",
    [
        "\f#include <stddef.h>\nint main(void) { return 0; }\n",
        "\v%:include <stddef.h>\nint main(void) { return 0; }\n",
        "int value;\r#include <stddef.h>\rint main(void) { return value; }\r",
        "\ufeff#include <stddef.h>\nint main(void) { return 0; }\n",
        "/\\\n* marker */ #include <stddef.h>\nint main(void) { return 0; }\n",
        "??/\n??=include <stddef.h>\nint main(void) { return 0; }\n",
        '_Pragma("GCC diagnostic ignored \\"-Wall\\"")\nint main(void) { return 0; }\n',
        'int main(void) { __asm__ volatile (""); return 0; }\n',
        'int open(const char *, int); int main(void) { return open("x", 0); }\n',
        "int socket(int, int, int); int main(void) { return socket(0, 0, 0); }\n",
        'int system(const char *); int main(void) { return system("true"); }\n',
        "extern int (*system)(void); int main(void) { return (system)(); }\n",
        'int main(void) { return __builtin_printf("value"); }\n',
        "long syscall(long); int main(void) { return (int)syscall(1); }\n",
        'void perror(const char *); int main(void) { perror("x"); return 0; }\n',
        'void *dlopen(const char *, int); int main(void) { return dlopen("x", 0) == 0; }\n',
    ],
)
def test_safe_pair_extended_forbidden_facilities_never_reach_compiler(
    forbidden_source: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    author = _author(record)
    author["vulnerable_source"] = forbidden_source
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._compile_author_source_fields",
        lambda *_args, **_kwargs: pytest.fail("forbidden source must not reach the compiler"),
    )

    with pytest.raises(ValueError, match="forbidden C facilities"):
        validate_author_record(
            author,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers=set(),
            compiler="cc",
            **_recommendation_bindings(record),
        )


def test_safe_pair_forbidden_names_in_comments_and_literals_are_not_calls() -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    author = _author(record)
    author["vulnerable_source"] = (
        "int helper(int value) { return value; }\n"
        'int main(void) { const char *name = "socket("; /* open( */ '
        "return helper(name[0]); }\n"
    )
    author["fixed_or_near_miss_source"] = (
        "int helper(int value) { return value != 0; }\n"
        'int main(void) { const char *name = "system("; /* fopen( */ '
        "return helper(name[0]); }\n"
    )

    validate_author_record(
        author,
        truth_id=record["truth_id"],
        packet_sha256=record["packet_sha256"],
        final_decision_sha256=record["final_decision_sha256"],
        forbidden_identifiers=set(),
        **_recommendation_bindings(record),
    )


def test_safe_pair_compiler_infrastructure_failure_prevents_contract_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["fixed_or_near_miss_source"] = invalid["vulnerable_source"]
    model_calls = 0

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._compile_author_source_fields",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            E0GovernanceError("safe-pair author compiler execution failed")
        ),
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal model_calls
        model_calls += 1
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(invalid),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="compiler execution failed"):
        _author_one(
            packet,
            record,
            output=tmp_path / "author",
            resume=False,
            compiler="cc",
        )
    assert model_calls == 1


def test_safe_pair_author_compile_gate_does_not_expose_compiler_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    author = _author(record)
    calls: list[list[str]] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/cc",
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if len(calls) == 1:
            output = Path(command[command.index("-o") + 1])
            output.write_bytes(b"object")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="untrusted compiler stdout",
            stderr="private compiler diagnostic body",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="independent compilation failed") as captured:
        validate_author_record(
            author,
            truth_id=str(record["truth_id"]),
            packet_sha256=str(record["packet_sha256"]),
            final_decision_sha256=str(record["final_decision_sha256"]),
            forbidden_identifiers=_source_identifiers(packet, str(record["truth_id"])),
            compiler="cc",
            **_recommendation_bindings(record),
        )

    assert getattr(captured.value, "failing_source_fields") == ("fixed_or_near_miss_source",)
    assert "private compiler diagnostic body" not in str(captured.value)
    assert "untrusted compiler stdout" not in str(captured.value)
    assert all(
        argument in calls[0] for argument in ("-std=c11", "-Werror", "-Wall", "-Wextra", "-c")
    )


def test_safe_pair_author_repairs_independent_compile_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["fixed_or_near_miss_source"] = "int main(void) { int unused_value = 0; return 0; }\n"
    repaired = _author(record)
    responses = [invalid, repaired]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._compile_author_source_fields",
        lambda value, *, compiler: (
            ("fixed_or_near_miss_source",)
            if "unused_value" in str(value["fixed_or_near_miss_source"])
            else ()
        ),
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(
        packet,
        record,
        output=tmp_path / "author",
        resume=False,
        compiler="cc",
    )

    assert result["status"] == "authored"
    assert len(prompts) == 2
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    assert repair_request["validation_class"] == "independent_compile_failure"
    assert repair_request["deterministic_constraints"]["failing_source_fields"] == [
        "fixed_or_near_miss_source"
    ]
    assert repair_request["deterministic_constraints"]["compiler_contract"] == {
        "language": "c",
        "standard": "c11",
        "compiler": "cc",
        "arguments": ["-Werror", "-Wall", "-Wextra", "-c"],
    }
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["accepted_attempt"] == 2
    assert raw["attempts"][0]["validation_class"] == "independent_compile_failure"
    assert raw["attempts"][1]["validation_class"] is None


def test_safe_pair_author_retries_nonzero_transport_without_retaining_bodies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    expected = _author(record)
    responses = iter(
        (
            subprocess.CompletedProcess(
                ["codex"],
                2,
                stdout="partial answer material",
                stderr="temporary provider body",
            ),
            subprocess.CompletedProcess(
                ["codex"],
                0,
                stdout=json.dumps(expected),
                stderr="",
            ),
        )
    )
    calls: list[tuple[list[str], str]] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, str(kwargs["input"])))
        return next(responses)

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(packet, record, output=tmp_path / "author", resume=False)

    assert result["status"] == "authored"
    assert len(calls) == 2
    assert calls[0] == calls[1]
    assert "authorized defensive static-analysis benchmark" in calls[0][1]
    assert "code_windows" not in calls[0][1]
    assert "project_specific_function" not in calls[0][1]
    assert "safe_pair_recommendation" in calls[0][1]
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["transport_retry"] == {
        "initial_exit_code": 2,
        "initial_stdout_sha256": sha256_value("partial answer material"),
        "initial_stdout_retained": False,
        "initial_stderr_sha256": sha256_value("temporary provider body"),
    }
    assert "partial answer material" not in json.dumps(raw)
    assert "temporary provider body" not in json.dumps(raw)


def test_safe_pair_author_transport_retry_is_bounded_and_answer_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    calls: list[list[str]] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="untrusted partial output",
            stderr="provider unavailable",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="failed after transport retry"):
        _author_one(packet, record, output=tmp_path / "author", resume=False)

    assert len(calls) == 2
    assert calls[0] == calls[1]
    assert not (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").exists()


def test_safe_pair_eight_worker_batch_collects_completed_futures_before_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized_path = tmp_path / "normalized.json"
    _dump(normalized_path, {"records": []})
    work = [
        ({"packet_sha256": str(index) * 64}, {"truth_id": f"T-{index:03d}"})
        for index in range(1, 13)
    ]
    calls: list[str] = []
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    active = 0
    max_active = 0

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.validate_normalized_decisions",
        lambda _: None,
    )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._confirmable_work",
        lambda *_, **__: work,
    )

    def fake_author(
        _packet_value: object,
        record: dict,
        **_: object,
    ) -> dict:
        nonlocal active, max_active
        truth_id = record["truth_id"]
        with lock:
            calls.append(truth_id)
            active += 1
            max_active = max(max_active, active)
        try:
            barrier.wait(timeout=5)
            if truth_id == "T-001":
                raise ValueError("synthetic failure")
            return {"truth_id": truth_id}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs._author_one", fake_author)
    args = SimpleNamespace(
        output_dir=tmp_path / "author",
        normalized_decisions=normalized_path,
        packet_dir=tmp_path,
        workers=8,
        resume=False,
        checkpoint_source_sha=None,
        checkpoint_workflow_run_id=None,
    )
    with pytest.raises(ValueError, match="failure_count=1") as exc_info:
        author_pairs(args)

    assert sorted(calls) == [f"T-{index:03d}" for index in range(1, 9)]
    assert max_active == 8
    assert "failure_classes=author_harness_failure:1" in str(exc_info.value)
    assert "T-001" not in str(exc_info.value)
    failure = json.loads(
        (tmp_path / "author" / "failure-manifest.json").read_text(encoding="utf-8")
    )
    assert failure["schema_version"] == AUTHOR_FAILURE_SCHEMA_VERSION
    assert failure["verified_record_count"] == 7
    assert failure["failure_record_count"] == 1
    assert failure["failure_records"][0]["answer_material_present"] is False


def test_safe_pair_failure_checkpoint_resume_compacts_only_missing_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized_path = tmp_path / "normalized.json"
    _dump(normalized_path, {"records": []})
    work = [
        (
            {"packet_sha256": f"{index:064x}"},
            {
                "truth_id": f"T-{index:03d}",
                "packet_sha256": f"{index:064x}",
                "final_decision_sha256": f"{index + 100:064x}",
            },
        )
        for index in range(1, 17)
    ]
    retained = tmp_path / "retained"
    checkpoint = tmp_path / "checkpoint"
    source_sha = "a" * 40
    run_id = "33228930421"
    phase = "initial"
    calls: dict[str, list[str]] = {"initial": [], "resume": []}
    initial_barrier = threading.Barrier(8)
    resume_barrier = threading.Barrier(8)
    lock = threading.Lock()
    resume_active = 0
    resume_max_active = 0
    first_resume_batch = {"T-001", *(f"T-{index:03d}" for index in range(9, 16))}

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.validate_normalized_decisions",
        lambda _: None,
    )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._confirmable_work",
        lambda *_, **__: work,
    )

    def fake_validated_existing(
        root: Path,
        packet: dict,
        record: dict,
        *,
        status: str,
        **_: object,
    ) -> dict:
        truth_id = record["truth_id"]
        author_path = root / "authors" / f"{truth_id}.json"
        raw_path = root / "raw" / f"{truth_id}.json"
        if not author_path.is_file() or not raw_path.is_file():
            raise ValueError(f"invalid existing pair: {truth_id}")
        return {
            "truth_id": truth_id,
            "packet_sha256": packet["packet_sha256"],
            "final_decision_sha256": record["final_decision_sha256"],
            "author_sha256": sha256_file(author_path),
            "raw_sha256": sha256_file(raw_path),
            "status": status,
        }

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._validated_existing_author_pair",
        fake_validated_existing,
    )

    def fake_author(
        packet: dict,
        record: dict,
        *,
        output: Path,
        **_: object,
    ) -> dict:
        nonlocal resume_active, resume_max_active
        truth_id = record["truth_id"]
        with lock:
            calls[phase].append(truth_id)
            if phase == "resume":
                resume_active += 1
                resume_max_active = max(resume_max_active, resume_active)
        try:
            if phase == "initial":
                initial_barrier.wait(timeout=5)
                if truth_id == "T-001":
                    raise ValueError("synthetic failure")
            elif truth_id in first_resume_batch:
                resume_barrier.wait(timeout=5)
            _dump(output / "authors" / f"{truth_id}.json", {"truth_id": truth_id})
            _dump(output / "raw" / f"{truth_id}.json", {"truth_id": truth_id})
            return fake_validated_existing(
                output,
                packet,
                record,
                status="authored",
            )
        finally:
            if phase == "resume":
                with lock:
                    resume_active -= 1

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs._author_one", fake_author)

    with pytest.raises(ValueError, match="failure_count=1"):
        author_pairs(
            SimpleNamespace(
                output_dir=retained,
                normalized_decisions=normalized_path,
                packet_dir=tmp_path,
                workers=8,
                resume=False,
                checkpoint_source_sha=None,
                checkpoint_workflow_run_id=None,
            )
        )
    assert sorted(calls["initial"]) == [f"T-{index:03d}" for index in range(1, 9)]

    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    assert (
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=tmp_path,
                normalized_decisions=normalized_path,
                retained_dir=retained,
                output_dir=checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id=run_id,
                require_complete=False,
            )
        )
        == 0
    )
    checkpoint_manifest = json.loads(
        (checkpoint / "checkpoint-manifest.json").read_text(encoding="utf-8")
    )
    assert checkpoint_manifest["verified_record_count"] == 7
    assert checkpoint_manifest["failure_records"][0]["truth_id"] == "T-001"

    phase = "resume"
    assert (
        author_pairs(
            SimpleNamespace(
                output_dir=checkpoint,
                normalized_decisions=normalized_path,
                packet_dir=tmp_path,
                workers=8,
                resume=True,
                checkpoint_source_sha=source_sha,
                checkpoint_workflow_run_id=run_id,
            )
        )
        == 0
    )

    assert set(calls["resume"]) == first_resume_batch | {"T-016"}
    assert not set(calls["resume"]) & {f"T-{index:03d}" for index in range(2, 9)}
    assert resume_max_active == 8
    completed = json.loads((checkpoint / "manifest.json").read_text(encoding="utf-8"))
    assert [record["truth_id"] for record in completed["records"]] == [
        f"T-{index:03d}" for index in range(1, 17)
    ]
    assert {
        record["truth_id"] for record in completed["records"] if record["status"] == "reused"
    } == {f"T-{index:03d}" for index in range(2, 9)}
    assert {
        record["truth_id"] for record in completed["records"] if record["status"] == "authored"
    } == first_resume_batch | {"T-016"}


@pytest.mark.parametrize("existing_state", ["incomplete", "invalid"])
def test_safe_pair_resume_rejects_bad_existing_pair_before_model_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_state: str,
) -> None:
    normalized_path = tmp_path / "normalized.json"
    _dump(normalized_path, {"records": []})
    output = tmp_path / "checkpoint"
    _dump(output / "checkpoint-manifest.json", {})
    _dump(output / "authors" / "T-001.json", {"truth_id": "T-001"})
    if existing_state == "invalid":
        _dump(output / "raw" / "T-001.json", {"truth_id": "T-001"})
    work = [
        ({"packet_sha256": f"{index:064x}"}, {"truth_id": f"T-{index:03d}"})
        for index in range(1, 10)
    ]

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.validate_normalized_decisions",
        lambda _: None,
    )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._confirmable_work",
        lambda *_, **__: work,
    )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._validate_author_checkpoint",
        lambda *_, **__: None,
    )
    if existing_state == "invalid":
        monkeypatch.setattr(
            "scripts.generate_range_v16_safe_pairs._validated_existing_author_pair",
            lambda *_, **__: (_ for _ in ()).throw(ValueError("invalid existing pair")),
        )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._author_one",
        lambda *_, **__: pytest.fail("bad existing pairs must fail before model calls"),
    )

    expected = "incomplete or unexpected" if existing_state == "incomplete" else "invalid existing"
    with pytest.raises(ValueError, match=expected):
        author_pairs(
            SimpleNamespace(
                output_dir=output,
                normalized_decisions=normalized_path,
                packet_dir=tmp_path,
                workers=8,
                resume=True,
                checkpoint_source_sha="a" * 40,
                checkpoint_workflow_run_id="33228930421",
            )
        )
    assert (output / "checkpoint-manifest.json").is_file()


def test_safe_pair_workers_one_and_eight_match_after_out_of_order_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized_path = tmp_path / "normalized.json"
    _dump(normalized_path, {"records": []})
    work = [
        ({"packet_sha256": f"{index:064x}"}, {"truth_id": f"T-{index:03d}"})
        for index in range(1, 17)
    ]
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    run_workers = 1
    completion_orders: dict[int, list[str]] = {1: [], 8: []}

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.validate_normalized_decisions",
        lambda _: None,
    )
    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs._confirmable_work",
        lambda *_, **__: work,
    )

    def fake_author(
        packet: dict,
        record: dict,
        **_: object,
    ) -> dict:
        truth_id = record["truth_id"]
        if run_workers == 8:
            barrier.wait(timeout=5)
            index = int(truth_id.rsplit("-", 1)[1])
            time.sleep((8 - (index % 8)) * 0.001)
        with lock:
            completion_orders[run_workers].append(truth_id)
        return {
            "truth_id": truth_id,
            "packet_sha256": packet["packet_sha256"],
            "status": "reviewed",
        }

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs._author_one", fake_author)
    manifests: list[dict] = []
    for workers in (1, 8):
        run_workers = workers
        output = tmp_path / f"author-{workers}"
        assert (
            author_pairs(
                SimpleNamespace(
                    output_dir=output,
                    normalized_decisions=normalized_path,
                    packet_dir=tmp_path,
                    workers=workers,
                    resume=False,
                    checkpoint_source_sha=None,
                    checkpoint_workflow_run_id=None,
                )
            )
            == 0
        )
        manifests.append(json.loads((output / "manifest.json").read_text(encoding="utf-8")))

    expected_ids = [f"T-{index:03d}" for index in range(1, 17)]
    assert completion_orders[1] == expected_ids
    assert completion_orders[8] != expected_ids
    assert manifests[0] == manifests[1]
    assert [record["truth_id"] for record in manifests[1]["records"]] == expected_ids


def test_safe_pair_author_cli_defaults_to_eight_workers(tmp_path: Path) -> None:
    args = _parser().parse_args(
        [
            "author",
            "--packet-dir",
            str(tmp_path / "packets"),
            "--normalized-decisions",
            str(tmp_path / "normalized.json"),
            "--output-dir",
            str(tmp_path / "author"),
        ]
    )

    assert args.workers == 8


def test_safe_pair_complete_checkpoint_requires_all_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    retained = tmp_path / "retained"
    checkpoint = tmp_path / "checkpoint"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    _dump(retained / "authors" / f"{record['truth_id']}.json", author)
    _dump(retained / "raw" / f"{record['truth_id']}.json", _raw_author(record, author))
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    source_sha = "a" * 40

    assert (
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=packet_dir,
                normalized_decisions=normalized_path,
                retained_dir=retained,
                output_dir=checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id="33228930421",
                require_complete=True,
            )
        )
        == 0
    )
    manifest = json.loads((checkpoint / "checkpoint-manifest.json").read_text(encoding="utf-8"))
    assert manifest["verified_record_count"] == manifest["expected_record_count"] == 1
    assert manifest["invalid_records"] == []
    assert manifest["incomplete_records"] == []
    assert manifest["failure_records"] == []


def test_safe_pair_complete_checkpoint_rejects_failure_residual(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    retained = tmp_path / "retained"
    checkpoint = tmp_path / "checkpoint"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    _dump(retained / "authors" / f"{record['truth_id']}.json", author)
    _dump(retained / "raw" / f"{record['truth_id']}.json", _raw_author(record, author))
    _write_failure_manifest(
        retained,
        normalized_sha256=sha256_file(normalized_path),
        expected_record_count=1,
        verified_record_count=1,
        failure_records=[
            {
                "truth_id": record["truth_id"],
                "failure_code": "author_contract_failure",
                "error_sha256": "7" * 64,
                "initial_exit_code": None,
                "initial_stdout_sha256": None,
                "initial_stdout_retained": False,
                "initial_stderr_sha256": None,
                "retry_exit_code": None,
                "retry_stdout_sha256": None,
                "retry_stdout_retained": False,
                "retry_stderr_sha256": None,
                "answer_material_present": False,
            }
        ],
    )
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    source_sha = "a" * 40

    with pytest.raises(
        ValueError,
        match="complete checkpoint requires every expected record to be verified",
    ):
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=packet_dir,
                normalized_decisions=normalized_path,
                retained_dir=retained,
                output_dir=checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id="33228930421",
                require_complete=True,
            )
        )

    assert not checkpoint.exists()


@pytest.mark.parametrize("retained_state", ["missing", "incomplete", "invalid"])
def test_safe_pair_complete_checkpoint_rejects_nonverified_records_without_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retained_state: str,
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    retained = tmp_path / "retained"
    checkpoint = tmp_path / "checkpoint"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    (retained / "authors").mkdir(parents=True)
    (retained / "raw").mkdir()
    if retained_state in {"incomplete", "invalid"}:
        author = _author(record)
        if retained_state == "invalid":
            author["packet_sha256"] = "f" * 64
        _dump(retained / "authors" / f"{record['truth_id']}.json", author)
    if retained_state == "invalid":
        _dump(retained / "raw" / f"{record['truth_id']}.json", _raw_author(record, author))
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    source_sha = "a" * 40

    with pytest.raises(
        ValueError,
        match="complete checkpoint requires every expected record to be verified",
    ):
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=packet_dir,
                normalized_decisions=normalized_path,
                retained_dir=retained,
                output_dir=checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id="33228930421",
                require_complete=True,
            )
        )

    assert not checkpoint.exists()


def test_safe_pair_checkpoint_allows_partial_without_complete_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    retained = tmp_path / "retained"
    checkpoint = tmp_path / "checkpoint"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    (retained / "authors").mkdir(parents=True)
    (retained / "raw").mkdir()
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    source_sha = "a" * 40

    assert (
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=packet_dir,
                normalized_decisions=normalized_path,
                retained_dir=retained,
                output_dir=checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id="33228930421",
            )
        )
        == 0
    )
    manifest = json.loads((checkpoint / "checkpoint-manifest.json").read_text(encoding="utf-8"))
    assert manifest["expected_record_count"] == 1
    assert manifest["verified_record_count"] == 0
    assert manifest["checkpoint_contains_author_material"] is False


def test_safe_pair_checkpoint_revalidates_and_resumes_without_model_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    retained = tmp_path / "retained"
    checkpoint = tmp_path / "checkpoint"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    _dump(retained / "authors" / f"{record['truth_id']}.json", author)
    _dump(retained / "raw" / f"{record['truth_id']}.json", _raw_author(record, author))
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    source_sha = "a" * 40
    run_id = "32862797901"

    assert (
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=packet_dir,
                normalized_decisions=normalized_path,
                retained_dir=retained,
                output_dir=checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id=run_id,
            )
        )
        == 0
    )
    checkpoint_manifest = json.loads(
        (checkpoint / "checkpoint-manifest.json").read_text(encoding="utf-8")
    )
    assert checkpoint_manifest["schema_version"] == AUTHOR_CHECKPOINT_SCHEMA_VERSION
    assert checkpoint_manifest["verified_record_count"] == 1
    assert checkpoint_manifest["checkpoint_contains_author_material"] is True

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("resume must not call the model"),
    )
    assert (
        author_pairs(
            SimpleNamespace(
                output_dir=checkpoint,
                normalized_decisions=normalized_path,
                packet_dir=packet_dir,
                workers=4,
                resume=True,
                checkpoint_source_sha=source_sha,
                checkpoint_workflow_run_id=run_id,
            )
        )
        == 0
    )
    completed = json.loads((checkpoint / "manifest.json").read_text(encoding="utf-8"))
    assert completed["record_count"] == 1
    assert completed["records"][0]["status"] == "reused"
    assert not (checkpoint / "checkpoint-manifest.json").exists()


def test_safe_pair_checkpoint_rebuilds_uploaded_checkpoint_after_provenance_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized-original.json"
    changed_normalized_path = tmp_path / "normalized-current.json"
    packet_dir = tmp_path / "packets"
    retained = tmp_path / "retained"
    uploaded_checkpoint = tmp_path / "uploaded-checkpoint"
    rebuilt_checkpoint = tmp_path / "rebuilt-checkpoint"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    _dump(retained / "authors" / f"{record['truth_id']}.json", author)
    _dump(retained / "raw" / f"{record['truth_id']}.json", _raw_author(record, author))
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    source_sha = "a" * 40
    run_id = "33037684216"

    assert (
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=packet_dir,
                normalized_decisions=normalized_path,
                retained_dir=retained,
                output_dir=uploaded_checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id=run_id,
            )
        )
        == 0
    )
    changed = json.loads(json.dumps(normalized))
    changed["review_provenance"]["artifact_digest"] = f"sha256:{'b' * 64}"
    unsigned = dict(changed)
    unsigned.pop("content_sha256")
    changed["content_sha256"] = sha256_value(unsigned)
    _dump(changed_normalized_path, changed)

    assert sha256_file(changed_normalized_path) != sha256_file(normalized_path)
    assert (
        build_author_checkpoint(
            SimpleNamespace(
                packet_dir=packet_dir,
                normalized_decisions=changed_normalized_path,
                retained_dir=uploaded_checkpoint,
                output_dir=rebuilt_checkpoint,
                packet_source_sha=source_sha,
                retained_source_sha=source_sha,
                workflow_run_id=run_id,
            )
        )
        == 0
    )
    rebuilt_manifest = json.loads(
        (rebuilt_checkpoint / "checkpoint-manifest.json").read_text(encoding="utf-8")
    )
    assert rebuilt_manifest["verified_record_count"] == 1
    assert rebuilt_manifest["invalid_records"] == []
    assert rebuilt_manifest["incomplete_records"] == []
    assert rebuilt_manifest["normalized_decisions_sha256"] == sha256_file(changed_normalized_path)


def test_safe_pair_author_anonymity_repair_gets_recomputed_constraints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["vulnerable_source"] += (
        f"/* project_specific_function {record['truth_id']} */\n"
        "int project_specific_function(void) { return 0; }\n"
    )
    invalid["fixed_or_near_miss_source"] += (
        f'const char *case_name = "{record["truth_id"]}";\n'
        "int project_specific_function(void) { return case_name[0]; }\n"
    )
    repaired = _author(record)
    responses = [invalid, repaired]
    prompts: list[str] = []
    schemas: list[dict] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        schemas.append(
            json.loads(
                (Path(str(kwargs["cwd"])) / "author-schema.json").read_text(encoding="utf-8")
            )
        )
        author = responses.pop(0)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(author),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(packet, record, output=tmp_path / "author", resume=False)
    assert result["status"] == "authored"
    assert len(prompts) == 2
    assert schemas[0] == schemas[1]
    assert schemas[0]["properties"]["truth_id"] == {
        "type": "string",
        "const": record["truth_id"],
    }
    assert schemas[0]["properties"]["packet_sha256"] == {
        "type": "string",
        "const": record["packet_sha256"],
        "pattern": "^[0-9a-f]{64}$",
    }
    assert schemas[0]["properties"]["final_decision_sha256"] == {
        "type": "string",
        "const": record["final_decision_sha256"],
        "pattern": "^[0-9a-f]{64}$",
    }
    assert "pattern" not in schemas[0]["properties"]["vulnerable_source"]
    source_pattern = _author_schema(
        _source_identifiers(packet, str(record["truth_id"])),
        truth_id=str(record["truth_id"]),
        packet_sha256=str(record["packet_sha256"]),
        final_decision_sha256=str(record["final_decision_sha256"]),
    )["properties"]["vulnerable_source"]["pattern"]
    assert not re.search(source_pattern, invalid["vulnerable_source"])
    assert not re.search(source_pattern, invalid["fixed_or_near_miss_source"])
    assert re.search(source_pattern, repaired["vulnerable_source"])
    assert re.search(source_pattern, repaired["fixed_or_near_miss_source"])
    assert '"validation_class": "source_not_anonymous"' in prompts[1]
    assert '"identifier_match": "exact_c_token_or_literal_non_identifier"' in prompts[1]
    assert '"project_specific_function"' in prompts[1]
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    conflicts = repair_request["deterministic_constraints"]["detected_conflicts_by_source_field"]
    assert conflicts == {
        "fixed_or_near_miss_source": [
            {
                "identifier": record["truth_id"],
                "match_count": 1,
                "match_kind": "literal_non_identifier",
            },
            {
                "identifier": "project_specific_function",
                "match_count": 1,
                "match_kind": "complete_c_token",
            },
        ],
        "vulnerable_source": [
            {
                "identifier": record["truth_id"],
                "match_count": 1,
                "match_kind": "literal_non_identifier",
            },
            {
                "identifier": "project_specific_function",
                "match_count": 2,
                "match_kind": "complete_c_token",
            },
        ],
    }
    assert (
        repair_request["deterministic_constraints"]["required_postcondition"]
        == "zero forbidden-identifier matches across the complete text of both source fields"
    )
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["accepted_attempt"] == 2
    assert raw["attempts"][0]["validation_class"] == "source_not_anonymous"
    assert raw["attempts"][1]["validation_class"] is None


def test_safe_pair_author_identical_source_repair_gets_behavioral_constraints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["fixed_or_near_miss_source"] = invalid["vulnerable_source"]
    repaired = _author(record)
    responses = [invalid, repaired]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(responses.pop(0)),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(packet, record, output=tmp_path / "author", resume=False)

    assert result["status"] == "authored"
    assert len(prompts) == 2
    repair_request = json.loads(prompts[1].split("REPAIR_REQUEST:\n", 1)[1])
    assert repair_request["validation_class"] == "sources_identical"
    constraints = repair_request["deterministic_constraints"]
    assert constraints["detected_condition"] == "sources_equal_after_newline_normalization"
    assert constraints["required_postcondition"] == (
        "vulnerable_source and fixed_or_near_miss_source have different C token projections "
        "after ignoring comments and whitespace"
    )
    assert "Rewrite only fixed_or_near_miss_source" in constraints["required_correction"]
    assert "safe_pair_recommendation" in constraints["required_correction"]
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["accepted_attempt"] == 2
    assert raw["attempts"][0]["validation_class"] == "sources_identical"
    assert raw["attempts"][1]["validation_class"] is None


def test_safe_pair_author_fails_closed_after_one_contract_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["vulnerable_source"] = "#include <stddef.h>\n" + invalid["vulnerable_source"]
    call_count = 0

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/codex",
    )

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(invalid),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="contract repair exhausted"):
        _author_one(packet, record, output=tmp_path / "author", resume=False)
    assert call_count == 2
    raw = json.loads(
        (tmp_path / "author" / "raw" / f"{record['truth_id']}.json").read_text(encoding="utf-8")
    )
    assert raw["accepted_attempt"] is None
    assert len(raw["attempts"]) == 2
    assert all(
        attempt["validation_class"] == "forbidden_c_facilities" for attempt in raw["attempts"]
    )


def test_materialize_pair_writes_only_bound_source_and_manifest(tmp_path: Path) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    author_dir = tmp_path / "author"
    output_dir = tmp_path / "pairs"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    author_path = author_dir / "authors" / f"{record['truth_id']}.json"
    raw_path = author_dir / "raw" / f"{record['truth_id']}.json"
    _dump(author_path, author)
    _dump(raw_path, _raw_author(record, author))
    author_records = [
        {
            "truth_id": record["truth_id"],
            "packet_sha256": record["packet_sha256"],
            "final_decision_sha256": record["final_decision_sha256"],
            "author_sha256": sha256_file(author_path),
            "raw_sha256": sha256_file(raw_path),
            "status": "authored",
        }
    ]
    _dump(
        author_dir / "manifest.json",
        {
            "schema_version": "zscope.range-v16-safe-pair-author-run.v1",
            "author_model": AUTHOR_MODEL,
            "record_count": 1,
            "normalized_decisions_sha256": sha256_file(normalized_path),
            "records": author_records,
            "content_sha256": sha256_value(author_records),
        },
    )
    args = SimpleNamespace(
        output_dir=output_dir,
        normalized_decisions=normalized_path,
        author_dir=author_dir,
        packet_dir=packet_dir,
        compiler="cc",
        compile=False,
    )
    assert materialize_pairs(args) == 0
    pair_root = output_dir / record["truth_id"]
    manifest = json.loads((pair_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["review_decision_sha256"] == record["final_decision_sha256"]
    assert (pair_root / "vulnerable" / "case.c").is_file()
    assert (pair_root / "fixed_or_near_miss" / "case.c").is_file()

    raw_path.write_text('{"tampered": true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        validate_author_run(
            author_root=author_dir,
            normalized_path=normalized_path,
            expected_records={record["truth_id"]: record},
            packet_dir=packet_dir,
        )


def test_safe_pair_run_rejects_enum_valid_recommendation_drift(tmp_path: Path) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    recommendation = record["final_decision"]["safe_pair_recommendation"]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    author_dir = tmp_path / "author"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    author["kind"] = "fixed" if recommendation["kind"] == "near_miss" else "near_miss"
    author["invariant_summary"] = "A different but nonempty invariant."
    author_path = author_dir / "authors" / f"{record['truth_id']}.json"
    raw_path = author_dir / "raw" / f"{record['truth_id']}.json"
    _dump(author_path, author)
    _dump(raw_path, _raw_author(record, author))
    records = [
        {
            "truth_id": record["truth_id"],
            "packet_sha256": record["packet_sha256"],
            "final_decision_sha256": record["final_decision_sha256"],
            "author_sha256": sha256_file(author_path),
            "raw_sha256": sha256_file(raw_path),
            "status": "authored",
        }
    ]
    _dump(
        author_dir / "manifest.json",
        {
            "schema_version": "zscope.range-v16-safe-pair-author-run.v1",
            "author_model": AUTHOR_MODEL,
            "record_count": 1,
            "normalized_decisions_sha256": sha256_file(normalized_path),
            "records": records,
            "content_sha256": sha256_value(records),
        },
    )

    with pytest.raises(ValueError, match="kind is invalid"):
        validate_author_run(
            author_root=author_dir,
            normalized_path=normalized_path,
            expected_records={record["truth_id"]: record},
            packet_dir=packet_dir,
        )


def test_safe_pair_run_rejects_untrusted_raw_command_envelope(tmp_path: Path) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    author_dir = tmp_path / "author"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    author_path = author_dir / "authors" / f"{record['truth_id']}.json"
    raw_path = author_dir / "raw" / f"{record['truth_id']}.json"
    _dump(author_path, author)
    raw = _raw_author(record, author)
    raw["command_identity"][3] = "gpt-5.6-sol-untrusted"
    _dump(raw_path, raw)
    author_records = [
        {
            "truth_id": record["truth_id"],
            "packet_sha256": record["packet_sha256"],
            "final_decision_sha256": record["final_decision_sha256"],
            "author_sha256": sha256_file(author_path),
            "raw_sha256": sha256_file(raw_path),
            "status": "authored",
        }
    ]
    _dump(
        author_dir / "manifest.json",
        {
            "schema_version": "zscope.range-v16-safe-pair-author-run.v1",
            "author_model": AUTHOR_MODEL,
            "record_count": 1,
            "normalized_decisions_sha256": sha256_file(normalized_path),
            "records": author_records,
            "content_sha256": sha256_value(author_records),
        },
    )
    with pytest.raises(ValueError, match="raw author envelope"):
        validate_author_run(
            author_root=author_dir,
            normalized_path=normalized_path,
            expected_records={record["truth_id"]: record},
            packet_dir=packet_dir,
        )


def test_safe_pair_run_rejects_unbound_anonymity_schema(tmp_path: Path) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    author_dir = tmp_path / "author"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    author_path = author_dir / "authors" / f"{record['truth_id']}.json"
    raw_path = author_dir / "raw" / f"{record['truth_id']}.json"
    _dump(author_path, author)
    raw = _raw_author(record, author)
    raw["output_schema_sha256"] = sha256_value(_author_schema())
    _dump(raw_path, raw)
    records = [
        {
            "truth_id": record["truth_id"],
            "packet_sha256": record["packet_sha256"],
            "final_decision_sha256": record["final_decision_sha256"],
            "author_sha256": sha256_file(author_path),
            "raw_sha256": sha256_file(raw_path),
            "status": "authored",
        }
    ]
    _dump(
        author_dir / "manifest.json",
        {
            "schema_version": "zscope.range-v16-safe-pair-author-run.v1",
            "author_model": AUTHOR_MODEL,
            "record_count": 1,
            "normalized_decisions_sha256": sha256_file(normalized_path),
            "records": records,
            "content_sha256": sha256_value(records),
        },
    )
    with pytest.raises(ValueError, match="raw author envelope"):
        validate_author_run(
            author_root=author_dir,
            normalized_path=normalized_path,
            expected_records={record["truth_id"]: record},
            packet_dir=packet_dir,
        )


def test_safe_pair_run_rejects_hidden_reasoning_body(tmp_path: Path) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    packet_dir = tmp_path / "packets"
    author_dir = tmp_path / "author"
    _dump(normalized_path, normalized)
    _dump(packet_dir / f"{record['truth_id']}.json", _packet(record))
    author = _author(record)
    author_path = author_dir / "authors" / f"{record['truth_id']}.json"
    raw_path = author_dir / "raw" / f"{record['truth_id']}.json"
    _dump(author_path, author)
    raw = _raw_author(record, author)
    hidden = dict(author)
    hidden["reasoning_content"] = "must not be retained"
    raw["attempts"][0]["stdout"] = json.dumps(hidden)
    _dump(raw_path, raw)
    records = [
        {
            "truth_id": record["truth_id"],
            "packet_sha256": record["packet_sha256"],
            "final_decision_sha256": record["final_decision_sha256"],
            "author_sha256": sha256_file(author_path),
            "raw_sha256": sha256_file(raw_path),
            "status": "authored",
        }
    ]
    _dump(
        author_dir / "manifest.json",
        {
            "schema_version": "zscope.range-v16-safe-pair-author-run.v1",
            "author_model": AUTHOR_MODEL,
            "record_count": 1,
            "normalized_decisions_sha256": sha256_file(normalized_path),
            "records": records,
            "content_sha256": sha256_value(records),
        },
    )
    with pytest.raises(ValueError, match="hidden reasoning"):
        validate_author_run(
            author_root=author_dir,
            normalized_path=normalized_path,
            expected_records={record["truth_id"]: record},
            packet_dir=packet_dir,
        )
