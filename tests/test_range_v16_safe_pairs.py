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

from scripts.e0_review_governance import PACKET_SCHEMA_VERSION, sha256_file, sha256_value
from scripts.generate_range_v16_safe_pairs import (
    AUTHOR_CHECKPOINT_SCHEMA_VERSION,
    AUTHOR_DIAGNOSTIC_SCHEMA_VERSION,
    AUTHOR_FAILURE_SCHEMA_VERSION,
    AUTHOR_MODEL,
    AUTHOR_REQUEST_SCHEMA_VERSION,
    AUTHOR_SCHEMA_VERSION,
    RAW_AUTHOR_SCHEMA_VERSION,
    _author_one,
    _author_request,
    _author_schema,
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
    return {
        "schema_version": AUTHOR_SCHEMA_VERSION,
        "truth_id": record["truth_id"],
        "packet_sha256": record["packet_sha256"],
        "final_decision_sha256": record["final_decision_sha256"],
        "author_role": "safe_pair_author",
        "author_model": AUTHOR_MODEL,
        "kind": "fixed",
        "invariant_summary": "A length must be checked before an indexed read.",
        "vulnerable_source": (
            "int read_item(const int *p, int n) { (void)n; return p[1]; }\n"
            "int main(void) { int a[1] = {0}; return read_item(a, 1); }\n"
        ),
        "fixed_or_near_miss_source": (
            "int read_item(const int *p, int n) { return n > 1 ? p[1] : 0; }\n"
            "int main(void) { int a[1] = {0}; return read_item(a, 1); }\n"
        ),
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


def test_safe_pair_checkpoint_diagnostic_projects_only_fixed_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    assert diagnostic["verified_record_count"] == 1
    assert diagnostic["incomplete_record_count"] == 1
    assert diagnostic["failure_record_count"] == 1
    assert diagnostic["diagnostic_answer_material_present"] is False
    serialized = json.dumps(diagnostic)
    assert "CASE-FAILURE-SECRET" not in serialized
    assert "CASE-VERIFIED-SECRET" not in serialized
    assert "7" * 64 not in serialized


def test_safe_pair_checkpoint_diagnostic_projects_fixed_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    )
    author["vulnerable_source"] += "int project_specific_function(void) { return 0; }\n"
    with pytest.raises(ValueError, match="not anonymous"):
        validate_author_record(
            author,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers={"project_specific_function", record["truth_id"]},
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
        )


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
    )

    author["vulnerable_source"] += "int project_entry(void) { return 0; }\n"
    with pytest.raises(ValueError, match="not anonymous"):
        validate_author_record(
            author,
            truth_id=record["truth_id"],
            packet_sha256=record["packet_sha256"],
            final_decision_sha256=record["final_decision_sha256"],
            forbidden_identifiers={"project_entry", record["truth_id"]},
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
    schema = _author_schema(
        {"project_entry", str(record["truth_id"])},
        truth_id=str(record["truth_id"]),
        packet_sha256=str(record["packet_sha256"]),
        final_decision_sha256=str(record["final_decision_sha256"]),
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

    with pytest.raises(ValueError, match="identity must be fully bound"):
        _author_schema({"project_entry"}, truth_id=str(record["truth_id"]))


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
        "vulnerable_source and fixed_or_near_miss_source differ after normalizing CRLF and CR "
        "newlines to LF"
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
