from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.e0_review_governance import PACKET_SCHEMA_VERSION, sha256_file, sha256_value
from scripts.generate_range_v16_safe_pairs import (
    AUTHOR_CHECKPOINT_SCHEMA_VERSION,
    AUTHOR_FAILURE_SCHEMA_VERSION,
    AUTHOR_MODEL,
    AUTHOR_SCHEMA_VERSION,
    RAW_AUTHOR_SCHEMA_VERSION,
    _author_one,
    _author_schema,
    _source_identifiers,
    author_pairs,
    build_author_checkpoint,
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


def test_safe_pair_batch_collects_completed_futures_before_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized_path = tmp_path / "normalized.json"
    _dump(normalized_path, {"records": []})
    work = [
        ({"packet_sha256": str(index) * 64}, {"truth_id": f"T-{index:03d}"})
        for index in range(1, 5)
    ]
    calls: list[str] = []

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
        truth_id = record["truth_id"]
        calls.append(truth_id)
        if truth_id == "T-001":
            raise ValueError("synthetic failure")
        return {"truth_id": truth_id}

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs._author_one", fake_author)
    args = SimpleNamespace(
        output_dir=tmp_path / "author",
        normalized_decisions=normalized_path,
        packet_dir=tmp_path,
        workers=4,
        resume=False,
        checkpoint_source_sha=None,
        checkpoint_workflow_run_id=None,
    )
    with pytest.raises(ValueError, match="failure_count=1"):
        author_pairs(args)

    assert sorted(calls) == ["T-001", "T-002", "T-003", "T-004"]
    failure = json.loads(
        (tmp_path / "author" / "failure-manifest.json").read_text(encoding="utf-8")
    )
    assert failure["schema_version"] == AUTHOR_FAILURE_SCHEMA_VERSION
    assert failure["verified_record_count"] == 3
    assert failure["failure_record_count"] == 1
    assert failure["failure_records"][0]["answer_material_present"] is False


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
