from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.e0_review_governance import sha256_file, sha256_value
from scripts.generate_range_v16_safe_pairs import (
    AUTHOR_MODEL,
    AUTHOR_SCHEMA_VERSION,
    RAW_AUTHOR_SCHEMA_VERSION,
    _author_one,
    _author_schema,
    _source_identifiers,
    materialize_pairs,
    validate_author_run,
    validate_author_record,
)
from tests.test_range_v16_truth import _normalized


def _dump(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _confirmable_normalized() -> dict:
    value = _normalized()
    record = value["records"][0]
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
    return {
        "packet_uid": f"range-v16:{truth_id}",
        "packet_sha256": record["packet_sha256"],
        "truth_record": {"id": truth_id, "function": "project_specific_function"},
    }


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
    return {
        "schema_version": RAW_AUTHOR_SCHEMA_VERSION,
        "truth_id": record["truth_id"],
        "packet_sha256": record["packet_sha256"],
        "final_decision_sha256": record["final_decision_sha256"],
        "author_model": AUTHOR_MODEL,
        "command_identity": [
            "claude",
            "--print",
            "--model",
            AUTHOR_MODEL,
            "--effort",
            "max",
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(_author_schema(), separators=(",", ":")),
            "--permission-mode",
            "plan",
            "--tools",
            "",
            "--no-session-persistence",
            "--disable-slash-commands",
        ],
        "attempts": [
            {
                "attempt": 1,
                "kind": "initial",
                "exit_code": 0,
                "stdout": json.dumps({"structured_output": author}),
                "stderr_sha256": sha256_value(""),
                "validation_class": None,
            }
        ],
        "accepted_attempt": 1,
    }


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
        lambda _: "/usr/bin/claude",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        author = responses.pop(0)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"structured_output": author}),
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
    _dump(normalized_path, normalized)
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
    ) == {record["truth_id"]: result}


def test_safe_pair_author_anonymity_repair_gets_recomputed_constraints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    packet = _packet(record)
    invalid = _author(record)
    invalid["vulnerable_source"] += "int project_specific_function(void) { return 0; }\n"
    repaired = _author(record)
    responses = [invalid, repaired]
    prompts: list[str] = []

    monkeypatch.setattr(
        "scripts.generate_range_v16_safe_pairs.shutil.which",
        lambda _: "/usr/bin/claude",
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompts.append(str(kwargs["input"]))
        author = responses.pop(0)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"structured_output": author}),
            stderr="",
        )

    monkeypatch.setattr("scripts.generate_range_v16_safe_pairs.subprocess.run", fake_run)
    result = _author_one(packet, record, output=tmp_path / "author", resume=False)
    assert result["status"] == "authored"
    assert len(prompts) == 2
    assert '"validation_class": "source_not_anonymous"' in prompts[1]
    assert '"identifier_match": "exact_c_token_or_literal_non_identifier"' in prompts[1]
    assert '"project_specific_function"' in prompts[1]
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
        lambda _: "/usr/bin/claude",
    )

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"structured_output": invalid}),
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
        )


def test_safe_pair_run_rejects_untrusted_raw_command_envelope(tmp_path: Path) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    author_dir = tmp_path / "author"
    _dump(normalized_path, normalized)
    author = _author(record)
    author_path = author_dir / "authors" / f"{record['truth_id']}.json"
    raw_path = author_dir / "raw" / f"{record['truth_id']}.json"
    _dump(author_path, author)
    raw = _raw_author(record, author)
    raw["command_identity"][3] = "claude-opus-untrusted"
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
        )


def test_safe_pair_run_rejects_hidden_reasoning_body(tmp_path: Path) -> None:
    normalized = _confirmable_normalized()
    record = normalized["records"][0]
    normalized_path = tmp_path / "normalized.json"
    author_dir = tmp_path / "author"
    _dump(normalized_path, normalized)
    author = _author(record)
    author_path = author_dir / "authors" / f"{record['truth_id']}.json"
    raw_path = author_dir / "raw" / f"{record['truth_id']}.json"
    _dump(author_path, author)
    raw = _raw_author(record, author)
    raw["attempts"][0]["stdout"] = json.dumps(
        {"structured_output": author, "reasoning_content": "must not be retained"}
    )
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
        )
