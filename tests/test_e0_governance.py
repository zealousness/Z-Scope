from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_e0_reviewers as reviewer_runner
from scripts import build_e0_attestation as attestation_builder
from scripts.check_benchmark_hygiene import _allowed as benchmark_asset_allowed

from scripts.e0_review_governance import (
    ATTESTATION_SCHEMA_VERSION,
    DECISION_SCHEMA_VERSION,
    E0GovernanceError,
    PACKET_SCHEMA_VERSION,
    attestation_content_sha256,
    sha256_value,
    validate_e0_attestation,
    validate_review_decision,
    validate_review_packet,
    validate_review_provenance,
)


def _packet() -> dict:
    packet = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "packet_uid": "range-v16:RANGE-001",
        "source_truth_sha256": "1" * 64,
        "truth_record": {"id": "RANGE-001", "category": "bounds"},
        "code_windows": [
            {
                "path": "src/example.c",
                "start_line": 1,
                "end_line": 2,
                "content": "void f(void) {}\nreturn;\n",
                "sha256": hashlib.sha256(b"void f(void) {}\nreturn;\n").hexdigest(),
            }
        ],
        "threat_assumptions": ["The public function can receive untrusted input."],
        "safe_pair_candidate": {"kind": "fixed"},
        "packet_sha256": "",
    }
    unsigned = dict(packet)
    unsigned.pop("packet_sha256")
    packet["packet_sha256"] = sha256_value(unsigned)
    return packet


def _decision(packet: dict) -> dict:
    return {
        "schema_version": DECISION_SCHEMA_VERSION,
        "packet_uid": packet["packet_uid"],
        "packet_sha256": packet["packet_sha256"],
        "reviewer_role": "primary_fable",
        "reviewer_model": "claude-fable-5",
        "contract_kind": "concrete_trigger",
        "disposition": "keep",
        "confidence": 0.9,
        "defect_taxonomy_id": "bounds",
        "cwe_ids": ["CWE-125"],
        "structured_anchors": [
            {
                "kind": "primary",
                "corrected": False,
                "file": "src/example.c",
                "function": "f",
                "start_line": 1,
                "end_line": 2,
            }
        ],
        "required_evidence_clauses": [
            {
                "clause_id": "path_exists",
                "predicate": "A path reaches the operation.",
                "evidence_refs": ["src/example.c:1-2"],
            }
        ],
        "evidence_refs": ["src/example.c:1"],
        "trigger_summary": "An unchecked path reaches the operation.",
        "threat_assumptions": ["The input is externally controllable."],
        "safe_pair_recommendation": {
            "kind": "fixed",
            "invariant_summary": "The path is guarded.",
            "vulnerable_summary": "The path is unguarded.",
            "safe_summary": "The path is guarded before use.",
            "compile_requirements": ["Compile as C11."],
        },
        "reason_codes": ["TRIGGER_PRESENT", "SAFE_PAIR_REQUIRED"],
    }


def test_confirmable_final_decision_requires_direct_trigger_evidence() -> None:
    packet = _packet()
    decision = _decision(packet)
    decision["evidence_refs"] = []
    with pytest.raises(
        ValueError, match="confirmable review decision requires direct trigger evidence"
    ):
        reviewer_runner.validate_decision_against_packet(
            decision,
            packet,
            require_resolvable_evidence=True,
        )

    decision["contract_kind"] = "pattern_model"
    reviewer_runner.validate_decision_against_packet(
        decision,
        packet,
        require_resolvable_evidence=True,
    )


def test_primary_review_still_rejects_noncanonical_supplied_evidence() -> None:
    packet = _packet()
    decision = _decision(packet)
    decision["evidence_refs"] = ["src/other.c:1"]
    with pytest.raises(ValueError, match="evidence ref is not canonical"):
        reviewer_runner.validate_decision_against_packet(
            decision,
            packet,
            require_resolvable_evidence=False,
        )


@pytest.mark.parametrize(
    "path",
    (
        "test/range/benchmark/v16/ground_truth.json",
        "test/range/benchmark/v16/reviews/normalized-decisions.json",
        "test/range/benchmark/v16/review-packets/RANGE-001.json",
        "test/range/benchmark/v16/pairs/RANGE-001/manifest.json",
        "test/range/benchmark/v16/pairs/RANGE-001/vulnerable/case.c",
        "test/range/benchmark/v16/pairs/RANGE-001/fixed_or_near_miss/case.c",
    ),
)
def test_benchmark_hygiene_allows_only_canonical_v16_assets(path: str) -> None:
    assert benchmark_asset_allowed(Path(path))


@pytest.mark.parametrize(
    "path",
    (
        "test/range/benchmark/v16/reviews/raw/RANGE-001.json",
        "test/range/benchmark/v16/review-packets/nested/RANGE-001.json",
        "test/range/benchmark/v16/pairs/RANGE-001/vulnerable/debug.log",
        "test/range/benchmark/v16/pairs/RANGE-001/extra.c",
        "test/range/benchmark/v16/reviewer-output.json",
    ),
)
def test_benchmark_hygiene_rejects_unbound_v16_assets(path: str) -> None:
    assert not benchmark_asset_allowed(Path(path))


def _attestation() -> dict:
    payload = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "issued_at": "2026-08-18T00:00:00+00:00",
        "workflow": {
            "path": ".github/workflows/range-v16-benchmark-v5-attestation.yml",
            "run_id": "123",
            "head_sha": "a" * 40,
            "environment": "sealed-benchmark",
        },
        "component_commits": {
            "governance": "b" * 40,
            "scorer": "c" * 40,
            "truth": "d" * 40,
        },
        "artifacts": {
            "truth_v16": "1" * 64,
            "truth_v16_content": "2" * 64,
            "truth_contract_manifest": "3" * 64,
            "truth_manifest": "4" * 64,
            "source_truth_v15": "c" * 64,
            "review_packet_catalog": "d" * 64,
            "review_packet_catalog_content": "e" * 64,
            "normalized_decisions": "f" * 64,
            "normalized_decisions_content": "0" * 64,
            "safe_pair_author_manifest": "1" * 64,
            "safe_pair_author_content": "2" * 64,
            "safe_pair_author_artifact": "3" * 64,
            "review_bundle": "5" * 64,
            "review_bundle_content": "6" * 64,
            "review_provenance": "7" * 64,
            "safe_pair_manifest": "8" * 64,
            "defect_taxonomy": "9" * 64,
            "benchmark_policy": "a" * 64,
            "scorer_bundle": "b" * 64,
        },
        "review_summary": {
            "record_count": 136,
            "dual_review_count": 136,
            "opus_review_count": 12,
            "disputed_opus_count": 9,
        },
        "invariants": {
            "matcher_v2_unchanged": True,
            "v15_read_only": True,
            "safe_units_cover_confirmable_truth": True,
            "scanner_answer_isolated": True,
            "raw_reviews_artifact_only": True,
            "product_runtime_unchanged": True,
        },
        "content_sha256": "",
    }
    payload["content_sha256"] = attestation_content_sha256(payload)
    return payload


def test_review_packet_and_decision_bind_exact_packet() -> None:
    packet = _packet()
    validate_review_packet(packet)
    validate_review_decision(
        _decision(packet),
        expected_packet_uid=packet["packet_uid"],
        expected_packet_sha256=packet["packet_sha256"],
        expected_role="primary_fable",
    )


def test_every_material_primary_difference_requires_arbitration() -> None:
    packet = _packet()
    left = _decision(packet)
    right = deepcopy(left)
    assert reviewer_runner.decision_disagreement_fields(left, right) == ()
    for field in reviewer_runner.MATERIAL_DECISION_FIELDS:
        changed = deepcopy(right)
        if field == "required_evidence_clauses":
            changed[field][0]["predicate"] = "A different evidence obligation."
        elif field == "safe_pair_recommendation":
            changed[field]["safe_summary"] = "A different safe behavior."
        elif isinstance(changed[field], list):
            changed[field] = [*changed[field], "different"]
        else:
            changed[field] = "different"
        assert field in reviewer_runner.decision_disagreement_fields(left, changed)


@pytest.mark.parametrize(
    "value",
    [
        {"candidate_uid": "secret"},
        {"notes": "copied from benchmark-artifacts/run/report.json"},
        {"nested": [{"text": "api_key=do-not-send"}]},
    ],
)
def test_review_packet_recursively_rejects_product_results_and_credentials(value: dict) -> None:
    packet = _packet()
    packet["safe_pair_candidate"] = value
    unsigned = dict(packet)
    unsigned.pop("packet_sha256")
    packet["packet_sha256"] = sha256_value(unsigned)
    with pytest.raises(E0GovernanceError):
        validate_review_packet(packet)


def test_review_packet_rejects_content_tampering() -> None:
    packet = _packet()
    packet["truth_record"]["category"] = "state_machine"
    with pytest.raises(E0GovernanceError, match="hash mismatch"):
        validate_review_packet(packet)


def test_review_packet_rejects_tampered_code_window_even_after_packet_rehash() -> None:
    packet = _packet()
    packet["code_windows"][0]["content"] = "void changed(void) {}\nreturn;\n"
    unsigned = dict(packet)
    unsigned.pop("packet_sha256")
    packet["packet_sha256"] = sha256_value(unsigned)
    with pytest.raises(E0GovernanceError, match="code window hash"):
        validate_review_packet(packet)


def test_e0_attestation_requires_external_workflow_identity_and_hash() -> None:
    payload = _attestation()
    validate_e0_attestation(payload, expected_workflow_run_id="123", expected_head_sha="a" * 40)
    with pytest.raises(E0GovernanceError, match="run ID"):
        validate_e0_attestation(
            payload,
            expected_workflow_run_id="self-asserted",
            expected_head_sha="a" * 40,
        )
    tampered = deepcopy(payload)
    tampered["invariants"]["matcher_v2_unchanged"] = False
    with pytest.raises(E0GovernanceError):
        validate_e0_attestation(
            tampered,
            expected_workflow_run_id="123",
            expected_head_sha="a" * 40,
        )
    malformed = deepcopy(payload)
    malformed["workflow"]["trusted"] = True
    malformed["content_sha256"] = attestation_content_sha256(malformed)
    with pytest.raises(E0GovernanceError, match="workflow identity"):
        validate_e0_attestation(
            malformed,
            expected_workflow_run_id="123",
            expected_head_sha="a" * 40,
        )
    malformed = deepcopy(payload)
    malformed["issued_at"] = "not-a-time"
    malformed["content_sha256"] = attestation_content_sha256(malformed)
    with pytest.raises(E0GovernanceError, match="issue time"):
        validate_e0_attestation(
            malformed,
            expected_workflow_run_id="123",
            expected_head_sha="a" * 40,
        )


def test_review_provenance_separates_workflow_and_packet_commits() -> None:
    provenance = {
        "schema_version": "zscope.range-v16-review-provenance.v1",
        "workflow_path": ".github/workflows/range-v16-review.yml",
        "workflow_run_id": 123,
        "workflow_head_sha": "a" * 40,
        "packet_source_sha": "b" * 40,
        "environment": "sealed-benchmark",
        "artifact_name": f"range-v16-reviewed-{'b' * 40}",
        "artifact_digest": f"sha256:{'c' * 64}",
        "packet_catalog_sha256": "d" * 64,
        "review_bundle_sha256": "e" * 64,
    }
    validate_review_provenance(
        provenance,
        expected_workflow_run_id="123",
        expected_workflow_head_sha="a" * 40,
        expected_packet_source_sha="b" * 40,
        expected_artifact_digest=f"sha256:{'c' * 64}",
    )
    provenance["workflow_head_sha"] = provenance["packet_source_sha"]
    with pytest.raises(E0GovernanceError, match="workflow head SHA"):
        validate_review_provenance(
            provenance,
            expected_workflow_head_sha="a" * 40,
        )


def test_protected_review_jobs_pin_reviewer_cli_versions() -> None:
    workflow = Path(".github/workflows/range-v16-review.yml").read_text(encoding="utf-8")
    assert workflow.count("claude --version | awk '{print $1}'") == 2
    assert workflow.count("dsh --version") == 2
    assert workflow.count('"2.1.233"') == 2
    assert workflow.count(f'"{reviewer_runner.DSH_VERSION}"') == 2


def test_protected_review_workflow_checkpoints_failures_and_revalidates_resume() -> None:
    workflow = Path(".github/workflows/range-v16-review.yml").read_text(encoding="utf-8")
    assert "fable_checkpoint_run_id:" in workflow
    assert "fable_checkpoint_source_sha:" in workflow
    assert "deepseek_checkpoint_run_id:" in workflow
    assert "deepseek_checkpoint_source_sha:" in workflow
    assert "fail-fast: false" in workflow
    assert "id: primary_review" in workflow
    assert "failure() && steps.primary_review.outcome == 'failure'" in workflow
    assert "${FABLE_CHECKPOINT_SOURCE_SHA:-$PACKET_SOURCE_SHA}" in workflow
    assert "${DEEPSEEK_CHECKPOINT_SOURCE_SHA:-$PACKET_SOURCE_SHA}" in workflow
    assert "scripts/run_e0_reviewers.py checkpoint" in workflow
    assert "range-v16-primary-checkpoint-${{ matrix.reviewer }}" in workflow

    recovery = Path(".github/workflows/range-v16-review-recover.yml").read_text(encoding="utf-8")
    freeze_index = recovery.index("Freeze retained primary workspace before checkout")
    checkout_index = recovery.index("uses: actions/checkout@v7")
    assert freeze_index < checkout_index
    assert "fable|deepseek" in recovery
    assert '--reviewer "$REVIEWER"' in recovery
    assert "runs-on: [self-hosted, linux, x64, zscope-sealed]" in recovery
    assert "environment: sealed-benchmark" in recovery
    assert "clean: false" in recovery
    assert "scripts/run_e0_reviewers.py checkpoint" in recovery


def test_review_command_identity_disables_claude_tools_and_binds_deepseek_patch() -> None:
    fable = ["claude", *reviewer_runner._claude_arguments("fable")]
    reviewer_runner._validate_command_identity(fable, reviewer="fable")
    without_tool_isolation = [value for index, value in enumerate(fable) if index not in {12, 13}]
    with pytest.raises(ValueError, match="Claude command identity"):
        reviewer_runner._validate_command_identity(without_tool_isolation, reviewer="fable")
    deepseek = [
        "dsh",
        "--profile",
        "headless",
        "--patch",
        f"<ephemeral-patch-sha256:{reviewer_runner._deepseek_patch_sha256()}>",
    ]
    reviewer_runner._validate_command_identity(deepseek, reviewer="deepseek")
    deepseek[-1] = "unbound.patch.yml"
    with pytest.raises(ValueError, match="DeepSeek command identity"):
        reviewer_runner._validate_command_identity(deepseek, reviewer="deepseek")


def test_deepseek_accepts_only_direct_json_or_one_exact_json_fence() -> None:
    direct = json.dumps({"status": "ok"})
    assert reviewer_runner._normalize_deepseek_json_artifact(direct) == direct

    fenced = '```json\n{"status":"ok"}\n```'
    assert reviewer_runner._normalize_deepseek_json_artifact(fenced) == '{"status":"ok"}'
    tight_fenced = '```json\n{"status":"ok"}```'
    assert reviewer_runner._normalize_deepseek_json_artifact(tight_fenced) == '{"status":"ok"}'
    unlabeled = '```\n{"status":"ok"}\n```'
    assert reviewer_runner._normalize_deepseek_json_artifact(unlabeled) == '{"status":"ok"}'

    rejected = [
        'Result:\n```json\n{"status":"ok"}\n```',
        '```json\n{"status":"ok"}\n```\nDone.',
        '```JSON\n{"status":"ok"}\n```',
        '```json\n{"status":"ok"}\n```\n```json\n{}\n```',
        "```json\nnot json\n```",
    ]
    for value in rejected:
        with pytest.raises(ValueError, match="not a JSON artifact"):
            reviewer_runner._normalize_deepseek_json_artifact(value)


def test_deepseek_fenced_json_still_rejects_hidden_reasoning() -> None:
    fenced = '```json\n{"hidden_reasoning":"do not retain"}\n```'
    with pytest.raises(ValueError, match="hidden reasoning"):
        reviewer_runner._validated_decision_from_stdout(fenced, reviewer="deepseek")


def test_deepseek_review_patch_uses_deepseek_provider_and_pins_model() -> None:
    patch = reviewer_runner._deepseek_patch_text()
    assert "    provider: deepseek\n" in patch
    assert "    model: deepseek-v4-pro-0813\n" in patch
    assert "    reasoningEffort: max\n" in patch
    assert "    provider: DeepSeek\n" not in patch
    assert "    provider: openai\n" not in patch
    assert "deepseek-official" not in patch


@pytest.mark.parametrize(
    ("reviewer", "role", "model"),
    (
        ("fable", "primary_fable", "claude-fable-5"),
        ("deepseek", "primary_deepseek", "deepseek-v4-pro-0813:max"),
    ),
)
def test_primary_reviewer_retries_one_transport_failure_and_binds_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reviewer: str,
    role: str,
    model: str,
) -> None:
    packet = _packet()
    expected = _decision(packet)
    expected["reviewer_role"] = role
    expected["reviewer_model"] = model
    results = iter(
        (
            SimpleNamespace(
                returncode=2,
                stdout="partial response",
                stderr="temporary provider error",
            ),
            SimpleNamespace(returncode=0, stdout=json.dumps(expected), stderr=""),
        )
    )
    calls: list[tuple[list[str], object]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((command, kwargs.get("input")))
        return next(results)

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer=reviewer,
        raw_output_path=raw_path,
    )

    assert decision == expected
    assert len(calls) == 2
    assert calls[0] == calls[1]
    assert raw["transport_retry"] == {
        "initial_exit_code": 2,
        "initial_stdout_sha256": sha256_value("partial response"),
        "initial_stdout_retained": False,
        "initial_stderr_sha256": sha256_value("temporary provider error"),
    }
    assert "partial response" not in json.dumps(raw)
    assert "temporary provider error" not in json.dumps(raw)

    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer=reviewer,
        decision_path=decision_path,
        raw_path=raw_path,
    )

    tampered = deepcopy(raw)
    tampered["transport_retry"]["initial_stderr_sha256"] = "invalid"
    raw_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="transport retry envelope"):
        reviewer_runner._validate_existing_primary(
            packet,
            reviewer=reviewer,
            decision_path=decision_path,
            raw_path=raw_path,
        )


@pytest.mark.parametrize("reviewer", ("fable", "deepseek"))
def test_primary_transport_retry_is_bounded_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reviewer: str
) -> None:
    packet = _packet()
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=2, stdout="", stderr="provider unavailable")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)

    with pytest.raises(
        reviewer_runner.E0GovernanceError,
        match=rf"{reviewer} reviewer failed",
    ):
        reviewer_runner._run_model(
            packet,
            reviewer=reviewer,
            raw_output_path=tmp_path / "raw.json",
        )

    assert len(calls) == 2
    assert calls[0] == calls[1]


def test_deepseek_format_retry_accepts_exact_fence_and_preserves_raw_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    expected = _decision(packet)
    expected["reviewer_role"] = "primary_deepseek"
    expected["reviewer_model"] = "deepseek-v4-pro-0813:max"
    fenced = f"```json\n{json.dumps(expected)}\n```"
    outputs = iter((f"Decision follows:\n{fenced}", fenced))
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="deepseek",
        raw_output_path=raw_path,
    )

    assert decision == expected
    assert len(calls) == 2
    assert raw["stdout"] == fenced
    assert raw["format_retry"]["original_stdout_retained"] is False
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="deepseek",
        decision_path=decision_path,
        raw_path=raw_path,
    )


def test_deepseek_uses_bounded_second_format_retry_without_accepting_prose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    expected = _decision(packet)
    expected["reviewer_role"] = "primary_deepseek"
    expected["reviewer_model"] = "deepseek-v4-pro-0813:max"
    fenced = f"```json\n{json.dumps(expected)}\n```"
    outputs = iter(
        (
            f"Decision follows:\n{fenced}",
            f"Here is the reformatted decision:\n{fenced}",
            fenced,
        )
    )
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="deepseek",
        raw_output_path=raw_path,
    )

    assert decision == expected
    assert len(calls) == 3
    assert "first non-whitespace character" in calls[1][-1]
    assert "previous formatting attempt" in calls[2][-1]
    assert raw["stdout"] == fenced
    assert raw["format_retry"]["original_stdout_retained"] is False
    assert raw["format_retry_second"]["original_stdout_retained"] is False
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="deepseek",
        decision_path=decision_path,
        raw_path=raw_path,
    )


def test_deepseek_format_retry_requires_strict_schema_before_stopping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    expected = _decision(packet)
    expected["reviewer_role"] = "primary_deepseek"
    expected["reviewer_model"] = "deepseek-v4-pro-0813:max"
    schema_invalid = deepcopy(expected)
    invalid_safe_pair = schema_invalid["safe_pair_recommendation"]
    invalid_safe_pair["invariant_sumary"] = invalid_safe_pair.pop("invariant_summary")
    invalid_safe_pair["vulnerable_sumary"] = invalid_safe_pair.pop("vulnerable_summary")
    invalid_safe_pair["safe_sumary"] = invalid_safe_pair.pop("safe_summary")
    fenced = f"```json\n{json.dumps(expected)}\n```"
    outputs = iter(
        (
            f"Decision follows:\n{fenced}",
            json.dumps(schema_invalid),
            fenced,
        )
    )
    calls: list[list[str]] = []
    feedbacks: list[dict[str, object]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(command)
        if len(calls) > 1:
            feedback_path = Path(str(kwargs["cwd"])) / "format-validation.json"
            feedbacks.append(json.loads(feedback_path.read_text(encoding="utf-8")))
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="deepseek",
        raw_output_path=raw_path,
    )

    assert decision == expected
    assert len(calls) == 3
    assert "format-validation.json" in calls[1][-1]
    assert feedbacks[0]["parsed_object"] is False
    assert feedbacks[1]["parsed_object"] is True
    assert feedbacks[1]["missing_top_level_fields"] == []
    assert feedbacks[1]["unexpected_top_level_fields"] == []
    assert feedbacks[1]["schema_shape_errors"] == [
        {
            "path": "$.safe_pair_recommendation",
            "expected_types": ["object"],
            "actual_type": "object",
            "missing_fields": [
                "invariant_summary",
                "safe_summary",
                "vulnerable_summary",
            ],
            "unexpected_fields": [
                "invariant_sumary",
                "safe_sumary",
                "vulnerable_sumary",
            ],
        }
    ]
    assert raw["stdout"] == fenced
    assert raw["format_retry"]["original_stdout_retained"] is False
    assert raw["format_retry_second"]["original_stdout_retained"] is False
    assert len(raw["format_retry"]["validation_feedback_sha256"]) == 64
    assert len(raw["format_retry_second"]["validation_feedback_sha256"]) == 64
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="deepseek",
        decision_path=decision_path,
        raw_path=raw_path,
    )

    tampered = deepcopy(raw)
    tampered["format_retry_second"]["validation_feedback_sha256"] = "invalid"
    raw_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="format retry envelope"):
        reviewer_runner._validate_existing_primary(
            packet,
            reviewer="deepseek",
            decision_path=decision_path,
            raw_path=raw_path,
        )


def test_deepseek_contract_regeneration_fails_closed_after_format_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    expected = _decision(packet)
    expected["reviewer_role"] = "primary_deepseek"
    expected["reviewer_model"] = "deepseek-v4-pro-0813:max"
    schema_invalid = dict(expected)
    schema_invalid["safe_pair_recomendation"] = schema_invalid.pop("safe_pair_recommendation")
    invalid_stdout = json.dumps(schema_invalid)
    outputs = iter(("not JSON", invalid_stdout, invalid_stdout, invalid_stdout))
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"

    with pytest.raises(
        reviewer_runner.E0GovernanceError,
        match="contract regeneration did not produce a valid decision",
    ):
        reviewer_runner._run_model(
            packet,
            reviewer="deepseek",
            raw_output_path=raw_path,
        )

    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    assert raw["stdout"] == invalid_stdout
    assert "format_retry" in raw
    assert "format_retry_second" in raw
    assert "contract_retry" in raw
    assert raw["contract_retry"]["mutable_material_fields"] == ["safe_pair_recommendation"]
    assert raw["contract_retry"]["preserved_substantive_projection_sha256"] == (
        sha256_value(
            reviewer_runner._contract_retry_locked_projection(
                schema_invalid,
                ["safe_pair_recommendation"],
            )
        )
    )
    assert len(calls) == 4


def test_deepseek_contract_regeneration_recovers_after_format_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    expected = _decision(packet)
    expected["reviewer_role"] = "primary_deepseek"
    expected["reviewer_model"] = "deepseek-v4-pro-0813:max"
    invalid = dict(expected)
    invalid["safe_pair_recomendation"] = invalid.pop("safe_pair_recommendation")
    outputs = iter(("not JSON", json.dumps(invalid), json.dumps(invalid), json.dumps(expected)))
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="deepseek",
        raw_output_path=raw_path,
    )

    assert decision == expected
    assert len(calls) == 4
    assert "format-validation.json" in calls[-1][-1]
    assert "prior-output.txt" in calls[-1][-1]
    assert raw["contract_retry"]["mutable_material_fields"] == ["safe_pair_recommendation"]
    assert raw["contract_retry"]["preserved_substantive_projection_sha256"] == (
        sha256_value(
            reviewer_runner._contract_retry_locked_projection(
                expected,
                ["safe_pair_recommendation"],
            )
        )
    )
    assert raw["contract_retry"]["original_stdout_retained"] is False
    assert raw["stdout"] == json.dumps(expected)
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="deepseek",
        decision_path=decision_path,
        raw_path=raw_path,
    )


def test_deepseek_contract_regeneration_locks_valid_material_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    expected = _decision(packet)
    expected["reviewer_role"] = "primary_deepseek"
    expected["reviewer_model"] = "deepseek-v4-pro-0813:max"
    invalid = dict(expected)
    invalid["safe_pair_recomendation"] = invalid.pop("safe_pair_recommendation")
    changed = deepcopy(expected)
    changed["confidence"] = 0.1
    outputs = iter(
        (
            "not JSON",
            json.dumps(invalid),
            json.dumps(invalid),
            json.dumps(changed),
        )
    )

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        del command
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    with pytest.raises(
        reviewer_runner.E0GovernanceError,
        match="contract regeneration changed substantive fields",
    ):
        reviewer_runner._run_model(
            packet,
            reviewer="deepseek",
            raw_output_path=tmp_path / "raw.json",
        )


def test_fable_contract_retry_corrects_only_frozen_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    invalid = _decision(packet)
    invalid["packet_sha256"] = "0" * 64
    corrected = deepcopy(invalid)
    corrected["packet_sha256"] = packet["packet_sha256"]
    outputs = iter((invalid, corrected))
    calls: list[dict[str, object]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        del command
        calls.append(kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"structured_output": next(outputs)}),
            stderr="",
        )

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="fable",
        raw_output_path=raw_path,
    )

    expected_projection = sha256_value(
        reviewer_runner._contract_retry_substantive_projection(corrected)
    )
    assert decision == corrected
    assert len(calls) == 2
    assert "correct only schema_version" in str(calls[1]["input"])
    assert raw["contract_retry"]["preserved_substantive_projection_sha256"] == (expected_projection)
    assert json.dumps(invalid) not in json.dumps(raw)
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="fable",
        decision_path=decision_path,
        raw_path=raw_path,
    )
    tampered = deepcopy(raw)
    tampered["contract_retry"]["preserved_substantive_projection_sha256"] = "0" * 64
    raw_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="contract retry envelope"):
        reviewer_runner._validate_existing_primary(
            packet,
            reviewer="fable",
            decision_path=decision_path,
            raw_path=raw_path,
        )


def test_fable_contract_retry_rejects_substantive_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    invalid = _decision(packet)
    invalid["packet_sha256"] = "0" * 64
    changed = deepcopy(invalid)
    changed["packet_sha256"] = packet["packet_sha256"]
    changed["confidence"] = 0.1
    outputs = iter((invalid, changed))

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        del command
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"structured_output": next(outputs)}),
            stderr="",
        )

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    with pytest.raises(
        reviewer_runner.E0GovernanceError,
        match="contract regeneration changed substantive fields",
    ):
        reviewer_runner._run_model(
            packet,
            reviewer="fable",
            raw_output_path=tmp_path / "raw.json",
        )


def test_deepseek_grounding_retry_preserves_substantive_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    original = _decision(packet)
    original["reviewer_role"] = "primary_deepseek"
    original["reviewer_model"] = "deepseek-v4-pro-0813:max"
    original["structured_anchors"].append(
        {
            "kind": "secondary",
            "corrected": True,
            "file": "src/example.c",
            "function": "not_in_the_supplied_window",
            "start_line": 1,
            "end_line": 1,
        }
    )
    corrected = deepcopy(original)
    corrected["structured_anchors"][1]["function"] = "f"
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        decision = original if len(calls) == 1 else corrected
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(decision),
            stderr="",
        )

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="deepseek",
        raw_output_path=raw_path,
    )

    assert decision == corrected
    assert len(calls) == 2
    assert "failed deterministic packet grounding" in calls[1][-1]
    retry = raw["semantic_retry"]
    assert retry["exit_code"] == 0
    assert retry["original_stdout_retained"] is False
    assert retry["substantive_projection_sha256"] == sha256_value(
        reviewer_runner._semantic_retry_substantive_projection(corrected)
    )
    assert raw["stdout"] == json.dumps(corrected)
    assert json.dumps(original) not in json.dumps(raw)

    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(corrected), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="deepseek",
        decision_path=decision_path,
        raw_path=raw_path,
    )
    valid_raw = json.loads(raw_path.read_text(encoding="utf-8"))
    mismatched = deepcopy(valid_raw)
    mismatched_stdout = json.loads(mismatched["stdout"])
    mismatched_stdout["confidence"] = 0.7
    mismatched["stdout"] = json.dumps(mismatched_stdout)
    raw_path.write_text(json.dumps(mismatched), encoding="utf-8")
    with pytest.raises(ValueError, match="raw review output does not match"):
        reviewer_runner._validate_existing_primary(
            packet,
            reviewer="deepseek",
            decision_path=decision_path,
            raw_path=raw_path,
        )

    tampered = deepcopy(valid_raw)
    tampered["semantic_retry"]["substantive_projection_sha256"] = "0" * 64
    raw_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="semantic retry envelope"):
        reviewer_runner._validate_existing_primary(
            packet,
            reviewer="deepseek",
            decision_path=decision_path,
            raw_path=raw_path,
        )


def test_deepseek_grounding_format_retry_recovers_without_new_material_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    original = _decision(packet)
    original["reviewer_role"] = "primary_deepseek"
    original["reviewer_model"] = "deepseek-v4-pro-0813:max"
    original["evidence_refs"] = ["src/example.c:3"]
    corrected = deepcopy(original)
    corrected["evidence_refs"] = ["src/example.c:1"]
    outputs = iter((json.dumps(original), "not JSON", json.dumps(corrected)))
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="deepseek",
        raw_output_path=raw_path,
    )

    assert decision == corrected
    assert len(calls) == 3
    assert "format-validation.json" in calls[-1][-1]
    assert "prior-output.txt" in calls[-1][-1]
    retry = raw["semantic_format_retry"]
    assert retry["original_stdout_retained"] is False
    assert retry["substantive_projection_sha256"] == sha256_value(
        reviewer_runner._semantic_retry_substantive_projection(corrected)
    )
    assert "semantic_format_retry_second" not in raw

    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="deepseek",
        decision_path=decision_path,
        raw_path=raw_path,
    )
    tampered = deepcopy(raw)
    tampered["semantic_format_retry"]["substantive_projection_sha256"] = "0" * 64
    raw_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="semantic format retry envelope"):
        reviewer_runner._validate_existing_primary(
            packet,
            reviewer="deepseek",
            decision_path=decision_path,
            raw_path=raw_path,
        )


def test_deepseek_grounding_format_retry_rejects_material_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    original = _decision(packet)
    original["reviewer_role"] = "primary_deepseek"
    original["reviewer_model"] = "deepseek-v4-pro-0813:max"
    original["evidence_refs"] = ["src/example.c:3"]
    changed = deepcopy(original)
    changed["evidence_refs"] = ["src/example.c:1"]
    changed["confidence"] = 0.1
    outputs = iter((json.dumps(original), "not JSON", json.dumps(changed)))

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        del command
        return SimpleNamespace(returncode=0, stdout=next(outputs), stderr="")

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    with pytest.raises(
        reviewer_runner.E0GovernanceError,
        match="grounding-only retry changed substantive fields",
    ):
        reviewer_runner._run_model(
            packet,
            reviewer="deepseek",
            raw_output_path=tmp_path / "raw.json",
        )


def test_deepseek_grounding_contract_retry_corrects_only_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    original = _decision(packet)
    original["reviewer_role"] = "primary_deepseek"
    original["reviewer_model"] = "deepseek-v4-pro-0813:max"
    original["evidence_refs"] = ["src/example.c:3"]
    grounded_with_bad_identity = deepcopy(original)
    grounded_with_bad_identity["evidence_refs"] = ["src/example.c:1"]
    grounded_with_bad_identity["packet_sha256"] = "0" * 64
    corrected = deepcopy(grounded_with_bad_identity)
    corrected["packet_sha256"] = packet["packet_sha256"]
    outputs = iter((original, grounded_with_bad_identity, corrected))
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(next(outputs)),
            stderr="",
        )

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / "raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer="deepseek",
        raw_output_path=raw_path,
    )

    assert decision == corrected
    assert len(calls) == 3
    assert "prior-output.txt" in calls[-1][-1]
    retry = raw["semantic_contract_retry"]
    assert retry["original_stdout_retained"] is False
    assert retry["substantive_projection_sha256"] == sha256_value(
        reviewer_runner._contract_retry_substantive_projection(corrected)
    )
    assert raw["stdout"] == json.dumps(corrected)
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer="deepseek",
        decision_path=decision_path,
        raw_path=raw_path,
    )
    tampered = deepcopy(raw)
    tampered["semantic_contract_retry"]["validation_feedback_sha256"] = "invalid"
    raw_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="semantic contract retry envelope"):
        reviewer_runner._validate_existing_primary(
            packet,
            reviewer="deepseek",
            decision_path=decision_path,
            raw_path=raw_path,
        )


@pytest.mark.parametrize(
    ("reviewer", "role", "model"),
    (
        ("fable", "primary_fable", "claude-fable-5"),
        ("opus", "arbiter_opus", "claude-opus-5"),
    ),
)
def test_claude_grounding_retry_preserves_substantive_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reviewer: str,
    role: str,
    model: str,
) -> None:
    packet = _packet()
    original = _decision(packet)
    original["reviewer_role"] = role
    original["reviewer_model"] = model
    original["evidence_refs"] = ["src/example.c:3"]
    corrected = deepcopy(original)
    corrected["evidence_refs"] = ["src/example.c:1"]
    outputs = iter((original, corrected))
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((command, kwargs))
        decision = next(outputs)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"structured_output": decision}),
            stderr="",
        )

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    raw_path = tmp_path / f"{reviewer}-raw.json"
    decision, raw = reviewer_runner._run_model(
        packet,
        reviewer=reviewer,
        primary_decisions=(_decision(packet), _decision(packet)) if reviewer == "opus" else (),
        raw_output_path=raw_path,
    )

    assert decision == corrected
    assert len(calls) == 2
    claude_name = "claude.cmd" if reviewer_runner.os.name == "nt" else "claude"
    assert calls[1][0] == [f"/bin/{claude_name}", *reviewer_runner._claude_arguments(reviewer)]
    retry_prompt = str(calls[1][1]["input"])
    assert "failed deterministic packet grounding" in retry_prompt
    assert "PRIOR_DECISION:\n" in retry_prompt
    assert "PACKET:\n" in retry_prompt
    assert "Read prior-output.txt" not in retry_prompt
    assert raw["semantic_retry"]["substantive_projection_sha256"] == sha256_value(
        reviewer_runner._semantic_retry_substantive_projection(corrected)
    )
    assert raw["stdout"] == json.dumps({"structured_output": corrected})

    decision_path = tmp_path / f"{reviewer}-decision.json"
    decision_path.write_text(json.dumps(corrected), encoding="utf-8")
    reviewer_runner._validate_existing_primary(
        packet,
        reviewer=reviewer,
        decision_path=decision_path,
        raw_path=raw_path,
    )


def test_fable_grounding_retry_rejects_substantive_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    original = _decision(packet)
    original["evidence_refs"] = ["src/example.c:3"]
    changed = deepcopy(original)
    changed["evidence_refs"] = ["src/example.c:1"]
    changed["confidence"] = 0.8
    outputs = iter((original, changed))

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        del command
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"structured_output": next(outputs)}),
            stderr="",
        )

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="changed substantive fields"):
        reviewer_runner._run_model(
            packet,
            reviewer="fable",
            raw_output_path=tmp_path / "raw.json",
        )


def test_primary_failure_identifies_reviewer_and_packet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "fable"
    (output / "decisions").mkdir(parents=True)
    (output / "raw").mkdir()

    def fail_review(*_: object, **__: object) -> tuple[dict, dict]:
        raise E0GovernanceError("grounding failed")

    monkeypatch.setattr(reviewer_runner, "_run_model", fail_review)
    with pytest.raises(
        ValueError,
        match="fable review failed for RANGE-001: grounding failed",
    ):
        reviewer_runner._run_primary_packet(
            _packet(),
            reviewer="fable",
            output=output,
            resume=False,
        )
    failure = json.loads((output / "failures" / "RANGE-001.json").read_text(encoding="utf-8"))
    assert failure["failure_code"] == "grounding_validation_failure"
    assert failure["answer_material_present"] is False
    assert failure["decision_file_sha256"] is None
    assert failure["raw_file_sha256"] is None
    assert failure["content_sha256"] == reviewer_runner._checkpoint_manifest_content_sha256(failure)


@pytest.mark.parametrize(
    ("message", "expected"),
    (
        (
            "deepseek contract regeneration did not produce a valid decision",
            "contract_retry_validation_failure",
        ),
        (
            "fable contract regeneration changed substantive fields",
            "contract_retry_substantive_change",
        ),
        (
            "deepseek grounding contract retry remained invalid",
            "grounding_contract_retry_validation_failure",
        ),
        (
            "deepseek grounding contract retry changed material fields",
            "grounding_contract_retry_substantive_change",
        ),
        (
            "deepseek grounding format retry failed",
            "grounding_format_retry_process_nonzero",
        ),
        (
            "deepseek grounding format retries did not produce a valid decision",
            "grounding_format_retry_validation_failure",
        ),
    ),
)
def test_primary_failure_classifies_contract_retry_without_answer_material(
    message: str, expected: str
) -> None:
    assert reviewer_runner._primary_failure_code(message) == expected


def test_primary_checkpoint_copies_only_verified_pairs_and_binds_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet_dir = tmp_path / "packets"
    retained = tmp_path / "retained"
    output = tmp_path / "checkpoint"
    packet_dir.mkdir()
    (retained / "decisions").mkdir(parents=True)
    (retained / "raw").mkdir()
    packets: list[dict] = []
    for index in range(136):
        packet = _packet()
        truth_id = f"CASE-{index:03d}"
        packet["packet_uid"] = f"range-v16:{truth_id}"
        packet["truth_record"]["id"] = truth_id
        unsigned = dict(packet)
        unsigned.pop("packet_sha256")
        packet["packet_sha256"] = sha256_value(unsigned)
        packets.append(packet)
        (packet_dir / f"{truth_id}.json").write_text(json.dumps(packet), encoding="utf-8")

    def deepseek_pair(packet: dict) -> tuple[dict, dict]:
        decision = _decision(packet)
        decision["packet_uid"] = packet["packet_uid"]
        decision["packet_sha256"] = packet["packet_sha256"]
        decision["reviewer_role"] = "primary_deepseek"
        decision["reviewer_model"] = "deepseek-v4-pro-0813:max"
        raw = {
            "schema_version": "zscope.range-v16-review-raw-envelope.v1",
            "reviewer_role": "primary_deepseek",
            "reviewer_model": "deepseek-v4-pro-0813:max",
            "packet_uid": packet["packet_uid"],
            "packet_sha256": packet["packet_sha256"],
            "input_delivery": "isolated_files",
            "command_identity": [
                "dsh",
                "--profile",
                "headless",
                "--patch",
                f"<ephemeral-patch-sha256:{reviewer_runner._deepseek_patch_sha256()}>",
            ],
            "exit_code": 0,
            "stdout": json.dumps(decision),
            "stderr_sha256": sha256_value(""),
        }
        return decision, raw

    valid_decision, valid_raw = deepseek_pair(packets[0])
    (retained / "decisions" / "CASE-000.json").write_text(
        json.dumps(valid_decision), encoding="utf-8"
    )
    (retained / "raw" / "CASE-000.json").write_text(json.dumps(valid_raw), encoding="utf-8")

    _, orphan_raw = deepseek_pair(packets[1])
    orphan_raw["stdout"] = "schema-invalid output"
    orphan_raw["format_retry"] = {
        "exit_code": 2,
        "original_stdout_sha256": sha256_value("earlier output"),
        "original_stdout_retained": False,
        "stderr_sha256": sha256_value("provider error"),
    }
    orphan_raw["contract_retry"] = {
        "exit_code": 0,
    }
    (retained / "raw" / "CASE-001.json").write_text(json.dumps(orphan_raw), encoding="utf-8")

    invalid_decision, invalid_raw = deepseek_pair(packets[2])
    invalid_decision["packet_uid"] = "range-v16:WRONG"
    (retained / "decisions" / "CASE-002.json").write_text(
        json.dumps(invalid_decision), encoding="utf-8"
    )
    (retained / "raw" / "CASE-002.json").write_text(json.dumps(invalid_raw), encoding="utf-8")
    failure_marker = reviewer_runner._primary_failure_marker(
        packets[3],
        reviewer="deepseek",
        exc=E0GovernanceError(
            "deepseek reviewer failed for range-v16:CASE-003; " f"stderr_sha256={'6' * 64}"
        ),
        decision_path=retained / "decisions" / "CASE-003.json",
        raw_path=retained / "raw" / "CASE-003.json",
    )
    reviewer_runner._json_dump(
        retained / "failures" / "CASE-003.json",
        failure_marker,
    )

    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    args = SimpleNamespace(
        reviewer="deepseek",
        packet_dir=packet_dir,
        retained_dir=retained,
        output_dir=output,
        packet_source_sha="a" * 40,
        retained_source_sha="b" * 40,
        workflow_run_id="32367751336",
        workers=4,
    )
    assert reviewer_runner.build_primary_checkpoint(args) == 0

    manifest_path = output / "checkpoint-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["verified_record_count"] == 1
    assert manifest["incomplete_pair_count"] == 1
    assert manifest["invalid_pair_count"] == 1
    assert manifest["missing_pair_count"] == 133
    assert manifest["failure_record_count"] == 1
    assert manifest["failure_records"][0]["failure_code"] == "reviewer_process_nonzero"
    assert manifest["failure_records"][0]["stderr_sha256"] == "6" * 64
    assert manifest["first_unverified_batch_ids"] == [
        "CASE-001",
        "CASE-002",
        "CASE-003",
        "CASE-004",
    ]
    assert manifest["incomplete_records"] == [
        {
            "truth_id": "CASE-001",
            "present_files": ["raw"],
            "raw_signals": {
                "raw_envelope_status": "parsed_object",
                "top_level_exit_code": 0,
                "retry_stages": [
                    {"stage": "format_retry", "exit_code": 2},
                    {"stage": "contract_retry", "exit_code": 0},
                ],
            },
        }
    ]
    assert sorted(path.name for path in (output / "decisions").iterdir()) == ["CASE-000.json"]
    assert sorted(path.name for path in (output / "raw").iterdir()) == ["CASE-000.json"]
    reviewer_runner._validate_primary_checkpoint(
        output,
        reviewer="deepseek",
        packet_source_sha="a" * 40,
        packets=packets,
    )

    manifest["content_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint manifest is invalid"):
        reviewer_runner._validate_primary_checkpoint(
            output,
            reviewer="deepseek",
            packet_source_sha="a" * 40,
            packets=packets,
        )


def test_deepseek_grounding_retry_rejects_substantive_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet()
    original = _decision(packet)
    original["reviewer_role"] = "primary_deepseek"
    original["reviewer_model"] = "deepseek-v4-pro-0813:max"
    original["structured_anchors"][0]["function"] = "not_in_the_supplied_window"
    changed = deepcopy(original)
    changed["structured_anchors"][0]["function"] = "f"
    changed["confidence"] = 0.8
    outputs = iter((original, changed))

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        del command
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(next(outputs)),
            stderr="",
        )

    monkeypatch.setattr(reviewer_runner.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(reviewer_runner.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="changed substantive fields"):
        reviewer_runner._run_model(
            packet,
            reviewer="deepseek",
            raw_output_path=tmp_path / "raw.json",
        )


def test_e0_attestation_scorer_bundle_binds_exact_dependency_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative_paths = {
        "scripts/score.py",
        "zscope/benchmarking/matcher.py",
    }
    paths = []
    for relative in sorted(relative_paths):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative, encoding="utf-8")
        paths.append(path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(attestation_builder, "_SCORER_BUNDLE_PATHS", relative_paths)
    original = attestation_builder._scorer_bundle_sha256(paths)
    paths[0].write_text("changed", encoding="utf-8")
    assert attestation_builder._scorer_bundle_sha256(paths) != original
    with pytest.raises(ValueError, match="fixed v5 dependency set"):
        attestation_builder._scorer_bundle_sha256(paths[:1])


def test_primary_reviewer_resume_reuses_verified_outputs_and_finishes_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet_dir = tmp_path / "packets"
    output_dir = tmp_path / "output"
    packet_dir.mkdir()
    (output_dir / "decisions").mkdir(parents=True)
    (output_dir / "raw").mkdir()
    packets: list[dict] = []
    for index in range(136):
        packet = _packet()
        truth_id = f"CASE-{index:03d}"
        packet["packet_uid"] = f"range-v16:{truth_id}"
        packet["truth_record"]["id"] = truth_id
        unsigned = dict(packet)
        unsigned.pop("packet_sha256")
        packet["packet_sha256"] = sha256_value(unsigned)
        packets.append(packet)
        (packet_dir / f"{truth_id}.json").write_text(json.dumps(packet), encoding="utf-8")

    def raw_for(packet: dict) -> dict:
        decision = _decision(packet)
        decision["packet_uid"] = packet["packet_uid"]
        decision["packet_sha256"] = packet["packet_sha256"]
        return {
            "schema_version": "zscope.range-v16-review-raw-envelope.v1",
            "reviewer_role": "primary_fable",
            "reviewer_model": "claude-fable-5",
            "packet_uid": packet["packet_uid"],
            "packet_sha256": packet["packet_sha256"],
            "input_delivery": "embedded_prompt",
            "command_identity": ["claude", *reviewer_runner._claude_arguments("fable")],
            "exit_code": 0,
            "stdout": json.dumps({"structured_output": decision}),
            "stderr_sha256": sha256_value(""),
        }

    first = packets[0]
    first_decision = _decision(first)
    first_decision["packet_uid"] = first["packet_uid"]
    first_decision["packet_sha256"] = first["packet_sha256"]
    (output_dir / "decisions" / "CASE-000.json").write_text(
        json.dumps(first_decision), encoding="utf-8"
    )
    (output_dir / "raw" / "CASE-000.json").write_text(json.dumps(raw_for(first)), encoding="utf-8")

    reviewed: list[str] = []

    def fake_run_model(packet: dict, **_: object) -> tuple[dict, dict]:
        reviewed.append(packet["packet_uid"])
        decision = _decision(packet)
        decision["packet_uid"] = packet["packet_uid"]
        decision["packet_sha256"] = packet["packet_sha256"]
        return decision, raw_for(packet)

    monkeypatch.setattr(reviewer_runner, "_run_model", fake_run_model)
    args = SimpleNamespace(
        packet_dir=packet_dir,
        output_dir=output_dir,
        reviewer="fable",
        workers=4,
        resume=True,
    )
    assert reviewer_runner.run_primary(args) == 0
    assert len(reviewed) == 135
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["record_count"] == 136
    assert len(manifest["records"]) == 136
    assert manifest["records"][0]["status"] == "reused"
