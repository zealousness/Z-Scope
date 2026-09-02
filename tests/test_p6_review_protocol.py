import hashlib
import json
from pathlib import Path

import pytest

from zscope.benchmarking import p6_review
from zscope.benchmarking.p6_protocol import P6ProtocolError, canonical_sha256
from zscope.benchmarking.p6_review import (
    FROZEN_REVIEWER_IDENTITIES,
    REVIEW_ROLES,
    ROLE_CHECKS,
    aggregate_review_set,
    build_common_review_evidence,
    build_review_packet,
    finalize_review_packet,
    load_reviewer_identity_manifest,
    reviewer_identity_sha256,
    validate_review_artifact,
    validate_review_decision,
    validate_review_packet,
)


def _write_role_packet(root: Path, role: str, *, evidence_root: str = "d" * 64) -> Path:
    root.mkdir(parents=True)
    common = build_common_review_evidence(
        qualification_sha256="c" * 64,
        e0_lineage_artifact_sha256="1" * 64,
        balanced_quality_gate_sha256=evidence_root,
        quality_revalidation_receipt_sha256="2" * 64,
        successor_qualification_sha256="3" * 64,
    )
    common_path = root / "evidence" / "common-review-evidence.json"
    common_path.parent.mkdir()
    common_path.write_text(json.dumps(common, sort_keys=True) + "\n", encoding="utf-8")
    evidence = root / "evidence.json"
    evidence.write_text('{"answer_free":true}\n', encoding="utf-8")
    material = root / "review-material-manifest.json"
    material.write_text(
        json.dumps(p6_review.build_review_material_manifest(candidate_root=Path.cwd(), role=role))
        + "\n",
        encoding="utf-8",
    )
    packet = build_review_packet(
        role=role,
        candidate_sha256="a" * 64,
        policy_sha256="b" * 64,
        qualification_sha256="c" * 64,
        evidence_root_sha256=common["evidence_root_sha256"],
        artifact_files=[
            {
                "path": "evidence.json",
                "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                "content": evidence.read_text(encoding="utf-8"),
            },
            {
                "path": "review-material-manifest.json",
                "sha256": hashlib.sha256(material.read_bytes()).hexdigest(),
                "content": material.read_text(encoding="utf-8"),
            },
            {
                "path": "evidence/common-review-evidence.json",
                "sha256": hashlib.sha256(common_path.read_bytes()).hexdigest(),
                "content": common_path.read_text(encoding="utf-8"),
            },
        ],
    )
    path = root / "packet.json"
    path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    validate_review_packet(packet, packet_root=root)
    return path


def _decision(packet: dict, role: str) -> dict:
    identity = FROZEN_REVIEWER_IDENTITIES[role]
    material_sha = next(
        row["sha256"]
        for row in packet["artifact_files"]
        if row["path"] == "review-material-manifest.json"
    )
    evidence_sha = next(
        row["sha256"] for row in packet["artifact_files"] if row["path"] == "evidence.json"
    )
    return {
        "schema_version": "zscope.p6-review-decision.v1",
        "packet_uid": packet["packet_uid"],
        "packet_sha256": packet["packet_sha256"],
        "qualification_sha256": packet["qualification_sha256"],
        "evidence_root_sha256": packet["evidence_root_sha256"],
        "role": role,
        "harness": identity["harness"],
        "harness_version": identity["harness_version"],
        "provider": identity["provider"],
        "model": identity["model"],
        "reasoning_effort": identity["reasoning_effort"],
        "decision": "approved",
        "blocker_count": 0,
        "blockers": [],
        "checks": [
            {
                "name": name,
                "result": "pass",
                "artifact_sha256": material_sha if index == 0 else evidence_sha,
            }
            for index, name in enumerate(ROLE_CHECKS[role])
        ],
    }


def _executable_identity(role: str) -> tuple[str, str]:
    root = (
        Path("C:/zscope-sealed-runtime")
        if p6_review.os.name == "nt"
        else Path("/opt/zscope-sealed-runtime")
    )
    return str((root / role).resolve()), "e" * 64


def _configure_route(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, role: str) -> str:
    if role == "independent_benchmark":
        return p6_review._CODEX_EXPLICIT_ROUTE_SHA256
    root = tmp_path / f"{role}-route"
    root.mkdir()
    (root / "provider-config.json").write_text(
        json.dumps({"provider": FROZEN_REVIEWER_IDENTITIES[role]["provider"]}) + "\n",
        encoding="utf-8",
    )
    digest = p6_review._route_config_tree_sha256(root)
    root_name, sha_name = p6_review._REVIEWER_ROUTE_CONFIG_ENV[role]
    monkeypatch.setenv(root_name, str(root.resolve()))
    monkeypatch.setenv(sha_name, digest)
    return digest


def _command_identity(packet: dict, role: str) -> list[str]:
    executable, executable_sha = _executable_identity(role)
    route_sha = (
        p6_review._CODEX_EXPLICIT_ROUTE_SHA256 if role == "independent_benchmark" else "f" * 64
    )
    prefix = [
        executable,
        f"<binary-sha256:{executable_sha}>",
        f"<route-config-sha256:{route_sha}>",
    ]
    if role == "product_architecture":
        return [
            *prefix,
            *p6_review._claude_arguments(p6_review._decision_schema(packet, role=role)),
        ]
    if role == "proof_security":
        patch_hash = hashlib.sha256(p6_review._deepseek_patch_text().encode()).hexdigest()
        return [
            *prefix,
            "--profile",
            "headless",
            "--patch",
            f"<ephemeral-policy-patch-sha256:{patch_hash}>",
            "--patch",
            "<ephemeral-review-input-channel>",
            "<isolated-instruction-sha256:"
            + hashlib.sha256(p6_review._deepseek_instruction().encode()).hexdigest()
            + ">",
        ]
    return [*prefix, *p6_review._codex_arguments()]


def _write_review_artifact(packet_path: Path, output_dir: Path, role: str) -> None:
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    decision = _decision(packet, role)
    stdout = json.dumps(decision, sort_keys=True)
    material_sha, material = p6_review._material_from_packet(packet, material_root=Path.cwd())
    prompt = p6_review._prompt(packet, role=role, material=material)
    prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()
    call = p6_review._review_usage_call(
        sequence=1,
        attribution="initial",
        role=role,
        observed_model_identity=FROZEN_REVIEWER_IDENTITIES[role]["model"],
        model_observation_source=(
            "sealed_command" if role == "independent_benchmark" else "provider_reported"
        ),
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        input_sha256=prompt_sha,
        transport_stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        transport_stderr_sha256=hashlib.sha256(b"").hexdigest(),
    )
    reviewer_usage = p6_review._build_reviewer_usage(
        role=role, packet=packet, decision=decision, calls=[call]
    )
    raw = {
        "schema_version": p6_review.P6_REVIEW_RAW_SCHEMA_VERSION,
        "packet_uid": packet["packet_uid"],
        "packet_sha256": packet["packet_sha256"],
        "role": role,
        "reviewer_identity_sha256": reviewer_identity_sha256(role),
        "runtime_identity_contract": p6_review._SEALED_RUNNER_TEMPORAL_IDENTITY,
        "executable_path": _executable_identity(role)[0],
        "executable_sha256": _executable_identity(role)[1],
        "executable_snapshot_sha256": _executable_identity(role)[1],
        "harness_version_observed": FROZEN_REVIEWER_IDENTITIES[role]["harness_version"],
        "command_identity": _command_identity(packet, role),
        "exit_code": 0,
        "stdout": stdout,
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "reviewer_stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "transport_retry": None,
        "bounded_correction": None,
        "initial_prompt_sha256": prompt_sha,
        "accepted_prompt_sha256": prompt_sha,
        "material_root_sha256": material_sha,
        "decision_sha256": canonical_sha256(decision),
        "reviewer_usage": reviewer_usage,
    }
    output_dir.mkdir()
    (output_dir / "decision.json").write_text(
        json.dumps(decision, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "raw-envelope.json").write_text(
        json.dumps(raw, indent=2) + "\n", encoding="utf-8"
    )


def _review_process_result(
    role: str, decision_stdout: str, *, returncode: int = 0, stderr: str = ""
) -> object:
    return type(
        "Result",
        (),
        {
            "returncode": returncode,
            "stdout": decision_stdout,
            "stderr": stderr,
            "p6_decision_stdout": decision_stdout,
            "p6_review_usage_rows": [
                {
                    "observed_model_identity": FROZEN_REVIEWER_IDENTITIES[role]["model"],
                    "model_observation_source": (
                        "sealed_command" if role == "independent_benchmark" else "provider_reported"
                    ),
                    "prompt_tokens": 20,
                    "completion_tokens": 5,
                    "total_tokens": 25,
                }
            ],
        },
    )()


def _dsh_usage_event(*, input_tokens: int = 13, output_tokens: int = 5) -> str:
    return (
        json.dumps(
            {
                "type": "assistant/message",
                "data": {
                    "message": {
                        "role": "assistant",
                        "content": "answer-free reviewer output is never projected",
                        "source": {
                            "provider": "deepseek",
                            "model": "deepseek-v4-pro-0813",
                        },
                    },
                    "usage": {
                        "inputTokens": input_tokens,
                        "outputTokens": output_tokens,
                    },
                },
            }
        )
        + "\n"
    )


def _set_correction_records(
    packet_path: Path, output_dir: Path, role: str, kinds: tuple[str, ...]
) -> dict:
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    decision = json.loads((output_dir / "decision.json").read_text(encoding="utf-8"))
    raw_path = output_dir / "raw-envelope.json"
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    _material_sha, material = p6_review._material_from_packet(packet, material_root=Path.cwd())
    initial_prompt = p6_review._prompt(packet, role=role, material=material)
    records = []
    for index, kind in enumerate(kinds):
        correction_kind = p6_review._CorrectionKind(kind)
        mutable = [] if correction_kind is p6_review._CorrectionKind.CONTRACT_REGENERATION else None
        feedback = p6_review._correction_feedback(
            correction_kind,
            parsed_object=True,
            mutable_material_fields=mutable,
        )
        correction_prompt = p6_review._correction_prompt(
            initial_prompt,
            correction_kind,
            feedback=feedback,
            prior_decision=decision,
        )
        correction_sha = hashlib.sha256(correction_prompt.encode()).hexdigest()
        projection = (
            p6_review._decision_substantive_projection(decision)
            if correction_kind is p6_review._CorrectionKind.GROUNDING_CORRECTION
            else p6_review._contract_locked_projection(decision, mutable or ())
        )
        records.append(
            {
                "kind": kind,
                "initial_exit_code": 0,
                "initial_stdout_sha256": f"{index + 1:x}" * 64,
                "initial_stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "validation_feedback_sha256": canonical_sha256(feedback),
                "prior_decision_sha256": canonical_sha256(decision),
                "result_decision_sha256": canonical_sha256(decision),
                "correction_prompt_sha256": correction_sha,
                "correction_input_sha256": correction_sha,
                "command_identity": raw["command_identity"],
                "mutable_material_fields": mutable,
                "locked_projection": projection,
                "locked_projection_sha256": canonical_sha256(projection),
            }
        )
    raw["bounded_correction"] = records
    raw["accepted_prompt_sha256"] = records[-1]["correction_prompt_sha256"]
    calls = []
    invocation_rows = [
        (
            "initial",
            hashlib.sha256(initial_prompt.encode()).hexdigest(),
            records[0]["initial_stdout_sha256"],
            records[0]["initial_stderr_sha256"],
        )
    ]
    for index, record in enumerate(records):
        next_stdout = (
            records[index + 1]["initial_stdout_sha256"]
            if index + 1 < len(records)
            else raw["reviewer_stdout_sha256"]
        )
        next_stderr = (
            records[index + 1]["initial_stderr_sha256"]
            if index + 1 < len(records)
            else raw["stderr_sha256"]
        )
        invocation_rows.append(
            (
                record["kind"],
                record["correction_prompt_sha256"],
                next_stdout,
                next_stderr,
            )
        )
    for sequence, (attribution, input_sha, stdout_sha, stderr_sha) in enumerate(
        invocation_rows, start=1
    ):
        calls.append(
            p6_review._review_usage_call(
                sequence=sequence,
                attribution=attribution,
                role=role,
                observed_model_identity=FROZEN_REVIEWER_IDENTITIES[role]["model"],
                model_observation_source=(
                    "sealed_command" if role == "independent_benchmark" else "provider_reported"
                ),
                prompt_tokens=10 + sequence,
                completion_tokens=5,
                total_tokens=15 + sequence,
                input_sha256=input_sha,
                transport_stdout_sha256=stdout_sha,
                transport_stderr_sha256=stderr_sha,
            )
        )
    raw["reviewer_usage"] = p6_review._build_reviewer_usage(
        role=role,
        packet=packet,
        decision=decision,
        calls=calls,
    )
    raw_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    return raw


def _usage_conservation(calls: int) -> dict:
    return {
        "physical_call_count": calls,
        "provider_reported_call_count": calls,
        "estimated_call_count": 0,
        "provider_usage_coverage": 1.0,
        "requested_model": "deepseek-v4-flash",
        "requested_model_coverage": 1.0,
        "response_model": "deepseek-v4-flash-ga-260731",
        "response_model_coverage": 1.0,
        "queue_empty": True,
        "dimensions": {
            name: {"numerator": calls, "denominator": calls, "conserved": True}
            for name in ("token", "tool", "trace", "finding", "terminal")
        },
    }


def _qualification_for_role_projection() -> dict:
    provider_identity = "7" * 64
    toolchain_artifact = "8" * 64
    runtime_source = "9" * 64
    control_plane_commit = "c" * 40
    usage = _usage_conservation(1)
    depths = [
        {
            "scan_depth": depth,
            "artifact_sha256": f"{index + 1:x}" * 64,
            "projection_file_sha256": f"{index + 4:x}" * 64,
            "cache_identity_sha256": f"{index + 10:x}" * 64,
            "producer_attempt_id": "p6-attempt-recovery",
            "provider_identity_sha256": provider_identity,
            "toolchain_evidence_sha256": toolchain_artifact,
            "runtime_source_sha256": runtime_source,
            "call_count": 1,
            "provider_usage_coverage": 1.0,
            "provider_response_model_coverage": 1.0,
            "estimated_provider_call_count": 0,
            "telemetry_complete_rate": 1.0,
            "queue_empty": True,
            "token_conservation_passed": True,
            "eligible_count": 1,
            "entered_count": 1,
            "usage_conservation": usage,
        }
        for index, depth in enumerate(("fast", "balanced", "deep"))
    ]
    qualification = {
        "schema_version": "zscope.p6-qualification.v1",
        "attempt_id": "p6-attempt-recovery",
        "control_plane_commit": control_plane_commit,
        "candidate_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "offline_evidence_sha256": "c" * 64,
        "provider_identity_sha256": provider_identity,
        "provider_probe": {
            "artifact_sha256": "d" * 64,
            "provider_identity_sha256": provider_identity,
            "config_sha256": "e" * 64,
            "model": "deepseek-v4-flash",
            "call_count": 1,
            "provider_usage_coverage": 1.0,
            "estimated_provider_call_count": 0,
            "usage_conservation": usage,
        },
        "toolchain_evidence": {
            "artifact_sha256": toolchain_artifact,
            "evidence_sha256": "f" * 64,
            "control_plane_commit": control_plane_commit,
            "candidate_git_sha": "1" * 40,
            "candidate_git_tree": "2" * 40,
            "image_ref": "registry.invalid/zscope@sha256:" + "3" * 64,
            "image_digest": "sha256:" + "3" * 64,
            "image_id": "sha256:" + "4" * 64,
            "runtime_source_sha256": runtime_source,
            "oci_execution_sha256": "5" * 64,
        },
        "usage_conservation": _usage_conservation(4),
        "selected_producer_attempt_id": "p6-attempt-recovery",
        "depths": depths,
        "depth_count": 3,
        "all_depths_passed": True,
        "formal_benchmark": False,
        "formal_evidence": False,
        "release_eligible": False,
    }
    qualification["qualification_sha256"] = canonical_sha256(qualification)
    return qualification


def test_reviewer_identity_manifest_freezes_three_non_scanner_models() -> None:
    manifest = load_reviewer_identity_manifest()

    assert manifest["scanner"] == {"model": "deepseek-v4-flash", "review_eligible": False}
    assert manifest["reviewers"] == FROZEN_REVIEWER_IDENTITIES
    assert manifest["reviewers"]["product_architecture"]["model"] == "glm-5.3"
    assert manifest["reviewers"]["proof_security"]["model"] == "deepseek-v4-pro-0813"
    assert manifest["reviewers"]["independent_benchmark"]["model"] == "gpt-5.6-sol"
    assert "claude-opus-5" not in json.dumps(manifest)
    assert "claude-fable-5" not in json.dumps(manifest)


def test_role_evidence_requires_and_projects_recovery_control_plane_commit() -> None:
    qualification = _qualification_for_role_projection()

    for role in REVIEW_ROLES:
        evidence = p6_review.project_role_evidence(qualification, role=role)
        assert evidence["control_plane_commit"] == "c" * 40
        assert evidence["evidence"]["toolchain_evidence"]["control_plane_commit"] == "c" * 40

    qualification["control_plane_commit"] = "not-a-40-hex-commit"
    qualification["qualification_sha256"] = canonical_sha256(
        {key: value for key, value in qualification.items() if key != "qualification_sha256"}
    )
    with pytest.raises(P6ProtocolError, match="control-plane commit"):
        p6_review.project_role_evidence(qualification, role="independent_benchmark")


def test_packet_rejects_truth_or_cross_review_material(tmp_path: Path) -> None:
    root = tmp_path / "packet"
    root.mkdir()
    answer = root / "ground_truth.json"
    answer.write_text("{}\n", encoding="utf-8")
    payload = build_review_packet(
        role="independent_benchmark",
        candidate_sha256="a" * 64,
        policy_sha256="b" * 64,
        qualification_sha256="c" * 64,
        evidence_root_sha256="d" * 64,
        artifact_files=[
            {
                "path": answer.name,
                "sha256": hashlib.sha256(answer.read_bytes()).hexdigest(),
                "content": answer.read_text(encoding="utf-8"),
            }
        ],
    )

    with pytest.raises(P6ProtocolError, match="answer or cross-review"):
        validate_review_packet(payload, packet_root=root)


def test_review_decision_requires_exact_role_identity_and_checks(tmp_path: Path) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "proof_security")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    decision = _decision(packet, "proof_security")
    validate_review_decision(decision, packet=packet, role="proof_security")

    decision["model"] = "deepseek-v4-flash"
    with pytest.raises(P6ProtocolError, match="reviewer identity"):
        validate_review_decision(decision, packet=packet, role="proof_security")


def test_approved_review_cannot_hide_failed_check_or_blocker(tmp_path: Path) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "product_architecture")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    decision = _decision(packet, "product_architecture")
    decision["checks"][0]["result"] = "fail"

    with pytest.raises(P6ProtocolError, match="all checks pass"):
        validate_review_decision(decision, packet=packet, role="product_architecture")


def test_raw_review_artifact_binds_subprocess_output_and_command(tmp_path: Path) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "independent_benchmark")
    output_dir = tmp_path / "review"
    _write_review_artifact(packet_path, output_dir, "independent_benchmark")

    validate_review_artifact(
        output_dir=output_dir,
        packet_path=packet_path,
        role="independent_benchmark",
    )

    raw = json.loads((output_dir / "raw-envelope.json").read_text(encoding="utf-8"))
    raw["command_identity"][3] = "gpt-5.4"
    (output_dir / "raw-envelope.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="command identity"):
        validate_review_artifact(
            output_dir=output_dir,
            packet_path=packet_path,
            role="independent_benchmark",
        )


def test_raw_review_rejects_source_snapshot_digest_drift(tmp_path: Path) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "independent_benchmark")
    output_dir = tmp_path / "review"
    _write_review_artifact(packet_path, output_dir, "independent_benchmark")
    raw_path = output_dir / "raw-envelope.json"
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["executable_snapshot_sha256"] = "f" * 64
    raw_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(P6ProtocolError, match="snapshot binding"):
        validate_review_artifact(
            output_dir=output_dir,
            packet_path=packet_path,
            role="independent_benchmark",
        )


def test_raw_review_accepts_only_null_snapshot_for_temporal_launcher(
    tmp_path: Path,
) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "independent_benchmark")
    output_dir = tmp_path / "review"
    _write_review_artifact(packet_path, output_dir, "independent_benchmark")
    raw_path = output_dir / "raw-envelope.json"
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["runtime_identity_contract"] = p6_review._SEALED_RUNNER_TEMPORAL_LAUNCHER_IDENTITY
    raw["executable_snapshot_sha256"] = None
    raw_path.write_text(json.dumps(raw), encoding="utf-8")

    validate_review_artifact(
        output_dir=output_dir,
        packet_path=packet_path,
        role="independent_benchmark",
    )

    raw["executable_snapshot_sha256"] = raw["executable_sha256"]
    raw_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="snapshot binding"):
        validate_review_artifact(
            output_dir=output_dir,
            packet_path=packet_path,
            role="independent_benchmark",
        )


def test_three_reviews_are_role_separated_and_share_one_evidence_root(tmp_path: Path) -> None:
    packets = {}
    outputs = {}
    for role in REVIEW_ROLES:
        packet_path = _write_role_packet(tmp_path / f"packet-{role}", role)
        output_dir = tmp_path / f"output-{role}"
        _write_review_artifact(packet_path, output_dir, role)
        packets[role] = packet_path
        outputs[role] = output_dir

    review_set = aggregate_review_set(packet_paths=packets, output_dirs=outputs)

    assert review_set["approved_count"] == 3
    assert review_set["blocker_count"] == 0
    assert review_set["formal_evidence"] is False
    assert review_set["release_eligible"] is False
    packet_values = [json.loads(path.read_text(encoding="utf-8")) for path in packets.values()]
    assert len({packet["packet_sha256"] for packet in packet_values}) == 3
    assert len({packet["evidence_root_sha256"] for packet in packet_values}) == 1
    role_payloads = [
        next(
            row
            for row in packet["artifact_files"]
            if row["path"] == "review-material-manifest.json"
        )
        for packet in packet_values
    ]
    assert len({packet["role"] for packet in packet_values}) == 3
    assert len({payload["sha256"] for payload in role_payloads}) == 3
    conservation = review_set["reviewer_usage_conservation"]
    assert conservation["role_count"] == 3
    assert conservation["physical_call_count"] == 3
    assert conservation["provider_reported_call_count"] == 3
    assert conservation["provider_usage_coverage"] == 1.0
    assert conservation["missing_usage_call_count"] == 0
    assert conservation["mismatched_model_call_count"] == 0
    assert conservation["estimated_call_count"] == 0
    assert conservation["token_conservation_passed"] is True
    assert conservation["included_in_balanced_scan_token_gate"] is False
    assert all(len(row["review_artifact_sha256"]) == 64 for row in review_set["reviews"])
    observation_sources = {
        row["role"]: row["model_observation_source"] for row in review_set["reviews"]
    }
    assert observation_sources == {
        "product_architecture": "provider_reported",
        "proof_security": "provider_reported",
        "independent_benchmark": "sealed_command",
    }
    assert all("actual_model" not in row for row in review_set["reviews"])


def test_reviewer_usage_schema_and_three_frozen_harness_envelopes(tmp_path: Path) -> None:
    claude_outer = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "duration_ms": 1,
        "duration_api_ms": 1,
        "num_turns": 1,
        "result": "",
        "session_id": "answer-free",
        "total_cost_usd": 0,
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "cache_creation_input_tokens": 4,
            "cache_read_input_tokens": 6,
        },
        "modelUsage": {"glm-5.3": {"inputTokens": 110, "outputTokens": 20}},
        "permission_denials": [],
        "uuid": "answer-free",
        "structured_output": {},
    }
    assert p6_review._claude_usage_rows(json.dumps(claude_outer)) == [
        {
            "observed_model_identity": "glm-5.3",
            "model_observation_source": "provider_reported",
            "prompt_tokens": 110,
            "completion_tokens": 20,
            "total_tokens": 130,
        }
    ]

    codex_jsonl = "\n".join(
        (
            json.dumps({"type": "thread.started", "thread_id": "answer-free"}),
            json.dumps({"type": "turn.started"}),
            json.dumps(
                {
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 200,
                        "cached_input_tokens": 50,
                        "cache_write_input_tokens": 0,
                        "output_tokens": 30,
                        "reasoning_output_tokens": 10,
                    },
                }
            ),
        )
    )
    assert p6_review._codex_usage_rows(codex_jsonl, requested_model="gpt-5.6-sol") == [
        {
            "observed_model_identity": "gpt-5.6-sol",
            "model_observation_source": "sealed_command",
            "prompt_tokens": 200,
            "completion_tokens": 30,
            "total_tokens": 230,
        }
    ]

    dsh_home = tmp_path / "dsh"
    dsh_home.mkdir()
    environment = {"DSH_HOME": str(dsh_home.resolve())}
    session = dsh_home / "sessions" / "project" / "review.jsonl"
    session.parent.mkdir(parents=True)
    session.write_text(
        "\n".join(
            (
                json.dumps({"schemaVersion": 1, "answer_free": True}),
                json.dumps(
                    {
                        "type": "request/context",
                        "data": {
                            "provider": "deepseek",
                            "model": "deepseek-v4-pro-0813",
                        },
                    }
                ),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    before = p6_review._dsh_session_state(environment)
    with session.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "type": "assistant/message",
                    "data": {
                        "message": {
                            "role": "assistant",
                            "content": "never persisted",
                            "source": {
                                "provider": "deepseek",
                                "model": "deepseek-v4-pro-0813",
                            },
                        },
                        "usage": {
                            "inputTokens": 300,
                            "outputTokens": 40,
                            "cacheReadTokens": 7,
                            "cacheWriteTokens": 3,
                            "reasoningTokens": 11,
                        },
                    },
                }
            )
            + "\n"
        )
    dsh_rows = p6_review._dsh_usage_rows(environment=environment, before=before)
    assert dsh_rows == [
        {
            "provider": "deepseek",
            "observed_model_identity": "deepseek-v4-pro-0813",
            "model_observation_source": "provider_reported",
            "prompt_tokens": 310,
            "completion_tokens": 40,
            "total_tokens": 350,
        }
    ]
    assert "message" not in dsh_rows[0]
    assert "reasoningTokens" not in dsh_rows[0]

    before_append = p6_review._dsh_session_state(environment)
    with session.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "type": "assistant/message",
                    "data": {
                        "message": {
                            "role": "assistant",
                            "content": "second call not persisted",
                            "source": {
                                "provider": "deepseek",
                                "model": "deepseek-v4-pro-0813",
                            },
                        },
                        "usage": {
                            "inputTokens": 13,
                            "outputTokens": 5,
                        },
                    },
                }
            )
            + "\n"
        )
    assert p6_review._dsh_usage_rows(environment=environment, before=before_append) == [
        {
            "provider": "deepseek",
            "observed_model_identity": "deepseek-v4-pro-0813",
            "model_observation_source": "provider_reported",
            "prompt_tokens": 13,
            "completion_tokens": 5,
            "total_tokens": 18,
        }
    ]

    packet_path = _write_role_packet(tmp_path / "schema-packet", "proof_security")
    output = tmp_path / "schema-review"
    _write_review_artifact(packet_path, output, "proof_security")
    raw = json.loads((output / "raw-envelope.json").read_text(encoding="utf-8"))
    schema = json.loads(
        Path("zscope/benchmarking/p6_reviewer_usage.schema.json").read_text(encoding="utf-8")
    )
    assert schema["$id"] == "https://zscope.dev/schemas/p6_reviewer_usage.schema.json"


def test_codex_failed_turn_requires_and_conserves_strict_provider_usage() -> None:
    failed_with_usage = json.dumps(
        {
            "type": "turn.failed",
            "usage": {
                "input_tokens": 31,
                "cached_input_tokens": 0,
                "cache_write_input_tokens": 0,
                "output_tokens": 7,
                "reasoning_output_tokens": 2,
            },
        }
    )
    assert p6_review._codex_usage_rows(failed_with_usage, requested_model="gpt-5.6-sol") == [
        {
            "observed_model_identity": "gpt-5.6-sol",
            "model_observation_source": "sealed_command",
            "prompt_tokens": 31,
            "completion_tokens": 7,
            "total_tokens": 38,
        }
    ]
    with pytest.raises(P6ProtocolError, match="provider usage"):
        p6_review._codex_usage_rows(
            json.dumps({"type": "turn.failed", "error": {"message": "redacted"}}),
            requested_model="gpt-5.6-sol",
        )


def test_dsh_usage_rejects_inode_replacement_prefix_forge_and_new_file(
    tmp_path: Path,
) -> None:
    def session_tree(name: str) -> tuple[dict[str, str], Path]:
        root = tmp_path / name
        session = root / "sessions" / "project" / "review.jsonl"
        session.parent.mkdir(parents=True)
        session.write_text('{"schemaVersion":1}\n', encoding="utf-8")
        return {"DSH_HOME": str(root.resolve())}, session

    environment, session = session_tree("inode-replace")
    before = p6_review._dsh_session_state(environment)
    replacement = session.with_name("replacement.jsonl")
    replacement.write_bytes(session.read_bytes() + _dsh_usage_event().encode("utf-8"))
    replacement.replace(session)
    with pytest.raises(P6ProtocolError, match="replaced or linked"):
        p6_review._dsh_usage_rows(environment=environment, before=before)

    environment, session = session_tree("prefix-forge")
    before = p6_review._dsh_session_state(environment)
    prefix = bytearray(session.read_bytes())
    prefix[0] ^= 1
    session.write_bytes(bytes(prefix) + _dsh_usage_event().encode("utf-8"))
    with pytest.raises(P6ProtocolError, match="prefix changed"):
        p6_review._dsh_usage_rows(environment=environment, before=before)

    environment, session = session_tree("new-file")
    before = p6_review._dsh_session_state(environment)
    session.with_name("injected.jsonl").write_text(_dsh_usage_event(), encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="session tree changed"):
        p6_review._dsh_usage_rows(environment=environment, before=before)


def test_reviewer_usage_rejects_self_resealed_model_usage_and_token_tamper(
    tmp_path: Path,
) -> None:
    role = "proof_security"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    output = tmp_path / "review"
    _write_review_artifact(packet_path, output, role)
    raw_path = output / "raw-envelope.json"
    raw = json.loads(raw_path.read_text(encoding="utf-8"))

    call = raw["reviewer_usage"]["calls"][0]
    call["observed_model_identity"] = "gpt-5.6-sol"
    call["call_sha256"] = canonical_sha256(
        {key: value for key, value in call.items() if key != "call_sha256"}
    )
    raw["reviewer_usage"]["mismatched_model_call_count"] = 1
    raw["reviewer_usage"]["reviewer_usage_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in raw["reviewer_usage"].items()
            if key != "reviewer_usage_sha256"
        }
    )
    raw_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="usage binding or conservation"):
        validate_review_artifact(output_dir=output, packet_path=packet_path, role=role)


def test_review_set_rejects_any_common_evidence_tamper(tmp_path: Path) -> None:
    packets = {}
    outputs = {}
    for role in REVIEW_ROLES:
        packet_path = _write_role_packet(tmp_path / f"packet-{role}", role)
        output_dir = tmp_path / f"output-{role}"
        _write_review_artifact(packet_path, output_dir, role)
        packets[role] = packet_path
        outputs[role] = output_dir

    common_path = packets["proof_security"].parent / "evidence" / "common-review-evidence.json"
    common = json.loads(common_path.read_text(encoding="utf-8"))
    common["quality_revalidation_receipt_sha256"] = "f" * 64
    common_path.write_text(json.dumps(common) + "\n", encoding="utf-8")

    with pytest.raises(P6ProtocolError):
        aggregate_review_set(packet_paths=packets, output_dirs=outputs)


def test_review_set_rejects_mixed_qualification_roots(tmp_path: Path) -> None:
    packets = {}
    outputs = {}
    for index, role in enumerate(REVIEW_ROLES):
        packet_path = _write_role_packet(
            tmp_path / f"packet-{role}", role, evidence_root=(f"{index + 1:x}" * 64)
        )
        output_dir = tmp_path / f"output-{role}"
        _write_review_artifact(packet_path, output_dir, role)
        packets[role] = packet_path
        outputs[role] = output_dir

    with pytest.raises(P6ProtocolError, match="one qualification and evidence root"):
        aggregate_review_set(packet_paths=packets, output_dirs=outputs)


def test_review_material_is_allowlisted_hash_bound_and_never_embedded(tmp_path: Path) -> None:
    manifest = p6_review.build_review_material_manifest(
        candidate_root=Path.cwd(), role="proof_security"
    )
    assert tuple(row["path"] for row in manifest["files"]) == (
        p6_review.ROLE_REVIEW_MATERIAL_PATHS["proof_security"]
    )
    assert all("content" not in row for row in manifest["files"])
    assert all(not row["path"].startswith("test/range/") for row in manifest["files"])
    assert manifest["material_root_sha256"] == canonical_sha256(
        {key: value for key, value in manifest.items() if key != "material_root_sha256"}
    )


@pytest.mark.parametrize(
    "forbidden_path",
    (
        "test/range/benchmark/v16/ground_truth.json",
        "tmp/scorer/material.json",
        "tmp/packets/review-packet.json",
    ),
)
def test_review_material_allowlist_rejects_truth_scorer_and_packets(
    forbidden_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        p6_review.ROLE_REVIEW_MATERIAL_PATHS,
        "proof_security",
        (forbidden_path,),
    )

    with pytest.raises(P6ProtocolError, match="answer material"):
        p6_review.build_review_material_manifest(candidate_root=Path.cwd(), role="proof_security")


def test_review_material_allowlists_cover_current_p6_quality_and_proof_authority() -> None:
    assert p6_review._MAX_REVIEW_MATERIAL_BYTES == 4_194_304
    assert p6_review._ANSWER_FREE_REVIEW_MATERIAL_PATH_EXCEPTIONS == frozenset(
        {"zscope/benchmarking/p6_expected_proxy_attestation.schema.json"}
    )
    common = {
        ".github/workflows/p6-pilot-validation.yml",
        "scripts/qualify_p6_proof_promotion.py",
        "tests/test_p6_proof_promotion_qualification.py",
        "zscope/benchmarking/p6_review.py",
        "zscope/orchestration/p6-proof-promotion-qualification.v1.json",
        "zscope/orchestration/proof_promotion_qualification.py",
        "zscope/orchestration/schemas/p6-proof-promotion-qualification-v1.schema.json",
        "zscope/orchestration/schemas/successor-runtime-review-status-v1.schema.json",
        "zscope/orchestration/successor-runtime-review-status.v1.json",
        "zscope/orchestration/successor_runtime_review_status.py",
        "zscope/rules/builtin_catalog.yaml",
        "zscope/rules/qualification_registry.yaml",
    }
    for role in REVIEW_ROLES:
        assert common <= set(p6_review.ROLE_REVIEW_MATERIAL_PATHS[role])
    proof_critical = {
        "scripts/run_p6_synthetic_replay.py",
        "tests/test_p6_synthetic_replay.py",
        "zscope/agents/base.py",
        "zscope/agents/proof_engine/agent.py",
        "zscope/benchmarking/p6_synthetic_replay.py",
        "zscope/core/analysis/analyzer.py",
        "zscope/core/candidates/clang_ast_cfg.py",
        "zscope/core/candidates/cpp_domains/concurrency_shared_state.py",
        "zscope/core/candidates/cpp_domains/resource_lifecycle.py",
        "zscope/core/candidates/regex.py",
        "zscope/core/validation/audit_eligibility.py",
        "zscope/core/validation/evidence_completion.py",
        "zscope/core/validation/fact_capabilities.py",
        "zscope/core/validation/function_ir.py",
        "zscope/core/validation/proof_kernel/closure.py",
        "zscope/core/validation/proof_kernel/registry.py",
        "zscope/core/validation/runner.py",
        "zscope/orchestration/hypothesis_hunter/resource_proof.py",
        "zscope/orchestration/hypothesis_hunter/catalog.py",
        "zscope/orchestration/hypothesis_hunter/planner.py",
        "zscope/orchestration/hypothesis_hunter/runtime.py",
        "zscope/orchestration/candidate_envelope.py",
        "zscope/orchestration/candidates.py",
        "zscope/orchestration/decision_trace.py",
        "zscope/orchestration/parallel_analyzer.py",
        "zscope/retrieval/clang_backend.py",
        "zscope/retrieval/clang_extractor.py",
        "zscope/retrieval/clang_tooling_evidence.py",
        "zscope/reporting/assembler.py",
        "zscope/reporting/finding_roots.py",
        "zscope/reporting/report.py",
        "zscope/reporting/schema.py",
        "zscope/reporting/views.py",
    }
    assert proof_critical <= set(p6_review.ROLE_REVIEW_MATERIAL_PATHS["proof_security"])
    quality_critical = {
        ".github/actions/validate-p6-artifact/action.yml",
        "containers/p6/Containerfile",
        "containers/p6/runtime-lock.json",
        "containers/p6/verify_toolchain.py",
        "scripts/p6_balanced_orchestrator.py",
        "scripts/p6_balanced_quality_gate.py",
        "scripts/p6_tcp_relay.py",
        "scripts/run_p6_cold_producer.py",
        "zscope/benchmarking/p6_balanced_quality_aggregate.schema.json",
        "zscope/benchmarking/p6_balanced_quality_gate.schema.json",
        "zscope/benchmarking/p6_expected_proxy_attestation.schema.json",
        "zscope/benchmarking/p6_final_evidence_manifest.schema.json",
        "zscope/benchmarking/p6_local_image_provenance.schema.json",
        "zscope/benchmarking/p6_local_proxy_provision.schema.json",
        "zscope/benchmarking/p6_balanced_orchestrator.py",
        "zscope/benchmarking/p6_quality_revalidation_receipt.schema.json",
        "zscope/benchmarking/p6_producer_metrics.py",
        "zscope/benchmarking/p6_producer_package_init.py",
        "zscope/benchmarking/p6_producer_sandbox.py",
        "zscope/benchmarking/p6_reviewer_usage.schema.json",
        "zscope/benchmarking/p6_toolchain_oci_evidence.schema.json",
        "zscope/cli/cli.py",
    }
    for role in ("product_architecture", "independent_benchmark"):
        assert quality_critical <= set(p6_review.ROLE_REVIEW_MATERIAL_PATHS[role])

    forbidden = (
        "ground_truth",
        "ground-truth",
        "/truth/",
        "scorer",
        "/packet/",
        "/packets/",
        "/reviews/",
        "packet.json",
        "review-packet",
        "review_packet",
    )
    for role in REVIEW_ROLES:
        paths = p6_review.ROLE_REVIEW_MATERIAL_PATHS[role]
        assert len(paths) == len(set(paths))
        assert all(
            path == "test/range/zscope.benchmark.yaml" or not path.startswith("test/range/")
            for path in paths
        )
        assert all(
            not any(token in f"/{path.casefold()}/" for token in forbidden) for path in paths
        )
        total_bytes = sum((Path.cwd() / path).stat().st_size for path in paths)
        assert total_bytes < p6_review._MAX_REVIEW_MATERIAL_BYTES
        manifest = p6_review.build_review_material_manifest(candidate_root=Path.cwd(), role=role)
        assert manifest["file_count"] == len(paths)


def test_review_decision_must_ground_to_material_manifest(tmp_path: Path) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "product_architecture")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    decision = _decision(packet, "product_architecture")
    evidence_sha = next(
        row["sha256"] for row in packet["artifact_files"] if row["path"] == "evidence.json"
    )
    for check in decision["checks"]:
        check["artifact_sha256"] = evidence_sha

    with pytest.raises(P6ProtocolError, match="material manifest"):
        validate_review_decision(decision, packet=packet, role="product_architecture")


def test_reviewer_environments_are_role_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sealed_runner_path = p6_review.os.environ["PATH"]
    values = {
        "PATH": sealed_runner_path,
        "Z_SCOPE_API_KEY": "scanner",
        "Z_SCOPE_P6_API_KEY_FILE": "scanner-file",
        "ANTHROPIC_API_KEY": "claude",
        "ANTHROPIC_BASE_URL": "forbidden",
        "CLAUDE_MODEL": "forbidden",
        "DEEPSEEK_API_KEY": "deepseek",
        "DSH_CONFIG": "forbidden",
        "OPENAI_API_KEY": "codex",
        "OPENAI_BASE_URL": "forbidden",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    _configure_route(monkeypatch, tmp_path, "product_architecture")
    _configure_route(monkeypatch, tmp_path, "proof_security")

    product = p6_review._reviewer_environment(
        "product_architecture", temp_root=tmp_path / "product"
    )
    proof = p6_review._reviewer_environment("proof_security", temp_root=tmp_path / "proof")
    benchmark = p6_review._reviewer_environment(
        "independent_benchmark", temp_root=tmp_path / "benchmark"
    )

    assert product.get("ANTHROPIC_API_KEY") == "claude"
    assert proof.get("DEEPSEEK_API_KEY") == "deepseek"
    assert benchmark.get("OPENAI_API_KEY") == "codex"
    for environment in (product, proof, benchmark):
        assert [key.upper() for key in environment].count("PATH") == 1
        assert "Z_SCOPE_API_KEY" not in environment
        assert "Z_SCOPE_P6_API_KEY_FILE" not in environment
        assert environment["HOME"].startswith(str(tmp_path))
        assert environment["XDG_CONFIG_HOME"].startswith(str(tmp_path))
    assert product["ANTHROPIC_BASE_URL"] == "forbidden"
    assert "CLAUDE_MODEL" not in product
    assert "DSH_CONFIG" not in proof
    assert "OPENAI_BASE_URL" not in benchmark
    assert "DEEPSEEK_API_KEY" not in product and "OPENAI_API_KEY" not in product
    assert "ANTHROPIC_API_KEY" not in proof and "OPENAI_API_KEY" not in proof
    assert "ANTHROPIC_API_KEY" not in benchmark and "DEEPSEEK_API_KEY" not in benchmark


@pytest.mark.parametrize("role", REVIEW_ROLES)
@pytest.mark.parametrize("credential", (None, "", "   "))
def test_reviewer_environment_does_not_require_new_github_secret_when_sealed_login_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    credential: str | None,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("DSH_HOME", raising=False)
    for credential_name in p6_review._REVIEWER_CREDENTIAL_ENV.values():
        monkeypatch.delenv(credential_name, raising=False)
    if credential is not None:
        monkeypatch.setenv(p6_review._REVIEWER_CREDENTIAL_ENV[role], credential)

    environment = p6_review._reviewer_environment(role, temp_root=tmp_path / role)
    assert p6_review._REVIEWER_CREDENTIAL_ENV[role] not in environment
    assert "Z_SCOPE_API_KEY" not in environment


@pytest.mark.parametrize("role", ("product_architecture", "proof_security"))
def test_reviewer_route_config_is_absolute_tree_bound_and_copied_to_ephemeral_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    monkeypatch.setenv(p6_review._REVIEWER_CREDENTIAL_ENV[role], "role-key")
    digest = _configure_route(monkeypatch, tmp_path, role)

    environment = p6_review._reviewer_environment(role, temp_root=tmp_path / "ephemeral")

    config_name = "CLAUDE_CONFIG_DIR" if role == "product_architecture" else "DSH_HOME"
    copied = Path(environment[config_name])
    assert copied.is_relative_to(tmp_path / "ephemeral")
    assert p6_review._route_config_tree_sha256(copied) == digest
    assert environment["Z_SCOPE_P6_REVIEW_ROUTE_CONFIG_SHA256"] == digest

    _root_name, sha_name = p6_review._REVIEWER_ROUTE_CONFIG_ENV[role]
    monkeypatch.setenv(sha_name, "f" * 64)
    with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
        p6_review._reviewer_environment(role, temp_root=tmp_path / "invalid")


def test_reviewer_executable_is_resolved_only_from_cleaned_runner_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = tmp_path / "sealed-runner-bin"
    trusted.mkdir()
    executable = trusted / "claude"
    executable.write_bytes(b"sealed claude executable")
    executable.chmod(0o500)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(p6_review, "_untrusted_reviewer_roots", lambda: ())
    monkeypatch.setattr(
        p6_review.shutil,
        "which",
        lambda name, *, path: (
            str(executable.resolve())
            if name == "claude" and path == str(trusted.resolve())
            else None
        ),
    )

    assert p6_review._resolve_reviewer_executable(
        "product_architecture", search_path=str(trusted)
    ) == (
        executable.resolve(),
        digest,
    )

    executable.chmod(0o700)
    executable.write_bytes(b"changed sealed runner command")
    executable.chmod(0o500)
    changed_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert changed_digest != digest
    assert (
        p6_review._resolve_reviewer_executable("product_architecture", search_path=str(trusted))[1]
        == changed_digest
    )


def test_reviewer_executable_rejects_workspace_temp_and_relative_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate_bin = tmp_path / "candidate" / "bin"
    candidate_bin.mkdir(parents=True)
    executable = candidate_bin / "claude"
    executable.write_bytes(b"candidate controlled")
    executable.chmod(0o500)
    monkeypatch.setenv("P6_CANDIDATE_ROOT", str(tmp_path / "candidate"))

    with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
        p6_review._resolve_reviewer_executable(
            "product_architecture", search_path=str(candidate_bin)
        )
    with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
        p6_review._resolve_reviewer_executable("product_architecture", search_path="relative/bin")


def test_reviewer_executable_rejects_missing_sealed_path_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = tmp_path / "sealed-runner-bin"
    trusted.mkdir()
    monkeypatch.setattr(p6_review, "_untrusted_reviewer_roots", lambda: ())
    monkeypatch.setattr(p6_review.shutil, "which", lambda _name, *, path: None)

    with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
        p6_review._resolve_reviewer_executable("product_architecture", search_path=str(trusted))


def test_reviewer_executes_a_private_digest_bound_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / ("claude.exe" if p6_review.os.name == "nt" else "claude")
    executable.write_bytes(b"sealed executable bytes")
    executable.chmod(0o500)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    snapshot = p6_review._snapshot_reviewer_executable(
        executable.resolve(),
        expected_sha256=digest,
        destination_root=tmp_path / "private-snapshot",
    )

    assert snapshot != executable.resolve()
    assert snapshot.read_bytes() == b"sealed executable bytes"
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == digest

    executable.chmod(0o700)
    executable.write_bytes(b"replaced after initial binding")
    with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
        p6_review._snapshot_reviewer_executable(
            executable.resolve(),
            expected_sha256=digest,
            destination_root=tmp_path / "replaced-snapshot",
        )


def test_reviewer_script_launcher_snapshot_fails_closed(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"#!/usr/bin/env node\nconsole.log('codex')\n")
    executable.chmod(0o500)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    with pytest.raises(P6ProtocolError, match="review_runtime_snapshot_unsupported"):
        p6_review._snapshot_reviewer_executable(
            executable,
            expected_sha256=digest,
            destination_root=tmp_path / "script-snapshot",
        )


def test_reviewer_script_launcher_uses_temporal_source_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"#!/usr/bin/env node\nconsole.log('codex')\n")
    executable.chmod(0o500)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    prepared, contract, snapshot_sha = p6_review._prepare_reviewer_executable(
        executable.resolve(),
        expected_sha256=digest,
        destination_root=tmp_path / "unused-snapshot",
    )

    assert prepared == executable.resolve()
    assert contract == p6_review._SEALED_RUNNER_TEMPORAL_LAUNCHER_IDENTITY
    assert snapshot_sha is None
    assert not (tmp_path / "unused-snapshot").exists()

    monkeypatch.setattr(
        p6_review.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Result",
            (),
            {"returncode": 0, "stdout": "codex-cli 0.144.4\n", "stderr": ""},
        )(),
    )
    assert (
        p6_review._probe_reviewer_version(
            "independent_benchmark",
            executable=prepared,
            executable_sha256=digest,
            environment={"PATH": str(tmp_path)},
        )
        == "0.144.4"
    )


def test_reviewer_script_launcher_rejects_replacement_during_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"#!/usr/bin/env node\nconsole.log('codex')\n")
    executable.chmod(0o500)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    def replace_during_run(*_args: object, **_kwargs: object) -> object:
        executable.chmod(0o700)
        executable.write_bytes(b"#!/usr/bin/env node\nconsole.log('replaced')\n")
        executable.chmod(0o500)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(p6_review.subprocess, "run", replace_during_run)
    with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
        p6_review._run_bound_reviewer_process(
            [str(executable.resolve()), "--version"],
            executable=executable.resolve(),
            expected_sha256=digest,
            capture_output=True,
            text=True,
        )


def test_reviewer_transport_exception_does_not_expose_captured_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"#!/usr/bin/env node\nconsole.log('codex')\n")
    executable.chmod(0o500)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    marker = "private-reviewer-output-must-not-escape"

    def time_out(*_args: object, **_kwargs: object) -> object:
        raise p6_review.subprocess.TimeoutExpired(
            cmd=[str(executable)], timeout=1, output=marker, stderr=marker
        )

    monkeypatch.setattr(p6_review.subprocess, "run", time_out)
    with pytest.raises(P6ProtocolError) as failure:
        p6_review._run_bound_reviewer_process(
            [str(executable.resolve()), "--version"],
            executable=executable.resolve(),
            expected_sha256=digest,
            capture_output=True,
            text=True,
        )
    assert str(failure.value) == "review_transport_failed"
    assert marker not in str(failure.value)


@pytest.mark.parametrize(
    ("failure", "expected_class", "expected_count"),
    (
        (
            P6ProtocolError(
                "P6 reviewer transport failed after one bounded retry; "
                "class=review_transport_failed; count=2"
            ),
            "review_transport_failed",
            2,
        ),
        (P6ProtocolError("review_binding_invalid"), "review_binding_invalid", 1),
    ),
)
def test_reviewer_wrapper_writes_only_typed_failure_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: P6ProtocolError,
    expected_class: str,
    expected_count: int,
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path.resolve()))
    monkeypatch.setattr(
        p6_review,
        "run_reviewer",
        lambda **_kwargs: (_ for _ in ()).throw(failure),
    )
    marker = tmp_path / "review-failure.json"

    with pytest.raises(P6ProtocolError, match=expected_class):
        p6_review.run_reviewer_with_failure_marker(
            role="proof_security",
            packet_path=tmp_path / "packet.json",
            output_dir=tmp_path / "review",
            failure_marker=marker,
        )

    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "failure_class": expected_class,
        "failure_count": expected_count,
    }
    assert "transport failed" not in marker.read_text(encoding="utf-8")


def test_reviewer_wrapper_classifies_a_valid_blocking_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path.resolve()))
    monkeypatch.setattr(
        p6_review,
        "run_reviewer",
        lambda **_kwargs: {"decision": "changes_required", "blocker_count": 3},
    )
    marker = tmp_path / "review-blocker.json"

    with pytest.raises(P6ProtocolError, match="review_blocker"):
        p6_review.run_reviewer_with_failure_marker(
            role="proof_security",
            packet_path=tmp_path / "packet.json",
            output_dir=tmp_path / "review",
            failure_marker=marker,
        )

    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "failure_class": "review_blocker",
        "failure_count": 3,
    }


def test_deepseek_prompt_never_enters_process_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_prompt = "hash-bound candidate material must stay out of argv"
    executable = tmp_path / "dsh"
    executable.write_text("frozen", encoding="utf-8")
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()

    command, identity = p6_review._command_for_role(
        "proof_security",
        executable=executable.resolve(),
        executable_sha256=executable_sha,
        temp_root=tmp_path,
        schema={"type": "object"},
        prompt=secret_prompt,
    )

    assert all(secret_prompt not in value for value in command)
    assert all(secret_prompt not in value for value in identity)
    assert command[-1] == p6_review._deepseek_instruction()
    assert identity[-1].startswith("<isolated-instruction-sha256:")
    assert identity[:2] == [str(executable.resolve()), f"<binary-sha256:{executable_sha}>"]
    assert "- id: tool-fs\n  disabled: true" in p6_review._deepseek_patch_text()
    assert "- id: tool-fs-search\n  disabled: true" in p6_review._deepseek_patch_text()
    input_patch = tmp_path / "deepseek-review-input.patch.yml"
    assert secret_prompt in input_patch.read_text(encoding="utf-8")
    assert "<ephemeral-review-input-channel>" in identity

    _, correction_identity = p6_review._command_for_role(
        "proof_security",
        executable=executable.resolve(),
        executable_sha256=executable_sha,
        temp_root=tmp_path,
        schema={"type": "object"},
        prompt="bounded correction with the same frozen command identity",
    )
    assert correction_identity == identity


def test_codex_reviewer_command_identity_keeps_exact_e0_no_shell_contract() -> None:
    assert p6_review._codex_arguments() == [
        "exec",
        "--model",
        "gpt-5.6-sol",
        "--config",
        'model_reasoning_effort="xhigh"',
        "--strict-config",
        "--disable",
        "shell_tool",
        "--sandbox",
        "read-only",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--output-schema",
        "decision-schema.json",
        "--json",
        "--output-last-message",
        "codex-last-message.json",
        "--color",
        "never",
        "-",
    ]


def test_reviewer_json_rejects_duplicate_keys_and_unbounded_claude_outer_fields(
    tmp_path: Path,
) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "product_architecture")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    decision = _decision(packet, "product_architecture")

    with pytest.raises(P6ProtocolError, match="JSON artifact"):
        p6_review.decision_from_stdout(
            '{"schema_version":"a","schema_version":"b"}',
            role="product_architecture",
        )

    outer = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "duration_ms": 1,
        "duration_api_ms": 1,
        "num_turns": 1,
        "result": "",
        "session_id": "answer-free",
        "total_cost_usd": 0,
        "usage": {},
        "modelUsage": {},
        "permission_denials": [],
        "uuid": "answer-free",
        "structured_output": decision,
        "unexpected_echo": "candidate material",
    }
    with pytest.raises(P6ProtocolError, match="envelope fields"):
        p6_review.decision_from_stdout(json.dumps(outer), role="product_architecture")


def test_raw_review_recomputes_the_actual_accepted_prompt(tmp_path: Path) -> None:
    packet_path = _write_role_packet(tmp_path / "packet", "independent_benchmark")
    output_dir = tmp_path / "review"
    _write_review_artifact(packet_path, output_dir, "independent_benchmark")
    raw_path = output_dir / "raw-envelope.json"
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["accepted_prompt_sha256"] = "f" * 64
    raw_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(P6ProtocolError, match="accepted prompt binding"):
        validate_review_artifact(
            output_dir=output_dir,
            packet_path=packet_path,
            role="independent_benchmark",
        )


def test_correction_failure_classification_is_typed_and_stage_bound(
    tmp_path: Path,
) -> None:
    role = "proof_security"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    wrong_identity = _decision(packet, role)
    wrong_identity["model"] = "not-the-frozen-model"
    candidate, failure = p6_review._classify_decision_output(
        json.dumps(wrong_identity), packet=packet, role=role
    )
    assert candidate == wrong_identity
    assert failure is p6_review._CorrectionKind.CONTRACT_REGENERATION
    assert p6_review._contract_mutable_material_fields(candidate, role=role) == ()

    wrong_grounding = _decision(packet, role)
    wrong_grounding["checks"][-1]["artifact_sha256"] = "f" * 64
    candidate, failure = p6_review._classify_decision_output(
        json.dumps(wrong_grounding), packet=packet, role=role
    )
    assert candidate == wrong_grounding
    assert failure is p6_review._CorrectionKind.GROUNDING_CORRECTION

    feedback = p6_review._correction_prompt("fixed prompt", failure)
    assert "role-packet grounding" in feedback
    assert "outside the role packet" not in feedback


def test_bounded_correction_transition_disallows_duplicates_and_reverse_order() -> None:
    contract = p6_review._CorrectionKind.CONTRACT_REGENERATION
    grounding = p6_review._CorrectionKind.GROUNDING_CORRECTION

    assert p6_review._next_correction_kind([], contract) is contract
    assert p6_review._next_correction_kind([], grounding) is grounding
    assert p6_review._next_correction_kind([contract], grounding) is grounding
    assert p6_review._next_correction_kind([contract], contract) is None
    assert p6_review._next_correction_kind([grounding], contract) is None
    assert p6_review._next_correction_kind([grounding], grounding) is None
    assert p6_review._next_correction_kind([contract, grounding], contract) is None


def test_codex_failed_turn_usage_is_counted_before_one_transport_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    executable = tmp_path / "codex"
    executable.write_bytes(b"sealed independent reviewer")
    executable.chmod(0o500)
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(
        p6_review,
        "_resolve_reviewer_executable",
        lambda _role, *, search_path: (executable.resolve(), executable_sha),
    )
    monkeypatch.setattr(p6_review, "_untrusted_reviewer_roots", lambda: ())
    invocation_count = 0

    def run(command: list[str], **kwargs: object) -> object:
        nonlocal invocation_count
        if len(command) == 2 and command[1] == "--version":
            return type(
                "Result",
                (),
                {"returncode": 0, "stdout": "codex-cli 0.144.4\n", "stderr": ""},
            )()
        invocation_count += 1
        if invocation_count == 1:
            return type(
                "Result",
                (),
                {
                    "returncode": 1,
                    "stdout": json.dumps(
                        {
                            "type": "turn.failed",
                            "usage": {"input_tokens": 31, "output_tokens": 7},
                        }
                    ),
                    "stderr": "answer-free transport failure",
                },
            )()
        cwd = Path(str(kwargs["cwd"]))
        (cwd / "codex-last-message.json").write_text(
            json.dumps(_decision(packet, role)), encoding="utf-8"
        )
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {"input_tokens": 41, "output_tokens": 9},
                    }
                ),
                "stderr": "",
            },
        )()

    monkeypatch.setattr(p6_review.subprocess, "run", run)
    output_dir = tmp_path / "output"
    p6_review.run_reviewer(
        role=role,
        packet_path=packet_path,
        output_dir=output_dir,
        material_root=Path.cwd(),
    )
    raw = json.loads((output_dir / "raw-envelope.json").read_text(encoding="utf-8"))
    calls = raw["reviewer_usage"]["calls"]
    assert invocation_count == 2
    assert [call["attribution"] for call in calls] == ["initial", "transport_retry"]
    assert [call["total_tokens"] for call in calls] == [38, 50]
    assert all(call["model_observation_source"] == "sealed_command" for call in calls)
    validate_review_artifact(output_dir=output_dir, packet_path=packet_path, role=role)


def test_codex_failed_turn_without_usage_fails_closed_before_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    executable = tmp_path / "codex"
    executable.write_bytes(b"sealed independent reviewer")
    executable.chmod(0o500)
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(
        p6_review,
        "_resolve_reviewer_executable",
        lambda _role, *, search_path: (executable.resolve(), executable_sha),
    )
    monkeypatch.setattr(p6_review, "_untrusted_reviewer_roots", lambda: ())
    invocation_count = 0

    def run(command: list[str], **_kwargs: object) -> object:
        nonlocal invocation_count
        if len(command) == 2 and command[1] == "--version":
            return type(
                "Result",
                (),
                {"returncode": 0, "stdout": "codex-cli 0.144.4\n", "stderr": ""},
            )()
        invocation_count += 1
        return type(
            "Result",
            (),
            {
                "returncode": 1,
                "stdout": json.dumps({"type": "turn.failed", "error": "redacted"}),
                "stderr": "answer-free transport failure",
            },
        )()

    monkeypatch.setattr(p6_review.subprocess, "run", run)
    with pytest.raises(P6ProtocolError, match="provider usage"):
        p6_review.run_reviewer(
            role=role,
            packet_path=packet_path,
            output_dir=tmp_path / "output",
            material_root=Path.cwd(),
        )
    assert invocation_count == 1


def test_reviewer_runs_contract_then_optional_grounding_correction_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    executable = tmp_path / "reviewer"
    executable.write_bytes(b"sealed independent reviewer")
    executable.chmod(0o500)
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setenv(
        p6_review._REVIEWER_CREDENTIAL_ENV[role],
        "independent-reviewer-key-canary-unique",
    )
    monkeypatch.setattr(
        p6_review,
        "_resolve_reviewer_executable",
        lambda _role, *, search_path: (executable.resolve(), executable_sha),
    )
    monkeypatch.setattr(p6_review, "_untrusted_reviewer_roots", lambda: ())

    bad_grounding = _decision(packet, role)
    bad_grounding["checks"][-1]["artifact_sha256"] = "f" * 64
    review_outputs = iter(
        ("not-json", json.dumps(bad_grounding), json.dumps(_decision(packet, role)))
    )
    review_inputs: list[str | None] = []

    def run(command: list[str], **kwargs: object) -> object:
        if len(command) == 2 and command[1] == "--version":
            return type(
                "Result",
                (),
                {"returncode": 0, "stdout": "codex-cli 0.144.4\n", "stderr": ""},
            )()
        review_inputs.append(kwargs.get("input") if isinstance(kwargs.get("input"), str) else None)
        return _review_process_result(role, next(review_outputs))

    monkeypatch.setattr(p6_review.subprocess, "run", run)
    output_dir = tmp_path / "output"
    p6_review.run_reviewer(
        role=role,
        packet_path=packet_path,
        output_dir=output_dir,
        material_root=Path.cwd(),
    )

    raw = json.loads((output_dir / "raw-envelope.json").read_text(encoding="utf-8"))
    assert [row["kind"] for row in raw["bounded_correction"]] == [
        "contract_regeneration",
        "grounding_correction",
    ]
    assert len(review_inputs) == 3
    assert "frozen decision contract" in review_inputs[1]
    assert "role-packet grounding" in review_inputs[2]


def test_contract_regeneration_rejects_changes_to_locked_material_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    executable = tmp_path / "reviewer"
    executable.write_bytes(b"sealed independent reviewer")
    executable.chmod(0o500)
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(
        p6_review,
        "_resolve_reviewer_executable",
        lambda _role, *, search_path: (executable.resolve(), executable_sha),
    )
    monkeypatch.setattr(p6_review, "_untrusted_reviewer_roots", lambda: ())

    prior = _decision(packet, role)
    prior["model"] = "wrong-envelope-model"
    changed = _decision(packet, role)
    material_sha = packet["artifact_files"][1]["sha256"]
    changed["decision"] = "changes_required"
    changed["blocker_count"] = 1
    changed["blockers"] = [
        {"code": "benchmark_protocol_violation", "artifact_sha256": material_sha}
    ]
    changed["checks"][0]["result"] = "fail"
    outputs = iter((json.dumps(prior), json.dumps(changed)))

    def run(command: list[str], **_kwargs: object) -> object:
        stdout = (
            "codex-cli 0.144.4\n"
            if len(command) == 2 and command[1] == "--version"
            else next(outputs)
        )
        return (
            type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()
            if len(command) == 2 and command[1] == "--version"
            else _review_process_result(role, stdout)
        )

    monkeypatch.setattr(p6_review.subprocess, "run", run)
    with pytest.raises(P6ProtocolError, match="changed substantive fields"):
        p6_review.run_reviewer(
            role=role,
            packet_path=packet_path,
            output_dir=tmp_path / "output",
            material_root=Path.cwd(),
        )


def test_grounding_correction_rejects_non_grounding_material_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    executable = tmp_path / "reviewer"
    executable.write_bytes(b"sealed independent reviewer")
    executable.chmod(0o500)
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(
        p6_review,
        "_resolve_reviewer_executable",
        lambda _role, *, search_path: (executable.resolve(), executable_sha),
    )
    monkeypatch.setattr(p6_review, "_untrusted_reviewer_roots", lambda: ())

    prior = _decision(packet, role)
    prior["checks"][-1]["artifact_sha256"] = "f" * 64
    changed = _decision(packet, role)
    changed["checks"][0]["result"] = "fail"
    outputs = iter((json.dumps(prior), json.dumps(changed)))

    def run(command: list[str], **_kwargs: object) -> object:
        stdout = (
            "codex-cli 0.144.4\n"
            if len(command) == 2 and command[1] == "--version"
            else next(outputs)
        )
        return (
            type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()
            if len(command) == 2 and command[1] == "--version"
            else _review_process_result(role, stdout)
        )

    monkeypatch.setattr(p6_review.subprocess, "run", run)
    with pytest.raises(P6ProtocolError, match="changed substantive fields"):
        p6_review.run_reviewer(
            role=role,
            packet_path=packet_path,
            output_dir=tmp_path / "output",
            material_root=Path.cwd(),
        )


@pytest.mark.parametrize(
    "kinds",
    (
        ("grounding_correction", "contract_regeneration"),
        ("contract_regeneration", "contract_regeneration"),
        ("grounding_correction", "grounding_correction"),
    ),
)
def test_raw_validator_rejects_illegal_bounded_correction_order(
    tmp_path: Path, kinds: tuple[str, ...]
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    output_dir = tmp_path / "review"
    _write_review_artifact(packet_path, output_dir, role)
    _set_correction_records(packet_path, output_dir, role, kinds)

    with pytest.raises(P6ProtocolError, match="correction order"):
        validate_review_artifact(
            output_dir=output_dir,
            packet_path=packet_path,
            role=role,
        )


def test_raw_validator_binds_correction_sequence_projection_and_prompt_hashes(
    tmp_path: Path,
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    output_dir = tmp_path / "review"
    _write_review_artifact(packet_path, output_dir, role)
    raw = _set_correction_records(
        packet_path,
        output_dir,
        role,
        ("contract_regeneration", "grounding_correction"),
    )

    validate_review_artifact(output_dir=output_dir, packet_path=packet_path, role=role)

    raw["bounded_correction"][1]["correction_prompt_sha256"] = "f" * 64
    (output_dir / "raw-envelope.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="correction prompt binding"):
        validate_review_artifact(
            output_dir=output_dir,
            packet_path=packet_path,
            role=role,
        )


def test_raw_validator_rejects_rewritten_prior_material_projection(
    tmp_path: Path,
) -> None:
    role = "independent_benchmark"
    packet_path = _write_role_packet(tmp_path / "packet", role)
    output_dir = tmp_path / "review"
    _write_review_artifact(packet_path, output_dir, role)
    raw = _set_correction_records(
        packet_path,
        output_dir,
        role,
        ("contract_regeneration",),
    )

    projection = raw["bounded_correction"][0]["locked_projection"]
    projection["decision"]["value"] = "changes_required"
    raw["bounded_correction"][0]["locked_projection_sha256"] = canonical_sha256(projection)
    (output_dir / "raw-envelope.json").write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(P6ProtocolError, match="changed substantive fields"):
        validate_review_artifact(
            output_dir=output_dir,
            packet_path=packet_path,
            role=role,
        )


def test_secret_canary_is_rejected_from_every_persisted_review_object() -> None:
    credential = "p6-role-credential-canary-that-must-never-be-persisted"
    persisted_objects = (
        {"artifact_files": [{"content": f"packet:{credential}"}]},
        {"decision": f"decision:{credential}"},
        {"stdout": f"raw:{credential}"},
    )

    for persisted in persisted_objects:
        with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
            p6_review._assert_role_credential_absent(persisted, credential=credential)


@pytest.mark.parametrize(
    ("role", "stdout"),
    (
        ("product_architecture", "2.1.233 (Claude Code)\n"),
        ("proof_security", "0.1.0-rc.6\n"),
        ("independent_benchmark", "codex-cli 0.144.4\n"),
    ),
)
def test_reviewer_version_probe_accepts_only_the_exact_harness_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    stdout: str,
) -> None:
    executable = tmp_path / "reviewer"
    executable.write_text("frozen reviewer", encoding="utf-8")
    executable.chmod(0o700)
    observed_commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> object:
        observed_commands.append(command)
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr(p6_review.subprocess, "run", run)
    monkeypatch.setenv(p6_review._REVIEWER_CREDENTIAL_ENV[role], f"{role}-version-probe-credential")
    _configure_route(monkeypatch, tmp_path, role)
    environment = p6_review._reviewer_environment(role, temp_root=tmp_path / role)

    assert p6_review._probe_reviewer_version(
        role,
        executable=executable.resolve(),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        environment=environment,
    ) == (p6_review.FROZEN_REVIEWER_IDENTITIES[role]["harness_version"])
    assert observed_commands == [[str(executable.resolve()), "--version"]]

    bad = stdout.strip() + " unbound"
    monkeypatch.setattr(
        p6_review.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Result", (), {"returncode": 0, "stdout": bad, "stderr": ""}
        )(),
    )
    with pytest.raises(P6ProtocolError, match="review_binding_invalid"):
        p6_review._probe_reviewer_version(
            role,
            executable=executable.resolve(),
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            environment=environment,
        )
