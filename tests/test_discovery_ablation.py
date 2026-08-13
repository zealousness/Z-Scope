from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from zscope.benchmarking.discovery_ablation import (
    ABLATION_ARM_IDS,
    ABLATION_EXPECTED_MAX_TOKENS,
    DiscoveryAblationError,
    DiscoveryAblationRuntimeOverride,
    build_discovery_ablation_plan,
    build_discovery_ablation_run_request,
    discovery_ablation_runtime_override,
    discovery_ablation_runtime_override_from_request,
    execute_discovery_ablation_request,
    load_discovery_ablation_catalog,
    validate_discovery_ablation_plan,
    validate_discovery_ablation_run_request,
)
from zscope.benchmarking.validator_replay import load_validator_arm_catalog, validator_arm
from zscope.benchmarking.protocol import _build_release_evidence, _release_trial_errors
from zscope.orchestration.active_discovery import (
    ActiveDiscoveryCoordinator,
    CoverageGapPlanner,
    DISCOVERY_PROFILES,
)
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer


SHA = "a" * 64


def _write_json(path: Path, value: Mapping[str, Any]) -> Path:
    path.write_text(json.dumps(dict(value), ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_usage_sidecar(path: Path, *, provider_reported: bool = True) -> Path:
    attribution = {
        "schema_version": "zscope.llm-usage-attribution.v1",
        "stage": "validation",
        "agent": "validator_agent",
        "skill": "",
        "entry_identity": "",
        "audit_unit_uid": "",
        "candidate_uid": "candidate-1",
        "finding_uid": "",
        "validation_cluster_uid": "cluster-1",
        "llm_ref": "validation",
        "call_kind": "initial_decision",
    }
    event = {
        "schema_version": "zscope.llm-usage-event.v1",
        "sequence": 1,
        "call_id": "reservation-1",
        "reservation_id": "reservation-1",
        "agent": "validator_agent",
        "stage": "validation",
        "candidate_uid": "candidate-1",
        "audit_unit_uid": "",
        "validation_cluster_uid": "cluster-1",
        "llm_ref": "validation",
        "call_kind": "initial_decision",
        "outcome": "success",
        "prompt_tokens": 8_000_000,
        "completion_tokens": 1_000_000,
        "total_tokens": 9_000_000,
        "reserved_total_tokens": 9_000_000,
        "provider_reported": provider_reported,
        "conservative_charge": False,
        "budget_violation": False,
        "attribution": attribution,
        "budget_stage": "validation",
        "model": "glm-5.1",
        "reason": "",
        "finish_reason": "stop",
        "cached_prompt_tokens": 0,
        "reasoning_tokens": 0,
        "retry": False,
        "repair": False,
        "tool_call_count": 0,
        "new_fact_count": 0,
        "duration_ms": 1,
    }
    path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _plan_inputs(tmp_path: Path) -> dict[str, Any]:
    validator_catalog = load_validator_arm_catalog()
    selected_validator = validator_arm(validator_catalog, "C")
    manifest = _write_json(
        tmp_path / "input-manifest.json",
        {
            "schema_version": "zscope.answer-free-project-manifest.v1",
            "files": [{"path": "src/main.c", "sha256": SHA}],
        },
    )
    config = tmp_path / "zscope.yaml"
    config.write_text(
        "config_version: 2\n"
        "project:\n"
        "  language: c_cpp\n"
        "  root: /zscope-input\n"
        "scan:\n"
        "  depth: balanced\n"
        "  expected_max_tokens: 12000000\n"
        "llms:\n"
        "  default:\n"
        "    model: glm-5.1\n",
        encoding="utf-8",
    )
    runtime = tmp_path / "runtime.yaml"
    runtime.write_text(
        "runtime_spec_version: 1\nanalysis:\n  max_recursion_depth: 3\n",
        encoding="utf-8",
    )
    model = _write_json(
        tmp_path / "model.json",
        {"schema_version": "zscope.model-spec.v1", "model": "glm-5.1"},
    )
    prompt_bundle_sha256 = "f" * 64
    validator = _write_json(
        tmp_path / "validator.json",
        {
            "schema_version": "zscope.fixed-validator-config.v1",
            "selected_arm": "C",
            "validator_protocol_version": "zscope.validator-protocol.v3",
            "validator_result_schema_version": "zscope.validator-result.v3",
            "validator_arm_catalog_sha256": validator_catalog["catalog_sha256"],
            "validator_arm_spec_sha256": selected_validator["arm_spec_sha256"],
            "validation_model_spec_sha256": _sha256(model),
            "validation_prompt_sha256": prompt_bundle_sha256,
        },
    )
    return {
        "dataset_id": "public-external-frozen-2026q3",
        "answer_free_manifest": manifest,
        "expected_answer_free_manifest_sha256": _sha256(manifest),
        "config": config,
        "runtime_spec": runtime,
        "validator_config": validator,
        "model_spec": model,
        "scanner_bundle_sha256": "d" * 64,
        "rule_catalog_sha256": "e" * 64,
        "prompt_bundle_sha256": prompt_bundle_sha256,
        "production_executor_sha256": "1" * 64,
        "legacy_executor_sha256": "2" * 64,
    }


def _build_plan(tmp_path: Path) -> dict[str, Any]:
    return build_discovery_ablation_plan(**_plan_inputs(tmp_path))


def test_catalog_freezes_exact_d0_d4_stage_contracts() -> None:
    catalog = load_discovery_ablation_catalog()

    assert [arm["arm_id"] for arm in catalog["arms"]] == list(ABLATION_ARM_IDS)
    assert catalog["expected_max_tokens"] == ABLATION_EXPECTED_MAX_TOKENS
    assert catalog["trials_per_arm"] == 5
    assert catalog["arms"][1]["semantic_enrichment_mode"] == "active"
    assert catalog["arms"][1]["active_discovery_mode"] == "disabled"
    assert catalog["arms"][2]["semantic_enrichment_mode"] == "disabled"
    assert catalog["arms"][2]["active_discovery_mode"] == "active"
    assert catalog["arms"][4]["execution_path"] == "external_legacy_full_entry"
    assert all(arm["release_eligible"] is False for arm in catalog["arms"])


def test_plan_is_answer_free_hash_bound_and_schedules_25_cold_runs(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)

    validate_discovery_ablation_plan(plan)
    assert plan["answer_material_present"] is False
    assert plan["release_eligible"] is False
    assert plan["fixed_contract"]["expected_max_tokens"] == 12_000_000
    assert plan["fixed_contract"]["cold_trials_per_arm"] == 5
    assert sum(len(arm["runs"]) for arm in plan["arms"]) == 25
    assert {run["cache_mode"] for arm in plan["arms"] for run in arm["runs"]} == {"isolated_cold"}
    assert len(plan["plan_sha256"]) == 64


def test_plan_rejects_truth_fields_and_truth_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _plan_inputs(tmp_path)
    manifest = inputs["answer_free_manifest"]
    _write_json(manifest, {"schema_version": "x", "ground_truth": [{"id": "T1"}]})
    inputs["expected_answer_free_manifest_sha256"] = _sha256(manifest)
    with pytest.raises(DiscoveryAblationError, match="forbidden field"):
        build_discovery_ablation_plan(**inputs)

    inputs = _plan_inputs(tmp_path)
    monkeypatch.setenv("Z_SCOPE_BENCHMARK_TRUTH", str(tmp_path / "truth.json"))
    with pytest.raises(DiscoveryAblationError, match="truth-bearing environment"):
        build_discovery_ablation_plan(**inputs)


def test_plan_rejects_unbound_validator_model_or_prompt(tmp_path: Path) -> None:
    inputs = _plan_inputs(tmp_path)
    validator_path = inputs["validator_config"]
    validator = json.loads(validator_path.read_text(encoding="utf-8"))
    validator["validation_model_spec_sha256"] = "9" * 64
    _write_json(validator_path, validator)
    with pytest.raises(DiscoveryAblationError, match="model SHA-256"):
        build_discovery_ablation_plan(**inputs)

    inputs = _plan_inputs(tmp_path)
    validator_path = inputs["validator_config"]
    validator = json.loads(validator_path.read_text(encoding="utf-8"))
    validator["validation_prompt_sha256"] = "8" * 64
    _write_json(validator_path, validator)
    with pytest.raises(DiscoveryAblationError, match="prompt SHA-256"):
        build_discovery_ablation_plan(**inputs)


def test_request_and_runtime_override_are_hash_bound_and_d4_external(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    request = build_discovery_ablation_run_request(
        plan,
        arm_id="D2",
        trial_index=3,
        expected_plan_sha256=plan["plan_sha256"],
    )
    validate_discovery_ablation_run_request(request)
    override = discovery_ablation_runtime_override(
        plan,
        arm_id="D2",
        expected_plan_sha256=plan["plan_sha256"],
    )
    assert override.semantic_map_enabled is True
    assert override.semantic_enrichment_enabled is False
    assert override.active_discovery_enabled is True
    assert override.report_metadata()["release_eligible"] is False
    assert override.report_metadata()["validator_selected_arm"] == "C"
    assert len(override.report_metadata()["validator_arm_spec_sha256"]) == 64
    with pytest.raises(TypeError, match="factory-only"):
        DiscoveryAblationRuntimeOverride()

    d4 = discovery_ablation_runtime_override(
        plan,
        arm_id="D4",
        expected_plan_sha256=plan["plan_sha256"],
    )
    with pytest.raises(DiscoveryAblationError, match="external legacy"):
        d4.require_in_process_supported()

    request["trial"]["expected_max_tokens"] = 12_000_001
    with pytest.raises(DiscoveryAblationError):
        validate_discovery_ablation_run_request(request)


def test_request_runtime_binds_unique_cold_identity_and_rejects_reuse(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    first_request = build_discovery_ablation_run_request(
        plan,
        arm_id="D1",
        trial_index=1,
        expected_plan_sha256=plan["plan_sha256"],
    )
    second_request = build_discovery_ablation_run_request(
        plan,
        arm_id="D1",
        trial_index=2,
        expected_plan_sha256=plan["plan_sha256"],
    )
    first = discovery_ablation_runtime_override_from_request(first_request)
    second = discovery_ablation_runtime_override_from_request(second_request)
    assert first.cold_snapshot_identity_sha256 != second.cold_snapshot_identity_sha256
    assert first.cold_cache_identity_sha256 != second.cold_cache_identity_sha256

    snapshot = tmp_path / "already-used-snapshots"
    snapshot.mkdir()
    config = SimpleNamespace(
        scan=SimpleNamespace(depth="balanced", expected_max_tokens=12_000_000),
        analysis=SimpleNamespace(snapshot_dir=str(snapshot), user_config_db=""),
        indexing=SimpleNamespace(knowledge_db_path=str(tmp_path / "fresh.db")),
    )
    with pytest.raises(DiscoveryAblationError, match="must not already exist"):
        first.attest_cold_runtime(config, resume=False, maintain=False)
    config.analysis.snapshot_dir = str(tmp_path / "fresh-snapshots")
    with pytest.raises(DiscoveryAblationError, match="forbids resume"):
        first.attest_cold_runtime(config, resume=True, maintain=False)


def test_live_validator_queue_is_bounded_by_frozen_selected_arm(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)

    class Runner:
        def _assign_v3_investigation_budget(self, prepared: Any) -> str:
            return "v3-enabled"

        def _run_v3_evidence_recheck(self, *_args: Any) -> str:
            return "v2-enabled"

    c_request = build_discovery_ablation_run_request(
        plan,
        arm_id="D1",
        trial_index=1,
        expected_plan_sha256=plan["plan_sha256"],
    )
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer._benchmark_ablation_override = discovery_ablation_runtime_override_from_request(
        c_request
    )
    runner = Runner()
    analyzer._bind_ablation_validator_policy(runner)
    prepared = [object()]
    assert runner._assign_v3_investigation_budget(prepared) is prepared
    assert runner._run_v3_evidence_recheck(None) == "v2-enabled"

    object.__setattr__(analyzer._benchmark_ablation_override, "validator_selected_arm", "B")
    runner = Runner()
    analyzer._bind_ablation_validator_policy(runner)
    assert runner._assign_v3_investigation_budget(prepared) is prepared
    assert runner._run_v3_evidence_recheck(None, None, {"pass": "initial"}, {}) == {
        "pass": "initial"
    }


class _Executor:
    def __init__(self, usage_sidecar: Path, storage_root: Path):
        self.usage_sidecar = usage_sidecar
        self.storage_root = storage_root

    def execute(
        self,
        request: Mapping[str, Any],
        override: DiscoveryAblationRuntimeOverride,
    ) -> Mapping[str, Any]:
        runtime_config = SimpleNamespace(
            scan=SimpleNamespace(depth="balanced", expected_max_tokens=12_000_000),
            analysis=SimpleNamespace(
                snapshot_dir=str(self.storage_root / f"{request['trial']['run_id']}-snapshots"),
                user_config_db="",
            ),
            indexing=SimpleNamespace(
                knowledge_db_path=str(
                    self.storage_root / f"{request['trial']['run_id']}-knowledge.db"
                )
            ),
        )
        override.attest_cold_runtime(runtime_config, resume=False, maintain=False)
        return {
            "schema_version": "zscope.report.v2",
            "completeness": "complete",
            "answer_material_present": False,
            "release_eligible": False,
            "formal_eligible": False,
            "metadata": {
                "benchmark_ablation": override.report_metadata(),
                "effective_scan": {
                    "depth": "balanced",
                    "expected_max_tokens": 12_000_000,
                },
                "llm_usage": {
                    "expected_max_tokens": 12_000_000,
                    "consumed_tokens": 9_000_000,
                    "reserved_tokens": 0,
                    "cost_expectation_met": True,
                    "usage_events_path": str(self.usage_sidecar),
                },
            },
            "issues": [],
        }


def test_execution_adapter_validates_report_and_remains_release_ineligible(
    tmp_path: Path,
) -> None:
    plan = _build_plan(tmp_path)
    request = build_discovery_ablation_run_request(
        plan,
        arm_id="D3",
        trial_index=1,
        expected_plan_sha256=plan["plan_sha256"],
    )
    usage_sidecar = _write_usage_sidecar(tmp_path / "llm_usage_events.jsonl")

    report, execution = execute_discovery_ablation_request(
        request,
        executor=_Executor(usage_sidecar, tmp_path),
        expected_request_sha256=request["request_sha256"],
        usage_sidecar_path=usage_sidecar,
    )

    assert report["metadata"]["benchmark_ablation"]["arm_id"] == "D3"
    assert execution["report_contract"]["consumed_tokens"] == 9_000_000
    assert execution["release_eligible"] is False
    assert execution["formal_eligible"] is False
    assert execution["answer_free_attested"] is False
    assert execution["report_contract"]["raw_usage_evidence"]["provider_usage_coverage"] == 1.0


def test_execution_adapter_rejects_usage_mismatch_or_truth_material(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    request = build_discovery_ablation_run_request(
        plan,
        arm_id="D0",
        trial_index=1,
        expected_plan_sha256=plan["plan_sha256"],
    )
    usage_sidecar = _write_usage_sidecar(tmp_path / "llm_usage_events.jsonl")

    class Broken(_Executor):
        def execute(
            self,
            request: Mapping[str, Any],
            override: DiscoveryAblationRuntimeOverride,
        ) -> Mapping[str, Any]:
            report = dict(super().execute(request, override))
            report["metadata"]["llm_usage"]["consumed_tokens"] = 12_000_001
            return report

    with pytest.raises(DiscoveryAblationError, match="does not conserve"):
        execute_discovery_ablation_request(
            request,
            executor=Broken(usage_sidecar, tmp_path),
            expected_request_sha256=request["request_sha256"],
            usage_sidecar_path=usage_sidecar,
        )

    class TruthLeaking(_Executor):
        def execute(
            self,
            request: Mapping[str, Any],
            override: DiscoveryAblationRuntimeOverride,
        ) -> Mapping[str, Any]:
            report = dict(super().execute(request, override))
            report["ground_truth"] = {"T1": "vulnerable"}
            return report

    with pytest.raises(DiscoveryAblationError, match="truth material"):
        execute_discovery_ablation_request(
            request,
            executor=TruthLeaking(usage_sidecar, tmp_path),
            expected_request_sha256=request["request_sha256"],
            usage_sidecar_path=usage_sidecar,
        )


def test_execution_rejects_non_provider_usage_and_missing_report_markers(tmp_path: Path) -> None:
    plan = _build_plan(tmp_path)
    request = build_discovery_ablation_run_request(
        plan,
        arm_id="D0",
        trial_index=1,
        expected_plan_sha256=plan["plan_sha256"],
    )
    usage_sidecar = _write_usage_sidecar(
        tmp_path / "llm_usage_events.jsonl", provider_reported=False
    )
    with pytest.raises(DiscoveryAblationError, match="complete provider usage"):
        execute_discovery_ablation_request(
            request,
            executor=_Executor(usage_sidecar, tmp_path),
            expected_request_sha256=request["request_sha256"],
            usage_sidecar_path=usage_sidecar,
        )

    _write_usage_sidecar(usage_sidecar)

    class MissingMarkers(_Executor):
        def execute(
            self,
            request: Mapping[str, Any],
            override: DiscoveryAblationRuntimeOverride,
        ) -> Mapping[str, Any]:
            report = dict(super().execute(request, override))
            report.pop("answer_material_present")
            return report

    with pytest.raises(DiscoveryAblationError, match="explicitly"):
        execute_discovery_ablation_request(
            request,
            executor=MissingMarkers(usage_sidecar, tmp_path),
            expected_request_sha256=request["request_sha256"],
            usage_sidecar_path=usage_sidecar,
        )


def test_formal_release_rejects_ablation_report() -> None:
    report = {
        "metadata": {"benchmark_ablation": {"arm_id": "D3"}},
        "summary": {},
        "run_manifest": {},
    }
    summary = {
        "run_kind": "formal",
        "release_evidence": _build_release_evidence(report),
    }

    assert any(
        "ablation artifacts are not release eligible" in error
        for error in _release_trial_errors(summary)
    )


def test_package_module_cli_fails_closed_for_formal_oci_mode(tmp_path: Path) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "run_discovery_ablation_request.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--execution-mode",
            "formal-rootless-oci",
            "--oci-image",
            "registry.example/zscope@sha256:" + "a" * 64,
            "--request",
            str(tmp_path / "request.json"),
            "--expected-request-sha256",
            "b" * 64,
            "--executor-sha256",
            "c" * 64,
            "--usage-sidecar",
            str(tmp_path / "usage.jsonl"),
            "--report-output",
            str(tmp_path / "report.json"),
            "--execution-output",
            str(tmp_path / "execution.json"),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 2
    assert "RootlessOciExecutor" in completed.stderr
    assert not (tmp_path / "report.json").exists()


def test_semantic_only_coordinator_never_loads_cached_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = SimpleNamespace(unit_id="AU-1")
    semantic_map = SimpleNamespace(
        map_fingerprint="m" * 64,
        coverage={},
        functions={},
        claims=(),
        unknowns=(),
        with_audit_units=lambda units: semantic_map,
    )

    class Store:
        def save_map(self, value: Any) -> None:
            assert value is semantic_map

    class Registrar:
        pass

    monkeypatch.setattr(CoverageGapPlanner, "plan", lambda *_args, **_kwargs: [unit])
    coordinator = ActiveDiscoveryCoordinator(
        profile=DISCOVERY_PROFILES["balanced"],
        store=Store(),  # type: ignore[arg-type]
        registrar=Registrar(),  # type: ignore[arg-type]
        report_runner=lambda *_args: pytest.fail("discovery runner must not execute"),
        discovery_enabled=False,
    )
    monkeypatch.setattr(
        coordinator,
        "_load_cached",
        lambda *_args: pytest.fail("cached discovery must not load"),
    )

    _planned, state = coordinator.run(semantic_map)

    assert state["status"] == "semantic_only"
    assert state["discovery_enabled"] is False
    assert state["attempted_unit_count"] == 0
    assert state["cached_report_count"] == 0
