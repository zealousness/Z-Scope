from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

import zscope.benchmarking.discovery_ablation_experiment as experiment_module
from zscope.benchmarking.discovery_ablation import (
    ABLATION_ARM_IDS,
    DiscoveryAblationRuntimeOverride,
    build_discovery_ablation_plan,
    build_discovery_ablation_run_request,
    execute_discovery_ablation_request,
    write_discovery_ablation_plan,
)
from zscope.benchmarking.discovery_ablation_experiment import (
    DiscoveryAblationExperimentError,
    load_discovery_ablation_experiment,
    score_discovery_ablation_experiment,
    validate_discovery_ablation_experiment,
    write_discovery_ablation_experiment,
)
from zscope.benchmarking.replay_bundle import canonical_json_sha256
from zscope.benchmarking.validator_replay import load_validator_arm_catalog, validator_arm
from zscope.framework.llm_usage import LLMUsageAttribution, LLMUsageEvent


SHA = "a" * 64


def _write_json(path: Path, value: Mapping[str, Any]) -> Path:
    path.write_text(
        json.dumps(dict(value), ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_plan(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
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
        "  expected_max_tokens: 12000000\n",
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
    validator = _write_json(
        tmp_path / "validator.json",
        {
            "schema_version": "zscope.fixed-validator-config.v1",
            "selected_arm": "C",
            "validator_protocol_version": "zscope.validator-protocol.v3",
            "validator_result_schema_version": "zscope.validator-result.v3",
            "validator_arm_catalog_sha256": validator_catalog["catalog_sha256"],
            "validator_arm_spec_sha256": selected_validator["arm_spec_sha256"],
            "validation_model_spec_sha256": _file_sha(model),
            "validation_prompt_sha256": "f" * 64,
        },
    )
    plan = build_discovery_ablation_plan(
        dataset_id="unit-ablation-frozen-v1",
        answer_free_manifest=manifest,
        config=config,
        runtime_spec=runtime,
        validator_config=validator,
        model_spec=model,
        scanner_bundle_sha256="d" * 64,
        rule_catalog_sha256="e" * 64,
        prompt_bundle_sha256="f" * 64,
        production_executor_sha256="1" * 64,
        legacy_executor_sha256="2" * 64,
        expected_answer_free_manifest_sha256=_file_sha(manifest),
    )
    plan_path = tmp_path / "plan.json"
    write_discovery_ablation_plan(plan_path, plan)
    return plan, plan_path


def _attribution(source: str, *, decided_by: str = "validator_llm") -> dict[str, Any]:
    return {
        "schema_version": "zscope.finding-attribution.v1",
        "discovered_by": [source],
        "discovery_details": [],
        "decided_by": decided_by,
        "decision_level": "V1" if decided_by == "validator_llm" else "V0",
    }


def _issues() -> tuple[dict[str, Any], dict[str, Any]]:
    confirmed = {
        "category": "memory_leak",
        "function": "leaky",
        "location": "src/demo.c:10",
        "description": "memory leak on error path",
        "attribution": {
            **_attribution("deterministic_rule", decided_by="deterministic_proof"),
            "discovered_by": ["deterministic_rule", "backend_signal"],
        },
    }
    review = {
        "category": "use_after_free",
        "function": "uaf",
        "location": "src/demo.c:41",
        "description": "use after free after cleanup",
        "needs_review": True,
        "attribution": _attribution("llm_active_discovery"),
    }
    return confirmed, review


def _usage_row() -> dict[str, int]:
    return {
        "request_count": 1,
        "successful_calls": 1,
        "denied_requests": 0,
        "failed_or_unknown_calls": 0,
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "total_tokens": 120,
        "provider_reported_calls": 1,
        "estimated_or_conservative_calls": 0,
        "budget_violation_count": 0,
        "cached_prompt_tokens": 10,
        "reasoning_tokens": 5,
        "retry_count": 0,
        "repair_count": 0,
        "tool_call_count": 0,
        "new_fact_count": 0,
        "duration_ms": 1,
    }


class _Executor:
    def __init__(self, root: Path, usage_path: Path) -> None:
        self.root = root
        self.usage_path = usage_path

    def execute(
        self,
        request: Mapping[str, Any],
        override: DiscoveryAblationRuntimeOverride,
    ) -> Mapping[str, Any]:
        run_id = str(request["trial"]["run_id"])
        config = SimpleNamespace(
            scan=SimpleNamespace(depth="balanced", expected_max_tokens=12_000_000),
            analysis=SimpleNamespace(
                snapshot_dir=self.root / f"snapshot-{run_id}",
                user_config_db="",
            ),
            indexing=SimpleNamespace(knowledge_db_path=self.root / f"knowledge-{run_id}.db"),
        )
        override.attest_cold_runtime(config, resume=False, maintain=False)
        confirmed, review = _issues()
        usage = _usage_row()
        return {
            "schema_version": "zscope.report.v2",
            "answer_material_present": False,
            "release_eligible": False,
            "formal_eligible": False,
            "completeness": "complete",
            "metadata": {
                "benchmark_ablation": override.report_metadata(),
                "effective_scan": {
                    "depth": "balanced",
                    "expected_max_tokens": 12_000_000,
                },
                "llm_usage": {
                    "expected_max_tokens": 12_000_000,
                    "consumed_tokens": 120,
                    "reserved_tokens": 0,
                    "cost_expectation_met": True,
                    "usage_events_path": str(self.usage_path.resolve()),
                    "usage_attribution": {
                        "telemetry_complete": True,
                        "totals": usage,
                        "by_agent": {"validator_agent": usage},
                        "by_stage": {"validation": usage},
                        "by_finish_reason": {"stop": usage},
                    },
                },
            },
            "issues": [confirmed],
            "report_views": {
                "default": {"issues": [confirmed]},
                "with_needs_review": {"issues": [confirmed, review]},
            },
        }


def _truth() -> dict[str, Any]:
    return {
        "benchmark": "unit_suite",
        "suite": "unit",
        "dataset_id": "unit-ablation-frozen-v1",
        "version": "1",
        "total_vulnerabilities": 2,
        "vulnerabilities": [
            {
                "id": "BUG-1",
                "category": "memory_leak",
                "function": "leaky",
                "file": "src/demo.c",
                "line": 10,
            },
            {
                "id": "BUG-2",
                "category": "use_after_free",
                "function": "uaf",
                "file": "src/demo.c",
                "line": 40,
            },
        ],
        "safe_entries": [{"function": "safe"}],
    }


def _matrix(tmp_path: Path) -> dict[str, Any]:
    plan, plan_path = _build_plan(tmp_path)
    executions = {}
    reports = {}
    expected_executions = {}
    expected_reports = {}
    expected_execution_files = {}
    expected_report_files = {}
    usage_sidecars = {}
    expected_usage_sidecars = {}
    for arm_id in ABLATION_ARM_IDS:
        for trial_index in range(1, 6):
            key = (arm_id, trial_index)
            request = build_discovery_ablation_run_request(
                plan,
                arm_id=arm_id,
                trial_index=trial_index,
                expected_plan_sha256=plan["plan_sha256"],
            )
            usage_path = tmp_path / f"{arm_id}-{trial_index}-usage.jsonl"
            usage_event = LLMUsageEvent(
                sequence=1,
                reservation_id=f"{request['trial']['run_id']}-call-1",
                outcome="success",
                prompt_tokens=100,
                completion_tokens=20,
                total_tokens=120,
                reserved_total_tokens=120,
                provider_reported=True,
                conservative_charge=False,
                budget_violation=False,
                attribution=LLMUsageAttribution(
                    stage="validation",
                    agent="validator_agent",
                    candidate_uid="candidate-1",
                    validation_cluster_uid="cluster-1",
                    llm_ref="validation",
                    call_kind="initial_decision",
                ),
                budget_stage="validation",
                model="glm-5.1",
                finish_reason="stop",
                cached_prompt_tokens=10,
                reasoning_tokens=5,
            ).to_dict()
            usage_path.write_text(
                json.dumps(usage_event, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report, execution = execute_discovery_ablation_request(
                request,
                executor=_Executor(tmp_path, usage_path),
                expected_request_sha256=request["request_sha256"],
                usage_sidecar_path=usage_path,
                expected_usage_sidecar_sha256=_file_sha(usage_path),
            )
            report_path = _write_json(tmp_path / f"{arm_id}-{trial_index}-report.json", report)
            execution_path = _write_json(
                tmp_path / f"{arm_id}-{trial_index}-execution.json", execution
            )
            executions[key] = execution_path
            reports[key] = report_path
            expected_executions[key] = execution["execution_sha256"]
            expected_reports[key] = canonical_json_sha256(report)
            expected_execution_files[key] = _file_sha(execution_path)
            expected_report_files[key] = _file_sha(report_path)
            usage_sidecars[key] = usage_path
            expected_usage_sidecars[key] = _file_sha(usage_path)
    truth_path = _write_json(tmp_path / "truth.json", _truth())
    return {
        "plan": plan,
        "plan_path": plan_path,
        "executions": executions,
        "reports": reports,
        "expected_executions": expected_executions,
        "expected_reports": expected_reports,
        "expected_execution_files": expected_execution_files,
        "expected_report_files": expected_report_files,
        "usage_sidecars": usage_sidecars,
        "expected_usage_sidecars": expected_usage_sidecars,
        "truth_path": truth_path,
    }


@pytest.fixture(scope="module")
def pristine_matrix(tmp_path_factory) -> dict[str, Any]:
    """Build the 25-pair frozen matrix once and share it as copy source.

    Every test receives its own ``copytree`` so tampering tests mutate only
    their copy; content hashes recorded by ``_matrix`` stay valid because
    copied bytes are identical.
    """

    root = tmp_path_factory.mktemp("ablation-pristine")
    matrix = _matrix(root)
    matrix["root"] = root
    return matrix


def _copied_matrix(pristine: Mapping[str, Any], target: Path) -> dict[str, Any]:
    shutil.copytree(Path(pristine["root"]), target)
    matrix = copy.deepcopy(pristine)
    matrix.pop("root", None)
    matrix["plan_path"] = target / Path(pristine["plan_path"]).name
    matrix["truth_path"] = target / Path(pristine["truth_path"]).name
    matrix["executions"] = {
        key: target / path.name for key, path in pristine["executions"].items()
    }
    matrix["reports"] = {
        key: target / path.name for key, path in pristine["reports"].items()
    }
    matrix["usage_sidecars"] = {
        key: target / path.name for key, path in pristine["usage_sidecars"].items()
    }
    return matrix


def _score(matrix: Mapping[str, Any]) -> dict[str, Any]:
    return score_discovery_ablation_experiment(
        plan_path=matrix["plan_path"],
        execution_paths=matrix["executions"],
        report_paths=matrix["reports"],
        usage_sidecar_paths=matrix["usage_sidecars"],
        truth_path=matrix["truth_path"],
        expected_plan_sha256=matrix["plan"]["plan_sha256"],
        expected_truth_sha256=_file_sha(matrix["truth_path"]),
        expected_execution_sha256s=matrix["expected_executions"],
        expected_report_sha256s=matrix["expected_reports"],
        expected_execution_file_sha256s=matrix["expected_execution_files"],
        expected_report_file_sha256s=matrix["expected_report_files"],
        expected_usage_sidecar_sha256s=matrix["expected_usage_sidecars"],
        cold_trials_attested=True,
    )


def _replace_report(
    matrix: dict[str, Any],
    key: tuple[str, int],
    report: Mapping[str, Any],
) -> None:
    report_path = matrix["reports"][key]
    _write_json(report_path, report)
    report_sha = canonical_json_sha256(report)
    matrix["expected_reports"][key] = report_sha
    matrix["expected_report_files"][key] = _file_sha(report_path)
    execution_path = matrix["executions"][key]
    execution = json.loads(execution_path.read_text(encoding="utf-8"))
    execution["report_sha256"] = report_sha
    execution["execution_sha256"] = canonical_json_sha256(
        {field: value for field, value in execution.items() if field != "execution_sha256"}
    )
    _write_json(execution_path, execution)
    matrix["expected_executions"][key] = execution["execution_sha256"]
    matrix["expected_execution_files"][key] = _file_sha(execution_path)


def test_scores_five_frozen_trials_with_both_views_and_attribution(
    pristine_matrix, tmp_path: Path
) -> None:
    result = _score(_copied_matrix(pristine_matrix, tmp_path / "matrix"))

    validate_discovery_ablation_experiment(result)
    assert result["release_eligible"] is False
    assert (
        result["arms"]["D0"]["aggregates"]["views"]["confirmed"]["metric_distributions"][
            "true_positives"
        ]["median"]
        == 1.0
    )
    assert (
        result["arms"]["D3"]["aggregates"]["views"]["with_review"]["metric_distributions"][
            "true_positives"
        ]["p95"]
        == 2.0
    )
    assert (
        result["arms"]["D3"]["trials"][0]["views"]["with_review"]["discovery"][
            "exclusive_by_source"
        ]["llm_active_discovery"]["true_positives"]
        == 1
    )
    assert (
        result["arms"]["D3"]["trials"][0]["views"]["with_review"][
            "tokens_per_exclusive_true_positive"
        ]["llm_active_discovery"]
        == 120.0
    )
    assert (
        result["arms"]["D3"]["trials"][0]["views"]["confirmed"]["discovery"][
            "intersections_by_source_set"
        ]["backend_signal+deterministic_rule"]["true_positives"]
        == 1
    )
    assert result["arms"]["D4"]["role"] == "cost_upper_bound_only"
    assert result["arms"]["D4"]["warm_cache_benefit"]["available"] is False
    assert result["interpretation"]["selection_performed"] is False


def test_round_trip_validates_hash_and_aggregates(
    pristine_matrix, tmp_path: Path
) -> None:
    result = _score(_copied_matrix(pristine_matrix, tmp_path / "matrix"))
    output = tmp_path / "experiment.json"

    write_discovery_ablation_experiment(output, result)

    assert load_discovery_ablation_experiment(output) == result
    changed = json.loads(json.dumps(result))
    changed["arms"]["D0"]["aggregates"]["cost"]["total_tokens"]["median"] = 121.0
    changed["experiment_sha256"] = canonical_json_sha256(
        {key: value for key, value in changed.items() if key != "experiment_sha256"}
    )
    with pytest.raises(DiscoveryAblationExperimentError, match="aggregates do not conserve"):
        validate_discovery_ablation_experiment(changed)


def test_rejects_external_file_hash_mismatch_before_truth_is_opened(
    pristine_matrix, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix = _copied_matrix(pristine_matrix, tmp_path / "matrix")
    matrix["expected_report_files"][("D0", 1)] = "0" * 64
    original_load = experiment_module._stable_json_load
    truth_opened = False

    def observed_load(path: Path, *, label: str):
        nonlocal truth_opened
        if label == "ground truth":
            truth_opened = True
        return original_load(path, label=label)

    monkeypatch.setattr(experiment_module, "_stable_json_load", observed_load)

    with pytest.raises(DiscoveryAblationExperimentError, match="report file"):
        _score(matrix)
    assert truth_opened is False


def test_rejects_usage_sidecar_tamper_before_truth_is_opened(
    pristine_matrix, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix = _copied_matrix(pristine_matrix, tmp_path / "matrix")
    usage_path = matrix["usage_sidecars"][("D0", 1)]
    usage_path.write_text(
        usage_path.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    original_load = experiment_module._stable_json_load
    truth_opened = False

    def observed_load(path: Path, *, label: str):
        nonlocal truth_opened
        if label == "ground truth":
            truth_opened = True
        return original_load(path, label=label)

    monkeypatch.setattr(experiment_module, "_stable_json_load", observed_load)

    with pytest.raises(DiscoveryAblationExperimentError, match="usage sidecar|SHA-256"):
        _score(matrix)
    assert truth_opened is False


def test_rejects_missing_view_incomplete_usage_and_release_eligible_report(
    pristine_matrix, tmp_path: Path
) -> None:
    matrix = _copied_matrix(pristine_matrix, tmp_path / "matrix")
    report_path = matrix["reports"][("D1", 2)]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["release_eligible"] = True
    _replace_report(matrix, ("D1", 2), report)

    with pytest.raises(DiscoveryAblationExperimentError, match="release eligible|release_eligible"):
        _score(matrix)


def test_rejects_missing_with_review_view_before_truth_is_opened(
    pristine_matrix, tmp_path: Path
) -> None:
    matrix = _copied_matrix(pristine_matrix, tmp_path / "matrix")
    key = ("D2", 3)
    report_path = matrix["reports"][key]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    del report["report_views"]["with_needs_review"]
    _replace_report(matrix, key, report)

    with pytest.raises(DiscoveryAblationExperimentError, match="with_needs_review"):
        _score(matrix)


def test_rejects_incomplete_provider_usage_before_truth_is_opened(
    pristine_matrix, tmp_path: Path
) -> None:
    matrix = _copied_matrix(pristine_matrix, tmp_path / "matrix")
    key = ("D3", 4)
    report_path = matrix["reports"][key]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    usage = report["metadata"]["llm_usage"]["usage_attribution"]
    usage["totals"]["provider_reported_calls"] = 0
    usage["by_agent"]["validator_agent"]["provider_reported_calls"] = 0
    usage["by_stage"]["validation"]["provider_reported_calls"] = 0
    usage["by_finish_reason"]["stop"]["provider_reported_calls"] = 0
    _replace_report(matrix, key, report)

    with pytest.raises(
        DiscoveryAblationExperimentError,
        match="usage attribution|usage ledger|provider usage",
    ):
        _score(matrix)


def test_requires_exact_25_pair_matrix_and_cold_attestation(
    pristine_matrix, tmp_path: Path
) -> None:
    matrix = _copied_matrix(pristine_matrix, tmp_path / "matrix")
    del matrix["reports"][("D4", 5)]
    with pytest.raises(DiscoveryAblationExperimentError, match="D0-D4 trials 1-5"):
        _score(matrix)

    complete = _copied_matrix(pristine_matrix, tmp_path / "second")
    with pytest.raises(DiscoveryAblationExperimentError, match="cold trial attestation"):
        score_discovery_ablation_experiment(
            plan_path=complete["plan_path"],
            execution_paths=complete["executions"],
            report_paths=complete["reports"],
            usage_sidecar_paths=complete["usage_sidecars"],
            truth_path=complete["truth_path"],
            expected_plan_sha256=complete["plan"]["plan_sha256"],
            expected_truth_sha256=_file_sha(complete["truth_path"]),
            expected_execution_sha256s=complete["expected_executions"],
            expected_report_sha256s=complete["expected_reports"],
            expected_execution_file_sha256s=complete["expected_execution_files"],
            expected_report_file_sha256s=complete["expected_report_files"],
            expected_usage_sidecar_sha256s=complete["expected_usage_sidecars"],
            cold_trials_attested=False,
        )
