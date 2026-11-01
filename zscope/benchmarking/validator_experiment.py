"""Independent, hash-bound scoring for frozen Validator A-E replay experiments.

The replay phase is intentionally truth-free.  This module first loads and
freezes every answer-free replay ledger, verifies all externally supplied
hashes and experiment identities, and only then opens the ground-truth file.
It never imports or invokes a model executor.
"""

from __future__ import annotations

import copy
import hashlib
import json
import statistics
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

from .policy import DEFAULT_BENCHMARK_POLICY
from .protocol import score_report, select_validator_arm
from .replay_bundle import (
    REPLAY_BUNDLE_SCHEMA_VERSION,
    canonical_json_sha256,
    load_validator_replay_bundle,
)
from .validator_replay import (
    ARM_CATALOG_SCHEMA_VERSION,
    DEFAULT_ARM_CATALOG_FILE,
    LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS,
    REPLAY_RUN_SCHEMA_VERSION,
    VALIDATOR_ARM_CATALOG_REVISION,
    load_validator_arm_catalog,
    load_validator_replay_run,
    validator_arm,
)


VALIDATOR_EXPERIMENT_SCHEMA_VERSION = "zscope.validator-replay-experiment.v1"
FORMAL_VALIDATOR_ARMS: Tuple[str, ...] = tuple("ABCDE")
FORMAL_COLD_TRIALS_PER_ARM = 5
RANGE_GROUND_TRUTH_COUNT = 141
BALANCED_DEFAULT_EXPECTED_MAX_TOKENS = 12_000_000

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "scorer",
        "inputs",
        "contract",
        "policy",
        "arms",
        "selection",
        "release_eligible",
        "experiment_sha256",
    }
)
_SCORER_FIELDS = frozenset({"component", "revision", "source_sha256", "policy_id", "policy_sha256"})
_INPUT_FIELDS = frozenset({"bundle", "arm_catalog", "truth", "runs"})
_BUNDLE_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "bundle_sha256",
        "file_sha256",
        "source_identity_sha256",
        "group_count",
    }
)
_CATALOG_INPUT_FIELDS = frozenset(
    {"schema_version", "catalog_revision", "catalog_sha256", "file_sha256"}
)
_TRUTH_INPUT_FIELDS = frozenset(
    {
        "benchmark",
        "version",
        "ground_truth_count",
        "file_sha256",
        "payload_sha256",
    }
)
_RUN_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "arm_id",
        "trial_index",
        "run_sha256",
        "file_sha256",
        "arm_spec_sha256",
        "expected_total_tokens",
        "total_tokens",
        "execution_identity",
        "ledger_complete",
    }
)
_CONTRACT_FIELDS = frozenset(
    {
        "scoring_order",
        "replay_answer_free",
        "truth_loaded_by",
        "required_arms",
        "trials_per_arm",
        "cold_trials_attested",
        "fixed_execution_identity",
        "legacy_arm_e_cost_expectation_tokens",
        "default_gate_cost_expectation_tokens",
        "model_execution",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "policy_id",
        "policy_sha256",
        "arm_a_baseline",
        "expected_ground_truth_count",
        "recall_tie_pp",
        "gates",
    }
)
_ARM_FIELDS = frozenset(
    {
        "arm_id",
        "arm_revision",
        "arm_spec_sha256",
        "baseline",
        "protocol_mode",
        "trial_count",
        "configured_cost_expectation_tokens",
        "trials",
        "metrics",
        "gates",
        "passed",
    }
)
_TRIAL_FIELDS = frozenset(
    {
        "trial_index",
        "run_sha256",
        "confirmed_count",
        "true_positives",
        "false_positives_raw",
        "recall",
        "actionable_false_discovery_rate",
        "true_positive_truth_ids",
        "total_tokens",
        "call_count",
        "provider_reported_call_count",
        "provider_usage_coverage",
        "queue_drained",
        "token_conserved",
        "protocol_anomaly_count",
        "cost_expectation_met",
        "complete",
    }
)
_METRIC_FIELDS = frozenset(
    {
        "median_confirmed_tp",
        "median_recall",
        "median_actionable_fdr",
        "actionable_fdr_delta_vs_arm_a_pp",
        "median_tokens",
        "max_tokens",
        "true_positive_jaccard",
        "recall_range_pp",
        "provider_usage_coverage",
        "queue_drained_rate",
        "token_conservation_rate",
        "protocol_anomaly_count",
    }
)
_GATE_FIELDS = frozenset({"actual", "operator", "threshold", "passed"})
_SELECTION_FIELDS = frozenset(
    {
        "status",
        "selected_arm",
        "eligible_arms",
        "best_passing_recall",
        "recall_tie_pp",
        "selection_rule",
    }
)
_EXECUTION_IDENTITY_FIELDS = frozenset({"executor_sha256", "model_spec_sha256", "prompt_sha256"})
_USAGE_SUM_FIELDS = (
    "prompt_tokens",
    "cached_prompt_tokens",
    "completion_tokens",
    "reasoning_tokens",
    "total_tokens",
    "tool_call_count",
    "api_attempt_count",
    "provider_reported_call_count",
    "call_count",
)
_EXPERIMENT_GATE_NAMES = (
    "median_confirmed_tp",
    "median_tokens",
    "per_run_tokens",
    "actionable_fdr_delta_vs_arm_a_pp",
    "true_positive_jaccard",
    "recall_range_pp",
    "provider_usage_coverage",
    "queue_drained_rate",
    "token_conservation_rate",
    "protocol_anomaly_count",
)


class ValidatorExperimentError(ValueError):
    """Raised when a formal replay experiment cannot be independently scored."""


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(Path(path).read_bytes())
    except OSError as exc:
        raise ValidatorExperimentError(f"cannot hash experiment input: {path}") from exc


def _strict_json_bytes(raw: bytes, *, label: str) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidatorExperimentError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValidatorExperimentError(f"{label} contains non-finite JSON value: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidatorExperimentError(f"{label} must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValidatorExperimentError(f"{label} must be a JSON object")
    return value


def _stable_load(
    path: Path,
    loader: Callable[[Path], Dict[str, Any]],
    *,
    label: str,
) -> Tuple[Dict[str, Any], str]:
    selected = Path(path)
    try:
        before = selected.read_bytes()
        value = loader(selected)
        after = selected.read_bytes()
    except OSError as exc:
        raise ValidatorExperimentError(f"cannot load {label}: {selected}") from exc
    if before != after:
        raise ValidatorExperimentError(f"{label} changed while it was being frozen")
    return value, _sha256_bytes(before)


def _load_catalog_snapshot(path: Optional[Path]) -> Tuple[Dict[str, Any], str]:
    if path is not None:
        return _stable_load(
            Path(path),
            lambda selected: load_validator_arm_catalog(selected),
            label="validator arm catalog",
        )
    resource = files("zscope.benchmarking").joinpath(DEFAULT_ARM_CATALOG_FILE)
    try:
        before = resource.read_bytes()
        catalog = load_validator_arm_catalog()
        after = resource.read_bytes()
    except OSError as exc:
        raise ValidatorExperimentError("cannot load packaged validator arm catalog") from exc
    if before != after:
        raise ValidatorExperimentError("validator arm catalog changed while being frozen")
    return catalog, _sha256_bytes(before)


def _read_truth_after_runs(path: Path) -> Tuple[Dict[str, Any], str]:
    """Open truth only after the caller has frozen every replay ledger."""

    selected = Path(path)
    try:
        before = selected.read_bytes()
        truth = _strict_json_bytes(before, label="ground truth")
        after = selected.read_bytes()
    except OSError as exc:
        raise ValidatorExperimentError(f"cannot load ground truth: {selected}") from exc
    if before != after:
        raise ValidatorExperimentError("ground truth changed while it was being scored")
    return truth, _sha256_bytes(before)


def _require_external_hash(value: Any, *, label: str) -> str:
    if not _is_sha256(value):
        raise ValidatorExperimentError(f"{label} must be a lowercase SHA-256")
    return str(value)


def _expected_trial_keys() -> set[Tuple[str, int]]:
    return {
        (arm_id, trial_index)
        for arm_id in FORMAL_VALIDATOR_ARMS
        for trial_index in range(1, FORMAL_COLD_TRIALS_PER_ARM + 1)
    }


def _validate_truth(truth: Mapping[str, Any]) -> None:
    vulnerabilities = truth.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) != RANGE_GROUND_TRUTH_COUNT:
        raise ValidatorExperimentError(
            f"formal Range truth must contain exactly {RANGE_GROUND_TRUTH_COUNT} vulnerabilities"
        )
    if truth.get("total_vulnerabilities") != RANGE_GROUND_TRUTH_COUNT:
        raise ValidatorExperimentError(
            f"formal Range truth total_vulnerabilities must equal {RANGE_GROUND_TRUTH_COUNT}"
        )
    truth_ids: list[str] = []
    for index, row in enumerate(vulnerabilities):
        if not isinstance(row, Mapping):
            raise ValidatorExperimentError(
                f"ground truth vulnerabilities[{index}] is not an object"
            )
        truth_id = row.get("id")
        if not isinstance(truth_id, str) or not truth_id.strip():
            raise ValidatorExperimentError(
                f"ground truth vulnerabilities[{index}] has no stable id"
            )
        truth_ids.append(truth_id)
    if len(set(truth_ids)) != len(truth_ids):
        raise ValidatorExperimentError("ground truth vulnerability ids are not unique")
    if not isinstance(truth.get("benchmark"), str) or not str(truth.get("benchmark")).strip():
        raise ValidatorExperimentError("ground truth benchmark identity is missing")


def _verify_run_binding(
    run: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any],
    catalog: Mapping[str, Any],
) -> None:
    arm_id = str(run.get("arm_id") or "")
    if arm_id not in FORMAL_VALIDATOR_ARMS:
        raise ValidatorExperimentError(f"unexpected replay arm: {arm_id or '<empty>'}")
    spec = validator_arm(catalog, arm_id)
    expected = {
        "bundle_sha256": bundle["bundle_sha256"],
        "source_identity_sha256": bundle["source_identity"]["identity_sha256"],
        "arm_catalog_sha256": catalog["catalog_sha256"],
        "arm_revision": spec["revision"],
        "arm_spec_sha256": spec["arm_spec_sha256"],
        "planned_group_count": bundle["group_count"],
    }
    for field, value in expected.items():
        if run.get(field) != value:
            raise ValidatorExperimentError(
                f"Arm {arm_id} trial {run.get('trial_index')} {field} binding mismatch"
            )

    contract = run.get("contract")
    if (
        not isinstance(contract, Mapping)
        or contract.get("executor_formal_eligible") is not True
        or contract.get("executor_trust_mode") not in {"builtin_provider", "trusted_oci_external"}
    ):
        raise ValidatorExperimentError(
            "formal A-E scoring requires the built-in executor or trusted OCI external evidence"
        )
    if arm_id == "E" and contract.get("executor_trust_mode") != "trusted_oci_external":
        raise ValidatorExperimentError(
            "formal Arm E requires a trusted OCI legacy external executor"
        )

    cap = run.get("expected_total_tokens")
    if isinstance(cap, bool) or not isinstance(cap, int) or cap <= 0:
        raise ValidatorExperimentError("formal replay ledgers require a positive cost expectation")

    bundle_groups = {
        str(group["validation_cluster_uid"]): group for group in bundle["canonical_groups"]
    }
    observed_clusters: list[str] = []
    for group in run["groups"]:
        cluster = str(group["validation_cluster_uid"])
        expected_group = bundle_groups.get(cluster)
        if expected_group is None:
            raise ValidatorExperimentError(f"replay ledger contains unknown cluster: {cluster}")
        if group.get("group_sha256") != expected_group.get("group_sha256") or group.get(
            "candidate_uid"
        ) != expected_group.get("candidate_uid"):
            raise ValidatorExperimentError(f"replay ledger cluster binding mismatch: {cluster}")
        observed_clusters.append(cluster)
    frozen_order = [str(group["validation_cluster_uid"]) for group in bundle["canonical_groups"]]
    if observed_clusters != frozen_order[: len(observed_clusters)]:
        raise ValidatorExperimentError("replay ledger groups are not the frozen canonical prefix")


def _token_conserved(run: Mapping[str, Any]) -> bool:
    usage = run["usage"]
    summed = {
        field: sum(int(group["usage"].get(field) or 0) for group in run["groups"])
        for field in _USAGE_SUM_FIELDS
    }
    return bool(
        summed == usage
        and int(usage["total_tokens"])
        == int(usage["prompt_tokens"]) + int(usage["completion_tokens"])
        and int(usage["cached_prompt_tokens"]) <= int(usage["prompt_tokens"])
        and int(usage["reasoning_tokens"]) <= int(usage["completion_tokens"])
    )


def _protocol_anomaly_count(run: Mapping[str, Any]) -> int:
    anomalies: set[str] = set()
    for group_index, group in enumerate(run["groups"]):
        if group.get("protocol_valid") is not True:
            anomalies.add(f"group:{group_index}:protocol_invalid")
        if group.get("execution_status") == "invalid":
            anomalies.add(f"group:{group_index}:execution_invalid")
        for error in group.get("protocol_errors") or []:
            anomalies.add(f"group:{group_index}:{error}")
        for call_index, call in enumerate(group.get("calls") or []):
            for error in call.get("protocol_errors") or []:
                anomalies.add(f"group:{group_index}:call:{call_index}:{error}")
    return len(anomalies)


def _queue_drained(run: Mapping[str, Any]) -> bool:
    return bool(
        run.get("complete") is True
        and run.get("group_count") == run.get("planned_group_count")
        and all(group.get("execution_status") == "complete" for group in run["groups"])
    )


def _score_trial(
    run: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any],
    truth: Mapping[str, Any],
) -> Dict[str, Any]:
    bundle_groups = {
        str(group["validation_cluster_uid"]): group for group in bundle["canonical_groups"]
    }
    issues: list[Dict[str, Any]] = []
    for group in run["groups"]:
        terminal = group.get("terminal_result")
        if (
            group.get("execution_status") != "complete"
            or group.get("protocol_valid") is not True
            or not isinstance(terminal, Mapping)
            or terminal.get("verdict") != "verified"
        ):
            continue
        frozen = bundle_groups[str(group["validation_cluster_uid"])]
        issue = copy.deepcopy(dict(frozen["candidate"]))
        issue["candidate_uid"] = frozen["candidate_uid"]
        issue["validation_cluster_uid"] = frozen["validation_cluster_uid"]
        issues.append(issue)

    score = score_report({"issues": issues}, dict(truth), view="default")
    true_positives = int(score["true_positives"])
    false_positives_raw = int(score["false_positives_raw"])
    denominator = true_positives + false_positives_raw
    usage = run["usage"]
    call_count = int(usage["call_count"])
    provider_calls = int(usage["provider_reported_call_count"])
    return {
        "trial_index": int(run["trial_index"]),
        "run_sha256": str(run["run_sha256"]),
        "confirmed_count": len(issues),
        "true_positives": true_positives,
        "false_positives_raw": false_positives_raw,
        "recall": true_positives / RANGE_GROUND_TRUTH_COUNT,
        "actionable_false_discovery_rate": (
            false_positives_raw / denominator if denominator else 0.0
        ),
        "true_positive_truth_ids": sorted(str(item) for item in score["true_positive_truth_ids"]),
        "total_tokens": int(usage["total_tokens"]),
        "call_count": call_count,
        "provider_reported_call_count": provider_calls,
        "provider_usage_coverage": provider_calls / call_count if call_count else 0.0,
        "queue_drained": _queue_drained(run),
        "token_conserved": _token_conserved(run),
        "protocol_anomaly_count": _protocol_anomaly_count(run),
        "cost_expectation_met": bool(run["cost_expectation_met"]),
        "complete": bool(run["complete"]),
    }


def _mean_pairwise_jaccard(trials: Sequence[Mapping[str, Any]]) -> float:
    sets = [set(str(item) for item in trial["true_positive_truth_ids"]) for trial in trials]
    values: list[float] = []
    for left_index, left in enumerate(sets):
        for right in sets[left_index + 1 :]:
            union = left | right
            values.append(len(left & right) / len(union) if union else 1.0)
    return sum(values) / len(values) if values else 1.0


def _aggregate_trials(
    trials: Sequence[Mapping[str, Any]],
    *,
    arm_a_median_fdr: float,
) -> Dict[str, Any]:
    recalls = [float(trial["recall"]) for trial in trials]
    fdrs = [float(trial["actionable_false_discovery_rate"]) for trial in trials]
    tokens = [int(trial["total_tokens"]) for trial in trials]
    total_calls = sum(int(trial["call_count"]) for trial in trials)
    provider_calls = sum(int(trial["provider_reported_call_count"]) for trial in trials)
    median_fdr = float(statistics.median(fdrs))
    return {
        "median_confirmed_tp": float(
            statistics.median(int(trial["true_positives"]) for trial in trials)
        ),
        "median_recall": float(statistics.median(recalls)),
        "median_actionable_fdr": median_fdr,
        "actionable_fdr_delta_vs_arm_a_pp": (median_fdr - arm_a_median_fdr) * 100.0,
        "median_tokens": float(statistics.median(tokens)),
        "max_tokens": max(tokens),
        "true_positive_jaccard": _mean_pairwise_jaccard(trials),
        "recall_range_pp": (max(recalls) - min(recalls)) * 100.0,
        "provider_usage_coverage": provider_calls / total_calls if total_calls else 0.0,
        "queue_drained_rate": sum(trial["queue_drained"] is True for trial in trials) / len(trials),
        "token_conservation_rate": sum(trial["token_conserved"] is True for trial in trials)
        / len(trials),
        "protocol_anomaly_count": sum(int(trial["protocol_anomaly_count"]) for trial in trials),
    }


def _gate(*, actual: float, operator: str, threshold: float) -> Dict[str, Any]:
    if operator == ">=":
        passed = actual >= threshold
    elif operator == "<=":
        passed = actual <= threshold
    else:
        raise ValidatorExperimentError(f"unsupported gate operator: {operator}")
    return {
        "actual": actual,
        "operator": operator,
        "threshold": threshold,
        "passed": passed,
    }


def _policy_gate_contract() -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for name in _EXPERIMENT_GATE_NAMES:
        operator, threshold = DEFAULT_BENCHMARK_POLICY.range_gates[name]
        result[name] = {"operator": operator, "threshold": float(threshold)}
    return result


def _arm_gates(metrics: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    actuals = {
        "median_confirmed_tp": float(metrics["median_confirmed_tp"]),
        "median_tokens": float(metrics["median_tokens"]),
        "per_run_tokens": float(metrics["max_tokens"]),
        "actionable_fdr_delta_vs_arm_a_pp": float(metrics["actionable_fdr_delta_vs_arm_a_pp"]),
        "true_positive_jaccard": float(metrics["true_positive_jaccard"]),
        "recall_range_pp": float(metrics["recall_range_pp"]),
        "provider_usage_coverage": float(metrics["provider_usage_coverage"]),
        "queue_drained_rate": float(metrics["queue_drained_rate"]),
        "token_conservation_rate": float(metrics["token_conservation_rate"]),
        "protocol_anomaly_count": float(metrics["protocol_anomaly_count"]),
    }
    result: Dict[str, Dict[str, Any]] = {}
    for name, actual in actuals.items():
        operator, threshold = DEFAULT_BENCHMARK_POLICY.range_gates[name]
        result[name] = _gate(actual=actual, operator=operator, threshold=float(threshold))
    return result


def _selection(arms: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    candidates = {
        arm_id: {
            "passed": arm["passed"],
            "median_recall": arm["metrics"]["median_recall"],
            "median_tokens": arm["metrics"]["median_tokens"],
        }
        for arm_id, arm in arms.items()
    }
    selected = select_validator_arm(candidates)
    eligible = sorted(arm_id for arm_id, arm in arms.items() if arm["passed"] is True)
    best_recall = (
        max(float(arms[arm_id]["metrics"]["median_recall"]) for arm_id in eligible)
        if eligible
        else None
    )
    return {
        "status": "selected" if selected is not None else "no_passing_arm",
        "selected_arm": selected,
        "eligible_arms": eligible,
        "best_passing_recall": best_recall,
        "recall_tie_pp": float(DEFAULT_BENCHMARK_POLICY.matrix_thresholds["arm_recall_tie_pp"]),
        "selection_rule": "lowest_median_tokens_within_strictly_less_than_1pp_of_best_recall",
    }


def score_validator_replay_experiment(
    *,
    bundle_path: Path,
    run_paths: Sequence[Path],
    truth_path: Path,
    expected_bundle_sha256: str,
    expected_truth_sha256: str,
    expected_arm_catalog_sha256: str,
    expected_run_sha256s: Mapping[Tuple[str, int], str],
    arm_catalog_path: Optional[Path] = None,
    cold_trials_attested: bool,
) -> Dict[str, Any]:
    """Score five cold trials for Arms A-E after freezing every answer-free run.

    ``expected_*`` values must come from orchestration outside the scorer.  In
    particular, accepting self-declared run hashes would let a replaced ledger
    silently become the experiment input.
    """

    if cold_trials_attested is not True:
        raise ValidatorExperimentError("formal A-E scoring requires cold-trial attestation")
    expected_bundle = _require_external_hash(
        expected_bundle_sha256, label="expected bundle SHA-256"
    )
    expected_truth = _require_external_hash(
        expected_truth_sha256, label="expected truth file SHA-256"
    )
    expected_catalog = _require_external_hash(
        expected_arm_catalog_sha256, label="expected arm catalog SHA-256"
    )
    expected_keys = _expected_trial_keys()
    if set(expected_run_sha256s) != expected_keys:
        raise ValidatorExperimentError("expected run hashes must bind Arms A-E trials 1-5 exactly")
    normalized_expected_runs = {
        key: _require_external_hash(value, label=f"expected Arm {key[0]} trial {key[1]} SHA-256")
        for key, value in expected_run_sha256s.items()
    }
    if len(run_paths) != len(expected_keys):
        raise ValidatorExperimentError("formal A-E scoring requires exactly 25 replay ledgers")

    # Phase 1: freeze all answer-free inputs.  Do not open truth in this phase.
    bundle, bundle_file_sha = _stable_load(
        Path(bundle_path), load_validator_replay_bundle, label="validator replay bundle"
    )
    if bundle["bundle_sha256"] != expected_bundle:
        raise ValidatorExperimentError("replay bundle does not match the externally expected hash")
    catalog, catalog_file_sha = _load_catalog_snapshot(arm_catalog_path)
    if catalog["catalog_sha256"] != expected_catalog:
        raise ValidatorExperimentError("arm catalog does not match the externally expected hash")

    frozen_runs: Dict[Tuple[str, int], Dict[str, Any]] = {}
    run_file_hashes: Dict[Tuple[str, int], str] = {}
    execution_identities: Dict[str, Dict[str, Any]] = {}
    model_spec_sha256: Optional[str] = None
    configured_caps: Dict[str, set[int]] = {arm_id: set() for arm_id in FORMAL_VALIDATOR_ARMS}
    for path in run_paths:
        run, file_sha = _stable_load(
            Path(path), load_validator_replay_run, label="validator replay run"
        )
        arm_id = str(run.get("arm_id") or "")
        trial_index = run.get("trial_index")
        if (
            arm_id not in FORMAL_VALIDATOR_ARMS
            or isinstance(trial_index, bool)
            or not isinstance(trial_index, int)
        ):
            raise ValidatorExperimentError("replay run has an invalid arm/trial identity")
        key = (arm_id, trial_index)
        if key not in expected_keys:
            raise ValidatorExperimentError(f"unexpected replay run identity: {key!r}")
        if key in frozen_runs:
            raise ValidatorExperimentError(f"duplicate replay run identity: {key!r}")
        if run["run_sha256"] != normalized_expected_runs[key]:
            raise ValidatorExperimentError(
                f"Arm {arm_id} trial {trial_index} does not match its externally expected hash"
            )
        _verify_run_binding(run, bundle=bundle, catalog=catalog)
        observed_identity = dict(run["execution_identity"])
        prior_arm_identity = execution_identities.get(arm_id)
        if prior_arm_identity is None:
            execution_identities[arm_id] = observed_identity
        elif observed_identity != prior_arm_identity:
            raise ValidatorExperimentError(
                f"all formal Arm {arm_id} trials must use one executor/model/prompt identity"
            )
        observed_model_spec = str(observed_identity["model_spec_sha256"])
        if model_spec_sha256 is None:
            model_spec_sha256 = observed_model_spec
        elif observed_model_spec != model_spec_sha256:
            raise ValidatorExperimentError("all formal A-E trials must use one model spec")
        configured_caps[arm_id].add(int(run["expected_total_tokens"]))
        frozen_runs[key] = copy.deepcopy(run)
        run_file_hashes[key] = file_sha

    if set(frozen_runs) != expected_keys:
        raise ValidatorExperimentError("formal A-E replay ledger matrix is incomplete")
    if len({run["run_sha256"] for run in frozen_runs.values()}) != len(expected_keys):
        raise ValidatorExperimentError("formal cold trials must have distinct run ledgers")
    for arm_id, caps in configured_caps.items():
        if len(caps) != 1:
            raise ValidatorExperimentError(
                f"Arm {arm_id} changed its configured cost expectation across cold trials"
            )

    # Phase 2: all model outputs are now frozen.  Only the independent scorer
    # may open truth from this point onward.
    truth, truth_file_sha = _read_truth_after_runs(Path(truth_path))
    if truth_file_sha != expected_truth:
        raise ValidatorExperimentError("ground truth does not match the externally expected hash")
    _validate_truth(truth)

    scored_trials: Dict[str, list[Dict[str, Any]]] = {}
    for arm_id in FORMAL_VALIDATOR_ARMS:
        scored_trials[arm_id] = [
            _score_trial(
                frozen_runs[(arm_id, trial_index)],
                bundle=bundle,
                truth=truth,
            )
            for trial_index in range(1, FORMAL_COLD_TRIALS_PER_ARM + 1)
        ]

    arm_a_median_fdr = float(
        statistics.median(trial["actionable_false_discovery_rate"] for trial in scored_trials["A"])
    )
    arms: Dict[str, Dict[str, Any]] = {}
    for arm_id in FORMAL_VALIDATOR_ARMS:
        spec = validator_arm(catalog, arm_id)
        trials = scored_trials[arm_id]
        metrics = _aggregate_trials(trials, arm_a_median_fdr=arm_a_median_fdr)
        gates = _arm_gates(metrics)
        arms[arm_id] = {
            "arm_id": arm_id,
            "arm_revision": int(spec["revision"]),
            "arm_spec_sha256": str(spec["arm_spec_sha256"]),
            "baseline": bool(spec["baseline"]),
            "protocol_mode": str(spec["protocol_mode"]),
            "trial_count": len(trials),
            "configured_cost_expectation_tokens": next(iter(configured_caps[arm_id])),
            "trials": trials,
            "metrics": metrics,
            "gates": gates,
            "passed": all(gate["passed"] is True for gate in gates.values()),
        }

    run_inputs = []
    for arm_id, trial_index in sorted(expected_keys):
        run = frozen_runs[(arm_id, trial_index)]
        run_inputs.append(
            {
                "schema_version": str(run["schema_version"]),
                "arm_id": arm_id,
                "trial_index": trial_index,
                "run_sha256": str(run["run_sha256"]),
                "file_sha256": run_file_hashes[(arm_id, trial_index)],
                "arm_spec_sha256": str(run["arm_spec_sha256"]),
                "expected_total_tokens": int(run["expected_total_tokens"]),
                "total_tokens": int(run["usage"]["total_tokens"]),
                "execution_identity": dict(run["execution_identity"]),
                "ledger_complete": bool(run["complete"]),
            }
        )

    result: Dict[str, Any] = {
        "schema_version": VALIDATOR_EXPERIMENT_SCHEMA_VERSION,
        "scorer": {
            "component": "zscope.benchmarking.validator_experiment",
            "revision": 1,
            "source_sha256": _sha256_file(Path(__file__)),
            "policy_id": DEFAULT_BENCHMARK_POLICY.policy_id,
            "policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
        },
        "inputs": {
            "bundle": {
                "schema_version": str(bundle["schema_version"]),
                "bundle_sha256": str(bundle["bundle_sha256"]),
                "file_sha256": bundle_file_sha,
                "source_identity_sha256": str(bundle["source_identity"]["identity_sha256"]),
                "group_count": int(bundle["group_count"]),
            },
            "arm_catalog": {
                "schema_version": str(catalog["schema_version"]),
                "catalog_revision": int(catalog["catalog_revision"]),
                "catalog_sha256": str(catalog["catalog_sha256"]),
                "file_sha256": catalog_file_sha,
            },
            "truth": {
                "benchmark": str(truth["benchmark"]),
                "version": str(truth.get("version") or ""),
                "ground_truth_count": RANGE_GROUND_TRUTH_COUNT,
                "file_sha256": truth_file_sha,
                "payload_sha256": canonical_json_sha256(truth),
            },
            "runs": run_inputs,
        },
        "contract": {
            "scoring_order": "runs_frozen_before_truth_open",
            "replay_answer_free": True,
            "truth_loaded_by": "independent_scorer_only",
            "required_arms": list(FORMAL_VALIDATOR_ARMS),
            "trials_per_arm": FORMAL_COLD_TRIALS_PER_ARM,
            "cold_trials_attested": True,
            "fixed_execution_identity": False,
            "legacy_arm_e_cost_expectation_tokens": LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS,
            "default_gate_cost_expectation_tokens": BALANCED_DEFAULT_EXPECTED_MAX_TOKENS,
            "model_execution": "forbidden",
        },
        "policy": {
            "policy_id": DEFAULT_BENCHMARK_POLICY.policy_id,
            "policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
            "arm_a_baseline": "A",
            "expected_ground_truth_count": RANGE_GROUND_TRUTH_COUNT,
            "recall_tie_pp": float(DEFAULT_BENCHMARK_POLICY.matrix_thresholds["arm_recall_tie_pp"]),
            "gates": _policy_gate_contract(),
        },
        "arms": arms,
        "selection": _selection(arms),
        # Arm selection is an experiment input to a later protected formal
        # scan.  A caller-provided cold-trial declaration and content hashes
        # do not turn this standalone scorer output into release provenance.
        "release_eligible": False,
    }
    result["experiment_sha256"] = canonical_json_sha256(result)
    validate_validator_replay_experiment(result)
    return result


def _require_exact(value: Any, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValidatorExperimentError(f"{label} has missing or unknown fields")
    return value


def _require_number(value: Any, *, label: str, minimum: Optional[float] = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidatorExperimentError(f"{label} must be numeric")
    numeric = float(value)
    if minimum is not None and numeric < minimum:
        raise ValidatorExperimentError(f"{label} must be at least {minimum}")
    return numeric


def validate_validator_replay_experiment(result: Mapping[str, Any]) -> None:
    """Fail closed on schema drift or recomputed aggregate/gate disagreement."""

    _require_exact(result, _TOP_LEVEL_FIELDS, label="validator experiment")
    if result.get("schema_version") != VALIDATOR_EXPERIMENT_SCHEMA_VERSION:
        raise ValidatorExperimentError("validator experiment schema_version is invalid")
    if result.get("release_eligible") is not False:
        raise ValidatorExperimentError("validator experiments are never direct release evidence")
    if result.get("experiment_sha256") != canonical_json_sha256(
        {key: value for key, value in result.items() if key != "experiment_sha256"}
    ):
        raise ValidatorExperimentError("validator experiment hash mismatch")

    scorer = _require_exact(result.get("scorer"), _SCORER_FIELDS, label="scorer")
    if (
        scorer.get("component") != "zscope.benchmarking.validator_experiment"
        or scorer.get("revision") != 1
        or scorer.get("policy_id") != DEFAULT_BENCHMARK_POLICY.policy_id
        or scorer.get("policy_sha256") != DEFAULT_BENCHMARK_POLICY.sha256
        or not _is_sha256(scorer.get("source_sha256"))
    ):
        raise ValidatorExperimentError("validator experiment scorer identity is invalid")

    inputs = _require_exact(result.get("inputs"), _INPUT_FIELDS, label="inputs")
    bundle = _require_exact(inputs.get("bundle"), _BUNDLE_INPUT_FIELDS, label="bundle input")
    catalog = _require_exact(
        inputs.get("arm_catalog"), _CATALOG_INPUT_FIELDS, label="catalog input"
    )
    truth = _require_exact(inputs.get("truth"), _TRUTH_INPUT_FIELDS, label="truth input")
    if (
        bundle.get("schema_version") != REPLAY_BUNDLE_SCHEMA_VERSION
        or catalog.get("schema_version") != ARM_CATALOG_SCHEMA_VERSION
        or truth.get("ground_truth_count") != RANGE_GROUND_TRUTH_COUNT
    ):
        raise ValidatorExperimentError("validator experiment input schema/count binding is invalid")
    for label, value in (
        ("bundle_sha256", bundle.get("bundle_sha256")),
        ("bundle file_sha256", bundle.get("file_sha256")),
        ("source_identity_sha256", bundle.get("source_identity_sha256")),
        ("catalog_sha256", catalog.get("catalog_sha256")),
        ("catalog file_sha256", catalog.get("file_sha256")),
        ("truth file_sha256", truth.get("file_sha256")),
        ("truth payload_sha256", truth.get("payload_sha256")),
    ):
        _require_external_hash(value, label=label)
    if (
        isinstance(bundle.get("group_count"), bool)
        or not isinstance(bundle.get("group_count"), int)
        or int(bundle["group_count"]) < 0
        or catalog.get("catalog_revision") != VALIDATOR_ARM_CATALOG_REVISION
        or not isinstance(truth.get("benchmark"), str)
        or not str(truth.get("benchmark")).strip()
        or not isinstance(truth.get("version"), str)
    ):
        raise ValidatorExperimentError("validator experiment input metadata is invalid")

    contract = _require_exact(result.get("contract"), _CONTRACT_FIELDS, label="contract")
    expected_contract = {
        "scoring_order": "runs_frozen_before_truth_open",
        "replay_answer_free": True,
        "truth_loaded_by": "independent_scorer_only",
        "required_arms": list(FORMAL_VALIDATOR_ARMS),
        "trials_per_arm": FORMAL_COLD_TRIALS_PER_ARM,
        "cold_trials_attested": True,
        "fixed_execution_identity": False,
        "legacy_arm_e_cost_expectation_tokens": LEGACY_UPPER_BOUND_EXPECTED_TOTAL_TOKENS,
        "default_gate_cost_expectation_tokens": BALANCED_DEFAULT_EXPECTED_MAX_TOKENS,
        "model_execution": "forbidden",
    }
    if dict(contract) != expected_contract:
        raise ValidatorExperimentError("validator experiment contract is invalid")

    policy = _require_exact(result.get("policy"), _POLICY_FIELDS, label="policy")
    expected_policy = {
        "policy_id": DEFAULT_BENCHMARK_POLICY.policy_id,
        "policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
        "arm_a_baseline": "A",
        "expected_ground_truth_count": RANGE_GROUND_TRUTH_COUNT,
        "recall_tie_pp": float(DEFAULT_BENCHMARK_POLICY.matrix_thresholds["arm_recall_tie_pp"]),
        "gates": _policy_gate_contract(),
    }
    if dict(policy) != expected_policy:
        raise ValidatorExperimentError("validator experiment policy binding is invalid")

    arms_value = result.get("arms")
    if not isinstance(arms_value, Mapping) or set(arms_value) != set(FORMAL_VALIDATOR_ARMS):
        raise ValidatorExperimentError("validator experiment must contain Arms A-E exactly")
    arms: Mapping[str, Any] = arms_value
    trial_by_key: Dict[Tuple[str, int], Mapping[str, Any]] = {}
    arm_a_row = _require_exact(arms["A"], _ARM_FIELDS, label="Arm A")
    arm_a_trials = arm_a_row.get("trials")
    if not isinstance(arm_a_trials, list):
        raise ValidatorExperimentError("Arm A trials must be a list")
    arm_a_median_fdr = float(
        statistics.median(
            _require_number(
                _require_exact(trial, _TRIAL_FIELDS, label="Arm A trial").get(
                    "actionable_false_discovery_rate"
                ),
                label="Arm A trial actionable FDR",
                minimum=0.0,
            )
            for trial in arm_a_trials
        )
    )

    for arm_id in FORMAL_VALIDATOR_ARMS:
        arm = _require_exact(arms[arm_id], _ARM_FIELDS, label=f"Arm {arm_id}")
        if arm.get("arm_id") != arm_id or arm.get("baseline") is not (arm_id == "A"):
            raise ValidatorExperimentError(f"Arm {arm_id} identity/baseline is invalid")
        if (
            isinstance(arm.get("arm_revision"), bool)
            or not isinstance(arm.get("arm_revision"), int)
            or int(arm["arm_revision"]) <= 0
            or not _is_sha256(arm.get("arm_spec_sha256"))
            or not isinstance(arm.get("protocol_mode"), str)
            or not str(arm.get("protocol_mode")).strip()
            or arm.get("trial_count") != FORMAL_COLD_TRIALS_PER_ARM
        ):
            raise ValidatorExperimentError(f"Arm {arm_id} metadata is invalid")
        cap = arm.get("configured_cost_expectation_tokens")
        if isinstance(cap, bool) or not isinstance(cap, int) or cap <= 0:
            raise ValidatorExperimentError(f"Arm {arm_id} cost expectation is invalid")

        trials_value = arm.get("trials")
        if not isinstance(trials_value, list) or len(trials_value) != FORMAL_COLD_TRIALS_PER_ARM:
            raise ValidatorExperimentError(f"Arm {arm_id} requires exactly five trials")
        indexes: list[int] = []
        for trial_value in trials_value:
            trial = _require_exact(trial_value, _TRIAL_FIELDS, label=f"Arm {arm_id} trial")
            index = trial.get("trial_index")
            if isinstance(index, bool) or not isinstance(index, int):
                raise ValidatorExperimentError(f"Arm {arm_id} trial index is invalid")
            indexes.append(index)
            if not _is_sha256(trial.get("run_sha256")):
                raise ValidatorExperimentError(f"Arm {arm_id} trial run hash is invalid")
            for field in (
                "confirmed_count",
                "true_positives",
                "false_positives_raw",
                "total_tokens",
                "call_count",
                "provider_reported_call_count",
                "protocol_anomaly_count",
            ):
                value = trial.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValidatorExperimentError(f"Arm {arm_id} trial {field} is invalid")
            for field in ("recall", "actionable_false_discovery_rate", "provider_usage_coverage"):
                numeric = _require_number(trial.get(field), label=f"Arm {arm_id} trial {field}")
                if not 0.0 <= numeric <= 1.0:
                    raise ValidatorExperimentError(f"Arm {arm_id} trial {field} is out of range")
            for field in (
                "queue_drained",
                "token_conserved",
                "cost_expectation_met",
                "complete",
            ):
                if not isinstance(trial.get(field), bool):
                    raise ValidatorExperimentError(f"Arm {arm_id} trial {field} is not boolean")
            truth_ids = trial.get("true_positive_truth_ids")
            if (
                not isinstance(truth_ids, list)
                or any(not isinstance(value, str) or not value for value in truth_ids)
                or truth_ids != sorted(set(truth_ids))
                or len(truth_ids) != int(trial["true_positives"])
                or float(trial["recall"]) != int(trial["true_positives"]) / RANGE_GROUND_TRUTH_COUNT
            ):
                raise ValidatorExperimentError(f"Arm {arm_id} trial truth scoring is inconsistent")
            trial_by_key[(arm_id, index)] = trial
        if indexes != list(range(1, FORMAL_COLD_TRIALS_PER_ARM + 1)):
            raise ValidatorExperimentError(f"Arm {arm_id} trials are not ordered 1-5")

        metrics = _require_exact(arm.get("metrics"), _METRIC_FIELDS, label=f"Arm {arm_id} metrics")
        expected_metrics = _aggregate_trials(trials_value, arm_a_median_fdr=arm_a_median_fdr)
        if dict(metrics) != expected_metrics:
            raise ValidatorExperimentError(f"Arm {arm_id} aggregate metrics do not conserve")
        gates = arm.get("gates")
        expected_gates = _arm_gates(expected_metrics)
        if not isinstance(gates, Mapping) or set(gates) != set(_EXPERIMENT_GATE_NAMES):
            raise ValidatorExperimentError(f"Arm {arm_id} gate schema is invalid")
        for gate_name, gate_value in gates.items():
            _require_exact(gate_value, _GATE_FIELDS, label=f"Arm {arm_id} gate {gate_name}")
        if dict(gates) != expected_gates:
            raise ValidatorExperimentError(f"Arm {arm_id} gates disagree with the frozen policy")
        expected_passed = all(gate["passed"] is True for gate in expected_gates.values())
        if arm.get("passed") is not expected_passed:
            raise ValidatorExperimentError(f"Arm {arm_id} passed status is invalid")

    runs = inputs.get("runs")
    if not isinstance(runs, list) or len(runs) != len(_expected_trial_keys()):
        raise ValidatorExperimentError("validator experiment run input matrix is incomplete")
    run_keys: list[Tuple[str, int]] = []
    identities: list[Mapping[str, Any]] = []
    run_hashes: list[str] = []
    for value in runs:
        row = _require_exact(value, _RUN_INPUT_FIELDS, label="run input")
        raw_arm_id = row.get("arm_id")
        trial_index = row.get("trial_index")
        if (
            raw_arm_id not in FORMAL_VALIDATOR_ARMS
            or isinstance(trial_index, bool)
            or not isinstance(trial_index, int)
        ):
            raise ValidatorExperimentError("run input arm/trial identity is invalid")
        run_arm_id = str(raw_arm_id)
        key = (run_arm_id, trial_index)
        run_keys.append(key)
        scored_trial = trial_by_key.get(key)
        if scored_trial is None:
            raise ValidatorExperimentError("run input has no scored trial")
        if (
            row.get("schema_version") != REPLAY_RUN_SCHEMA_VERSION
            or row.get("run_sha256") != scored_trial.get("run_sha256")
            or row.get("total_tokens") != scored_trial.get("total_tokens")
            or row.get("ledger_complete") is not scored_trial.get("complete")
            or row.get("arm_spec_sha256") != arms[run_arm_id]["arm_spec_sha256"]
            or row.get("expected_total_tokens") != arms[run_arm_id]["configured_cost_expectation_tokens"]
            or not _is_sha256(row.get("file_sha256"))
        ):
            raise ValidatorExperimentError("run input does not bind its scored trial")
        identity = _require_exact(
            row.get("execution_identity"), _EXECUTION_IDENTITY_FIELDS, label="execution identity"
        )
        if any(not _is_sha256(identity.get(field)) for field in _EXECUTION_IDENTITY_FIELDS):
            raise ValidatorExperimentError("run execution identity contains an invalid hash")
        identities.append(identity)
        run_hashes.append(str(row["run_sha256"]))
    if run_keys != sorted(_expected_trial_keys()) or len(set(run_hashes)) != len(run_hashes):
        raise ValidatorExperimentError("run inputs are not unique and ordered Arms A-E trials 1-5")
    if not identities:
        raise ValidatorExperimentError("run inputs have no execution identity")
    by_arm: Dict[str, list[Mapping[str, Any]]] = {arm_id: [] for arm_id in FORMAL_VALIDATOR_ARMS}
    for key, identity in zip(run_keys, identities):
        by_arm[key[0]].append(identity)
    if any(
        not values or any(dict(value) != dict(values[0]) for value in values[1:])
        for values in by_arm.values()
    ):
        raise ValidatorExperimentError("run inputs do not keep a fixed identity within each arm")
    model_specs = {str(identity["model_spec_sha256"]) for identity in identities}
    if len(model_specs) != 1:
        raise ValidatorExperimentError("run inputs do not share one model spec")
    if any(dict(by_arm[arm_id][0]) != dict(by_arm["A"][0]) for arm_id in ("B", "C", "D")):
        raise ValidatorExperimentError("built-in Arms A-D do not share one execution identity")

    selection = _require_exact(result.get("selection"), _SELECTION_FIELDS, label="selection")
    expected_selection = _selection(arms)
    if dict(selection) != expected_selection:
        raise ValidatorExperimentError("validator experiment selection is invalid")


def write_validator_replay_experiment(path: Path, result: Mapping[str, Any]) -> None:
    validate_validator_replay_experiment(result)
    Path(path).write_text(
        json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def load_validator_replay_experiment(path: Path) -> Dict[str, Any]:
    selected = Path(path)
    try:
        raw = selected.read_bytes()
    except OSError as exc:
        raise ValidatorExperimentError(f"cannot load validator experiment: {selected}") from exc
    result = _strict_json_bytes(raw, label="validator experiment")
    validate_validator_replay_experiment(result)
    return result


__all__ = [
    "BALANCED_DEFAULT_EXPECTED_MAX_TOKENS",
    "FORMAL_COLD_TRIALS_PER_ARM",
    "FORMAL_VALIDATOR_ARMS",
    "RANGE_GROUND_TRUTH_COUNT",
    "VALIDATOR_EXPERIMENT_SCHEMA_VERSION",
    "ValidatorExperimentError",
    "load_validator_replay_experiment",
    "score_validator_replay_experiment",
    "validate_validator_replay_experiment",
    "write_validator_replay_experiment",
]
