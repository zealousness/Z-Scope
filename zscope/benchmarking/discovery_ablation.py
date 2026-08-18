"""Answer-free, hash-bound D0-D4 semantic/discovery ablation contracts.

This module never loads benchmark truth.  It freezes the input/configuration
identity shared by all five arms, emits isolated run requests, and validates
reports returned by an explicitly injected scanner adapter.  D0-D3 use a
factory-only in-process stage override; D4 is an external legacy executor
contract and can never be silently projected onto the bounded production path.
"""

from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Sequence, Tuple, Union

try:  # pragma: no cover - exercised through the configured project dependency
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from .replay_bundle import canonical_json_sha256
from .validator_replay import load_validator_arm_catalog, validator_arm
from ..framework.llm_usage import TOKEN_USAGE_STAGES


ABLATION_CATALOG_SCHEMA_VERSION = "zscope.discovery-ablation-arm-catalog.v1"
ABLATION_PLAN_SCHEMA_VERSION = "zscope.discovery-ablation-plan.v1"
ABLATION_RUN_REQUEST_SCHEMA_VERSION = "zscope.discovery-ablation-run-request.v1"
ABLATION_RUNTIME_SCHEMA_VERSION = "zscope.discovery-ablation-runtime-override.v1"
ABLATION_EXECUTION_SCHEMA_VERSION = "zscope.discovery-ablation-execution.v1"
FIXED_VALIDATOR_CONFIG_SCHEMA_VERSION = "zscope.fixed-validator-config.v1"
DEFAULT_ABLATION_CATALOG_FILE = "discovery_ablation_arms.v1.json"
ABLATION_ARM_IDS: Tuple[str, ...] = ("D0", "D1", "D2", "D3", "D4")
ABLATION_EXPECTED_MAX_TOKENS = 12_000_000
ABLATION_COLD_TRIALS = 5
ABLATION_USAGE_EVIDENCE_SCHEMA_VERSION = "zscope.discovery-ablation-usage-evidence.v1"
NON_FORMAL_IN_PROCESS_MODE = "non_formal_in_process"

_CATALOG_FIELDS = frozenset(
    {
        "schema_version",
        "catalog_revision",
        "plan_schema_version",
        "run_request_schema_version",
        "expected_max_tokens",
        "trials_per_arm",
        "expected_stage_tokens",
        "arms",
        "catalog_sha256",
    }
)
_ARM_FIELDS = frozenset(
    {
        "arm_id",
        "revision",
        "baseline",
        "description",
        "semantic_map_mode",
        "semantic_enrichment_mode",
        "active_discovery_mode",
        "legacy_full_entry_agents_mode",
        "execution_path",
        "executor_protocol",
        "release_eligible",
        "cost_upper_bound",
        "arm_spec_sha256",
    }
)
_STAGE_BUDGET_FIELDS = frozenset(
    {
        "semantic_completion",
        "active_discovery",
        "validator",
        "investigation_remediation_reserve",
    }
)
_VALIDATOR_FIELDS = frozenset(
    {
        "schema_version",
        "selected_arm",
        "validator_protocol_version",
        "validator_result_schema_version",
        "validator_arm_catalog_sha256",
        "validator_arm_spec_sha256",
        "validation_model_spec_sha256",
        "validation_prompt_sha256",
    }
)
_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "catalog",
        "answer_free_input",
        "config_identity",
        "fixed_contract",
        "arms",
        "answer_material_present",
        "release_eligible",
        "plan_seed_sha256",
        "plan_sha256",
    }
)
_PLAN_CATALOG_FIELDS = frozenset({"schema_version", "revision", "catalog_sha256"})
_INPUT_FIELDS = frozenset(
    {"dataset_id", "manifest_schema_version", "file_sha256", "payload_sha256"}
)
_CONFIG_IDENTITY_FIELDS = frozenset(
    {
        "config_sha256",
        "runtime_spec_sha256",
        "validator_config_sha256",
        "model_spec_sha256",
        "scanner_bundle_sha256",
        "rule_catalog_sha256",
        "prompt_bundle_sha256",
        "production_executor_sha256",
        "legacy_executor_sha256",
        "combined_sha256",
    }
)
_FIXED_CONTRACT_FIELDS = frozenset(
    {
        "scan_depth",
        "expected_max_tokens",
        "cold_trials_per_arm",
        "cache_mode",
        "expected_stage_tokens",
        "validator_config",
        "candidate_ledger_policy",
        "truth_access",
        "release_policy",
    }
)
_PLAN_ARM_FIELDS = frozenset({"arm_spec", "executor_sha256", "runs"})
_RUN_SLOT_FIELDS = frozenset(
    {
        "trial_index",
        "run_id",
        "expected_max_tokens",
        "cache_mode",
        "execution_path",
        "executor_protocol",
        "request_identity_sha256",
    }
)
_RUN_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "plan_sha256",
        "plan_seed_sha256",
        "arm_spec",
        "trial",
        "answer_free_input",
        "config_identity",
        "fixed_contract",
        "executor_sha256",
        "answer_material_present",
        "release_eligible",
        "request_sha256",
    }
)
_EXECUTION_FIELDS = frozenset(
    {
        "schema_version",
        "request_sha256",
        "plan_sha256",
        "arm_id",
        "trial_index",
        "run_id",
        "execution_path",
        "executor_protocol",
        "executor_sha256",
        "execution_mode",
        "report_sha256",
        "report_contract",
        "usage_sidecar_sha256",
        "answer_free_attested",
        "formal_eligible",
        "answer_material_present",
        "release_eligible",
        "execution_sha256",
    }
)
_USAGE_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "path",
        "sha256",
        "call_count",
        "total_tokens",
        "by_stage",
        "provider_reported_calls",
        "provider_usage_coverage",
        "budget_violation_count",
        "conservative_charge_count",
        "answer_free",
    }
)

_FORBIDDEN_NORMALIZED_KEYS = frozenset(
    {
        "answer",
        "answerkey",
        "benchmarkscore",
        "candidateledger",
        "deterministicfinding",
        "expectedlabel",
        "expectedverdict",
        "falsepositive",
        "findings",
        "groundtruth",
        "isvulnerable",
        "issues",
        "label",
        "matchedpairs",
        "missedtruthids",
        "oracle",
        "precision",
        "recall",
        "ruleconclusion",
        "safe",
        "score",
        "scorer",
        "truepositive",
        "truth",
        "truthid",
        "truthids",
        "verdict",
        "vulnerable",
    }
)
_FORBIDDEN_STRING_MARKERS = (
    "ground_truth",
    "ground-truth",
    "answer_key",
    "answer-key",
    "matched_pairs",
    "truth.json",
    "scorer.py",
)
_FORBIDDEN_ENV_MARKERS = ("GROUND_TRUTH", "BENCHMARK_TRUTH", "ANSWER_KEY", "SCORER")
_REPORT_FORBIDDEN_NORMALIZED_KEYS = frozenset(
    {
        "answerkey",
        "benchmarktruth",
        "expectedlabel",
        "expectedverdict",
        "groundtruth",
        "matchedpairs",
        "oracle",
        "scorer",
        "truth",
        "truthid",
        "truthids",
    }
)


class DiscoveryAblationError(ValueError):
    """Raised when an ablation plan or runtime binding is not trustworthy."""


class DiscoveryAblationExecutor(Protocol):
    """External harness callback; D4 receives a non-runnable runtime binding."""

    def execute(
        self,
        request: Mapping[str, Any],
        runtime_override: "DiscoveryAblationRuntimeOverride",
    ) -> Mapping[str, Any]: ...


DiscoveryAblationExecutorLike = Union[
    DiscoveryAblationExecutor,
    Callable[
        [Mapping[str, Any], "DiscoveryAblationRuntimeOverride"],
        Mapping[str, Any],
    ],
]


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _without_hash(value: Mapping[str, Any], field: str) -> Dict[str, Any]:
    return {key: item for key, item in value.items() if key != field}


def _strict_json_bytes(raw: bytes, *, label: str) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DiscoveryAblationError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise DiscoveryAblationError(f"{label} contains non-finite JSON value: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryAblationError(f"{label} must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise DiscoveryAblationError(f"{label} must be a JSON object")
    return value


def _strict_yaml_bytes(raw: bytes, *, label: str) -> Dict[str, Any]:
    if yaml is None:
        raise DiscoveryAblationError("PyYAML is required to inspect ablation config inputs")

    class UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc,valid-type]
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> Dict[Any, Any]:
        loader.flatten_mapping(node)
        result: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise DiscoveryAblationError(f"{label} contains duplicate YAML key: {key}")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueKeyLoader.add_constructor(  # type: ignore[no-untyped-call]
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=UniqueKeyLoader)
    except DiscoveryAblationError:
        raise
    except Exception as exc:
        raise DiscoveryAblationError(f"{label} must be strict UTF-8 YAML") from exc
    if not isinstance(value, dict):
        raise DiscoveryAblationError(f"{label} must be a YAML object")
    return dict(value)


def _normalize_key(value: Any) -> str:
    return "".join(char for char in str(value or "").lower() if char.isalnum())


def assert_answer_free(value: Any, *, label: str = "ablation input", path: str = "$") -> None:
    """Reject truth, scores, historical findings, and answer-key material recursively."""

    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key)
            if _normalize_key(key) in _FORBIDDEN_NORMALIZED_KEYS:
                raise DiscoveryAblationError(f"{label} contains forbidden field at {path}.{key}")
            assert_answer_free(nested, label=label, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            assert_answer_free(nested, label=label, path=f"{path}[{index}]")
        return
    if isinstance(value, str):
        lowered = value.replace("\\", "/").lower()
        marker = next((item for item in _FORBIDDEN_STRING_MARKERS if item in lowered), "")
        if marker:
            raise DiscoveryAblationError(
                f"{label} contains forbidden answer-material marker at {path}: {marker}"
            )


def _read_structured(path: Path, *, label: str) -> Tuple[Dict[str, Any], str, str]:
    selected = Path(path)
    lowered_path = selected.as_posix().lower()
    if any(marker in lowered_path for marker in _FORBIDDEN_STRING_MARKERS):
        raise DiscoveryAblationError(f"{label} path appears to contain answer material")
    try:
        raw = selected.read_bytes()
    except OSError as exc:
        raise DiscoveryAblationError(f"cannot read {label}: {selected}") from exc
    value = (
        _strict_json_bytes(raw, label=label)
        if selected.suffix.lower() == ".json"
        else _strict_yaml_bytes(raw, label=label)
    )
    assert_answer_free(value, label=label)
    return value, _sha256_bytes(raw), canonical_json_sha256(value)


def reject_truth_environment(environment: Optional[Mapping[str, str]] = None) -> None:
    source = environment if environment is not None else os.environ
    forbidden = sorted(
        key
        for key, value in source.items()
        if value and any(marker in key.upper() for marker in _FORBIDDEN_ENV_MARKERS)
    )
    if forbidden:
        raise DiscoveryAblationError(
            "ablation planning refuses truth-bearing environment variables: " + ", ".join(forbidden)
        )


def validate_fixed_validator_config(value: Mapping[str, Any]) -> None:
    if set(value) != _VALIDATOR_FIELDS:
        raise DiscoveryAblationError("fixed Validator config has missing or unknown fields")
    if value.get("schema_version") != FIXED_VALIDATOR_CONFIG_SCHEMA_VERSION:
        raise DiscoveryAblationError("fixed Validator config schema_version is invalid")
    if value.get("validator_protocol_version") != "zscope.validator-protocol.v3":
        raise DiscoveryAblationError("ablation requires Validator protocol v3")
    if value.get("validator_result_schema_version") != "zscope.validator-result.v3":
        raise DiscoveryAblationError("ablation requires ValidatorResult v3")
    selected_arm = str(value.get("selected_arm") or "")
    if selected_arm not in {"B", "C", "D"}:
        raise DiscoveryAblationError("selected Validator arm must be the winning B, C, or D arm")
    catalog = load_validator_arm_catalog()
    selected = validator_arm(catalog, selected_arm)
    expected = {
        "validator_arm_catalog_sha256": catalog["catalog_sha256"],
        "validator_arm_spec_sha256": selected["arm_spec_sha256"],
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise DiscoveryAblationError(f"fixed Validator config {field} mismatch")
    for field in ("validation_model_spec_sha256", "validation_prompt_sha256"):
        if not _is_sha256(value.get(field)):
            raise DiscoveryAblationError(f"fixed Validator config {field} must be SHA-256")


def validate_discovery_ablation_catalog(catalog: Mapping[str, Any]) -> None:
    if set(catalog) != _CATALOG_FIELDS:
        raise DiscoveryAblationError("ablation arm catalog has missing or unknown fields")
    if catalog.get("schema_version") != ABLATION_CATALOG_SCHEMA_VERSION:
        raise DiscoveryAblationError("ablation arm catalog schema_version is invalid")
    if catalog.get("catalog_revision") != 1:
        raise DiscoveryAblationError("ablation arm catalog revision must be 1")
    if catalog.get("plan_schema_version") != ABLATION_PLAN_SCHEMA_VERSION:
        raise DiscoveryAblationError("ablation arm catalog plan schema is invalid")
    if catalog.get("run_request_schema_version") != ABLATION_RUN_REQUEST_SCHEMA_VERSION:
        raise DiscoveryAblationError("ablation arm catalog request schema is invalid")
    if catalog.get("expected_max_tokens") != ABLATION_EXPECTED_MAX_TOKENS:
        raise DiscoveryAblationError("all ablation arms must use the same 12M cost expectation")
    if catalog.get("trials_per_arm") != ABLATION_COLD_TRIALS:
        raise DiscoveryAblationError("ablation catalog must schedule five cold trials per arm")
    budgets = catalog.get("expected_stage_tokens")
    if not isinstance(budgets, Mapping) or set(budgets) != _STAGE_BUDGET_FIELDS:
        raise DiscoveryAblationError("ablation stage budget has missing or unknown fields")
    expected_budgets = {
        "semantic_completion": 1_000_000,
        "active_discovery": 2_500_000,
        "validator": 8_000_000,
        "investigation_remediation_reserve": 500_000,
    }
    if (
        dict(budgets) != expected_budgets
        or sum(int(item) for item in budgets.values()) != 12_000_000
    ):
        raise DiscoveryAblationError("ablation stage budgets must equal the balanced allocation")
    arms = catalog.get("arms")
    if not isinstance(arms, list) or len(arms) != len(ABLATION_ARM_IDS):
        raise DiscoveryAblationError("ablation catalog must contain D0-D4 exactly once")
    seen = []
    for index, raw in enumerate(arms):
        if not isinstance(raw, Mapping) or set(raw) != _ARM_FIELDS:
            raise DiscoveryAblationError(f"arms[{index}] has missing or unknown fields")
        arm_id = str(raw.get("arm_id") or "")
        seen.append(arm_id)
        if raw.get("revision") != 1 or not str(raw.get("description") or ""):
            raise DiscoveryAblationError(f"arms[{index}] identity is invalid")
        if not isinstance(raw.get("baseline"), bool):
            raise DiscoveryAblationError(f"arms[{index}].baseline must be boolean")
        if raw.get("release_eligible") is not False:
            raise DiscoveryAblationError("ablation artifacts must never be release eligible")
        if not isinstance(raw.get("cost_upper_bound"), bool):
            raise DiscoveryAblationError(f"arms[{index}].cost_upper_bound must be boolean")
        legacy = arm_id == "D4"
        if legacy:
            expected_modes = (
                "legacy_executor_owned",
                "legacy_executor_owned",
                "legacy_executor_owned",
                "active",
                "external_legacy_full_entry",
                "zscope.discovery-ablation-legacy-full-entry-executor.v1",
            )
        else:
            expected_modes_by_arm = {
                "D0": ("disabled", "disabled", "disabled"),
                "D1": ("evidence_backed", "active", "disabled"),
                "D2": ("zero_llm_skeleton", "disabled", "active"),
                "D3": ("evidence_backed", "active", "active"),
            }
            expected_modes = (
                *expected_modes_by_arm.get(arm_id, ()),
                "disabled",
                "production_bounded_pipeline",
                "zscope.discovery-ablation-production-executor.v1",
            )
        actual_modes = (
            raw.get("semantic_map_mode"),
            raw.get("semantic_enrichment_mode"),
            raw.get("active_discovery_mode"),
            raw.get("legacy_full_entry_agents_mode"),
            raw.get("execution_path"),
            raw.get("executor_protocol"),
        )
        if actual_modes != expected_modes:
            raise DiscoveryAblationError(f"arms[{index}] stage contract is invalid")
        if raw.get("cost_upper_bound") is not legacy:
            raise DiscoveryAblationError("D4 must be the sole cost-upper-bound arm")
        if raw.get("arm_spec_sha256") != canonical_json_sha256(
            _without_hash(raw, "arm_spec_sha256")
        ):
            raise DiscoveryAblationError(f"arms[{index}] arm_spec_sha256 mismatch")
    if seen != list(ABLATION_ARM_IDS) or arms[0].get("baseline") is not True:
        raise DiscoveryAblationError("ablation arms must be ordered D0-D4 with D0 baseline")
    if sum(int(raw.get("baseline") is True) for raw in arms) != 1:
        raise DiscoveryAblationError("D0 must be the sole ablation baseline")
    if catalog.get("catalog_sha256") != canonical_json_sha256(
        _without_hash(catalog, "catalog_sha256")
    ):
        raise DiscoveryAblationError("ablation catalog_sha256 mismatch")


def load_discovery_ablation_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    if path is None:
        resource = files(__package__).joinpath(DEFAULT_ABLATION_CATALOG_FILE)
        try:
            loaded = json.loads(resource.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DiscoveryAblationError("cannot load packaged ablation catalog") from exc
        if not isinstance(loaded, dict):
            raise DiscoveryAblationError("packaged ablation catalog must be an object")
        value: Dict[str, Any] = dict(loaded)
    else:
        try:
            value = _strict_json_bytes(Path(path).read_bytes(), label="ablation catalog")
        except OSError as exc:
            raise DiscoveryAblationError(f"cannot read ablation catalog: {path}") from exc
    validate_discovery_ablation_catalog(value)
    return dict(value)


def discovery_ablation_arm(catalog: Mapping[str, Any], arm_id: str) -> Dict[str, Any]:
    validate_discovery_ablation_catalog(catalog)
    normalized = str(arm_id or "").upper()
    for raw in catalog["arms"]:
        if raw["arm_id"] == normalized:
            return dict(raw)
    raise DiscoveryAblationError(f"unknown discovery ablation arm: {arm_id}")


def build_discovery_ablation_plan(
    *,
    dataset_id: str,
    answer_free_manifest: Path,
    config: Path,
    runtime_spec: Path,
    validator_config: Path,
    model_spec: Path,
    scanner_bundle_sha256: str,
    rule_catalog_sha256: str,
    prompt_bundle_sha256: str,
    production_executor_sha256: str,
    legacy_executor_sha256: str,
    expected_answer_free_manifest_sha256: str,
    catalog_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Freeze a five-arm plan without executing a model or opening truth."""

    reject_truth_environment()
    normalized_dataset = str(dataset_id or "").strip()
    if not normalized_dataset or len(normalized_dataset) > 160:
        raise DiscoveryAblationError("dataset_id must be 1-160 characters")
    assert_answer_free(normalized_dataset, label="dataset_id")
    manifest, manifest_file_sha, manifest_payload_sha = _read_structured(
        answer_free_manifest,
        label="answer-free manifest",
    )
    if not _is_sha256(expected_answer_free_manifest_sha256):
        raise DiscoveryAblationError("expected answer-free manifest SHA-256 is required")
    if manifest_file_sha != expected_answer_free_manifest_sha256:
        raise DiscoveryAblationError("answer-free manifest file SHA-256 mismatch")
    config_value, config_sha, _ = _read_structured(config, label="scan config")
    runtime_value, runtime_sha, _ = _read_structured(runtime_spec, label="RuntimeSpec")
    fixed_validator, validator_sha, _ = _read_structured(
        validator_config,
        label="fixed Validator config",
    )
    _model_value, model_sha, _ = _read_structured(model_spec, label="model spec")
    if config_value.get("config_version") != 2:
        raise DiscoveryAblationError("ablation scan config must use config_version: 2")
    scan = config_value.get("scan")
    if not isinstance(scan, Mapping):
        raise DiscoveryAblationError("ablation scan config must contain an explicit scan object")
    if scan.get("depth") != "balanced":
        raise DiscoveryAblationError("all ablation arms require explicit balanced depth")
    if runtime_value.get("runtime_spec_version") != 1:
        raise DiscoveryAblationError("ablation RuntimeSpec must use runtime_spec_version: 1")
    validate_fixed_validator_config(fixed_validator)
    if fixed_validator["validation_model_spec_sha256"] != model_sha:
        raise DiscoveryAblationError(
            "fixed Validator model SHA-256 does not match the frozen model spec file"
        )
    if fixed_validator["validation_prompt_sha256"] != prompt_bundle_sha256:
        raise DiscoveryAblationError(
            "fixed Validator prompt SHA-256 does not match the frozen prompt bundle"
        )
    identity_hash_fields = {
        "scanner_bundle_sha256": scanner_bundle_sha256,
        "rule_catalog_sha256": rule_catalog_sha256,
        "prompt_bundle_sha256": prompt_bundle_sha256,
        "production_executor_sha256": production_executor_sha256,
        "legacy_executor_sha256": legacy_executor_sha256,
    }
    invalid = [field for field, value in identity_hash_fields.items() if not _is_sha256(value)]
    if invalid:
        raise DiscoveryAblationError(
            "ablation execution identity requires SHA-256 fields: " + ", ".join(invalid)
        )
    catalog = load_discovery_ablation_catalog(catalog_path)
    config_identity: Dict[str, Any] = {
        "config_sha256": config_sha,
        "runtime_spec_sha256": runtime_sha,
        "validator_config_sha256": validator_sha,
        "model_spec_sha256": model_sha,
        **identity_hash_fields,
    }
    config_identity["combined_sha256"] = canonical_json_sha256(config_identity)
    answer_free_input = {
        "dataset_id": normalized_dataset,
        "manifest_schema_version": str(manifest.get("schema_version") or "unversioned"),
        "file_sha256": manifest_file_sha,
        "payload_sha256": manifest_payload_sha,
    }
    fixed_contract = {
        "scan_depth": "balanced",
        "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
        "cold_trials_per_arm": ABLATION_COLD_TRIALS,
        "cache_mode": "isolated_cold",
        "expected_stage_tokens": dict(catalog["expected_stage_tokens"]),
        "validator_config": dict(fixed_validator),
        "candidate_ledger_policy": "shared_ledger_freeze_before_fixed_validator",
        "truth_access": "forbidden_until_all_arm_reports_are_frozen",
        "release_policy": "ablation_artifacts_are_never_release_eligible",
    }
    seed = {
        "catalog_sha256": catalog["catalog_sha256"],
        "answer_free_input": answer_free_input,
        "config_identity": config_identity,
        "fixed_contract": fixed_contract,
    }
    plan_seed_sha256 = canonical_json_sha256(seed)
    plan_arms = []
    for raw_arm in catalog["arms"]:
        arm = dict(raw_arm)
        executor_sha = (
            legacy_executor_sha256
            if arm["execution_path"] == "external_legacy_full_entry"
            else production_executor_sha256
        )
        runs = []
        for trial_index in range(1, ABLATION_COLD_TRIALS + 1):
            run_identity = {
                "plan_seed_sha256": plan_seed_sha256,
                "arm_spec_sha256": arm["arm_spec_sha256"],
                "trial_index": trial_index,
                "executor_sha256": executor_sha,
                "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
                "cache_mode": "isolated_cold",
            }
            request_identity_sha256 = canonical_json_sha256(run_identity)
            runs.append(
                {
                    "trial_index": trial_index,
                    "run_id": f"{arm['arm_id'].lower()}-{request_identity_sha256[:20]}",
                    "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
                    "cache_mode": "isolated_cold",
                    "execution_path": arm["execution_path"],
                    "executor_protocol": arm["executor_protocol"],
                    "request_identity_sha256": request_identity_sha256,
                }
            )
        plan_arms.append({"arm_spec": arm, "executor_sha256": executor_sha, "runs": runs})
    plan: Dict[str, Any] = {
        "schema_version": ABLATION_PLAN_SCHEMA_VERSION,
        "catalog": {
            "schema_version": catalog["schema_version"],
            "revision": catalog["catalog_revision"],
            "catalog_sha256": catalog["catalog_sha256"],
        },
        "answer_free_input": answer_free_input,
        "config_identity": config_identity,
        "fixed_contract": fixed_contract,
        "arms": plan_arms,
        "answer_material_present": False,
        "release_eligible": False,
        "plan_seed_sha256": plan_seed_sha256,
    }
    plan["plan_sha256"] = canonical_json_sha256(plan)
    validate_discovery_ablation_plan(plan, catalog_path=catalog_path)
    return plan


def validate_discovery_ablation_plan(
    plan: Mapping[str, Any],
    *,
    catalog_path: Optional[Path] = None,
) -> None:
    if set(plan) != _PLAN_FIELDS:
        raise DiscoveryAblationError("ablation plan has missing or unknown fields")
    if plan.get("schema_version") != ABLATION_PLAN_SCHEMA_VERSION:
        raise DiscoveryAblationError("ablation plan schema_version is invalid")
    if (
        plan.get("answer_material_present") is not False
        or plan.get("release_eligible") is not False
    ):
        raise DiscoveryAblationError("ablation plan must be answer-free and release-ineligible")
    assert_answer_free(plan, label="ablation plan")
    catalog = load_discovery_ablation_catalog(catalog_path)
    catalog_identity = plan.get("catalog")
    if not isinstance(catalog_identity, Mapping) or set(catalog_identity) != _PLAN_CATALOG_FIELDS:
        raise DiscoveryAblationError("ablation plan catalog identity is invalid")
    if dict(catalog_identity) != {
        "schema_version": catalog["schema_version"],
        "revision": catalog["catalog_revision"],
        "catalog_sha256": catalog["catalog_sha256"],
    }:
        raise DiscoveryAblationError("ablation plan catalog identity mismatch")
    answer_free_input = plan.get("answer_free_input")
    if not isinstance(answer_free_input, Mapping) or set(answer_free_input) != _INPUT_FIELDS:
        raise DiscoveryAblationError("ablation answer-free input identity is invalid")
    if not str(answer_free_input.get("dataset_id") or ""):
        raise DiscoveryAblationError("ablation dataset_id is missing")
    for field in ("file_sha256", "payload_sha256"):
        if not _is_sha256(answer_free_input.get(field)):
            raise DiscoveryAblationError(f"ablation input {field} must be SHA-256")
    config_identity = plan.get("config_identity")
    if not isinstance(config_identity, Mapping) or set(config_identity) != _CONFIG_IDENTITY_FIELDS:
        raise DiscoveryAblationError("ablation config identity is invalid")
    for field, value in config_identity.items():
        if not _is_sha256(value):
            raise DiscoveryAblationError(f"ablation config identity {field} must be SHA-256")
    if config_identity.get("combined_sha256") != canonical_json_sha256(
        _without_hash(config_identity, "combined_sha256")
    ):
        raise DiscoveryAblationError("ablation combined config identity mismatch")
    fixed = plan.get("fixed_contract")
    if not isinstance(fixed, Mapping) or set(fixed) != _FIXED_CONTRACT_FIELDS:
        raise DiscoveryAblationError("ablation fixed contract is invalid")
    if (
        fixed.get("scan_depth") != "balanced"
        or fixed.get("expected_max_tokens") != ABLATION_EXPECTED_MAX_TOKENS
        or fixed.get("cold_trials_per_arm") != ABLATION_COLD_TRIALS
        or fixed.get("cache_mode") != "isolated_cold"
    ):
        raise DiscoveryAblationError("ablation fixed scan settings are invalid")
    if fixed.get("expected_stage_tokens") != catalog["expected_stage_tokens"]:
        raise DiscoveryAblationError("ablation fixed stage budget mismatch")
    validator_config = fixed.get("validator_config")
    if not isinstance(validator_config, Mapping):
        raise DiscoveryAblationError("ablation fixed Validator config is missing")
    validate_fixed_validator_config(validator_config)
    if validator_config.get("validation_model_spec_sha256") != config_identity.get(
        "model_spec_sha256"
    ) or validator_config.get("validation_prompt_sha256") != config_identity.get(
        "prompt_bundle_sha256"
    ):
        raise DiscoveryAblationError(
            "ablation fixed Validator model/prompt identity is not config-bound"
        )
    seed = {
        "catalog_sha256": catalog["catalog_sha256"],
        "answer_free_input": dict(answer_free_input),
        "config_identity": dict(config_identity),
        "fixed_contract": dict(fixed),
    }
    if plan.get("plan_seed_sha256") != canonical_json_sha256(seed):
        raise DiscoveryAblationError("ablation plan seed SHA-256 mismatch")
    arms = plan.get("arms")
    if not isinstance(arms, list) or len(arms) != len(ABLATION_ARM_IDS):
        raise DiscoveryAblationError("ablation plan must contain D0-D4")
    for index, raw in enumerate(arms):
        if not isinstance(raw, Mapping) or set(raw) != _PLAN_ARM_FIELDS:
            raise DiscoveryAblationError(f"plan arms[{index}] is invalid")
        arm = raw.get("arm_spec")
        if not isinstance(arm, Mapping) or dict(arm) != dict(catalog["arms"][index]):
            raise DiscoveryAblationError(f"plan arms[{index}] catalog spec mismatch")
        expected_executor = (
            config_identity["legacy_executor_sha256"]
            if arm["execution_path"] == "external_legacy_full_entry"
            else config_identity["production_executor_sha256"]
        )
        if raw.get("executor_sha256") != expected_executor:
            raise DiscoveryAblationError(f"plan arms[{index}] executor identity mismatch")
        runs = raw.get("runs")
        if not isinstance(runs, list) or len(runs) != ABLATION_COLD_TRIALS:
            raise DiscoveryAblationError(f"plan arms[{index}] must contain five cold runs")
        for trial_index, run in enumerate(runs, start=1):
            if not isinstance(run, Mapping) or set(run) != _RUN_SLOT_FIELDS:
                raise DiscoveryAblationError(f"plan arms[{index}] run is invalid")
            identity = {
                "plan_seed_sha256": plan["plan_seed_sha256"],
                "arm_spec_sha256": arm["arm_spec_sha256"],
                "trial_index": trial_index,
                "executor_sha256": expected_executor,
                "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
                "cache_mode": "isolated_cold",
            }
            expected_request_identity = canonical_json_sha256(identity)
            expected_run = {
                "trial_index": trial_index,
                "run_id": f"{arm['arm_id'].lower()}-{expected_request_identity[:20]}",
                "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
                "cache_mode": "isolated_cold",
                "execution_path": arm["execution_path"],
                "executor_protocol": arm["executor_protocol"],
                "request_identity_sha256": expected_request_identity,
            }
            if dict(run) != expected_run:
                raise DiscoveryAblationError(f"plan arms[{index}] run identity mismatch")
    if plan.get("plan_sha256") != canonical_json_sha256(_without_hash(plan, "plan_sha256")):
        raise DiscoveryAblationError("ablation plan_sha256 mismatch")


def load_discovery_ablation_plan(
    path: Path,
    *,
    expected_plan_sha256: str,
    catalog_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if not _is_sha256(expected_plan_sha256):
        raise DiscoveryAblationError("expected ablation plan SHA-256 is required")
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise DiscoveryAblationError(f"cannot read ablation plan: {path}") from exc
    plan = _strict_json_bytes(raw, label="ablation plan")
    validate_discovery_ablation_plan(plan, catalog_path=catalog_path)
    if plan["plan_sha256"] != expected_plan_sha256:
        raise DiscoveryAblationError("ablation plan expected SHA-256 mismatch")
    return plan


def build_discovery_ablation_run_request(
    plan: Mapping[str, Any],
    *,
    arm_id: str,
    trial_index: int,
    expected_plan_sha256: str,
    catalog_path: Optional[Path] = None,
) -> Dict[str, Any]:
    validate_discovery_ablation_plan(plan, catalog_path=catalog_path)
    if plan.get("plan_sha256") != expected_plan_sha256 or not _is_sha256(expected_plan_sha256):
        raise DiscoveryAblationError("run request requires the external expected plan SHA-256")
    normalized = str(arm_id or "").upper()
    if normalized not in ABLATION_ARM_IDS:
        raise DiscoveryAblationError(f"unknown discovery ablation arm: {arm_id}")
    if isinstance(trial_index, bool) or not isinstance(trial_index, int):
        raise DiscoveryAblationError("trial_index must be an integer")
    if trial_index < 1 or trial_index > ABLATION_COLD_TRIALS:
        raise DiscoveryAblationError("trial_index must be between 1 and 5")
    raw_arm = plan["arms"][ABLATION_ARM_IDS.index(normalized)]
    request: Dict[str, Any] = {
        "schema_version": ABLATION_RUN_REQUEST_SCHEMA_VERSION,
        "plan_sha256": plan["plan_sha256"],
        "plan_seed_sha256": plan["plan_seed_sha256"],
        "arm_spec": dict(raw_arm["arm_spec"]),
        "trial": dict(raw_arm["runs"][trial_index - 1]),
        "answer_free_input": dict(plan["answer_free_input"]),
        "config_identity": dict(plan["config_identity"]),
        "fixed_contract": dict(plan["fixed_contract"]),
        "executor_sha256": raw_arm["executor_sha256"],
        "answer_material_present": False,
        "release_eligible": False,
    }
    request["request_sha256"] = canonical_json_sha256(request)
    validate_discovery_ablation_run_request(request, catalog_path=catalog_path)
    return request


def validate_discovery_ablation_run_request(
    request: Mapping[str, Any],
    *,
    catalog_path: Optional[Path] = None,
) -> None:
    if set(request) != _RUN_REQUEST_FIELDS:
        raise DiscoveryAblationError("ablation run request has missing or unknown fields")
    if request.get("schema_version") != ABLATION_RUN_REQUEST_SCHEMA_VERSION:
        raise DiscoveryAblationError("ablation run request schema_version is invalid")
    if (
        request.get("answer_material_present") is not False
        or request.get("release_eligible") is not False
    ):
        raise DiscoveryAblationError("ablation run requests are answer-free/release-ineligible")
    assert_answer_free(request, label="ablation run request")
    catalog = load_discovery_ablation_catalog(catalog_path)
    arm = request.get("arm_spec")
    if not isinstance(arm, Mapping):
        raise DiscoveryAblationError("ablation run request arm_spec is missing")
    expected_arm = discovery_ablation_arm(catalog, str(arm.get("arm_id") or ""))
    if dict(arm) != expected_arm:
        raise DiscoveryAblationError("ablation run request arm_spec mismatch")
    trial = request.get("trial")
    if not isinstance(trial, Mapping) or set(trial) != _RUN_SLOT_FIELDS:
        raise DiscoveryAblationError("ablation run request trial is invalid")
    if trial.get("expected_max_tokens") != ABLATION_EXPECTED_MAX_TOKENS:
        raise DiscoveryAblationError("ablation run request lacks the 12M cost expectation")
    if trial.get("cache_mode") != "isolated_cold":
        raise DiscoveryAblationError("ablation run request must be an isolated cold run")
    if trial.get("execution_path") != arm.get("execution_path") or trial.get(
        "executor_protocol"
    ) != arm.get("executor_protocol"):
        raise DiscoveryAblationError("ablation run request execution path mismatch")
    for field in ("plan_sha256", "plan_seed_sha256", "executor_sha256"):
        if not _is_sha256(request.get(field)):
            raise DiscoveryAblationError(f"ablation run request {field} must be SHA-256")
    config_identity = request.get("config_identity")
    if not isinstance(config_identity, Mapping) or set(config_identity) != _CONFIG_IDENTITY_FIELDS:
        raise DiscoveryAblationError("ablation run request config identity is invalid")
    expected_executor = (
        config_identity["legacy_executor_sha256"]
        if arm["execution_path"] == "external_legacy_full_entry"
        else config_identity["production_executor_sha256"]
    )
    if request.get("executor_sha256") != expected_executor:
        raise DiscoveryAblationError("ablation run request executor identity mismatch")
    fixed = request.get("fixed_contract")
    if (
        not isinstance(fixed, Mapping)
        or fixed.get("expected_max_tokens") != ABLATION_EXPECTED_MAX_TOKENS
    ):
        raise DiscoveryAblationError("ablation run request fixed contract is invalid")
    if request.get("request_sha256") != canonical_json_sha256(
        _without_hash(request, "request_sha256")
    ):
        raise DiscoveryAblationError("ablation run request SHA-256 mismatch")


def load_discovery_ablation_run_request(
    path: Path,
    *,
    expected_request_sha256: str,
    catalog_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if not _is_sha256(expected_request_sha256):
        raise DiscoveryAblationError("expected ablation request SHA-256 is required")
    try:
        request = _strict_json_bytes(Path(path).read_bytes(), label="ablation run request")
    except OSError as exc:
        raise DiscoveryAblationError(f"cannot read ablation run request: {path}") from exc
    validate_discovery_ablation_run_request(request, catalog_path=catalog_path)
    if request["request_sha256"] != expected_request_sha256:
        raise DiscoveryAblationError("ablation request expected SHA-256 mismatch")
    return request


def _ablation_report_metadata(report: Mapping[str, Any]) -> Dict[str, Any]:
    metadata = report.get("metadata")
    if not isinstance(metadata, Mapping):
        raise DiscoveryAblationError("ablation executor report metadata is missing")
    raw = metadata.get("benchmark_ablation")
    if not isinstance(raw, Mapping):
        raise DiscoveryAblationError("ablation executor report binding is missing")
    return dict(raw)


def _assert_report_has_no_truth(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key)
            if _normalize_key(key) in _REPORT_FORBIDDEN_NORMALIZED_KEYS:
                raise DiscoveryAblationError(
                    f"ablation executor report contains truth material at {path}.{key}"
                )
            _assert_report_has_no_truth(nested, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _assert_report_has_no_truth(nested, path=f"{path}[{index}]")


def _ablation_report_usage(report: Mapping[str, Any]) -> Dict[str, Any]:
    candidates = [
        report.get("llm_usage"),
        (
            report.get("metadata", {}).get("llm_usage")
            if isinstance(report.get("metadata"), Mapping)
            else None
        ),
        (
            report.get("summary", {}).get("llm_usage")
            if isinstance(report.get("summary"), Mapping)
            else None
        ),
        (
            report.get("run_manifest", {}).get("llm_usage")
            if isinstance(report.get("run_manifest"), Mapping)
            else None
        ),
    ]
    for raw in candidates:
        if isinstance(raw, Mapping) and "consumed_tokens" in raw:
            return dict(raw)
    raise DiscoveryAblationError("ablation executor report LLM usage is missing")


def _usage_evidence_from_report(report: Mapping[str, Any]) -> Dict[str, Any]:
    metadata = report.get("metadata")
    manifest = report.get("run_manifest")
    raw = (
        metadata.get("discovery_ablation_usage_evidence") if isinstance(metadata, Mapping) else None
    )
    manifest_raw = (
        manifest.get("discovery_ablation_usage_evidence") if isinstance(manifest, Mapping) else None
    )
    if not isinstance(raw, Mapping) or set(raw) != _USAGE_EVIDENCE_FIELDS:
        raise DiscoveryAblationError("ablation report raw usage evidence is missing or invalid")
    if not isinstance(manifest_raw, Mapping) or dict(manifest_raw) != dict(raw):
        raise DiscoveryAblationError("ablation report raw usage evidence is not manifest-bound")
    evidence = dict(raw)
    if evidence.get("schema_version") != ABLATION_USAGE_EVIDENCE_SCHEMA_VERSION:
        raise DiscoveryAblationError("ablation raw usage evidence schema_version is invalid")
    if not _is_sha256(evidence.get("sha256")):
        raise DiscoveryAblationError("ablation raw usage sidecar SHA-256 is invalid")
    if not str(evidence.get("path") or ""):
        raise DiscoveryAblationError("ablation raw usage sidecar path is missing")
    for field in (
        "call_count",
        "total_tokens",
        "provider_reported_calls",
        "budget_violation_count",
        "conservative_charge_count",
    ):
        value = evidence.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DiscoveryAblationError(f"ablation raw usage evidence {field} is invalid")
    by_stage = evidence.get("by_stage")
    if not isinstance(by_stage, Mapping) or set(by_stage) != set(TOKEN_USAGE_STAGES):
        raise DiscoveryAblationError("ablation raw usage evidence stage set is invalid")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in by_stage.values()
    ):
        raise DiscoveryAblationError("ablation raw usage evidence stage tokens are invalid")
    if sum(int(value) for value in by_stage.values()) != evidence["total_tokens"]:
        raise DiscoveryAblationError("ablation raw usage evidence stage/run tokens do not conserve")
    if (
        evidence.get("answer_free") is not True
        or evidence["call_count"] <= 0
        or evidence["provider_reported_calls"] != evidence["call_count"]
        or evidence.get("provider_usage_coverage") != 1.0
        or evidence["budget_violation_count"] != 0
        or evidence["conservative_charge_count"] != 0
    ):
        raise DiscoveryAblationError(
            "ablation requires complete provider usage and zero budget/conservative violations"
        )
    return evidence


def _read_raw_usage_evidence(path: Path) -> Tuple[list[Dict[str, Any]], Dict[str, Any]]:
    selected = Path(path)
    if selected.is_symlink() or not selected.is_file():
        raise DiscoveryAblationError("ablation usage sidecar must be a regular non-symlink file")
    try:
        raw_bytes = selected.read_bytes()
        raw_text = raw_bytes.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise DiscoveryAblationError("cannot read strict UTF-8 ablation usage sidecar") from exc
    for line_number, line in enumerate(raw_text.splitlines(), 1):
        if line.strip():
            _strict_json_bytes(line.encode("utf-8"), label=f"usage sidecar line {line_number}")
    # Reuse the formal runner's exact v1 event validator after the duplicate
    # key/non-finite pre-pass above.  The import is lazy to avoid coupling
    # normal scanner imports to the benchmark runner.
    from .runner import BenchmarkError, _read_usage_events_jsonl

    try:
        rows = _read_usage_events_jsonl(selected)
    except (BenchmarkError, OSError) as exc:
        raise DiscoveryAblationError(str(exc)) from exc
    assert_answer_free(rows, label="ablation usage sidecar")
    by_stage = {stage: 0 for stage in TOKEN_USAGE_STAGES}
    for row in rows:
        by_stage[str(row["budget_stage"])] += int(row["total_tokens"])
    evidence = {
        "schema_version": ABLATION_USAGE_EVIDENCE_SCHEMA_VERSION,
        "path": selected.name,
        "sha256": _sha256_bytes(raw_bytes),
        "call_count": len(rows),
        "total_tokens": sum(int(row["total_tokens"]) for row in rows),
        "by_stage": by_stage,
        "provider_reported_calls": sum(row["provider_reported"] is True for row in rows),
        "provider_usage_coverage": round(
            sum(row["provider_reported"] is True for row in rows) / len(rows), 6
        ),
        "budget_violation_count": sum(row["budget_violation"] is True for row in rows),
        "conservative_charge_count": sum(row["conservative_charge"] is True for row in rows),
        "answer_free": True,
    }
    _usage_evidence_from_report(
        {
            "metadata": {"discovery_ablation_usage_evidence": evidence},
            "run_manifest": {"discovery_ablation_usage_evidence": evidence},
        }
    )
    return rows, evidence


def _bind_raw_usage_evidence(report: Dict[str, Any], evidence: Mapping[str, Any]) -> None:
    metadata = report.setdefault("metadata", {})
    manifest = report.setdefault("run_manifest", {})
    if not isinstance(metadata, dict) or not isinstance(manifest, dict):
        raise DiscoveryAblationError("ablation report metadata/run_manifest must be objects")
    metadata["discovery_ablation_usage_evidence"] = dict(evidence)
    manifest["discovery_ablation_usage_evidence"] = dict(evidence)


def validate_discovery_ablation_usage_sidecar(
    path: Path,
    *,
    expected_sha256: str,
) -> Dict[str, Any]:
    """Validate and aggregate one externally hash-bound raw usage sidecar."""

    if not _is_sha256(expected_sha256):
        raise DiscoveryAblationError("expected usage sidecar SHA-256 is invalid")
    _rows, evidence = _read_raw_usage_evidence(Path(path))
    if evidence["sha256"] != expected_sha256:
        raise DiscoveryAblationError("raw usage sidecar does not match its external SHA-256")
    return evidence


def validate_discovery_ablation_report(
    report: Mapping[str, Any],
    request: Mapping[str, Any],
    runtime_override: "DiscoveryAblationRuntimeOverride",
    *,
    catalog_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Validate scanner-owned identity and cost, never quality/truth."""

    validate_discovery_ablation_run_request(request, catalog_path=catalog_path)
    _assert_report_has_no_truth(report)
    if (
        report.get("answer_material_present") is not False
        or report.get("release_eligible") is not False
    ):
        raise DiscoveryAblationError(
            "ablation scanner report must explicitly set answer_material_present=false "
            "and release_eligible=false"
        )
    if report.get("formal_eligible") is not False:
        raise DiscoveryAblationError("ablation scanner report must be explicitly non-formal")
    expected_metadata = runtime_override.report_metadata()
    actual_metadata = _ablation_report_metadata(report)
    if expected_metadata.get("cold_runtime_attested") is False:
        expected_metadata["cold_runtime_attested"] = True
    if actual_metadata != expected_metadata:
        raise DiscoveryAblationError("ablation executor report binding mismatch")
    metadata = report.get("metadata")
    assert isinstance(metadata, Mapping)
    effective_scan = metadata.get("effective_scan")
    if not isinstance(effective_scan, Mapping):
        raise DiscoveryAblationError("ablation report effective_scan is missing")
    if effective_scan.get("depth") != "balanced":
        raise DiscoveryAblationError("ablation report did not use effective balanced depth")
    usage = _ablation_report_usage(report)
    usage_evidence = _usage_evidence_from_report(report)
    consumed = usage.get("consumed_tokens")
    reserved = usage.get("reserved_tokens", 0)
    if isinstance(consumed, bool) or not isinstance(consumed, int) or consumed < 0:
        raise DiscoveryAblationError("ablation report usage consumed_tokens is invalid")
    if isinstance(reserved, bool) or not isinstance(reserved, int) or reserved < 0:
        raise DiscoveryAblationError("ablation report usage reserved_tokens is invalid")
    if consumed != usage_evidence["total_tokens"] or reserved != 0:
        raise DiscoveryAblationError(
            "ablation report usage does not conserve against the raw sidecar or is not drained"
        )
    stage_budget = request["fixed_contract"]["expected_stage_tokens"]
    expected_stage_limits = {
        "semantic_modeling": stage_budget["semantic_completion"],
        "active_discovery": stage_budget["active_discovery"],
        "validation": stage_budget["validator"],
        "reserve": stage_budget["investigation_remediation_reserve"],
    }
    running_tokens = 0
    running_limit = 0
    cost_expectation_failures: list[str] = []
    for stage in TOKEN_USAGE_STAGES:
        running_tokens += int(usage_evidence["by_stage"][stage])
        running_limit += int(expected_stage_limits[stage])
        if running_tokens > running_limit:
            cost_expectation_failures.append(
                f"stage_prefix.{stage}={running_tokens} > {running_limit}"
            )
    if consumed > ABLATION_EXPECTED_MAX_TOKENS:
        cost_expectation_failures.append(
            f"total_tokens={consumed} > {ABLATION_EXPECTED_MAX_TOKENS}"
        )
    attribution = usage.get("usage_attribution")
    if isinstance(attribution, Mapping):
        totals = attribution.get("totals")
        if not isinstance(totals, Mapping):
            raise DiscoveryAblationError("ablation usage attribution totals are missing")
        expected_totals = {
            "request_count": usage_evidence["call_count"],
            "total_tokens": usage_evidence["total_tokens"],
            "provider_reported_calls": usage_evidence["provider_reported_calls"],
            "budget_violation_count": 0,
        }
        if any(totals.get(field) != value for field, value in expected_totals.items()):
            raise DiscoveryAblationError(
                "ablation report usage attribution does not conserve against the raw sidecar"
            )
    return {
        "depth": "balanced",
        "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
        "consumed_tokens": consumed,
        "reserved_tokens": reserved,
        "cost_expectation_met": not cost_expectation_failures,
        "cost_expectation_failures": cost_expectation_failures,
        "completeness": str(report.get("completeness") or ""),
        "benchmark_ablation": expected_metadata,
        "raw_usage_evidence": usage_evidence,
    }


def execute_discovery_ablation_request(
    request: Mapping[str, Any],
    *,
    executor: DiscoveryAblationExecutorLike,
    expected_request_sha256: str,
    usage_sidecar_path: Path,
    expected_usage_sidecar_sha256: Optional[str] = None,
    catalog_path: Optional[Path] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Execute one request through an injected, hash-bound scanner adapter.

    D0-D3 adapters must pass the runtime override into ``ScanSessionRunner``.
    D4 adapters must implement the explicitly versioned legacy full-entry
    protocol; this function never substitutes the bounded production path.
    """

    reject_truth_environment()
    validate_discovery_ablation_run_request(request, catalog_path=catalog_path)
    if request.get("request_sha256") != expected_request_sha256 or not _is_sha256(
        expected_request_sha256
    ):
        raise DiscoveryAblationError("executor requires the external expected request SHA-256")
    runtime_override = discovery_ablation_runtime_override_from_request(
        request,
        catalog_path=catalog_path,
    )
    execute = getattr(executor, "execute", None)
    if not callable(execute):
        execute = executor
    if not callable(execute):
        raise DiscoveryAblationError("ablation executor is not callable")
    raw_report = execute(deepcopy(dict(request)), runtime_override)
    runtime_override.require_cold_runtime_attested()
    if not isinstance(raw_report, Mapping):
        raise DiscoveryAblationError("ablation executor must return a report object")
    report = dict(raw_report)
    if (
        report.get("answer_material_present") is not False
        or report.get("release_eligible") is not False
        or report.get("formal_eligible") is not False
    ):
        raise DiscoveryAblationError(
            "in-process adapter reports must explicitly be answer-free-content, "
            "release-ineligible, and non-formal"
        )
    _rows, usage_evidence = _read_raw_usage_evidence(Path(usage_sidecar_path))
    if expected_usage_sidecar_sha256 is not None:
        expected_usage_sha = str(expected_usage_sidecar_sha256 or "")
        if not _is_sha256(expected_usage_sha) or expected_usage_sha != usage_evidence["sha256"]:
            raise DiscoveryAblationError("external expected usage sidecar SHA-256 mismatch")
    usage = _ablation_report_usage(report)
    reported_sidecar = str(usage.get("usage_events_path") or "").strip()
    if not reported_sidecar:
        raise DiscoveryAblationError("ablation report does not identify its raw usage sidecar")
    if Path(reported_sidecar).resolve() != Path(usage_sidecar_path).resolve():
        raise DiscoveryAblationError("ablation report usage sidecar path mismatch")
    _bind_raw_usage_evidence(report, usage_evidence)
    report_contract = validate_discovery_ablation_report(
        report,
        request,
        runtime_override,
        catalog_path=catalog_path,
    )
    execution: Dict[str, Any] = {
        "schema_version": ABLATION_EXECUTION_SCHEMA_VERSION,
        "request_sha256": request["request_sha256"],
        "plan_sha256": request["plan_sha256"],
        "arm_id": request["arm_spec"]["arm_id"],
        "trial_index": request["trial"]["trial_index"],
        "run_id": request["trial"]["run_id"],
        "execution_path": request["trial"]["execution_path"],
        "executor_protocol": request["trial"]["executor_protocol"],
        "executor_sha256": request["executor_sha256"],
        "execution_mode": NON_FORMAL_IN_PROCESS_MODE,
        "report_sha256": canonical_json_sha256(report),
        "report_contract": report_contract,
        "usage_sidecar_sha256": usage_evidence["sha256"],
        "answer_free_attested": False,
        "formal_eligible": False,
        "answer_material_present": False,
        "release_eligible": False,
    }
    execution["execution_sha256"] = canonical_json_sha256(execution)
    validate_discovery_ablation_execution(execution, request=request)
    return report, execution


def validate_discovery_ablation_execution(
    execution: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
) -> None:
    if set(execution) != _EXECUTION_FIELDS:
        raise DiscoveryAblationError("ablation execution has missing or unknown fields")
    if execution.get("schema_version") != ABLATION_EXECUTION_SCHEMA_VERSION:
        raise DiscoveryAblationError("ablation execution schema_version is invalid")
    if (
        execution.get("answer_material_present") is not False
        or execution.get("release_eligible") is not False
        or execution.get("answer_free_attested") is not False
        or execution.get("formal_eligible") is not False
    ):
        raise DiscoveryAblationError(
            "in-process ablation execution must be unattested and formal/release-ineligible"
        )
    if execution.get("execution_mode") != NON_FORMAL_IN_PROCESS_MODE:
        raise DiscoveryAblationError("package.module ablation execution must be non-formal")
    expected = {
        "request_sha256": request["request_sha256"],
        "plan_sha256": request["plan_sha256"],
        "arm_id": request["arm_spec"]["arm_id"],
        "trial_index": request["trial"]["trial_index"],
        "run_id": request["trial"]["run_id"],
        "execution_path": request["trial"]["execution_path"],
        "executor_protocol": request["trial"]["executor_protocol"],
        "executor_sha256": request["executor_sha256"],
    }
    for field, value in expected.items():
        if execution.get(field) != value:
            raise DiscoveryAblationError(f"ablation execution {field} mismatch")
    if not _is_sha256(execution.get("report_sha256")):
        raise DiscoveryAblationError("ablation execution report SHA-256 is invalid")
    usage_sha = execution.get("usage_sidecar_sha256")
    contract = execution.get("report_contract")
    raw_usage = contract.get("raw_usage_evidence") if isinstance(contract, Mapping) else None
    if (
        not _is_sha256(usage_sha)
        or not isinstance(raw_usage, Mapping)
        or raw_usage.get("sha256") != usage_sha
    ):
        raise DiscoveryAblationError("ablation execution raw usage SHA-256 binding is invalid")
    if execution.get("execution_sha256") != canonical_json_sha256(
        _without_hash(execution, "execution_sha256")
    ):
        raise DiscoveryAblationError("ablation execution SHA-256 mismatch")


def write_discovery_ablation_plan(
    path: Path,
    plan: Mapping[str, Any],
    *,
    catalog_path: Optional[Path] = None,
) -> None:
    validate_discovery_ablation_plan(plan, catalog_path=catalog_path)
    Path(path).write_text(
        json.dumps(dict(plan), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_discovery_ablation_run_request(
    path: Path,
    request: Mapping[str, Any],
    *,
    catalog_path: Optional[Path] = None,
) -> None:
    validate_discovery_ablation_run_request(request, catalog_path=catalog_path)
    Path(path).write_text(
        json.dumps(dict(request), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


@dataclass(frozen=True, init=False)
class DiscoveryAblationRuntimeOverride:
    """Factory-only, report-visible in-process binding for D0-D3.

    This type is intentionally not constructible by public configuration.  A
    caller must load a hash-verified plan and select one catalog arm through
    :func:`discovery_ablation_runtime_override`.
    """

    plan_sha256: str
    plan_seed_sha256: str
    arm_id: str
    arm_spec_sha256: str
    config_identity_sha256: str
    validator_config_sha256: str
    validator_selected_arm: str
    validator_protocol_version: str
    validator_result_schema_version: str
    validator_arm_catalog_sha256: str
    validator_arm_spec_sha256: str
    validation_model_spec_sha256: str
    validation_prompt_sha256: str
    run_id: str
    request_identity_sha256: str
    cache_mode: str
    cold_snapshot_identity_sha256: str
    cold_cache_identity_sha256: str
    cold_runtime_attested: bool
    semantic_map_mode: str
    semantic_enrichment_mode: str
    active_discovery_mode: str
    execution_path: str
    executor_protocol: str
    expected_max_tokens: int
    release_eligible: bool

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError(
            "DiscoveryAblationRuntimeOverride is factory-only; load a hash-verified plan"
        )

    @property
    def semantic_map_enabled(self) -> bool:
        return self.semantic_map_mode in {"zero_llm_skeleton", "evidence_backed"}

    @property
    def semantic_enrichment_enabled(self) -> bool:
        return self.semantic_enrichment_mode == "active"

    @property
    def active_discovery_enabled(self) -> bool:
        return self.active_discovery_mode == "active"

    @property
    def in_process_supported(self) -> bool:
        return self.execution_path == "production_bounded_pipeline"

    def require_in_process_supported(self) -> None:
        if not self.in_process_supported:
            raise DiscoveryAblationError(
                "D4 is an external legacy full-entry cost-upper-bound executor; "
                "the production pipeline cannot emulate it"
            )

    def validate_runtime_config(self, config: Any) -> None:
        scan = getattr(config, "scan", None)
        if scan is None:
            raise DiscoveryAblationError("ablation runtime requires scan configuration")
        if str(getattr(scan, "depth", "")) != "balanced":
            raise DiscoveryAblationError("ablation runtime requires effective balanced depth")

    def attest_cold_runtime(self, config: Any, *, resume: bool, maintain: bool) -> None:
        """Bind this run identity to fresh snapshot and KnowledgeDB storage."""

        self.validate_runtime_config(config)
        if resume or maintain:
            raise DiscoveryAblationError("isolated-cold ablation forbids resume and maintain modes")
        if self.cache_mode != "isolated_cold" or not self.run_id:
            raise DiscoveryAblationError(
                "ablation runtime is missing its isolated-cold run identity"
            )
        analysis = getattr(config, "analysis", None)
        indexing = getattr(config, "indexing", None)
        if analysis is None or indexing is None:
            raise DiscoveryAblationError("ablation runtime requires snapshot and indexing config")
        snapshot_text = str(getattr(analysis, "snapshot_dir", "") or "").strip()
        knowledge_text = str(getattr(indexing, "knowledge_db_path", "") or "").strip()
        if not snapshot_text or not knowledge_text:
            raise DiscoveryAblationError("ablation cold snapshot/cache paths must be explicit")
        snapshot_path = Path(snapshot_text)
        knowledge_path = Path(knowledge_text)
        if snapshot_path.exists() or knowledge_path.exists():
            raise DiscoveryAblationError(
                "ablation isolated-cold snapshot and KnowledgeDB paths must not already exist"
            )
        user_config = str(getattr(analysis, "user_config_db", "") or "").strip()
        if user_config and Path(user_config).exists():
            raise DiscoveryAblationError(
                "ablation isolated-cold run cannot reuse an existing user-config store"
            )
        object.__setattr__(self, "cold_runtime_attested", True)

    def require_cold_runtime_attested(self) -> None:
        if not self.cold_runtime_attested:
            raise DiscoveryAblationError(
                "ablation runtime must attest fresh snapshot/cache storage before analysis"
            )

    def report_metadata(self) -> Dict[str, Any]:
        return {
            "schema_version": ABLATION_RUNTIME_SCHEMA_VERSION,
            "plan_sha256": self.plan_sha256,
            "plan_seed_sha256": self.plan_seed_sha256,
            "arm_id": self.arm_id,
            "arm_spec_sha256": self.arm_spec_sha256,
            "config_identity_sha256": self.config_identity_sha256,
            "validator_config_sha256": self.validator_config_sha256,
            "validator_selected_arm": self.validator_selected_arm,
            "validator_protocol_version": self.validator_protocol_version,
            "validator_result_schema_version": self.validator_result_schema_version,
            "validator_arm_catalog_sha256": self.validator_arm_catalog_sha256,
            "validator_arm_spec_sha256": self.validator_arm_spec_sha256,
            "validation_model_spec_sha256": self.validation_model_spec_sha256,
            "validation_prompt_sha256": self.validation_prompt_sha256,
            "run_id": self.run_id,
            "request_identity_sha256": self.request_identity_sha256,
            "cache_mode": self.cache_mode,
            "cold_snapshot_identity_sha256": self.cold_snapshot_identity_sha256,
            "cold_cache_identity_sha256": self.cold_cache_identity_sha256,
            "cold_runtime_attested": self.cold_runtime_attested,
            "semantic_map_mode": self.semantic_map_mode,
            "semantic_enrichment_mode": self.semantic_enrichment_mode,
            "active_discovery_mode": self.active_discovery_mode,
            "execution_path": self.execution_path,
            "executor_protocol": self.executor_protocol,
            "expected_max_tokens": self.expected_max_tokens,
            "release_eligible": False,
        }


def discovery_ablation_runtime_override(
    plan: Mapping[str, Any],
    *,
    arm_id: str,
    expected_plan_sha256: str,
    catalog_path: Optional[Path] = None,
) -> DiscoveryAblationRuntimeOverride:
    validate_discovery_ablation_plan(plan, catalog_path=catalog_path)
    if plan.get("plan_sha256") != expected_plan_sha256 or not _is_sha256(expected_plan_sha256):
        raise DiscoveryAblationError("runtime override requires the external expected plan SHA-256")
    normalized = str(arm_id or "").upper()
    if normalized not in ABLATION_ARM_IDS:
        raise DiscoveryAblationError(f"unknown discovery ablation arm: {arm_id}")
    arm = plan["arms"][ABLATION_ARM_IDS.index(normalized)]["arm_spec"]
    validator_config = plan["fixed_contract"]["validator_config"]
    logical_run_identity = canonical_json_sha256(
        {"plan_sha256": plan["plan_sha256"], "arm_id": normalized, "scope": "plan-preview"}
    )
    value = object.__new__(DiscoveryAblationRuntimeOverride)
    fields = {
        "plan_sha256": plan["plan_sha256"],
        "plan_seed_sha256": plan["plan_seed_sha256"],
        "arm_id": normalized,
        "arm_spec_sha256": arm["arm_spec_sha256"],
        "config_identity_sha256": plan["config_identity"]["combined_sha256"],
        "validator_config_sha256": plan["config_identity"]["validator_config_sha256"],
        "validator_selected_arm": validator_config["selected_arm"],
        "validator_protocol_version": validator_config["validator_protocol_version"],
        "validator_result_schema_version": validator_config["validator_result_schema_version"],
        "validator_arm_catalog_sha256": validator_config["validator_arm_catalog_sha256"],
        "validator_arm_spec_sha256": validator_config["validator_arm_spec_sha256"],
        "validation_model_spec_sha256": validator_config["validation_model_spec_sha256"],
        "validation_prompt_sha256": validator_config["validation_prompt_sha256"],
        "run_id": "",
        "request_identity_sha256": logical_run_identity,
        "cache_mode": "isolated_cold",
        "cold_snapshot_identity_sha256": canonical_json_sha256(
            {"run_identity": logical_run_identity, "storage": "snapshot"}
        ),
        "cold_cache_identity_sha256": canonical_json_sha256(
            {"run_identity": logical_run_identity, "storage": "cache"}
        ),
        "cold_runtime_attested": False,
        "semantic_map_mode": arm["semantic_map_mode"],
        "semantic_enrichment_mode": arm["semantic_enrichment_mode"],
        "active_discovery_mode": arm["active_discovery_mode"],
        "execution_path": arm["execution_path"],
        "executor_protocol": arm["executor_protocol"],
        "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
        "release_eligible": False,
    }
    for field, item in fields.items():
        object.__setattr__(value, field, item)
    return value


def discovery_ablation_runtime_override_from_request(
    request: Mapping[str, Any],
    *,
    catalog_path: Optional[Path] = None,
) -> DiscoveryAblationRuntimeOverride:
    """Build the factory-only runtime binding from a validated run request."""

    validate_discovery_ablation_run_request(request, catalog_path=catalog_path)
    arm = request["arm_spec"]
    validator_config = request["fixed_contract"]["validator_config"]
    request_identity = request["trial"]["request_identity_sha256"]
    value = object.__new__(DiscoveryAblationRuntimeOverride)
    fields = {
        "plan_sha256": request["plan_sha256"],
        "plan_seed_sha256": request["plan_seed_sha256"],
        "arm_id": arm["arm_id"],
        "arm_spec_sha256": arm["arm_spec_sha256"],
        "config_identity_sha256": request["config_identity"]["combined_sha256"],
        "validator_config_sha256": request["config_identity"]["validator_config_sha256"],
        "validator_selected_arm": validator_config["selected_arm"],
        "validator_protocol_version": validator_config["validator_protocol_version"],
        "validator_result_schema_version": validator_config["validator_result_schema_version"],
        "validator_arm_catalog_sha256": validator_config["validator_arm_catalog_sha256"],
        "validator_arm_spec_sha256": validator_config["validator_arm_spec_sha256"],
        "validation_model_spec_sha256": validator_config["validation_model_spec_sha256"],
        "validation_prompt_sha256": validator_config["validation_prompt_sha256"],
        "run_id": request["trial"]["run_id"],
        "request_identity_sha256": request_identity,
        "cache_mode": request["trial"]["cache_mode"],
        "cold_snapshot_identity_sha256": canonical_json_sha256(
            {"run_identity": request_identity, "storage": "snapshot"}
        ),
        "cold_cache_identity_sha256": canonical_json_sha256(
            {"run_identity": request_identity, "storage": "cache"}
        ),
        "cold_runtime_attested": False,
        "semantic_map_mode": arm["semantic_map_mode"],
        "semantic_enrichment_mode": arm["semantic_enrichment_mode"],
        "active_discovery_mode": arm["active_discovery_mode"],
        "execution_path": arm["execution_path"],
        "executor_protocol": arm["executor_protocol"],
        "expected_max_tokens": ABLATION_EXPECTED_MAX_TOKENS,
        "release_eligible": False,
    }
    for field, item in fields.items():
        object.__setattr__(value, field, item)
    return value


__all__ = [
    "ABLATION_ARM_IDS",
    "ABLATION_CATALOG_SCHEMA_VERSION",
    "ABLATION_COLD_TRIALS",
    "ABLATION_EXECUTION_SCHEMA_VERSION",
    "ABLATION_EXPECTED_MAX_TOKENS",
    "ABLATION_PLAN_SCHEMA_VERSION",
    "ABLATION_RUN_REQUEST_SCHEMA_VERSION",
    "ABLATION_RUNTIME_SCHEMA_VERSION",
    "DiscoveryAblationError",
    "DiscoveryAblationRuntimeOverride",
    "FIXED_VALIDATOR_CONFIG_SCHEMA_VERSION",
    "assert_answer_free",
    "build_discovery_ablation_plan",
    "build_discovery_ablation_run_request",
    "discovery_ablation_arm",
    "discovery_ablation_runtime_override",
    "discovery_ablation_runtime_override_from_request",
    "execute_discovery_ablation_request",
    "load_discovery_ablation_catalog",
    "load_discovery_ablation_plan",
    "load_discovery_ablation_run_request",
    "reject_truth_environment",
    "validate_discovery_ablation_catalog",
    "validate_discovery_ablation_plan",
    "validate_discovery_ablation_execution",
    "validate_discovery_ablation_report",
    "validate_discovery_ablation_run_request",
    "validate_discovery_ablation_usage_sidecar",
    "validate_fixed_validator_config",
    "write_discovery_ablation_plan",
    "write_discovery_ablation_run_request",
]
