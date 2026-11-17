"""Shared YAML validation and internal runtime-spec composition helpers."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import yaml

from ..common.portable import default_svf_directory, default_tool

from .config import (
    AgentConfig,
    AnalysisConfig,
    EffectiveConfig,
    ConcurrencyConfig,
    EntryDiscoveryConfig,
    ReviewMemoryConfig,
    RulesConfig,
    ScanLLMProfiles,
    WikiConfig,
    _optional_positive_int,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ReportingConfig,
    RuntimeAgentConfig,
    RuntimeSpec,
    RuntimeSpecProvenance,
    ScanConfig,
    SemanticDedupConfig,
)

PUBLIC_CONFIG_VERSION = 3
RUNTIME_SPEC_VERSION = 1
PROJECT_OPTION_KEYS = (
    "id",
    "entry_function",
    "entry_file_path",
    "entry_signature",
    "entry_functions_list",
    "entry_discovery",
    "include_paths",
    "exclude_paths",
    "user_config_file",
    "wiki",
    "review_memory",
)
CONCURRENCY_KEYS = (
    "entry_workers",
    "validator_workers",
    "investigator_workers",
    "evidence_completion_workers",
    "index_workers",
    "wiki_compiler_workers",
    "svf_workers",
    "llm_max_inflight",
)
RULES_KEYS = ("packs", "providers", "enabled_ids", "disabled_ids")
INDEXING_KEYS = ("backend", "clang", "svf", "java", "tools")
ENV_PATTERN = re.compile(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
SCAN_DEPTHS = frozenset({"fast", "balanced", "deep"})
# Shared LLM profile field table: consumed by _parse_llms and reused by the
# v3 formal model as the single source for its generated JSON schema.
LLM_PROFILE_KEYS = (
    "base_urls",
    "models",
    "api_key",
    "base_url_rate_limit_per_minute",
    "base_url_max_concurrent_requests",
    "max_tokens",
    "context_window",
    "model_context_windows",
    "timeout",
    "max_retries",
    "retry_until_available",
    "supports_structured_output",
)
SCAN_DEPTHS_BY_LANGUAGE = {
    "c_cpp": SCAN_DEPTHS,
    # Java balanced/deep require a separate quality gate.  Keeping the
    # language gate here prevents a CLI override from bypassing public config
    # validation while Java remains Preview.
    "java": frozenset({"fast"}),
}


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> Dict[Any, Any]:
    mapping: Dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_yaml_unique(path: Path) -> Dict[str, Any]:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, UnicodeError, OSError, ValueError) as exc:
        raise ValueError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"configuration root must be a mapping: {path}")
    if not all(isinstance(key, str) for key in raw):
        raise ValueError("configuration keys must be strings")
    return raw


def _unknown_key(path: str, key: str, allowed: Iterable[str]) -> ValueError:
    choices = sorted(set(allowed))
    suggestion = difflib.get_close_matches(key, choices, n=1, cutoff=0.55)
    suffix = f"; did you mean {suggestion[0]!r}?" if suggestion else ""
    return ValueError(f"unknown configuration key {path}.{key}{suffix}")


def _mapping(value: Any, path: str, *, required: bool = False) -> Dict[str, Any]:
    if value is None and not required:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a mapping")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{path} keys must be strings")
    return dict(value)


def _check_keys(data: Mapping[str, Any], allowed: Iterable[str], path: str) -> None:
    allowed_set = set(allowed)
    for key in data:
        if key not in allowed_set:
            raise _unknown_key(path, key, allowed_set)


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    cleaned = value.strip()
    if not cleaned and not allow_empty:
        raise ValueError(f"{path} must not be empty")
    return cleaned


def _string_list(
    value: Any,
    path: str,
    *,
    allow_empty: bool = True,
    deduplicate: bool = True,
) -> List[str]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list of strings")
    result: List[str] = []
    for index, item in enumerate(value):
        cleaned = _string(item, f"{path}[{index}]")
        if not deduplicate or cleaned not in result:
            result.append(cleaned)
    if not result and not allow_empty:
        raise ValueError(f"{path} must not be empty")
    return result


def _positive_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{path} must be a positive integer")
    return int(value)


def _non_negative_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{path} must be a non-negative integer")
    return int(value)


def _positive_number_or_none(value: Any, path: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{path} must be a positive number or null")
    return float(value)


def _optional_bool_or_none(value: Any, path: str) -> Optional[bool]:
    """Parse an optional tri-state boolean (absent -> None = depth-scoped)."""
    if value is None:
        return None
    return _boolean(value, path)


def _optional_fraction_or_none(value: Any, path: str) -> Optional[float]:
    """Validate an optional confidence threshold in (0.5, 1.0]; None disables."""

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{path} must be a number in (0.5, 1.0] or null")
    parsed = float(value)
    if not 0.5 < parsed <= 1.0:
        raise ValueError(f"{path} must be in (0.5, 1.0] or null")
    return parsed


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path} must be true or false")
    return value


def _expand_env(value: Any, path: str = "config") -> Any:
    if isinstance(value, dict):
        return {key: _expand_env(item, f"{path}.{key}") for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if not isinstance(value, str):
        return value

    missing: List[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in os.environ:
            missing.append(name)
            return match.group(0)
        return os.environ[name]

    expanded = ENV_PATTERN.sub(replace, value)
    if missing:
        raise ValueError(
            f"{path} references unset environment variable(s): {', '.join(sorted(set(missing)))}"
        )
    return expanded


def _resolve_config_path(config_path: Optional[str]) -> Path:
    path = Path(config_path).expanduser() if config_path else Path.cwd() / "zscope.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    return path.resolve()


def _deep_merge(base: MutableMapping[str, Any], override: Mapping[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)  # type: ignore[index]
        else:
            base[key] = deepcopy(value)


_RUNTIME_AGENT_NAMES = {
    "semantic_modeler",
    "vulnerability_analyzer",
    "issue_reconciler_agent",
    "validator_agent",
}


def _validate_runtime_shape(raw: Mapping[str, Any], *, partial: bool) -> None:
    _check_keys(
        raw,
        {"runtime_spec_version", "agents", "analysis", "reporting", "paths"},
        "runtime",
    )
    if not partial and raw.get("runtime_spec_version") != RUNTIME_SPEC_VERSION:
        raise ValueError(f"runtime.runtime_spec_version must be {RUNTIME_SPEC_VERSION}")
    if "runtime_spec_version" in raw and raw["runtime_spec_version"] != RUNTIME_SPEC_VERSION:
        raise ValueError(f"runtime.runtime_spec_version must be {RUNTIME_SPEC_VERSION}")

    agents = _mapping(raw.get("agents"), "runtime.agents")
    for name, value in agents.items():
        if name not in _RUNTIME_AGENT_NAMES:
            raise _unknown_key("runtime.agents", name, _RUNTIME_AGENT_NAMES)
        item = _mapping(value, f"runtime.agents.{name}", required=True)
        _check_keys(item, {"enabled", "llm_role", "can_spawn_subagents"}, f"runtime.agents.{name}")

    analysis = _mapping(raw.get("analysis"), "runtime.analysis")
    _check_keys(
        analysis,
        {
            "max_recursion_depth",
            "max_function_lines",
            "max_tool_iterations",
            "enable_snapshot_cache",
            "validation_cache_entries",
            "enable_global_model",
            "semantic_model_max_rounds",
            "max_premodel_depth",
            "max_premodel_callees",
            "trivial_function_max_lines",
            "llm_interface_inference",
            "llm_interface_inference_budget",
            "llm_decision_explanation",
            "llm_decision_explanation_budget",
            "enable_subagent_workers",
            "security_semantic_enrichment_mode",
            "active_investigation_mode",
            "active_investigation_max_rounds",
            "active_investigation_timeout_seconds",
            "active_investigation_max_scope_extensions",
            "semantic_snapshot_candidate_mode",
            "semantic_model_demand_mode",
            "dynamic_reproduction_mode",
            "dynamic_reproduction_required_replays",
            "dynamic_reproduction_max_replays",
            "dynamic_reproduction_timeout_seconds",
            "dynamic_reproduction_deadline_seconds",
            "dynamic_reproduction_memory_limit_mb",
            "dynamic_reproduction_isolation",
            "max_subagent_tickets",
            "subagent_max_turns",
            "request_deadline_seconds",
            "validation_deadline_seconds",
            "subagent_ticket_timeout",
            "entry_deadline_seconds",
            "scan_deadline_seconds",
            "budget_exhaustion_policy",
            "subagent_spawn_allowlist",
            "subagent_skill_llm_refs",
            "subagent_skill_efforts",
            "tool_audit_log",
            "validation_uncertain_confirm_threshold",
            "validation_v3_reattempt",
            "validation_v2b_adjudication",
            "validation_review_protocol",
            "validation_checked_proofs",
            "validation_positive_case",
            "validation_related_findings",
            "validation_review_checkpoint",
            "validation_uncertain_replay_review",
            "validation_demote_source_lifecycle_confirm",
            "validation_obligation_infunction_release_guard",
        },
        "runtime.analysis",
    )

    reporting = _mapping(raw.get("reporting"), "runtime.reporting")
    _check_keys(reporting, {"semantic_dedup"}, "runtime.reporting")
    semantic = _mapping(reporting.get("semantic_dedup"), "runtime.reporting.semantic_dedup")
    _check_keys(
        semantic,
        {"enabled", "llm_enabled", "llm_confidence_threshold", "max_cluster_size"},
        "runtime.reporting.semantic_dedup",
    )

    paths = _mapping(raw.get("paths"), "runtime.paths")
    _check_keys(
        paths,
        {"knowledge_db", "snapshots", "user_config_file"},
        "runtime.paths",
    )


def _runtime_analysis(data: Mapping[str, Any]) -> AnalysisConfig:
    def integer(name: str, default: int, *, non_negative: bool = False) -> int:
        value = data.get(name, default)
        return (
            _non_negative_int(value, f"runtime.analysis.{name}")
            if non_negative
            else _positive_int(value, f"runtime.analysis.{name}")
        )

    def boolean(name: str, default: bool) -> bool:
        value = data.get(name, default)
        return _boolean(value, f"runtime.analysis.{name}")

    def deadline(name: str, default: Optional[float]) -> Optional[float]:
        return _positive_number_or_none(data.get(name, default), f"runtime.analysis.{name}")

    spawn_allowlist = data.get("subagent_spawn_allowlist", ["deep_worker"])
    llm_refs = data.get("subagent_skill_llm_refs", {})
    efforts = data.get("subagent_skill_efforts", {})
    if not isinstance(llm_refs, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in llm_refs.items()
    ):
        raise ValueError("runtime.analysis.subagent_skill_llm_refs must map strings to strings")
    if not isinstance(efforts, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in efforts.items()
    ):
        raise ValueError("runtime.analysis.subagent_skill_efforts must map strings to strings")

    policy = _string(
        data.get("budget_exhaustion_policy", "observe"),
        "runtime.analysis.budget_exhaustion_policy",
    )
    if policy != "observe":
        raise ValueError("runtime.analysis.budget_exhaustion_policy must be 'observe'")

    return AnalysisConfig(
        max_recursion_depth=integer("max_recursion_depth", 3, non_negative=True),
        max_function_lines=integer("max_function_lines", 500),
        max_tool_iterations=integer("max_tool_iterations", 50),
        enable_snapshot_cache=boolean("enable_snapshot_cache", True),
        validation_cache_entries=integer("validation_cache_entries", 4096, non_negative=True),
        enable_global_model=boolean("enable_global_model", False),
        semantic_model_max_rounds=integer("semantic_model_max_rounds", 3),
        max_premodel_depth=integer("max_premodel_depth", 3, non_negative=True),
        max_premodel_callees=integer("max_premodel_callees", 20, non_negative=True),
        trivial_function_max_lines=integer("trivial_function_max_lines", 5, non_negative=True),
        llm_interface_inference=boolean("llm_interface_inference", True),
        llm_interface_inference_budget=integer(
            "llm_interface_inference_budget", 50, non_negative=True
        ),
        llm_decision_explanation=boolean("llm_decision_explanation", True),
        llm_decision_explanation_budget=integer(
            "llm_decision_explanation_budget", 50, non_negative=True
        ),
        enable_subagent_workers=boolean("enable_subagent_workers", False),
        security_semantic_enrichment_mode=_string(
            data.get("security_semantic_enrichment_mode", "shadow"),
            "runtime.analysis.security_semantic_enrichment_mode",
        ),
        active_investigation_mode=_string(
            data.get("active_investigation_mode", "off"),
            "runtime.analysis.active_investigation_mode",
        ),
        semantic_snapshot_candidate_mode=_string(
            data.get("semantic_snapshot_candidate_mode", "off"),
            "runtime.analysis.semantic_snapshot_candidate_mode",
        ),
        semantic_model_demand_mode=_string(
            data.get("semantic_model_demand_mode", "off"),
            "runtime.analysis.semantic_model_demand_mode",
        ),
        dynamic_reproduction_mode=_string(
            data.get("dynamic_reproduction_mode", "off"),
            "runtime.analysis.dynamic_reproduction_mode",
        ),
        dynamic_reproduction_required_replays=integer("dynamic_reproduction_required_replays", 2),
        dynamic_reproduction_max_replays=integer("dynamic_reproduction_max_replays", 3),
        dynamic_reproduction_timeout_seconds=integer("dynamic_reproduction_timeout_seconds", 30),
        dynamic_reproduction_deadline_seconds=integer("dynamic_reproduction_deadline_seconds", 900),
        dynamic_reproduction_memory_limit_mb=integer(
            "dynamic_reproduction_memory_limit_mb", 512, non_negative=True
        ),
        dynamic_reproduction_isolation=_string(
            data.get("dynamic_reproduction_isolation", "process"),
            "runtime.analysis.dynamic_reproduction_isolation",
        ),
        active_investigation_max_rounds=integer("active_investigation_max_rounds", 4),
        active_investigation_timeout_seconds=data.get(
            "active_investigation_timeout_seconds", 120.0
        ),
        active_investigation_max_scope_extensions=integer(
            "active_investigation_max_scope_extensions", 1, non_negative=True
        ),
        max_subagent_tickets=integer("max_subagent_tickets", 4, non_negative=True),
        subagent_max_turns=integer("subagent_max_turns", 20),
        request_deadline_seconds=deadline("request_deadline_seconds", 120.0),
        validation_deadline_seconds=deadline("validation_deadline_seconds", 600.0),
        subagent_ticket_timeout=deadline("subagent_ticket_timeout", 300.0),
        entry_deadline_seconds=deadline("entry_deadline_seconds", 1800.0),
        scan_deadline_seconds=deadline("scan_deadline_seconds", None),
        budget_exhaustion_policy=policy,
        subagent_spawn_allowlist=_string_list(
            spawn_allowlist,
            "runtime.analysis.subagent_spawn_allowlist",
        ),
        subagent_skill_llm_refs={str(key): str(value) for key, value in llm_refs.items()},
        subagent_skill_efforts={str(key): str(value) for key, value in efforts.items()},
        tool_audit_log=_string(
            data.get("tool_audit_log", ""),
            "runtime.analysis.tool_audit_log",
            allow_empty=True,
        ),
        validation_uncertain_confirm_threshold=_optional_fraction_or_none(
            data.get("validation_uncertain_confirm_threshold"),
            "runtime.analysis.validation_uncertain_confirm_threshold",
        ),
        validation_v3_reattempt=boolean("validation_v3_reattempt", True),
        validation_v2b_adjudication=boolean("validation_v2b_adjudication", False),
        validation_review_protocol=boolean("validation_review_protocol", False),
        validation_checked_proofs=_optional_bool_or_none(
            data.get("validation_checked_proofs"),
            "runtime.analysis.validation_checked_proofs",
        ),
        validation_positive_case=boolean("validation_positive_case", False),
        validation_related_findings=boolean("validation_related_findings", False),
        validation_review_checkpoint=boolean("validation_review_checkpoint", False),
        validation_uncertain_replay_review=_optional_bool_or_none(
            data.get("validation_uncertain_replay_review"),
            "runtime.analysis.validation_uncertain_replay_review",
        ),
        validation_demote_source_lifecycle_confirm=_optional_bool_or_none(
            data.get("validation_demote_source_lifecycle_confirm"),
            "runtime.analysis.validation_demote_source_lifecycle_confirm",
        ),
        validation_obligation_infunction_release_guard=_optional_bool_or_none(
            data.get("validation_obligation_infunction_release_guard"),
            "runtime.analysis.validation_obligation_infunction_release_guard",
        ),
    )


def load_runtime_spec() -> RuntimeSpec:
    package_path = Path(__file__).with_name("runtime_defaults.yaml").resolve()
    base = load_yaml_unique(package_path)
    _validate_runtime_shape(base, partial=False)

    override_text = os.environ.get("Z_SCOPE_RUNTIME_SPEC", "").strip()
    developer_mode = os.environ.get("Z_SCOPE_DEVELOPER_MODE", "").strip() == "1"
    source_path = package_path
    if override_text:
        if not developer_mode:
            raise ValueError("Z_SCOPE_RUNTIME_SPEC requires Z_SCOPE_DEVELOPER_MODE=1")
        override_path = Path(override_text).expanduser()
        if not override_path.is_absolute():
            raise ValueError("Z_SCOPE_RUNTIME_SPEC must be an absolute path")
        if not override_path.is_file():
            raise ValueError(f"runtime override not found: {override_path}")
        override = _expand_env(load_yaml_unique(override_path.resolve()), path="runtime")
        _validate_runtime_shape(override, partial=True)
        _deep_merge(base, override)
        source_path = override_path.resolve()

    _validate_runtime_shape(base, partial=False)
    stable = json.dumps(base, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    provenance = RuntimeSpecProvenance(
        version=RUNTIME_SPEC_VERSION,
        source_path=str(source_path),
        sha256=hashlib.sha256(stable.encode("utf-8")).hexdigest(),
        developer_override=bool(override_text),
    )

    agents_data = _mapping(base.get("agents"), "runtime.agents", required=True)
    if set(agents_data) != _RUNTIME_AGENT_NAMES:
        missing = sorted(_RUNTIME_AGENT_NAMES - set(agents_data))
        raise ValueError("runtime.agents is missing: " + ", ".join(missing))
    agents: List[RuntimeAgentConfig] = []
    for name in sorted(agents_data):
        data = _mapping(agents_data[name], f"runtime.agents.{name}", required=True)
        role = _string(data.get("llm_role"), f"runtime.agents.{name}.llm_role")
        if role not in {"modeling", "analysis", "validation"}:
            raise ValueError(
                f"runtime.agents.{name}.llm_role must be modeling, analysis, or validation"
            )
        can_spawn = data.get("can_spawn_subagents")
        if can_spawn is not None:
            can_spawn = _boolean(can_spawn, f"runtime.agents.{name}.can_spawn_subagents")
        agents.append(
            RuntimeAgentConfig(
                name=name,
                llm_role=role,
                enabled=_boolean(data.get("enabled", True), f"runtime.agents.{name}.enabled"),
                can_spawn_subagents=can_spawn,
            )
        )

    reporting_data = _mapping(base.get("reporting"), "runtime.reporting")
    semantic_data = _mapping(
        reporting_data.get("semantic_dedup"),
        "runtime.reporting.semantic_dedup",
    )
    confidence = semantic_data.get("llm_confidence_threshold", 0.85)
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError(
            "runtime.reporting.semantic_dedup.llm_confidence_threshold must be numeric"
        )
    if not 0 <= float(confidence) <= 1:
        raise ValueError(
            "runtime.reporting.semantic_dedup.llm_confidence_threshold must be between 0 and 1"
        )
    reporting = ReportingConfig(
        semantic_dedup=SemanticDedupConfig(
            enabled=_boolean(
                semantic_data.get("enabled", True),
                "runtime.reporting.semantic_dedup.enabled",
            ),
            llm_enabled=_boolean(
                semantic_data.get("llm_enabled", False),
                "runtime.reporting.semantic_dedup.llm_enabled",
            ),
            llm_confidence_threshold=float(confidence),
            max_cluster_size=_positive_int(
                semantic_data.get("max_cluster_size", 8),
                "runtime.reporting.semantic_dedup.max_cluster_size",
            ),
        )
    )
    paths = _mapping(base.get("paths"), "runtime.paths", required=True)
    return RuntimeSpec(
        analysis=_runtime_analysis(_mapping(base.get("analysis"), "runtime.analysis")),
        reporting=reporting,
        agents=agents,
        knowledge_db_path=_string(paths.get("knowledge_db"), "runtime.paths.knowledge_db"),
        snapshot_dir=_string(paths.get("snapshots"), "runtime.paths.snapshots"),
        default_user_config_file=_string(
            paths.get("user_config_file"), "runtime.paths.user_config_file"
        ),
        provenance=provenance,
    )


def _parse_llms(raw: Any) -> Dict[str, LLMConfig]:
    data = _mapping(raw, "llms", required=True)
    if "default" not in data:
        raise ValueError("llms.default is required")
    result: Dict[str, LLMConfig] = {}
    allowed = set(LLM_PROFILE_KEYS)
    for name, value in data.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("llms profile names must be non-empty strings")
        profile_path = f"llms.{name}"
        profile = _mapping(value, profile_path, required=True)
        _check_keys(profile, allowed, profile_path)
        base_urls = _string_list(
            profile.get("base_urls"), f"{profile_path}.base_urls", allow_empty=False
        )
        models = _string_list(profile.get("models"), f"{profile_path}.models", allow_empty=False)
        api_key = _string(profile.get("api_key"), f"{profile_path}.api_key")

        rate_limit = profile.get("base_url_rate_limit_per_minute")
        if rate_limit is not None:
            rate_limit = _positive_int(rate_limit, f"{profile_path}.base_url_rate_limit_per_minute")
        endpoint_limit = profile.get("base_url_max_concurrent_requests")
        if endpoint_limit is not None:
            endpoint_limit = _positive_int(
                endpoint_limit, f"{profile_path}.base_url_max_concurrent_requests"
            )
        max_retries = profile.get("max_retries", 2)
        max_retries = _non_negative_int(max_retries, f"{profile_path}.max_retries")
        context_window = _positive_int(
            profile.get("context_window", LLMConfig().context_window),
            f"{profile_path}.context_window",
        )
        windows = _mapping(
            profile.get("model_context_windows", {}),
            f"{profile_path}.model_context_windows",
            required=True,
        )
        model_context_windows = {}
        for model_name, window in windows.items():
            if not isinstance(model_name, str) or not model_name.strip():
                raise ValueError(
                    f"{profile_path}.model_context_windows requires non-empty model names"
                )
            model_context_windows[model_name] = _positive_int(
                window, f"{profile_path}.model_context_windows.{model_name}"
            )

        result[name] = LLMConfig(
            api_key=api_key,
            base_url=base_urls[0],
            base_urls=base_urls,
            base_url_rate_limit_per_minute=rate_limit,
            base_url_max_concurrent_requests=endpoint_limit,
            models=models,
            max_tokens=_positive_int(
                profile.get("max_tokens", LLMConfig().max_tokens), f"{profile_path}.max_tokens"
            ),
            context_window=context_window,
            model_context_windows=model_context_windows,
            timeout=_positive_number_or_none(
                profile.get("timeout", 120), f"{profile_path}.timeout"
            ),
            max_retries=max_retries,
            retry_until_available=_boolean(
                profile.get("retry_until_available", False),
                f"{profile_path}.retry_until_available",
            ),
            supports_structured_output=_boolean(
                profile.get("supports_structured_output", False),
                f"{profile_path}.supports_structured_output",
            ),
        )
    return result


def reject_legacy_project_roots(data: Mapping[str, Any]) -> None:
    """Reject removed roots even when their values would happen to be equivalent."""
    removed = [f"project.{key}" for key in ("root", "source_root") if key in data]
    if removed:
        raise ValueError(
            ", ".join(removed) + " removed: the YAML file directory is the only project root. "
            "Move/migrate the configuration into the intended project directory with "
            "'zscope-config migrate --input OLD --output PROJECT/zscope.yaml'; "
            "do not just remove these keys from a configuration stored elsewhere."
        )


def _validated_scan_depth(value: Any, *, language: str, path: str) -> str:
    depth = _string(value, path).lower()
    if depth not in SCAN_DEPTHS:
        raise ValueError(f"{path} must be fast, balanced, or deep")
    allowed = SCAN_DEPTHS_BY_LANGUAGE.get(language, frozenset())
    if depth not in allowed:
        raise ValueError(
            f"{path}={depth!r} is not currently available for "
            f"project.language={language!r}; use 'fast'"
        )
    return depth


def apply_scan_overrides(
    config: EffectiveConfig,
    *,
    scan_depth: Optional[str] = None,
) -> EffectiveConfig:
    """Apply the CLI depth control after YAML parsing."""

    if scan_depth is not None:
        config.scan.depth = _validated_scan_depth(
            scan_depth,
            language=config.project.language,
            path="--scan-depth",
        )
        config.scan.depth_source = "cli"
    return config


def _parse_pool_list(value: Any, path: str, *, shared: bool) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    result: List[Dict[str, Any]] = []
    names: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        data = _mapping(item, item_path, required=True)
        allowed = {"name", "paths", "conflicts_with"} if shared else {"name", "paths"}
        _check_keys(data, allowed, item_path)
        name = _string(data.get("name"), f"{item_path}.name")
        if name in names:
            raise ValueError(f"{path} contains duplicate pool name {name!r}")
        names.add(name)
        parsed: Dict[str, Any] = {
            "name": name,
            "paths": _string_list(data.get("paths"), f"{item_path}.paths", allow_empty=False),
        }
        if shared:
            parsed["conflicts_with"] = _string_list(
                data.get("conflicts_with", []), f"{item_path}.conflicts_with"
            )
        result.append(parsed)
    return result


def _parse_indexing(raw: Any, *, language: str, runtime: RuntimeSpec) -> IndexingConfig:
    data = _mapping(raw, "indexing", required=True)
    _check_keys(data, INDEXING_KEYS, "indexing")
    backend = _string(data.get("backend"), "indexing.backend").lower().replace("-", "_")
    allowed_backends = (
        {"unified", "clang", "regex"}
        if language == "c_cpp"
        else {"java_unified", "java_source", "joern"}
    )
    if backend not in allowed_backends:
        raise ValueError(
            f"indexing.backend={backend!r} is invalid for project.language={language!r}"
        )
    tools = _mapping(data.get("tools"), "indexing.tools")
    svf = _mapping(data.get("svf"), "indexing.svf")
    java = _mapping(data.get("java"), "indexing.java")
    clang = _mapping(data.get("clang"), "indexing.clang")
    _check_keys(clang, {"frontend"}, "indexing.clang")

    if language == "java":
        if clang:
            raise ValueError("indexing.clang is not valid for Java")
        if svf:
            raise ValueError("indexing.svf is not valid for Java")
        _check_keys(
            java,
            {"structure_frontend", "extractor_command", "signals", "provider_commands"},
            "indexing.java",
        )
        _check_keys(tools, {"joern"}, "indexing.tools")
        frontend = _string(
            java.get("structure_frontend", "auto"), "indexing.java.structure_frontend"
        )
        if frontend not in {"auto", "spoon", "javaparser", "builtin"}:
            raise ValueError(
                "indexing.java.structure_frontend must be auto, spoon, javaparser, or builtin"
            )
        provider_commands_raw = _mapping(
            java.get("provider_commands"), "indexing.java.provider_commands"
        )
        provider_commands: Dict[str, List[str]] = {}
        for name, command in provider_commands_raw.items():
            provider_commands[name] = _string_list(
                command,
                f"indexing.java.provider_commands.{name}",
                allow_empty=False,
                deduplicate=False,
            )
        joern = _mapping(tools.get("joern"), "indexing.tools.joern")
        _check_keys(joern, {"command", "host", "port", "heap"}, "indexing.tools.joern")
        port = joern.get("port", 8080)
        port = _positive_int(port, "indexing.tools.joern.port")
        if port > 65535:
            raise ValueError("indexing.tools.joern.port must be <= 65535")
        signals = _string_list(java.get("signals", ["joern"]), "indexing.java.signals")
        if backend == "java_unified" and not signals:
            raise ValueError("indexing.java.signals must not be empty for java_unified")
        return IndexingConfig(
            backend=backend,
            knowledge_db_path=runtime.knowledge_db_path,
            java_structure_frontend=frontend,
            java_structure_extractor_command=_string_list(
                java.get("extractor_command", []),
                "indexing.java.extractor_command",
                deduplicate=False,
            ),
            java_signal_backends=signals,
            java_signal_provider_commands=provider_commands,
            joern_path=_string(
                joern["command"] if "command" in joern else default_tool("joern"),
                "indexing.tools.joern.command",
            ),
            joern_server_host=_string(joern.get("host", "127.0.0.1"), "indexing.tools.joern.host"),
            joern_server_port=port,
            joern_heap_size=_string(joern.get("heap", "8g"), "indexing.tools.joern.heap"),
        )

    if java:
        raise ValueError("indexing.java is not valid for C/C++")
    _check_keys(
        tools,
        {"clangd", "clang_indexer", "svf_bin_dir", "gclang", "get_bc", "llvm_link"},
        "indexing.tools",
    )
    _check_keys(
        svf,
        {
            "scope",
            "entry_depth",
            "max_selected_tus",
            "fallback",
            "groups_file",
            "always_include",
            "exclusive_pools",
            "shared_pools",
            "heap_limit_mb",
            "timeout_seconds",
        },
        "indexing.svf",
    )
    scope = _string(svf.get("scope", "auto"), "indexing.svf.scope")
    if scope not in {"full", "auto", "entry"}:
        raise ValueError("indexing.svf.scope must be full, auto, or entry")
    fallback = _string(svf.get("fallback", "full"), "indexing.svf.fallback")
    if fallback not in {"full", "skip"}:
        raise ValueError("indexing.svf.fallback must be full or skip")
    exclusive = _parse_pool_list(
        svf.get("exclusive_pools", []), "indexing.svf.exclusive_pools", shared=False
    )
    shared = _parse_pool_list(svf.get("shared_pools", []), "indexing.svf.shared_pools", shared=True)
    exclusive_names = {item["name"] for item in exclusive}
    shared_names = {item["name"] for item in shared}
    duplicate_names = sorted(exclusive_names & shared_names)
    if duplicate_names:
        raise ValueError(
            "indexing.svf pool names must be unique across exclusive_pools and "
            f"shared_pools: {', '.join(duplicate_names)}"
        )
    for index, pool in enumerate(shared):
        unknown = sorted(set(pool.get("conflicts_with", [])) - exclusive_names)
        if unknown:
            raise ValueError(
                f"indexing.svf.shared_pools[{index}].conflicts_with references unknown "
                f"exclusive pool(s): {', '.join(unknown)}"
            )
    timeout = _positive_number_or_none(
        svf.get("timeout_seconds", 1800), "indexing.svf.timeout_seconds"
    )
    return IndexingConfig(
        backend=backend,
        knowledge_db_path=runtime.knowledge_db_path,
        clang_frontend=_string(clang.get("frontend", "auto"), "indexing.clang.frontend"),
        clang_indexer_path=_string(
            (
                tools["clang_indexer"]
                if "clang_indexer" in tools
                else default_tool("zscope-clang-indexer")
            ),
            "indexing.tools.clang_indexer",
        ),
        clangd_path=_string(
            tools["clangd"] if "clangd" in tools else default_tool("clangd"),
            "indexing.tools.clangd",
        ),
        svf_bin_dir=_string(
            tools["svf_bin_dir"] if "svf_bin_dir" in tools else default_svf_directory(),
            "indexing.tools.svf_bin_dir",
            allow_empty=True,
        ),
        gclang_path=_string(
            tools["gclang"] if "gclang" in tools else default_tool("gclang"),
            "indexing.tools.gclang",
        ),
        get_bc_path=_string(
            tools["get_bc"] if "get_bc" in tools else default_tool("get-bc"),
            "indexing.tools.get_bc",
        ),
        llvm_link_path=_string(
            tools["llvm_link"] if "llvm_link" in tools else default_tool("llvm-link"),
            "indexing.tools.llvm_link",
        ),
        svf_heap_limit_mb=_positive_int(
            svf.get("heap_limit_mb", 32768), "indexing.svf.heap_limit_mb"
        ),
        svf_timeout=timeout,
        svf_groups_config=_string(
            svf.get("groups_file", ""), "indexing.svf.groups_file", allow_empty=True
        ),
        svf_scope=scope,
        svf_entry_depth=_non_negative_int(svf.get("entry_depth", 4), "indexing.svf.entry_depth"),
        svf_max_selected_tus=_positive_int(
            svf.get("max_selected_tus", 200), "indexing.svf.max_selected_tus"
        ),
        svf_fallback=fallback,
        svf_always_include=_string_list(
            svf.get("always_include", []), "indexing.svf.always_include"
        ),
        svf_symbol_closure=True,
        svf_exclusive_pools=exclusive,
        svf_shared_pools=shared,
    )


def _anchor_runtime_paths(
    runtime: RuntimeSpec, project: ProjectConfig, indexing: IndexingConfig
) -> None:
    knowledge = Path(runtime.knowledge_db_path)
    if not knowledge.is_absolute():
        knowledge = project.project_root / knowledge
    indexing.knowledge_db_path = str(knowledge.resolve())

    snapshots = Path(runtime.snapshot_dir)
    if not snapshots.is_absolute():
        snapshots = project.project_root / snapshots
    runtime.analysis.snapshot_dir = str(snapshots.resolve())

    configured_user_file = project.user_config_file
    if configured_user_file is None:
        configured_user_file = Path(runtime.default_user_config_file)
        if not configured_user_file.is_absolute():
            configured_user_file = project.project_root / configured_user_file
        configured_user_file = configured_user_file.resolve()
        project.user_config_file = configured_user_file
    runtime.analysis.user_config_db = str(
        project.semantics_file
        if project.language == "c_cpp" and project.semantics_file is not None
        else configured_user_file
    )


def _agents_from_runtime(runtime: RuntimeSpec, scan: ScanConfig) -> List[AgentConfig]:
    role_refs = vars(scan.llm_profiles)
    agents: List[AgentConfig] = []
    for spec in runtime.agents:
        agents.append(
            AgentConfig(
                name=spec.name,
                enabled=spec.enabled,
                task=scan.task if spec.name == "vulnerability_analyzer" else "",
                llm_ref=role_refs[spec.llm_role],
                can_spawn_subagents=spec.can_spawn_subagents,
            )
        )
    return agents


def _interface_patterns(value: Any, path: str) -> List[str]:
    patterns = _string_list(value, path)
    for index, pattern in enumerate(patterns):
        if "\\" in pattern:
            raise ValueError(f"{path}[{index}] must use POSIX '/' separators")
        if pattern.startswith("^") or pattern.endswith("$"):
            raise ValueError(f"{path}[{index}] must be a glob, not a regular expression")
    return patterns


def _wiki_document_patterns(value: Any, path: str) -> List[str]:
    patterns = _interface_patterns(value, path)
    for index, pattern in enumerate(patterns):
        if (
            pattern.startswith("/")
            or re.match(r"^[A-Za-z]:/", pattern)
            or ".." in Path(pattern).parts
        ):
            raise ValueError(f"{path}[{index}] must be project-root relative")
    return patterns


def _parse_project_options(raw: Any, *, language: str, config_path: Path) -> ProjectConfig:
    data = _mapping(raw, "project", required=True)
    reject_legacy_project_roots(data)
    _check_keys(
        data,
        {
            "id",
            "language",
            "entry_function",
            "entry_file_path",
            "entry_signature",
            "entry_functions_list",
            "entry_discovery",
            "include_paths",
            "exclude_paths",
            "user_config_file",
            "semantics_file",
            "wiki",
            "review_memory",
        },
        "project",
    )
    root_path = config_path.resolve().parent
    discovery_data = _mapping(data.get("entry_discovery"), "project.entry_discovery")
    _check_keys(
        discovery_data,
        {"enabled", "search_root", "interface_files", "max_entries", "max_functions"},
        "project.entry_discovery",
    )
    search_root = discovery_data.get("search_root")
    if search_root is not None:
        search_root = _string(search_root, "project.entry_discovery.search_root")
    discovery = EntryDiscoveryConfig(
        enabled=_boolean(discovery_data.get("enabled", True), "project.entry_discovery.enabled"),
        search_root=Path(search_root) if search_root is not None else None,
        interface_files=_interface_patterns(
            discovery_data.get("interface_files", []),
            "project.entry_discovery.interface_files",
        ),
        max_entries=_positive_int(
            discovery_data.get("max_entries", 200),
            "project.entry_discovery.max_entries",
        ),
        max_functions=_positive_int(
            discovery_data.get("max_functions", 10000),
            "project.entry_discovery.max_functions",
        ),
    )

    wiki_data = _mapping(data.get("wiki"), "project.wiki")
    _check_keys(
        wiki_data,
        {
            "mode",
            "auto_maintain",
            "state_dir",
            "compiler_enabled",
            "documents",
            "max_file_bytes",
            "max_files",
            "max_total_bytes",
            "compiler_max_tokens",
            "max_wall_seconds",
            "max_constraints",
        },
        "project.wiki",
    )
    documents = _mapping(wiki_data.get("documents"), "project.wiki.documents")
    _check_keys(documents, {"exclude", "classify"}, "project.wiki.documents")
    classify = _mapping(documents.get("classify"), "project.wiki.documents.classify")
    _check_keys(classify, {"explanatory", "generated"}, "project.wiki.documents.classify")
    document_exclude = _wiki_document_patterns(
        documents.get("exclude", []),
        "project.wiki.documents.exclude",
    )
    explanatory_overrides = _wiki_document_patterns(
        classify.get("explanatory", []),
        "project.wiki.documents.classify.explanatory",
    )
    generated_overrides = _wiki_document_patterns(
        classify.get("generated", []),
        "project.wiki.documents.classify.generated",
    )
    conflicting_overrides = sorted(set(explanatory_overrides).intersection(generated_overrides))
    if conflicting_overrides:
        raise ValueError(
            "project.wiki.documents.classify assigns the same glob to explanatory "
            f"and generated: {conflicting_overrides[0]!r}"
        )
    wiki = WikiConfig(
        mode=_string(wiki_data.get("mode", "off"), "project.wiki.mode"),
        auto_maintain=_boolean(wiki_data.get("auto_maintain", False), "project.wiki.auto_maintain"),
        state_dir=_string(
            wiki_data.get("state_dir", ".zscope_knowledge/wiki"), "project.wiki.state_dir"
        ),
        compiler_enabled=_boolean(
            wiki_data.get("compiler_enabled", False), "project.wiki.compiler_enabled"
        ),
        document_exclude=document_exclude,
        explanatory_overrides=explanatory_overrides,
        generated_overrides=generated_overrides,
        max_file_bytes=_positive_int(
            wiki_data.get("max_file_bytes", 10 * 1024 * 1024), "project.wiki.max_file_bytes"
        ),
        max_files=_positive_int(wiki_data.get("max_files", 10_000), "project.wiki.max_files"),
        max_total_bytes=_positive_int(
            wiki_data.get("max_total_bytes", 100 * 1024 * 1024), "project.wiki.max_total_bytes"
        ),
        compiler_max_tokens=_optional_positive_int(wiki_data.get("compiler_max_tokens"), None),
        max_wall_seconds=_optional_positive_int(wiki_data.get("max_wall_seconds"), None),
        max_constraints=_optional_positive_int(wiki_data.get("max_constraints"), None),
    )

    review_data = _mapping(data.get("review_memory"), "project.review_memory")
    _check_keys(
        review_data,
        {
            "mode",
            "state_dir",
            "project_scope",
            "extraction",
            "llm_enabled",
            "max_patterns_per_finding",
            "max_context_tokens",
            "stale_on_source_drift",
            "allow_direct_suppression",
        },
        "project.review_memory",
    )
    review_memory = ReviewMemoryConfig(
        mode=_string(review_data.get("mode", "off"), "project.review_memory.mode"),
        state_dir=_string(
            review_data.get("state_dir", ".zscope/review-memory"), "project.review_memory.state_dir"
        ),
        project_scope=_string(
            review_data.get("project_scope", "project"), "project.review_memory.project_scope"
        ),
        extraction=_string(
            review_data.get("extraction", "auto_extract"), "project.review_memory.extraction"
        ),
        llm_enabled=_boolean(
            review_data.get("llm_enabled", True), "project.review_memory.llm_enabled"
        ),
        max_patterns_per_finding=_non_negative_int(
            review_data.get("max_patterns_per_finding", 3),
            "project.review_memory.max_patterns_per_finding",
        ),
        max_context_tokens=_non_negative_int(
            review_data.get("max_context_tokens", 1200), "project.review_memory.max_context_tokens"
        ),
        stale_on_source_drift=_boolean(
            review_data.get("stale_on_source_drift", True),
            "project.review_memory.stale_on_source_drift",
        ),
        allow_direct_suppression=_boolean(
            review_data.get("allow_direct_suppression", False),
            "project.review_memory.allow_direct_suppression",
        ),
    )

    project = ProjectConfig(
        project_root=root_path,
        project_id=_string(data.get("id", ""), "project.id", allow_empty=True),
        language=language,
        entry_function=(
            _string(data["entry_function"], "project.entry_function")
            if data.get("entry_function") is not None
            else None
        ),
        entry_file_path=(
            _string(data["entry_file_path"], "project.entry_file_path")
            if data.get("entry_file_path") is not None
            else None
        ),
        entry_signature=(
            _string(data["entry_signature"], "project.entry_signature")
            if data.get("entry_signature") is not None
            else None
        ),
        entry_functions_list=(
            Path(_string(data["entry_functions_list"], "project.entry_functions_list"))
            if data.get("entry_functions_list") is not None
            else None
        ),
        semantics_file=(
            Path(_string(data["semantics_file"], "project.semantics_file"))
            if data.get("semantics_file") is not None
            else None
        ),
        user_config_file=(
            Path(_string(data["user_config_file"], "project.user_config_file"))
            if data.get("user_config_file") is not None
            else None
        ),
        include_paths=_string_list(data.get("include_paths", []), "project.include_paths"),
        exclude_paths=_string_list(data.get("exclude_paths", []), "project.exclude_paths"),
        entry_discovery=discovery,
        wiki=wiki,
        review_memory=review_memory,
    )
    if project.entry_discovery.search_root:
        try:
            # search_root 必须位于唯一 project_root 之下。
            project.entry_discovery.search_root.relative_to(project.project_root)
        except ValueError as exc:
            raise ValueError(
                "project.entry_discovery.search_root must be inside the configuration directory"
            ) from exc
    return project


def _parse_scan_options(raw: Any, llms: Mapping[str, LLMConfig], *, language: str) -> ScanConfig:
    data = _mapping(raw, "scan")
    _check_keys(data, {"task", "llm_profiles", "preset"}, "scan")
    profiles_data = _mapping(data.get("llm_profiles"), "scan.llm_profiles")
    _check_keys(profiles_data, {"modeling", "analysis", "validation"}, "scan.llm_profiles")
    profiles = ScanLLMProfiles(
        modeling=_string(profiles_data.get("modeling", "default"), "scan.llm_profiles.modeling"),
        analysis=_string(profiles_data.get("analysis", "default"), "scan.llm_profiles.analysis"),
        validation=_string(
            profiles_data.get("validation", "default"), "scan.llm_profiles.validation"
        ),
    )
    for role, ref in vars(profiles).items():
        if ref not in llms:
            raise ValueError(f"scan.llm_profiles.{role} references unknown llms profile {ref!r}")
    depth_source = "config" if "preset" in data else "default"
    depth = _validated_scan_depth(
        data.get("preset", "fast"),
        language=language,
        path="scan.preset",
    )
    return ScanConfig(
        task=_string(data.get("task", ""), "scan.task", allow_empty=True),
        llm_profiles=profiles,
        depth=depth,
        depth_source=depth_source,
    )


def _parse_concurrency(raw: Any, *, language: str) -> ConcurrencyConfig:
    data = _mapping(raw, "concurrency")
    allowed = set(CONCURRENCY_KEYS)
    if language != "c_cpp":
        allowed.remove("svf_workers")
    _check_keys(data, allowed, "concurrency")
    return ConcurrencyConfig(
        **{key: _positive_int(value, f"concurrency.{key}") for key, value in data.items()}
    )


def _parse_rules(raw: Any) -> RulesConfig:
    data = _mapping(raw, "rules")
    _check_keys(data, RULES_KEYS, "rules")
    return RulesConfig(
        packs=_string_list(data.get("packs", []), "rules.packs", deduplicate=False),
        providers=_string_list(data.get("providers", []), "rules.providers", deduplicate=False),
        enabled_ids=_string_list(
            data.get("enabled_ids", []), "rules.enabled_ids", deduplicate=False
        ),
        disabled_ids=_string_list(
            data.get("disabled_ids", []), "rules.disabled_ids", deduplicate=False
        ),
    )
