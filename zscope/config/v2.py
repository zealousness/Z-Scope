"""Strict public configuration v2 and internal runtime-spec composition.

The public loader deliberately has no legacy aliases.  Legacy YAML is handled
only by :mod:`zscope.cli.config_cli`, which produces a new v2 document before
the product runtime sees it.
"""

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

from .config import (
    AgentConfig,
    AnalysisConfig,
    ConcurrencyConfig,
    EffectiveConfig,
    EntryDiscoveryConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ReportingConfig,
    RulesConfig,
    RuntimeAgentConfig,
    RuntimeSpec,
    RuntimeSpecProvenance,
    ScanConfig,
    ScanLLMProfiles,
    UserConfigV2,
)


PUBLIC_CONFIG_VERSION = 2
RUNTIME_SPEC_VERSION = 1
ENV_PATTERN = re.compile(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
SCAN_DEPTHS = frozenset({"fast", "balanced", "deep"})
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
    "security_spec_miner",
    "hypothesis_hunter",
    "history_maintenance_agent",
    "proof_engine",
}

_REMOVED_RUNTIME_AGENTS = {
    "semantic_modeler": "security_spec_miner",
    "global_modeler": "security_spec_miner",
    "active_discovery": "hypothesis_hunter",
    "validator_agent": "proof_engine",
    "vulnerability_analyzer": "hypothesis_hunter",
    "issue_reconciler_agent": "history_maintenance_agent",
    "deep_worker": "hypothesis_hunter",
    "subagent_orchestrator": "hypothesis_hunter",
}

_REMOVED_ANALYSIS_KEYS = {
    "enable_subagent_workers",
    "max_subagent_tickets",
    "subagent_max_turns",
    "subagent_ticket_timeout",
    "subagent_spawn_allowlist",
    "subagent_skill_llm_refs",
    "subagent_skill_efforts",
    "enable_global_model",
    "max_premodel_depth",
    "max_premodel_callees",
    "security_semantic_enrichment_mode",
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
        if name in _REMOVED_RUNTIME_AGENTS:
            replacement = _REMOVED_RUNTIME_AGENTS[name]
            raise ValueError(
                f"runtime.agents.{name} was removed in Z-Scope 2.0 P1; "
                f"migrate explicitly to runtime.agents.{replacement}, save the migrated file, "
                "then reload it"
            )
        if name not in _RUNTIME_AGENT_NAMES:
            raise _unknown_key("runtime.agents", name, _RUNTIME_AGENT_NAMES)
        item = _mapping(value, f"runtime.agents.{name}", required=True)
        if "can_spawn_subagents" in item:
            raise ValueError(
                f"runtime.agents.{name}.can_spawn_subagents was removed in Z-Scope 2.0 P1; "
                "remove it, save the migrated file, then reload it"
            )
        _check_keys(item, {"enabled", "llm_role"}, f"runtime.agents.{name}")

    analysis = _mapping(raw.get("analysis"), "runtime.analysis")
    removed_analysis = sorted(_REMOVED_ANALYSIS_KEYS.intersection(analysis))
    if removed_analysis:
        raise ValueError(
            "removed Z-Scope 2.0 P1 runtime.analysis field(s): "
            + ", ".join(removed_analysis)
            + "; run the explicit compat migration, save the migrated file, then reload it"
        )
    _check_keys(
        analysis,
        {
            "max_recursion_depth",
            "max_function_lines",
            "max_tool_iterations",
            "enable_snapshot_cache",
            "validation_cache_entries",
            "trivial_function_max_lines",
            "request_deadline_seconds",
            "validation_deadline_seconds",
            "entry_deadline_seconds",
            "scan_deadline_seconds",
            "budget_exhaustion_policy",
            "tool_audit_log",
        },
        "runtime.analysis",
    )

    reporting = _mapping(raw.get("reporting"), "runtime.reporting")
    if "semantic_dedup" in reporting:
        raise ValueError(
            "runtime.reporting.semantic_dedup was removed in Z-Scope 2.0 P1; "
            "Finding-root v2 is the sole live report projection"
        )
    _check_keys(reporting, set(), "runtime.reporting")

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
        trivial_function_max_lines=integer("trivial_function_max_lines", 5, non_negative=True),
        request_deadline_seconds=deadline("request_deadline_seconds", 120.0),
        validation_deadline_seconds=deadline("validation_deadline_seconds", 240.0),
        entry_deadline_seconds=deadline("entry_deadline_seconds", 1800.0),
        scan_deadline_seconds=deadline("scan_deadline_seconds", None),
        budget_exhaustion_policy=policy,
        tool_audit_log=_string(
            data.get("tool_audit_log", ""),
            "runtime.analysis.tool_audit_log",
            allow_empty=True,
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
        agents.append(
            RuntimeAgentConfig(
                name=name,
                llm_role=role,
                enabled=_boolean(data.get("enabled", True), f"runtime.agents.{name}.enabled"),
            )
        )

    reporting = ReportingConfig()
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
    allowed = {
        "base_urls",
        "models",
        "api_key",
        "base_url_rate_limit_per_minute",
        "base_url_max_concurrent_requests",
        "max_tokens",
        "timeout",
        "max_retries",
        "retry_until_available",
        "supports_structured_output",
        "require_exact_response_model",
    }
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

        result[name] = LLMConfig(
            api_key=api_key,
            base_url=base_urls[0],
            base_urls=base_urls,
            base_url_rate_limit_per_minute=rate_limit,
            base_url_max_concurrent_requests=endpoint_limit,
            models=models,
            max_tokens=_positive_int(profile.get("max_tokens", 4096), f"{profile_path}.max_tokens"),
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
            require_exact_response_model=_boolean(
                profile.get("require_exact_response_model", False),
                f"{profile_path}.require_exact_response_model",
            ),
        )
    return result


def _interface_patterns(value: Any, path: str) -> List[str]:
    patterns = _string_list(value, path)
    for index, pattern in enumerate(patterns):
        if "\\" in pattern:
            raise ValueError(f"{path}[{index}] must use POSIX '/' separators")
        if pattern.startswith("^") or pattern.endswith("$"):
            raise ValueError(f"{path}[{index}] must be a glob, not a regular expression")
    return patterns


def _parse_project(raw: Any, *, language: str) -> ProjectConfig:
    data = _mapping(raw, "project", required=True)
    _check_keys(
        data,
        {
            "id",
            "root",
            "source_root",
            "language",
            "entry_function",
            "entry_file_path",
            "entry_signature",
            "entry_functions_list",
            "entry_discovery",
            "include_paths",
            "exclude_paths",
            "compile_commands_path",
            "user_config_file",
        },
        "project",
    )
    root = _string(data.get("root"), "project.root")
    source_root = _string(data.get("source_root", "."), "project.source_root")
    compile_commands = data.get("compile_commands_path")
    if language == "java" and compile_commands is not None:
        raise ValueError("project.compile_commands_path is not valid for Java")
    if compile_commands is not None:
        compile_commands = _string(compile_commands, "project.compile_commands_path")

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
        enabled=_boolean(discovery_data.get("enabled", False), "project.entry_discovery.enabled"),
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

    project = ProjectConfig(
        project_root=Path(root),
        source_root=Path(source_root),
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
        compile_commands_path=Path(compile_commands) if compile_commands else None,
        user_config_file=(
            Path(_string(data["user_config_file"], "project.user_config_file"))
            if data.get("user_config_file") is not None
            else None
        ),
        include_paths=_string_list(data.get("include_paths", []), "project.include_paths"),
        exclude_paths=_string_list(data.get("exclude_paths", []), "project.exclude_paths"),
        entry_discovery=discovery,
    )
    if project.entry_discovery.search_root:
        try:
            project.entry_discovery.search_root.relative_to(project.project_root)
        except ValueError as exc:
            raise ValueError(
                "project.entry_discovery.search_root must be inside project.root"
            ) from exc
    return project


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


def _parse_scan(raw: Any, llms: Mapping[str, LLMConfig], *, language: str) -> ScanConfig:
    data = _mapping(raw, "scan")
    _check_keys(data, {"task", "llm_profiles", "depth"}, "scan")
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
    depth_source = "config" if "depth" in data else "default"
    depth = _validated_scan_depth(
        data.get("depth", "fast"),
        language=language,
        path="scan.depth",
    )
    return ScanConfig(
        task=_string(data.get("task", ""), "scan.task", allow_empty=True),
        llm_profiles=profiles,
        depth=depth,
        depth_source=depth_source,
    )


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


def _parse_concurrency(raw: Any, *, language: str) -> ConcurrencyConfig:
    data = _mapping(raw, "concurrency", required=True)
    allowed = {
        "entry_workers",
        "validator_workers",
        "investigator_workers",
        "evidence_completion_workers",
        "index_workers",
        "llm_max_inflight",
    }
    if language == "c_cpp":
        allowed.add("svf_workers")
    _check_keys(data, allowed, "concurrency")
    required = set(allowed)
    missing = sorted(required - set(data))
    if missing:
        raise ValueError("concurrency is missing required key(s): " + ", ".join(missing))
    return ConcurrencyConfig(
        entry_workers=_positive_int(data["entry_workers"], "concurrency.entry_workers"),
        validator_workers=_positive_int(data["validator_workers"], "concurrency.validator_workers"),
        investigator_workers=_positive_int(
            data["investigator_workers"], "concurrency.investigator_workers"
        ),
        evidence_completion_workers=_positive_int(
            data["evidence_completion_workers"],
            "concurrency.evidence_completion_workers",
        ),
        index_workers=_positive_int(data["index_workers"], "concurrency.index_workers"),
        svf_workers=(
            _positive_int(data["svf_workers"], "concurrency.svf_workers")
            if language == "c_cpp"
            else None
        ),
        llm_max_inflight=_positive_int(data["llm_max_inflight"], "concurrency.llm_max_inflight"),
    )


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
    _check_keys(data, {"backend", "svf", "java", "tools"}, "indexing")
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

    if language == "java":
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
            joern_path=_string(joern.get("command", "joern"), "indexing.tools.joern.command"),
            joern_server_host=_string(joern.get("host", "127.0.0.1"), "indexing.tools.joern.host"),
            joern_server_port=port,
            joern_heap_size=_string(joern.get("heap", "8g"), "indexing.tools.joern.heap"),
        )

    if java:
        raise ValueError("indexing.java is not valid for C/C++")
    _check_keys(
        tools,
        {"clangd", "svf_bin_dir", "gclang", "get_bc", "llvm_link"},
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
        clangd_path=_string(tools.get("clangd", "clangd"), "indexing.tools.clangd"),
        svf_bin_dir=_string(
            tools.get("svf_bin_dir", ""), "indexing.tools.svf_bin_dir", allow_empty=True
        ),
        gclang_path=_string(tools.get("gclang", "gclang"), "indexing.tools.gclang"),
        get_bc_path=_string(tools.get("get_bc", "get-bc"), "indexing.tools.get_bc"),
        llvm_link_path=_string(tools.get("llvm_link", "llvm-link"), "indexing.tools.llvm_link"),
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


def _parse_rules(raw: Any) -> RulesConfig:
    data = _mapping(raw, "rules")
    _check_keys(data, {"packs", "providers", "enabled_ids", "disabled_ids"}, "rules")
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
    runtime.analysis.user_config_db = str(configured_user_file)


def _agents_from_runtime(runtime: RuntimeSpec, scan: ScanConfig) -> List[AgentConfig]:
    role_refs = vars(scan.llm_profiles)
    agents: List[AgentConfig] = []
    for spec in runtime.agents:
        agents.append(
            AgentConfig(
                name=spec.name,
                enabled=spec.enabled,
                task=scan.task if spec.name == "hypothesis_hunter" else "",
                llm_ref=role_refs[spec.llm_role],
            )
        )
    return agents


def load_user_config_v2(config_path: Optional[str] = None) -> EffectiveConfig:
    path = _resolve_config_path(config_path)
    raw = _expand_env(load_yaml_unique(path))
    _check_keys(
        raw,
        {"config_version", "llms", "project", "scan", "indexing", "concurrency", "rules"},
        "config",
    )
    if raw.get("config_version") != PUBLIC_CONFIG_VERSION:
        raise ValueError(
            "config.config_version must be 2; run "
            "'zscope-config migrate --input OLD --output NEW' for legacy YAML"
        )

    project_data = _mapping(raw.get("project"), "project", required=True)
    language = project_data.get("language")
    if language not in {"c_cpp", "java"}:
        raise ValueError("project.language must be exactly 'c_cpp' or 'java'")

    runtime = load_runtime_spec()
    llms = _parse_llms(raw.get("llms"))
    project = _parse_project(raw.get("project"), language=language)
    scan = _parse_scan(raw.get("scan"), llms, language=language)
    concurrency = _parse_concurrency(raw.get("concurrency"), language=language)
    indexing = _parse_indexing(raw.get("indexing"), language=language, runtime=runtime)
    indexing.max_clangd_threads = concurrency.index_workers
    rules = _parse_rules(raw.get("rules"))
    _anchor_runtime_paths(runtime, project, indexing)
    project.agents = _agents_from_runtime(runtime, scan)

    # Materialize the public DTO before composition.  This makes the public
    # boundary testable without making internal runtime settings serializable
    # back into zscope.yaml.
    UserConfigV2(
        llms=llms,
        project=project,
        scan=scan,
        indexing=indexing,
        concurrency=concurrency,
        rules=rules,
    )
    return EffectiveConfig(
        llm=llms["default"],
        llms=llms,
        indexing=indexing,
        analysis=runtime.analysis,
        project=project,
        scan=scan,
        concurrency=concurrency,
        reporting=runtime.reporting,
        rules=rules,
        runtime_provenance=runtime.provenance,
        user_config_version=PUBLIC_CONFIG_VERSION,
    )
