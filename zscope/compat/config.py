"""Read-only migration of legacy Z-Scope configuration documents.\n\nThe returned mapping is data only.  It is never accepted by the live runtime until\na caller explicitly saves it and reloads it through the strict v2 loader.\n"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from ..config.v2 import PUBLIC_CONFIG_VERSION


_LEGACY_TOP_LEVEL = {
    "config_version",
    "llm",
    "llms",
    "project",
    "indexing",
    "analysis",
    "reporting",
    "rules",
    "mcpServers",
}
_LEGACY_LLM_KEYS = {
    "provider",
    "api_key",
    "base_url",
    "base_urls",
    "base_url_rate_limit_per_minute",
    "base_url_rpm",
    "requests_per_minute",
    "base_url_max_concurrent_requests",
    "base_url_max_in_flight",
    "max_concurrent_requests",
    "model",
    "models",
    "temperature",
    "max_tokens",
    "timeout",
    "max_retries",
    "retry_until_available",
    "supports_structured_output",
    "require_exact_response_model",
}
_LEGACY_PROJECT_KEYS = {
    "id",
    "project_id",
    "root",
    "source_root",
    "language",
    "java_profile",
    "entry_function",
    "entry_file_path",
    "entry_signature",
    "entry_functions_list",
    "entry_discovery",
    "diff_impact",
    "include_paths",
    "exclude_paths",
    "compile_commands",
    "compile_commands_path",
    "task",
    "agents",
    "prompt_autofill",
}
_LEGACY_AGENT_KEYS = {
    "name",
    "task",
    "enabled",
    "llm_ref",
    "skills",
    "tools",
    "mcp_servers",
    "mcpServers",
    "can_spawn_subagents",
    "entry_custom_prompt",
}
_LEGACY_INDEXING_KEYS = {
    "backend",
    "joern_language",
    "joern_path",
    "joern_server_host",
    "joern_server_port",
    "joern_heap_size",
    "clangd_path",
    "knowledge_db_path",
    "batch_size",
    "max_clangd_threads",
    "shared_cache_max_bytes",
    "svf_bin_dir",
    "gclang_path",
    "get_bc_path",
    "llvm_link_path",
    "svf_heap_limit_mb",
    "svf_timeout",
    "svf_groups_config",
    "svf_scope",
    "svf_entry_depth",
    "svf_max_selected_tus",
    "svf_fallback",
    "svf_always_include",
    "svf_symbol_closure",
    "svf_exclusive_pools",
    "svf_shared_pools",
    "java",
    "java_structure_frontend",
    "java_structure_backends",
    "java_structure_extractor_command",
    "java_structure_db_path",
    "java_signal_backends",
    "java_signal_provider_commands",
}
_LEGACY_ANALYSIS_KEYS = {
    "max_recursion_depth",
    "max_function_lines",
    "max_tool_iterations",
    "snapshot_dir",
    "enable_snapshot_cache",
    "user_config_db",
    "parallel_workers",
    "entry_workers",
    "index_workers",
    "svf_workers",
    "llm_max_inflight",
    "validator_workers",
    "investigator_workers",
    "evidence_completion_workers",
    "enable_evidence_completion_queue",
    "candidate_lifecycle_v3",
    "canonical_outcome_projection",
    "deterministic_proof_routing",
    "decision_fact_graph_v1",
    "security_obligation_v1",
    "deterministic_prevalidation_v2",
    "decision_context_v31",
    "project_deterministic_fact_pass_v1",
    "proof_providers_v11",
    "decision_context_v32",
    "structured_candidate_promotion_v1",
    "proof_providers_v12",
    "decision_context_v33",
    "finding_root_v1",
    "validator_evidence_slice_v2",
    "global_validation_group_queue",
    "validation_cache_entries",
    "enable_global_model",
    "candidate_first_validation",
    "max_premodel_depth",
    "max_premodel_callees",
    "trivial_function_max_lines",
    "workflow_name",
    "enable_subagent_workers",
    "max_subagent_tickets",
    "subagent_max_turns",
    "request_deadline_seconds",
    "validation_deadline_seconds",
    "subagent_ticket_timeout",
    "entry_deadline_seconds",
    "scan_deadline_seconds",
    "budget_exhaustion_policy",
    "validation_parallel_workers",
    "subagent_spawn_allowlist",
    "subagent_skill_llm_refs",
    "subagent_skill_efforts",
    "tool_audit_log",
}
_LEGACY_REPORTING_KEYS = {"semantic_dedup"}
_LEGACY_SEMANTIC_DEDUP_KEYS = {
    "enabled",
    "llm_enabled",
    "llm_confidence_threshold",
    "max_cluster_size",
}


def _mapping(value: Any, path: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a mapping")
    return dict(value)


def _reject_unknown(data: Mapping[str, Any], allowed: Iterable[str], path: str) -> None:
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ValueError(f"unknown legacy key(s) at {path}: {', '.join(unknown)}")


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _positive(value: Any, default: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return result if result > 0 else default


def _migrate_llm_profile(raw: Any, path: str, warnings: List[str]) -> Dict[str, Any]:
    data = _mapping(raw, path)
    _reject_unknown(data, _LEGACY_LLM_KEYS, path)
    models = _as_list(data.get("models")) or _as_list(data.get("model"))
    urls = _as_list(data.get("base_urls")) or _as_list(data.get("base_url"))
    if not models:
        raise ValueError(f"{path} has no model/models")
    if not urls:
        urls = ["https://api.openai.com/v1"]
    normalized_urls: List[str] = []
    for index, value in enumerate(urls):
        if isinstance(value, dict):
            _reject_unknown(
                value,
                {"url", "base_url", "rate_limit_per_minute", "max_concurrent_requests"},
                f"{path}.base_urls[{index}]",
            )
            url = value.get("url", value.get("base_url"))
            warnings.append(
                f"flattened endpoint object {path}.base_urls[{index}]; review profile-level limits"
            )
        else:
            url = value
        if not isinstance(url, str) or not url.strip():
            raise ValueError(f"{path}.base_urls[{index}] has no URL")
        normalized_urls.append(url)
    if not data.get("api_key"):
        raise ValueError(f"{path}.api_key is required")
    result: Dict[str, Any] = {
        "base_urls": normalized_urls,
        "models": models,
        "api_key": data.get("api_key", ""),
    }
    optional = {
        "base_url_rate_limit_per_minute": data.get(
            "base_url_rate_limit_per_minute",
            data.get("base_url_rpm", data.get("requests_per_minute")),
        ),
        "base_url_max_concurrent_requests": data.get(
            "base_url_max_concurrent_requests",
            data.get("base_url_max_in_flight", data.get("max_concurrent_requests")),
        ),
        "max_tokens": data.get("max_tokens"),
        "timeout": data.get("timeout"),
        "max_retries": data.get("max_retries"),
        "retry_until_available": data.get("retry_until_available"),
        "supports_structured_output": data.get("supports_structured_output"),
        "require_exact_response_model": data.get("require_exact_response_model"),
    }
    for key in (
        "base_url_rate_limit_per_minute",
        "base_url_max_concurrent_requests",
    ):
        value = optional[key]
        if value is not None and _positive(value, 0) == 0:
            warnings.append(f"dropped non-positive/unlimited sentinel {path}.{key}")
            optional[key] = None
    result.update({key: value for key, value in optional.items() if value is not None})
    for dropped in ("provider", "temperature"):
        if dropped in data:
            warnings.append(f"dropped ineffective field {path}.{dropped}")
    return result


def _migrate_llms(raw: Mapping[str, Any], warnings: List[str]) -> Dict[str, Any]:
    profiles: Dict[str, Any] = {}
    if raw.get("llm"):
        profiles["default"] = _migrate_llm_profile(raw["llm"], "llm", warnings)
    llms = _mapping(raw.get("llms"), "llms")
    for name, value in llms.items():
        profiles[str(name)] = _migrate_llm_profile(value, f"llms.{name}", warnings)
    if not profiles:
        raise ValueError("legacy config has no llm/llms section")
    if "default" not in profiles:
        first_name = next(iter(profiles))
        profiles["default"] = dict(profiles[first_name])
        warnings.append(f"copied llms.{first_name} to required llms.default")
    return profiles


def _normalize_language(value: Any) -> str:
    text = str(value or "auto").strip().lower().replace("-", "_")
    if text in {"c", "cc", "cpp", "c++", "c_cpp", "auto"}:
        return "c_cpp"
    if text in {"java", "javasrc", "java_src"}:
        return "java"
    raise ValueError(f"unsupported legacy project.language: {value!r}")


def _migrate_project(raw: Any, warnings: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    data = _mapping(raw, "project")
    _reject_unknown(data, _LEGACY_PROJECT_KEYS, "project")
    language = _normalize_language(data.get("language"))
    project: Dict[str, Any] = {
        "language": language,
        "root": data.get("root", "."),
        "source_root": data.get("source_root", "."),
    }
    for source, target in (
        ("id", "id"),
        ("project_id", "id"),
        ("entry_function", "entry_function"),
        ("entry_file_path", "entry_file_path"),
        ("entry_signature", "entry_signature"),
        ("entry_functions_list", "entry_functions_list"),
        ("include_paths", "include_paths"),
        ("exclude_paths", "exclude_paths"),
    ):
        if source in data and target not in project:
            project[target] = data[source]
    compile_commands = data.get("compile_commands_path", data.get("compile_commands"))
    if language == "c_cpp" and compile_commands:
        project["compile_commands_path"] = compile_commands
    if "compile_commands" in data:
        warnings.append("renamed project.compile_commands to compile_commands_path")

    discovery = _mapping(data.get("entry_discovery"), "project.entry_discovery")
    _reject_unknown(
        discovery,
        {
            "enabled",
            "max_candidates",
            "max_entries",
            "max_functions",
            "header_files",
            "interface_files",
            "search_root",
            "root",
            "discovery_root",
            "scan_after_discovery",
        },
        "project.entry_discovery",
    )
    if discovery:
        migrated_discovery: Dict[str, Any] = {
            "enabled": bool(discovery.get("enabled", False)),
            "search_root": discovery.get(
                "search_root", discovery.get("root", discovery.get("discovery_root", "."))
            ),
            "interface_files": discovery.get("interface_files", discovery.get("header_files", [])),
            "max_entries": _positive(
                discovery.get("max_entries", discovery.get("max_candidates")), 200
            ),
        }
        if "max_functions" in discovery:
            migrated_discovery["max_functions"] = _positive(discovery.get("max_functions"), 10000)
        project["entry_discovery"] = migrated_discovery
        if "header_files" in discovery:
            warnings.append("renamed project.entry_discovery.header_files to interface_files")
        if "scan_after_discovery" in discovery:
            warnings.append("dropped ineffective project.entry_discovery.scan_after_discovery")
    if "java_profile" in data:
        warnings.append("dropped ineffective project.java_profile")
    if "diff_impact" in data:
        warnings.append("moved project.diff_impact to the internal runtime contract")
    if "prompt_autofill" in data:
        warnings.append("dropped internal project.prompt_autofill")

    scan: Dict[str, Any] = {"task": str(data.get("task") or "")}
    agents = data.get("agents", [])
    if agents is None:
        agents = []
    if not isinstance(agents, list):
        raise ValueError("project.agents must be a list")
    llm_roles: Dict[str, str] = {}
    role_by_agent = {
        "semantic_modeler": "modeling",
        "vulnerability_analyzer": "analysis",
        "validator_agent": "validation",
    }
    for index, raw_agent in enumerate(agents):
        agent = _mapping(raw_agent, f"project.agents[{index}]")
        _reject_unknown(agent, _LEGACY_AGENT_KEYS, f"project.agents[{index}]")
        name = str(agent.get("name") or "")
        if name == "vulnerability_analyzer" and agent.get("task") is not None:
            scan["task"] = str(agent.get("task") or "")
        role = role_by_agent.get(name)
        if role and agent.get("llm_ref"):
            llm_roles[role] = str(agent["llm_ref"])
        if any(
            key in agent
            for key in (
                "enabled",
                "skills",
                "tools",
                "mcp_servers",
                "mcpServers",
                "can_spawn_subagents",
                "entry_custom_prompt",
            )
        ):
            warnings.append(
                f"dropped internal Agent policy fields from project.agents[{index}] ({name})"
            )
    if llm_roles:
        scan["llm_profiles"] = llm_roles
    return project, scan, language


def _migrate_java_indexing(data: Mapping[str, Any]) -> Dict[str, Any]:
    java = _mapping(data.get("java"), "indexing.java")
    _reject_unknown(
        java,
        {
            "structure",
            "signals",
            "structure_frontend",
            "extractor_command",
            "structure_db_path",
            "provider_commands",
        },
        "indexing.java",
    )
    structure = java.get("structure", {})
    structure_backends: List[Any] = []
    if isinstance(structure, dict):
        _reject_unknown(structure, {"frontend", "backends"}, "indexing.java.structure")
        frontend = structure.get("frontend", java.get("structure_frontend", "auto"))
        structure_backends = _as_list(structure.get("backends"))
    else:
        frontend = java.get("structure_frontend", data.get("java_structure_frontend", "auto"))
        structure_backends = _as_list(structure)
    signals = []
    for item in (
        structure_backends
        + _as_list(java.get("signals"))
        + _as_list(data.get("java_signal_backends"))
    ):
        if item and item not in signals:
            signals.append(item)
    result: Dict[str, Any] = {
        "structure_frontend": frontend or "auto",
        "signals": signals or ["joern"],
    }
    extractor = java.get("extractor_command", data.get("java_structure_extractor_command"))
    if extractor:
        result["extractor_command"] = extractor
    commands = java.get("provider_commands", data.get("java_signal_provider_commands"))
    if commands:
        result["provider_commands"] = commands
    return result


def _migrate_indexing(raw: Any, language: str, warnings: List[str]) -> Tuple[Dict[str, Any], int]:
    data = _mapping(raw, "indexing")
    _reject_unknown(data, _LEGACY_INDEXING_KEYS, "indexing")
    backend = str(data.get("backend") or "auto").strip().lower().replace("-", "_")
    if backend in {"", "auto", "language_auto"}:
        backend = "java_unified" if language == "java" else "unified"
    if language == "c_cpp" and backend == "joern":
        raise ValueError(
            "legacy C/C++ backend=joern has no v2 equivalent; choose unified, clang, or regex"
        )
    result: Dict[str, Any] = {"backend": backend}
    index_workers = _positive(data.get("max_clangd_threads"), 4)
    if language == "java":
        result["java"] = _migrate_java_indexing(data)
        joern: Dict[str, Any] = {}
        for source, target in (
            ("joern_path", "command"),
            ("joern_server_host", "host"),
            ("joern_server_port", "port"),
            ("joern_heap_size", "heap"),
        ):
            if source in data:
                joern[target] = data[source]
        if joern:
            result["tools"] = {"joern": joern}
    else:
        result["svf"] = {
            "scope": data.get("svf_scope", "auto"),
            "entry_depth": data.get("svf_entry_depth", 4),
            "max_selected_tus": _positive(data.get("svf_max_selected_tus"), 200),
            "fallback": data.get("svf_fallback", "full"),
            "always_include": data.get("svf_always_include", []) or [],
            "exclusive_pools": data.get("svf_exclusive_pools", []) or [],
            "shared_pools": data.get("svf_shared_pools", []) or [],
            "heap_limit_mb": _positive(data.get("svf_heap_limit_mb"), 32768),
            "timeout_seconds": data.get("svf_timeout", 1800),
        }
        if data.get("svf_groups_config"):
            result["svf"]["groups_file"] = data["svf_groups_config"]
        tools = {}
        for source, target, default in (
            ("clangd_path", "clangd", "clangd"),
            ("svf_bin_dir", "svf_bin_dir", ""),
            ("gclang_path", "gclang", "gclang"),
            ("get_bc_path", "get_bc", "get-bc"),
            ("llvm_link_path", "llvm_link", "llvm-link"),
        ):
            value = data.get(source)
            if value not in (None, default):
                tools[target] = value
        if tools:
            result["tools"] = tools
        if data.get("svf_symbol_closure") is False:
            warnings.append(
                "svf_symbol_closure=false cannot be preserved; v2 uses the stable closure path"
            )
    for dropped in (
        "knowledge_db_path",
        "batch_size",
        "shared_cache_max_bytes",
        "java_structure_db_path",
        "java_structure_backends",
    ):
        if dropped in data:
            warnings.append(f"dropped internal or ineffective indexing.{dropped}")
    return result, index_workers


def migrate_legacy_document(raw: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    _reject_unknown(raw, _LEGACY_TOP_LEVEL, "config")
    if raw.get("config_version") == PUBLIC_CONFIG_VERSION:
        raise ValueError("input already declares config_version: 2; use zscope-config validate")
    warnings: List[str] = []
    llms = _migrate_llms(raw, warnings)
    project, scan, language = _migrate_project(raw.get("project"), warnings)
    indexing, index_workers = _migrate_indexing(raw.get("indexing"), language, warnings)
    analysis = _mapping(raw.get("analysis"), "analysis")
    _reject_unknown(analysis, _LEGACY_ANALYSIS_KEYS, "analysis")
    parallel = _positive(analysis.get("parallel_workers"), 4)
    validator = _positive(
        analysis.get("validator_workers", analysis.get("validation_parallel_workers")),
        2,
    )
    concurrency: Dict[str, Any] = {
        "entry_workers": _positive(analysis.get("entry_workers"), parallel),
        "validator_workers": validator,
        "investigator_workers": _positive(analysis.get("investigator_workers"), 1),
        "evidence_completion_workers": _positive(analysis.get("evidence_completion_workers"), 2),
        "index_workers": _positive(analysis.get("index_workers"), index_workers),
        "llm_max_inflight": _positive(analysis.get("llm_max_inflight"), 4),
    }
    if language == "c_cpp":
        concurrency["svf_workers"] = _positive(analysis.get("svf_workers"), parallel)
    if analysis.get("user_config_db"):
        user_path = Path(str(analysis["user_config_db"]))
        project["user_config_file"] = str(
            user_path if user_path.suffix.lower() == ".xlsx" else user_path / "user_config.xlsx"
        )
    if analysis:
        warnings.append(
            "moved analysis algorithms, budgets, cache, reporting, and Agent policy to runtime_defaults.yaml"
        )
    reporting = _mapping(raw.get("reporting"), "reporting")
    _reject_unknown(reporting, _LEGACY_REPORTING_KEYS, "reporting")
    semantic = _mapping(reporting.get("semantic_dedup"), "reporting.semantic_dedup")
    _reject_unknown(
        semantic,
        _LEGACY_SEMANTIC_DEDUP_KEYS,
        "reporting.semantic_dedup",
    )
    if reporting:
        warnings.append("moved reporting configuration to runtime_defaults.yaml")
    if raw.get("mcpServers") is not None:
        warnings.append("dropped top-level mcpServers; MCP policy is internal")
    rules = _mapping(raw.get("rules"), "rules")
    _reject_unknown(rules, {"packs", "providers", "disabled_ids"}, "rules")
    result: Dict[str, Any] = {
        "config_version": PUBLIC_CONFIG_VERSION,
        "llms": llms,
        "project": project,
        "scan": scan,
        "indexing": indexing,
        "concurrency": concurrency,
    }
    if any(rules.get(name) for name in ("packs", "providers", "disabled_ids")):
        result["rules"] = rules
    warnings.append(
        "review concurrency values against local CPU, memory, and LLM endpoint capacity"
    )
    return result, warnings
