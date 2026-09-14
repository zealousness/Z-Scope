#!/usr/bin/env python3
"""Patch zscope.yaml from frontend-agent supplied parameters."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence
from urllib.parse import urlparse


try:
    import yaml
except ImportError:  # pragma: no cover - runtime guard
    yaml = None


SCAN_MODE_BACKENDS = {
    "auto": "auto",
    "clang": "clang",
    "clangd": "clang",
    "unified": "unified",
    "svf": "unified",
    "regex": "regex",
    "joern": "joern",
    "java": "java_unified",
    "java_source": "java_source",
    "java_unified": "java_unified",
}

LANGUAGE_SCAN_MODES = {
    "c_cpp": {"auto", "clang", "unified", "regex", "joern"},
    "java": {"auto", "joern", "java_source", "java_unified"},
}

BACKEND_LANGUAGES = {
    "clang": "c_cpp",
    "unified": "c_cpp",
    "regex": "c_cpp",
    "java_source": "java",
    "java_unified": "java",
}

DEFAULT_SCAN_MODE_BY_LANGUAGE = {
    "c_cpp": "unified",
    "java": "java_unified",
}

JAVA_STRUCTURE_FRONTENDS = ("auto", "spoon", "javaparser", "builtin")
JAVA_SIGNAL_BACKENDS = ("joern", "sootup", "wala", "codeql")

PROJECT_PATH_FIELDS = (
    ("project.source_root", ("project", "source_root"), "scalar"),
    ("project.entry_functions_list", ("project", "entry_functions_list"), "scalar"),
    ("project.compile_commands_path", ("project", "compile_commands_path"), "scalar"),
    ("indexing.knowledge_db_path", ("indexing", "knowledge_db_path"), "scalar"),
    ("analysis.snapshot_dir", ("analysis", "snapshot_dir"), "scalar"),
    ("analysis.user_config_db", ("analysis", "user_config_db"), "scalar"),
    ("analysis.tool_audit_log", ("analysis", "tool_audit_log"), "scalar"),
    ("project.include_paths", ("project", "include_paths"), "list"),
    ("project.exclude_paths", ("project", "exclude_paths"), "list"),
    ("project.entry_discovery.header_files", ("project", "entry_discovery", "header_files"), "list"),
)

EXPLICIT_FIELD_MAP = {
    "source_root": ("project", "source_root"),
    "entry_functions_list": ("project", "entry_functions_list"),
    "compile_commands_path": ("project", "compile_commands_path"),
    "include_paths": ("project", "include_paths"),
    "exclude_paths": ("project", "exclude_paths"),
    "public_headers": ("project", "entry_discovery", "header_files"),
    "knowledge_db_path": ("indexing", "knowledge_db_path"),
    "snapshot_dir": ("analysis", "snapshot_dir"),
    "user_config_db": ("analysis", "user_config_db"),
    "tool_audit_log": ("analysis", "tool_audit_log"),
    "joern_path": ("indexing", "joern_path"),
    "clangd_path": ("indexing", "clangd_path"),
    "svf_bin_dir": ("indexing", "svf_bin_dir"),
    "gclang_path": ("indexing", "gclang_path"),
    "get_bc_path": ("indexing", "get_bc_path"),
    "llvm_link_path": ("indexing", "llvm_link_path"),
}

TOOL_FIELDS = (
    "joern_path",
    "clangd_path",
    "svf_bin_dir",
    "gclang_path",
    "get_bc_path",
    "llvm_link_path",
)

TOOL_FIELD_NAMES = {
    "joern_path": "indexing.joern_path",
    "clangd_path": "indexing.clangd_path",
    "svf_bin_dir": "indexing.svf_bin_dir",
    "gclang_path": "indexing.gclang_path",
    "get_bc_path": "indexing.get_bc_path",
    "llvm_link_path": "indexing.llvm_link_path",
}

KNOWN_TOOL_PATHS = {
    "joern_path": ["/opt/buildtools/joern-cli/joern", "/opt/buildtools/joern-cli/bin/joern"],
    "clangd_path": ["/opt/buildtools/clangd_20.1.0/bin/clangd"],
    "svf_bin_dir": ["/root/sdk/svf/bin"],
    "gclang_path": ["/opt/buildtools/go_workpace/bin/gclang"],
    "get_bc_path": ["/opt/buildtools/go_workpace/bin/get-bc"],
    "llvm_link_path": ["/root/sdk/llvm-18/bin/llvm-link"],
}

TOOL_COMMANDS = {
    "joern_path": "joern",
    "clangd_path": "clangd",
    "gclang_path": "gclang",
    "get_bc_path": "get-bc",
    "llvm_link_path": "llvm-link",
}

TOOL_ENV_VARS = {
    "joern_path": (("Z_SCOPE_JOERN_PATH", ""), ("JOERN_HOME", "joern"), ("JOERN_HOME", "bin/joern")),
    "clangd_path": (("Z_SCOPE_CLANGD_PATH", ""), ("CLANGD_PATH", "")),
    "svf_bin_dir": (("Z_SCOPE_SVF_BIN_DIR", ""), ("SVF_BIN_DIR", ""), ("SVF_HOME", "bin")),
    "gclang_path": (("Z_SCOPE_GCLANG_PATH", ""), ("GOPATH", "bin/gclang")),
    "get_bc_path": (("Z_SCOPE_GET_BC_PATH", ""), ("GOPATH", "bin/get-bc")),
    "llvm_link_path": (("Z_SCOPE_LLVM_LINK_PATH", ""), ("LLVM_HOME", "bin/llvm-link")),
}

DEPLOYMENT_PROBE_NAMES = {
    "joern_path": ("joern",),
    "clangd_path": ("clangd",),
    "gclang_path": ("gclang",),
    "get_bc_path": ("get-bc", "get_bc"),
    "llvm_link_path": ("llvm-link", "llvm_link"),
}


class ConfigPatchError(RuntimeError):
    """Raised when a frontend YAML patch cannot be applied."""


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Patch a Z-SCOPE YAML file from frontend web configuration."
    )
    parser.add_argument("--yaml", required=True, help="Input zscope.yaml path.")
    parser.add_argument("--output", default="", help="Output path. Defaults to overwriting --yaml.")
    parser.add_argument(
        "--create-if-missing",
        action="store_true",
        help="Create a minimal YAML document if --yaml does not exist.",
    )
    parser.add_argument(
        "--params-json",
        default="",
        help="Inline JSON object with frontend parameters.",
    )
    parser.add_argument(
        "--params-file",
        default="",
        help="JSON file with frontend parameters.",
    )

    parser.add_argument("--username", default="")
    parser.add_argument("--version", default="")
    parser.add_argument("--project-root", default="")
    parser.add_argument("--source-root", default="")
    parser.add_argument("--entry-functions-list", default="")
    parser.add_argument("--compile-commands-path", default="")
    parser.add_argument(
        "--target-path",
        action="append",
        default=[],
        help="User scan target file or directory path. Repeat for multiple targets.",
    )
    parser.add_argument("--include-path", action="append", default=[], help="Project include path. Repeat for multiple paths.")
    parser.add_argument("--exclude-path", action="append", default=[], help="Project exclude path. Repeat for multiple paths.")
    parser.add_argument(
        "--public-header",
        action="append",
        default=[],
        help="External/public header naming pattern. Repeat for multiple patterns.",
    )
    parser.add_argument(
        "--scan-mode",
        default="",
        help="Scan backend mode: auto, clang, unified, regex, joern, java_source, java_unified.",
    )
    parser.add_argument("--language", default="")
    parser.add_argument("--java-structure-frontend", default="")
    parser.add_argument(
        "--java-signal-backend",
        action="append",
        default=None,
        help="Java signal backend. Repeat for multiple values.",
    )
    parser.add_argument("--clear-java-signal-backends", action="store_true")
    parser.add_argument("--knowledge-db-path", default="")
    parser.add_argument("--snapshot-dir", default="")
    parser.add_argument("--user-config-db", default="")
    parser.add_argument("--tool-audit-log", default="")
    parser.add_argument("--joern-path", default="")
    parser.add_argument("--clangd-path", default="")
    parser.add_argument("--svf-bin-dir", default="")
    parser.add_argument("--gclang-path", default="")
    parser.add_argument("--get-bc-path", default="")
    parser.add_argument("--llvm-link-path", default="")
    parser.add_argument("--toolchain-config-mode", default="")
    parser.add_argument("--auto-configure-toolchain", dest="auto_configure_toolchain", action="store_true", default=None)
    parser.add_argument("--no-auto-configure-toolchain", dest="auto_configure_toolchain", action="store_false")
    parser.add_argument("--no-migrate-project-paths", dest="migrate_project_paths", action="store_false", default=None)
    parser.add_argument("--llm-base-url", default="")
    parser.add_argument("--llm-model", default="")
    parser.add_argument("--llm-api-key", default="")
    parser.add_argument("--llm-api-key-env", default="")
    parser.add_argument("--smart-llm-base-url", default="")
    parser.add_argument("--smart-llm-model", default="")
    parser.add_argument("--smart-llm-api-key", default="")
    parser.add_argument("--smart-llm-api-key-env", default="")
    parser.add_argument("--json", action="store_true", help="Emit JSON result.")
    parser.add_argument("--dry-run", action="store_true", help="Do not write the YAML file.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = patch_yaml_from_args(args)
    except ConfigPatchError as exc:
        payload = {"success": False, "error": str(exc)}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"success: {result['success']}")
        print(f"path: {result['path']}")
        if args.dry_run:
            print("dry_run: true")
    return 0


def patch_yaml_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if yaml is None:
        raise ConfigPatchError("PyYAML is required")
    yaml_path = Path(args.yaml).expanduser()
    output_path = Path(args.output).expanduser() if args.output else yaml_path
    data = load_yaml_document(yaml_path, create_if_missing=bool(args.create_if_missing))
    params = collect_params(args)
    changed, path_migration, toolchain_detection = apply_frontend_params(data, params)
    text = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
    if not args.dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")
    return {
        "success": True,
        "dry_run": bool(args.dry_run),
        "path": str(output_path),
        "changed_fields": changed,
        "path_migration": path_migration,
        "toolchain_detection": toolchain_detection,
        "config": data,
    }


def load_yaml_document(path: Path, *, create_if_missing: bool) -> dict[str, Any]:
    if not path.exists():
        if not create_if_missing:
            raise ConfigPatchError(f"YAML file not found: {path}")
        return minimal_config()
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) if raw.strip() else {}
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigPatchError("YAML root must be an object")
    return data


def minimal_config() -> dict[str, Any]:
    return {
        "llms": {
            "default": {
                "provider": "openai",
                "base_urls": ["${Z_SCOPE_BASE_URL}"],
                "models": ["${Z_SCOPE_MODEL}"],
                "api_key": "${Z_SCOPE_API_KEY}",
                "temperature": 0.1,
                "max_tokens": 4096,
                "timeout": 180,
                "max_retries": 2,
            }
        },
        "project": {
            "root": ".",
            "source_root": ".",
            "language": "auto",
            "entry_discovery": {
                "enabled": True,
                "max_candidates": 200,
                "max_functions": 10000,
                "header_files": [],
                "scan_after_discovery": True,
            },
            "include_paths": [],
            "exclude_paths": ["build", "target", ".git", ".zscope_knowledge", ".zscope_snapshots"],
            "agents": [
                {"name": "semantic_modeler", "enabled": True, "llm_ref": "default"},
                {
                    "name": "vulnerability_analyzer",
                    "enabled": True,
                    "llm_ref": "smart_model",
                    "can_spawn_subagents": True,
                    "task": "Audit security defects, memory/resource lifecycle risks, Java web vulnerabilities, concurrency risks, and logic flaws.",
                },
                {"name": "issue_reconciler_agent", "enabled": True, "llm_ref": "default"},
                {"name": "validator_agent", "enabled": True, "llm_ref": "smart_model"},
            ],
        },
        "indexing": {"backend": "auto", "joern_language": "auto"},
        "analysis": {
            "snapshot_dir": ".zscope_snapshots",
            "enable_snapshot_cache": True,
            "parallel_workers": 5,
            "enable_subagent_workers": True,
            "max_subagent_tickets": 4,
        },
        "reporting": {
            "semantic_dedup": {
                "enabled": True,
                "llm_enabled": True,
                "llm_confidence_threshold": 0.85,
                "max_cluster_size": 8,
            }
        },
    }


def collect_params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for raw in (args.params_json,):
        if raw:
            loaded = json.loads(raw)
            if not isinstance(loaded, dict):
                raise ConfigPatchError("--params-json must be a JSON object")
            deep_merge(params, loaded)
    if args.params_file:
        loaded = json.loads(Path(args.params_file).expanduser().read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ConfigPatchError("--params-file must contain a JSON object")
        deep_merge(params, loaded)

    direct = {
        "username": args.username,
        "version": args.version,
        "project_root": args.project_root,
        "source_root": args.source_root,
        "entry_functions_list": args.entry_functions_list,
        "compile_commands_path": args.compile_commands_path,
        "scan_mode": args.scan_mode,
        "language": args.language,
        "java_structure_frontend": args.java_structure_frontend,
        "knowledge_db_path": args.knowledge_db_path,
        "snapshot_dir": args.snapshot_dir,
        "user_config_db": args.user_config_db,
        "tool_audit_log": args.tool_audit_log,
        "joern_path": args.joern_path,
        "clangd_path": args.clangd_path,
        "svf_bin_dir": args.svf_bin_dir,
        "gclang_path": args.gclang_path,
        "get_bc_path": args.get_bc_path,
        "llvm_link_path": args.llvm_link_path,
        "toolchain_config_mode": args.toolchain_config_mode,
        "llm_base_url": args.llm_base_url,
        "llm_model": args.llm_model,
        "llm_api_key": args.llm_api_key,
        "llm_api_key_env": args.llm_api_key_env,
        "smart_llm_base_url": args.smart_llm_base_url,
        "smart_llm_model": args.smart_llm_model,
        "smart_llm_api_key": args.smart_llm_api_key,
        "smart_llm_api_key_env": args.smart_llm_api_key_env,
    }
    for key, value in direct.items():
        if value:
            params[key] = value
    if args.java_signal_backend is not None and args.clear_java_signal_backends:
        raise ConfigPatchError("--java-signal-backend cannot be used with --clear-java-signal-backends")
    if args.java_signal_backend is not None:
        params["java_signal_backends"] = args.java_signal_backend
    if args.clear_java_signal_backends:
        params["java_signal_backends"] = []
    if args.target_path:
        params["target_paths"] = args.target_path
    if args.include_path:
        params["include_paths"] = args.include_path
    if args.exclude_path:
        params["exclude_paths"] = args.exclude_path
    if args.public_header:
        params["public_headers"] = args.public_header
    if args.auto_configure_toolchain is not None:
        params["auto_configure_toolchain"] = args.auto_configure_toolchain
    if args.migrate_project_paths is not None:
        params["migrate_project_paths"] = args.migrate_project_paths
    return params


def apply_frontend_params(config: dict[str, Any], params: dict[str, Any]) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
    changed: list[str] = []
    metadata = ensure_dict(config, "metadata")
    frontend = ensure_dict(metadata, "frontend")
    for source_key, target_key in (("username", "username"), ("version", "version")):
        value = clean(params.get(source_key))
        if value:
            frontend[target_key] = value
            changed.append(f"metadata.frontend.{target_key}")
    frontend["updated_at"] = datetime.now(timezone.utc).isoformat()
    changed.append("metadata.frontend.updated_at")

    project = ensure_dict(config, "project")
    old_project_root = clean(project.get("root"))
    project_root = clean(params.get("project_root") or params.get("build_root"))
    path_migration = apply_project_path_migration(config, params, old_project_root, project_root, changed)
    if project_root:
        set_config_value(config, ("project", "root"), project_root, changed, "project.root")
        if not clean(project.get("source_root")) and "source_root" not in params:
            set_config_value(config, ("project", "source_root"), project_root, changed, "project.source_root")

    apply_explicit_path_params(config, params, changed)

    apply_scan_configuration(config, params, changed)
    apply_java_backend_configuration(config, params, changed)

    toolchain_detection = apply_toolchain_config(config, params, changed)
    apply_llm(config, params, changed)
    return dedupe(changed), path_migration, toolchain_detection


def apply_scan_configuration(config: dict[str, Any], params: dict[str, Any], changed: list[str]) -> None:
    project = ensure_dict(config, "project")
    indexing = ensure_dict(config, "indexing")
    scan_mode = clean(params.get("scan_mode") or params.get("backend"))
    backend = normalize_scan_mode(scan_mode) if scan_mode else ""
    language_param = clean(params.get("language"))
    language = normalize_language(language_param) if language_param else ""
    if not language and backend:
        language = BACKEND_LANGUAGES.get(backend, "")
    if not backend and language:
        current_backend = normalize_scan_mode(clean(indexing.get("backend") or "auto"))
        if current_backend == "auto":
            backend = DEFAULT_SCAN_MODE_BY_LANGUAGE.get(language, "")

    final_backend = backend or normalize_scan_mode(clean(indexing.get("backend") or "auto"))
    final_language = language or normalize_language(clean(project.get("language") or BACKEND_LANGUAGES.get(final_backend, "auto")))
    validate_language_scan_mode(final_language, final_backend)

    if backend:
        set_config_value(config, ("indexing", "backend"), backend, changed, "indexing.backend")
    if language:
        set_config_value(config, ("project", "language"), language, changed, "project.language")
        if language in {"java", "c_cpp"}:
            set_config_value(config, ("indexing", "joern_language"), language, changed, "indexing.joern_language")


def apply_java_backend_configuration(config: dict[str, Any], params: dict[str, Any], changed: list[str]) -> None:
    project = ensure_dict(config, "project")
    indexing = ensure_dict(config, "indexing")
    language = normalize_language(clean(project.get("language") or "auto"))
    backend = normalize_scan_mode(clean(indexing.get("backend") or "auto"))
    has_structure = "java_structure_frontend" in params
    has_signal = "java_signal_backends" in params

    if (has_structure or has_signal) and language != "java":
        raise ConfigPatchError(f"Java-specific configuration requires language 'java', got '{language}'")

    if has_structure:
        value = normalize_java_structure_frontend(params.get("java_structure_frontend"))
        set_config_value(
            config,
            ("indexing", "java_structure_frontend"),
            value,
            changed,
            "indexing.java_structure_frontend",
        )

    if has_signal:
        values = normalize_java_signal_backends(params.get("java_signal_backends"))
        set_config_value(
            config,
            ("indexing", "java_signal_backends"),
            values,
            changed,
            "indexing.java_signal_backends",
        )

    signal_backends = normalize_java_signal_backends(indexing.get("java_signal_backends", []))
    if backend == "java_source" and signal_backends:
        raise ConfigPatchError("java_signal_backends requires scan_mode=java_unified")
    if backend == "joern" and has_signal and signal_backends:
        raise ConfigPatchError("java_signal_backends requires scan_mode=java_unified")


def validate_language_scan_mode(language: str, backend: str) -> None:
    if language in {"", "auto"} or backend in {"", "auto"}:
        return
    allowed = LANGUAGE_SCAN_MODES.get(language)
    if allowed is None:
        raise ConfigPatchError(f"Unsupported language: {language}")
    if backend not in allowed:
        raise ConfigPatchError(f"Scan mode '{backend}' is incompatible with language '{language}'")


def apply_llm(config: dict[str, Any], params: dict[str, Any], changed: list[str]) -> None:
    llms = ensure_dict(config, "llms")
    default = ensure_dict(llms, "default")
    default_values = {
        "base_url": params.get("llm_base_url") or params.get("base_url"),
        "model": params.get("llm_model") or params.get("model"),
        "api_key": params.get("llm_api_key"),
        "api_key_env": params.get("llm_api_key_env"),
    }
    update_llm_profile(
        default,
        changed=changed,
        prefix="llms.default",
        **default_values,
    )
    smart_values = {
        "base_url": params.get("smart_llm_base_url") or params.get("smart_base_url"),
        "model": params.get("smart_llm_model") or params.get("smart_model"),
        "api_key": params.get("smart_llm_api_key"),
        "api_key_env": params.get("smart_llm_api_key_env"),
    }
    if any(clean(value) for value in smart_values.values()):
        smart = ensure_dict(llms, "smart_model")
        if "provider" not in smart:
            smart["provider"] = "openai"
        update_llm_profile(
            smart,
            changed=changed,
            prefix="llms.smart_model",
            **smart_values,
        )
    elif any(clean(value) for value in default_values.values()):
        smart = ensure_dict(llms, "smart_model")
        if "provider" not in smart:
            smart["provider"] = "openai"
        update_llm_profile(
            smart,
            changed=changed,
            prefix="llms.smart_model",
            **default_values,
        )


def apply_project_path_migration(
    config: dict[str, Any],
    params: dict[str, Any],
    old_project_root: str,
    new_project_root: str,
    changed: list[str],
) -> dict[str, Any]:
    enabled = parse_bool(params.get("migrate_project_paths", True), name="migrate_project_paths")
    summary = {
        "enabled": enabled,
        "applied": False,
        "old_project_root": old_project_root,
        "new_project_root": new_project_root,
        "migrated_fields": [],
        "skipped_reason": "",
    }
    if not enabled:
        summary["skipped_reason"] = "disabled by user"
        return summary
    if not new_project_root:
        summary["skipped_reason"] = "project_root was not provided"
        return summary
    if not old_project_root:
        summary["skipped_reason"] = "old project.root is empty"
        return summary
    if old_project_root == new_project_root:
        summary["skipped_reason"] = "project_root is unchanged"
        return summary
    if not (is_absolute_posix_path(old_project_root) and is_absolute_posix_path(new_project_root)):
        summary["skipped_reason"] = "old and new project roots must both be absolute paths"
        return summary

    explicit_fields = explicit_config_fields(params)
    for field_name, keys, kind in PROJECT_PATH_FIELDS:
        if field_name in explicit_fields:
            continue
        current = get_nested(config, keys)
        if current is None:
            continue
        if kind == "list":
            migrated, records = migrate_path_list_under_root(
                current,
                old_root=old_project_root,
                new_root=new_project_root,
                field_name=field_name,
            )
            if records:
                set_nested(config, keys, migrated)
                changed.append(field_name)
                summary["migrated_fields"].extend(records)
        else:
            migrated, did_migrate = migrate_path_under_root(current, old_root=old_project_root, new_root=new_project_root)
            if did_migrate:
                set_nested(config, keys, migrated)
                changed.append(field_name)
                summary["migrated_fields"].append({"field": field_name, "old": clean(current), "new": migrated})

    project = ensure_dict(config, "project")
    if not clean(project.get("source_root")) and "project.source_root" not in explicit_fields:
        project["source_root"] = new_project_root
        changed.append("project.source_root")

    summary["applied"] = bool(summary["migrated_fields"])
    if not summary["applied"]:
        summary["skipped_reason"] = "no whitelisted project paths required migration"
    return summary


def explicit_config_fields(params: dict[str, Any]) -> set[str]:
    fields: set[str] = set()
    for param, keys in EXPLICIT_FIELD_MAP.items():
        if param in params and has_explicit_value(params.get(param)):
            fields.add(".".join(keys))
    if any(key in params and has_explicit_value(params.get(key)) for key in ("target_paths", "target_path", "scan_target_paths", "scan_target_file")):
        fields.add("project.include_paths")
    if any(key in params and has_explicit_value(params.get(key)) for key in ("public_header", "external_header_names", "external_header_naming")):
        fields.add("project.entry_discovery.header_files")
    return fields


def apply_explicit_path_params(config: dict[str, Any], params: dict[str, Any], changed: list[str]) -> None:
    scalar_params = (
        "source_root",
        "entry_functions_list",
        "compile_commands_path",
        "knowledge_db_path",
        "snapshot_dir",
        "user_config_db",
        "tool_audit_log",
    )
    for param in scalar_params:
        value = clean(params.get(param))
        if value:
            keys = EXPLICIT_FIELD_MAP[param]
            set_config_value(config, keys, value, changed, ".".join(keys))

    include_paths = string_list(params.get("include_paths"))
    if not include_paths:
        include_paths = string_list(
            params.get("target_paths")
            or params.get("target_path")
            or params.get("scan_target_paths")
            or params.get("scan_target_file")
        )
    if include_paths:
        set_config_value(config, ("project", "include_paths"), include_paths, changed, "project.include_paths")

    exclude_paths = string_list(params.get("exclude_paths"))
    if exclude_paths:
        set_config_value(config, ("project", "exclude_paths"), exclude_paths, changed, "project.exclude_paths")

    public_headers = string_list(
        params.get("public_headers")
        or params.get("public_header")
        or params.get("external_header_names")
        or params.get("external_header_naming")
    )
    if public_headers:
        entry_discovery = ensure_dict(ensure_dict(config, "project"), "entry_discovery")
        entry_discovery["enabled"] = True
        entry_discovery["header_files"] = public_headers
        changed.extend(["project.entry_discovery.enabled", "project.entry_discovery.header_files"])

    for param in TOOL_FIELDS:
        value = clean(params.get(param))
        if value:
            validated = validate_tool_value(param, value)
            set_config_value(config, EXPLICIT_FIELD_MAP[param], validated, changed, ".".join(EXPLICIT_FIELD_MAP[param]))


def migrate_path_under_root(value: Any, *, old_root: str, new_root: str) -> tuple[Any, bool]:
    if not isinstance(value, str):
        return value, False
    text = value.strip()
    if not text:
        return value, False
    if is_url(text) or text.startswith("${"):
        return value, False
    if not (is_absolute_posix_path(text) and is_absolute_posix_path(old_root) and is_absolute_posix_path(new_root)):
        return value, False
    try:
        suffix = PurePosixPath(text).relative_to(PurePosixPath(old_root))
    except ValueError:
        return value, False
    migrated = str(PurePosixPath(new_root) / suffix)
    return migrated, migrated != text


def migrate_path_list_under_root(value: Any, *, old_root: str, new_root: str, field_name: str) -> tuple[Any, list[dict[str, str]]]:
    if not isinstance(value, list):
        return value, []
    migrated_list = []
    records: list[dict[str, str]] = []
    for index, item in enumerate(value):
        migrated, changed = migrate_path_under_root(item, old_root=old_root, new_root=new_root)
        migrated_list.append(migrated)
        if changed:
            records.append({"field": f"{field_name}[{index}]", "old": clean(item), "new": migrated})
    return migrated_list, records


def is_absolute_posix_path(value: str) -> bool:
    return isinstance(value, str) and value.startswith("/") and not is_url(value)


def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def parse_bool(value: Any, *, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if value is None:
        return False
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "on"}:
        return True
    if text in {"false", "0", "no", "n", "off"}:
        return False
    raise ConfigPatchError(f"Invalid boolean value for {name}: {value}")


def has_explicit_value(value: Any) -> bool:
    if isinstance(value, list):
        return bool(string_list(value))
    return bool(clean(value))


def get_nested(data: dict[str, Any], keys: Sequence[str]) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def set_nested(data: dict[str, Any], keys: Sequence[str], value: Any) -> None:
    current = data
    for key in keys[:-1]:
        current = ensure_dict(current, key)
    current[keys[-1]] = value


def set_config_value(data: dict[str, Any], keys: Sequence[str], value: Any, changed: list[str], field_name: str) -> None:
    if get_nested(data, keys) != value:
        set_nested(data, keys, value)
        changed.append(field_name)


def update_llm_profile(
    profile: dict[str, Any],
    *,
    base_url: Any,
    model: Any,
    api_key: Any,
    api_key_env: Any,
    changed: list[str],
    prefix: str,
) -> None:
    if "provider" not in profile:
        profile["provider"] = "openai"
    base_url_text = clean(base_url)
    if base_url_text:
        profile["base_urls"] = [base_url_text]
        profile.pop("base_url", None)
        changed.append(f"{prefix}.base_urls")
    model_text = clean(model)
    if model_text:
        profile["models"] = [model_text]
        changed.append(f"{prefix}.models")
    api_key_text = clean(api_key)
    api_key_env_text = clean(api_key_env)
    if api_key_text:
        profile["api_key"] = api_key_text
        changed.append(f"{prefix}.api_key")
    elif api_key_env_text:
        profile["api_key"] = "${" + api_key_env_text + "}"
        changed.append(f"{prefix}.api_key")


def apply_toolchain_config(config: dict[str, Any], params: dict[str, Any], changed: list[str]) -> dict[str, Any]:
    detection = detect_toolchain(config, params)
    indexing = ensure_dict(config, "indexing")
    mode = detection["mode"]
    for item in detection["items"]:
        field = item["field"]
        key = field.split(".", 1)[1]
        if not item.get("validated") or not item.get("value"):
            continue
        if mode == "preserve" and item.get("source") != "explicit":
            continue
        if indexing.get(key) != item["value"]:
            indexing[key] = item["value"]
            changed.append(field)
    if mode == "explicit" and detection["errors"]:
        raise ConfigPatchError("; ".join(detection["errors"]))
    explicit_errors = [error for error in detection["errors"] if error.startswith("explicit ")]
    if explicit_errors:
        raise ConfigPatchError("; ".join(explicit_errors))
    return detection


def detect_toolchain(config: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    mode = toolchain_mode(params)
    detection = {"mode": mode, "success": True, "items": [], "warnings": [], "errors": []}
    indexing = ensure_dict(config, "indexing")
    required = required_tool_fields(config, params)
    explicit_fields = {field for field in TOOL_FIELDS if field in params and has_explicit_value(params.get(field))}

    if mode == "explicit":
        missing = [field for field in required if field not in explicit_fields]
        for field in missing:
            detection["errors"].append(f"missing explicit required tool: {TOOL_FIELD_NAMES[field]}")

    for field in TOOL_FIELDS:
        item = detect_one_tool(field, config, params, mode)
        detection["items"].append(item)

    values = {item["field"].split(".", 1)[1]: item for item in detection["items"]}
    if values.get("gclang_path", {}).get("validated") != values.get("get_bc_path", {}).get("validated"):
        detection["warnings"].append("GLLVM toolchain incomplete: gclang and get-bc should be configured together")

    for field in required:
        item = values.get(field, {})
        if not item.get("validated"):
            detection["success"] = False
            message = f"required tool not configured: {TOOL_FIELD_NAMES[field]}"
            if mode == "explicit":
                detection["errors"].append(message)
            else:
                detection["warnings"].append(message)

    if mode == "explicit" and detection["errors"]:
        detection["success"] = False
    if mode == "auto" and indexing.get("backend") == "auto":
        detection["success"] = True
    return detection


def toolchain_mode(params: dict[str, Any]) -> str:
    raw = clean(params.get("toolchain_config_mode"))
    if not raw and "auto_configure_toolchain" in params:
        raw = "auto" if parse_bool(params.get("auto_configure_toolchain"), name="auto_configure_toolchain") else "preserve"
    if not raw:
        raw = "auto"
    mode = raw.strip().lower()
    if mode not in {"auto", "preserve", "explicit"}:
        raise ConfigPatchError(f"Unsupported toolchain_config_mode: {raw}")
    return mode


def required_tool_fields(config: dict[str, Any], params: dict[str, Any] | None = None) -> set[str]:
    params = params or {}
    indexing = ensure_dict(config, "indexing")
    project = ensure_dict(config, "project")
    backend = normalize_scan_mode(clean(indexing.get("backend") or "auto"))
    language = normalize_language(clean(project.get("language") or BACKEND_LANGUAGES.get(backend, "auto")))
    if backend == "regex" or backend == "auto":
        return set()
    if backend == "joern" and language == "java":
        return {"joern_path"}
    if backend == "java_source" and language == "java":
        return set()
    if backend == "java_unified" and language == "java":
        signal_backends = normalize_java_signal_backends(indexing.get("java_signal_backends", []))
        signal_param_present = "java_signal_backends" in params
        if "joern" in signal_backends:
            return {"joern_path"}
        if signal_backends:
            return set()
        return set() if signal_param_present else {"joern_path"}
    if backend == "clang":
        return {"clangd_path"}
    if backend == "unified" and language == "c_cpp":
        return {"clangd_path", "svf_bin_dir", "gclang_path", "get_bc_path", "llvm_link_path"}
    return set()


def detect_one_tool(field: str, config: dict[str, Any], params: dict[str, Any], mode: str) -> dict[str, Any]:
    item = {"field": TOOL_FIELD_NAMES[field], "value": "", "source": "not_found", "validated": False}
    explicit_value = clean(params.get(field))
    if explicit_value:
        value = validate_tool_value(field, explicit_value)
        item.update({"value": value, "source": "explicit", "validated": True})
        return item
    if mode in {"preserve", "explicit"}:
        existing = clean(get_nested(config, ("indexing", field)))
        if existing:
            item.update({"value": existing, "source": "existing_config", "validated": mode == "preserve"})
        return item

    for source_name, candidate in tool_candidates(field, config, params):
        value = try_validate_tool_value(field, candidate)
        if value:
            item.update({"value": value, "source": source_name, "validated": True})
            return item

    existing = clean(get_nested(config, ("indexing", field)))
    if existing:
        item.update({"value": existing, "source": "existing_config", "validated": False})
    return item


def tool_candidates(field: str, config: dict[str, Any], params: dict[str, Any]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    candidates.extend(("deployment_status", value) for value in deployment_status_candidates(field, params.get("deployment_status")))
    candidates.extend(("environment", value) for value in environment_candidates(field))
    command = TOOL_COMMANDS.get(field)
    if command:
        candidates.append(("path", command))
    if field == "svf_bin_dir":
        candidates.extend(("path", value) for value in svf_from_path_candidates())
    candidates.extend(("known_installation", value) for value in KNOWN_TOOL_PATHS.get(field, ()))
    existing = clean(get_nested(config, ("indexing", field)))
    if existing:
        candidates.append(("existing_config", existing))
    if command:
        candidates.append(("path", command))
    return candidates


def deployment_status_candidates(field: str, deployment_status: Any) -> list[str]:
    if not isinstance(deployment_status, dict):
        return []
    values: list[str] = []
    sections = []
    if field == "joern_path":
        sections.append(deployment_status.get("java"))
    else:
        sections.append(deployment_status.get("c_cpp"))
    for status in sections:
        if not isinstance(status, dict) or status.get("status_ok") is not True:
            continue
        probes = status.get("probes") if isinstance(status.get("probes"), dict) else {}
        if field == "svf_bin_dir":
            wpa = probe_executable(probes, ("wpa",))
            saber = probe_executable(probes, ("saber",))
            if wpa and saber and Path(wpa).parent == Path(saber).parent:
                values.append(str(Path(wpa).parent))
            paths = status.get("paths") if isinstance(status.get("paths"), dict) else {}
            svf_dir = clean(paths.get("svf_dir"))
            if svf_dir:
                values.append(str(Path(svf_dir) / "bin"))
            continue
        probe = probe_executable(probes, DEPLOYMENT_PROBE_NAMES.get(field, ()))
        if probe:
            values.append(probe)
        paths = status.get("paths") if isinstance(status.get("paths"), dict) else {}
        runtime_paths = status.get("runtime_paths") if isinstance(status.get("runtime_paths"), dict) else {}
        path_value = deployment_path_value(field, paths, runtime_paths)
        if path_value:
            values.append(path_value)
    return values


def deployment_path_value(field: str, paths: dict[str, Any], runtime_paths: dict[str, Any]) -> str:
    if field == "clangd_path" and clean(paths.get("clangd_dir")):
        return str(Path(clean(paths["clangd_dir"])) / "bin" / "clangd")
    if field == "llvm_link_path" and clean(paths.get("llvm_dir")):
        return str(Path(clean(paths["llvm_dir"])) / "bin" / "llvm-link")
    if field == "svf_bin_dir" and clean(paths.get("svf_dir")):
        return str(Path(clean(paths["svf_dir"])) / "bin")
    if field == "gclang_path" and clean(paths.get("gopath")):
        return str(Path(clean(paths["gopath"])) / "bin" / "gclang")
    if field == "get_bc_path" and clean(paths.get("gopath")):
        return str(Path(clean(paths["gopath"])) / "bin" / "get-bc")
    return clean(runtime_paths.get(field))


def probe_executable(probes: dict[str, Any], names: Sequence[str]) -> str:
    for name in names:
        probe = probes.get(name)
        if isinstance(probe, dict) and probe.get("ok") is True:
            command = probe.get("command")
            if isinstance(command, list) and command:
                return clean(command[0])
    return ""


def environment_candidates(field: str) -> list[str]:
    values: list[str] = []
    for env_name, suffix in TOOL_ENV_VARS.get(field, ()):
        raw = clean(os.environ.get(env_name))
        if not raw:
            continue
        values.append(str(Path(raw) / suffix) if suffix else raw)
    return values


def svf_from_path_candidates() -> list[str]:
    wpa = shutil.which("wpa")
    saber = shutil.which("saber")
    if wpa and saber and Path(wpa).parent == Path(saber).parent:
        return [str(Path(wpa).parent)]
    return []


def try_validate_tool_value(field: str, value: str) -> str:
    try:
        return validate_tool_value(field, value)
    except ConfigPatchError:
        return ""


def validate_tool_value(field: str, value: str) -> str:
    text = clean(value)
    if not text:
        raise ConfigPatchError(f"{TOOL_FIELD_NAMES.get(field, field)} is empty")
    if field == "svf_bin_dir":
        return validate_svf_bin_dir(text)
    if field == "joern_path":
        expanded = Path(text).expanduser()
        if expanded.is_dir():
            for relative in ("joern", "bin/joern"):
                candidate = expanded / relative
                if is_executable_file(candidate):
                    return str(candidate)
        return validate_executable_candidate(text, field)
    return validate_executable_candidate(text, field)


def validate_executable_candidate(value: str, field: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        resolved = shutil.which(value)
        if resolved:
            path = Path(resolved)
        else:
            raise ConfigPatchError(f"{TOOL_FIELD_NAMES.get(field, field)} command not found: {value}")
    if not is_executable_file(path):
        raise ConfigPatchError(f"{TOOL_FIELD_NAMES.get(field, field)} is not an executable file: {path}")
    return str(path)


def validate_svf_bin_dir(value: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ConfigPatchError(f"indexing.svf_bin_dir must be an absolute directory: {value}")
    if not path.is_dir():
        raise ConfigPatchError(f"indexing.svf_bin_dir is not a directory: {path}")
    for name in ("wpa", "saber"):
        if not is_executable_file(path / name):
            raise ConfigPatchError(f"indexing.svf_bin_dir missing executable {name}: {path}")
    return str(path)


def is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def normalize_scan_mode(value: str) -> str:
    text = value.strip().lower().replace("-", "_")
    if text not in SCAN_MODE_BACKENDS:
        if text == "undefined":
            raise ConfigPatchError("Unsupported scan mode: undefined. Did you mean 'unified'?")
        raise ConfigPatchError(f"Unsupported scan mode: {value}")
    return SCAN_MODE_BACKENDS[text]


def normalize_language(value: str) -> str:
    text = value.strip().lower().replace("-", "_")
    aliases = {"c": "c_cpp", "cpp": "c_cpp", "c++": "c_cpp"}
    return aliases.get(text, text)


def normalize_java_structure_frontend(value: Any) -> str:
    text = clean(value).lower().replace("-", "_")
    if text not in JAVA_STRUCTURE_FRONTENDS:
        raise ConfigPatchError(
            f"Unsupported java_structure_frontend: {value}. "
            f"Allowed values: {', '.join(JAVA_STRUCTURE_FRONTENDS)}"
        )
    return text


def normalize_java_signal_backends(value: Any) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in string_list(value):
        backend = item.strip().lower().replace("-", "_")
        if backend not in JAVA_SIGNAL_BACKENDS:
            raise ConfigPatchError(
                f"Unsupported java_signal_backends value: {item}. "
                f"Allowed values: {', '.join(JAVA_SIGNAL_BACKENDS)}"
            )
        if backend not in seen:
            normalized.append(backend)
            seen.add(backend)
    return normalized


def ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        value = {}
        parent[key] = value
    return value


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def clean(value: Any) -> str:
    return str(value or "").strip()


def deep_merge(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = value


def dedupe(items: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
