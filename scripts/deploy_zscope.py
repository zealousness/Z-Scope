#!/usr/bin/env python3
"""Deploy Z-SCOPE into another project.

The script installs the current checkout into a target project's virtual
environment and writes a clean, project-local zscope.yaml.  It deliberately
does not install system tools such as Joern, CodeQL, clangd, Maven, or SVF;
use the explicit build/check flags to prepare repo-local Java runners or to
verify that optional tools are already present.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Sequence
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_TOOL_TIMEOUT_SECONDS = 30
PIP_TRUSTED_HOST_ENV = "PIP_TRUSTED_HOST"


class ToolCheckError(RuntimeError):
    pass


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _quote_yaml(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _rel_to_project(path: Path, project_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(project_root.resolve())) or "."
    except ValueError:
        return str(path.resolve())


def _venv_bin(venv: Path, executable: str) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / f"{executable}.exe"
    return venv / "bin" / executable


def _run(
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    dry_run: bool = False,
    env: dict[str, str] | None = None,
) -> None:
    printable = " ".join(str(part) for part in cmd)
    prefix = f"(cwd={cwd}) " if cwd else ""
    print(f"+ {prefix}{printable}")
    if dry_run:
        return
    subprocess.run(list(cmd), cwd=str(cwd) if cwd else None, env=env, check=True)


def pip_env_with_index_trusted_host(base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base_env) if base_env is not None else os.environ.copy()
    host = pip_index_host(env.get("PIP_INDEX_URL", ""))
    if not host:
        return env
    trusted_hosts = split_trusted_hosts(env.get(PIP_TRUSTED_HOST_ENV, ""))
    if host not in trusted_hosts:
        trusted_hosts.append(host)
    env[PIP_TRUSTED_HOST_ENV] = " ".join(trusted_hosts)
    return env


def pip_index_host(index_url: str) -> str:
    parsed = urlparse(index_url.strip())
    return parsed.hostname or ""


def split_trusted_hosts(value: str) -> list[str]:
    return [part for part in re.split(r"[\s,]+", value.strip()) if part]


def _tool(name: str) -> str:
    return shutil.which(name) or ""


def _split_csv(value: str) -> List[str]:
    return [part.strip().lower().replace("-", "_") for part in value.split(",") if part.strip()]


def _split_csv_raw(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _yaml_list(items: Iterable[str], *, indent: int = 0) -> str:
    prefix = " " * indent
    values = list(items)
    if not values:
        return "[]"
    return "\n".join(f"{prefix}- {item}" for item in values)


def _llm_urls(
    primary_url: str, url_list: str, *, fallback: Sequence[str] | None = None
) -> List[str]:
    urls = _split_csv_raw(url_list)
    if not urls and primary_url:
        urls = [primary_url]
    if not urls and fallback:
        urls = list(fallback)
    return urls or ["https://api.openai.com/v1"]


def _agent_block() -> str:
    return """  agents:
    - name: semantic_modeler
      enabled: true
      llm_ref: default
    - name: vulnerability_analyzer
      enabled: true
      llm_ref: smart_model
      can_spawn_subagents: true
      task: "查找逻辑漏洞、内存安全问题、资源生命周期和并发风险。"
    - name: issue_reconciler_agent
      enabled: true
      llm_ref: default
    - name: validator_agent
      enabled: true
      llm_ref: smart_model
"""


def render_config(args: argparse.Namespace, project_root: Path, source_root: Path) -> str:
    language = args.language
    compile_commands = project_root / "compile_commands.json"
    compile_line = ""
    build_compile_commands = project_root / "build" / "compile_commands.json"
    if compile_commands.exists():
        compile_line = "  compile_commands_path: compile_commands.json\n"
    elif build_compile_commands.exists():
        compile_line = "  compile_commands_path: build/compile_commands.json\n"

    signal_backends = _split_csv(args.enable_java_signals)
    signal_yaml = "[]"
    if signal_backends:
        signal_yaml = "[" + ", ".join(signal_backends) + "]"

    source_root_text = _rel_to_project(source_root, project_root)
    if source_root_text == "":
        source_root_text = "."

    entry_functions_line = ""
    if args.entry_functions_list:
        entry_functions_line = f"  entry_functions_list: {_quote_yaml(args.entry_functions_list)}\n"

    discovery_search_root = ""
    if args.entry_discovery_search_root:
        discovery_root = Path(args.entry_discovery_search_root).expanduser()
        if not discovery_root.is_absolute():
            discovery_root = (project_root / discovery_root).resolve()
        discovery_search_root = f"    search_root: {_quote_yaml(str(discovery_root))}\n"

    default_urls = _llm_urls(args.llm_base_url, args.llm_base_urls)
    smart_urls = _llm_urls(
        args.smart_llm_base_url,
        args.smart_llm_base_urls,
        fallback=default_urls,
    )
    smart_rpm = (
        args.smart_llm_rate_limit_per_minute
        if args.smart_llm_rate_limit_per_minute is not None
        else args.llm_rate_limit_per_minute
    )
    smart_max_concurrent = (
        args.smart_llm_max_concurrent_requests
        if args.smart_llm_max_concurrent_requests is not None
        else args.llm_max_concurrent_requests
    )

    return f"""# Generated by scripts/deploy_zscope.py.
# Use `zscope -c zscope.yaml --language java` or
# `zscope -c zscope.yaml --language c_cpp` to select the audit language.

llms:
  default:
    provider: openai
    base_urls:
{_yaml_list((_quote_yaml(url) for url in default_urls), indent=6)}
    models:
      - {_quote_yaml(args.llm_model)}
    api_key: {_quote_yaml("${" + args.llm_api_key_env + "}")}
    temperature: {args.temperature}
    max_tokens: {args.max_tokens}
    timeout: {args.timeout}
    max_retries: 2
    base_url_rate_limit_per_minute: {args.llm_rate_limit_per_minute}
    base_url_max_concurrent_requests: {args.llm_max_concurrent_requests}
    supports_structured_output: {_bool_text(args.supports_structured_output)}

  smart_model:
    provider: openai
    base_urls:
{_yaml_list((_quote_yaml(url) for url in smart_urls), indent=6)}
    models:
      - {_quote_yaml(args.smart_llm_model or args.llm_model)}
    api_key: {_quote_yaml("${" + (args.smart_llm_api_key_env or args.llm_api_key_env) + "}")}
    temperature: {args.temperature}
    max_tokens: {args.max_tokens}
    timeout: {args.timeout}
    max_retries: 2
    base_url_rate_limit_per_minute: {smart_rpm}
    base_url_max_concurrent_requests: {smart_max_concurrent}
    supports_structured_output: {_bool_text(args.smart_supports_structured_output or args.supports_structured_output)}

project:
  root: {_quote_yaml(str(project_root))}
  source_root: {_quote_yaml(source_root_text)}
  language: {language}
  java_profile: {args.java_profile}
{compile_line}  entry_discovery:
    enabled: {_bool_text(args.discover_entries)}
    max_candidates: {args.max_entries}
    max_functions: {args.max_functions}
    header_files: []
{discovery_search_root}    scan_after_discovery: true
{entry_functions_line}  diff_impact:
    strategy: semantic_obligation
    llm_triage: on_demand
    caller_search_depth_by_intent: {{}}
  include_paths: []
  exclude_paths:
    - .git
    - .venv
    - venv
    - .zscope_venv
    - .zscope_knowledge
    - .zscope_snapshots
    - .zscope_conversations
    - build
    - target
    - node_modules
{_agent_block()}
indexing:
  backend: auto
  joern_language: auto
  joern_path: {_quote_yaml(args.joern_path)}
  joern_server_host: 127.0.0.1
  joern_server_port: 8080
  joern_heap_size: 8g

  clangd_path: {_quote_yaml(args.clangd_path)}
  knowledge_db_path: .zscope_knowledge/code_knowledge.db
  batch_size: 50
  max_clangd_threads: {args.max_clangd_threads}

  svf_bin_dir: {_quote_yaml(args.svf_bin_dir)}
  gclang_path: {_quote_yaml(args.gclang_path)}
  get_bc_path: {_quote_yaml(args.get_bc_path)}
  llvm_link_path: {_quote_yaml(args.llvm_link_path)}
  svf_heap_limit_mb: {args.svf_heap_limit_mb}
  svf_timeout: {args.svf_timeout}
  svf_groups_config: {_quote_yaml(args.svf_groups_config)}
  svf_scope: auto
  svf_entry_depth: 4
  svf_max_selected_tus: 200
  svf_fallback: full
  svf_always_include: []
  svf_symbol_closure: true
  svf_exclusive_pools: []
  svf_shared_pools: []

  java_structure_frontend: auto
  java_structure_extractor_command: []
  java_structure_db_path: .zscope_knowledge/java_structure.db
  java_signal_backends: {signal_yaml}
  java_signal_provider_commands: {{}}

analysis:
  max_recursion_depth: {args.max_recursion_depth}
  max_function_lines: {args.max_function_lines}
  max_tool_iterations: 50
  snapshot_dir: .zscope_snapshots
  enable_snapshot_cache: true
  user_config_db: {_quote_yaml(args.user_config_db)}
  parallel_workers: {args.parallel_workers}
  max_premodel_depth: 3
  max_premodel_callees: 20
  trivial_function_max_lines: 5
  enable_subagent_workers: true
  max_subagent_tickets: {args.max_subagent_tickets}
  subagent_max_turns: 20
  subagent_ticket_timeout: 0
  validation_parallel_workers: 0
  subagent_spawn_allowlist:
    - deep_worker
  subagent_skill_llm_refs: {{}}
  subagent_skill_efforts: {{}}
  tool_audit_log: ""

reporting:
  semantic_dedup:
    enabled: true
    llm_enabled: true
    llm_confidence_threshold: 0.85
    max_cluster_size: 8
"""


def write_config(args: argparse.Namespace, project_root: Path, source_root: Path) -> Path:
    config_path = Path(args.config).expanduser()
    if not config_path.is_absolute():
        config_path = project_root / config_path
    if config_path.exists() and not args.force:
        raise SystemExit(f"Config already exists: {config_path}. Use --force to overwrite it.")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(render_config(args, project_root, source_root), encoding="utf-8")
    print(f"Wrote config: {config_path}")
    return config_path


def create_venv_and_install(args: argparse.Namespace, project_root: Path) -> Path | None:
    if args.no_venv:
        print("Skipping virtualenv creation (--no-venv).")
        return None

    venv = Path(args.venv).expanduser()
    if not venv.is_absolute():
        venv = project_root / venv
    python = _venv_bin(venv, "python")

    if not python.exists():
        _run([args.python, "-m", "venv", str(venv)], dry_run=args.dry_run)
    else:
        print(f"Using existing virtualenv: {venv}")

    pip_env = pip_env_with_index_trusted_host()
    pip_cmd = [str(python), "-m", "pip", "install", "--upgrade", "pip"]
    _run(pip_cmd, dry_run=args.dry_run, env=pip_env)

    install_target = f"{REPO_ROOT}[dev]" if args.with_dev else str(REPO_ROOT)
    if args.editable:
        _run([str(python), "-m", "pip", "install", "-e", install_target], dry_run=args.dry_run, env=pip_env)
    else:
        _run([str(python), "-m", "pip", "install", install_target], dry_run=args.dry_run, env=pip_env)
    return venv


def build_java_tools(args: argparse.Namespace) -> None:
    if args.build_java_structure_tools:
        for rel in ("tools/java-structure-spoon", "tools/java-structure-javaparser"):
            _run(
                ["mvn", "-q", "-DskipTests", "package"],
                cwd=REPO_ROOT / rel,
                dry_run=args.dry_run,
            )
    if args.build_java_signal_tools:
        for rel in ("tools/java-signal-sootup", "tools/java-signal-wala"):
            _run(
                ["mvn", "-q", "-DskipTests", "package"],
                cwd=REPO_ROOT / rel,
                dry_run=args.dry_run,
            )


def check_optional_tools(args: argparse.Namespace) -> None:
    if not args.check_tools:
        return
    svf_bin_dir = Path(args.svf_bin_dir).expanduser() if args.svf_bin_dir else None
    common_checks = {
        "python": [sys.executable, "--version"],
    }
    java_checks = {
        "java": [_tool_or_path("java"), "-version"],
        "mvn": [_tool_or_path("mvn"), "-version"],
        "joern": [_tool_or_path(args.joern_path), "--help"],
        "codeql": [_tool_or_path("codeql"), "version"],
    }
    c_cpp_checks = {
        "clangd": [_tool_or_path(args.clangd_path), "--version"],
        "gclang": [_tool_or_path(args.gclang_path), "--version"],
        "get-bc": [_tool_or_path(args.get_bc_path), "--help"],
        "llvm-link": [_tool_or_path(args.llvm_link_path), "--version"],
        "wpa": [str(svf_bin_dir / "wpa") if svf_bin_dir else _tool_or_path("wpa"), "-h"],
        "saber": [str(svf_bin_dir / "saber") if svf_bin_dir else _tool_or_path("saber"), "-h"],
    }

    groups = [("common", common_checks)]
    if args.language in {"auto", "java"}:
        groups.append(("java", java_checks))
    if args.language in {"auto", "c_cpp"}:
        groups.append(("c_cpp", c_cpp_checks))

    print("\nEnvironment check:")
    failed_by_group: dict[str, list[str]] = {}
    for group_name, checks in groups:
        print(f"\n[{group_name}]")
        for name, cmd in checks.items():
            result = _probe_tool(cmd, timeout=args.check_tools_timeout)
            status = "ok" if result["ok"] else "failed"
            print(f"  [{status}] {name:10s} {' '.join(cmd)}")
            if result["stderr"] and not result["ok"]:
                print(f"    stderr: {result['stderr']}")
            if not result["ok"]:
                failed_by_group.setdefault(group_name, []).append(name)
    failed = [f"{group}.{name}" for group, names in failed_by_group.items() for name in names]
    if args.language == "auto":
        language_groups = [name for name, _ in groups if name in {"java", "c_cpp"}]
        passing_language_groups = [name for name in language_groups if name not in failed_by_group]
        if "common" in failed_by_group or not passing_language_groups:
            raise ToolCheckError(f"tool check failed: {', '.join(failed)}")
        ignored = [
            f"{group}.{name}"
            for group in language_groups
            for name in failed_by_group.get(group, [])
        ]
        if ignored:
            print(
                "\nWarning: ignored failed checks for uninstalled language toolchain: "
                + ", ".join(ignored)
            )
        return
    if failed:
        raise ToolCheckError(f"tool check failed: {', '.join(failed)}")


def _tool_or_path(value: str) -> str:
    path = Path(value).expanduser()
    if path.exists():
        return str(path)
    return shutil.which(value) or value


def _probe_tool(cmd: Sequence[str], *, timeout: int) -> dict[str, object]:
    executable = cmd[0] if cmd else ""
    if not executable or not shutil.which(executable) and not Path(executable).exists():
        return {"ok": False, "returncode": None, "stdout": "", "stderr": f"not found: {executable}"}
    try:
        completed = subprocess.run(
            list(cmd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "returncode": None, "stdout": "", "stderr": str(exc)}
    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "").strip()[:2000],
        "stderr": (completed.stderr or "").strip()[:2000],
    }


def print_next_steps(config_path: Path, venv: Path | None, args: argparse.Namespace) -> None:
    zscope_cmd = str(_venv_bin(venv, "zscope")) if venv else "zscope"
    language_flag = "" if args.language == "auto" else f" --language {args.language}"
    print("\nDeployment complete.")
    print("\nNext commands:")
    print(f"  {zscope_cmd} -c {config_path}{language_flag} --build-cpg --verbose")
    print(f"  {zscope_cmd} -c {config_path}{language_flag} --discover-entries --verbose")
    print(
        f"  {zscope_cmd} -c {config_path} --dashboard --dashboard-host 0.0.0.0 --dashboard-port 8000"
    )
    if args.language == "auto":
        print("\nFor mixed projects, choose one language explicitly:")
        print(f"  {zscope_cmd} -c {config_path} --language java --build-cpg --verbose")
        print(f"  {zscope_cmd} -c {config_path} --language c_cpp --build-cpg --verbose")


def run_smoke_test(config_path: Path, venv: Path | None, args: argparse.Namespace) -> None:
    if not args.smoke_test:
        return
    zscope_cmd = str(_venv_bin(venv, "zscope")) if venv else "zscope"
    cmd = [zscope_cmd, "-c", str(config_path), "--build-cpg", "--verbose"]
    if args.language != "auto":
        cmd.extend(["--language", args.language])
    _run(cmd, dry_run=args.dry_run)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy Z-SCOPE into a target project and generate zscope.yaml."
    )
    parser.add_argument("--project-root", default=".", help="Target project root.")
    parser.add_argument("--source-root", default=".", help="Source root relative to project root.")
    parser.add_argument("--config", default="zscope.yaml", help="Output config path.")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing config file.")

    parser.add_argument(
        "--language",
        choices=("auto", "java", "c_cpp"),
        default="auto",
        help="Default project language in the generated config.",
    )
    parser.add_argument("--discover-entries", action="store_true", default=True)
    parser.add_argument("--no-discover-entries", dest="discover_entries", action="store_false")
    parser.add_argument("--max-entries", type=int, default=200)
    parser.add_argument("--max-functions", type=int, default=10000)

    parser.add_argument("--python", default=sys.executable, help="Python used to create the venv.")
    parser.add_argument(
        "--venv", default=".zscope_venv", help="Virtualenv path inside the target project."
    )
    parser.add_argument(
        "--no-venv", action="store_true", help="Do not create or update a virtualenv."
    )
    parser.add_argument(
        "--editable", action="store_true", default=True, help="Install Z-SCOPE editable."
    )
    parser.add_argument("--no-editable", dest="editable", action="store_false")
    parser.add_argument("--with-dev", action="store_true", help="Install Z-SCOPE dev extras.")

    parser.add_argument("--llm-base-url", default="http://127.0.0.1:11434/v1")
    parser.add_argument("--llm-model", default="qwen3:latest")
    parser.add_argument("--llm-api-key-env", default="Z_SCOPE_API_KEY")
    parser.add_argument("--smart-llm-base-url", default="")
    parser.add_argument(
        "--llm-base-urls",
        default="",
        help="Comma-separated endpoint pool for the default model. Overrides --llm-base-url.",
    )
    parser.add_argument(
        "--smart-llm-base-urls",
        default="",
        help="Comma-separated endpoint pool for the smart model.",
    )
    parser.add_argument("--smart-llm-model", default="")
    parser.add_argument("--smart-llm-api-key-env", default="")
    parser.add_argument("--llm-rate-limit-per-minute", type=int, default=0)
    parser.add_argument("--llm-max-concurrent-requests", type=int, default=0)
    parser.add_argument("--smart-llm-rate-limit-per-minute", type=int, default=None)
    parser.add_argument("--smart-llm-max-concurrent-requests", type=int, default=None)
    parser.add_argument("--supports-structured-output", action="store_true")
    parser.add_argument("--smart-supports-structured-output", action="store_true")
    parser.add_argument("--temperature", default="0.1")
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--timeout", type=int, default=180)

    parser.add_argument(
        "--java-profile",
        choices=("auto", "web", "cli", "library", "batch", "messaging", "middleware"),
        default="auto",
        help="Java project profile hint written to project.java_profile.",
    )
    parser.add_argument(
        "--entry-functions-list",
        default="",
        help="Optional batch entry JSON path, relative to the target project root.",
    )
    parser.add_argument(
        "--entry-discovery-search-root",
        default="",
        help="Optional entry discovery root. Relative paths are resolved under --project-root.",
    )
    parser.add_argument("--clangd-path", default="clangd")
    parser.add_argument("--max-clangd-threads", type=int, default=8)
    parser.add_argument("--joern-path", default="joern")
    parser.add_argument("--svf-bin-dir", default="")
    parser.add_argument("--gclang-path", default="gclang")
    parser.add_argument("--get-bc-path", default="get-bc")
    parser.add_argument("--llvm-link-path", default="llvm-link")
    parser.add_argument("--svf-groups-config", default="")
    parser.add_argument("--svf-heap-limit-mb", type=int, default=32768)
    parser.add_argument("--svf-timeout", type=int, default=1800)

    parser.add_argument(
        "--enable-java-signals",
        default="",
        help="Comma-separated Java signal providers: sootup,wala,codeql,joern.",
    )
    parser.add_argument("--build-java-structure-tools", action="store_true")
    parser.add_argument("--build-java-signal-tools", action="store_true")
    parser.add_argument("--check-tools", action="store_true")
    parser.add_argument("--check-tools-timeout", type=int, default=CHECK_TOOL_TIMEOUT_SECONDS)

    parser.add_argument("--parallel-workers", type=int, default=5)
    parser.add_argument("--max-recursion-depth", type=int, default=3)
    parser.add_argument("--max-function-lines", type=int, default=500)
    parser.add_argument("--max-subagent-tickets", type=int, default=4)
    parser.add_argument(
        "--user-config-db",
        default="",
        help="Optional user_config.xlsx path or directory. Empty uses snapshot_dir defaults.",
    )

    parser.add_argument(
        "--smoke-test", action="store_true", help="Run zscope --build-cpg after deployment."
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print commands without executing them."
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    project_root = Path(args.project_root).expanduser().resolve()
    source_root = Path(args.source_root).expanduser()
    if not source_root.is_absolute():
        source_root = (project_root / source_root).resolve()

    if not project_root.is_dir():
        raise SystemExit(f"Project root is not a directory: {project_root}")
    if not source_root.is_dir():
        raise SystemExit(f"Source root is not a directory: {source_root}")

    config_path = write_config(args, project_root, source_root)
    venv = create_venv_and_install(args, project_root)
    build_java_tools(args)
    try:
        check_optional_tools(args)
    except ToolCheckError as exc:
        raise SystemExit(str(exc)) from exc
    run_smoke_test(config_path, venv, args)
    print_next_steps(config_path, venv, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
