#!/usr/bin/env python3
"""Prepare and score external C/C++ benchmark subsets for Z-SCOPE.

The script keeps raw benchmark corpora out of the repository. It creates a small
Z-SCOPE-compatible project layout for each benchmark subset:

  <suite-root>/
    project/
    benchmark/entries.json
    benchmark/ground_truth.json
    project/zscope.benchmark.yaml

It can also run the local regex/graph candidate layer as a cheap first
signal before a full LLM-backed Z-SCOPE scan.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency in lightweight use
    yaml = None

from zscope.benchmarking.protocol import (
    BENCHMARK_CONDITIONS,
    CONDITION_CANDIDATES,
    CONDITION_FULL_ZSCOPE,
    CONDITION_PURE_LLM_ENTRY,
    CONDITION_PURE_LLM_REPO,
    DEFAULT_BOOTSTRAP_SAMPLES,
    MIN_RELEASE_TRIALS,
    RUN_KINDS,
    aggregate_trial_summaries,
    build_benchmark_artifact_manifest,
    build_trial_summary,
    collect_environment_metadata,
    copy_conversation_trajectory,
    json_dump as benchmark_json_dump,
    load_summaries,
    score_report,
    score_report_views,
    sha256_file,
    sha256_payload,
)
from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    RootlessOciExecutor,
    oci_capability,
    require_release_isolation,
)
from zscope.benchmarking.policy import DEFAULT_BENCHMARK_POLICY
from zscope.benchmarking.replay_bundle import (
    REPLAY_BUNDLE_SCHEMA_VERSION,
    ReplayBundleError,
    write_validator_replay_bundle,
)


FUNC_DEF_RE = re.compile(
    r"(?m)^[A-Za-z_~][\w\s\*\&:<>,~\(\)]*\b([A-Za-z_~]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{"
)
MAIN_DEF_RE = re.compile(r"(?m)^(\s*(?:int|void)\s+)main\s*\(")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
DEFAULT_MEMORY_CWES = [
    "CWE121",
    "CWE122",
    "CWE124",
    "CWE126",
    "CWE127",
    "CWE190",
    "CWE191",
    "CWE195",
    "CWE401",
    "CWE415",
    "CWE416",
    "CWE457",
    "CWE476",
    "CWE562",
    "CWE590",
    "CWE680",
    "CWE761",
    "CWE762",
    "CWE789",
]

CWE_CATEGORY = {
    "CWE-121": "stack_overflow",
    "CWE-122": "bounds",
    "CWE-124": "bounds",
    "CWE-126": "bounds",
    "CWE-127": "bounds",
    "CWE-190": "integer_overflow",
    "CWE-191": "integer_overflow",
    "CWE-195": "signed_unsigned",
    "CWE-401": "memory_leak",
    "CWE-415": "double_free",
    "CWE-416": "use_after_free",
    "CWE-457": "uninitialized_read",
    "CWE-476": "null_pointer_dereference",
    "CWE-562": "stack_escape",
    "CWE-590": "invalid_free",
    "CWE-680": "integer_overflow",
    "CWE-761": "invalid_free",
    "CWE-762": "invalid_free",
    "CWE-789": "stack_overflow",
}

FalsePositiveClassifier = Callable[[dict[str, Any]], dict[str, Any]]
RANGE_BENCHMARK_NAMES = {"zscope-range-service-runtime"}
_OCI_EXECUTOR_FACTORY = RootlessOciExecutor
_FORMAL_ANSWER_FREE_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".pytest_cache",
        ".zscope_knowledge",
        ".zscope_snapshots",
        "__pycache__",
        "benchmark",
        "benchmark-artifacts",
        "build",
        "runs",
    }
)
_FORMAL_ANSWER_KEYS = frozenset(
    {
        "cwe",
        "cwes",
        "category",
        "expected_label",
        "expected_verdict",
        "ground_truth",
        "is_vulnerable",
        "keywords",
        "label",
        "oracle",
        "property",
        "safe",
        "truth_id",
        "truth_ids",
        "verdict",
        "vulnerable",
    }
)

CATEGORY_ALIASES = {
    "memory_safety": [
        "memory safety",
        "bounds",
        "buffer",
        "overflow",
        "leak",
        "use after free",
        "double free",
        "invalid free",
        "null pointer",
        "uninitialized",
    ],
    "integer_overflow": ["integer overflow", "overflow", "wrap", "cwe-190", "cwe-191", "cwe-680"],
    "bounds": [
        "bounds",
        "out of bounds",
        "buffer overflow",
        "overread",
        "overread",
        "cwe-125",
        "cwe-787",
    ],
    "memory_leak": ["memory leak", "resource leak", "leak", "cwe-401"],
    "double_free": ["double free", "cwe-415"],
    "use_after_free": ["use after free", "use-after-free", "uaf", "dangling", "cwe-416"],
    "invalid_free": [
        "invalid free",
        "double free",
        "use after free",
        "use-after-free",
        "free memory not on heap",
        "non-heap",
        "cwe-415",
        "cwe-416",
        "cwe-590",
        "cwe-761",
        "cwe-762",
    ],
    "null_pointer_dereference": ["null pointer", "null dereference", "cwe-476"],
    "signed_unsigned": ["signed", "unsigned", "negative", "cwe-195"],
    "stack_escape": ["stack escape", "stack address", "cwe-562"],
    "stack_overflow": ["stack overflow", "stack buffer", "vla", "cwe-121"],
    "uninitialized_read": ["uninitialized", "padding", "cwe-457"],
    "data_race": ["data race", "race", "cwe-362"],
}


@dataclass
class FunctionInfo:
    name: str
    file: str
    line: int
    end_line: int


def _json_dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _limit(value: int) -> int | None:
    return None if value <= 0 else value


def _load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            env[key] = value
    return env


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _safe_reset_dir(path: Path, workspace_root: Path) -> None:
    path = path.resolve()
    workspace_root = workspace_root.resolve()
    if path.exists():
        if workspace_root not in path.parents and path != workspace_root:
            raise SystemExit(f"Refusing to delete outside workspace: {path}")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _scan_source_destination(
    project_dir: Path, suite_subdir: str, source_root: Path, src: Path
) -> Path:
    dst = project_dir / "src" / suite_subdir / src.relative_to(source_root)
    if dst.suffix == ".i":
        dst = dst.with_suffix(".c")
    return dst


def _clean_id(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_")


def _cwe_from_text(text: str) -> str:
    match = re.search(r"CWE[-_]?(\d+)", text, flags=re.IGNORECASE)
    if not match:
        return ""
    return f"CWE-{match.group(1)}"


def _category_for_cwe(cwe: str) -> str:
    return CWE_CATEGORY.get(cwe, "memory_safety")


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    if value is None:
        return ""
    return str(value)


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text)


def extract_functions(path: Path, rel_file: str) -> list[FunctionInfo]:
    text = _read(path)
    functions: list[FunctionInfo] = []
    for match in FUNC_DEF_RE.finditer(text):
        open_idx = text.find("{", match.end() - 1)
        if open_idx < 0:
            continue
        end_idx = _find_matching_brace(text, open_idx)
        functions.append(
            FunctionInfo(
                name=match.group(1),
                file=rel_file.replace("\\", "/"),
                line=text[: match.start()].count("\n") + 1,
                end_line=text[:end_idx].count("\n") + 1,
            )
        )
    return functions


def extract_function_code(path: Path, function_name: str) -> tuple[str, FunctionInfo] | None:
    text = _read(path)
    for match in FUNC_DEF_RE.finditer(text):
        name = match.group(1)
        if name != function_name:
            continue
        open_idx = text.find("{", match.end() - 1)
        if open_idx < 0:
            continue
        end_idx = _find_matching_brace(text, open_idx)
        start_line = text[: match.start()].count("\n") + 1
        end_line = text[:end_idx].count("\n") + 1
        source_lines = text[match.start() : end_idx + 1].splitlines()
        numbered = "\n".join(
            f"{start_line + offset:5d} | {line}" for offset, line in enumerate(source_lines)
        )
        return (
            numbered,
            FunctionInfo(
                name=name,
                file=str(path).replace("\\", "/"),
                line=start_line,
                end_line=end_line,
            ),
        )
    return None


def _function_source_blocks(text: str, names: set[str] | None = None) -> dict[str, str]:
    blocks: dict[str, str] = {}
    for match in FUNC_DEF_RE.finditer(text):
        name = match.group(1)
        if names is not None and name not in names:
            continue
        open_idx = text.find("{", match.end() - 1)
        if open_idx < 0:
            continue
        end_idx = _find_matching_brace(text, open_idx)
        blocks[name] = text[match.start() : end_idx + 1].strip() + "\n"
    return blocks


def _brace_on_signature_line(block: str) -> str:
    lines = block.splitlines()
    if len(lines) >= 2 and lines[1].strip() == "{" and lines[0].rstrip().endswith(")"):
        lines = [lines[0].rstrip() + " {"] + lines[2:]
    return "\n".join(lines).rstrip() + "\n"


def _write_function_projection(src: Path, dst: Path, names: set[str]) -> None:
    blocks = _function_source_blocks(_read(src), names)
    if not blocks:
        _copy_file(src, dst)
        return
    prelude = "\n".join(
        [
            "#include <stddef.h>",
            "#include <stdint.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <stdio.h>",
            "",
            "extern int globalReturnsTrue(void);",
            "extern int globalReturnsFalse(void);",
            "extern void printLine(const char *line);",
            "",
        ]
    )
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        prelude + "\n\n".join(_brace_on_signature_line(blocks[name]) for name in sorted(blocks)),
        encoding="utf-8",
    )


def _function_at_line(functions: list[FunctionInfo], line: int | None) -> FunctionInfo | None:
    if line is not None:
        for info in functions:
            if info.line <= line <= info.end_line:
                return info
    return functions[0] if functions else None


def _write_compile_commands(project_dir: Path, source_files: Iterable[Path]) -> None:
    commands = []
    include_dir = project_dir / "include"
    for source in sorted(source_files):
        commands.append(
            {
                "directory": project_dir.as_posix(),
                "command": f"clang -I{include_dir.as_posix()} -c {source.as_posix()} -o /tmp/zscope_external.o",
                "file": source.as_posix(),
            }
        )
    _json_dump(project_dir / "compile_commands.json", {"commands": commands})
    # compile_commands.json is conventionally a JSON array; rewrite after using
    # the shared helper for parent creation.
    (project_dir / "compile_commands.json").write_text(
        json.dumps(commands, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_zscope_config(suite_root: Path, *, title: str, backend: str = "regex") -> None:
    project = (suite_root / "project").resolve()
    svf_block = ""
    if backend == "unified":
        svf_block = """  svf:
    scope: auto
    entry_depth: 4
    max_selected_tus: 200
    fallback: full
    always_include: []
    exclusive_pools: []
    shared_pools: []
    heap_limit_mb: 32768
    timeout_seconds: 1800
"""
    config = f"""# Generated by scripts/external_benchmark.py for {title}.
config_version: 3

llms:
  default:
    base_urls: ["${{Z_SCOPE_BASE_URL}}"]
    models: ["${{Z_SCOPE_MODEL}}"]
    api_key: "${{Z_SCOPE_API_KEY}}"
    max_tokens: 8192
    max_retries: 2
    timeout: 120
  smart_model:
    base_urls: ["${{Z_SCOPE_BASE_URL}}"]
    models: ["${{Z_SCOPE_MODEL}}"]
    api_key: "${{Z_SCOPE_API_KEY}}"
    max_tokens: 8192
    max_retries: 2
    timeout: 120

project:
  language: c_cpp
  entry_functions_list: "../benchmark/entries.json"
  targets:
    - id: main
      compile_commands: "compile_commands.json"
  semantics_file: zscope.semantics.yaml
  include_paths:
    - include
    - src
  exclude_paths:
    - .zscope_knowledge
    - .zscope_snapshots
    - benchmark
  entry_discovery:
    enabled: false
    search_root: .
    interface_files: ["include/**/*.h"]
    max_entries: 200
    max_functions: 10000

scan:
  task: >-
    Audit this external benchmark subset for C/C++ memory safety,
    resource lifecycle, integer/bounds, null/failure, and concurrency
    defects. Use only source evidence, call paths, and local project
    semantics. Do not rely on benchmark answer-key files.
  llm_profiles:
    modeling: default
    analysis: smart_model
    validation: smart_model

indexing:
  backend: {backend}
{svf_block}  tools:
    clangd: clangd

concurrency:
  entry_workers: 8
  validator_workers: 4
  investigator_workers: 2
  evidence_completion_workers: 2
  index_workers: 4
  svf_workers: 4
  llm_max_inflight: 8
"""
    (project / "zscope.benchmark.yaml").write_text(config, encoding="utf-8")
    from zscope.config.project_semantics import render_empty_project_semantics

    semantics = project / "zscope.semantics.yaml"
    if not semantics.exists():
        semantics.write_text(render_empty_project_semantics(), encoding="utf-8")


def prepare_juliet(args: argparse.Namespace) -> dict[str, Any]:
    source = Path(args.source).resolve()
    workspace = Path(args.workspace).resolve()
    suite_root = workspace / args.name
    project_dir = suite_root / "project"
    benchmark_dir = suite_root / "benchmark"
    _safe_reset_dir(suite_root, workspace)
    (project_dir / "src").mkdir(parents=True, exist_ok=True)
    (project_dir / "include").mkdir(parents=True, exist_ok=True)

    all_cwes = any(str(cwe).upper() == "ALL" for cwe in args.cwes)
    cwe_prefixes = [] if all_cwes else [str(cwe).replace("-", "").upper() for cwe in args.cwes]
    source_files = []
    for ext in ("*.c", "*.cpp", "*.cc", "*.i"):
        source_files.extend(source.rglob(ext))
    buckets: dict[str, list[Path]] = (
        {"ALL": []} if all_cwes else {prefix: [] for prefix in cwe_prefixes}
    )
    for path in sorted(source_files):
        rel = path.relative_to(source).as_posix()
        rel_key = rel.upper().replace("-", "")
        matched_prefix = (
            "ALL"
            if all_cwes and "CWE" in rel_key
            else next(
                (prefix for prefix in cwe_prefixes if prefix in rel_key),
                "",
            )
        )
        if not matched_prefix:
            continue
        if args.flow_variants:
            stem = path.stem
            variant_match = re.search(r"_(\d\d)(?:_|$)", stem)
            variant = variant_match.group(1) if variant_match else stem.rsplit("_", 1)[-1]
            if variant not in args.flow_variants:
                continue
        buckets[matched_prefix].append(path)

    selected: list[Path] = []
    cap = _limit(args.max_cases)
    while cap is None or len(selected) < cap:
        grew = False
        for prefix in buckets:
            if buckets[prefix]:
                selected.append(buckets[prefix].pop(0))
                grew = True
                if cap is not None and len(selected) >= cap:
                    break
        if not grew:
            break

    if not selected:
        raise SystemExit(f"No Juliet files matched {args.cwes} under {source}")

    support_dirs = [p for p in source.rglob("testcasesupport") if p.is_dir()]
    if support_dirs:
        support = support_dirs[0]
        for item in support.rglob("*"):
            if item.is_file() and item.suffix.lower() in {".h", ".c", ".cpp"}:
                _copy_file(item, project_dir / "include" / item.relative_to(support))

    entries: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    safe_entries: list[dict[str, Any]] = []
    copied_sources: list[Path] = []

    for src in selected:
        cwe = _cwe_from_text(src.as_posix())
        category = _category_for_cwe(cwe)
        dst = _scan_source_destination(project_dir, "juliet", source, src)
        source_functions = extract_functions(src, src.relative_to(source).as_posix())
        target_names = {
            info.name
            for info in source_functions
            if "_bad" in info.name
            or info.name.endswith("bad")
            or "_good" in info.name
            or info.name.endswith("good")
        }
        if src.suffix == ".i":
            _write_function_projection(src, dst, target_names)
        else:
            _copy_file(src, dst)
        copied_sources.append(dst)
        rel_dst = dst.relative_to(project_dir).as_posix()
        functions = extract_functions(dst, rel_dst)
        for info in functions:
            if "_bad" in info.name or info.name.endswith("bad"):
                entries.append({"function_name": info.name, "file_path": info.file})
                vulnerabilities.append(
                    {
                        "id": f"JULIET-{_clean_id(info.name)}",
                        "suite": "juliet",
                        "file": info.file,
                        "line": info.line,
                        "end_line": info.end_line,
                        "function": info.name,
                        "category": category,
                        "cwe": cwe,
                        "keywords": [category.replace("_", " "), cwe],
                    }
                )
            elif "_good" in info.name or info.name.endswith("good"):
                entries.append({"function_name": info.name, "file_path": info.file})
                safe_entries.append({"function": info.name, "file": info.file})

    _write_compile_commands(project_dir, copied_sources)
    _json_dump(benchmark_dir / "entries.json", {"functions": entries})
    truth = {
        "benchmark": args.name,
        "suite": "juliet",
        "source": str(source),
        "selected_files": [p.relative_to(source).as_posix() for p in selected],
        "vulnerabilities": vulnerabilities,
        "safe_entries": safe_entries,
    }
    _json_dump(benchmark_dir / "ground_truth.json", truth)
    _write_zscope_config(suite_root, title=args.name, backend=args.backend)
    manifest = {
        "suite_root": suite_root.as_posix(),
        "suite": "juliet",
        "selected_files": len(selected),
        "complete": cap is None,
        "entries": len(entries),
        "ground_truth": len(vulnerabilities),
        "safe_entries": len(safe_entries),
    }
    _json_dump(benchmark_dir / "manifest.json", manifest)
    return manifest


def _load_yaml_like(path: Path) -> dict[str, Any]:
    text = _read(path)
    if yaml is not None:
        loaded = yaml.safe_load(text)
        return loaded if isinstance(loaded, dict) else {}
    data: dict[str, Any] = {}
    verdict = re.search(r"expected_verdict:\s*(true|false)", text)
    if verdict:
        data["expected_verdict"] = verdict.group(1) == "true"
    props = re.findall(r"property_file:\s*([^\s]+)", text)
    if props:
        data["properties"] = [{"property_file": prop} for prop in props]
    inputs = re.findall(r"input_files:\s*([^\n]+)", text)
    if inputs:
        data["input_files"] = [item.strip(" []'\"") for item in inputs[0].split(",")]
    return data


def _sv_expected_false(path: Path, data: dict[str, Any]) -> bool:
    def contains_false(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                key == "expected_verdict" and item is False or contains_false(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(contains_false(item) for item in value)
        return False

    if contains_false(data):
        return True
    verdict = data.get("expected_verdict")
    if isinstance(verdict, bool):
        return verdict is False
    return "_false-" in path.name or path.name.endswith("_false.yml")


def _sv_property(data: dict[str, Any], path: Path) -> str:
    text = json.dumps(data, ensure_ascii=False).lower() + " " + path.name.lower()
    if "data-race" in text:
        return "data_race"
    if "valid-memtrack" in text:
        return "memory_leak"
    if "valid-free" in text:
        return "invalid_free"
    if "valid-deref" in text or "valid-memsafety" in text:
        return "memory_safety"
    if "no-overflow" in text:
        return "integer_overflow"
    return "memory_safety"


def _sv_input_files(yml_path: Path, data: dict[str, Any]) -> list[Path]:
    raw = data.get("input_files")
    inputs: list[str] = []
    if isinstance(raw, str):
        inputs = [raw]
    elif isinstance(raw, list):
        inputs = [str(x) for x in raw]
    if not inputs:
        for suffix in (".c", ".i"):
            candidate = yml_path.with_suffix(suffix)
            if candidate.exists():
                inputs = [candidate.name]
                break
    resolved = []
    for item in inputs:
        candidate = (yml_path.parent / item).resolve()
        if candidate.exists() and candidate.is_file():
            resolved.append(candidate)
    return resolved


def _load_svcomp_set_patterns(source: Path, set_files: Iterable[str]) -> list[str]:
    patterns: list[str] = []
    seen: set[Path] = set()
    stack = [Path(item) for item in set_files if str(item).strip()]
    while stack:
        item = stack.pop(0)
        path = item if item.is_absolute() else source / item
        path = path.resolve()
        if path in seen:
            continue
        seen.add(path)
        if not path.exists():
            raise SystemExit(f"SV-COMP set file not found: {path}")
        for raw in _read(path).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith(".set"):
                stack.append(Path(line))
            else:
                patterns.append(line)
    return patterns


def _matches_svcomp_patterns(rel: str, patterns: list[str]) -> bool:
    if not patterns:
        return True
    rel_path = Path(rel)
    return any(rel_path.match(pattern) for pattern in patterns)


def _rename_main(text: str, unique: str) -> tuple[str, bool]:
    replaced, count = MAIN_DEF_RE.subn(rf"\1{unique}(", text, count=1)
    return replaced, count > 0


def prepare_svcomp(args: argparse.Namespace) -> dict[str, Any]:
    source = Path(args.source).resolve()
    workspace = Path(args.workspace).resolve()
    suite_root = workspace / args.name
    project_dir = suite_root / "project"
    benchmark_dir = suite_root / "benchmark"
    _safe_reset_dir(suite_root, workspace)
    (project_dir / "src" / "svcomp").mkdir(parents=True, exist_ok=True)
    (project_dir / "include").mkdir(parents=True, exist_ok=True)

    set_patterns = _load_svcomp_set_patterns(source, args.set_files)
    yml_files = sorted(source.rglob("*.yml"))
    selected: list[tuple[Path, dict[str, Any], list[Path]]] = []
    property_terms = [term.lower() for term in args.properties]
    for yml_path in yml_files:
        rel_yml = yml_path.relative_to(source).as_posix()
        if not _matches_svcomp_patterns(rel_yml, set_patterns):
            continue
        text = _read(yml_path).lower() + " " + yml_path.name.lower()
        if property_terms and not any(term in text for term in property_terms):
            continue
        data = _load_yaml_like(yml_path)
        inputs = _sv_input_files(yml_path, data)
        if len(inputs) != 1:
            continue
        selected.append((yml_path, data, inputs))
        cap = _limit(args.max_cases)
        if cap is not None and len(selected) >= cap:
            break

    if not selected:
        raise SystemExit(f"No SV-COMP tasks matched {args.properties} under {source}")

    entries: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    safe_entries: list[dict[str, Any]] = []
    copied_sources: list[Path] = []
    selected_tasks: list[str] = []

    for idx, (yml_path, data, inputs) in enumerate(selected, start=1):
        src = inputs[0]
        unique = f"svcomp_{idx:04d}_main"
        rel_source = src.relative_to(source).as_posix()
        dst = _scan_source_destination(project_dir, "svcomp", source, src)
        text, renamed = _rename_main(_read(src), unique)
        if not renamed:
            unique = src.stem
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.suffix == ".i":
            blocks = _function_source_blocks(text, {unique})
            if blocks:
                dst.write_text(_brace_on_signature_line(blocks[unique]), encoding="utf-8")
            else:
                dst.write_text(text, encoding="utf-8")
        else:
            dst.write_text(text, encoding="utf-8")
        copied_sources.append(dst)
        selected_tasks.append(yml_path.relative_to(source).as_posix())
        rel_dst = dst.relative_to(project_dir).as_posix()
        entry = {"function_name": unique, "file_path": rel_dst}
        entries.append(entry)
        category = _sv_property(data, yml_path)
        if _sv_expected_false(yml_path, data):
            vulnerabilities.append(
                {
                    "id": f"SVCOMP-{_clean_id(yml_path.stem)}",
                    "suite": "svcomp",
                    "file": rel_dst,
                    "line": None,
                    "function": unique,
                    "category": category,
                    "cwe": "",
                    "keywords": [category.replace("_", " "), yml_path.name],
                    "property": category,
                }
            )
        else:
            safe_entries.append({"function": unique, "file": rel_dst, "property": category})

    _write_compile_commands(project_dir, copied_sources)
    _json_dump(benchmark_dir / "entries.json", {"functions": entries})
    truth = {
        "benchmark": args.name,
        "suite": "svcomp",
        "source": str(source),
        "set_files": list(args.set_files),
        "set_patterns": set_patterns,
        "properties": list(args.properties),
        "selected_tasks": selected_tasks,
        "vulnerabilities": vulnerabilities,
        "safe_entries": safe_entries,
    }
    _json_dump(benchmark_dir / "ground_truth.json", truth)
    _write_zscope_config(suite_root, title=args.name, backend=args.backend)
    manifest = {
        "suite_root": suite_root.as_posix(),
        "suite": "svcomp",
        "set_files": list(args.set_files),
        "properties": list(args.properties),
        "selected_tasks": len(selected),
        "complete": _limit(args.max_cases) is None,
        "entries": len(entries),
        "ground_truth": len(vulnerabilities),
        "safe_entries": len(safe_entries),
    }
    _json_dump(benchmark_dir / "manifest.json", manifest)
    return manifest


def _patch_changed_files(patch: Path) -> list[str]:
    files: list[str] = []
    for line in _read(patch).splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                path = parts[2][2:] if parts[2].startswith("a/") else parts[2]
                if path not in files:
                    files.append(path)
    return files


def _first_patch_new_line(patch: Path) -> int | None:
    for line in _read(patch).splitlines():
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            if match:
                return int(match.group(1))
    return None


def _patch_changed_file_lines(patch: Path) -> dict[str, int | None]:
    lines: dict[str, int | None] = {}
    current = ""
    for line in _read(patch).splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            current = ""
            if len(parts) >= 4:
                current = parts[2][2:] if parts[2].startswith("a/") else parts[2]
                lines.setdefault(current, None)
        elif current and line.startswith("@@") and lines.get(current) is None:
            match = re.search(r"\+(\d+)", line)
            if match:
                lines[current] = int(match.group(1))
    return lines


def _source_suffix_supported(path: Path) -> bool:
    suffixes = "".join(path.suffixes).lower()
    return path.suffix.lower() in {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".hh",
    } or suffixes.endswith(".c.in")


def _copy_full_target_source(src_root: Path, dst_root: Path) -> list[Path]:
    copied: list[Path] = []
    for src in src_root.rglob("*"):
        try:
            is_file = src.is_file()
        except OSError:
            continue
        if not is_file or ".git" in src.parts:
            continue
        rel = src.relative_to(src_root)
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dst)
        except OSError:
            continue
        if _source_suffix_supported(dst):
            copied.append(dst)
    return copied


def prepare_magma(args: argparse.Namespace) -> dict[str, Any]:
    magma_root = Path(args.magma_root).resolve()
    workspace = Path(args.workspace).resolve()
    suite_root = workspace / args.name
    project_dir = suite_root / "project"
    benchmark_dir = suite_root / "benchmark"
    _safe_reset_dir(suite_root, workspace)
    (project_dir / "src" / "magma" / args.target).mkdir(parents=True, exist_ok=True)
    (project_dir / "include").mkdir(parents=True, exist_ok=True)

    bug_dir = magma_root / "targets" / args.target / "patches" / "bugs"
    bug_cap = _limit(args.max_bugs)
    patches = sorted(bug_dir.glob("*.patch"))
    if bug_cap is not None:
        patches = patches[:bug_cap]
    if not patches:
        raise SystemExit(f"No Magma bug patches found: {bug_dir}")

    target_source = Path(args.target_source).resolve() if args.target_source else None
    entries: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    copied_sources: list[Path] = []
    selected_bugs: list[dict[str, Any]] = []
    target_project_root = project_dir / "src" / "magma" / args.target

    if target_source and target_source.exists():
        if args.copy_full_source:
            copied_sources = _copy_full_target_source(target_source, target_project_root)
        for patch in patches:
            changed = _patch_changed_files(patch)
            changed_lines = _patch_changed_file_lines(patch)
            for rel in changed:
                src = target_source / rel
                if not src.exists() or not _source_suffix_supported(src):
                    continue
                line = changed_lines.get(rel) or _first_patch_new_line(patch)
                dst = target_project_root / rel
                if not args.copy_full_source:
                    _copy_file(src, dst)
                    if dst not in copied_sources:
                        copied_sources.append(dst)
                rel_dst = dst.relative_to(project_dir).as_posix()
                functions = extract_functions(dst, rel_dst)
                info = _function_at_line(functions, line)
                if not info:
                    continue
                entries.append({"function_name": info.name, "file_path": info.file})
                vulnerabilities.append(
                    {
                        "id": f"MAGMA-{patch.stem}",
                        "suite": "magma",
                        "target": args.target,
                        "file": info.file,
                        "line": line or info.line,
                        "end_line": info.end_line,
                        "function": info.name,
                        "category": "memory_safety",
                        "cwe": "",
                        "keywords": ["memory safety", patch.stem],
                        "patch": patch.relative_to(magma_root).as_posix(),
                    }
                )
                break
            selected_bugs.append(
                {
                    "bug": patch.stem,
                    "patch": patch.relative_to(magma_root).as_posix(),
                    "changed_files": changed,
                    "first_new_line": _first_patch_new_line(patch),
                }
            )
    else:
        selected_bugs = [
            {
                "bug": patch.stem,
                "patch": patch.relative_to(magma_root).as_posix(),
                "changed_files": _patch_changed_files(patch),
                "first_new_line": _first_patch_new_line(patch),
            }
            for patch in patches
        ]

    _write_compile_commands(project_dir, copied_sources)
    _json_dump(benchmark_dir / "entries.json", {"functions": entries})
    truth = {
        "benchmark": args.name,
        "suite": "magma",
        "source": str(magma_root),
        "target": args.target,
        "target_source": str(target_source) if target_source else "",
        "materialized": bool(target_source and target_source.exists()),
        "copy_full_source": bool(args.copy_full_source),
        "selected_bugs": selected_bugs,
        "vulnerabilities": vulnerabilities,
        "safe_entries": [],
    }
    _json_dump(benchmark_dir / "ground_truth.json", truth)
    _write_zscope_config(suite_root, title=args.name, backend=args.backend)
    manifest = {
        "suite_root": suite_root.as_posix(),
        "suite": "magma",
        "target": args.target,
        "materialized": bool(target_source and target_source.exists()),
        "copy_full_source": bool(args.copy_full_source),
        "complete": bug_cap is None,
        "selected_bugs": len(selected_bugs),
        "entries": len(entries),
        "ground_truth": len(vulnerabilities),
        "project_source_files": len(copied_sources),
    }
    _json_dump(benchmark_dir / "manifest.json", manifest)
    return manifest


def _load_entries(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("functions", [])
    return [x for x in entries if isinstance(x, dict)]


def _suite_project_dir(suite_root: Path) -> Path:
    nested = suite_root / "project"
    return nested if nested.exists() else suite_root


def _suite_config_metadata(suite_root: Path, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = env or os.environ
    config_path = _suite_project_dir(suite_root) / "zscope.benchmark.yaml"
    metadata: dict[str, Any] = {
        "backend": "",
        "model": env.get("Z_SCOPE_MODEL", ""),
        "prompt_autofill": {},
    }
    if not config_path.exists() or yaml is None:
        return metadata
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return metadata
    if not isinstance(config, dict):
        return metadata
    indexing = config.get("indexing") if isinstance(config.get("indexing"), dict) else {}
    project = config.get("project") if isinstance(config.get("project"), dict) else {}
    metadata["backend"] = str(indexing.get("backend") or "")
    prompt_autofill = (
        project.get("prompt_autofill") if isinstance(project.get("prompt_autofill"), dict) else {}
    )
    metadata["prompt_autofill"] = prompt_autofill
    llms = config.get("llms") if isinstance(config.get("llms"), dict) else {}
    default_llm = llms.get("default") if isinstance(llms.get("default"), dict) else {}
    models = default_llm.get("models") if isinstance(default_llm.get("models"), list) else []
    if models and not metadata["model"]:
        metadata["model"] = str(models[0]).replace("${Z_SCOPE_MODEL}", env.get("Z_SCOPE_MODEL", ""))
    return metadata


def _prepare_trial_config(
    suite_root: Path,
    run_dir: Path,
    *,
    warm_cache: bool,
) -> Path:
    """Create a strict v3 trial config plus an isolated RuntimeSpec override."""

    config_path = _suite_project_dir(suite_root) / "zscope.benchmark.yaml"
    if warm_cache:
        return config_path
    if yaml is None:
        raise RuntimeError("PyYAML is required to create an isolated benchmark trial config")
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise RuntimeError(f"Benchmark config is not a mapping: {config_path}")
    if loaded.get("config_version") != 3:
        raise RuntimeError(f"Benchmark config must declare config_version: 3: {config_path}")
    isolated_snapshot_dir = (run_dir / ".cold_snapshot_cache").resolve()
    if isolated_snapshot_dir.exists():
        if not isolated_snapshot_dir.is_dir() or any(isolated_snapshot_dir.iterdir()):
            raise RuntimeError(
                "Cold benchmark cache is not empty; use a fresh run directory "
                f"or pass --warm-cache: {isolated_snapshot_dir}"
            )
    runtime_override = run_dir / "runtime.cold.override.yaml"
    runtime_override.write_text(
        yaml.safe_dump(
            {
                "runtime_spec_version": 1,
                "analysis": {"enable_snapshot_cache": True},
                "paths": {"snapshots": isolated_snapshot_dir.as_posix()},
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    # The override isolates cache state; copying identical YAML outside the
    # project would change the only root authority. Load the original in place.
    return config_path


def _contains_answer_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _FORMAL_ANSWER_KEYS:
                return True
            if _contains_answer_key(item):
                return True
    elif isinstance(value, list):
        return any(_contains_answer_key(item) for item in value)
    return False


def _copy_answer_free_project(source: Path, destination: Path) -> None:
    """Copy a project into a sealed tree without runtime or answer material."""

    source = Path(source).resolve()
    destination = Path(destination).resolve()
    if not source.is_dir():
        raise BenchmarkIsolationError(f"external benchmark project does not exist: {source}")
    if destination.exists():
        raise BenchmarkIsolationError(f"formal scan input already exists: {destination}")
    destination.mkdir(parents=True)
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise BenchmarkIsolationError(
                f"formal answer-free project cannot contain symlinks: {relative.as_posix()}"
            )
        if any(part.lower() in _FORMAL_ANSWER_FREE_EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.is_dir():
            continue
        lowered_name = path.name.lower()
        if lowered_name in {"ground_truth.json", "ground_truth.md"}:
            raise BenchmarkIsolationError(
                f"truth material is present in the external project: {relative.as_posix()}"
            )
        if lowered_name in {
            "zscope_batch_report.json",
            "zscope.benchmark.yaml",
            "zscope.benchmark.cold.yaml",
        }:
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def _copy_answer_free_entries(source: Path, destination: Path) -> None:
    try:
        payload = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkIsolationError("cannot load external benchmark entries") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("functions"), list):
        raise BenchmarkIsolationError("external benchmark entries must contain functions[]")
    if _contains_answer_key(payload):
        raise BenchmarkIsolationError("external benchmark entries contain answer metadata")
    _json_dump(destination, payload)


def _answer_free_tree_manifest(root: Path) -> dict[str, Any]:
    files = [path for path in root.rglob("*") if path.is_file()]
    rows = [
        {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(files, key=lambda item: item.relative_to(root).as_posix())
    ]
    return {
        "schema_version": "zscope.external-formal-scan-input.v1",
        "file_count": len(rows),
        "files": rows,
        "manifest_sha256": sha256_payload(rows),
        "answer_material_present": False,
    }


def _container_project_path(value: Any, *, source_project: Path) -> str:
    raw = str(value or "")
    if not raw:
        return raw
    normalized = raw.replace("\\", "/")
    source_text = source_project.resolve().as_posix().rstrip("/")
    if normalized == source_text:
        return "/zscope-cache/project"
    if normalized.startswith(source_text + "/"):
        return "/zscope-cache/project/" + normalized[len(source_text) + 1 :]
    path = Path(raw)
    if not path.is_absolute():
        return "/zscope-cache/project/" + normalized.lstrip("./")
    return normalized


def _rewrite_compile_commands_for_container(path: Path, *, source_project: Path) -> None:
    if not path.is_file():
        return
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkIsolationError("compile_commands.json is invalid") from exc
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise BenchmarkIsolationError("compile_commands.json must be an array of objects")
    source_variants = {
        str(source_project.resolve()),
        source_project.resolve().as_posix(),
    }
    rewritten: list[dict[str, Any]] = []
    for raw_row in rows:
        row = dict(raw_row)
        row["directory"] = "/zscope-cache/project"
        if row.get("file"):
            container_file = _container_project_path(row["file"], source_project=source_project)
            if not container_file.startswith("/zscope-cache/project/"):
                raise BenchmarkIsolationError(
                    "compile_commands.json references a source outside the sealed project"
                )
            row["file"] = container_file
        if isinstance(row.get("command"), str):
            command = str(row["command"])
            for source_variant in sorted(source_variants, key=len, reverse=True):
                command = command.replace(source_variant, "/zscope-cache/project")
            row["command"] = command
        if isinstance(row.get("arguments"), list):
            rewritten_arguments = []
            for item in row["arguments"]:
                argument = str(item)
                for source_variant in sorted(source_variants, key=len, reverse=True):
                    argument = argument.replace(source_variant, "/zscope-cache/project")
                rewritten_arguments.append(argument)
            row["arguments"] = rewritten_arguments
        rewritten.append(row)
    serialized = json.dumps(rewritten, ensure_ascii=False, indent=2) + "\n"
    if any(source_variant in serialized for source_variant in source_variants):
        raise BenchmarkIsolationError(
            "compile_commands.json still references the host project after rewriting"
        )
    path.write_text(serialized, encoding="utf-8")


def _write_formal_container_config(
    source: Path,
    destination: Path,
    *,
    compile_commands_present: Optional[bool] = None,
) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML is required for formal external benchmark execution")
    loaded = yaml.safe_load(Path(source).read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict) or loaded.get("config_version") != 3:
        raise BenchmarkIsolationError("formal external config must declare config_version: 3")
    project = loaded.get("project")
    if not isinstance(project, dict):
        raise BenchmarkIsolationError("formal external config project must be an object")
    if "root" in project or "source_root" in project:
        raise BenchmarkIsolationError("legacy project roots require explicit migration before formal execution")
    project["entry_functions_list"] = "/zscope-input/entries.json"
    has_compile_commands = (
        (destination.parent / "compile_commands.json").is_file()
        if compile_commands_present is None
        else bool(compile_commands_present)
    )
    if has_compile_commands:
        project["targets"][0]["compile_commands"] = "compile_commands.json"
    scan = loaded.setdefault("scan", {})
    if not isinstance(scan, dict):
        raise BenchmarkIsolationError("formal external config scan must be an object")
    scan["task"] = (
        "Audit this C/C++ project for memory safety, resource lifecycle, "
        "integer and bounds, null and failure, and concurrency defects. "
        "Use only source evidence, call paths, and local project semantics."
    )
    llms = loaded.get("llms")
    if not isinstance(llms, dict) or not llms:
        raise BenchmarkIsolationError("formal external config must define an LLM profile")
    for raw_profile in llms.values():
        if not isinstance(raw_profile, dict):
            raise BenchmarkIsolationError("formal external LLM profile must be an object")
        raw_profile["base_urls"] = ["${Z_SCOPE_LLM_BASE_URL}"]
        raw_profile["models"] = ["${Z_SCOPE_LLM_MODEL}"]
        raw_profile["api_key"] = "${Z_SCOPE_API_KEY}"
    destination.write_text(
        yaml.safe_dump(loaded, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _write_formal_runtime_override(destination: Path) -> None:
    assert yaml is not None
    destination.write_text(
        yaml.safe_dump(
            {
                "runtime_spec_version": 1,
                "analysis": {"enable_snapshot_cache": True},
                "paths": {
                    "knowledge_db": "/zscope-cache/project/.zscope_knowledge/code_knowledge.db",
                    "snapshots": "/zscope-cache/project/.zscope_snapshots",
                    "user_config_file": (
                        "/zscope-cache/project/.zscope_snapshots/user_config.xlsx"
                    ),
                },
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _formal_oci_environment(run_env: Mapping[str, str]) -> dict[str, str]:
    environment = {
        str(key): str(value)
        for key, value in run_env.items()
        if "GROUND_TRUTH" not in str(key).upper() and "BENCHMARK_TRUTH" not in str(key).upper()
    }
    if not environment.get("Z_SCOPE_LLM_BASE_URL", "").strip():
        fallback_base_url = environment.get("Z_SCOPE_BASE_URL", "").strip()
        if fallback_base_url:
            environment["Z_SCOPE_LLM_BASE_URL"] = fallback_base_url
    if not environment.get("Z_SCOPE_LLM_MODEL", "").strip():
        fallback_model = environment.get("Z_SCOPE_MODEL", "").strip()
        if fallback_model:
            environment["Z_SCOPE_LLM_MODEL"] = fallback_model
    return environment


def _run_formal_full_zscope_oci(
    *,
    suite_root: Path,
    run_dir: Path,
    config_path: Path,
    run_env: Mapping[str, str],
) -> dict[str, Any]:
    """Execute the scanner in rootless OCI and return only answer-free artifacts."""

    source_project = _suite_project_dir(suite_root).resolve()
    truth_path = (suite_root / "benchmark" / "ground_truth.json").resolve()
    scorer_path = Path(__file__).resolve()
    environment = _formal_oci_environment(run_env)
    with tempfile.TemporaryDirectory(prefix="zscope-external-formal-") as raw_workspace:
        workspace = Path(raw_workspace).resolve()
        for protected in (REPO_ROOT.resolve(), suite_root.resolve()):
            if (
                workspace == protected
                or workspace.is_relative_to(protected)
                or protected.is_relative_to(workspace)
            ):
                raise BenchmarkIsolationError(
                    "formal OCI workspace must be disjoint from the repository and suite"
                )
        scan_input = workspace / "scan-input"
        sealed_project = scan_input / "project"
        artifact_output = workspace / "artifact-output"
        cache_output = workspace / "cache"
        writable_project = cache_output / "project"
        scan_input.mkdir()
        artifact_output.mkdir()
        cache_output.mkdir()
        _copy_answer_free_project(source_project, sealed_project)
        _copy_answer_free_entries(
            suite_root / "benchmark" / "entries.json", scan_input / "entries.json"
        )
        _rewrite_compile_commands_for_container(
            sealed_project / "compile_commands.json", source_project=source_project
        )
        container_config = sealed_project / "zscope.execution.yaml"
        _write_formal_container_config(
            config_path,
            container_config,
            compile_commands_present=(sealed_project / "compile_commands.json").is_file(),
        )
        container_config_text = container_config.read_text(encoding="utf-8")
        forbidden_config_values = {
            suite_root.resolve().as_posix(),
            str(suite_root.resolve()),
            REPO_ROOT.resolve().as_posix(),
            str(REPO_ROOT.resolve()),
        }
        if "ground_truth.json" in container_config_text.lower() or any(
            value and value in container_config_text for value in forbidden_config_values
        ):
            raise BenchmarkIsolationError(
                "formal container config references host checkout or truth material"
            )
        _write_formal_runtime_override(scan_input / "runtime.override.yaml")
        scan_input_manifest = _answer_free_tree_manifest(scan_input)
        benchmark_json_dump(run_dir / "formal-scan-input-manifest.json", scan_input_manifest)
        shutil.copytree(sealed_project, writable_project)

        container_python = environment.get("Z_SCOPE_BENCHMARK_OCI_PYTHON", "python3").strip()
        scan_command = [
            "env",
            "Z_SCOPE_DEVELOPER_MODE=1",
            "Z_SCOPE_RUNTIME_SPEC=/zscope-input/runtime.override.yaml",
            container_python,
            "-m",
            "zscope.cli.cli",
            "-c",
            "/zscope-cache/project/zscope.execution.yaml",
            "--verbose",
        ]
        executor = _OCI_EXECUTOR_FACTORY(
            runtime=environment.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
            image=environment.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
            scan_input=scan_input,
            artifact_output=artifact_output,
            cache_output=cache_output,
            environment=environment,
        )
        executor.preflight()
        phase = executor.execute_phase(
            "scan",
            scan_command,
            log_path=run_dir / "zscope.oci.log",
            accepted_returncodes=(0, 1, 2),
        )
        evidence = executor.execution_evidence(required_phases=("scan",))
        evidence["scan_input_manifest_sha256"] = scan_input_manifest["manifest_sha256"]
        evidence["scan_input_file_count"] = scan_input_manifest["file_count"]
        require_release_isolation(
            required=True,
            capability=evidence,
            repository_checkout=REPO_ROOT,
            truth_paths=(truth_path, scorer_path),
        )
        source_report = writable_project / "zscope_batch_report.json"
        if source_report.is_file():
            shutil.copy2(source_report, artifact_output / source_report.name)
        final_report = run_dir / "zscope_batch_report.json"
        if (artifact_output / source_report.name).is_file():
            shutil.copy2(artifact_output / source_report.name, final_report)
        conversation_files = copy_conversation_trajectory(writable_project, run_dir)
        return {
            "return_code": int(phase.return_code),
            "duration_seconds": round(float(phase.seconds), 4),
            "report": final_report.as_posix(),
            "conversation_files": conversation_files,
            "command": scan_command,
            "isolation": evidence,
        }


def _file_integrity_state(path: Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        return {
            "exists": False,
            "sha256": "",
            "size": 0,
            "mtime_ns": 0,
        }
    stat = path.stat()
    return {
        "exists": True,
        "sha256": sha256_file(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _integrity_manifest_changes(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[str]:
    protected_keys = (
        "truth_sha256",
        "scorer_sha256",
        "config_sha256",
        "execution_config_sha256",
        "benchmark_manifest_sha256",
        "entries_sha256",
        "source_manifest_sha256",
        "source_file_count",
        "benchmark_policy_sha256",
    )
    return [key for key in protected_keys if before.get(key) != after.get(key)]


def _validate_trial_integrity(
    *,
    condition: str,
    return_code: int | None,
    started_at: float,
    report_before: dict[str, Any],
    report_after: dict[str, Any],
    report_payload: dict[str, Any],
    artifact_manifest_before: dict[str, Any],
    artifact_manifest_after: dict[str, Any],
    expected_entry_count: int,
    cold_snapshot_cache: bool,
) -> dict[str, Any]:
    errors: list[str] = []
    changed_inputs = _integrity_manifest_changes(
        artifact_manifest_before,
        artifact_manifest_after,
    )
    if changed_inputs:
        errors.append(f"benchmark inputs changed during trial: {', '.join(changed_inputs)}")
    required_hashes = (
        "truth_sha256",
        "scorer_sha256",
        "config_sha256",
        "execution_config_sha256",
        "entries_sha256",
        "source_manifest_sha256",
        "benchmark_policy_sha256",
    )
    missing_hashes = [key for key in required_hashes if not artifact_manifest_after.get(key)]
    if missing_hashes:
        errors.append(f"required integrity hashes are missing: {', '.join(missing_hashes)}")
    if return_code not in {0, 1}:
        errors.append(f"unexpected process return code: {return_code}")
    if not report_after.get("exists"):
        errors.append("report was not produced")
    else:
        if int(report_after.get("mtime_ns") or 0) < int((started_at - 2.0) * 1_000_000_000):
            errors.append("report predates this trial")
        if (
            report_before.get("exists")
            and report_before.get("mtime_ns") == report_after.get("mtime_ns")
            and report_before.get("sha256") == report_after.get("sha256")
        ):
            errors.append("report was not refreshed and may be stale")
    if str(report_payload.get("overall_verdict") or "").lower() == "error":
        errors.append("report contains an error verdict")

    summary = report_payload.get("summary")
    metadata = report_payload.get("metadata")
    reported_completeness = (
        str(
            report_payload.get("completeness")
            or (metadata.get("completeness") if isinstance(metadata, dict) else "")
            or ""
        )
        .strip()
        .lower()
    )
    if reported_completeness and reported_completeness != "complete":
        errors.append(f"report completeness is {reported_completeness}, expected complete")
    if str(report_payload.get("scan_outcome") or "").strip().lower() == "incomplete":
        errors.append("report scan outcome is incomplete")
    if isinstance(summary, dict) and summary.get("interrupted") is True:
        errors.append("report summary is marked interrupted")
    if isinstance(metadata, dict) and metadata.get("interrupted") is True:
        errors.append("report metadata is marked interrupted")
    if condition == CONDITION_FULL_ZSCOPE:
        if not isinstance(summary, dict):
            errors.append("full-pipeline report is missing its completion summary")
        else:
            analyzed = summary.get("functions_analyzed")
            if not isinstance(analyzed, int):
                errors.append("full-pipeline report is missing functions_analyzed")
            elif expected_entry_count and analyzed < expected_entry_count:
                errors.append(
                    "full-pipeline report analyzed fewer functions than requested "
                    f"({analyzed} < {expected_entry_count})"
                )

    chain_payload = {
        "condition": condition,
        "return_code": return_code,
        "artifact_manifest_before": artifact_manifest_before,
        "artifact_manifest_after": artifact_manifest_after,
        "report_after": report_after,
        "errors": errors,
    }
    return {
        "schema_version": "zscope.benchmark.integrity.v1",
        "status": "failed" if errors else "passed",
        "errors": errors,
        "cold_snapshot_cache": cold_snapshot_cache,
        "report_before": report_before,
        "report_after": report_after,
        "input_changes": changed_inputs,
        "chain_sha256": sha256_payload(chain_payload),
    }


def _condition_from_args(args: argparse.Namespace) -> str:
    condition = str(getattr(args, "condition", "") or "").strip()
    if condition:
        return condition
    mode = str(getattr(args, "mode", "") or "").strip()
    if mode == "candidates":
        return CONDITION_CANDIDATES
    if mode == "zscope":
        return CONDITION_FULL_ZSCOPE
    return CONDITION_FULL_ZSCOPE


def _mode_from_condition(condition: str) -> str:
    return "candidates" if condition == CONDITION_CANDIDATES else "zscope"


def _load_truth(suite_root: Path) -> dict[str, Any]:
    return json.loads((suite_root / "benchmark" / "ground_truth.json").read_text(encoding="utf-8"))


def _load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "entry_function": "external_benchmark_missing_report",
            "overall_verdict": "error",
            "issues": [],
            "metadata": {"missing_report": path.as_posix()},
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "entry_function": "external_benchmark_invalid_report",
            "overall_verdict": "error",
            "issues": [],
            "metadata": {
                "invalid_report": path.as_posix(),
                "parse_error": f"{type(exc).__name__}: {exc}",
            },
        }
    if not isinstance(payload, dict):
        return {
            "entry_function": "external_benchmark_invalid_report",
            "overall_verdict": "error",
            "issues": [],
            "metadata": {
                "invalid_report": path.as_posix(),
                "parse_error": "top-level report must be a JSON object",
            },
        }
    return payload


def _extract_llm_issues(content: str) -> list[dict[str, Any]]:
    from zscope.common.utils import extract_json_blocks

    for block in extract_json_blocks(content):
        if isinstance(block, dict) and isinstance(block.get("issues"), list):
            return [item for item in block["issues"] if isinstance(item, dict)]
        if isinstance(block, list):
            return [item for item in block if isinstance(item, dict)]
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, dict) and isinstance(parsed.get("issues"), list):
        return [item for item in parsed["issues"] if isinstance(item, dict)]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def _repo_context_for_entry(project: Path, entry: dict[str, Any], code: str) -> str:
    entry_file = str(entry.get("file_path") or "")
    file_path = project / entry_file
    siblings: list[str] = []
    if file_path.exists():
        for info in extract_functions(file_path, entry_file):
            siblings.append(f"{info.name}:{info.line}-{info.end_line}")
    files = sorted(
        path.relative_to(project).as_posix()
        for path in project.rglob("*")
        if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".h", ".hpp"}
    )[:200]
    return (
        "Repository context without Z-SCOPE candidates.\n"
        f"Entry file: {entry_file}\n"
        f"Sibling functions: {siblings[:80]}\n"
        f"Source files: {files}\n"
        f"Entry code chars: {len(code)}"
    )


def run_pure_llm(args: argparse.Namespace, *, repo_context: bool) -> dict[str, Any]:
    from zscope.framework.llm_client import LLMClient

    suite_root = Path(args.suite_root).resolve()
    project = _suite_project_dir(suite_root)
    entries = _load_entries(suite_root / "benchmark" / "entries.json")
    run_dir = Path(args.run_dir).resolve()
    report_path = run_dir / (
        "pure_llm_repo_report.json" if repo_context else "pure_llm_entry_report.json"
    )
    transcript_path = (
        run_dir
        / "trajectory"
        / ("pure_llm_repo_transcript.jsonl" if repo_context else "pure_llm_entry_transcript.jsonl")
    )
    transcript_path.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env_file = Path(args.env_file) if args.env_file else Path("test/range/zscope.local.env")
    env.update(_load_env_file(env_file))
    base_url = (
        env.get("Z_SCOPE_LLM_BASE_URL") or env.get("Z_SCOPE_BASE_URL") or ""
    ).strip()
    model = (env.get("Z_SCOPE_LLM_MODEL") or env.get("Z_SCOPE_MODEL") or "").strip()
    if not base_url or not model:
        raise ValueError(
            "Set Z_SCOPE_LLM_BASE_URL (or Z_SCOPE_BASE_URL) and Z_SCOPE_LLM_MODEL (or Z_SCOPE_MODEL)"
        )
    client = LLMClient(
        api_key=env.get("Z_SCOPE_API_KEY", ""),
        base_url=base_url,
        models=[model],
        timeout=120,
        max_retries=2,
        max_tokens=8192,
    )
    issues: list[dict[str, Any]] = []
    total_context_tokens = 0
    started = time.time()
    try:
        with transcript_path.open("w", encoding="utf-8") as transcript:
            for entry in entries:
                name = str(entry.get("function_name") or "")
                entry_file = str(entry.get("file_path") or "")
                direct = extract_function_code(project / entry_file, name) if entry_file else None
                if not direct:
                    continue
                code, info = direct
                context = _repo_context_for_entry(project, entry, code) if repo_context else ""
                prompt = (
                    "Analyze this C/C++ benchmark entry for memory, bounds/integer, null/failure, "
                    "resource lifecycle, and concurrency defects. Return only JSON with key 'issues'. "
                    "Each issue must include category, function, file, line, description, and evidence. "
                    "Do not use any answer-key or ground-truth files.\n\n"
                    f"Function: {name}\nFile: {info.file}\n\n{context}\n\n```c\n{code}\n```"
                )
                messages = [
                    {
                        "role": "system",
                        "content": "You are a C/C++ security evaluator. Return strict JSON only.",
                    },
                    {"role": "user", "content": prompt},
                ]
                response = client.chat_completion(messages, tools=None, temperature=0.0)
                message = (response.get("choices") or [{}])[0].get("message") or {}
                content = str(message.get("content") or "")
                entry_issues = _extract_llm_issues(content)
                for issue in entry_issues:
                    issue.setdefault("function", name)
                    issue.setdefault("file", info.file)
                    issues.append(issue)
                total_context_tokens += LLMClient.estimate_tokens(messages + [message])
                transcript.write(
                    json.dumps(
                        {
                            "entry": entry,
                            "request_messages": messages,
                            "response_message": message,
                            "issues": entry_issues,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
    finally:
        client.close()

    report = {
        "entry_function": "external_benchmark_pure_llm",
        "overall_verdict": "issues_found" if issues else "no_issue_found",
        "issues": issues,
        "metadata": {
            "condition": CONDITION_PURE_LLM_REPO if repo_context else CONDITION_PURE_LLM_ENTRY,
            "entry_count": len(entries),
            "context_tokens": total_context_tokens,
            "tool_call_count": 0,
            "duration_seconds": round(time.time() - started, 4),
            "transcript": transcript_path.relative_to(run_dir).as_posix(),
        },
    }
    _json_dump(report_path, report)
    return {
        "return_code": 0,
        "duration_seconds": report["metadata"]["duration_seconds"],
        "report": report_path.as_posix(),
        "transcript": transcript_path.as_posix(),
    }


def run_candidates(args: argparse.Namespace) -> dict[str, Any]:
    from zscope.core.candidates.graph import GraphCandidateGenerator
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.config.config import IndexingConfig
    from zscope.retrieval.code_index import CodeIndex

    project = Path(args.project).resolve()
    entries_path = Path(args.entries).resolve()
    output = Path(args.output).resolve()
    entries = _load_entries(entries_path)
    index = CodeIndex(
        project,
        project / "compile_commands.json",
        source_root=project,
        indexing_config=IndexingConfig(backend="regex"),
    )
    generator = RegexCandidateGenerator()
    graph_generator = GraphCandidateGenerator(index)
    issues: list[dict[str, Any]] = []
    missing: list[str] = []
    start = time.time()
    try:
        for entry in entries:
            name = str(entry.get("function_name") or "")
            if not name:
                continue
            entry_file = str(entry.get("file_path") or "")
            fallback_path = (project / entry_file).resolve() if entry_file else None
            direct = (
                extract_function_code(fallback_path, name)
                if fallback_path and fallback_path.exists()
                else None
            )
            impl = None if direct else index.get_function_impl(name)
            if direct:
                code, info = direct
                file_path = Path(info.file).resolve().relative_to(project).as_posix()
            elif impl:
                code = str(impl.get("code") or "")
                file_path = str(impl.get("file") or entry.get("file_path") or "")
            else:
                missing.append(name)
                continue
            issues.extend(generator.generate_issues(name, code, file_path))
        entry_names = [
            str(entry.get("function_name") or "") for entry in entries if entry.get("function_name")
        ]
        issues.extend(graph_generator.generate_for_functions(entry_names))
    finally:
        index.close()

    report = {
        "entry_function": "external_benchmark_candidates",
        "overall_verdict": "issues_found" if issues else "no_issue_found",
        "issues": issues,
        "metadata": {
            "mode": "regex_candidate_coverage",
            "entry_count": len(entries),
            "missing_entry_impls": missing,
            "duration_seconds": round(time.time() - start, 4),
        },
    }
    _json_dump(output, report)
    return {
        "report": output.as_posix(),
        "entry_count": len(entries),
        "issue_count": len(issues),
        "missing_entry_impls": missing,
        "duration_seconds": report["metadata"]["duration_seconds"],
    }


def _report_issues(report: dict[str, Any], view: str = "default") -> list[dict[str, Any]]:
    views = report.get("report_views")
    if isinstance(views, dict):
        selected = views.get(view)
        if isinstance(selected, dict) and isinstance(selected.get("issues"), list):
            return [x for x in selected["issues"] if isinstance(x, dict)]
    if isinstance(report.get("issues"), list):
        return [x for x in report["issues"] if isinstance(x, dict)]
    issues: list[dict[str, Any]] = []
    results = report.get("results")
    if isinstance(results, dict):
        for result in results.values():
            if isinstance(result, dict) and isinstance(result.get("issues"), list):
                issues.extend(x for x in result["issues"] if isinstance(x, dict))
    return issues


def _issue_function(issue: dict[str, Any]) -> str:
    return str(issue.get("function") or issue.get("func_name") or "").lower()


def _load_range_fp_audit_classifier() -> Optional[FalsePositiveClassifier]:
    module_path = REPO_ROOT / "test" / "range" / "benchmark" / "fp_audit_rules.py"
    if not module_path.exists():
        return None
    spec = importlib.util.spec_from_file_location("zscope_range_fp_audit_rules", module_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    classifier = getattr(module, "classify_range_false_positive_record", None)
    return classifier if callable(classifier) else None


def _fp_audit_classifier_for_truth(
    truth: dict[str, Any],
    *,
    truth_path: Optional[Path] = None,
    suite_root: Optional[Path] = None,
) -> Optional[FalsePositiveClassifier]:
    benchmark = str(truth.get("benchmark") or "")
    truth_path_text = truth_path.as_posix().lower() if truth_path else ""
    suite_root_text = suite_root.as_posix().lower() if suite_root else ""
    is_range = (
        benchmark in RANGE_BENCHMARK_NAMES
        or "test/range/benchmark/ground_truth.json" in truth_path_text
        or suite_root_text.endswith("test/range")
    )
    return _load_range_fp_audit_classifier() if is_range else None


def _text_has_category(text: str, truth: dict[str, Any]) -> bool:
    lowered = text.replace("_", " ").replace("-", " ").lower()
    category = str(truth.get("category") or "").lower()
    cwe = str(truth.get("cwe") or "").lower()
    aliases = CATEGORY_ALIASES.get(category, [category.replace("_", " "), cwe])
    if cwe and cwe in lowered:
        return True
    return any(alias and alias in lowered for alias in aliases)


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    from zscope.reporting.json_io import read_report
    report = read_report(Path(args.report))
    truth_path = Path(args.truth)
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    fp_audit_classifier = _fp_audit_classifier_for_truth(truth, truth_path=truth_path)
    evaluation_views = score_report_views(
        report,
        truth,
        line_tolerance=args.line_tolerance,
        fp_audit_classifier=fp_audit_classifier,
    )
    selected_view = args.view if args.view in evaluation_views else "default"
    result = dict(evaluation_views[selected_view])
    result["evaluation_views"] = evaluation_views
    if args.output:
        _json_dump(Path(args.output), result)
    return result


def run_prepared(args: argparse.Namespace) -> dict[str, Any]:
    suite_root = Path(args.suite_root).resolve()
    condition = _condition_from_args(args)
    run_kind = str(getattr(args, "run_kind", "sample") or "sample")
    if run_kind == "formal" and condition != CONDITION_FULL_ZSCOPE:
        raise ValueError("Formal external benchmarks currently permit full_zscope_pipeline only")
    if run_kind == "formal" and bool(getattr(args, "warm_cache", False)):
        raise ValueError("Formal external benchmarks require an isolated cold cache")
    trial_index = int(getattr(args, "trial_index", 1) or 1)
    run_suffix = f"{condition}_trial_{trial_index:02d}"
    run_dir = (
        Path(args.run_dir).resolve()
        if args.run_dir
        else suite_root / "runs" / time.strftime("%Y%m%d_%H%M%S") / run_suffix
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    config_path = _suite_project_dir(suite_root) / "zscope.benchmark.yaml"
    warm_cache = bool(getattr(args, "warm_cache", False))
    cold_snapshot_cache = condition == CONDITION_FULL_ZSCOPE and not warm_cache
    if run_kind == "formal":
        execution_config = run_dir / "zscope.execution.yaml"
        _write_formal_container_config(
            config_path,
            execution_config,
            compile_commands_present=(
                _suite_project_dir(suite_root) / "compile_commands.json"
            ).is_file(),
        )
    else:
        execution_config = (
            _prepare_trial_config(suite_root, run_dir, warm_cache=warm_cache)
            if condition == CONDITION_FULL_ZSCOPE
            else config_path
        )
    truth: Optional[dict[str, Any]] = None if run_kind == "formal" else _load_truth(suite_root)
    entries = _load_entries(suite_root / "benchmark" / "entries.json")
    expected_entry_count = len(
        {
            (
                str(entry.get("function_name") or ""),
                str(entry.get("file_path") or ""),
            )
            for entry in entries
            if entry.get("function_name")
        }
    )
    artifact_manifest_before = build_benchmark_artifact_manifest(
        suite_root,
        truth=truth,
        config_path=config_path,
        execution_config_path=execution_config,
    )
    report = run_dir / "missing_report.json"
    report_before = _file_integrity_state(report)
    command = [sys.executable, "scripts/external_benchmark.py", "run-prepared"]
    return_code: int | None = 0
    conversation_files: list[str] = []
    run_result: dict[str, Any]
    run_env = os.environ.copy()
    env_file = Path(args.env_file) if args.env_file else Path("test/range/zscope.local.env")
    run_env.update(_load_env_file(env_file))
    if run_env.get("Z_SCOPE_LLM_BASE_URL") and not run_env.get("Z_SCOPE_BASE_URL"):
        run_env["Z_SCOPE_BASE_URL"] = run_env["Z_SCOPE_LLM_BASE_URL"]
    if run_env.get("Z_SCOPE_LLM_MODEL") and not run_env.get("Z_SCOPE_MODEL"):
        run_env["Z_SCOPE_MODEL"] = run_env["Z_SCOPE_LLM_MODEL"]
    if cold_snapshot_cache and run_kind != "formal":
        run_env["Z_SCOPE_DEVELOPER_MODE"] = "1"
        run_env["Z_SCOPE_RUNTIME_SPEC"] = str((run_dir / "runtime.cold.override.yaml").resolve())
    started = time.time()

    isolation_capability: dict[str, Any] = (
        {}
        if run_kind == "formal"
        else oci_capability(
            runtime=run_env.get("Z_SCOPE_BENCHMARK_OCI_RUNTIME", ""),
            image=run_env.get("Z_SCOPE_BENCHMARK_OCI_IMAGE", ""),
        )
    )
    if run_kind == "formal":
        report = run_dir / "zscope_batch_report.json"
        report_before = _file_integrity_state(report)
        formal_result = _run_formal_full_zscope_oci(
            suite_root=suite_root,
            run_dir=run_dir,
            config_path=config_path,
            run_env=run_env,
        )
        report = Path(formal_result["report"])
        return_code = int(formal_result["return_code"])
        conversation_files = list(formal_result["conversation_files"])
        command = list(formal_result["command"])
        isolation_capability = dict(formal_result["isolation"])
        benchmark_json_dump(run_dir / "isolation.json", isolation_capability)
        run_result = {
            "return_code": return_code,
            "duration_seconds": round(time.time() - started, 4),
            "report": report.as_posix(),
            "execution": "rootless_oci",
        }
    elif condition == CONDITION_CANDIDATES:
        report = run_dir / "candidate_report.json"
        report_before = _file_integrity_state(report)
        run_result = run_candidates(
            argparse.Namespace(
                project=_suite_project_dir(suite_root),
                entries=suite_root / "benchmark" / "entries.json",
                output=report,
            )
        )
        return_code = int(run_result.get("return_code", 0) or 0)
    elif condition in {CONDITION_PURE_LLM_ENTRY, CONDITION_PURE_LLM_REPO}:
        report = run_dir / (
            "pure_llm_repo_report.json"
            if condition == CONDITION_PURE_LLM_REPO
            else "pure_llm_entry_report.json"
        )
        report_before = _file_integrity_state(report)
        pure_args = argparse.Namespace(**vars(args))
        pure_args.run_dir = run_dir.as_posix()
        run_result = run_pure_llm(
            pure_args,
            repo_context=condition == CONDITION_PURE_LLM_REPO,
        )
        report = Path(run_result["report"])
        return_code = int(run_result.get("return_code", 0) or 0)
        transcript = run_result.get("transcript")
        if transcript:
            conversation_files = [Path(transcript).relative_to(run_dir).as_posix()]
    else:
        project_dir = _suite_project_dir(suite_root)
        report = project_dir / "zscope_batch_report.json"
        report_before = _file_integrity_state(report)
        cmd = [
            sys.executable,
            "-m",
            "zscope.cli.cli",
            "-c",
            str(execution_config),
            "--verbose",
        ]
        command = cmd
        try:
            completed = subprocess.run(
                cmd,
                cwd=Path.cwd(),
                text=True,
                capture_output=True,
                env=run_env,
                timeout=3660,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            completed = subprocess.CompletedProcess(
                cmd,
                returncode=2,
                stdout=stdout,
                stderr=f"{stderr}\nbenchmark_total_deadline_exceeded",
            )
        (run_dir / "zscope.stdout.log").write_text(completed.stdout, encoding="utf-8")
        (run_dir / "zscope.stderr.log").write_text(completed.stderr, encoding="utf-8")
        return_code = completed.returncode
        run_result = {
            "return_code": completed.returncode,
            "duration_seconds": round(time.time() - started, 4),
            "report": report.as_posix(),
        }

    finished = time.time()
    if truth is None:
        # Formal scoring starts only after the scanner container has exited and
        # its inspected answer-free report has been copied back to the host.
        truth = _load_truth(suite_root)
    report_after = _file_integrity_state(report)
    report_payload = _load_report(Path(report))
    artifact_manifest_after = build_benchmark_artifact_manifest(
        suite_root,
        truth=truth,
        config_path=config_path,
        execution_config_path=execution_config,
    )
    integrity = _validate_trial_integrity(
        condition=condition,
        return_code=return_code,
        started_at=started,
        report_before=report_before,
        report_after=report_after,
        report_payload=report_payload,
        artifact_manifest_before=artifact_manifest_before,
        artifact_manifest_after=artifact_manifest_after,
        expected_entry_count=expected_entry_count,
        cold_snapshot_cache=cold_snapshot_cache,
    )
    integrity["cache_mode"] = (
        ("warm" if warm_cache else "isolated_cold")
        if condition == CONDITION_FULL_ZSCOPE
        else "not_applicable"
    )
    integrity["artifact_manifest_before"] = artifact_manifest_before
    integrity["artifact_manifest_after"] = artifact_manifest_after
    benchmark_json_dump(run_dir / "integrity.json", integrity)
    if integrity["status"] != "passed":
        raise RuntimeError(
            "Benchmark integrity validation failed: "
            + "; ".join(str(item) for item in integrity["errors"])
        )

    if condition == CONDITION_FULL_ZSCOPE and run_kind != "formal":
        copied_report = run_dir / "zscope_batch_report.json"
        shutil.copy2(report, copied_report)
        report = copied_report
        conversation_files = copy_conversation_trajectory(project_dir, run_dir)

    replay_bundle_path = run_dir / "validator-replay-bundle.json"
    replay_report = dict(report_payload)
    replay_manifest = dict(
        replay_report.get("run_manifest")
        if isinstance(replay_report.get("run_manifest"), dict)
        else {}
    )
    # Candidate-only and pure-LLM comparison reports predate the product run
    # manifest.  Bind their answer-free source/config inputs explicitly instead
    # of weakening the replay bundle's strict identity contract.
    replay_manifest.setdefault(
        "source_tree_hash", artifact_manifest_after["source_manifest_sha256"]
    )
    replay_manifest.setdefault("config_hash", artifact_manifest_after["execution_config_sha256"])
    replay_report["run_manifest"] = replay_manifest
    try:
        replay_bundle = write_validator_replay_bundle(replay_bundle_path, replay_report)
        replay_bundle_metadata = {
            "schema_version": replay_bundle["schema_version"],
            "group_count": replay_bundle["group_count"],
            "bundle_sha256": replay_bundle["bundle_sha256"],
            "path": replay_bundle_path.name,
            "answer_material_present": False,
            "available": True,
        }
    except ReplayBundleError as exc:
        if run_kind == "formal":
            raise
        replay_bundle_metadata = {
            "schema_version": REPLAY_BUNDLE_SCHEMA_VERSION,
            "group_count": 0,
            "bundle_sha256": "",
            "path": "",
            "answer_material_present": False,
            "available": False,
            "reason": f"nonformal_report_not_replayable:{exc}",
        }

    env_metadata = collect_environment_metadata(
        suite_root=suite_root,
        condition=condition,
        run_kind=run_kind,
        command=command,
        started_at=started,
        finished_at=finished,
        return_code=return_code,
        config=_suite_config_metadata(suite_root, run_env),
    )
    env_metadata["execution_config"] = execution_config.as_posix()
    env_metadata["cache_mode"] = integrity["cache_mode"]
    fp_audit_classifier = _fp_audit_classifier_for_truth(truth, suite_root=suite_root)
    summary = build_trial_summary(
        suite_root=suite_root,
        run_dir=run_dir,
        condition=condition,
        run_kind=run_kind,
        trial_index=trial_index,
        report=report_payload,
        truth=truth,
        environment=env_metadata,
        line_tolerance=args.line_tolerance,
        conversation_files=conversation_files,
        fp_audit_classifier=fp_audit_classifier,
        integrity=integrity,
        artifact_manifest=artifact_manifest_after,
    )
    summary["mode"] = _mode_from_condition(condition)
    summary["run"] = run_result
    summary["validator_replay_bundle"] = replay_bundle_metadata
    summary["isolation"] = {
        **isolation_capability,
        "required_for_release": bool(
            run_kind == "formal"
            and DEFAULT_BENCHMARK_POLICY.requirements.get(
                "require_oci_isolation_for_release", False
            )
        ),
        "scoring_execution": "host_after_scanner_exit",
    }
    benchmark_json_dump(run_dir / "evaluation.json", summary["evaluation"])
    benchmark_json_dump(run_dir / "evaluation_views.json", summary["evaluation_views"])
    benchmark_json_dump(run_dir / "summary.json", summary)
    return summary


def run_matrix(args: argparse.Namespace) -> dict[str, Any]:
    suite_root = Path(args.suite_root).resolve()
    trial_count = int(args.trials or 1)
    run_kind = str(getattr(args, "run_kind", "sample") or "sample")
    if run_kind == "formal" and trial_count < MIN_RELEASE_TRIALS:
        raise ValueError(
            f"Formal benchmark matrices require at least {MIN_RELEASE_TRIALS} paired trials"
        )
    if run_kind == "formal" and bool(getattr(args, "warm_cache", False)):
        raise ValueError("Formal benchmark matrices require isolated cold caches")
    conditions = list(getattr(args, "conditions", []))
    if run_kind == "formal" and conditions != [CONDITION_FULL_ZSCOPE]:
        raise ValueError(
            "Formal external benchmark matrices currently require exactly " "full_zscope_pipeline"
        )
    matrix_root = (
        Path(args.run_dir).resolve()
        if args.run_dir
        else suite_root / "runs" / time.strftime("%Y%m%d_%H%M%S_matrix")
    )
    matrix_root.mkdir(parents=True, exist_ok=True)
    summaries: list[dict[str, Any]] = []
    for condition in conditions:
        for trial_index in range(1, trial_count + 1):
            trial_args = argparse.Namespace(**vars(args))
            trial_args.condition = condition
            trial_args.mode = _mode_from_condition(condition)
            trial_args.trial_index = trial_index
            trial_args.run_dir = (matrix_root / condition / f"trial_{trial_index:02d}").as_posix()
            summaries.append(run_prepared(trial_args))
    baseline_summaries = load_summaries(
        [Path(path) for path in getattr(args, "baseline_summaries", [])]
    )
    aggregate = aggregate_trial_summaries(
        summaries,
        baseline_summaries=baseline_summaries,
        baseline_tokens_per_tp=getattr(args, "baseline_tokens_per_tp", None),
        bootstrap_samples=int(
            getattr(args, "bootstrap_samples", DEFAULT_BOOTSTRAP_SAMPLES)
            or DEFAULT_BOOTSTRAP_SAMPLES
        ),
        require_improvement_claim=bool(getattr(args, "require_improvement_claim", False)),
        balanced_attestation=_load_balanced_attestation_input(args),
        balanced_attestation_workflow_run_id=str(
            getattr(args, "balanced_attestation_workflow_run_id", "") or ""
        ),
        release_sha=_aggregate_release_sha(args, summaries),
    )
    aggregate["run_dir"] = matrix_root.as_posix()
    aggregate["summary_files"] = [
        (Path(summary["run_dir"]) / "summary.json").as_posix() for summary in summaries
    ]
    benchmark_json_dump(matrix_root / "matrix_summary.json", aggregate)
    if run_kind == "formal" and not aggregate["release_readiness"]["passed"]:
        raise RuntimeError(
            "Formal benchmark matrix failed release gates; inspect "
            f"{matrix_root / 'matrix_summary.json'}"
        )
    return aggregate


def aggregate_trials(args: argparse.Namespace) -> dict[str, Any]:
    summaries = load_summaries([Path(path) for path in args.summaries])
    baseline_summaries = load_summaries(
        [Path(path) for path in getattr(args, "baseline_summaries", [])]
    )
    aggregate = aggregate_trial_summaries(
        summaries,
        baseline_summaries=baseline_summaries,
        baseline_tokens_per_tp=getattr(args, "baseline_tokens_per_tp", None),
        bootstrap_samples=int(
            getattr(args, "bootstrap_samples", DEFAULT_BOOTSTRAP_SAMPLES)
            or DEFAULT_BOOTSTRAP_SAMPLES
        ),
        require_improvement_claim=bool(getattr(args, "require_improvement_claim", False)),
        balanced_attestation=_load_balanced_attestation_input(args),
        balanced_attestation_workflow_run_id=str(
            getattr(args, "balanced_attestation_workflow_run_id", "") or ""
        ),
        release_sha=_aggregate_release_sha(args, summaries),
    )
    if args.output:
        benchmark_json_dump(Path(args.output), aggregate)
    if (
        bool(getattr(args, "require_release_pass", False))
        and not aggregate["release_readiness"]["passed"]
    ):
        raise RuntimeError("Aggregated benchmark summaries failed release gates")
    return aggregate


def _load_balanced_attestation_input(args: argparse.Namespace) -> dict[str, Any] | None:
    raw = str(getattr(args, "balanced_default_attestation", "") or "").strip()
    if not raw:
        return None
    value = json.loads(Path(raw).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("balanced default attestation must be a JSON object")
    return value


def _aggregate_release_sha(
    args: argparse.Namespace,
    summaries: list[dict[str, Any]],
) -> str:
    explicit = str(getattr(args, "release_sha", "") or "").strip()
    if explicit:
        return explicit
    for summary in summaries:
        environment = summary.get("environment")
        if isinstance(environment, dict) and environment.get("commit_sha"):
            return str(environment["commit_sha"])
    return ""


def _print_result(result: dict[str, Any]) -> None:
    print(json.dumps(result, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare-juliet", help="Prepare a Juliet C/C++ memory subset")
    p.add_argument("--source", required=True, help="Extracted Juliet root or a subset directory")
    p.add_argument("--workspace", default="benchmarks/external/workspace")
    p.add_argument("--name", default="juliet_memory_sample")
    p.add_argument(
        "--max-cases",
        type=int,
        default=20,
        help="Maximum source files to select; 0 means all matched files",
    )
    p.add_argument(
        "--cwes", nargs="+", default=DEFAULT_MEMORY_CWES, help="CWE filters such as CWE401, or ALL"
    )
    p.add_argument("--flow-variants", nargs="*", default=["01", "02", "03", "04", "05"])
    p.add_argument("--backend", default="regex", choices=["regex", "clang", "unified"])
    p.set_defaults(func=prepare_juliet)

    p = sub.add_parser("prepare-svcomp", help="Prepare an SV-COMP memory/concurrency subset")
    p.add_argument("--source", required=True, help="sv-benchmarks/c directory or a subset")
    p.add_argument("--workspace", default="benchmarks/external/workspace")
    p.add_argument("--name", default="svcomp_memsafety_sample")
    p.add_argument(
        "--max-cases",
        type=int,
        default=20,
        help="Maximum tasks to select; 0 means all matched tasks",
    )
    p.add_argument(
        "--set-files", nargs="*", default=[], help="SV-COMP .set files relative to --source"
    )
    p.add_argument(
        "--properties",
        nargs="*",
        default=["valid-memtrack", "valid-free", "valid-deref", "valid-memsafety", "data-race"],
    )
    p.add_argument("--backend", default="regex", choices=["regex", "clang", "unified"])
    p.set_defaults(func=prepare_svcomp)

    p = sub.add_parser(
        "prepare-magma", help="Prepare Magma bug metadata and optional materialized target source"
    )
    p.add_argument("--magma-root", required=True, help="Magma repository checkout")
    p.add_argument("--target", default="libpng")
    p.add_argument(
        "--target-source", default="", help="Fetched/patched Magma target source root, if available"
    )
    p.add_argument("--workspace", default="benchmarks/external/workspace")
    p.add_argument("--name", default="magma_libpng_sample")
    p.add_argument(
        "--max-bugs", type=int, default=5, help="Maximum Magma bug patches to select; 0 means all"
    )
    p.add_argument(
        "--copy-full-source",
        action="store_true",
        help="Copy the full target source tree into the suite project",
    )
    p.add_argument("--backend", default="regex", choices=["regex", "clang", "unified"])
    p.set_defaults(func=prepare_magma)

    p = sub.add_parser("run-candidates", help="Run regex/graph candidate coverage")
    p.add_argument("--project", required=True)
    p.add_argument("--entries", required=True)
    p.add_argument("--output", required=True)
    p.set_defaults(func=run_candidates)

    p = sub.add_parser("evaluate", help="Evaluate a Z-SCOPE JSON report against generated truth")
    p.add_argument("--report", required=True)
    p.add_argument("--truth", required=True)
    p.add_argument("--output", default="")
    p.add_argument("--line-tolerance", type=int, default=8)
    p.add_argument("--view", default="default")
    p.set_defaults(func=evaluate)

    p = sub.add_parser("run-prepared", help="Run and evaluate a prepared suite")
    p.add_argument("--suite-root", required=True)
    p.add_argument("--run-dir", default="")
    p.add_argument("--mode", default="candidates", choices=["candidates", "zscope"])
    p.add_argument("--condition", default="", choices=["", *BENCHMARK_CONDITIONS])
    p.add_argument("--run-kind", default="sample", choices=RUN_KINDS)
    p.add_argument("--trial-index", type=int, default=1)
    p.add_argument("--line-tolerance", type=int, default=8)
    p.add_argument("--view", default="default")
    p.add_argument("--env-file", default="test/range/zscope.local.env")
    p.add_argument(
        "--warm-cache",
        action="store_true",
        help="Reuse the suite snapshot cache; default trials use an isolated cold cache",
    )
    p.set_defaults(func=run_prepared)

    p = sub.add_parser(
        "run-matrix", help="Run one or more benchmark conditions for multiple trials"
    )
    p.add_argument("--suite-root", required=True)
    p.add_argument("--run-dir", default="")
    p.add_argument(
        "--conditions",
        nargs="+",
        default=[CONDITION_PURE_LLM_ENTRY, CONDITION_PURE_LLM_REPO, CONDITION_FULL_ZSCOPE],
        choices=BENCHMARK_CONDITIONS,
    )
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--run-kind", default="sample", choices=RUN_KINDS)
    p.add_argument("--mode", default="zscope", choices=["candidates", "zscope"])
    p.add_argument("--line-tolerance", type=int, default=8)
    p.add_argument("--view", default="default")
    p.add_argument("--env-file", default="test/range/zscope.local.env")
    p.add_argument(
        "--warm-cache",
        action="store_true",
        help="Reuse the suite snapshot cache; default trials use isolated per-trial caches",
    )
    p.add_argument(
        "--baseline-summaries",
        nargs="*",
        default=[],
        help="Five frozen Validator Arm-A summary.json files",
    )
    p.add_argument("--balanced-default-attestation", default="")
    p.add_argument(
        "--balanced-attestation-workflow-run-id",
        default="",
        help="Trusted protected-workflow run identity bound to the attestation artifact",
    )
    p.add_argument("--release-sha", default="")
    p.add_argument(
        "--baseline-tokens-per-tp",
        type=float,
        default=None,
        help="Historical compatibility input; policy v1 uses paired summaries",
    )
    p.add_argument(
        "--bootstrap-samples",
        type=int,
        default=DEFAULT_BOOTSTRAP_SAMPLES,
        help="Bootstrap resamples used for 95%% confidence intervals",
    )
    p.add_argument(
        "--require-improvement-claim",
        action="store_true",
        help="Require the paired improvement-claim rule in addition to release gates",
    )
    p.set_defaults(func=run_matrix)

    p = sub.add_parser("aggregate-trials", help="Aggregate existing benchmark summary.json files")
    p.add_argument("summaries", nargs="+")
    p.add_argument("--output", default="")
    p.add_argument("--baseline-summaries", nargs="*", default=[])
    p.add_argument("--balanced-default-attestation", default="")
    p.add_argument(
        "--balanced-attestation-workflow-run-id",
        default="",
        help="Trusted protected-workflow run identity bound to the attestation artifact",
    )
    p.add_argument("--release-sha", default="")
    p.add_argument("--baseline-tokens-per-tp", type=float, default=None)
    p.add_argument("--bootstrap-samples", type=int, default=DEFAULT_BOOTSTRAP_SAMPLES)
    p.add_argument("--require-improvement-claim", action="store_true")
    p.add_argument("--require-release-pass", action="store_true")
    p.set_defaults(func=aggregate_trials)
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    _print_result(result)


if __name__ == "__main__":
    main()
