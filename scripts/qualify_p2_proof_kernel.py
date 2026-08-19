#!/usr/bin/env python3
"""Qualify frozen P2 source-to-ProgramProofIR conversion with local Clang 21.1.8."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel.canonical import content_sha256
from zscope.core.validation.proof_kernel.models import (
    program_proof_ir_from_graph,
    validate_program_ir,
)
from zscope.retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "p2_proof_kernel"
BASELINE = FIXTURE / "source-qualification.json"
SOURCES = {
    "concurrency": "neutral_concurrency",
    "resource": "neutral_resource",
    "path_guard": "neutral_path_guard",
    "contract_type": "neutral_contract_type",
}


def _run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout + result.stderr


def qualify(clang: Path) -> Dict[str, Any]:
    version_output = _run([str(clang), "--version"])
    version_line = version_output.splitlines()[0].strip()
    if "clang version 21.1.8" not in version_line:
        raise RuntimeError(f"P2 requires Clang 21.1.8, got: {version_line}")
    cases = []
    for family, function in SOURCES.items():
        source = FIXTURE / "sources" / f"{family}.c"
        relative = source.relative_to(ROOT).as_posix()
        source_bytes = source.read_bytes()
        syntax_command = [str(clang), "-std=c11", "-fsyntax-only", str(source)]
        _run(syntax_command)
        ast_command = [
            str(clang),
            "-std=c11",
            "-Xclang",
            "-ast-dump=json",
            "-fsyntax-only",
            str(source),
        ]
        cfg_command = [
            str(clang),
            "--analyze",
            "-std=c11",
            "-Xclang",
            "-analyzer-checker=debug.DumpCFG",
            "-o",
            os.devnull,
            str(source),
        ]
        ast_output = _run(ast_command)
        cfg_output = _run(cfg_command)
        ast_summary = ClangToolingEvidenceProvider._summarize_ast_json(
            ast_output, func_name=function
        )
        cfg_summary = ClangToolingEvidenceProvider._summarize_cfg_dump(
            cfg_output, func_name=function
        )
        evidence = {
            "clang_path": "clang-21.1.8",
            "ast_dump_command": ["clang", "ast-json", relative],
            "cfg_dump_command": ["clang", "cfg", relative],
            "code_snapshot_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "unresolved_dynamic_edges": False,
            "ast_dump": {"summary": ast_summary},
            "cfg_dump": {"summary": cfg_summary},
        }
        graph = FunctionIRGraph.from_clang_evidence(evidence, function=function, file=relative)
        if graph is None or not graph.coverage_complete:
            raise RuntimeError(f"source-to-FunctionIR conversion incomplete for {family}")
        proof_ir = program_proof_ir_from_graph(
            graph,
            project_uid="PROJECT_P2_SOURCE_QUALIFICATION",
            revision_uid="REV_" + evidence["code_snapshot_sha256"][:32],
        )
        valid, reason = validate_program_ir(proof_ir)
        if not valid:
            raise RuntimeError(f"ProgramProofIR invalid for {family}: {reason}")
        summary = proof_ir["functions"][0]
        cases.append(
            {
                "family": family,
                "function": function,
                "source": relative,
                "source_sha256": evidence["code_snapshot_sha256"],
                "cfg_node_uids": [value["node_uid"] for value in summary["cfg_nodes"]],
                "cfg_edges": summary["cfg_edges"],
                "exit_node_uids": summary["exit_node_uids"],
                "event_kinds": sorted(value["kind"] for value in summary["events"]),
                "program_proof_ir_sha256": proof_ir["content_sha256"],
            }
        )
    semantic = {
        "clang_version": "21.1.8",
        "case_count": len(cases),
        "cases": cases,
    }
    return {
        "schema_version": "zscope.p2-source-to-ir-qualification.v1",
        "semantic": semantic,
        "semantic_sha256": content_sha256(semantic),
        "environment": {
            "clang_version_line": version_line,
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "llm_calls": 0,
        "network": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", required=True, type=Path)
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()
    result = qualify(args.clang)
    if args.write_baseline:
        BASELINE.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(BASELINE.relative_to(ROOT).as_posix())
        return 0
    frozen = json.loads(BASELINE.read_text(encoding="utf-8"))
    if result["semantic"] != frozen.get("semantic"):
        print("P2 source-to-IR semantic replay mismatch", file=sys.stderr)
        return 1
    print(
        "P2 source-to-IR qualification passed: "
        f"clang=21.1.8 cases={result['semantic']['case_count']} "
        f"semantic_sha256={result['semantic_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
