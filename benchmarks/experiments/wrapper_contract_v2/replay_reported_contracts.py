"""Local source/XLSX replay of the 41 historical model contracts; no LLM calls."""

from __future__ import annotations

import argparse
from collections import defaultdict
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace

from zscope.benchmarking.runner import SPECS, copy_scan_input
from zscope.config.user_config_store import UserConfigStore
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.evidence import SemanticOverlayCompiler
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.framework.llm_client import LLMClient
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.contract_compiler import compile_snapshot, complete_transparent_pairs
from zscope.semantics.contracts import ApiContract, contract_rows
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.inference import LocalPatternSemanticBuilder
from zscope.snapshots.modeling_input import build_semantic_model_input


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang-indexer", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Historical contract replay must not call an LLM")

    LLMClient.chat_completion = forbidden
    raw = json.loads(args.contracts.read_text())["inferred_contracts"]
    groups = defaultdict(list)
    for row in raw:
        groups[row["symbol"]["name"]].append(row)
    root = Path(tempfile.mkdtemp(prefix="zscope-contract-replay-")) / "scan-input"
    copy_scan_input(SPECS["c_cpp"].fixture_root, root, "c_cpp")
    with (output / "configure.log").open("w") as log:
        subprocess.run(
            [
                "cmake",
                "-S",
                str(root),
                "-B",
                str(root / "build"),
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                "-DCMAKE_C_COMPILER=clang",
            ],
            check=True,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    backend = ClangBackend(frontend="auto", clang_indexer_path=args.clang_indexer, max_threads=2)
    index = CodeIndex(
        root,
        root / "build/compile_commands.json",
        backend=backend,
        indexing_config=SimpleNamespace(backend="clang"),
    )
    contexts, missing = {}, {}
    try:
        for name, rows in groups.items():
            try:
                contexts[name] = build_semantic_model_input(
                    index,
                    name,
                    file_path=rows[0]["symbol"].get("file_path", ""),
                    include_context=False,
                )
            except Exception as exc:
                missing[name] = str(exc)
        registry = default_local_pattern_semantics().contracts
        pending, snapshots, diagnostics = dict(contexts), [], {}
        while pending:
            ready = [
                name
                for name, ctx in pending.items()
                if not any(
                    other != name and re.search(r"\b" + re.escape(other) + r"\s*\(", ctx["code"])
                    for other in pending
                )
            ]
            if not ready:
                for name in pending:
                    missing[name] = "recursive replay requires frozen SCC; not published"
                break
            for name in ready:
                ctx = pending.pop(name)
                snapshot = {**ctx, "interface_contracts": deepcopy(groups[name])}
                diagnostics[name] = compile_snapshot(snapshot, ctx, registry)
                snapshots.append(snapshot)
                for row in snapshot["interface_contracts"]:
                    contract = ApiContract.from_row(
                        {
                            "contract": row,
                            "symbol_name": name,
                            "file_path": ctx.get("file_path"),
                            "signature": ctx.get("signature"),
                        }
                    )
                    if contract is not None:
                        registry.add(contract)
        paired = complete_transparent_pairs(snapshots, registry)
        writer = UserConfigStore(output / "user_config.xlsx")
        writer.workbook.merge_generated(contract_rows(snapshots), covered_symbols=set())
        reader = UserConfigStore(writer.workbook.path)
        semantics = default_local_pattern_semantics()
        semantics.merge(
            LocalPatternSemanticBuilder(None, reader, None, []).semantics_from_user_config()
        )
        overlay = SemanticOverlayCompiler(reader).compile()
        consumers = {}
        for name, ctx in contexts.items():
            if ctx.get("is_macro"):
                continue
            for label, engine in (
                (
                    "clang",
                    ClangAstCfgCandidateGenerator(
                        semantics, overlay, program_facts_provider=index.get_function_program_facts
                    ),
                ),
                ("regex", RegexCandidateGenerator(semantics)),
            ):
                issues = engine.generate_issues(name, ctx["code"], ctx["file_path"])
                consumers[label + ":" + name] = {
                    "events": engine.last_semantic_events,
                    "candidates": [
                        {"rule": i.get("rule"), "location": i.get("location")} for i in issues
                    ],
                }
        graph = GraphCandidateGenerator(index, semantics, overlay)
        graph.generate_for_functions(
            [name for name, ctx in contexts.items() if not ctx.get("is_macro")]
        )
        consumers["graph"] = {"events": graph.last_semantic_events}
        result = {
            "workspace": str(root),
            "llm_calls": 0,
            "release_eligible": False,
            "historical_contract_count": len(raw),
            "diagnostics": diagnostics,
            "unresolved": missing,
            "derived_pairs": paired,
            "contract_version": semantics.contracts.version,
            "api_contracts": overlay["api_contracts"],
            "api_pairs": overlay["api_pairs"],
            "snapshots": snapshots,
            "consumers": consumers,
        }
        (output / "replay.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "workspace": str(root),
                    "modeled_symbols_replayed": len(snapshots),
                    "unresolved": missing,
                    "derived_pairs": paired,
                },
                ensure_ascii=False,
            )
        )
    finally:
        index.close()


if __name__ == "__main__":
    main()
