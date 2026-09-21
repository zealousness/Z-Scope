"""Replay saved real model responses through source compilation and XLSX consumers.

No model requests, fixture changes, scoring hints, or handwritten API contracts.
The input is the retained workspace from probe.py or an isolated scan workspace.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import zscope

from zscope.config.user_config_store import UserConfigStore
from zscope.core.candidates.backend_signals import resource_release_pairs_from_overlay
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.evidence import SemanticOverlayCompiler
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.framework.llm_client import LLMClient
from zscope.semantics.contract_compiler import compile_snapshot, complete_transparent_pairs
from zscope.semantics.contracts import ApiContract, contract_rows
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.inference import LocalPatternSemanticBuilder
from zscope.snapshots.store import SnapshotStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--workspace", type=Path)
    inputs.add_argument("--snapshot-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--symbols",
        nargs="+",
        help="Compile only these symbols; replay call sites in every input snapshot.",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    def source_hashes():
        root = Path(zscope.__file__).parent
        return {
            p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix in {".py", ".yaml", ".json", ".md"}
        }

    initial_hashes = source_hashes()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Contract replay must not call an LLM")

    LLMClient.chat_completion = forbidden
    if args.snapshot_dir:
        original = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in args.snapshot_dir.glob("*.json")
        ]
    else:
        store = SnapshotStore(args.workspace / ".zscope_snapshots")
        original = [store.load_snapshot(name) for name in store.list_snapshots()]
    originals = {s["index_name"]: s for s in original if s and s.get("code")}
    selected = {
        key: s for key, s in originals.items() if not args.symbols or s["func_name"] in args.symbols
    }
    if args.symbols:
        missing = set(args.symbols) - {s["func_name"] for s in selected.values()}
        if missing:
            raise ValueError("Missing requested snapshots: " + ", ".join(sorted(missing)))
    pending = deepcopy(selected)
    registry = default_local_pattern_semantics().contracts
    normalized, diagnostics = [], {}
    names = {s["func_name"]: key for key, s in selected.items()}
    while pending:
        ready = [
            key
            for key, snapshot in pending.items()
            if not any(
                other != key and other in pending
                for name, other in names.items()
                if name != snapshot["func_name"]
                and re.search(r"\b" + re.escape(name) + r"\s*\(", snapshot["code"])
            )
        ]
        if not ready:
            raise RuntimeError(
                "Recursive replay needs a frozen SCC input; use the modeling integration tests"
            )
        for key in ready:
            snapshot = pending.pop(key)
            snapshot["interface_contracts"] = deepcopy(snapshot.get("raw_interface_contracts", []))
            diagnostics[key] = compile_snapshot(snapshot, snapshot, registry)
            normalized.append(snapshot)
            for raw in snapshot["interface_contracts"]:
                contract = ApiContract.from_row(
                    {
                        "contract": raw,
                        "symbol_name": snapshot["func_name"],
                        "file_path": snapshot.get("file_path"),
                        "signature": snapshot.get("signature"),
                    }
                )
                if contract is not None:
                    registry.add(contract)
    derived_pairs = complete_transparent_pairs(normalized, registry)
    writer = UserConfigStore(output / "user_config.xlsx")
    writer.workbook.merge_generated(contract_rows(normalized), covered_symbols=set())
    reader = UserConfigStore(writer.workbook.path)
    semantics = default_local_pattern_semantics()
    semantics.merge(
        LocalPatternSemanticBuilder(None, reader, None, []).semantics_from_user_config()
    )
    overlay = SemanticOverlayCompiler(reader).compile()
    assert overlay["contract_version"] == semantics.contracts.version
    results = {}
    for snapshot in originals.values():
        if snapshot.get("is_macro"):
            continue
        name, code, file = snapshot["func_name"], snapshot["code"], snapshot["file_path"]
        for engine_name, engine in (
            ("clang", ClangAstCfgCandidateGenerator(semantics, overlay)),
            ("regex", RegexCandidateGenerator(semantics)),
        ):
            issues = engine.generate_issues(name, code, file)
            results[engine_name + ":" + snapshot["index_name"]] = {
                "calls": engine.last_semantic_events,
                "candidates": [
                    {
                        "rule": i.get("rule"),
                        "location": i.get("location"),
                        "candidate_source": i.get("candidate_source"),
                    }
                    for i in issues
                ],
            }
        graph = GraphCandidateGenerator(object(), semantics, overlay)
        results["graph:" + snapshot["index_name"]] = {
            "calls": graph.semantics.contracts.trace_calls(snapshot)
        }
    artifact = {
        "llm_calls": 0,
        "release_eligible": False,
        "compiled_symbols": sorted(s["index_name"] for s in selected.values()),
        "consumer_snapshots": len(originals),
        "scope_note": "Graph records shared semantic call resolution; Clang and Regex also execute candidate generation. Unselected project contracts are intentionally absent.",
        "product_source_hashes": initial_hashes,
        "contract_version": semantics.contracts.version,
        "diagnostics": diagnostics,
        "derived_pairs": derived_pairs,
        "api_contracts": overlay["api_contracts"],
        "api_pairs": overlay["api_pairs"],
        "knowledge_db_pairs": resource_release_pairs_from_overlay(overlay),
        "raw_snapshots": list(originals.values()),
        "normalized_snapshots": normalized,
        "consumers": results,
    }
    if source_hashes() != initial_hashes:
        raise RuntimeError("Product sources changed while replay was running")
    (output / "replay.json").write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "snapshots": len(normalized),
                "errors": sum(len(x) for x in diagnostics.values()),
                "llm_calls": 0,
                "contract_version": semantics.contracts.version,
            }
        )
    )


if __name__ == "__main__":
    main()
