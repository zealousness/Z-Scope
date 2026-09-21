"""Replay the zero-LLM discovery map from isolated source and a real workbook."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from zscope.config.function_entry import FunctionListLoader
from zscope.config.config import IndexingConfig
from zscope.config.user_config_store import UserConfigStore
from zscope.core.candidates.evidence import SemanticOverlayCompiler
from zscope.framework.llm_client import LLMClient
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.security_map import SecuritySemanticMap, ZeroLLMSecurityMapBuilder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--workbook", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--clang-indexer", default="")
    args = parser.parse_args()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("The security map replay must not call an LLM")

    LLMClient.chat_completion = forbidden
    source = args.source.resolve()
    assert not (source / "GROUND_TRUTH.md").exists()
    assert not (source / "benchmark/ground_truth.json").exists()
    entries = FunctionListLoader.load(source / "entry_functions_list.json")
    overlay = SemanticOverlayCompiler(UserConfigStore(args.workbook.resolve())).compile()
    args.output.mkdir(parents=True, exist_ok=True)
    indexing = IndexingConfig(
        backend="clang", clang_frontend="batch", clang_indexer_path=args.clang_indexer,
        knowledge_db_path=str(args.output.resolve() / "knowledge.db"), max_clangd_threads=2,
    ) if args.clang_indexer else None
    include_paths = [source / p for p in ("src", "include", "internal")]
    exclude_paths = []
    if indexing:
        commands = json.loads((source / "build/compile_commands.json").read_text(encoding="utf-8"))
        compiled = {(Path(row["directory"]) / row["file"]).resolve() for row in commands}
        assert all(path.is_relative_to(source) for path in compiled)
        exclude_paths = sorted(p for base in include_paths for p in base.rglob("*") if p.suffix in {".c", ".cpp", ".cc", ".cxx"} and p.resolve() not in compiled)
    index = CodeIndex(
        source, compile_commands_path=source / "build/compile_commands.json" if indexing else None,
        indexing_config=indexing, include_paths=include_paths, exclude_paths=exclude_paths,
    )
    try:
        result = ZeroLLMSecurityMapBuilder(
            index, project_id="range-map-replay", revision="isolated-source",
            profile="balanced", semantic_overlay=overlay, project_root=source,
        ).build(entries)
    finally:
        index.close()
    SecuritySemanticMap.from_dict(result.to_dict())
    assert result.fingerprints["contract_version"] == overlay["contract_version"]
    calls = [c for c in result.claims if "call_semantics" in c.value]
    summary = {
        "llm_calls": 0, "release_eligible": False,
        "scope": "Real isolated source and XLSX reload; zero-LLM Security Map only. Does not rerun the active discovery LLM or the benchmark.",
        "backend": "clang_batch" if indexing else "regex_source_without_callgraph",
        "index_scope": [str(p.relative_to(source)) for p in include_paths],
        "uncompiled_files_excluded": [str(p.relative_to(source)) for p in exclude_paths],
        "entries": len(entries), "functions": len(result.functions),
        "events": sum(len(f.events) for f in result.functions),
        "contract_call_claims": len(calls),
        "call_origins": dict(Counter(c.origin for c in calls)),
        "call_statuses": dict(Counter(c.status for c in calls)),
        "call_roles": dict(Counter(c.value["call_semantics"]["role"] for c in calls)),
        "families": dict(Counter(e.family for f in result.functions for e in f.events)),
        "contract_version": overlay["contract_version"], "coverage": result.coverage,
        "workbook_sha256": hashlib.sha256(args.workbook.read_bytes()).hexdigest(),
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "security-map.json").write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
