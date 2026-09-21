"""Synthetic live pool discovery and hot-cache probe; not Range qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from pathlib import Path
import shutil
import tempfile

import yaml

from zscope.config.config import ConfigLoader
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.retrieval.code_index import CodeIndex

SOURCE = """typedef struct Node { struct Node *link; } Node;
typedef struct Pool { Node *available; } Pool;
Node *alpha(Pool *pool) {
    Node *node = pool->available;
    if (node) { pool->available = node->link; }
    return node;
}
void omega(Node *node, Pool *pool) {
    node->link = pool->available;
    pool->available = node;
}
Node *outer(int unused, Pool *arena) { return alpha(arena); }
void drop(Pool *arena, Node *node) { omega(node, arena); }
#define FETCH(arena) outer(0, (arena))
#define RETURN(arena, node) drop((arena), (node))
Node *nested(Pool *arena) { return FETCH(arena); }
void nested_drop(Pool *arena, Node *node) { RETURN(arena, node); }
void balanced(Pool *a, Pool *b) {
    Node *p = outer(7, a);
    if (!p) return;
    Node *q = p;
    drop(a, q);
}
void wrong_pool(Pool *a, Pool *b) {
    Node *p = outer(7, a);
    if (!p) return;
    drop(b, p);
}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang-indexer", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO, handlers=[logging.FileHandler(output / "probe.log", encoding="utf-8")]
    )
    root = args.workspace.resolve()
    root.mkdir(parents=True, exist_ok=True)
    source = root / "pool.c"
    source.write_text(SOURCE, encoding="utf-8")
    (output / "pool.c").write_text(SOURCE, encoding="utf-8")
    (output / "workspace.json").write_text(
        json.dumps(
            {
                "workspace": str(root),
                "source_sha256": hashlib.sha256(SOURCE.encode()).hexdigest(),
                "qualification": "not_formal",
            }
        ),
        encoding="utf-8",
    )
    (root / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "file": str(source),
                    "directory": str(root),
                    "arguments": ["clang", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    config_path = root / "zscope.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "config_version": 2,
                "llms": {
                    "default": {
                        "base_urls": ["${Z_SCOPE_LLM_BASE_URL}"],
                        "models": ["${Z_SCOPE_LLM_MODEL}"],
                        "api_key": "${Z_SCOPE_API_KEY}",
                        "max_tokens": 8192,
                        "base_url_max_concurrent_requests": 2,
                    }
                },
                "project": {
                    "language": "c_cpp",
                    "root": str(root),
                    "compile_commands_path": "compile_commands.json",
                    "entry_function": "nested",
                    "wiki": {"mode": "off"},
                },
                "scan": {"depth": "fast"},
                "indexing": {
                    "backend": "clang",
                    "clang": {"frontend": "batch"},
                    "tools": {"clang_indexer": args.clang_indexer},
                },
                "concurrency": {
                    "entry_workers": 1,
                    "validator_workers": 1,
                    "investigator_workers": 1,
                    "evidence_completion_workers": 1,
                    "index_workers": 2,
                    "svf_workers": 1,
                    "llm_max_inflight": 2,
                },
            }
        ),
        encoding="utf-8",
    )
    rounds = []
    for number in range(2):
        config = ConfigLoader.load(str(config_path))
        index = CodeIndex(
            config.project.project_root,
            config.project.compile_commands_path,
            indexing_config=config.indexing,
            wait_for_cpg=True,
            defer_svf=True,
        )
        analyzer = Analyzer(config, code_index=index, write_root_reports=False)
        folder = output / f"round-{number + 1}"
        folder.mkdir(exist_ok=True)
        try:
            result = analyzer.prepare_semantics(
                [FunctionEntry("nested"), FunctionEntry("nested_drop")]
            )
            calls, candidates = {}, {}
            for label, engine in (
                (
                    "clang",
                    ClangAstCfgCandidateGenerator(
                        result.local_semantics,
                        result.overlay,
                        program_facts_provider=index.get_function_program_facts,
                    ),
                ),
                ("regex", RegexCandidateGenerator(result.local_semantics)),
            ):
                for name in ("balanced", "wrong_pool"):
                    impl = index.get_function_impl(name, max_lines=None)
                    issues = engine.generate_issues(name, impl["code"], impl["file"])
                    candidates[f"{label}:{name}"] = [
                        {
                            "rule": i.get("rule"),
                            "defect_class": i.get("defect_class"),
                            "source": i.get("candidate_source"),
                            "evidence_pack": i.get("evidence_pack"),
                        }
                        for i in issues
                    ]
                    calls[f"{label}:{name}"] = engine.last_semantic_events
            graph = GraphCandidateGenerator(index, result.local_semantics, result.overlay)
            graph.generate_for_functions(["balanced", "wrong_pool"])
            calls["graph"] = graph.last_semantic_events
            rounds.append(
                {
                    "stats": result.stats.to_dict(),
                    "partial": result.partial,
                    "contract_version": result.contract_version,
                    "calls": calls,
                    "candidates": candidates,
                    "suspicious_metrics": result.suspicious_metrics,
                }
            )
        finally:
            analyzer.close()
            index.close()
            workbook = analyzer.user_config.workbook.path
            if workbook.exists():
                shutil.copy2(workbook, folder / "user_config.xlsx")
            snapshots = Path(config.analysis.snapshot_dir)
            shutil.copytree(
                snapshots / ".semantic-modeling", folder / "semantic-modeling", dirs_exist_ok=True
            )
            for snapshot in snapshots.glob("*.json"):
                shutil.copy2(snapshot, folder / snapshot.name)
            for usage in snapshots.glob("llm_usage_events_*.jsonl"):
                shutil.copy2(usage, folder / usage.name)
            (output / "result.json").write_text(
                json.dumps(rounds, ensure_ascii=False, indent=2), encoding="utf-8"
            )
    publication = json.loads((output / "round-1/semantic-modeling/publication.json").read_text())
    contracts = {c["symbol"]["name"]: c for c in publication["api_contracts"]}
    assert all(
        contracts[n]["verification"]["method"] == "source_protocol" for n in ("alpha", "omega")
    )
    assert all(
        contracts[n]["verification"]["method"] == "source_composition"
        for n in ("outer", "drop", "FETCH", "RETURN", "nested", "nested_drop")
    )
    assert (
        rounds[1]["stats"]["modeled_functions"] == rounds[1]["stats"]["total_context_tokens"] == 0
    )
    assert rounds[0]["contract_version"] == rounds[1]["contract_version"]
    books = [output / f"round-{n}/user_config.xlsx" for n in (1, 2)]
    assert books[0].read_bytes() == books[1].read_bytes()
    assert books[0].stat().st_mtime_ns == books[1].stat().st_mtime_ns
    for round_result in rounds:
        assert round_result["suspicious_metrics"]["registered"] == 0
        for engine in ("clang", "regex"):
            assert not any(
                i["defect_class"] == "memory_leak"
                for i in round_result["candidates"][f"{engine}:balanced"]
            )
            assert any(
                i["defect_class"] == "memory_leak"
                for i in round_result["candidates"][f"{engine}:wrong_pool"]
            )
    print(
        json.dumps(
            {
                "rounds": [{"stats": r["stats"], "partial": r["partial"]} for r in rounds],
                "verified": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
