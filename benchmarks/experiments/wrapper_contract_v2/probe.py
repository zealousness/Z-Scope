"""Source-only live modeling probe; this is not a Range accuracy qualification."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
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

SOURCE = """#include <stdlib.h>
#include <pthread.h>
void *alpha(size_t n) { return malloc(n); }
void *beta(size_t n, size_t count) { return calloc(count, n); }
void *delta(void *old, size_t n) { return realloc(old, n); }
void omega(int unused, void *p) { if (p) free(p); }
void enter(int unused, pthread_mutex_t *p) { if (p) pthread_mutex_lock(p); }
int leave(int unused, pthread_mutex_t *p) { return pthread_mutex_unlock(p); }
#define TAKE(m) enter(0, (m))
#define DROP(m) leave(0, (m))
#define CLEAR(p) do { omega(0, (p)); (p) = NULL; } while (0)
void out(size_t n, void **p) { *p = alpha(n); }
typedef struct State { void *ptr; } State;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
#define START() pthread_mutex_lock(&gate)
#define STOP() pthread_mutex_unlock(&gate)
void member_out(State *s) { s->ptr = alpha(8); }
void nested_out(State *s) { out(8, &s->ptr); }
void local_out(void *p) { out(8, &p); }
#define MAKE_SLOT(p) out(8, &(p))
void macro_out(State *s) { MAKE_SLOT(s->ptr); }
void global_use(void) { START(); STOP(); }
void condition_use(pthread_mutex_t *m) {
  if (pthread_mutex_lock(m) != 0) return;
  pthread_mutex_unlock(m);
}
void balanced(pthread_mutex_t *m) {
  void *p = alpha(8);
  if (!p) return;
  TAKE(m);
  DROP(m);
  CLEAR(p);
}
void leaking(void) {
  void *p = beta(8, 2);
  if (!p) return;
  ((char*)p)[0] = 1;
}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang-indexer", required=True)
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO, handlers=[logging.FileHandler(output / "probe.log", encoding="utf-8")]
    )
    with nullcontext(
        str(args.workspace) if args.workspace else tempfile.mkdtemp(prefix="zscope-wrapper-v2-")
    ) as temporary:
        root = Path(temporary)
        root.mkdir(parents=True, exist_ok=True)
        (output / "workspace.json").write_text(
            json.dumps({"workspace": str(root), "qualification": "not_formal"}), encoding="utf-8"
        )
        source = root / "interfaces.c"
        if not source.exists() or source.read_text(encoding="utf-8") != SOURCE:
            source.write_text(SOURCE, encoding="utf-8")
        (root / "compile_commands.json").write_text(
            json.dumps(
                [
                    {
                        "file": str(source),
                        "directory": str(root),
                        "arguments": ["clang", "-pthread", "-c", str(source)],
                    }
                ]
            ),
            encoding="utf-8",
        )
        configuration = {
            "config_version": 2,
            "llms": {
                "default": {
                    "base_urls": ["${Z_SCOPE_LLM_BASE_URL}"],
                    "models": ["${Z_SCOPE_LLM_MODEL}"],
                    "api_key": "${Z_SCOPE_API_KEY}",
                    "max_tokens": 8192,
                    "base_url_max_concurrent_requests": 4,
                }
            },
            "project": {
                "language": "c_cpp",
                "root": str(root),
                "compile_commands_path": "compile_commands.json",
                "entry_function": "balanced",
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
                "validator_workers": 2,
                "investigator_workers": 1,
                "evidence_completion_workers": 2,
                "index_workers": 2,
                "svf_workers": 1,
                "llm_max_inflight": 4,
            },
        }
        config_path = root / "zscope.yaml"
        config_path.write_text(yaml.safe_dump(configuration), encoding="utf-8")
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
            try:
                entries = [
                    FunctionEntry(name)
                    for name in (
                        "balanced",
                        "leaking",
                        "delta",
                        "out",
                        "member_out",
                        "global_use",
                        "condition_use",
                        "nested_out",
                        "local_out",
                        "macro_out",
                    )
                ]
                result = analyzer.prepare_semantics(entries)
                folder = output / f"round-{number + 1}"
                folder.mkdir(exist_ok=True)
                shutil.copy2(analyzer.user_config.workbook.path, folder / "user_config.xlsx")
                shutil.copy2(
                    Path(config.analysis.snapshot_dir) / ".semantic-modeling" / "publication.json",
                    folder / "publication.json",
                )
                clang = ClangAstCfgCandidateGenerator(
                    result.local_semantics,
                    result.overlay,
                    program_facts_provider=index.get_function_program_facts,
                )
                regex = RegexCandidateGenerator(result.local_semantics)
                graph = GraphCandidateGenerator(index, result.local_semantics, result.overlay)
                calls, candidates = {}, {}
                for name in ("balanced", "leaking", "global_use", "condition_use", "macro_out"):
                    impl = index.get_function_impl(name, max_lines=None)
                    for engine_name, engine in (("clang", clang), ("regex", regex)):
                        issues = engine.generate_issues(name, impl["code"], impl["file"])
                        candidates[f"{engine_name}:{name}"] = [
                            {
                                "rule": i.get("rule"),
                                "source": i.get("candidate_source"),
                                "location": i.get("location"),
                            }
                            for i in issues
                        ]
                        calls[f"{engine_name}:{name}"] = engine.last_semantic_events
                graph.generate_for_functions(
                    ["balanced", "leaking", "global_use", "condition_use", "macro_out"]
                )
                calls["graph"] = graph.last_semantic_events
                rounds.append(
                    {
                        "round": number + 1,
                        "stats": result.stats.to_dict(),
                        "partial": result.partial,
                        "contract_version": result.contract_version,
                        "calls": calls,
                        "candidates": candidates,
                        "suspicious_metrics": result.suspicious_metrics,
                    }
                )
                folder = output / f"round-{number + 1}"
                folder.mkdir(exist_ok=True)
                shutil.copy2(analyzer.user_config.workbook.path, folder / "user_config.xlsx")
                shutil.copy2(
                    Path(config.analysis.snapshot_dir) / ".semantic-modeling" / "publication.json",
                    folder / "publication.json",
                )
                for usage in Path(config.analysis.snapshot_dir).glob("llm_usage_events_*.jsonl"):
                    shutil.copy2(usage, folder / usage.name)
                (output / "result.json").write_text(
                    json.dumps(rounds, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            finally:
                analyzer.close()
                index.close()
        (output / "interfaces.c").write_text(SOURCE, encoding="utf-8")
        assert rounds[1]["stats"]["modeled_functions"] == 0
        assert rounds[1]["stats"]["total_context_tokens"] == 0
        assert rounds[0]["contract_version"] == rounds[1]["contract_version"]
        assert all(r["suspicious_metrics"]["registered"] == 0 for r in rounds)
        publication = json.loads((output / "round-1/publication.json").read_text())
        contracts = {c["symbol"]["name"]: c for c in publication["api_contracts"]}
        assert contracts["START"]["carrier"]["global_name"] == "gate"
        assert contracts["STOP"]["carrier"]["global_name"] == "gate"
        assert contracts["member_out"]["carrier"]["member_path"] == "->ptr"
        assert contracts["member_out"]["carrier"]["kind"] == "output_argument"
        assert all(
            name not in contracts
            for name in ("balanced", "global_use", "local_out")
        )
        # Nonzero includes EOWNERDEAD: condition_use is not a universally
        # balanced mutex protocol, so its conditional effects must be retained.
        assert any(c["symbol"]["name"] == "condition_use" and c["role"] == "lock"
                   for c in publication["api_contracts"])
        assert contracts["START"]["carrier"]["address_of"]
        assert contracts["nested_out"]["carrier"]["member_path"] == "->ptr"
        assert not contracts["nested_out"]["carrier"]["address_of"]
        assert contracts["macro_out"]["carrier"]["member_path"] == "->ptr"
        assert any(
            p["acquire"]["name"] == "START" and p["release"]["name"] == "STOP"
            for p in publication["api_pairs"]
        )
        print(
            json.dumps(
                [
                    {"round": r["round"], "partial": r["partial"], "stats": r["stats"]}
                    for r in rounds
                ],
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
