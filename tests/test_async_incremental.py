"""Supported callback changes invalidate old witnesses; cold/hot results agree."""

from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

from test_clang_batch import project, build
from test_lifecycle_paths import candidates
from test_validation_pipeline import FakeUserConfig
from zscope.core.candidates.cpp_domains.async_paths import AsyncLifecyclePaths
from zscope.core.candidates.decision_facts import attach_decision_facts
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.defaults import default_local_pattern_semantics

CODE = """#include <stdlib.h>
#include <pthread.h>
struct Item {int value;};
static void *work(void *raw) {struct Item *p=raw; BODY return 0;}
static void *other(void *raw) {return 0;}
void entry(void) {
struct Item *p=malloc(sizeof *p);
if(!p)return;
pthread_t t;
if(pthread_create(&t,0,TARGET,p)!=0){free(p);return;}
pthread_cancel(t);
free(p);
pthread_join(t,0);
}
"""


def evaluate(backend, root, cdb, registry):
    index = CodeIndex(root, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang"))
    source = root / "a.c"
    result = AsyncLifecyclePaths(
        index.get_function_program_facts("entry", str(source)),
        registry,
        index.get_function_program_facts,
    ).run()
    issues = candidates((index, source, registry), "entry")
    projections = []
    for issue in issues:
        attach_decision_facts(issue)
        issue["protocol_assessment"] = assess_protocol_candidate(issue, index, registry)
        outcome = ValidationPipeline(FakeUserConfig()).apply_unvalidated(
            issue, {"final_score": 0.5}
        )
        projections.append(
            {
                "candidate": issue["candidate_id"],
                "state": issue["candidate_disposition"],
                "sub_state": issue.get("needs_review_sub_state"),
                "bucket": outcome.report_bucket,
                "missing": issue["missing_fact_kinds"],
                "coverage": issue["decision_fact_slice"]["coverage"],
            }
        )
    return index, issues, {"path": result, "projection": projections}


def test_callback_target_body_and_root_changes_match_independent_full(project):
    backend, root, cdb = project
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) {return 0;}\n')
    (root / "notes.txt").write_text("existing document\n")
    previous = None
    for stage, body, target in [
        ("initial", "", "work"),
        ("added_access", "p->value=1;", "work"),
        ("unchanged", "p->value=1;", "work"),
        ("target_changed", "p->value=1;", "other"),
        ("access_removed", "", "work"),
        ("restored", "p->value=1;", "work"),
        ("root_changed", "p->value=1;", "work"),
    ]:
        registry = default_local_pattern_semantics().contracts
        if stage == "root_changed":
            (base,) = registry.find_for_call("free")
            registry.add(
                replace(base, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}])
            )
        (root / "a.c").write_text(CODE.replace("BODY", body).replace("TARGET", target))
        if stage == "unchanged":
            (root / "notes.txt").write_text("unrelated document\n")
        if previous and stage not in {"unchanged"}:
            old_index, old_issues = previous
            for issue in old_issues:
                assessment = assess_protocol_candidate(issue, old_index, registry)
                assert (
                    assessment["state"] == "pending" and not assessment["technical_witness_current"]
                ), (stage, assessment)
        assert build(project)
        stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
        if stage in {"unchanged", "root_changed"}:
            assert stats["compiled_tus"] == 0 and stats["reused_tus"] == 2
        hot_index, hot_issues, hot = evaluate(backend, root, cdb, registry)
        cold = ClangBackend(
            frontend="batch",
            clang_indexer_path=backend._clang_indexer_path,
            db_path=f".zscope_knowledge/full-{stage}/db.sqlite",
            max_threads=1,
        )
        try:
            assert cold.initialize(str(root), compile_commands_path=str(cdb))
            assert json.loads(cold.db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2
            _, _, full = evaluate(cold, root, cdb, registry)
            assert hot == full
        finally:
            cold.close()
        present = stage in {"added_access", "unchanged", "restored"}
        assert bool(hot_issues) == present
        if present:
            assert hot["projection"][0]["state"] == "needs_review"
            assert hot["projection"][0]["sub_state"] == "business_conditional"
            assert hot["projection"][0]["missing"] == ["event:business_release_requirement"]
        assert hot["path"]["complete"] == (stage != "root_changed")
        previous = (hot_index, deepcopy(hot_issues))
