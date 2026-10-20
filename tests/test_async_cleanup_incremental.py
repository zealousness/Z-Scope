"""Cleanup bodies, capture targets and cancel roots invalidate current receipts."""

import json
from copy import deepcopy
from dataclasses import replace

from test_clang_batch import project, build
from test_async_incremental import evaluate
from test_async_queue import queue_driver
from test_async_cleanup import CLEANUP_SOURCE
from zscope.core.validation.protocol_assessment import assess_protocol_candidate, checked_assessment
from zscope.retrieval.clang_backend import ClangBackend
from zscope.semantics.defaults import default_local_pattern_semantics


def test_cleanup_dependencies_match_cold_analysis(project):
    backend, root, cdb = project
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) {return 0;}\n')
    previous = None
    for stage in (
        "initial",
        "unchanged",
        "handler_changed",
        "target_changed",
        "restored",
        "root_changed",
        "drain_fixed",
    ):
        registry = default_local_pattern_semantics().contracts
        code = CLEANUP_SOURCE
        driver = "submit(q,p); pthread_cancel(t); free(p); pthread_join(t,0);"
        if stage == "handler_changed":
            code = code.replace("p->value=7;", "")
        if stage == "target_changed":
            code = code.replace(
                "pthread_cleanup_push(touch_item,p)", "pthread_cleanup_push(noop,p)"
            )
        if stage == "root_changed":
            (contract,) = registry.find_for_call("pthread_testcancel")
            registry.add(
                replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}])
            )
        if stage == "drain_fixed":
            driver = "submit(q,p); pthread_cancel(t); pthread_join(t,0); free(p);"
        (root / "a.c").write_text(code + queue_driver("entry", driver, "test_point", "q->saved=p;"))
        if previous and stage != "unchanged":
            old_index, old_issues = previous
            for issue in old_issues:
                if stage != "root_changed":
                    assert not checked_assessment(issue)
                assert assess_protocol_candidate(issue, old_index, registry)["state"] == "pending"
        assert build(project)
        if stage in {"unchanged", "root_changed"}:
            stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
            assert stats["compiled_tus"] == 0 and stats["reused_tus"] == 2
        hot_index, issues, hot = evaluate(backend, root, cdb, registry)
        cold = ClangBackend(
            frontend="batch",
            clang_indexer_path=backend._clang_indexer_path,
            db_path=f".zscope_knowledge/cleanup-full-{stage}/db.sqlite",
            max_threads=1,
        )
        try:
            assert cold.initialize(str(root), compile_commands_path=str(cdb))
            assert json.loads(cold.db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2
            _, _, full = evaluate(cold, root, cdb, registry)
            assert hot == full
        finally:
            cold.close()
        assert bool(issues) == (stage in {"initial", "unchanged", "restored"})
        assert hot["path"]["complete"] == (stage != "root_changed")
        if issues:
            assert all(checked_assessment(issue) for issue in issues)
            assert hot["projection"][0]["sub_state"] == "business_conditional"
        previous = hot_index, deepcopy(issues)
