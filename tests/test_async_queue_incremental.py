"""Queue helper/worker/lock changes invalidate proof and agree cold versus hot."""

import json
from copy import deepcopy
from dataclasses import replace

from test_clang_batch import project, build
from test_async_incremental import evaluate
from test_async_queue import QUEUE_SOURCE, DRIVERS, queue_driver
from zscope.core.validation.protocol_assessment import assess_protocol_candidate, checked_assessment
from zscope.retrieval.clang_backend import ClangBackend
from zscope.semantics.defaults import default_local_pattern_semantics


def test_queue_dependencies_match_independent_full(project):
    backend, root, cdb = project
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) {return 0;}\n')
    (root / "notes.txt").write_text("existing note\n")
    previous = None
    for stage in (
        "initial",
        "unchanged",
        "helper_changed",
        "access_removed",
        "restored",
        "drain_fixed",
        "root_changed",
    ):
        registry = default_local_pattern_semantics().contracts
        code = QUEUE_SOURCE
        driver = DRIVERS["drain_active" if stage == "drain_fixed" else "cancel_active"]
        if stage == "helper_changed":
            code = code.replace(
                "q->slot=0; pthread_mutex_unlock", "q->slot=0; q->active=0; pthread_mutex_unlock"
            )
        if stage == "access_removed":
            code = code.replace("if(p) p->value=1;", "", 1)
        if stage == "unchanged":
            (root / "notes.txt").write_text("unrelated note change\n")
        if stage == "root_changed":
            (contract,) = registry.find_for_call("pthread_mutex_unlock")
            registry.add(
                replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}])
            )
        (root / "a.c").write_text(code + queue_driver("entry", driver))
        if previous and stage != "unchanged":
            old_index, old_issues = previous
            for issue in old_issues:
                assert not checked_assessment(issue)
                assert assess_protocol_candidate(issue, old_index, registry)["state"] == "pending"
        assert build(project)
        if stage == "unchanged":
            stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
            assert stats["compiled_tus"] == 0 and stats["reused_tus"] == 2
        hot_index, issues, hot = evaluate(backend, root, cdb, registry)
        cold = ClangBackend(
            frontend="batch",
            clang_indexer_path=backend._clang_indexer_path,
            db_path=f".zscope_knowledge/queue-full-{stage}/db.sqlite",
            max_threads=1,
        )
        try:
            assert cold.initialize(str(root), compile_commands_path=str(cdb))
            assert json.loads(cold.db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2
            _, _, full = evaluate(cold, root, cdb, registry)
            assert hot == full
        finally:
            cold.close()
        assert bool(issues) == (stage in {"initial", "unchanged", "helper_changed", "restored"})
        assert hot["path"]["complete"] == (stage != "root_changed")
        if issues:
            assert all(checked_assessment(issue) for issue in issues)
            assert hot["projection"][0]["sub_state"] == "business_conditional"
            assert hot["projection"][0]["missing"] == ["event:business_release_requirement"]
        previous = (hot_index, deepcopy(issues))
