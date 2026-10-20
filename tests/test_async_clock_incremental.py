"""Clock selection/definition changes invalidate the same bounded path receipts."""

import json
from copy import deepcopy
from dataclasses import replace

from test_clang_batch import project, build
from test_async_incremental import evaluate
from test_async_queue import queue_driver
from test_async_clock import clock_source
from zscope.core.validation.protocol_assessment import assess_protocol_candidate, checked_assessment
from zscope.retrieval.clang_backend import ClangBackend
from zscope.semantics.defaults import default_local_pattern_semantics


def test_explicit_clock_changes_match_cold_replay(project):
    backend, root, cdb = project
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) {return 0;}\n')
    previous = None
    for stage in (
        "initial",
        "unchanged",
        "realtime",
        "predicate",
        "redefined",
        "unsupported",
        "restored",
        "root_changed",
        "drain_fixed",
    ):
        registry = default_local_pattern_semantics().contracts
        clock = {"realtime": "CLOCK_REALTIME", "unsupported": "CLOCK_BOOTTIME"}.get(
            stage, "CLOCK_MONOTONIC"
        )
        code = clock_source(clock)
        driver = "cancel_pending(q); free(p); pthread_join(t,0);"
        if stage == "predicate":
            code = code.replace("rc==ETIMEDOUT", "rc==0")
        if stage == "redefined":
            code = code.replace(
                "#include <errno.h>",
                "#include <errno.h>\n#undef CLOCK_MONOTONIC\n#define CLOCK_MONOTONIC 1",
            )
        if stage == "root_changed":
            (contract,) = registry.find_for_call("pthread_cond_clockwait")
            registry.add(
                replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}])
            )
        if stage == "drain_fixed":
            driver = "cancel_pending(q); pthread_join(t,0); free(p);"
        (root / "a.c").write_text(
            code + queue_driver("entry", driver, "timed_access", "q->saved=p;")
        )
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
        index, issues, hot = evaluate(backend, root, cdb, registry)
        cold = ClangBackend(
            frontend="batch",
            clang_indexer_path=backend._clang_indexer_path,
            db_path=f".zscope_knowledge/clock-full-{stage}/db.sqlite",
            max_threads=1,
        )
        try:
            assert cold.initialize(str(root), compile_commands_path=str(cdb))
            assert json.loads(cold.db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2
            _, _, full = evaluate(cold, root, cdb, registry)
            assert hot == full
        finally:
            cold.close()
        assert bool(issues) == (
            stage in {"initial", "unchanged", "realtime", "predicate", "restored"}
        )
        assert hot["path"]["complete"] == (
            stage not in {"redefined", "unsupported", "root_changed"}
        )
        if issues:
            assert all(checked_assessment(issue) for issue in issues)
            assert hot["projection"][0]["sub_state"] == "business_conditional"
            outcome = next(
                c
                for c in hot["path"]["schedule"]["constraints"]
                if c["kind"].startswith("pthread_cond_clockwait_returns")
            )
            if stage == "predicate":
                assert outcome["result"] == 0 and outcome["clock_constraint"] is None
                assert hot["path"]["schedule"]["wait_exploration"]["selected"] == "spurious_once"
            else:
                assert outcome["clock_constraint"]["clock"] == clock
                assert hot["path"]["schedule"]["wait_exploration"]["selected"] == "timeout_once"
        previous = index, deepcopy(issues)
