"""Native consumer wiring plus controlled current-input/cache boundaries."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_instance_analysis import _native_config, _native_index, native_variants
from test_instance_semantics_context import frozen_context
from test_validation_build_scope import _make_runner, ScopeRecordingAgent
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis.analyzer import Analyzer
from zscope.core.validation.runner import ValidationResultCache
from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.semantics.instance_semantics import materialize_effect_semantics


def test_real_native_entry_and_validation_helpers_share_exact_snapshot(
    native_variants, monkeypatch
):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    seen = []
    original = Analyzer.__init__

    def observe(self, *args, **kwargs):
        original(self, *args, **kwargs)
        if kwargs.get("instance_scope") is not None:
            seen.append(
                (
                    kwargs["instance_scope"],
                    kwargs.get("instance_semantics_snapshot"),
                    kwargs.get("defer_validation_to_scan"),
                    self._local_pattern_semantics,
                    kwargs.get("semantic_result"),
                )
            )

    monkeypatch.setattr(parallel_module.Analyzer, "__init__", observe)
    parallel = ParallelAnalyzer(_native_config(root, cdb, root), code_index=index)
    try:
        report = parallel.analyze_entry_instances(plan)
        assert report.analyzed_instances == 2
        context = parallel._instance_semantics_context
        assert context is not None and not context.unavailable
        # The project pass also validates non-entry functions. Their snapshots
        # are admitted lazily from the frozen build and exact native facts.
        snapshots = {**context.snapshots, **parallel._validation_semantics_snapshots}
        assert {scope.identity for scope, *_ in seen} == set(snapshots)
        assert any(deferred is False for _scope, _snapshot, deferred, _local, _global in seen)
        for scope, snapshot, _deferred, _local, global_semantics in seen:
            assert snapshot is snapshots[scope.identity]
            assert snapshot.scope == scope
            assert global_semantics is None
        objects = [local for _scope, _snapshot, _deferred, local, _global in seen]
        assert len({id(value) for value in objects}) == len(objects)
        for outcome in report.outcomes:
            assert outcome.semantics == "builtin_current_automatic_native_confirmed_project.v3"
    finally:
        parallel.close()


def test_current_instance_entry_hydration_uses_exact_native_owner_not_navigation(
    native_variants, monkeypatch
):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    parallel = ParallelAnalyzer(_native_config(root, cdb, root), code_index=index)

    def forbidden(*args, **kwargs):
        pytest.fail("an exact instance must not be re-resolved through navigation metadata")

    monkeypatch.setattr(
        "zscope.snapshots.modeling_input.build_semantic_model_input",
        forbidden,
    )
    try:
        parallel.freeze_instance_semantics(plan)
        entries = parallel._current_instance_entries(plan)
        assert len(entries) == 2
        assert {scope.build_context_id for _entry, scope in entries} == {
            instance.build_context_id for instance in plan.instances
        }
        assert all(entry.signature for entry, _scope in entries)
        assert all(Path(str(entry.file_path)).is_absolute() for entry, _scope in entries)
    finally:
        parallel.close()


def test_materialized_nested_objects_cannot_modify_other_consumers(frozen_context):
    context, _plan, _store = frozen_context
    snapshot = next(iter(context.snapshots.values()))
    first, first_overlay = materialize_effect_semantics(snapshot)
    second, second_overlay = materialize_effect_semantics(snapshot)
    before_bytes = snapshot.effect_payload
    before_second = deepcopy(second_overlay)
    first.type_aliases["CALLER_ONLY"] = "changed"
    first_overlay.setdefault("caller_only", {})["nested"] = ["changed"]
    assert "CALLER_ONLY" not in second.type_aliases
    assert second_overlay == before_second
    assert snapshot.effect_payload == before_bytes
    assert context.is_current(snapshot)


def test_declared_no_inferred_stage_does_not_turn_into_active_collection_failure(frozen_context):
    from zscope.core.analysis.analyzer import DEFAULT_SCAN_STEP_IDS

    context, _plan, _store = frozen_context
    snapshot = next(iter(context.snapshots.values()))
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = context.config
    analyzer.code_index = SimpleNamespace()
    analyzer.instance_scope = snapshot.scope
    analyzer._instance_semantics_snapshot = snapshot
    analyzer._instance_semantics_current = context.is_current
    analyzer.defer_validation_to_scan = True
    analyzer.semantic_result = None
    analyzer._selected_workflow_steps = lambda: [
        SimpleNamespace(id=identity, scope="entry") for identity in DEFAULT_SCAN_STEP_IDS
    ]
    analyzer._begin_instance_collection()
    analyzer.prepare_semantics()
    # Controlled zero-member stage outputs isolate the closure state machine;
    # the separate native full-chain test executes real collectors.
    for stage in ("local", "graph", "backend", "merge"):
        analyzer._observe_instance_collection(stage, lambda: [])
    for stage in ("persist", "registration"):
        analyzer._observe_instance_collection(stage, lambda: None)
    state = {"entry_identity": "controlled-entry", "impl_result": {"truncated": False}}
    analyzer._close_instance_collection(state)
    assert state["instance_collection"]["collection_closed"] is True
    assert analyzer._runtime_engine_capabilities["semantic_modeling"]["status"] == "excluded"
    analyzer._record_engine_capability(
        "graph_protocol", status="failed", active=True, reason="controlled real stage error"
    )
    analyzer._close_instance_collection(state)
    assert state["instance_collection"]["collection_closed"] is False
    assert any(
        "graph_protocol" in reason for reason in state["instance_collection"]["active_stage_errors"]
    )


def test_validator_rechecks_guard_after_memory_cache_read():
    runner = _make_runner(ScopeRecordingAgent(), build="BASE")
    live = {"current": True}

    def guard():
        if not live["current"]:
            raise ValueError("controlled current-input revocation")

    class FlipCache(ValidationResultCache):
        def get(self, key):
            value = super().get(key)
            live["current"] = False
            return value

    cache = FlipCache(16)
    cache.put("controlled-key", {"schema_version": "legacy-cache-shape", "verdict": "needs_review"})
    runner._validator_result_cache = cache
    runner._input_current_guard = guard
    with pytest.raises(ValueError, match="current-input revocation"):
        runner._validator_cache_get("controlled-key")


def test_validator_rechecks_guard_after_persistent_cache_read():
    runner = _make_runner(ScopeRecordingAgent(), build="BASE")
    live = {"current": True}

    def guard():
        if not live["current"]:
            raise ValueError("controlled persistent-input revocation")

    def load(*args, **kwargs):
        live["current"] = False
        return {"schema_version": "legacy-cache-shape", "verdict": "needs_review"}

    runner.snapshot_store.load_validation_result = load
    runner._input_current_guard = guard
    with pytest.raises(ValueError, match="persistent-input revocation"):
        runner._validator_cache_get("controlled-persistent-key")
    assert runner._validator_result_cache.get("controlled-persistent-key") is None
