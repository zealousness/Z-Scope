"""Current-input admission around real native instance semantic snapshots."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from test_instance_analysis import _native_config, _native_index, native_variants
from test_scan_checkpoint_resume import _record_answer
from zscope.config.function_entry import FunctionEntry
from zscope.config.user_config_store import UserConfigStore
from zscope.config.user_config_workbook import UserConfigWorkbook
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.instance_semantics_context import (
    current_dependencies,
    exact_inputs_current,
    freeze_instance_context,
    freeze_workbook,
)
from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint
from zscope.retrieval.instance_index import (
    instance_scope_from_entry_instance,
    wrap_scoped_code_index,
)


@pytest.fixture
def frozen_context(native_variants):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    config = _native_config(root, cdb, root)
    store = UserConfigStore(Path(config.analysis.user_config_db))
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert len(plan.instances) == 2
    scopes = [instance_scope_from_entry_instance(instance) for instance in plan.instances]
    context = freeze_instance_context(
        config=config, code_index=index, workbook_path=store.workbook.path, scopes=scopes
    )
    assert not context.unavailable, context.unavailable
    assert len(context.snapshots) == 2
    return context, plan, store


def test_native_snapshots_are_exact_and_not_caller_constructed_authority(frozen_context):
    context, _plan, _store = frozen_context
    for snapshot in context.snapshots.values():
        assert context.is_current(snapshot)
        assert not context.is_current(replace(snapshot))
        assert context.require(snapshot.scope) is snapshot
    with pytest.raises(TypeError):
        context.snapshots["invented"] = next(iter(context.snapshots.values()))


@pytest.mark.parametrize("input_name", ["compile_commands.json", "flags.h", "unit.c"])
def test_edit_revokes_snapshot_even_when_file_times_are_restored(frozen_context, input_name):
    context, _plan, _store = frozen_context
    path = context.config.project.project_root / input_name
    before, stat = path.read_bytes(), path.stat()
    path.write_bytes(before + b"\n")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert all(not context.is_current(snapshot) for snapshot in context.snapshots.values())


def test_fresh_workbook_reader_observes_same_size_same_time_replacement(tmp_path):
    path = tmp_path / "user.xlsx"
    reader = UserConfigWorkbook(path)
    reader.upsert_external_function("custom", "manual AAA")
    first = freeze_workbook(path)
    stat = path.stat()
    # Workbook ZIP size need not stay equal; the stronger assertion is that a
    # pre-existing reader's cache never supplies the bytes frozen here.
    reader.upsert_external_function("custom", "manual BBB")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    second = freeze_workbook(path)
    assert first != second
    assert b"manual BBB" in b"".join(second.external_rows)
    assert b"manual AAA" not in b"".join(second.external_rows)


def test_workbook_change_invalidates_all_consumer_snapshots(frozen_context):
    context, _plan, store = frozen_context
    store.upsert_external_function("custom_free", "manual advisory", return_semantics="release")
    assert all(not context.is_current(snapshot) for snapshot in context.snapshots.values())


def test_business_answer_change_invalidates_and_baseline_write_does_not(frozen_context):
    context, _plan, store = frozen_context
    before = current_dependencies(context.config)
    store.upsert_finding_baseline("unrelated", "accepted", {"function": "f"})
    assert current_dependencies(context.config) == before
    _record_answer(store.db_path)
    assert current_dependencies(context.config) != before
    assert all(not context.is_current(snapshot) for snapshot in context.snapshots.values())


def test_policy_change_revokes_frozen_snapshot(frozen_context):
    context, _plan, _store = frozen_context
    context.config.analysis.entry_deadline_seconds = 37.0
    assert all(not context.is_current(snapshot) for snapshot in context.snapshots.values())


def test_missing_or_foreign_semantic_manifest_cannot_fingerprint(frozen_context):
    context, plan, _store = frozen_context
    assert compute_plan_fingerprint(plan, context.config, semantics_by_instance={}) is None
    mapping = dict(context.snapshots)
    first, second = list(mapping)
    mapping[first] = mapping[second]
    assert compute_plan_fingerprint(plan, context.config, semantics_by_instance=mapping) is None
    fingerprint = compute_plan_fingerprint(
        plan, context.config, semantics_by_instance=context.snapshots
    )
    assert fingerprint is not None
    changed = dict(context.snapshots)
    changed[first] = replace(changed[first], digest="f" * 64)
    assert (
        compute_plan_fingerprint(plan, context.config, semantics_by_instance=changed) != fingerprint
    )


def test_exact_currentness_does_not_reuse_facade_probe_after_input_edit(frozen_context):
    context, _plan, _store = frozen_context
    snapshot = next(iter(context.snapshots.values()))
    scoped = wrap_scoped_code_index(context.code_index, snapshot.scope)
    assert scoped.get_function_program_facts(snapshot.scope.usr, snapshot.scope.source)["complete"]
    assert exact_inputs_current(scoped, snapshot.scope)
    path = context.config.project.compile_commands_path
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert not exact_inputs_current(scoped, snapshot.scope)


@pytest.mark.parametrize(
    "source_path",
    [
        "semantics/instance_semantics.py",
        "core/candidates/graph.py",
        "core/candidates/cpp_domains/resource_lifecycle.py",
        "core/candidates/cpp_domains/shared_access.py",
        "orchestration/jobs/instance_results.py",
    ],
)
def test_current_producer_or_effect_consumer_source_change_revokes_recovery_context(
    frozen_context, monkeypatch, source_path
):
    from zscope.orchestration import instance_semantics_context as context_module

    context, _plan, _store = frozen_context
    snapshots = list(context.snapshots.values())
    assert all(context.is_current(snapshot) for snapshot in snapshots)
    resource_files = context_module.files
    selected = resource_files("zscope").joinpath(source_path)

    class ResourceView:
        def __init__(self, resource):
            self.resource = resource

        def joinpath(self, *parts):
            return ResourceView(self.resource.joinpath(*parts))

        def read_bytes(self):
            raw = self.resource.read_bytes()
            return raw + b"\n# controlled source revision\n" if self.resource == selected else raw

        def __getattr__(self, name):
            return getattr(self.resource, name)

    # Change the source view without modifying any shared source on disk.
    # Config, registry revision, workbook and native input remain unchanged.
    monkeypatch.setattr(
        context_module, "files", lambda package: ResourceView(resource_files(package))
    )
    assert current_dependencies(context.config) != context.dependencies
    assert all(not context.is_current(snapshot) for snapshot in snapshots)
