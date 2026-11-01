"""Real native authority must expire when its emitting inputs lose currency.

Only read-only digest/stat views change after the real factory has authorized
the physical host glibc declarations. No shared tool, library or header is edited.
"""

from __future__ import annotations

import json
import os
import stat
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_instance_analysis import _native_config, _native_index
from test_job_bound_completion import binding
from test_job_bound_instance_results import settled_context, settle, queue_status, trusted
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.instance_semantics_context import exact_inputs_current
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.instance_index import wrap_scoped_code_index
from zscope.retrieval import indexing_identity
from zscope.semantics import instance_semantics
from zscope.semantics.instance_semantics import materialize_effect_semantics


@pytest.fixture(scope="module")
def native_project(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("native-currentness-r33")
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    assert executable and Path(executable).is_file(), "real native tool required; no skip"
    source = tmp_path / "unit.c"
    source.write_text(
        "#include <stdlib.h>\nvoid f(void){void *p=malloc(4);free(p);}\n", encoding="utf-8"
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                dict(
                    directory=str(tmp_path),
                    file=str(source),
                    arguments=["clang", "-c", str(source)],
                )
            ]
        ),
        encoding="utf-8",
    )
    # The semantics authority is an ordinary project file.  It must exist
    # before the native namespace receipt is captured; creating it afterwards
    # is correctly treated as a new include-search member.
    from zscope.config.project_semantics import render_empty_project_semantics

    (tmp_path / "zscope.semantics.yaml").write_text(
        render_empty_project_semantics(), encoding="utf-8"
    )
    protected = pytest.MonkeyPatch()
    protected.setattr(ClangBackend, "_ensure_extractor", lambda self: pytest.fail("LSP"))
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    index = _native_index(backend, tmp_path, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert len(plan.instances) == 1
    try:
        yield index, plan, tmp_path, cdb
    finally:
        backend.close()
        protected.undo()


@pytest.fixture
def native_context(native_project):
    index, plan, tmp_path, cdb = native_project
    parallel = ParallelAnalyzer(_native_config(tmp_path, cdb, tmp_path), code_index=index)
    try:
        context = parallel.freeze_instance_semantics(plan)
        assert not context.unavailable, context.unavailable
        (snapshot,) = context.snapshots.values()
        assert context.require(snapshot.scope) is snapshot
        local, overlay = materialize_effect_semantics(snapshot)
        assert "malloc" in local.allocators and "free" in local.deallocators
        assert overlay["symbol_origins"]["malloc"] == instance_semantics.ORIGIN_SYSTEM_RECEIPT
        assert overlay["symbol_origins"]["free"] == instance_semantics.ORIGIN_SYSTEM_RECEIPT
        scoped = wrap_scoped_code_index(index, snapshot.scope)
        (record,) = scoped.get_build_contexts(snapshot.scope.source)
        binary = record["tool"]["binary"]
        assert binary["shared_libraries"], "real dynamically linked indexer required"
        yield SimpleNamespace(
            context=context,
            snapshot=snapshot,
            scoped=scoped,
            record=record,
            parallel=parallel,
            plan=plan,
            binary=binary,
            index=index,
        )
    finally:
        parallel.close()


def digest_view(monkeypatch, path, value):
    original = indexing_identity.file_digest

    def observed(candidate):
        return value if Path(candidate) == path else original(candidate)

    monkeypatch.setattr(indexing_identity, "file_digest", observed)
    # The immutable S01 module imports the same read-only digest operation.
    monkeypatch.setattr(instance_semantics, "file_digest", observed)


def trust_view(monkeypatch, path, change):
    original_lstat = Path.lstat
    original_resolve = Path.resolve

    def observed(candidate):
        info = original_lstat(candidate)
        if candidate != path:
            return info
        if change == "missing":
            raise FileNotFoundError(str(candidate))
        fields = list(info)
        if change == "uid":
            fields[4] = 1000
        elif change == "group_write":
            fields[0] |= stat.S_IWGRP
        elif change == "other_write":
            fields[0] |= stat.S_IWOTH
        elif change == "symlink":
            fields[0] = stat.S_IFLNK | 0o777
        else:
            raise AssertionError(change)
        return os.stat_result(fields)

    def resolved(candidate, *args, **kwargs):
        physical_header = candidate in {
            Path("/usr/include/stdlib.h"),
            Path("/usr/include/features.h"),
        }
        if change == "symlink" and (
            candidate == path or (physical_header and path in candidate.parents)
        ):
            return Path("/controlled-untrusted-installation") / candidate.name
        return original_resolve(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", observed)
    monkeypatch.setattr(Path, "resolve", resolved)


def assert_revoked(native):
    assert not exact_inputs_current(native.scoped, native.snapshot.scope)
    assert not native.context.is_current(native.snapshot)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        native.context.require(native.snapshot.scope)


def test_real_glibc_authority_stays_current(native_context):
    native = native_context
    assert exact_inputs_current(native.scoped, native.snapshot.scope)
    native.parallel.require_current_instance_inputs()
    assert native.context.require(native.snapshot.scope) is native.snapshot


@pytest.mark.parametrize("input_kind", ["binary", "library"])
@pytest.mark.parametrize("change", ["changed", "missing", "unknown"])
def test_native_bytes_change_revokes_frozen_authority(
    native_context, monkeypatch, input_kind, change
):
    native = native_context
    path = Path(
        native.binary["path"]
        if input_kind == "binary"
        else next(iter(native.binary["shared_libraries"]))
    )
    digest_view(
        monkeypatch, path, {"changed": "0" * 64, "missing": "missing", "unknown": ""}[change]
    )
    assert_revoked(native)


@pytest.mark.parametrize("header", ["stdlib.h", "features.h"])
@pytest.mark.parametrize("change", ["uid", "group_write", "other_write", "symlink", "missing"])
def test_physical_glibc_header_trust_loss_revokes_authority(
    native_context, monkeypatch, header, change
):
    trust_view(monkeypatch, Path("/usr/include") / header, change)
    if change in {"symlink", "missing"}:
        # The pre-existing namespace scan already observes these views (and can
        # raise while reading the physical non-symlink fixture). Public currency
        # must remain fail closed. These are existing-rejection controls, not new
        # evidence for the missing uid/mode/tool revocation fixed in this change.
        assert not native_context.context.is_current(native_context.snapshot)
        with pytest.raises(ValueError, match="instance_semantics_not_current"):
            native_context.context.require(native_context.snapshot.scope)
    else:
        assert_revoked(native_context)


@pytest.mark.parametrize("component", ["/usr/include", "/usr", "/"])
@pytest.mark.parametrize("change", ["uid", "group_write", "symlink", "missing"])
def test_physical_glibc_parent_trust_loss_revokes_authority(
    native_context, monkeypatch, component, change
):
    trust_view(monkeypatch, Path(component), change)
    assert_revoked(native_context)


@pytest.mark.parametrize(
    "field", ["tool", "binary", "path", "sha256", "shared_libraries", "loader"]
)
def test_missing_native_identity_is_unknown_after_freeze(native_context, monkeypatch, field):
    native = native_context
    original = native.index.get_build_contexts

    def observed(*args, **kwargs):
        records = deepcopy(original(*args, **kwargs))
        for record in records:
            if record["build_context_id"] != native.snapshot.scope.build_context_id:
                continue
            if field == "tool":
                record.pop("tool")
            elif field == "binary":
                record["tool"].pop("binary")
            elif field == "loader":
                record["tool"]["binary"]["unverified_loader_run"] = "unknown"
            else:
                record["tool"]["binary"].pop(field)
        return records

    # Only the subsequent persisted-record read becomes incomplete. The native
    # factory and initial exact context are real and remain unmodified.
    monkeypatch.setattr(native.index, "get_build_contexts", observed)
    assert_revoked(native)


@pytest.mark.parametrize("change", ["binary", "library", "header"])
def test_actual_consumer_guard_and_collection_cannot_keep_old_effects(
    native_context, monkeypatch, change
):
    native = native_context
    batch = native.parallel.open_instance_batch(native.plan)
    try:
        native.parallel.run_instance_batch(batch, [native.snapshot.scope.identity])
        native.parallel.require_instance_collection_closed(
            batch, identity=native.snapshot.scope.identity
        )
        if change == "header":
            trust_view(monkeypatch, Path("/usr/include/features.h"), "group_write")
        else:
            path = Path(
                native.binary["path"]
                if change == "binary"
                else next(iter(native.binary["shared_libraries"]))
            )
            digest_view(monkeypatch, path, "0" * 64)
        with pytest.raises(ValueError, match="instance_semantics_not_current"):
            native.parallel.require_current_instance_inputs()
        with pytest.raises(ValueError, match="instance_semantics_not_current"):
            native.parallel.require_instance_collection_closed(
                batch, identity=native.snapshot.scope.identity
            )
        entry, scope = batch.scoped_entries[0]
        with pytest.raises(ValueError, match="instance_semantics_not_current"):
            native.parallel._instance_semantic_snapshot(scope)
    finally:
        native.parallel.abandon_instance_batch(batch)


@pytest.mark.parametrize("change", ["binary", "library", "header"])
def test_actual_analyzer_constructor_and_recovery_identity_recheck(
    native_context, monkeypatch, change
):
    from zscope.orchestration.jobs.scan_work import current_recovery_identity

    native = native_context
    before = current_recovery_identity(
        analyzer=native.parallel,
        job_id="native-currentness",
        input_revision="current-input",
        plan_fingerprint="a" * 64,
    )
    assert before.semantics_digest == native.context.manifest_digest()
    if change == "header":
        trust_view(monkeypatch, Path("/usr/include/stdlib.h"), "uid")
    else:
        path = Path(
            native.binary["path"]
            if change == "binary"
            else next(iter(native.binary["shared_libraries"]))
        )
        digest_view(monkeypatch, path, "0" * 64)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        Analyzer(
            native.parallel.base_config,
            code_index=native.scoped,
            instance_scope=native.snapshot.scope,
            instance_semantics_snapshot=native.snapshot,
            instance_semantics_current=native.context.is_current,
        )
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        current_recovery_identity(
            analyzer=native.parallel,
            job_id="native-currentness",
            input_revision="current-input",
            plan_fingerprint="a" * 64,
        )


@pytest.mark.parametrize("change", ["binary", "library", "header"])
def test_real_store_queue_rejects_revoked_native_guard(
    native_context, settled_context, monkeypatch, change
):
    """Actual SQL/claim consumer with controlled neutral codec data and a real native guard.

    This does not claim native producer closure: that remains the strict collection
    test above and the existing partial-recovery integration suite.
    """
    native = native_context
    native.parallel.require_current_instance_inputs()
    if change == "header":
        trust_view(monkeypatch, Path("/usr/include/features.h"), "other_write")
    else:
        path = Path(
            native.binary["path"]
            if change == "binary"
            else next(iter(native.binary["shared_libraries"]))
        )
        digest_view(monkeypatch, path, "0" * 64)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        settle(settled_context, input_current_guard=native.parallel.require_current_instance_inputs)
    assert queue_status(settled_context[7], settled_context[8]) == "active"
    assert trusted(settled_context) == ()


def test_real_store_late_native_revocation_cannot_publish_receipt(
    native_context, settled_context, monkeypatch
):
    native = native_context
    queue = settled_context[7]
    original = queue.settle

    def actual_settlement_then_change(*args, **kwargs):
        result = original(*args, **kwargs)
        digest_view(monkeypatch, Path(native.binary["path"]), "0" * 64)
        return result

    monkeypatch.setattr(queue, "settle", actual_settlement_then_change)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        settle(settled_context, input_current_guard=native.parallel.require_current_instance_inputs)
    # Store and queue are distinct transactions: the committed queue is retained,
    # but no bound receipt or settlement acknowledgement is published.
    assert queue_status(queue, settled_context[8]) == "completed"
    assert trusted(settled_context) == ()


@pytest.mark.parametrize("change", ["uid", "group_write"])
@pytest.mark.parametrize("consumer", ["require", "classifier"])
def test_removed_used_header_receipt_cannot_retain_standard_authority(
    native_context, monkeypatch, change, consumer
):
    from zscope.orchestration.parallel_analyzer import _InstanceEntryLookupIndex

    native = native_context
    header = "/usr/include/features.h"
    assert header in native.record["dependencies"]
    assert "/usr/include/stdlib.h" in native.record["dependencies"]
    ((entry, scope),) = native.parallel._current_instance_entries(native.plan)
    assert scope == native.snapshot.scope
    lookup = _InstanceEntryLookupIndex(native.index, scope, entry, semantics_context=native.context)
    assert lookup.call_model_status("malloc", "f") == "standard_model"
    assert lookup.call_model_status("free", "f") == "standard_model"
    original = native.index.get_build_contexts

    def observed(*args, **kwargs):
        records = deepcopy(original(*args, **kwargs))
        for record in records:
            if record["build_context_id"] == scope.build_context_id:
                record["dependencies"].pop(header)
        return records

    # Only the later read loses one actually used dependency receipt. Native
    # facts, source, build identity, complete flag and stdlib receipt stay real.
    monkeypatch.setattr(native.index, "get_build_contexts", observed)
    (current,) = native.scoped.get_build_contexts(scope.source)
    assert current["build_context_id"] == native.record["build_context_id"]
    assert current["source"] == native.record["source"]
    assert current["dependencies_complete"] is True
    assert current["dependencies"] == {
        path: digest for path, digest in native.record["dependencies"].items() if path != header
    }
    trust_view(monkeypatch, Path(header), change)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        if consumer == "require":
            native.context.require(scope)
        else:
            lookup.call_model_status("malloc", "f")
    assert not native.context.is_current(native.snapshot)


def test_native_without_standard_authority_does_not_require_unused_glibc_headers(
    tmp_path, monkeypatch
):
    from zscope.orchestration.parallel_analyzer import _InstanceEntryLookupIndex

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    assert executable and Path(executable).is_file(), "real native tool required; no skip"
    source = tmp_path / "unit.c"
    source.write_text("void f(void){}\n", encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                dict(
                    directory=str(tmp_path),
                    file=str(source),
                    arguments=["clang", "-c", str(source)],
                )
            ]
        ),
        encoding="utf-8",
    )
    from zscope.config.project_semantics import render_empty_project_semantics

    (tmp_path / "zscope.semantics.yaml").write_text(
        render_empty_project_semantics(), encoding="utf-8"
    )
    monkeypatch.setattr(ClangBackend, "_ensure_extractor", lambda self: pytest.fail("LSP"))
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    index = _native_index(backend, tmp_path, cdb)
    parallel = ParallelAnalyzer(_native_config(tmp_path, cdb, tmp_path), code_index=index)
    try:
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        assert len(plan.instances) == 1
        context = parallel.freeze_instance_semantics(plan)
        assert not context.unavailable, context.unavailable
        (snapshot,) = context.snapshots.values()
        assert context.require(snapshot.scope) is snapshot
        local, overlay = materialize_effect_semantics(snapshot)
        assert "malloc" not in local.allocators and "free" not in local.deallocators
        assert instance_semantics.ORIGIN_SYSTEM_RECEIPT not in overlay["symbol_origins"].values()
        scoped = wrap_scoped_code_index(index, snapshot.scope)
        (record,) = scoped.get_build_contexts(snapshot.scope.source)
        for header in ("/usr/include/stdlib.h", "/usr/include/features.h"):
            assert header not in record["dependencies"]
        ((entry, scope),) = parallel._current_instance_entries(plan)
        lookup = _InstanceEntryLookupIndex(index, scope, entry, semantics_context=context)
        assert lookup.call_model_status("malloc", "f") == "source_unavailable"
        # Unused physical headers cannot become new prerequisites for this
        # actual native snapshot, which grants no standard-library authority.
        for header in ("/usr/include/stdlib.h", "/usr/include/features.h"):
            trust_view(monkeypatch, Path(header), "uid")
        assert context.require(scope) is snapshot
        parallel.require_current_instance_inputs()
        assert lookup.call_model_status("malloc", "f") == "source_unavailable"
    finally:
        parallel.close()
        backend.close()
