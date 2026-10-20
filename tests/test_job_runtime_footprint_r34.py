"""Real native job runtime writes must preserve exact compilation inputs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from test_scan_session_instances import (
    _config,
    _forbid_global_modeling,
    _instance_analysis,
    _read_report,
    _write_project,
)
from test_scan_session_jobs import (
    JOB_ID,
    _bind_job_env,
    _completed_by_kind,
    _job_store,
    _run_dir,
)
from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.instance_semantics import materialize_effect_semantics


JOB_ENV = (
    "ZSCOPE_JOB_STORE",
    "ZSCOPE_JOB_ID",
    "ZSCOPE_JOB_RUN_ID",
    "ZSCOPE_JOB_OWNER_TOKEN",
    "ZSCOPE_JOB_RUN_DIR",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _files(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): _digest(path)
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.fixture
def project(tmp_path, monkeypatch):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    _forbid_global_modeling(monkeypatch)
    _write_project(tmp_path)
    store = _job_store(tmp_path)
    _bind_job_env(monkeypatch, tmp_path, store)
    return tmp_path, store


def _add_lookup(root: Path, name: str, *, source_prefix: str, found: bool = True):
    high = _run_dir(root)
    low = root / "lower-priority-headers"
    low.mkdir()
    target = low / name
    if found:
        target.write_text("#define FOOTPRINT_HEADER_VALUE 7\n", encoding="utf-8")
    source = root / "unit.c"
    source.write_text(source_prefix + source.read_text(encoding="utf-8"), encoding="utf-8")
    database = root / "compile_commands.json"
    rows = json.loads(database.read_text(encoding="utf-8"))
    for row in rows:
        row["arguments"][1:1] = ["-I", str(high), "-I", str(low)]
    database.write_text(json.dumps(rows), encoding="utf-8")
    return high, target


def _after_actual_freeze(monkeypatch, change):
    original = ParallelAnalyzer.freeze_instance_semantics
    observed = {"contexts": [], "changed": False}

    def freeze(analyzer, plan):
        context = original(analyzer, plan)
        if all(context is not item for item in observed["contexts"]):
            observed["contexts"].append(context)
        if observed["changed"]:
            return context
        assert len(context.snapshots) == 2, context.unavailable
        assert all(context.is_current(item) for item in context.snapshots.values())
        change(context)
        observed["changed"] = True
        observed["after"] = [context.is_current(item) for item in context.snapshots.values()]
        return context

    monkeypatch.setattr(ParallelAnalyzer, "freeze_instance_semantics", freeze)
    return observed


def test_native_positive_baseline_without_job_outputs(tmp_path, monkeypatch):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    for name in JOB_ENV:
        monkeypatch.delenv(name, raising=False)
    _forbid_global_modeling(monkeypatch)
    _write_project(tmp_path)
    ScanSessionRunner(_config(tmp_path), task_id="footprint/baseline").run()
    analysis = _instance_analysis(_read_report(tmp_path / "report.json"))
    assert analysis["analyzed_instances"] == 2
    assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1]


@pytest.mark.parametrize("batch", [False, True])
def test_bound_project_runtime_outputs_close_real_queue(project, batch):
    root, _store = project
    config = _config(root, single=not batch, entry_list=batch)
    task = "footprint/batch" if batch else "footprint/single"
    ScanSessionRunner(config, task_id=task).run()
    report_path = root / ("zscope_batch_report_footprint_batch.json" if batch else "report.json")
    report = _read_report(report_path)
    analysis = _instance_analysis(report)
    assert analysis["analyzed_instances"] == 2
    assert analysis["instance_scope_complete"] is True
    assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1]
    assert report["metadata"]["job"]["checkpointed"] is True
    assert report["metadata"]["job"]["remaining_count"] == 0
    assert _completed_by_kind(root) == {
        "instance_analysis": 2,
        "instance_validation": 1,
        "instance_checkpoint": 1,
    }
    assert (_run_dir(root) / "instance-checkpoint.json").is_file()
    assert len(list((_run_dir(root) / "instance-results").glob("*.json"))) == 2
    assert (_run_dir(root) / "pending.json").is_file()
    assert report["metadata"]["job"]["executed_instances"] == 2


@pytest.mark.parametrize("missing_high", [False, True])
@pytest.mark.parametrize("macro", [False, True])
def test_ordinary_include_shadow_revokes_with_old_target_unchanged(
    project, monkeypatch, missing_high, macro
):
    root, _store = project
    prefix = (
        '#define FOOTPRINT_HEADER "ordinary.h"\n#include FOOTPRINT_HEADER\n'
        if macro
        else '#include "ordinary.h"\n'
    )
    high, old = _add_lookup(root, "ordinary.h", source_prefix=prefix)
    if not missing_high:
        high.mkdir(parents=True)
    old_hash = _digest(old)

    def shadow(context):
        snapshot = next(iter(context.snapshots.values()))
        materialize_effect_semantics(context.require(snapshot.scope))
        high.mkdir(parents=True, exist_ok=True)
        (high / "ordinary.h").write_text("#define FOOTPRINT_HEADER_VALUE 99\n", encoding="utf-8")

    observed = _after_actual_freeze(monkeypatch, shadow)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        ScanSessionRunner(_config(root), task_id="footprint/ordinary-shadow").run()
    assert observed["changed"] is True
    assert observed["after"] == [False, False]
    assert _digest(old) == old_hash
    context = observed["contexts"][0]
    for snapshot in context.snapshots.values():
        with pytest.raises(ValueError, match="instance_semantics_not_current"):
            materialize_effect_semantics(context.require(snapshot.scope))


@pytest.mark.parametrize("found", [False, True])
@pytest.mark.parametrize("angled", [False, True])
def test_has_include_change_revokes_independently(project, monkeypatch, found, angled):
    root, _store = project
    spelling = "<probe.lookup>" if angled else '"probe.lookup"'
    high, old = _add_lookup(
        root,
        "probe.lookup",
        source_prefix=f"#if __has_include({spelling})\n#define PROBE_PRESENT 1\n#endif\n",
        found=found,
    )
    old_hash = _digest(old) if found else None

    def create(context):
        for raw in context.native_input_receipts.values():
            contexts = json.loads(raw)
            queries = [query for row in contexts for query in row["include_probes"]["queries"]]
            probe = [query for query in queries if query["name"] == "probe.lookup"]
            assert len(probe) == 1 and probe[0]["found"] is found
        high.mkdir(parents=True, exist_ok=True)
        (high / "probe.lookup").write_text("#define NEW_PROBE 1\n", encoding="utf-8")

    observed = _after_actual_freeze(monkeypatch, create)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        ScanSessionRunner(_config(root), task_id="footprint/probe-shadow").run()
    assert observed["changed"] and observed["after"] == [False, False]
    if found:
        assert _digest(old) == old_hash
    else:
        assert not old.exists()


@pytest.mark.parametrize("edited", ["source", "header"])
def test_entered_dependency_content_still_revokes(project, monkeypatch, edited):
    root, _store = project
    _high, header = _add_lookup(root, "entered.h", source_prefix='#include "entered.h"\n')
    target = root / "unit.c" if edited == "source" else header

    def edit(_context):
        target.write_text(
            target.read_text(encoding="utf-8") + "\n/* changed input */\n", encoding="utf-8"
        )

    observed = _after_actual_freeze(monkeypatch, edit)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        ScanSessionRunner(_config(root), task_id="footprint/dependency-edit").run()
    assert observed["changed"] and observed["after"] == [False, False]


@pytest.mark.parametrize("name", ["unowned.h", "new-source.c", "unowned.json"])
def test_unknown_runtime_directory_names_are_not_filtered(project, monkeypatch, name):
    root, _store = project

    def add(_context):
        directory = _run_dir(root)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text("/* unowned new name */\n", encoding="utf-8")

    observed = _after_actual_freeze(monkeypatch, add)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        ScanSessionRunner(_config(root), task_id="footprint/unowned").run()
    assert observed["changed"] and observed["after"] == [False, False]


@pytest.mark.parametrize("alias", ["hardlink", "symlink"])
def test_direct_header_output_alias_is_refused_before_runtime_writes(project, alias):
    root, _store = project
    _high, header = _add_lookup(root, "entered.h", source_prefix='#include "entered.h"\n')
    directory = _run_dir(root)
    directory.mkdir(parents=True)
    output = directory / "pending.json"
    if alias == "symlink":
        output.symlink_to(header)
    else:
        output.hardlink_to(header)
    before = _files(directory)
    header_hash = _digest(header)
    with pytest.raises((ValueError, JobError)):
        ScanSessionRunner(_config(root), task_id="footprint/alias-overlap").run()
    assert _files(directory) == before, "overlap must be refused before queue/pending writes"
    assert _digest(header) == header_hash
    assert output.samefile(header)


@pytest.mark.parametrize("invalid", ["owner", "run", "input"])
def test_invalid_binding_creates_no_runtime_outputs(project, monkeypatch, invalid):
    root, store = project
    if invalid == "owner":
        monkeypatch.setenv("ZSCOPE_JOB_OWNER_TOKEN", "a-foreign-owner")
    elif invalid == "run":
        monkeypatch.setenv("ZSCOPE_JOB_RUN_ID", "a-foreign-run")
    else:
        row = store.get_job(JOB_ID)
        assert row is not None
        store.update_job(
            JOB_ID, expected_revision=row["revision"], updates={"input_revision": "unbound-input"}
        )
    before = _files(_run_dir(root))
    database_hash = _digest(store.db_path)
    with pytest.raises(JobError):
        ScanSessionRunner(_config(root), task_id="footprint/invalid-binding").run()
    assert _files(_run_dir(root)) == before
    assert _digest(store.db_path) == database_hash
    assert not (root / "report.json").exists()
    assert not (root / "report.md").exists()


def test_native_lookup_receipt_captures_macro_and_nested_system_reads(project, monkeypatch):
    root, _store = project
    _high, _header = _add_lookup(
        root,
        "macro.h",
        source_prefix='#define HEADER_TO_READ "macro.h"\n#include HEADER_TO_READ\n',
    )
    captured = []
    original = ParallelAnalyzer.freeze_instance_semantics

    def freeze(analyzer, plan):
        context = original(analyzer, plan)
        if not captured:
            assert len(context.snapshots) == 2, context.unavailable
            for raw in context.native_input_receipts.values():
                row = json.loads(raw)[0]
                receipt = row.get("include_lookups")
                assert isinstance(receipt, dict), "new ordinary native lookup receipt required"
                assert receipt["version"] == "zscope.include-lookups.v1"
                assert receipt["complete"] is True
                queries = receipt["queries"]
                assert any(query["name"] == "macro.h" and query["found"] for query in queries)
                assert any(
                    not Path(query["including_file"]).is_relative_to(root) for query in queries
                )
                captured.append(receipt)
        return context

    monkeypatch.setattr(ParallelAnalyzer, "freeze_instance_semantics", freeze)
    ScanSessionRunner(_config(root), task_id="footprint/native-receipt").run()
    assert len(captured) == 2


def test_old_owner_context_cannot_inherit_new_owner_permission(project, monkeypatch):
    root, store = project

    def handoff(_context):
        row = store.get_job(JOB_ID)
        assert row is not None
        store.update_job(
            JOB_ID, expected_revision=row["revision"], updates={"owner_token": "replacement-owner"}
        )

    observed = _after_actual_freeze(monkeypatch, handoff)
    with pytest.raises((ValueError, JobError)):
        ScanSessionRunner(_config(root), task_id="footprint/first-owner").run()
    assert observed["changed"] and observed["after"] == [False, False]
    monkeypatch.setenv("ZSCOPE_JOB_OWNER_TOKEN", "replacement-owner")
    ScanSessionRunner(_config(root), task_id="footprint/replacement-owner").run()
    assert len(observed["contexts"]) == 2
    assert observed["contexts"][0] is not observed["contexts"][1]
    assert _instance_analysis(_read_report(root / "report.json"))["analyzed_instances"] == 2


@pytest.mark.parametrize("kind", ["ordinary", "found_probe", "negative_probe"])
def test_exact_declared_output_lookup_conflict_is_refused_before_writes(project, monkeypatch, kind):
    root, _store = project
    prefix = (
        '#include "pending.json"\n'
        if kind == "ordinary"
        else '#if __has_include("pending.json")\n#define PENDING_HEADER_PRESENT 1\n#endif\n'
    )
    _high, old = _add_lookup(
        root, "pending.json", source_prefix=prefix, found=kind != "negative_probe"
    )
    old_hash = _digest(old) if old.is_file() else None
    original = ScanSessionRunner._build_entry_instance_plan
    plans = []

    def plan(runner, state):
        result = original(runner, state)
        assert len(result.instances) == 2, result
        plans.append(result)
        return result

    monkeypatch.setattr(ScanSessionRunner, "_build_entry_instance_plan", plan)
    before = _files(_run_dir(root))
    with pytest.raises((ValueError, JobError)):
        ScanSessionRunner(_config(root), task_id="footprint/declared-collision").run()
    assert plans, "real native two-variant plan must precede filtering refusal"
    assert _files(_run_dir(root)) == before
    if old_hash is not None:
        assert _digest(old) == old_hash


@pytest.mark.parametrize("removed", ["file", "directory"])
def test_original_namespace_members_cannot_be_removed_by_filter(project, monkeypatch, removed):
    root, _store = project
    directory = _run_dir(root)
    directory.mkdir(parents=True)
    target = directory / "pending.json"
    if removed == "file":
        target.write_text('{"existing":true}\n', encoding="utf-8")

    def delete(_context):
        if removed == "file":
            target.unlink()
        else:
            directory.rmdir()

    observed = _after_actual_freeze(monkeypatch, delete)
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        ScanSessionRunner(_config(root), task_id="footprint/existing-name").run()
    assert observed["changed"] and observed["after"] == [False, False]


def test_old_tool_without_ordinary_lookup_receipt_cannot_authorize_outputs(project):
    root, _store = project
    config = _config(root)
    config.indexing.clang_indexer_path = (
        "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
    )
    before = _files(_run_dir(root))
    with pytest.raises((ValueError, JobError)):
        ScanSessionRunner(config, task_id="footprint/old-tool").run()
    assert _files(_run_dir(root)) == before


def test_missing_native_lookup_member_cannot_authorize_outputs(project, monkeypatch):
    root, _store = project
    original = CodeIndex.get_build_contexts
    observed = []

    def missing(index, file_path=""):
        rows = original(index, file_path)
        observed.extend(rows)
        result = []
        for row in rows:
            copied = dict(row)
            copied.pop("include_lookups", None)
            result.append(copied)
        return result

    monkeypatch.setattr(CodeIndex, "get_build_contexts", missing)
    before = _files(_run_dir(root))
    with pytest.raises((ValueError, JobError)):
        ScanSessionRunner(_config(root), task_id="footprint/missing-receipt").run()
    assert observed and all(row["dependencies_complete"] for row in observed)
    assert _files(_run_dir(root)) == before


def test_unsupported_include_next_refuses_filter_before_runtime_writes(project, monkeypatch):
    root, _store = project
    high, _old = _add_lookup(root, "chain.h", source_prefix="#include <chain.h>\n")
    high.mkdir(parents=True)
    (high / "chain.h").write_text("#include_next <chain.h>\n", encoding="utf-8")
    before = _files(high)
    plans = []
    original = ScanSessionRunner._build_entry_instance_plan

    def plan(runner, state):
        result = original(runner, state)
        assert len(result.instances) == 2, result
        plans.append(result)
        return result

    monkeypatch.setattr(ScanSessionRunner, "_build_entry_instance_plan", plan)
    with pytest.raises((ValueError, JobError)):
        ScanSessionRunner(_config(root), task_id="footprint/include-next").run()
    assert plans
    assert _files(high) == before


def test_include_next_does_not_downgrade_nonfiltered_legacy_inputs(tmp_path, monkeypatch):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    for name in JOB_ENV:
        monkeypatch.delenv(name, raising=False)
    _forbid_global_modeling(monkeypatch)
    _write_project(tmp_path)
    high, _old = _add_lookup(tmp_path, "chain.h", source_prefix="#include <chain.h>\n")
    high.mkdir(parents=True)
    (high / "chain.h").write_text("#include_next <chain.h>\n", encoding="utf-8")
    captured = []
    original = ParallelAnalyzer.freeze_instance_semantics

    def freeze(analyzer, plan):
        context = original(analyzer, plan)
        if not captured:
            assert len(context.snapshots) == 2, context.unavailable
            for raw in context.native_input_receipts.values():
                row = json.loads(raw)[0]
                assert row["dependencies_complete"] is True
                if row["tool"]["capability"].get("include_lookup_version") == 1:
                    assert row["include_lookups"]["complete"] is False
                captured.append(row)
        return context

    monkeypatch.setattr(ParallelAnalyzer, "freeze_instance_semantics", freeze)
    ScanSessionRunner(_config(tmp_path), task_id="footprint/legacy-include-next").run()
    assert len(captured) == 2
    assert _instance_analysis(_read_report(tmp_path / "report.json"))["analyzed_instances"] == 2


def test_absolute_entered_header_output_overlap_is_refused_before_writes(project):
    root, _store = project
    directory = _run_dir(root)
    directory.mkdir(parents=True)
    header = directory / "pending.json"
    header.write_text("#define ABSOLUTE_ENTERED_HEADER 1\n", encoding="utf-8")
    source = root / "unit.c"
    source.write_text(
        f'#include "{header}"\n' + source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    before = _files(directory)
    with pytest.raises((ValueError, JobError)):
        ScanSessionRunner(_config(root), task_id="footprint/absolute-overlap").run()
    assert _files(directory) == before


def test_direct_source_is_not_a_writable_run_directory(project, monkeypatch):
    root, store = project
    source = root / "unit.c"
    row = store.get_job(JOB_ID)
    assert row is not None
    store.update_job(JOB_ID, expected_revision=row["revision"], updates={"run_dir": str(source)})
    monkeypatch.setenv("ZSCOPE_JOB_RUN_DIR", str(source))
    source_hash = _digest(source)
    with pytest.raises((ValueError, JobError, OSError)):
        ScanSessionRunner(_config(root), task_id="footprint/source-overlap").run()
    assert _digest(source) == source_hash
    assert source.is_file()


def test_real_codec_temporary_file_blocks_concurrent_guard_and_closes_queue(project, monkeypatch):
    import sqlite3
    import threading

    from zscope.orchestration.jobs import instance_results
    from zscope.orchestration.jobs.scan_work import InstanceWorkHandlers

    root, store = project
    contexts = []
    observations = []
    original_freeze = ParallelAnalyzer.freeze_instance_semantics
    original_link = instance_results.os.link
    original_prepare = InstanceWorkHandlers._prepare_instance_completion
    actual_locks = []
    opened_connections = []
    original_connect = sqlite3.connect

    def current_observation():
        return next(
            (row for row in observations if row["worker"] is threading.current_thread()),
            None,
        )

    def observed_factory(base):
        class ConnectionObservation(base):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.observed_thread = threading.get_ident()
                self.observed_closed = False
                opened_connections.append(self)

            def execute(self, sql, parameters=(), /):
                observation = current_observation()
                acquiring = observation is not None and sql.strip().upper() == "BEGIN IMMEDIATE"
                if acquiring:
                    observation["sql_entered"].set()
                try:
                    cursor = super().execute(sql, parameters)
                except BaseException as error:
                    if acquiring:
                        observation["sql_errors"].append(error)
                    raise
                if acquiring:
                    observation["sql_acquired"].set()
                    observation["temporary_visible_on_sql_acquire"].append(
                        observation["temporary"].exists()
                    )
                return cursor

            def close(self):
                try:
                    return super().close()
                finally:
                    self.observed_closed = True

        return ConnectionObservation

    def connect(database, *args, **kwargs):
        if str(database) != str(store.db_path):
            return original_connect(database, *args, **kwargs)
        base = kwargs.get("factory", sqlite3.Connection)
        kwargs["factory"] = observed_factory(base)
        return original_connect(database, *args, **kwargs)

    class LockObservation:
        def __init__(self, actual):
            self.actual = actual

        def acquire(self, *args, **kwargs):
            observation = current_observation()
            if observation is not None:
                assert observation[
                    "sql_acquired"
                ].is_set(), "Store must be acquired before namespace"
                observation["entered"].set()
            try:
                acquired = self.actual.acquire(*args, **kwargs)
            except BaseException as error:
                if observation is not None:
                    observation["acquire_errors"].append(error)
                raise
            if observation is not None and acquired:
                observation["acquired"].set()
                observation["temporary_visible_on_acquire"].append(
                    observation["temporary"].exists()
                )
            return acquired

        def release(self):
            return self.actual.release()

        def __enter__(self):
            return self.acquire()

        def __exit__(self, *exception):
            return self.actual.__exit__(*exception)

        def __getattr__(self, name):
            return getattr(self.actual, name)

    def freeze(analyzer, plan):
        context = original_freeze(analyzer, plan)
        assert len(context.snapshots) == 2, context.unavailable
        if all(context is not known for known in contexts):
            contexts.append(context)
            scope = context.code_index._job_runtime_outputs
            assert scope is not None, "actual factory-issued job output scope required"
            actual_locks.append(scope._lock)
            monkeypatch.setattr(scope, "_lock", LockObservation(scope._lock))
        return context

    def link(source, target, *args, **kwargs):
        temporary, output = Path(source), Path(target)
        if output.parent != _run_dir(root) / "instance-results":
            return original_link(source, target, *args, **kwargs)
        assert len(contexts) == 1
        assert actual_locks[0]._is_owned(), "the real publisher must hold the actual scope lock"
        assert any(
            connection.observed_thread == threading.get_ident()
            and not connection.observed_closed
            and connection.in_transaction
            for connection in opened_connections
        ), "the publisher must hold a real live JobStore SQL transaction"
        assert temporary.is_file() and not output.exists()
        assert temporary.name.startswith(f".{output.name}.tmp-{os.getpid()}-")
        assert temporary.read_bytes()
        entered, acquired, finished = threading.Event(), threading.Event(), threading.Event()
        observation = {
            "temporary": temporary,
            "output": output,
            "entered": entered,
            "acquired": acquired,
            "finished": finished,
            "errors": [],
            "acquire_errors": [],
            "temporary_visible_on_acquire": [],
            "required": [],
            "sql_entered": threading.Event(),
            "sql_acquired": threading.Event(),
            "sql_errors": [],
            "temporary_visible_on_sql_acquire": [],
        }

        def consume():
            try:
                for snapshot in contexts[0].snapshots.values():
                    required = contexts[0].require(snapshot.scope)
                    materialize_effect_semantics(required)
                    observation["required"].append(required)
                observation["temporary_visible_after_require"] = temporary.exists()
            except BaseException as error:
                observation["errors"].append(error)
            finally:
                finished.set()

        worker = threading.Thread(target=consume, daemon=True)
        observation["worker"] = worker
        observations.append(observation)
        worker.start()
        assert observation["sql_entered"].wait(
            5
        ), "the consumer must actually attempt BEGIN IMMEDIATE"
        assert not observation[
            "sql_acquired"
        ].is_set(), "the consumer must wait for the real Store fence"
        assert not entered.is_set(), "a blocked Store acquisition precedes namespace acquisition"
        assert not acquired.is_set()
        assert not finished.wait(0.1), "a guard cannot consume the codec temporary namespace"
        assert temporary.is_file(), "the original codec temporary remains visible"
        return original_link(source, target, *args, **kwargs)

    def prepare(handlers, batch, identity):
        request = original_prepare(handlers, batch, identity)
        for observation in observations:
            observation["worker"].join(10)
            assert not observation["worker"].is_alive(), "guard must finish after publication"
            assert observation["finished"].is_set()
            assert observation["errors"] == []
            assert observation["acquire_errors"] == []
            assert observation["sql_errors"] == []
            assert observation["sql_acquired"].is_set()
            assert observation["temporary_visible_on_sql_acquire"]
            assert not any(observation["temporary_visible_on_sql_acquire"])
            assert observation["entered"].is_set()
            assert observation["acquired"].is_set()
            assert observation["temporary_visible_on_acquire"]
            assert not any(observation["temporary_visible_on_acquire"])
            assert len(observation["required"]) == 2
            assert observation["temporary_visible_after_require"] is False
            assert not observation["temporary"].exists()
            assert observation["output"].is_file()
        return request

    monkeypatch.setattr(ParallelAnalyzer, "freeze_instance_semantics", freeze)
    monkeypatch.setattr(sqlite3, "connect", connect)
    monkeypatch.setattr(instance_results.os, "link", link)
    monkeypatch.setattr(InstanceWorkHandlers, "_prepare_instance_completion", prepare)
    ScanSessionRunner(_config(root), task_id="footprint/concurrent-codec").run()
    assert len(observations) == 2, "both real exported instance results must publish"
    assert _completed_by_kind(root) == {
        "instance_analysis": 2,
        "instance_validation": 1,
        "instance_checkpoint": 1,
    }
    report = _read_report(root / "report.json")
    assert report["metadata"]["job"]["checkpointed"] is True
    assert report["metadata"]["job"]["remaining_count"] == 0
    assert _instance_analysis(report)["analyzed_instances"] == 2
    assert not list((_run_dir(root) / "instance-results").glob(".*.tmp-*"))


@pytest.mark.parametrize("mode", ["vfs", "remap", "include_alias"])
def test_actual_ordinary_lookup_alias_modes_refuse_only_output_filter(project, monkeypatch, mode):
    from zscope.retrieval.build_context import context_input_status

    root, _store = project
    prefix = '#include "alias-original.lookup"\n'
    if mode == "include_alias":
        prefix = '#pragma include_alias("alias-original.lookup", "alias-target.lookup")\n' + prefix
    _high, original_header = _add_lookup(root, "alias-original.lookup", source_prefix=prefix)
    actual_header = original_header.with_name("alias-target.lookup")
    actual_header.write_bytes(original_header.read_bytes())
    database = root / "compile_commands.json"
    rows = json.loads(database.read_text(encoding="utf-8"))
    if mode == "vfs":
        overlay = root / "include-overlay.json"
        overlay.write_text(
            json.dumps(
                {
                    "version": 0,
                    "case-sensitive": True,
                    "use-external-names": True,
                    "roots": [
                        {
                            "type": "file",
                            "name": str(original_header),
                            "external-contents": str(actual_header),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        arguments = ["-ivfsoverlay", str(overlay)]
    elif mode == "remap":
        arguments = [
            "-Xclang",
            "-remap-file",
            "-Xclang",
            f"{original_header};{actual_header}",
        ]
    else:
        arguments = ["-fms-extensions"]
    for row in rows:
        row["arguments"][1:1] = arguments
    database.write_text(json.dumps(rows), encoding="utf-8")
    plans = []
    original_plan = ScanSessionRunner._build_entry_instance_plan

    def plan(runner, state):
        result = original_plan(runner, state)
        assert len(result.instances) == 2, result
        index = state["code_index"]
        contexts = index.get_build_contexts()
        assert len(contexts) == 2
        assert {row["build_context_id"] for row in contexts} == {
            item.build_context_id for item in result.instances
        }
        for row in contexts:
            assert row["dependencies_complete"] is True
            assert context_input_status(row) == "current"
            lookup = row.get("include_lookups")
            assert isinstance(lookup, dict), "actual new native lookup receipt required"
            assert lookup["version"] == "zscope.include-lookups.v1"
            assert lookup["complete"] is False
            reason = {
                "vfs": "vfs_overlay",
                "remap": "remapped_inputs",
                "include_alias": "include_alias_unproven",
            }[mode]
            assert reason in lookup["unsupported_reasons"], "actual parsed mode must deny filtering"
            actual = [
                query
                for query in lookup["queries"]
                if query["including_file"] == str(root / "unit.c")
                and query["name"] in {"alias-original.lookup", "alias-target.lookup"}
            ]
            assert len(actual) == 1 and actual[0]["found"] is True
            # RemappedFilesKeepOriginalName preserves FileEntry's original name;
            # that mode is rejected from native options, not inferred as an alias.
            expected_target = original_header if mode == "remap" else actual_header
            assert actual[0]["target_file"] == str(expected_target)
        plans.append(result)
        return result

    monkeypatch.setattr(ScanSessionRunner, "_build_entry_instance_plan", plan)
    before = _files(_run_dir(root))
    with pytest.raises(ValueError, match="job_runtime_output_lookup"):
        ScanSessionRunner(_config(root), task_id=f"footprint/lookup-{mode}").run()
    assert len(plans) == 1, "real current two-variant inputs must reach the filter gate"
    assert _files(_run_dir(root)) == before


def test_real_bound_attempt_borrows_same_active_connection(project):
    from test_scan_session_jobs import INPUT_REVISION, OWNER_TOKEN, RUN_ID

    root, store = project
    accessor = getattr(store, "_active_transaction_connection", None)
    assert callable(accessor), "verified live-transaction accessor is required"
    statements = []
    with store.bound_attempt(
        job_id=JOB_ID,
        run_id=RUN_ID,
        owner_token=OWNER_TOKEN,
        expected_input_revision=INPUT_REVISION,
    ):
        outer = accessor()
        assert outer.in_transaction
        outer.set_trace_callback(statements.append)
        with store.bound_attempt(
            job_id=JOB_ID,
            run_id=RUN_ID,
            owner_token=OWNER_TOKEN,
            expected_input_revision=INPUT_REVISION,
        ) as row:
            assert accessor() is outer
            assert row["run_dir"] == str(_run_dir(root))
        assert outer.in_transaction
        assert statements and all(
            statement.strip().upper() not in {"BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"}
            for statement in statements
        )
    assert statements[-1].strip().upper() == "COMMIT"
    with pytest.raises(JobError):
        accessor()


@pytest.mark.parametrize("exit_mode", ["commit", "exception", "base_exception"])
def test_real_transaction_capability_revoked_before_control_flow(project, monkeypatch, exit_mode):
    import sqlite3

    root, store = project
    accessor = getattr(store, "_active_transaction_connection", None)
    assert callable(accessor), "verified live-transaction accessor is required"
    events = []
    saved = []
    original_connect = sqlite3.connect

    class ProbeException(Exception):
        pass

    class ProbeBaseException(BaseException):
        pass

    def observed_factory(base):
        class LifecycleConnection(base):
            def observe(self, operation):
                try:
                    accessor()
                except JobError:
                    events.append((operation, "revoked"))
                else:
                    events.append((operation, "still_active"))

            def commit(self):
                self.observe("commit")
                return super().commit()

            def rollback(self):
                self.observe("rollback")
                return super().rollback()

            def close(self):
                self.observe("close")
                return super().close()

        return LifecycleConnection

    def connect(database, *args, **kwargs):
        if str(database) != str(store.db_path):
            return original_connect(database, *args, **kwargs)
        base = kwargs.get("factory", sqlite3.Connection)
        kwargs["factory"] = observed_factory(base)
        return original_connect(database, *args, **kwargs)

    def exercise():
        with store._write() as connection:
            assert accessor() is connection
            assert connection.in_transaction
            saved.append(connection)
            connection.execute("SELECT job_id FROM jobs WHERE job_id=?", (JOB_ID,)).fetchone()
            if exit_mode == "exception":
                raise ProbeException()
            if exit_mode == "base_exception":
                raise ProbeBaseException()

    monkeypatch.setattr(sqlite3, "connect", connect)
    if exit_mode == "commit":
        exercise()
        expected = ["commit", "close"]
    elif exit_mode == "exception":
        with pytest.raises(ProbeException):
            exercise()
        expected = ["rollback", "close"]
    else:
        with pytest.raises(ProbeBaseException):
            exercise()
        expected = ["close"]
    assert events == [(operation, "revoked") for operation in expected]
    with pytest.raises(JobError):
        accessor()
    with pytest.raises(sqlite3.ProgrammingError):
        saved[0].execute("SELECT 1")
    assert _files(_run_dir(root)) == {}


@pytest.mark.parametrize("foreign", ["store", "thread", "read_transaction"])
def test_real_transaction_capability_is_not_inherited(project, foreign):
    import threading

    root, store = project
    accessor = getattr(store, "_active_transaction_connection", None)
    assert callable(accessor), "verified live-transaction accessor is required"
    if foreign == "read_transaction":
        with store._read() as connection:
            connection.execute("BEGIN")
            assert connection.in_transaction
            with pytest.raises(JobError):
                accessor()
            connection.rollback()
    elif foreign == "store":
        other = _job_store(root / "foreign-store")
        with store._write() as connection:
            assert accessor() is connection
            with pytest.raises(JobError):
                other._active_transaction_connection()
    else:
        observed = []

        def borrow():
            try:
                accessor()
            except BaseException as error:
                observed.append(error)
            else:
                observed.append("foreign thread obtained authority")

        with store._write() as connection:
            assert accessor() is connection
            worker = threading.Thread(target=borrow, daemon=True)
            worker.start()
            worker.join(5)
            assert not worker.is_alive()
            assert len(observed) == 1 and isinstance(observed[0], JobError)
    assert _files(_run_dir(root)) == {}


@pytest.mark.parametrize("invalid", ["owner_token", "input_revision", "run_dir"])
def test_live_native_scope_rejects_invalid_binding_inside_real_transaction(
    project, monkeypatch, invalid
):
    from test_scan_session_jobs import INPUT_REVISION, OWNER_TOKEN, RUN_ID
    from zscope.orchestration.jobs.scheduler_hook import JobWindowHook

    root, store = project
    original_freeze = ParallelAnalyzer.freeze_instance_semantics
    observed = []

    class RollbackProbe(Exception):
        pass

    class FinishedProbe(BaseException):
        pass

    def freeze(analyzer, plan):
        context = original_freeze(analyzer, plan)
        assert len(context.snapshots) == 2, context.unavailable
        scope = context.code_index._job_runtime_outputs
        assert scope is not None
        hook = JobWindowHook(
            store.db_path,
            job_id=JOB_ID,
            run_id=RUN_ID,
            owner_token=OWNER_TOKEN,
            run_dir=_run_dir(root),
        )
        hook._bind_runtime_outputs(scope)
        before = _files(_run_dir(root))
        try:
            with store.bound_attempt(
                job_id=JOB_ID,
                run_id=RUN_ID,
                owner_token=OWNER_TOKEN,
                expected_input_revision=INPUT_REVISION,
            ):
                connection = store._active_transaction_connection()
                event_count = connection.execute(
                    "SELECT COUNT(*) FROM events WHERE kind='pending_persisted'"
                ).fetchone()[0]
                value = str(root / "foreign-output") if invalid == "run_dir" else "foreign-binding"
                connection.execute(f"UPDATE jobs SET {invalid}=? WHERE job_id=?", (value, JOB_ID))
                for snapshot in context.snapshots.values():
                    with pytest.raises(ValueError, match="instance_semantics_not_current"):
                        context.require(snapshot.scope)
                assert hook.persist_pending([{"entry": "f"}], source="invalid_scope_probe") is None
                assert _files(_run_dir(root)) == before
                assert (
                    connection.execute(
                        "SELECT COUNT(*) FROM events WHERE kind='pending_persisted'"
                    ).fetchone()[0]
                    == event_count
                )
                observed.append(invalid)
                raise RollbackProbe()
        except RollbackProbe:
            pass
        for snapshot in context.snapshots.values():
            assert context.require(snapshot.scope) is snapshot
        raise FinishedProbe()

    monkeypatch.setattr(ParallelAnalyzer, "freeze_instance_semantics", freeze)
    with pytest.raises(FinishedProbe):
        ScanSessionRunner(_config(root), task_id="footprint/invalid-live-frame").run()
    assert observed == [invalid]
    assert _files(_run_dir(root)) == {}
    assert not (root / "report.json").exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_store_sidecar_ordinary_lookup_conflict_precedes_store_connection(
    project, monkeypatch, suffix
):
    import sqlite3

    from zscope.retrieval.build_context import context_input_status

    root, store = project
    name = store.db_path.name + suffix
    _high, old = _add_lookup(root, name, source_prefix=f'#include "{name}"\n')
    old_hash, database_hash = _digest(old), _digest(store.db_path)
    original_plan = ScanSessionRunner._build_entry_instance_plan
    original_connect = sqlite3.connect
    plans, connections = [], []

    def plan(runner, state):
        result = original_plan(runner, state)
        assert len(result.instances) == 2, result
        contexts = state["code_index"].get_build_contexts()
        assert len(contexts) == 2
        assert all(
            row["dependencies_complete"] and context_input_status(row) == "current"
            for row in contexts
        )
        plans.append(result)
        return result

    def connect(database, *args, **kwargs):
        if str(database) == str(store.db_path):
            connections.append(str(database))
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(ScanSessionRunner, "_build_entry_instance_plan", plan)
    monkeypatch.setattr(sqlite3, "connect", connect)
    with pytest.raises(ValueError, match="job_runtime_output_lookup"):
        ScanSessionRunner(_config(root), task_id="footprint/store-sidecar-conflict").run()
    assert len(plans) == 1
    assert connections == [], "lookup collision must precede WAL/SHM-producing connect"
    assert _files(_run_dir(root)) == {}
    assert _digest(old) == old_hash and _digest(store.db_path) == database_hash


def test_actual_has_include_next_refuses_output_filter_without_global_downgrade(
    project, monkeypatch
):
    from zscope.retrieval.build_context import context_input_status

    root, _store = project
    _add_lookup(
        root,
        "next-probe.lookup",
        source_prefix='#if __has_include_next("next-probe.lookup")\n#define NEXT_PROBE 1\n#endif\n',
    )
    original_plan = ScanSessionRunner._build_entry_instance_plan
    observed = []

    def plan(runner, state):
        result = original_plan(runner, state)
        assert len(result.instances) == 2, result
        for row in state["code_index"].get_build_contexts():
            assert row["dependencies_complete"] is True
            assert context_input_status(row) == "current"
            lookup = row.get("include_lookups")
            assert isinstance(lookup, dict)
            assert lookup["complete"] is False
            assert any("__has_include_next" in reason for reason in lookup["unsupported_reasons"])
            observed.append(row)
        return result

    monkeypatch.setattr(ScanSessionRunner, "_build_entry_instance_plan", plan)
    with pytest.raises(ValueError, match="job_runtime_output_lookup"):
        ScanSessionRunner(_config(root), task_id="footprint/has-include-next").run()
    assert len(observed) == 2
    assert _files(_run_dir(root)) == {}
