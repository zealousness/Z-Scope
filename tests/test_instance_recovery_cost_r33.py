"""Real native/SQL recovery with explicit metric fixtures, without model calls."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_instance_partial_recovery_integration import assert_partition
from test_instance_analysis import _native_config, _native_index, native_variants
from test_scan_checkpoint_resume import (
    _bind_env,
    _count_executions,
    _native_project,
    _read_report,
    _resume,
    _session_config,
)
from test_scan_jobs import start_job, store_for
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.parallel_analyzer import _InstanceEntryLookupIndex
from zscope.orchestration.parallel_analyzer import ParallelAnalysisResult
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.snapshots.modeling_input import SemanticModelInputError
from zscope.orchestration.scan_session import ScanSessionRunner

HISTORICAL = {
    "duration_seconds": 17017.0,
    "context_tokens": 1717,
    "cumulative_prompt_tokens": 10123,
    "cumulative_completion_tokens": 20234,
    "cumulative_total_tokens": 30357,
}
CURRENT = {
    "duration_seconds": 3.0,
    "context_tokens": 7,
    "cumulative_prompt_tokens": 11,
    "cumulative_completion_tokens": 13,
    "cumulative_total_tokens": 24,
}
VALIDATION = {
    "duration_seconds": 5.0,
    "context_tokens": 17,
    "cumulative_prompt_tokens": 19,
    "cumulative_completion_tokens": 23,
    "cumulative_total_tokens": 42,
}


@pytest.fixture
def metric_recovery(monkeypatch, tmp_path):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project = _native_project(tmp_path)
    service = ScanJobService(project / "zscope.yaml", spawn_owner=False)
    created = start_job(service, request_id="native-recovery-cost-r33")
    store = store_for(project)
    producer = store.get_job(created["job_id"])
    assert producer is not None
    calls = _count_executions(monkeypatch)
    phase = {"producer": True, "validation_cost": False}
    validations = []
    analyzers = []
    restored_results = []
    analyze = ParallelAnalyzer._analyze_single_entry
    validate = ParallelAnalyzer.validate_instance_batch
    restore = ParallelAnalyzer.restore_instance_result

    def measured_analysis(self, *args, **kwargs):
        result = analyze(self, *args, **kwargs)
        if result.error or not (result.instance_collection or {}).get("collection_closed"):
            diagnostic = (
                Path(__file__).resolve().parents[1]
                / "artifacts/stage-cost-r33/collection-observations"
            )
            diagnostic.mkdir(parents=True, exist_ok=True)
            (diagnostic / f"{uuid.uuid4().hex}.json").write_text(
                json.dumps(
                    {
                        "error": result.error,
                        "collection": result.instance_collection,
                        "engine_capabilities": result.metadata.get("engine_capabilities"),
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        assert result.error is None
        assert result.instance_collection["collection_closed"] is True, result.instance_collection
        assert result.entry_signature == "void f(void)"
        assert result.metadata["entry_signature"] == result.entry_signature
        assert result.metadata["entry_identity"] == result.entry_identity
        # These numbers are recognizable accounting fixtures applied only after
        # actual native collection. They do not claim provider/model usage.
        for name, value in (HISTORICAL if phase["producer"] else CURRENT).items():
            setattr(result, name, value)
        return result

    def measured_validation(self, batch):
        result = validate(self, batch)
        analyzers.append(self)
        validations.append((set(batch.restored_instances), set(batch.executed_instances)))
        if phase["validation_cost"]:
            self._global_validation_duration_seconds = VALIDATION["duration_seconds"]
            for name, value in VALIDATION.items():
                if name != "duration_seconds":
                    self._global_validation_state[f"total_{name}"] = value
        else:
            self._global_validation_duration_seconds = 0.0
        return result

    def observed_restore(self, batch, *, admitted):
        result = restore(self, batch, admitted=admitted)
        restored_results.extend(
            row
            for row in batch.results.values()
            if row.instance_identity == admitted.payload.instance.identity
        )
        return result

    monkeypatch.setattr(ParallelAnalyzer, "_analyze_single_entry", measured_analysis)
    monkeypatch.setattr(ParallelAnalyzer, "validate_instance_batch", measured_validation)
    monkeypatch.setattr(ParallelAnalyzer, "restore_instance_result", observed_restore)
    _bind_env(monkeypatch, project, store, producer)
    ScanSessionRunner(_session_config(project), task_id="cost/producer").run()
    assert sum(map(len, calls)) == 2
    assert len(validations) == 1
    with sqlite3.connect(str(store.db_path)) as connection:
        rows = connection.execute(
            "SELECT e.data_json FROM events e JOIN bound_event_receipts r "
            "ON r.event_seq=e.seq WHERE e.job_id=? AND "
            "e.kind='instance_result_persisted' ORDER BY e.seq",
            (producer["job_id"],),
        ).fetchall()
    receipts = [json.loads(row[0]) for row in rows]
    assert len(receipts) == 2
    immutable = {}
    for receipt in receipts:
        path = Path(receipt["artifact_path"])
        raw = path.read_bytes()
        payload = json.loads(raw)
        outcome = payload["outcome"]
        assert {key: outcome["result"][key] for key in HISTORICAL} == HISTORICAL
        immutable[path] = hashlib.sha256(raw).hexdigest()
    phase["producer"] = False
    return {
        "project": project,
        "service": service,
        "store": store,
        "producer": producer,
        "phase": phase,
        "calls": calls,
        "validations": validations,
        "receipts": receipts,
        "immutable": immutable,
        "restored_results": restored_results,
        "analyzers": analyzers,
    }


@pytest.mark.parametrize("executed,validation_cost", [(0, False), (0, True), (1, True)])
def test_native_recovery_preserves_history_and_charges_only_current_work(
    metric_recovery, monkeypatch, executed, validation_cost
):
    fixture = metric_recovery
    damaged = None
    if executed:
        damaged = Path(fixture["receipts"][0]["artifact_path"])
        damaged.write_bytes(damaged.read_bytes() + b"\n")
    fixture["phase"]["validation_cost"] = validation_cost
    resumed = _resume(fixture["service"], fixture["store"], fixture["producer"])
    fixture["calls"].clear()
    _bind_env(monkeypatch, fixture["project"], fixture["store"], resumed)
    ScanSessionRunner(_session_config(fixture["project"]), task_id="cost/resumed").run()
    report = _read_report(fixture["project"] / "report.json")
    assert_partition(report["metadata"]["job"], restored=2 - executed, executed=executed)
    assert sum(map(len, fixture["calls"])) == executed
    assert len(fixture["validations"]) == 2
    for row in fixture["restored_results"]:
        assert {key: getattr(row, key) for key in HISTORICAL} == HISTORICAL
    for path, digest in fixture["immutable"].items():
        if path != damaged:
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    expected = {
        key: executed * CURRENT[key] + (VALIDATION[key] if validation_cost else 0)
        for key in CURRENT
    }
    for key, value in expected.items():
        assert report["summary"][f"total_{key}"] == value, (
            key,
            report["summary"],
            "historical metrics must not enter current cost",
        )
        if key != "duration_seconds":
            assert report["metadata"][key] == value
    history = report["metadata"]["instance_recovery_costs"]
    assert history["accounting_scope"] == "historical_producer_work"
    assert len(history["results"]) == 2 - executed
    assert history["totals"] == {key: value * (2 - executed) for key, value in HISTORICAL.items()}
    for item in history["results"]:
        assert item["producer_run_id"] == fixture["producer"]["run_id"]
        assert item["producer_job_id"] == fixture["producer"]["job_id"]
        assert item["metrics"] == HISTORICAL
    functions = report["function_results"]
    restored = [item for item in functions if item["cost_provenance"] == "historical_producer_work"]
    assert len(restored) == 2 - executed
    for item in restored:
        assert all(item[key] == 0 for key in HISTORICAL)
        assert item["historical_cost"]["metrics"] == HISTORICAL
    # A projection of a different current result object at the same key must
    # not inherit an earlier restored object's provenance. No work is claimed.
    analyzer = fixture["analyzers"][-1]
    result_key, old_result = next(iter(analyzer.last_instance_results().items()))
    current_projection = replace(old_result, **CURRENT)
    analyzer._global_validation_state = {}
    analyzer._global_validation_duration_seconds = 0.0
    projected = analyzer.generate_combined_report({result_key: current_projection})
    assert projected["function_results"][0]["cost_provenance"] == "current_run"
    assert projected["summary"]["total_duration_seconds"] == CURRENT["duration_seconds"]
    assert (
        projected["summary"]["total_cumulative_total_tokens"] == CURRENT["cumulative_total_tokens"]
    )
    assert projected["metadata"]["instance_recovery_costs"]["results"] == []


def test_native_lookup_bridge_keeps_signature_and_rejects_foreign_identity(
    native_variants, monkeypatch
):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    parallel = ParallelAnalyzer(_native_config(root, cdb, root), code_index=index)
    try:
        parallel.freeze_instance_semantics(plan)
        entry, scope = parallel._current_instance_entries(plan)[0]
        lookup = _InstanceEntryLookupIndex(index, scope, entry)
        assert lookup.call_model_status("free", entry.function_name) == "source_unavailable"
        classified = _InstanceEntryLookupIndex(
            index, scope, entry, semantics_context=parallel._instance_semantics_context
        )
        for name in ("malloc", "free"):
            assert classified.call_model_status(name, entry.function_name) == "standard_model"
        assert classified.call_model_status("free", "foreign-caller") == "source_unavailable"
        assert (
            classified.call_model_status(
                "printf",
                entry.function_name,
                {"callee_kind": "system_function", "usr": "c:@F@printf"},
            )
            == "source_unavailable"
        )
        assert (
            classified.call_model_status(
                "free", entry.function_name, {"build_context_id": "foreign-build"}
            )
            == "source_unavailable"
        )
        assert (
            classified.call_model_status("free", entry.function_name, {"usr": "foreign-native-usr"})
            == "source_unavailable"
        )
        for record in (
            {"source": str(root / "foreign.c")},
            {"callee_file": str(root / "foreign.c")},
            {"caller_file": str(root / "foreign.c")},
            {"owner_usr": "foreign-native-usr"},
            {"target": {"usr": "foreign-native-usr"}},
            {"target": {"name": "foreign-target"}},
            {"target": {"declaration": {"file": str(root / "foreign.c")}}},
            {"owner": {"file": str(root / "foreign.c")}},
            {"owner": {"name": "foreign-caller"}},
        ):
            assert (
                classified.call_model_status("free", entry.function_name, record)
                == "source_unavailable"
            )
        records = lookup.find_function_metadata(entry.signature, entry.file_path)
        assert len(records) == 1
        assert records[0]["signature"] == entry.signature
        assert lookup.find_function_metadata("void foreign(void)", entry.file_path) == []
        assert lookup.find_function_metadata(entry.signature, str(root / "foreign.c")) == []
        for wrong_scope, wrong_entry in (
            (scope, replace(entry, signature="void foreign(void)")),
            (scope, replace(entry, file_path=str(root / "foreign.c"))),
            (replace(scope, usr="foreign-native-usr"), entry),
            (replace(scope, build_context_id="foreign-build-context"), entry),
        ):
            with pytest.raises((ValueError, SemanticModelInputError)):
                _InstanceEntryLookupIndex(index, wrong_scope, wrong_entry)
        finder = index.find_function_infos

        def ambiguous(*args, **kwargs):
            rows = finder(*args, **kwargs)
            return rows + deepcopy(rows)

        with monkeypatch.context() as controlled:
            controlled.setattr(index, "find_function_infos", ambiguous)
            assert lookup.find_function_metadata(entry.signature, entry.file_path) == []

        def changed_signature(*args, **kwargs):
            rows = deepcopy(finder(*args, **kwargs))
            for row in rows:
                row["signature"] = "void foreign(void)"
            return rows

        with monkeypatch.context() as controlled:
            controlled.setattr(index, "find_function_infos", changed_signature)
            assert lookup.find_function_metadata(entry.signature, entry.file_path) == []
        for nested in (False, True):

            def foreign_usr(*args, **kwargs):
                rows = deepcopy(finder(*args, **kwargs))
                for row in rows:
                    if nested:
                        row["function_identity"] = {
                            "usr": "foreign-native-usr",
                            "build_context_id": scope.build_context_id,
                        }
                    else:
                        row["usr"] = "foreign-native-usr"
                return rows

            with monkeypatch.context() as controlled:
                controlled.setattr(index, "find_function_infos", foreign_usr)
                assert lookup.find_function_metadata(entry.signature, entry.file_path) == []
                with pytest.raises((ValueError, SemanticModelInputError)):
                    _InstanceEntryLookupIndex(index, scope, entry)
        assert entry.signature == "void f(void)"
        header = root / "flags.h"
        original_header = header.read_bytes()
        stamp = header.stat()
        try:
            header.write_bytes(original_header + b"\n/* actual currentness revocation */\n")
            with pytest.raises(ValueError):
                classified.call_model_status("free", entry.function_name)
        finally:
            header.write_bytes(original_header)
            os.utime(header, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        from zscope.semantics import instance_semantics as semantics_module

        materialize = semantics_module.materialize_effect_semantics

        def revoke_during_materialization(snapshot):
            result = materialize(snapshot)
            header.write_bytes(original_header + b"\n/* revoke after actual materialization */\n")
            return result

        try:
            with monkeypatch.context() as controlled:
                controlled.setattr(
                    semantics_module, "materialize_effect_semantics", revoke_during_materialization
                )
                with pytest.raises(ValueError):
                    classified.call_model_status("free", entry.function_name)
        finally:
            header.write_bytes(original_header)
            os.utime(header, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    finally:
        parallel.close()


@pytest.mark.parametrize("response", [(0, 0, 0), (0, 29, 29), (31, 0, 31)])
def test_current_model_validation_dedup_response_metrics_count_once(response):
    """Metric snapshots exercise projection only; no provider is executed."""
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.max_workers = 2
    snapshot = {
        "successful_calls": 3,
        "provider_reported_calls": 3,
        "prompt_tokens": response[0],
        "completion_tokens": response[1],
        "total_tokens": response[2],
    }
    client = SimpleNamespace(usage_snapshot=lambda: dict(snapshot))
    analyzer._shared_llm_clients = {"modeling": client, "validation": client, "dedup": client}
    analyzer._global_validation_state = {
        f"total_{key}": value for key, value in VALIDATION.items() if key != "duration_seconds"
    }
    analyzer._global_validation_duration_seconds = VALIDATION["duration_seconds"]
    result = ParallelAnalysisResult(function_name="entry", verdict="no_issue_found", **CURRENT)
    report = analyzer.generate_combined_report({"entry": result})
    for key, value in zip(("prompt", "completion", "total"), response):
        assert report["summary"][f"total_cumulative_{key}_tokens"] == value
        assert report["metadata"][f"cumulative_{key}_tokens"] == value
    assert report["summary"]["llm_usage"]["successful_calls"] == 3
    assert len(report["summary"]["llm_usage"]["per_client"]) == 1
    assert report["summary"]["retained_entry_total_tokens"] == 66
    assert report["summary"]["total_duration_seconds"] == 8.0


def test_real_native_same_line_functions_cannot_exchange_lookup_identity(tmp_path, monkeypatch):
    from zscope.retrieval.clang_backend import ClangBackend

    tool = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    assert tool, "real native tool required"
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    source = tmp_path / "unit.c"
    source.write_text("void f(void) {} void g(void) {}\n", encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=tool, max_threads=2)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    parallel = None
    try:
        index = _native_index(backend, tmp_path, cdb)
        plan = plan_entry_instances(
            index, [FunctionEntry("f", file_path="unit.c"), FunctionEntry("g", file_path="unit.c")]
        )
        assert len(plan.instances) == 2
        parallel = ParallelAnalyzer(_native_config(tmp_path, cdb, tmp_path), code_index=index)
        parallel.freeze_instance_semantics(plan)
        entries = {
            entry.function_name: (entry, scope)
            for entry, scope in parallel._current_instance_entries(plan)
        }
        assert set(entries) == {"f", "g"}
        for entry, scope in entries.values():
            lookup = _InstanceEntryLookupIndex(index, scope, entry)
            rows = lookup.find_function_metadata(entry.signature, entry.file_path)
            assert len(rows) == 1
            assert rows[0]["function_name"] == entry.function_name
            assert rows[0]["signature"] == entry.signature
        f_entry, f_scope = entries["f"]
        _g_entry, g_scope = entries["g"]
        wrong_owner = replace(g_scope, function_names=f_scope.function_names)
        with pytest.raises((ValueError, SemanticModelInputError)):
            _InstanceEntryLookupIndex(index, wrong_owner, f_entry)
    finally:
        if parallel is not None:
            parallel.close()
        backend.close()


def test_real_native_project_standard_spelling_does_not_authorize_external_skip(
    tmp_path, monkeypatch
):
    from zscope.retrieval.clang_backend import ClangBackend

    tool = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    assert tool, "real native tool required"
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    source = tmp_path / "unit.c"
    source.write_text(
        "#include <stdlib.h>\nvoid *malloc(size_t n) { (void)n; return 0; }\n"
        "void f(void) { (void)malloc(4); }\n",
        encoding="utf-8",
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=tool, max_threads=2)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    parallel = None
    try:
        index = _native_index(backend, tmp_path, cdb)
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        parallel = ParallelAnalyzer(_native_config(tmp_path, cdb, tmp_path), code_index=index)
        parallel.freeze_instance_semantics(plan)
        entry, scope = parallel._current_instance_entries(plan)[0]
        lookup = _InstanceEntryLookupIndex(
            index, scope, entry, semantics_context=parallel._instance_semantics_context
        )
        assert lookup.call_model_status("malloc", entry.function_name) == "source_unavailable"
        assert (
            lookup.call_model_status(
                "malloc", entry.function_name, {"callee_kind": "system_function"}
            )
            == "source_unavailable"
        )
    finally:
        if parallel is not None:
            parallel.close()
        backend.close()


def _offline_usage_record(client, prompt, completion, *, duration=2.0):
    """Use real telemetry's response-record API; no provider request is made."""
    client._record_successful_usage(
        {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
            "estimated": False,
        },
        duration_seconds=duration,
    )


def _offline_usage_analyzer(native_variants, client):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    clients = {"modeling": client, "validation": client, "dedup": client}
    analyzer = ParallelAnalyzer(
        _native_config(root, cdb, root), code_index=index, llm_clients=clients
    )
    return analyzer, plan


def _offline_client():
    from zscope.framework.llm_client import LLMClient

    return LLMClient(
        api_key="offline-accounting-fixture",
        base_url="http://example.invalid",
        models=["offline-accounting-fixture"],
    )


def test_offline_preused_real_client_does_not_charge_previous_analyzer_work(native_variants):
    """Offline accounting evidence does not claim an actual provider charge."""
    client = _offline_client()
    _offline_usage_record(client, 10123, 20234, duration=17017.0)
    analyzer, plan = _offline_usage_analyzer(native_variants, client)
    batch = None
    try:
        batch = analyzer.open_instance_batch(plan)
        report = analyzer.generate_combined_report({})
        usage = report["summary"]["llm_usage"]
        assert usage["successful_calls"] == 0
        assert usage["total_tokens"] == 0
        assert usage["successful_call_wall_seconds_total"] == 0
        assert report["summary"]["total_cumulative_total_tokens"] == 0
        assert client.usage_snapshot()["total_tokens"] == 30357
    finally:
        if batch is not None:
            analyzer.abandon_instance_batch(batch)
        analyzer.close()
        client.close()


@pytest.mark.parametrize("response", [None, (0, 0), (0, 29), (31, 0)])
def test_offline_real_client_reopened_batch_preserves_current_zero_and_no_response(
    native_variants, response
):
    """Actual native batch opening delimits real cumulative client telemetry."""
    client = _offline_client()
    analyzer, plan = _offline_usage_analyzer(native_variants, client)
    batch = None
    try:
        batch = analyzer.open_instance_batch(plan)
        _offline_usage_record(client, 10123, 20234, duration=17017.0)
        assert (
            analyzer.generate_combined_report({})["summary"]["llm_usage"]["total_tokens"] == 30357
        )
        analyzer.abandon_instance_batch(batch)
        batch = None
        batch = analyzer.open_instance_batch(plan)
        if response is not None:
            _offline_usage_record(client, *response)
        result = ParallelAnalysisResult(function_name="entry", verdict="no_issue_found", **CURRENT)
        report = analyzer.generate_combined_report({"entry": result})
        usage = report["summary"]["llm_usage"]
        assert usage["successful_calls"] == int(response is not None)
        assert usage["successful_call_wall_seconds_total"] == (2.0 if response is not None else 0)
        expected = (11, 13, 24) if response is None else (*response, sum(response))
        for key, value in zip(("prompt", "completion", "total"), expected):
            assert report["summary"][f"total_cumulative_{key}_tokens"] == value
            assert report["metadata"][f"cumulative_{key}_tokens"] == value
        assert len(usage["per_client"]) == 1
        assert usage["per_client"][0]["total_tokens"] == (sum(response) if response else 0)
        assert client.usage_snapshot()["successful_calls"] == 1 + int(response is not None)
        assert client.usage_snapshot()["total_tokens"] == 30357 + (sum(response) if response else 0)
    finally:
        if batch is not None:
            analyzer.abandon_instance_batch(batch)
        analyzer.close()
        client.close()


def test_offline_current_premodeling_before_first_open_is_not_lost(native_variants):
    client = _offline_client()
    analyzer, plan = _offline_usage_analyzer(native_variants, client)
    batch = None
    try:
        _offline_usage_record(client, 17, 19)
        batch = analyzer.open_instance_batch(plan)
        report = analyzer.generate_combined_report({})
        assert report["summary"]["llm_usage"]["successful_calls"] == 1
        assert report["summary"]["total_cumulative_total_tokens"] == 36
        assert client.usage_snapshot()["total_tokens"] == 36
    finally:
        if batch is not None:
            analyzer.abandon_instance_batch(batch)
        analyzer.close()
        client.close()


def test_offline_factory_session_premodeling_before_parallel_construction_counts_once(
    native_variants,
):
    """The real session factory runs before Session's semantic modeling stage."""
    from zscope.config.config import LLMConfig
    from zscope.framework.llm_client import LLMClient

    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    config = _native_config(root, cdb, root)
    config.llms = {
        "default": LLMConfig(
            api_key="offline-accounting-fixture",
            base_url="http://example.invalid",
            models=["offline-accounting-fixture"],
        )
    }
    clients = ParallelAnalyzer._build_shared_llm_clients(config)
    client = clients["default"]
    assert isinstance(client, LLMClient)
    _offline_usage_record(client, 13, 17)
    analyzer = ParallelAnalyzer(config, code_index=index, llm_clients=clients)
    batch = None
    second = None
    try:
        batch = analyzer.open_instance_batch(plan)
        report = analyzer.generate_combined_report({})
        assert report["summary"]["llm_usage"]["successful_calls"] == 1
        assert report["summary"]["total_cumulative_total_tokens"] == 30
        analyzer.abandon_instance_batch(batch)
        batch = None
        analyzer.close()
        # Reusing the factory mapping cannot re-claim its previous session's
        # response usage as the new analyzer's pre-modeling work.
        second = ParallelAnalyzer(config, code_index=index, llm_clients=clients)
        batch = second.open_instance_batch(plan)
        report = second.generate_combined_report({})
        assert report["summary"]["llm_usage"]["successful_calls"] == 0
        assert report["summary"]["total_cumulative_total_tokens"] == 0
        assert client.usage_snapshot()["total_tokens"] == 30
    finally:
        if batch is not None:
            (second or analyzer).abandon_instance_batch(batch)
        if second is not None:
            second.close()
        analyzer.close()
        client.close()
