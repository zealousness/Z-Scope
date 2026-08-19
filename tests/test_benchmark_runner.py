from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from zscope.benchmarking import runner as benchmark_runner
from zscope.cli import benchmark as benchmark_cli
from zscope.benchmarking.runner import (
    BenchmarkError,
    SPECS,
    _aggregate,
    _benchmark_environment,
    _benchmark_work_parent,
    _run_release_eligible,
    clean_benchmark_artifacts,
    copy_scan_input,
    restore_scan_input,
    run_benchmark,
    score_artifact,
)
from zscope.framework.llm_usage import LLMUsageAttribution, LLMUsageEvent
from zscope.orchestration.decision_trace import DecisionTraceStore


def _usage_event(*, sequence: int = 1, reservation_id: str = "call-1") -> dict:
    return LLMUsageEvent(
        sequence=sequence,
        reservation_id=reservation_id,
        outcome="success",
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        reserved_total_tokens=20,
        provider_reported=True,
        conservative_charge=False,
        budget_violation=False,
        attribution=LLMUsageAttribution(
            stage="validation",
            agent="validator_agent",
            candidate_uid="candidate-1",
            validation_cluster_uid="cluster-1",
            llm_ref="validation",
            call_kind="initial_decision",
        ),
        budget_stage="validation",
        model="glm-5.1",
        finish_reason="stop",
        cached_prompt_tokens=2,
        reasoning_tokens=1,
    ).to_dict()


@pytest.mark.parametrize("language", ["c_cpp", "java"])
def test_scan_input_is_a_strict_answer_free_allowlist(tmp_path: Path, language: str) -> None:
    source = tmp_path / "fixture"
    source.mkdir()
    if language == "c_cpp":
        (source / "src").mkdir()
        (source / "src/main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
        (source / "CMakeLists.txt").write_text("project(test C)\n", encoding="utf-8")
    else:
        (source / "src").mkdir()
        (source / "src/Main.java").write_text("class Main {}\n", encoding="utf-8")
        (source / "pom.xml").write_text("<project/>\n", encoding="utf-8")
        (source / "benchmark").mkdir()
        (source / "benchmark/entries.json").write_text(
            json.dumps(
                {"functions": [{"function_name": "Main.main", "file_path": "src/Main.java"}]}
            ),
            encoding="utf-8",
        )
    (source / "README.md").write_text("neutral\n", encoding="utf-8")
    (source / "benchmark").mkdir(exist_ok=True)
    (source / "benchmark/ground_truth.json").write_text("{}", encoding="utf-8")
    (source / "CODEX_BLIND_SCAN_REPORT.md").write_text("answer", encoding="utf-8")
    (source / "build").mkdir()
    (source / "build/generated.c").write_text("answer", encoding="utf-8")
    (source / "codeql_runs").mkdir()
    (source / "codeql_runs/result.sarif").write_text("answer", encoding="utf-8")

    destination = tmp_path / "scan"
    manifest = copy_scan_input(source, destination, language)
    observed = {row["path"] for row in manifest["files"]}

    assert not any("ground_truth" in path.lower() for path in observed)
    assert not any(path.startswith("benchmark/") for path in observed)
    assert not any(
        path.startswith("build/") or path.startswith("codeql_runs/") for path in observed
    )
    if language == "java":
        assert "entries.json" in observed


def test_java_scan_input_rejects_answer_metadata(tmp_path: Path) -> None:
    source = tmp_path / "java"
    (source / "benchmark").mkdir(parents=True)
    (source / "src").mkdir()
    (source / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (source / "benchmark/entries.json").write_text(
        json.dumps(
            {
                "functions": [
                    {
                        "function_name": "Main.main",
                        "file_path": "src/Main.java",
                        "covers_rule_ids": ["java_command_execution"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkError, match="answer metadata"):
        copy_scan_input(source, tmp_path / "scan", "java")


def test_trial_is_exactly_one_and_formal_requires_five() -> None:
    with pytest.raises(BenchmarkError, match="exactly one"):
        run_benchmark("java", "trial", runs=2, dry_run=True)
    with pytest.raises(BenchmarkError, match="at least five"):
        run_benchmark("java", "formal", runs=4, dry_run=True)
    assert run_benchmark("java", "formal", runs=5, dry_run=True)["runs"] == 5


def test_trial_aggregate_never_marks_nested_run_release_eligible() -> None:
    summary = {
        "run": 1,
        "completed": True,
        "release_eligible": False,
        "queue_empty": True,
        "gate_failures": [],
        "sealed_gate_failures": [],
        "metrics": {"recall": 1.0},
        "phase_seconds": {"total": 1.0},
        "execution": {},
    }

    aggregate = _aggregate(SPECS["c_cpp"], [summary], "trial")

    assert aggregate["release_eligible"] is False
    assert aggregate["runs"][0]["release_eligible"] is False


def test_individual_run_release_eligibility_requires_formal_mode_and_gates() -> None:
    assert not _run_release_eligible("trial", {"queue_empty": True}, [])
    assert not _run_release_eligible("formal", {"queue_empty": False}, [])
    assert not _run_release_eligible("formal", {"queue_empty": True}, ["too slow"])
    assert _run_release_eligible("formal", {"queue_empty": True}, [])


def test_cpp_benchmark_uses_eight_parallel_entry_and_validation_workers() -> None:
    config = yaml.safe_load(SPECS["c_cpp"].config_path.read_text(encoding="utf-8"))

    assert config["concurrency"]["entry_workers"] == 8
    assert config["concurrency"]["validator_workers"] == 8
    assert config["concurrency"]["llm_max_inflight"] == 8
    assert config["llms"]["default"]["base_url_max_concurrent_requests"] == 8
    assert config["concurrency"]["investigator_workers"] == 1
    assert config["concurrency"]["evidence_completion_workers"] == 2
    assert config["concurrency"]["index_workers"] == 4
    assert config["concurrency"]["svf_workers"] == 2


def test_wsl_cpp_work_root_rejects_windows_mount(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("Z_SCOPE_BENCHMARK_WORK_ROOT", str(tmp_path))
    monkeypatch.setattr(benchmark_runner, "_is_wsl", lambda: True)
    monkeypatch.setattr(benchmark_runner, "_is_windows_mount_in_wsl", lambda path: True)

    with pytest.raises(BenchmarkError, match="WSL native filesystem"):
        _benchmark_work_parent("c_cpp")


def test_trial_workspace_is_temporary_and_removed(monkeypatch, tmp_path: Path) -> None:
    work_parent = tmp_path / "native-work"
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    monkeypatch.setenv("Z_SCOPE_BENCHMARK_WORK_ROOT", str(work_parent))
    observed = {}

    def fake_run(spec, run_dir, run_number, *, mode, workspace, scan_depth):
        observed["workspace"] = workspace
        assert scan_depth == "fast"
        assert workspace.is_relative_to(work_parent)
        (workspace / "state").write_text("temporary", encoding="utf-8")
        return {"run": run_number, "mode": mode}

    monkeypatch.setattr(benchmark_runner, "_run_trial_in_workspace", fake_run)

    result = benchmark_runner._run_trial(SPECS["c_cpp"], artifact, 1, mode="trial")

    assert result == {"run": 1, "mode": "trial"}
    assert not observed["workspace"].exists()


def test_failed_trial_archives_partial_trace_before_workspace_cleanup(
    monkeypatch, tmp_path: Path
) -> None:
    work_parent = tmp_path / "native-work"
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    monkeypatch.setenv("Z_SCOPE_BENCHMARK_WORK_ROOT", str(work_parent))
    observed = {}

    def fake_run(spec, run_dir, run_number, *, mode, workspace, scan_depth):
        observed["workspace"] = workspace
        trace_root = workspace / "scan-input" / ".zscope_snapshots"
        (trace_root / "decision_traces").mkdir(parents=True)
        (trace_root / "decision_traces" / "VAL_1.json").write_text(
            json.dumps({"validation_cluster_uid": "VAL_1"}),
            encoding="utf-8",
        )
        (trace_root / "llm_usage_events_deadbeef.jsonl").write_text(
            json.dumps(_usage_event()) + "\n",
            encoding="utf-8",
        )
        raise BenchmarkError("scan interrupted")

    monkeypatch.setattr(benchmark_runner, "_run_trial_in_workspace", fake_run)

    with pytest.raises(BenchmarkError, match="scan interrupted"):
        benchmark_runner._run_trial(SPECS["c_cpp"], artifact, 1, mode="trial")

    assert not observed["workspace"].exists()
    archive = json.loads((artifact / "interrupted-diagnostics.json").read_text(encoding="utf-8"))
    assert archive["release_eligible"] is False
    assert archive["answer_material_present"] is False
    assert {item["path"] for item in archive["files"]} == {
        "decision_traces/VAL_1.json",
        "llm_usage_events_deadbeef.jsonl",
    }
    assert (artifact / "interrupted-diagnostics" / "decision_traces" / "VAL_1.json").is_file()


def test_score_exposes_confirmed_and_with_review_views(monkeypatch, tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    truth = tmp_path / "truth.json"
    output = tmp_path / "score.json"
    report.write_text(
        json.dumps(
            {
                "summary": {
                    "batch_wall_seconds": 120.5,
                    "global_validation_queue": {
                        "duration_seconds": 100.0,
                        "validator_session_count": 8,
                        "validator_api_call_count": 10,
                    },
                },
                "run_manifest": {"validation_queue_drained": True},
            }
        ),
        encoding="utf-8",
    )
    truth.write_text(
        json.dumps({"total_vulnerabilities": 0, "vulnerabilities": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        benchmark_runner,
        "score_report_views",
        lambda report_payload, truth_payload: {
            "default": {
                "true_positives": 89,
                "false_negatives": 47,
                "false_positives_raw": 2,
                "recall": 0.6544,
                "actionable_precision": 0.978,
                "root_cause_precision": 1.0,
            },
            "with_needs_review": {
                "true_positives": 135,
                "false_negatives": 1,
                "false_positives_raw": 94,
                "recall": 0.9926,
                "actionable_precision": 0.5895,
                "root_cause_precision": 0.6,
            },
        },
    )

    score = score_artifact(report, truth, output)

    assert score["confirmed_recall"] == 0.6544
    assert score["confirmed_precision"] == 0.978
    assert score["with_review_recall"] == 0.9926
    assert score["with_review_precision"] == 0.5895
    assert score["quality_views"]["confirmed"]["true_positives"] == 89
    assert score["quality_views"]["with_review"]["true_positives"] == 135
    assert score["scan_wall_seconds"] == 120.5
    assert score["wall_seconds"] == score["scan_wall_seconds"]
    assert score["performance_telemetry"]["validator_api_call_count"] == 10


def test_formal_gate_requires_current_truth_matcher_but_trial_remains_readable() -> None:
    legacy = {"scoring_contract": {}}
    current = {"scoring_contract": {"matcher_version": benchmark_runner.MATCHER_VERSION}}

    assert benchmark_runner._truth_matcher_gate_failures("trial", legacy) == []
    assert benchmark_runner._truth_matcher_gate_failures("formal", current) == []
    failures = benchmark_runner._truth_matcher_gate_failures("formal", legacy)
    assert len(failures) == 1
    assert benchmark_runner.MATCHER_VERSION in failures[0]


def test_dry_run_does_not_require_llm_or_create_output(monkeypatch, tmp_path: Path) -> None:
    for key in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    output = tmp_path / "not-created"

    plan = run_benchmark("c_cpp", "formal", runs=5, output=output, dry_run=True)

    assert plan["dry_run"] is True
    assert plan["truth_stage"] == "score_only"
    assert plan["isolation"]["required"] is True
    assert plan["isolation"]["fail_closed"] is True
    assert plan["isolation"]["release_capable"] is False
    assert not output.exists()


def test_health_and_scan_environment_never_inherit_truth(monkeypatch) -> None:
    monkeypatch.setenv("Z_SCOPE_BENCHMARK_TRUTH", "secret-truth.json")
    monkeypatch.setenv("GROUND_TRUTH_PATH", "another-secret.json")
    environment = _benchmark_environment()
    assert not any("TRUTH" in key.upper() for key in environment)


def test_restore_scan_input_removes_generated_state_and_preserves_manifest(tmp_path: Path) -> None:
    source = tmp_path / "fixture"
    (source / "src").mkdir(parents=True)
    (source / "src/main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (source / "CMakeLists.txt").write_text("project(test C)\n", encoding="utf-8")
    (source / "README.md").write_text("neutral\n", encoding="utf-8")
    destination = tmp_path / "scan"
    manifest = copy_scan_input(source, destination, "c_cpp")
    (destination / ".zscope_knowledge").mkdir()
    (destination / ".zscope_knowledge/state.db").write_bytes(b"generated")
    (destination / "report.json").write_text("{}", encoding="utf-8")

    restore_scan_input(destination, manifest)

    assert not (destination / ".zscope_knowledge").exists()
    assert not (destination / "report.json").exists()
    assert (destination / "src/main.c").is_file()


def test_usage_event_sidecar_is_archived_from_scan_workspace(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan"
    run_dir = tmp_path / "run"
    source = scan_root / ".zscope_snapshots" / "usage.jsonl"
    source.parent.mkdir(parents=True)
    run_dir.mkdir()
    event = _usage_event()
    source.write_text(json.dumps(event) + "\n", encoding="utf-8")
    report = {"metadata": {"llm_budget": {"usage_events_path": str(source)}}}

    artifact = benchmark_runner._archive_usage_events(
        report,
        scan_root=scan_root,
        run_dir=run_dir,
    )
    spans = benchmark_runner._read_archived_usage_events(run_dir)

    assert artifact is not None
    assert artifact["call_count"] == 1
    assert len(artifact["sha256"]) == 64
    assert spans == [event]
    assert report["metadata"]["llm_usage_events_artifact"] == artifact


def test_decision_trace_sidecar_is_archived_and_rebound_for_offline_explain(
    tmp_path: Path, capsys
) -> None:
    scan_root = tmp_path / "scan"
    trace_root = scan_root / ".zscope_snapshots"
    run_dir = tmp_path / "run"
    trace_root.mkdir(parents=True)
    run_dir.mkdir()
    event = _usage_event()
    usage_path = trace_root / "usage.jsonl"
    usage_path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    class UsageLedger:
        def snapshot(self, include_events=False):
            return {
                "schema_version": "zscope.llm-usage-ledger.v1",
                "usage_events_path": str(usage_path),
                "events": [event] if include_events else [],
                "usage_attribution": {"provider_usage_coverage": 1.0},
            }

    store = DecisionTraceStore(trace_root, scan_uid="SCAN_1", usage_ledger=UsageLedger())
    evidence_ref = store.put_evidence(
        kind="decision_slice",
        payload={"fact": "verified"},
        producer="test",
    )
    store.append_event(
        "cluster-1",
        stage="V1",
        actor="validator_agent",
        reason_code="V1_COMPLETED",
        output_refs=(evidence_ref,),
        call_ids=(event["call_id"],),
        token_delta=event["total_tokens"],
    )
    issue = {
        "candidate_uid": "candidate-1",
        "validation_cluster_uid": "cluster-1",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        "proof_coverage": "complete",
        "decision_proof": {"coverage": "complete", "polarity": "positive"},
        "terminal_authority_decision": {
            "schema_version": "zscope.terminal-authority-decision.v3",
            "terminal": True,
            "disposition": "confirmed",
            "reason_code": "CONFIRMED_DETERMINISTIC_PROOF",
            "authority": "zscope.proof-checker",
            "next_action": "",
            "conflict_resolution": None,
        },
    }
    store.finalize_issue(issue, view_memberships=("default", "with_needs_review"))
    manifest = store.snapshot()
    report = {
        "issues": [issue],
        "metadata": {"llm_budget": {"usage_events_path": str(usage_path)}},
        "run_manifest": {"decision_trace": manifest},
    }

    usage_artifact = benchmark_runner._archive_usage_events(
        report,
        scan_root=scan_root,
        run_dir=run_dir,
    )
    trace_artifact = benchmark_runner._archive_decision_trace_artifacts(
        report,
        scan_root=scan_root,
        run_dir=run_dir,
        usage_artifact=usage_artifact,
    )
    report_path = run_dir / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    assert trace_artifact is not None
    assert trace_artifact["trace_count"] == 1
    assert trace_artifact["evidence_object_count"] >= 1
    assert report["run_manifest"]["decision_trace"]["manifest_path"] == (
        "decision_trace_manifest.json"
    )
    archived_manifest = json.loads(
        (run_dir / "decision_trace_manifest.json").read_text(encoding="utf-8")
    )
    assert archived_manifest["llm_usage_events"]["path"] == "llm_usage_events.jsonl"
    assert archived_manifest["llm_usage_events"]["file_sha256"] == usage_artifact["sha256"]
    assert (run_dir / issue["decision_trace_ref"]).is_file()
    assert (run_dir / evidence_ref).is_file()

    try:
        from zscope.cli.explain import main as explain_main
    except ModuleNotFoundError as exc:
        if exc.name != "zscope.cli.explain":
            raise
        pytest.skip("offline explain is delivered by the separately published P0 product package")

    assert (
        explain_main(["--report", str(report_path), "--cluster", "cluster-1", "--format", "json"])
        == 0
    )
    explanation = json.loads(capsys.readouterr().out)
    assert explanation["terminal_disposition"] == "confirmed"


def test_decision_trace_archive_rejects_tampered_content_object(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan"
    trace_root = scan_root / ".zscope_snapshots"
    run_dir = tmp_path / "run"
    trace_root.mkdir(parents=True)
    run_dir.mkdir()
    store = DecisionTraceStore(trace_root)
    reference = store.put_evidence(kind="fact", payload={"ok": True}, producer="test")
    store.append_event(
        "VAL_1",
        stage="V1",
        actor="validator_agent",
        reason_code="V1_COMPLETED",
        output_refs=(reference,),
    )
    issue = {
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "candidate_disposition": "needs_review",
        "terminal_authority_decision": {
            "schema_version": "zscope.terminal-authority-decision.v3",
            "terminal": True,
            "disposition": "needs_review",
            "reason_code": "NEEDS_REVIEW_OPEN_CLAUSES",
            "authority": "zscope.proof-checker",
            "next_action": "",
            "conflict_resolution": None,
        },
    }
    store.finalize_issue(issue, view_memberships=("with_needs_review",))
    manifest = store.snapshot()
    evidence_path = trace_root / reference
    evidence_path.write_text("{}\n", encoding="utf-8")
    report = {
        "issues_with_needs_review": [issue],
        "candidate_terminal_states": [issue],
        "run_manifest": {"decision_trace": manifest},
    }

    with pytest.raises(BenchmarkError, match="invalid evidence object"):
        benchmark_runner._archive_decision_trace_artifacts(
            report,
            scan_root=scan_root,
            run_dir=run_dir,
            usage_artifact=None,
        )


def test_usage_event_sidecar_rejects_sparse_or_unknown_v1_fields(tmp_path: Path) -> None:
    path = tmp_path / "usage.jsonl"
    sparse = {
        "schema_version": "zscope.llm-usage-event.v1",
        "sequence": 1,
        "call_id": "call-1",
    }
    path.write_text(json.dumps(sparse) + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkError, match="fields do not match v1"):
        benchmark_runner._read_usage_events_jsonl(path)

    event = _usage_event()
    event["future_extension"] = True
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkError, match="unknown=future_extension"):
        benchmark_runner._read_usage_events_jsonl(path)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda row: row.update(schema_version="v0"), "unsupported schema_version"),
        (lambda row: row.update(provider_reported=1), "must be a boolean"),
        (lambda row: row.update(prompt_tokens=True), "non-negative integer"),
        (lambda row: row.update(total_tokens=16), "token totals do not conserve"),
        (lambda row: row.update(cached_prompt_tokens=11), "exceeds prompt_tokens"),
        (lambda row: row.update(reasoning_tokens=6), "exceeds completion_tokens"),
    ],
)
def test_usage_event_sidecar_rejects_invalid_v1_values(
    tmp_path: Path, mutate, message: str
) -> None:
    path = tmp_path / "usage.jsonl"
    event = _usage_event()
    mutate(event)
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkError, match=message):
        benchmark_runner._read_usage_events_jsonl(path)


def test_usage_event_sidecar_rejects_nested_sensitive_body(tmp_path: Path) -> None:
    path = tmp_path / "usage.jsonl"
    event = _usage_event()
    event["attribution"]["extension"] = {
        "nested": [{"reasoningContent": "private chain of thought"}]
    }
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkError, match="reasoning_content"):
        benchmark_runner._read_usage_events_jsonl(path)


def test_usage_event_sidecar_rejects_duplicate_or_out_of_order_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "usage.jsonl"
    first = _usage_event()
    duplicate_call = _usage_event(sequence=2)
    path.write_text(
        json.dumps(first) + "\n" + json.dumps(duplicate_call) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(BenchmarkError, match="duplicate LLM usage call_id"):
        benchmark_runner._read_usage_events_jsonl(path)

    duplicate_sequence = _usage_event(sequence=1, reservation_id="call-2")
    path.write_text(
        json.dumps(first) + "\n" + json.dumps(duplicate_sequence) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(BenchmarkError, match="duplicate LLM usage sequence"):
        benchmark_runner._read_usage_events_jsonl(path)

    skipped = _usage_event(sequence=2, reservation_id="call-2")
    path.write_text(json.dumps(skipped) + "\n", encoding="utf-8")
    with pytest.raises(BenchmarkError, match="must start at 1 and be contiguous"):
        benchmark_runner._read_usage_events_jsonl(path)


def test_usage_event_sidecar_rejects_attribution_dimension_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "usage.jsonl"
    event = _usage_event()
    event["attribution"]["candidate_uid"] = "different-candidate"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkError, match="does not match attribution.candidate_uid"):
        benchmark_runner._read_usage_events_jsonl(path)


def test_usage_event_archive_rejects_path_outside_scan_workspace(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan"
    run_dir = tmp_path / "run"
    scan_root.mkdir()
    run_dir.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")

    with pytest.raises(BenchmarkError, match="escapes the answer-free scan workspace"):
        benchmark_runner._archive_usage_events(
            {"metadata": {"llm_budget": {"usage_events_path": str(outside)}}},
            scan_root=scan_root,
            run_dir=run_dir,
        )


def test_source_line_metrics_ignore_generated_build_tree(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("one\ntwo\nthree\n", encoding="utf-8")
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "api.h").write_text("one\ntwo\n", encoding="utf-8")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "generated.c").write_text("ignored\n", encoding="utf-8")

    metrics = benchmark_runner._source_line_metrics(tmp_path, "c_cpp")

    assert metrics["source_file_count"] == 2
    assert metrics["source_line_count"] == 5
    assert metrics["source_kloc"] == 0.005


def test_clean_defaults_to_preview_and_protects_large_runs(tmp_path: Path, monkeypatch) -> None:
    fixture = tmp_path / "fixture"
    (fixture / "build").mkdir(parents=True)
    (fixture / "build/object.o").write_bytes(b"x")
    (fixture / "benchmark_runs").mkdir()
    (fixture / "benchmark_runs/report.json").write_text("{}", encoding="utf-8")
    spec = SPECS["c_cpp"]
    monkeypatch.setitem(
        SPECS,
        "c_cpp",
        type(spec)("c_cpp", str(fixture), spec.required_tools),
    )
    monkeypatch.setattr("zscope.benchmarking.runner._tracked_paths", lambda: set())

    preview = clean_benchmark_artifacts("c_cpp")
    assert preview["dry_run"] is True
    assert (fixture / "build").exists()
    assert not any(Path(row["path"]).name == "benchmark_runs" for row in preview["targets"])

    clean_benchmark_artifacts("c_cpp", apply=True)
    assert not (fixture / "build").exists()
    assert (fixture / "benchmark_runs").exists()


def test_current_java_entries_have_no_answer_fields() -> None:
    payload = json.loads(
        (SPECS["java"].fixture_root / "benchmark/entries.json").read_text(encoding="utf-8")
    )
    forbidden = {"covers_rule_ids", "cwe", "truth_id", "audit_prompt"}
    assert all(forbidden.isdisjoint(item) for item in payload["functions"])


def test_cpp_run_restarts_inside_wsl_on_windows(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(benchmark_cli.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        benchmark_cli.subprocess,
        "check_output",
        lambda *args, **kwargs: "/mnt/c/work/Z-Scope\n",
    )

    class Completed:
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        return Completed()

    monkeypatch.setattr(benchmark_cli.subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as exit_info:
        benchmark_cli.main(["run", "--language", "c_cpp", "--mode", "smoke"])

    assert exit_info.value.code == 0
    assert captured["argv"][:3] == ["wsl", "bash", "-lc"]
    assert "Z_SCOPE_BENCHMARK_IN_WSL" in captured["env"]["WSLENV"]
    assert "Z_SCOPE_BENCHMARK_WORK_ROOT/p" in captured["env"]["WSLENV"]
