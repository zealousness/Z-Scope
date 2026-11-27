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
    scan_input_manifest,
)
from zscope.framework.llm_usage import LLMUsageAttribution, LLMUsageEvent


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


def test_cpp_benchmark_concurrency_matches_released_capacity() -> None:
    config = yaml.safe_load(SPECS["c_cpp"].config_path.read_text(encoding="utf-8"))

    # Public v3 keeps runtime concurrency out of the user's YAML.
    assert config["config_version"] == 3
    assert "concurrency" not in config
    assert config["execution"]["max_workers"] == 8
    assert config["llms"]["default"]["base_url_max_concurrent_requests"] == 16


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
    rendered = {}

    def fake_run(spec, run_dir, run_number, *, mode, workspace, scan_depth):
        observed["workspace"] = workspace
        assert scan_depth == "fast"
        assert workspace.is_relative_to(work_parent)
        (workspace / "state").write_text("temporary", encoding="utf-8")
        return {"run": run_number, "mode": mode}

    monkeypatch.setattr(benchmark_runner, "_run_trial_in_workspace", fake_run)
    monkeypatch.setattr(
        benchmark_runner,
        "_render_trial_metrics",
        lambda run_dir, *, language: rendered.update(run_dir=run_dir, language=language),
    )

    result = benchmark_runner._run_trial(SPECS["c_cpp"], artifact, 1, mode="trial")

    assert result == {"run": 1, "mode": "trial"}
    assert rendered == {"run_dir": artifact, "language": "c_cpp"}
    assert not observed["workspace"].exists()


def test_experimental_review_workspace_keeps_bound_dependency_paths(
    monkeypatch, tmp_path: Path
) -> None:
    work_parent = tmp_path / "work"
    work_parent.mkdir()
    monkeypatch.setattr(benchmark_runner, "_benchmark_work_parent", lambda _: work_parent)

    def run(spec, run_dir, run_number, *, mode, workspace, scan_depth):
        (workspace / ".review-checkpoints-retained.json").write_text("{}", encoding="utf-8")
        return {"workspace": workspace}

    monkeypatch.setattr(benchmark_runner, "_run_trial_in_workspace", run)
    monkeypatch.setattr(benchmark_runner, "_render_trial_metrics", lambda *args, **kwargs: None)
    result = benchmark_runner._run_trial(SPECS["c_cpp"], tmp_path / "artifact", 1, mode="trial")
    assert result["workspace"].is_dir()


@pytest.mark.parametrize("fail", [False, True])
def test_explicit_workspace_retains_success_and_failure_without_mkdtemp(
    monkeypatch, tmp_path, fail
):
    root = tmp_path / "persistent"
    artifact = tmp_path / "artifact"
    artifact.mkdir()

    def forbidden(*args, **kwargs):
        raise AssertionError("explicit workspaces must not use a temporary directory")

    def run(spec, run_dir, run_number, *, mode, workspace, scan_depth, retain_workspace):
        assert retain_workspace is True
        state = workspace / "scan-input" / ".zscope_snapshots"
        state.mkdir(parents=True)
        (state / "state.db").write_bytes(b"retained")
        if fail:
            raise RuntimeError("simulated interruption")
        return {"workspace": str(workspace)}

    monkeypatch.setattr(benchmark_runner.tempfile, "mkdtemp", forbidden)
    monkeypatch.setattr(benchmark_runner, "_run_trial_in_workspace", run)
    monkeypatch.setattr(benchmark_runner, "_render_trial_metrics", lambda *args, **kwargs: None)
    if fail:
        with pytest.raises(RuntimeError, match="simulated interruption"):
            benchmark_runner._run_trial(
                SPECS["c_cpp"], artifact, 1, mode="trial", work_directory=root
            )
    else:
        benchmark_runner._run_trial(SPECS["c_cpp"], artifact, 1, mode="trial", work_directory=root)
    assert (root / "run-01/scan-input/.zscope_snapshots/state.db").read_bytes() == b"retained"
    assert json.loads((artifact / "workspace.json").read_text())["temporary"] is False
    with pytest.raises(FileExistsError):
        benchmark_runner._run_trial(SPECS["c_cpp"], artifact, 1, mode="trial", work_directory=root)


def test_explicit_work_directory_must_be_new_absolute_and_native(monkeypatch, tmp_path):
    with pytest.raises(BenchmarkError, match="absolute"):
        run_benchmark("c_cpp", "trial", dry_run=True, work_directory=Path("relative"))
    with pytest.raises(BenchmarkError, match="already exist"):
        run_benchmark("c_cpp", "trial", dry_run=True, work_directory=tmp_path)
    monkeypatch.setattr(benchmark_runner, "_is_wsl", lambda: True)
    monkeypatch.setattr(benchmark_runner, "_is_windows_mount_in_wsl", lambda _: True)
    with pytest.raises(BenchmarkError, match="WSL native"):
        run_benchmark("c_cpp", "trial", dry_run=True, work_directory=tmp_path / "new")


def test_windows_forwarding_keeps_explicit_linux_workspace(monkeypatch):
    monkeypatch.setattr(benchmark_cli.subprocess, "check_output", lambda *a, **kw: "/mnt/c/repo\n")
    argv = benchmark_cli._wsl_argv(["run", "--work-directory", "/home/runner/benchmark-runs/cold-01"])
    assert "/home/runner/benchmark-runs/cold-01" in argv[-1]


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


def test_archive_scan_extras_copies_conversations_and_skips_sealed_build(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan"
    run_dir = tmp_path / "run"
    (scan_root / "src").mkdir(parents=True)
    (scan_root / "src/main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (scan_root / "CMakeLists.txt").write_text("project(test C)\n", encoding="utf-8")
    (scan_root / "README.md").write_text("neutral\n", encoding="utf-8")
    manifest = scan_input_manifest(scan_root)
    conversation = scan_root / ".zscope_conversations" / "run-abc" / "session.jsonl"
    conversation.parent.mkdir(parents=True)
    conversation.write_text('{"event":"session_start"}\n', encoding="utf-8")
    snapshot = scan_root / ".zscope_snapshots" / "state.json"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text("{}", encoding="utf-8")
    (scan_root / "build").mkdir()
    (scan_root / "build/object.o").write_bytes(b"obj")
    (scan_root / "zscope_batch_report.json").write_text("{}", encoding="utf-8")
    oci_output = tmp_path / "oci-output"
    oci_output.mkdir()
    (oci_output / "container.log").write_text("ok\n", encoding="utf-8")
    run_dir.mkdir()

    extras = benchmark_runner._archive_scan_extras(
        execution_root=scan_root,
        run_dir=run_dir,
        input_manifest=manifest,
        extra_roots={"oci-output": oci_output},
    )

    archived = {row["path"] for row in extras["files"]}
    assert extras["conversation_present"] is True
    assert extras["file_count"] == 4
    assert ".zscope_conversations/run-abc/session.jsonl" in archived
    assert ".zscope_snapshots/state.json" in archived
    assert "zscope_batch_report.json" in archived
    assert "oci-output/container.log" in archived
    assert "src/main.c" not in archived
    assert "build/object.o" not in archived
    copied = run_dir / "scan-extras/.zscope_conversations/run-abc/session.jsonl"
    assert copied.read_text(encoding="utf-8") == '{"event":"session_start"}\n'
    assert (run_dir / "scan-extras-manifest.json").is_file()


def test_archive_scan_extras_allows_missing_conversations(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan"
    run_dir = tmp_path / "run"
    scan_root.mkdir()
    (scan_root / "README.md").write_text("neutral\n", encoding="utf-8")
    run_dir.mkdir()

    extras = benchmark_runner._archive_scan_extras(
        execution_root=scan_root,
        run_dir=run_dir,
        input_manifest=scan_input_manifest(scan_root),
    )

    assert extras["file_count"] == 0
    assert extras["conversation_present"] is False
    assert extras["files"] == []


def test_archive_scan_extras_rejects_symlink(tmp_path: Path) -> None:
    scan_root = tmp_path / "scan"
    run_dir = tmp_path / "run"
    scan_root.mkdir()
    run_dir.mkdir()
    target = tmp_path / "outside.jsonl"
    target.write_text("secret\n", encoding="utf-8")
    conversations = scan_root / ".zscope_conversations"
    conversations.mkdir()
    (conversations / "session.jsonl").symlink_to(target)

    with pytest.raises(BenchmarkError, match="symbolic link"):
        benchmark_runner._archive_scan_extras(
            execution_root=scan_root,
            run_dir=run_dir,
            input_manifest={"files": []},
        )


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
