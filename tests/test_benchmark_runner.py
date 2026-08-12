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


def test_cpp_benchmark_restores_validator_capacity_without_raising_llm_cap() -> None:
    config = yaml.safe_load(SPECS["c_cpp"].config_path.read_text(encoding="utf-8"))

    assert config["concurrency"]["validator_workers"] == 4
    assert config["concurrency"]["llm_max_inflight"] == 4
    assert config["llms"]["default"]["base_url_max_concurrent_requests"] == 4


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

    def fake_run(spec, run_dir, run_number, *, mode, workspace):
        observed["workspace"] = workspace
        assert workspace.is_relative_to(work_parent)
        (workspace / "state").write_text("temporary", encoding="utf-8")
        return {"run": run_number, "mode": mode}

    monkeypatch.setattr(benchmark_runner, "_run_trial_in_workspace", fake_run)

    result = benchmark_runner._run_trial(SPECS["c_cpp"], artifact, 1, mode="trial")

    assert result == {"run": 1, "mode": "trial"}
    assert not observed["workspace"].exists()


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
