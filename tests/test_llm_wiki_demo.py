from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.score_llm_wiki_demo import score_demo_reports
from zscope.config.config import ConfigLoader


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "test" / "llm_wiki_demo"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_demo_has_five_public_entry_declarations_and_definitions() -> None:
    header = (DEMO / "include" / "wiki_demo_api.h").read_text(encoding="utf-8")
    names = [
        "wiki_copy_label",
        "wiki_execute_command",
        "wiki_decode_frame",
        "wiki_parse_port",
        "wiki_register_callback",
    ]
    assert sum(header.count(f"{name}(") for name in names) == len(names)
    for name in names:
        source_text = "\n".join(
            path.read_text(encoding="utf-8") for path in (DEMO / "src").glob("*.c")
        )
        assert f"{name}(" in source_text


def test_demo_config_uses_cpp_auto_entry_discovery() -> None:
    config = yaml.safe_load((DEMO / "zscope.benchmark.yaml").read_text(encoding="utf-8"))
    project = config["project"]
    discovery = project["entry_discovery"]
    assert project["root"] == "test/llm_wiki_demo"
    assert project["language"] == "c_cpp"
    assert discovery["enabled"] is True
    assert discovery["interface_files"] == ["include/**/*.h"]
    assert discovery["max_entries"] == 5


def test_demo_config_is_accepted_by_public_v2_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("Z_SCOPE_API_KEY", "demo-test-key")
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "https://demo.invalid/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "demo-test-model")
    monkeypatch.chdir(ROOT)
    config = ConfigLoader.load(str(DEMO / "zscope.benchmark.yaml"))
    assert config.project.project_root == DEMO.resolve()
    assert config.project.language == "c_cpp"
    assert config.project.entry_discovery.enabled is True
    assert config.project.entry_discovery.max_entries == 5


def test_demo_wiki_excludes_generated_benchmark_readme_but_keeps_project_readme() -> None:
    config = yaml.safe_load((DEMO / "zscope.llm-wiki-active.yaml").read_text(encoding="utf-8"))
    excludes = config["project"]["wiki"]["documents"]["exclude"]
    assert "benchmark/README.md" in excludes
    assert "README.md" not in excludes


def test_readme_contains_constraints_without_answer_terms() -> None:
    readme = (DEMO / "README.md").read_text(encoding="utf-8")
    for required in (
        "唯一 API 网关",
        "1--31",
        "1024..65535",
        "frame_len <= out_len",
        "互斥锁",
    ):
        assert required in readme
    lowered = readme.lower()
    for forbidden in ("ground_truth", "w iki-demo-vuln", "confirmed", "needs_review"):
        assert forbidden not in lowered.replace(" ", "")


def test_label_transition_uses_high_confidence_fixed_array_shape() -> None:
    source = (DEMO / "src" / "label_store.c").read_text(encoding="utf-8")
    for required in (
        "#define LABEL_CAPACITY 32",
        "char stored_label[LABEL_CAPACITY]",
        "label_len = strlen(label)",
        "index < label_len",
        "stored_label[index] = label[index]",
        "stored_label[label_len] = '\\0'",
    ):
        assert required in source
    assert "strcpy(" not in source


def test_ground_truth_is_scoring_only_and_points_to_existing_code() -> None:
    truth = _load(DEMO / "benchmark" / "ground_truth.json")
    assert truth["benchmark"] == "zscope-llm-wiki-demo"
    assert truth["total_vulnerabilities"] == len(truth["vulnerabilities"]) == 1
    assert len(truth["safe_entries"]) == 4
    assert truth["transition_target"]["function"] == "wiki_copy_label"
    for row in truth["vulnerabilities"]:
        source = DEMO / row["file"]
        lines = source.read_text(encoding="utf-8").splitlines()
        assert 1 <= row["line"] <= len(lines)
        assert row["line"] <= row["end_line"] <= len(lines)
    assert not any(
        path.name == "ground_truth.json"
        for path in (DEMO / "include").rglob("*")
        if path.is_file()
    )


def test_demo_run_contract_enables_clang_tooling() -> None:
    run_contract = (DEMO / "benchmark" / "README.md").read_text(encoding="utf-8")
    assert "ZSCOPE_ENABLE_CLANG_TOOLING=1" in run_contract
    assert "Wiki-off baseline" in run_contract
    assert "Wiki-active scan" in run_contract


def _issue(file: str, function: str, category: str, disposition: str, line: int) -> dict:
    return {
        "file": file,
        "function": function,
        "category": category,
        "line": line,
        "end_line": line,
        "candidate_disposition": disposition,
    }


def test_scorer_reports_both_views_and_expected_transition() -> None:
    truth = _load(DEMO / "benchmark" / "ground_truth.json")
    true_issue = _issue(
        "src/command_runner.c", "wiki_execute_command", "command_injection", "confirmed", 11
    )
    target_off = _issue(
        "src/label_store.c", "wiki_copy_label", "out_of_bounds_write", "confirmed", 18
    )
    target_active = dict(target_off)
    target_active["candidate_disposition"] = "needs_review"
    off = {"issues": [true_issue, target_off]}
    active = {
        "issues": [true_issue],
        "report_views": {"with_needs_review": {"issues": [true_issue, target_active]}},
    }

    metrics = score_demo_reports(off, active, truth)
    assert metrics["transition_check"]["passed"] is True
    assert metrics["views"]["off"]["confirmed"]["precision"] == 0.5
    assert metrics["views"]["active"]["confirmed"]["precision"] == 1.0
    assert metrics["views"]["active"]["with_needs_review"]["recall"] == 1.0
    assert "accuracy" not in metrics["metric_definition"]


@pytest.mark.parametrize("name", ["ground_truth.json", "README.md"])
def test_demo_artifacts_are_utf8(name: str) -> None:
    path = DEMO / "benchmark" / name if name == "ground_truth.json" else DEMO / name
    path.read_text(encoding="utf-8")
