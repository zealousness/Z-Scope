from pathlib import Path

import pytest
import yaml

from zscope.config.config import ConfigLoader


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("filename", "language", "backend"),
    [
        ("zscope.c_cpp.yaml", "c_cpp", "unified"),
        ("zscope.java.yaml", "java", "java_unified"),
    ],
)
def test_language_reference_config_loads(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    language: str,
    backend: str,
) -> None:
    monkeypatch.setenv("Z_SCOPE_API_KEY", "reference-config-test-key")
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://localhost/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "reference-model")
    monkeypatch.chdir(REPO_ROOT)

    config = ConfigLoader.load(str(REPO_ROOT / filename))

    assert config.project.language == language
    assert config.indexing.backend == backend


def test_reference_configs_keep_language_specific_indexing_separate() -> None:
    c_config = yaml.safe_load((REPO_ROOT / "zscope.c_cpp.yaml").read_text(encoding="utf-8"))
    java_config = yaml.safe_load((REPO_ROOT / "zscope.java.yaml").read_text(encoding="utf-8"))

    assert "java" not in c_config["indexing"]
    assert c_config["config_version"] == 2
    assert java_config["config_version"] == 2
    assert set(c_config) == {"config_version", "llms", "project", "scan", "indexing", "concurrency"}
    assert set(java_config) == {
        "config_version",
        "llms",
        "project",
        "scan",
        "indexing",
        "concurrency",
    }
    assert c_config["project"]["compile_commands_path"] == ("build/compile_commands.json")
    assert "java" in java_config["indexing"]
    assert "clangd_path" not in java_config["indexing"]
    assert "svf_bin_dir" not in java_config["indexing"]
    assert "compile_commands_path" not in java_config["project"]
    assert not (REPO_ROOT / "zscope.yaml").exists()
