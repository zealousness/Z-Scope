from pathlib import Path

import pytest
import yaml

from zscope.config.config import ConfigLoader
from zscope.config.v3 import V3_TOP_LEVEL_KEYS, parse_user_config_v3


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("filename", "language", "preset", "mapped_depth"),
    [
        ("zscope.c_cpp.yaml", "c_cpp", "overnight", "deep"),
        ("zscope.java.yaml", "java", "quick", "fast"),
    ],
)
def test_language_reference_config_loads_as_strict_v3(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    language: str,
    preset: str,
    mapped_depth: str,
) -> None:
    monkeypatch.setenv("Z_SCOPE_API_KEY", "reference-config-test-key")
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://localhost/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "reference-model")
    monkeypatch.chdir(REPO_ROOT)

    model = parse_user_config_v3(str(REPO_ROOT / filename))

    assert model.project.language == language
    assert model.project.root == REPO_ROOT.resolve()
    assert [target.id for target in model.project.targets] == ["main"]
    assert model.scan.preset == preset
    assert model.scan.mapped_depth == mapped_depth

    config = ConfigLoader.load(str(REPO_ROOT / filename))
    assert config.user_config_version == 3
    assert config.project.language == language


def test_reference_configs_keep_language_specific_targets_separate() -> None:
    c_config = yaml.safe_load((REPO_ROOT / "zscope.c_cpp.yaml").read_text(encoding="utf-8"))
    java_config = yaml.safe_load((REPO_ROOT / "zscope.java.yaml").read_text(encoding="utf-8"))

    assert c_config["config_version"] == 3
    assert java_config["config_version"] == 3
    assert set(c_config) == set(V3_TOP_LEVEL_KEYS)
    assert set(java_config) == set(V3_TOP_LEVEL_KEYS)
    assert c_config["project"]["targets"] == [
        {"id": "main", "compile_commands": "build/compile_commands.json"}
    ]
    assert java_config["project"]["targets"] == [{"id": "main"}]
    assert "compile_commands" not in java_config["project"]["targets"][0]
    assert c_config["scan"]["preset"] == "overnight"
    assert java_config["scan"]["preset"] == "quick"
    assert not (REPO_ROOT / "zscope.yaml").exists()


def test_reference_configs_keep_credentials_in_env_refs_and_hide_tool_paths() -> None:
    for filename in ("zscope.c_cpp.yaml", "zscope.java.yaml"):
        source = (REPO_ROOT / filename).read_text(encoding="utf-8")
        assert "${Z_SCOPE_LLM_BASE_URL}" in source
        assert "${Z_SCOPE_LLM_MODEL}" in source
        assert "${Z_SCOPE_API_KEY}" in source
        for forbidden in (
            "extractor_command",
            "provider_commands",
            "svf_bin_dir",
            "clangd_path",
            "java -jar",
            "/path/to",
            "http://localhost",
        ):
            assert forbidden not in source


def test_reference_configs_disclose_unconsumed_fields_as_comments_only() -> None:
    # focus/reproduction and the execution window stay commented examples:
    # the templates must not declare them as if anything consumed them.
    c_config = yaml.safe_load((REPO_ROOT / "zscope.c_cpp.yaml").read_text(encoding="utf-8"))
    java_config = yaml.safe_load((REPO_ROOT / "zscope.java.yaml").read_text(encoding="utf-8"))
    for config in (c_config, java_config):
        assert set(config["scan"]) == {"preset"}
        assert config["execution"] is None
