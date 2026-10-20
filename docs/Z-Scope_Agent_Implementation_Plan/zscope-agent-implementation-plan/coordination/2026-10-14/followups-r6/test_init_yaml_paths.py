"""Coordinator probe for real CLI serialization of user-selected paths."""

from click.testing import CliRunner
import pytest

from zscope.cli.init import main
from zscope.config.v3 import parse_user_config_v3


@pytest.mark.parametrize("dirname", ["source # preserved", "source: preserved"])
def test_init_preserves_yaml_sensitive_project_paths(tmp_path, monkeypatch, dirname):
    root = tmp_path / dirname
    root.mkdir()
    (root / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    config = tmp_path / "configs" / "zscope.yaml"
    for key, value in {"Z_SCOPE_LLM_BASE_URL": "http://dummy.invalid/v1",
                       "Z_SCOPE_LLM_MODEL": "dummy", "Z_SCOPE_API_KEY": "dummy"}.items():
        monkeypatch.setenv(key, value)
    result = CliRunner().invoke(main, ["--language", "c_cpp", "--project-root", str(root),
                                      "--output", str(config), "--no-interactive"])
    assert result.exit_code == 0, result.output
    model = parse_user_config_v3(str(config))
    assert model.project.root == root.resolve()
