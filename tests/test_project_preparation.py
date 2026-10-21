import json
from pathlib import Path

from click.testing import CliRunner

from test_config_v2 import _config, _write
from zscope.cli.config_cli import main
from zscope.config.config import ConfigLoader
from zscope.config.preparation import prepare_project
from zscope.web.services import ConfigService


def test_cli_and_web_share_the_same_profile_without_exposing_model_credentials(
    tmp_path, monkeypatch
):
    def prohibited(*args, **kwargs):
        raise AssertionError("preparation must not run tools, models, providers or rollout writes")

    monkeypatch.setattr("subprocess.run", prohibited)
    monkeypatch.setattr("zscope.rules.extensions.preflight_rules", prohibited)
    monkeypatch.setattr("zscope.orchestration.rollout.apply_persisted_rollout_policy", prohibited)
    monkeypatch.setattr("zscope.framework.llm_client.LLMClient.chat_completion", prohibited)
    project = tmp_path / "工程 with spaces"
    project.mkdir()
    source = project / "unit.c"
    source.write_text("int main(void) { return 0; }\n")
    rows = [{"directory": str(project), "file": "unit.c", "arguments": ["clang", "-c", "unit.c"]}]
    (project / "compile_commands.json").write_text(
        json.dumps([*rows, *rows, {**rows[0], "arguments": [*rows[0]["arguments"], "-DALT"]}])
    )
    document = _config(project)
    document["project"]["compile_commands_path"] = "compile_commands.json"
    document["llms"]["default"]["api_key"] = "preparation-secret"
    path = _write(tmp_path, document)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    web = ConfigService(path).prepare_project()
    cli = CliRunner().invoke(main, ["prepare", "--config", str(path), "--json"])
    assert cli.exit_code == 0, cli.output
    assert json.loads(cli.output) == web
    assert "preparation-secret" not in cli.output
    assert "http://localhost" not in cli.output
    assert web["build"]["compilation_instances"] == 2
    assert web["build"]["sources"] == 1
    assert web["build"]["link_targets"] == "unverified"
    assert web["project"]["root"] == str(project)
    assert web["models"][0]["connection_checked"] is False
    assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


def test_invalid_and_missing_database_have_actionable_messages(tmp_path):
    document = _config(tmp_path)
    document["project"]["compile_commands_path"] = "compile_commands.json"
    path = _write(tmp_path, document)
    config = ConfigLoader.load(str(path))
    report = prepare_project(config, path)
    assert report["build"]["status"] == "missing"
    assert report["messages"][0]["code"] == "compile_commands_missing"
    (tmp_path / "compile_commands.json").write_text("{ invalid json")
    report = prepare_project(config, path)
    assert report["build"]["status"] == "invalid"
    (tmp_path / "compile_commands.json").write_text(json.dumps([{}, {"file": "a.c"}]))
    report = prepare_project(config, path)
    assert report["build"]["status"] == "partial"
    assert report["build"]["invalid_rows"] == 2


def test_java_preparation_does_not_request_cpp_tools(tmp_path):
    path = _write(tmp_path, _config(tmp_path, language="java"))
    report = ConfigService(path).prepare_project()
    assert report["build"]["status"] == "not_applicable"
    assert not report["tools"]
    assert not any(message["code"].startswith("compile_commands") for message in report["messages"])


def test_web_preparation_endpoint_reports_saved_config_and_invalid_config(tmp_path, monkeypatch):
    from zscope.web import server

    path = _write(tmp_path, _config(tmp_path))
    service = ConfigService(path, scan_depth="balanced")
    monkeypatch.setattr(server, "_config_service", service)
    handler = object.__new__(server.ZScopeHandler)
    handler.path = "/api/scan/prepare"
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((status, payload))
    handler.do_GET()
    assert sent[0][0] == 200
    assert sent[0][1]["config_path"] == str(path)
    assert sent[0][1]["scan"]["depth"] == "balanced"
    path.write_text("invalid: true\n")
    handler.do_GET()
    assert sent[-1][0] == 400
    assert sent[-1][1]["error"]
