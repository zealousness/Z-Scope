from pathlib import Path
from subprocess import CompletedProcess

from zscope.common.joern_client import JoernClient


def test_joern_cli_query_uses_loaded_cpg_and_marker_json(monkeypatch, tmp_path) -> None:
    cpg_path = tmp_path / "cpg.bin"
    cpg_path.write_bytes(b"")
    client = JoernClient(joern_path="joern")
    client._cli_mode = True
    client._cpg_path = str(cpg_path)
    calls = {}

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        calls["cmd"] = cmd
        calls["script"] = Path(cmd[-1]).read_text(encoding="utf-8")
        return CompletedProcess(
            cmd,
            0,
            stdout='noise\n__ZSCOPE_JSON_BEGIN__\n[{"method":"api_recv"}]\n__ZSCOPE_JSON_END__\n',
            stderr="",
        )

    monkeypatch.setattr("zscope.common.joern_client.subprocess.run", fake_run)

    result = client.query('cpg.method.name("api_recv").l.toJson')

    assert result == [{"method": "api_recv"}]
    assert calls["cmd"][:2] == ["joern", "--nocolors"]
    assert "val __zscope_result" in calls["script"]
    assert "importCpg(" in calls["script"]
    assert str(cpg_path.resolve()).replace("\\", "\\\\") in calls["script"]
    assert 'cpg.method.name("api_recv").l.toJson' in calls["script"]


def test_joern_cli_import_reuses_existing_cpg(tmp_path) -> None:
    cpg_path = tmp_path / "cpg.bin"
    cpg_path.write_bytes(b"")
    client = JoernClient(joern_path="joern")
    client._cli_mode = True

    assert client.import_cpg(str(tmp_path))
    assert client.cpg_status == "ready"
    assert client._cpg_path == str(cpg_path)


def test_joern_windows_batch_launcher_prefers_cli_mode() -> None:
    client = JoernClient(joern_path=r"C:\tmp\joern\joern-cli\joern.bat")

    assert client.start_server()
    assert client._cli_mode


def test_joern_parse_path_follows_joern_binary_location() -> None:
    assert JoernClient(joern_path="joern")._joern_parse_path() == "joern-parse"
    assert JoernClient(joern_path=r"C:\tmp\joern\joern-cli\joern.bat")._joern_parse_path().endswith(
        "joern-parse.bat"
    )
    assert JoernClient(joern_path="/opt/joern/joern-cli/joern")._joern_parse_path() == (
        "/opt/joern/joern-cli/joern-parse"
    )
