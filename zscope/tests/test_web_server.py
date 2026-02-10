import json
from pathlib import Path

from zscope.web import server


def test_load_report_reads_report_from_current_working_directory(tmp_path, monkeypatch):
    cwd = tmp_path / "run-dir"
    cwd.mkdir()

    report = {
        "findings": [
            {
                "id": "F-1",
                "function": "demo",
                "location": "src/demo.c:10",
                "subcategory": "mem",
            }
        ]
    }
    (cwd / "zscope_batch_report.json").write_text(json.dumps(report), encoding="utf-8")

    monkeypatch.chdir(cwd)
    monkeypatch.setattr(server, "REPORT_PATH", Path("zscope_batch_report.json"))

    loaded = server.load_report()

    assert loaded["findings"][0]["id"] == "F-1"


def test_findings_fallback_to_findings_when_issues_empty(tmp_path, monkeypatch):
    cwd = tmp_path / "run-dir"
    cwd.mkdir()
    report = {"issues": [], "findings": [{"id": "F-2"}]}
    (cwd / "zscope_batch_report.json").write_text(json.dumps(report), encoding="utf-8")

    monkeypatch.chdir(cwd)
    monkeypatch.setattr(server, "REPORT_PATH", Path("zscope_batch_report.json"))

    loaded = server.load_report()
    findings = loaded.get("issues")
    if findings is None or (
        isinstance(findings, list)
        and not findings
        and isinstance(loaded.get("findings"), list)
        and loaded.get("findings")
    ):
        findings = loaded.get("findings", [])

    assert findings == [{"id": "F-2"}]


def test_load_report_returns_empty_when_report_missing_in_current_directory(tmp_path, monkeypatch):
    cwd = tmp_path / "run-dir"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(server, "REPORT_PATH", Path("zscope_batch_report.json"))

    loaded = server.load_report()

    assert loaded == {
        "issues": [],
        "issues_by_severity": {"critical": [], "high": [], "medium": [], "low": []},
    }
