import json

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

    loaded = server.load_report()

    assert loaded["findings"][0]["id"] == "F-1"


def test_load_report_returns_empty_when_report_missing_in_current_directory(tmp_path, monkeypatch):
    cwd = tmp_path / "run-dir"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    loaded = server.load_report()

    assert loaded == {
        "issues": [],
        "issues_by_severity": {"critical": [], "high": [], "medium": [], "low": []},
    }
