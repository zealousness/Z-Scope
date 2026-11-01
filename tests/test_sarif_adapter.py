import json
from pathlib import Path

import pytest

from zscope.alerts.sarif_adapter import SarifAdapter


def _document(uri: str) -> dict:
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": 12},
        }
    }
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Example"}},
                "results": [
                    {
                        "ruleId": "example/rule",
                        "message": {"text": "A finding " * 100},
                        "locations": [location],
                        "codeFlows": [{"threadFlows": [{"locations": [{"location": location}]}]}],
                    }
                ],
            }
        ],
    }


def test_inline_document_does_not_probe_filesystem(monkeypatch, tmp_path):
    def unexpected_probe(_path):
        pytest.fail("inline SARIF was interpreted as a filename")

    monkeypatch.setattr(Path, "is_file", unexpected_probe)
    alerts = SarifAdapter(str(tmp_path)).parse(json.dumps(_document("src/demo.c")))

    assert len(alerts) == 1
    assert alerts[0].file_path == str(tmp_path / "src/demo.c")


def test_file_input_accepts_utf8_bom(tmp_path):
    source = tmp_path / "alerts.sarif"
    source.write_text(json.dumps(_document("demo.c")), encoding="utf-8-sig")

    assert len(SarifAdapter().parse(str(source))) == 1


@pytest.mark.parametrize("document", ["[]", "null", '{"runs": {}}'])
def test_non_sarif_json_returns_no_alerts(document):
    assert SarifAdapter().parse(document) == []


def test_encoded_relative_paths_are_decoded_for_alerts_and_flow_steps(tmp_path):
    uri = "src/a%20b%23c%25%3F.c"
    alerts = SarifAdapter(str(tmp_path)).parse(json.dumps(_document(uri)))
    expected = str(tmp_path / "src/a b#c%?.c")

    assert alerts[0].file_path == expected
    assert alerts[0].code_flows[0]["steps"][0]["file"] == expected


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("file:///tmp/a%20b.c", "/tmp/a b.c"),
        ("file://localhost/tmp/a%20b.c", "/tmp/a b.c"),
        ("file:///C:/src/a%20b.c", "C:/src/a b.c"),
        ("file://server/share/a%20b.c", "//server/share/a b.c"),
        ("C:/src/a%20b.c", "C:/src/a b.c"),
    ],
)
def test_absolute_artifact_uris_are_not_prefixed_with_source_root(uri, expected):
    alerts = SarifAdapter("/project").parse(json.dumps(_document(uri)))

    assert alerts[0].file_path == expected


def test_remote_artifacts_are_not_treated_as_project_files():
    document = _document("https://example.invalid/source.c")
    assert SarifAdapter("/project").parse(json.dumps(document)) == []


@pytest.mark.parametrize("uri", ["file://[broken/path.c", "file://localhost"])
def test_invalid_artifacts_do_not_prevent_other_results_from_loading(uri):
    document = _document(uri)
    document["runs"][0]["results"].extend(_document("src/valid.c")["runs"][0]["results"])

    alerts = SarifAdapter().parse(json.dumps(document))

    assert [alert.file_path for alert in alerts] == ["src/valid.c"]
