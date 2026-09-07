"""Workbook README sheet, styling, kind warnings, and infer report tests."""

from __future__ import annotations

import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from zscope.cli.cli import _write_user_config_infer_report
from zscope.config.user_config_workbook import (
    README_SHEET_NAME,
    VALID_KINDS,
    UserConfigWorkbook,
)


def _write_sample_workbook(path: Path) -> None:
    workbook = UserConfigWorkbook(path)
    workbook.write_rows(
        {
            "resource": [
                {
                    "symbol_name": "file_open_wrap",
                    "kind": "io_acquire",
                    "symbol_type": "function",
                    "pair": "file_close_wrap",
                    "description": "resource_output=return",
                    "source": "inferred:body",
                    "confidence": "0.80",
                    "notes": "",
                },
                {
                    "symbol_name": "bad_row",
                    "kind": "magic_kind",
                    "symbol_type": "function",
                    "source": "manual",
                },
            ],
            "lock": [
                {
                    "symbol_name": "mutex_enter",
                    "kind": "lock",
                    "symbol_type": "function",
                    "pair": "mutex_exit",
                    "source": "inferred:body",
                    "confidence": "0.80",
                    "notes": "",
                }
            ],
        }
    )


def test_workbook_writes_readme_sheet_that_reader_ignores(tmp_path: Path) -> None:
    path = tmp_path / "user_config.xlsx"
    _write_sample_workbook(path)

    with zipfile.ZipFile(path) as zf:
        workbook_xml = zf.read("xl/workbook.xml").decode("utf-8")
        assert f'name="{README_SHEET_NAME}"' in workbook_xml
        readme_sheet = zf.read("xl/worksheets/sheet7.xml").decode("utf-8")
        assert "user_config" in readme_sheet  # guide text present

    rows = UserConfigWorkbook(path).read_rows()
    assert README_SHEET_NAME not in rows
    assert [row["symbol_name"] for row in rows["resource"]] == ["file_open_wrap", "bad_row"]


def test_workbook_applies_header_style_and_freeze_pane(tmp_path: Path) -> None:
    path = tmp_path / "user_config.xlsx"
    _write_sample_workbook(path)

    with zipfile.ZipFile(path) as zf:
        styles = zf.read("xl/styles.xml").decode("utf-8")
        assert "<b/>" in styles  # bold header font
        assert "FFD9E1F2" in styles  # header fill color
        sheet = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
        assert 'state="frozen"' in sheet
        assert 's="1"' in sheet  # styled header cells
        assert "customWidth" in sheet


def test_read_rows_collects_unknown_kind_warnings(tmp_path: Path) -> None:
    path = tmp_path / "user_config.xlsx"
    _write_sample_workbook(path)

    workbook = UserConfigWorkbook(path)
    workbook.read_rows()

    assert workbook.read_warnings == [
        "resource:bad_row unknown kind 'magic_kind' (valid: "
        + ", ".join(sorted(VALID_KINDS))
        + ")"
    ]


def test_workbook_round_trip_preserves_rows_and_manual_rows(tmp_path: Path) -> None:
    path = tmp_path / "user_config.xlsx"
    _write_sample_workbook(path)

    workbook = UserConfigWorkbook(path)
    workbook.merge_generated(
        {
            "resource": [
                {
                    "symbol_name": "net_send_wrap",
                    "kind": "send_sink",
                    "source": "inferred:body",
                }
            ]
        }
    )
    rows = UserConfigWorkbook(path).read_rows()
    names = {row["symbol_name"] for row in rows["resource"]}
    # inferred rows not re-generated are cleaned; manual rows are preserved.
    assert "net_send_wrap" in names
    assert "bad_row" in names
    assert "file_open_wrap" not in names


def test_infer_report_includes_rows_warnings_and_stats(tmp_path: Path) -> None:
    generated = {
        "resource": [
            {
                "symbol_name": "file_open_wrap",
                "kind": "io_acquire",
                "pair": "file_close_wrap",
                "confidence": "0.80",
                "source": "inferred:body",
                "description": "resource_output=return",
                "notes": "",
            },
            {
                "symbol_name": "cb_register",
                "kind": "callback_register",
                "pair": "",
                "confidence": "0.60",
                "source": "inferred:body|llm:needs_review",
                "description": "callback_arg=arg1",
                "notes": "llm:conflict",
            },
        ],
        "lock": [
            {
                "symbol_name": "mutex_enter",
                "kind": "lock",
                "pair": "mutex_exit",
                "confidence": "0.80",
                "source": "inferred:body",
                "description": "lock_arg=arg1",
                "notes": "",
            }
        ],
    }
    report_path = _write_user_config_infer_report(
        tmp_path / "user_config.infer_report.md",
        generated,
        {"reviewed": 4, "kept": 2, "revised": 1, "dropped": 1, "recheck": 1, "errors": 0},
        {"collected": 5, "classified": 2, "dropped": 3, "errors": 0},
        {"added": 3, "refreshed": 1, "removed": 0},
        read_warnings=["resource:bad_row unknown kind 'magic_kind'"],
    )
    text = report_path.read_text(encoding="utf-8")

    assert "file_open_wrap" in text
    assert "mutex_exit" in text
    assert "cb_register" in text
    assert "需要人工复核" in text and "cb_register" in text
    assert "工作簿告警" in text and "magic_kind" in text
    assert "rechecked=1" in text
    assert "classified=2" in text
