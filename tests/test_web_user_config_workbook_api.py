import json
import sqlite3
from pathlib import Path

import pytest

from zscope.config.user_config_store import UserConfigStore
from zscope.config.user_config_workbook import SHEET_HEADERS
from zscope.web.services import (
    CpgService,
    ConfigService,
    ReportFeedbackService,
    SourceSnippetService,
    UserConfigService,
    WorkbookService,
)


def test_workbook_payload_includes_all_user_config_sheets(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path / "user_config.xlsx")

    payload = WorkbookService(store).payload()
    service_payload = WorkbookService(store).payload()

    assert payload["headers"] == SHEET_HEADERS
    assert service_payload["headers"] == SHEET_HEADERS
    assert set(payload["rows"]) == set(SHEET_HEADERS)
    assert [sheet["name"] for sheet in payload["sheets"]] == list(SHEET_HEADERS)
    for sheet in payload["sheets"]:
        assert sheet["headers"] == SHEET_HEADERS[sheet["name"]]
        assert sheet["rows"] == []


def test_workbook_rows_payload_round_trips_through_store(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    rows = {name: [] for name in SHEET_HEADERS}
    rows["dispatcher"] = [
        {
            "dispatcher_name": "ZipDispatch",
            "file_path": "src/zip.c",
            "message_type": "ZIP_OPEN",
            "handler_name": "handle_zip_open",
            "handler_kind": "callback",
            "resource": "zip_handle",
            "pair": "handle_zip_close",
            "description": "zip dispatcher branch",
            "source": "user",
            "confidence": "0.90",
            "notes": "added from dashboard",
        }
    ]

    parsed_rows = WorkbookService.rows_from_payload({"rows": rows})
    store.workbook.write_rows(parsed_rows)
    payload = WorkbookService(store).payload()

    assert payload["rows"]["dispatcher"] == rows["dispatcher"]


def test_workbook_rows_payload_accepts_sheet_list_shape() -> None:
    payload = {
        "sheets": [
            {
                "name": "module_lifecycle",
                "rows": [
                    {
                        "symbol_name": "ZipInit",
                        "file_path": "src/zip.c",
                        "kind": "init",
                        "pair": "ZipFinit",
                    }
                ],
            }
        ]
    }

    rows = WorkbookService.rows_from_payload(payload)

    assert rows["module_lifecycle"][0]["symbol_name"] == "ZipInit"
    assert rows["resource"] == []


def test_workbook_rows_payload_rejects_unknown_shape() -> None:
    with pytest.raises(ValueError, match="Expected workbook rows or sheets"):
        WorkbookService.rows_from_payload({"items": []})


def _v2_config(root: Path) -> dict:
    return {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {
            "root": str(root),
            "source_root": ".",
            "language": "c_cpp",
            "entry_function": "main",
            "include_paths": ["include"],
            "exclude_paths": ["build"],
        },
        "scan": {"task": ""},
        "indexing": {"backend": "regex"},
        "concurrency": {
            "entry_workers": 2,
            "validator_workers": 2,
            "investigator_workers": 1,
            "evidence_completion_workers": 2,
            "index_workers": 2,
            "svf_workers": 1,
            "llm_max_inflight": 2,
        },
    }


def test_structured_config_round_trips_yaml_document(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = _v2_config(tmp_path)

    service = ConfigService()
    service.save_document(config)
    payload = service.structured_payload()

    assert payload["config"]["project"]["entry_function"] == "main"
    assert payload["config"]["indexing"]["backend"] == "regex"
    assert "Web UI 结构化配置编辑器" in (tmp_path / "zscope.yaml").read_text(encoding="utf-8")


def test_workbook_import_normalizes_uploaded_xlsx(tmp_path: Path) -> None:
    source = UserConfigStore(tmp_path / "source.xlsx")
    rows = {name: [] for name in SHEET_HEADERS}
    rows["resource"] = [
        {
            "symbol_name": "zip_alloc",
            "kind": "alloc",
            "symbol_type": "function",
            "pair": "zip_free",
            "description": "zip allocator",
            "source": "user",
            "confidence": "0.95",
            "notes": "",
        }
    ]
    source.workbook.write_rows(rows)

    target = UserConfigStore(tmp_path / "target.xlsx")
    upload = tmp_path / "target.upload.tmp.xlsx"
    upload.write_bytes((tmp_path / "source.xlsx").read_bytes())
    imported = type(target.workbook)(upload).read_rows()
    target.workbook.write_rows(imported)

    assert target.workbook.read_rows()["resource"][0]["symbol_name"] == "zip_alloc"


def test_workbook_service_download_creates_empty_workbook(tmp_path: Path) -> None:
    workbook_path = tmp_path / "download.xlsx"
    store = UserConfigStore(workbook_path)
    workbook_path.unlink(missing_ok=True)
    service = WorkbookService(store)

    data = service.download_bytes()

    assert data
    assert workbook_path.exists()
    assert store.workbook.read_rows()["resource"] == []


def test_config_service_uses_explicit_path(tmp_path: Path) -> None:
    config_path = tmp_path / "custom.yaml"
    service = ConfigService(config_path)

    service.save_document(_v2_config(tmp_path))

    assert service.structured_payload()["config"]["project"]["entry_function"] == "main"
    assert config_path.exists()


def test_report_feedback_service_saves_validation_feedback(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        """
        {
          "issues": [
            {
              "id": "ISSUE_1",
              "function": "entry",
              "location": "src/demo.c:42",
              "defect_class": "double_free",
              "validation_status": "pending",
              "validation_reasoning": "validator: free after ownership transfer",
              "dedup_key": "double_free|entry|src/demo.c:42"
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    service = ReportFeedbackService(store, report_filename=str(report_path))

    payload = service.save_validation_feedback(
        [
            {
                "id": "ISSUE_1",
                "function": "entry",
                "location": "src/demo.c:42",
                "defect_class": "double_free",
                "validation_status": "rejected",
                "validation_reasoning": "validator: free after ownership transfer",
                "user_rebuttal": "manual review: guard releases before second free",
                "dedup_key": "double_free|entry|src/demo.c:42",
            }
        ]
    )
    saved = service.load_report()

    assert payload["success"] is True
    assert payload["db_persisted"] is True
    assert saved["issues"][0]["validation_status"] == "rejected"
    # Validator 原始说明必须保留，用户反驳说明独立持久化。
    assert (
        saved["issues"][0]["validation_reasoning"]
        == "validator: free after ownership transfer"
    )
    assert (
        saved["issues"][0]["user_rebuttal"]
        == "manual review: guard releases before second free"
    )
    assert store.is_false_positive("entry", "src/demo.c:42", "double_free")
    baseline = store.get_finding_baseline("double_free|entry|src/demo.c:42")
    assert baseline["status"] == "false_positive"
    assert (
        json.loads(baseline["issue_json"]).get("user_rebuttal")
        == "manual review: guard releases before second free"
    )

    with sqlite3.connect(store.db_path) as conn:
        reason = conn.execute(
            "SELECT reason FROM finding_suppressions WHERE func_name = ? AND location = ?",
            ("entry", "src/demo.c:42"),
        ).fetchone()[0]
    assert reason == "manual review: guard releases before second free"


def test_report_feedback_service_rejected_persists_rebuttal_to_snapshots(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    issue = {
        "id": "ISSUE_1",
        "function": "entry",
        "location": "src/demo.c:42",
        "defect_class": "double_free",
        "validation_status": "pending",
        "validation_reasoning": "validator: free after ownership transfer",
        "dedup_key": "double_free|entry|src/demo.c:42",
    }
    report_path.write_text(json.dumps({"issues": [dict(issue)]}), encoding="utf-8")
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir()
    snapshot_report = snapshot_dir / "entry_final.json"
    snapshot_report.write_text(json.dumps({"issues": [dict(issue)]}), encoding="utf-8")
    snapshot_store = type("FakeSnapshotStore", (), {"snapshot_dir": snapshot_dir})()

    store = UserConfigStore(tmp_path / "user_config.xlsx")
    service = ReportFeedbackService(
        store,
        snapshot_store,
        report_filename=str(report_path),
    )

    payload = service.save_validation_feedback(
        [
            {
                **issue,
                "validation_status": "rejected",
                "user_rebuttal": "user: guard prevents the second free",
            }
        ]
    )
    snapshot_saved = json.loads(snapshot_report.read_text(encoding="utf-8"))

    assert payload["success"] is True
    assert snapshot_saved["issues"][0]["validation_status"] == "rejected"
    # Validator 原始说明不被拒绝操作覆盖，反驳说明与用户拒绝来源一起落盘。
    assert (
        snapshot_saved["issues"][0]["validation_reasoning"]
        == "validator: free after ownership transfer"
    )
    assert (
        snapshot_saved["issues"][0]["user_rebuttal"]
        == "user: guard prevents the second free"
    )
    assert snapshot_saved["issues"][0]["rejection_source"] == "user"

    with sqlite3.connect(store.db_path) as conn:
        reason = conn.execute(
            "SELECT reason FROM finding_suppressions WHERE func_name = ? AND location = ?",
            ("entry", "src/demo.c:42"),
        ).fetchone()[0]
    assert reason == "user: guard prevents the second free"


def test_report_feedback_service_rebuttal_only_update_preserves_status_and_reasoning(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "issues": [
                    {
                        "id": "ISSUE_1",
                        "function": "entry",
                        "location": "src/demo.c:42",
                        "defect_class": "double_free",
                        "validation_status": "needs_review",
                        "validation_reasoning": "validator: conflicting guard evidence",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    service = ReportFeedbackService(report_filename=str(report_path))

    service.save_validation_feedback(
        [
            {
                "id": "ISSUE_1",
                "function": "entry",
                "location": "src/demo.c:42",
                "defect_class": "double_free",
                "validation_status": "needs_review",
                "validation_reasoning": "validator: conflicting guard evidence",
                "user_rebuttal": "reviewer: guard is unreachable on this path",
            }
        ]
    )
    saved = service.load_report()

    assert saved["issues"][0]["validation_status"] == "needs_review"
    assert (
        saved["issues"][0]["validation_reasoning"]
        == "validator: conflicting guard evidence"
    )
    assert (
        saved["issues"][0]["user_rebuttal"]
        == "reviewer: guard is unreachable on this path"
    )


def test_report_feedback_service_partial_updates_preserve_other_issue_statuses(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "issues": [
                    {
                        "id": "ISSUE_1",
                        "function": "entry",
                        "location": "src/demo.c:42",
                        "defect_class": "double_free",
                        "validation_status": "pending",
                    },
                    {
                        "id": "ISSUE_2",
                        "function": "entry",
                        "location": "src/demo.c:64",
                        "defect_class": "bounds",
                        "validation_status": "pending",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    service = ReportFeedbackService(report_filename=str(report_path))

    service.save_validation_feedback(
        [
            {
                "id": "ISSUE_1",
                "function": "entry",
                "location": "src/demo.c:42",
                "defect_class": "double_free",
                "validation_status": "rejected",
                "validation_reasoning": "A reviewed issue1",
            }
        ]
    )
    service.save_validation_feedback(
        [
            {
                "id": "ISSUE_2",
                "function": "entry",
                "location": "src/demo.c:64",
                "defect_class": "bounds",
                "validation_status": "validated",
                "validation_reasoning": "B reviewed issue2",
            }
        ]
    )

    saved = service.load_report()

    assert saved["issues"][0]["validation_status"] == "rejected"
    assert saved["issues"][0]["validation_reasoning"] == "A reviewed issue1"
    assert saved["issues"][1]["validation_status"] == "validated"
    assert saved["issues"][1]["validation_reasoning"] == "B reviewed issue2"


def test_report_feedback_service_can_skip_snapshot_persistence_for_single_save(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    issue = {
        "id": "ISSUE_1",
        "function": "entry",
        "location": "src/demo.c:42",
        "defect_class": "double_free",
        "validation_status": "pending",
        "dedup_key": "double_free|entry|src/demo.c:42",
    }
    report_path.write_text(json.dumps({"issues": [dict(issue)]}), encoding="utf-8")
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir()
    snapshot_report = snapshot_dir / "entry_final.json"
    snapshot_report.write_text(json.dumps({"issues": [dict(issue)]}), encoding="utf-8")
    snapshot_store = type("FakeSnapshotStore", (), {"snapshot_dir": snapshot_dir})()

    store = UserConfigStore(tmp_path / "user_config.xlsx")
    service = ReportFeedbackService(
        store,
        snapshot_store,
        report_filename=str(report_path),
    )

    payload = service.save_validation_feedback(
        [
            {
                **issue,
                "validation_status": "validated",
                "validation_reasoning": "manual confirmation",
            }
        ],
        persist_snapshots=False,
        save_scope="single",
    )

    saved = service.load_report()
    snapshot_saved = json.loads(snapshot_report.read_text(encoding="utf-8"))

    assert payload["success"] is True
    assert payload["save_scope"] == "single"
    assert payload["snapshot_persistence"]["skipped"] is True
    assert payload["snapshot_persistence"]["final_reports_scanned"] == 0
    assert saved["issues"][0]["validation_status"] == "validated"
    assert (
        store.get_finding_baseline("double_free|entry|src/demo.c:42")["status"] == "true_positive"
    )
    assert snapshot_saved["issues"][0]["validation_status"] == "pending"


def test_report_feedback_service_updates_snapshots_by_default(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    issue = {
        "id": "ISSUE_1",
        "function": "entry",
        "location": "src/demo.c:42",
        "defect_class": "double_free",
        "validation_status": "pending",
        "dedup_key": "double_free|entry|src/demo.c:42",
    }
    report_path.write_text(json.dumps({"issues": [dict(issue)]}), encoding="utf-8")
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir()
    snapshot_report = snapshot_dir / "entry_final.json"
    snapshot_report.write_text(json.dumps({"issues": [dict(issue)]}), encoding="utf-8")
    snapshot_store = type("FakeSnapshotStore", (), {"snapshot_dir": snapshot_dir})()

    service = ReportFeedbackService(
        snapshot_store=snapshot_store,
        report_filename=str(report_path),
    )

    payload = service.save_validation_feedback(
        [
            {
                **issue,
                "validation_status": "needs_review",
                "validation_reasoning": "manual review",
                "user_rebuttal": "reviewer notes",
            }
        ]
    )
    snapshot_saved = json.loads(snapshot_report.read_text(encoding="utf-8"))

    assert payload["snapshot_persistence"]["final_reports_scanned"] == 1
    assert payload["snapshot_persistence"]["final_reports_updated"] == 1
    assert payload["snapshot_persistence"]["issues_updated"] == 1
    assert snapshot_saved["issues"][0]["validation_status"] == "needs_review"
    assert snapshot_saved["issues"][0]["validation_reasoning"] == "manual review"
    assert snapshot_saved["issues"][0]["user_rebuttal"] == "reviewer notes"


def test_report_feedback_service_accepts_structured_issue_key_fields(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    location = {"file": "src/demo.c", "line": 42}
    report_path.write_text(
        json.dumps(
            {
                "issues": [
                    {
                        "id": "ISSUE_1",
                        "function": "entry",
                        "location": location,
                        "subcategory": {"name": "double_free"},
                        "validation_status": "pending",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    service = ReportFeedbackService(report_filename=str(report_path))

    payload = service.save_validation_feedback(
        [
            {
                "id": "ISSUE_1",
                "function": "entry",
                "location": dict(location),
                "subcategory": {"name": "double_free"},
                "validation_status": "validated",
                "validation_reasoning": "manual confirmation",
            }
        ]
    )
    saved = service.load_report()

    assert payload["success"] is True
    assert saved["issues"][0]["validation_status"] == "validated"
    assert saved["issues"][0]["validation_reasoning"] == "manual confirmation"


def test_report_feedback_service_preserves_existing_report_view_membership_on_save(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    default_issue = {
        "id": "ISSUE_1",
        "function": "entry",
        "location": "src/demo.c:42",
        "subcategory": "bounds",
        "impact_level": "high",
        "validation_status": "validated",
        "validation_reasoning": "auto validation",
    }
    review_only_issue = {
        "id": "OBS_1",
        "function": "entry",
        "location": "src/demo.c:48",
        "subcategory": "bounds",
        "impact_level": "medium",
        "validation_status": "needs_review",
        "validation_reasoning": "needs manual review",
    }
    report_path.write_text(
        json.dumps(
            {
                "issues": [dict(default_issue)],
                "issues_with_needs_review": [dict(default_issue), dict(review_only_issue)],
                "report_views": {
                    "default": {
                        "label": "Default",
                        "issue_count": 1,
                        "issues": [dict(default_issue)],
                    },
                    "with_needs_review": {
                        "label": "With needs_review",
                        "issue_count": 2,
                        "included_needs_review_count": 1,
                        "independent_needs_review_count": 1,
                        "attached_needs_review_count": 0,
                        "issues": [dict(default_issue), dict(review_only_issue)],
                    },
                },
                "metadata": {
                    "audit_observations": [],
                    "report_view_summary": {
                        "default": {"issue_count": 1},
                        "with_needs_review": {"issue_count": 2},
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    service = ReportFeedbackService(report_filename=str(report_path))

    payload = service.save_validation_feedback(
        [
            {
                "id": "ISSUE_1",
                "function": "entry",
                "location": "src/demo.c:42",
                "subcategory": "bounds",
                "validation_status": "needs_review",
                "validation_reasoning": "manual confirmation",
            }
        ]
    )
    saved = service.load_report()

    assert payload["success"] is True
    with_review = saved["report_views"]["with_needs_review"]
    assert len(with_review["issues"]) == 2
    assert {issue["id"] for issue in with_review["issues"]} == {"ISSUE_1", "OBS_1"}
    assert with_review["issue_count"] == 2
    assert len(saved["issues_with_needs_review"]) == 2
    assert saved["metadata"]["report_view_summary"]["with_needs_review"]["issue_count"] == 2
    assert saved["report_views"]["default"]["issues"][0]["validation_status"] == "needs_review"
    assert with_review["issues"][0]["validation_reasoning"] == "manual confirmation"


def test_report_feedback_service_findings_payload_is_lightweight(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    heavy_issue = {
        "id": "ISSUE_1",
        "function": "entry",
        "location": "src/demo.c:42",
        "subcategory": "bounds",
        "validation_status": "validated",
        "code_snippet": "x" * 1000,
    }
    report_path.write_text(
        json.dumps(
            {
                "summary": {"total_issues": 1},
                "issues": [heavy_issue],
                "metadata": {"raw_trace": "y" * 1000},
                "report_views": {
                    "default": {
                        "label": "Default",
                        "issue_count": 1,
                        "issues": [heavy_issue],
                        "issues_by_severity": {"medium": [heavy_issue]},
                    },
                    "with_needs_review": {
                        "label": "With needs_review",
                        "issue_count": 1,
                        "included_needs_review_count": 0,
                        "issues": [heavy_issue],
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    service = ReportFeedbackService(report_filename=str(report_path))

    payload = service.selected_view_payload("/api/findings?view=default")

    assert payload["findings"][0]["id"] == "ISSUE_1"
    assert payload["report"]["summary"] == {"total_issues": 1}
    assert "issues" not in payload["report"]["report_views"]["default"]
    assert "issues_by_severity" not in payload["report"]["report_views"]["default"]
    assert payload["views"]["with_needs_review"]["issue_count"] == 1


def test_report_feedback_service_compacts_runaway_finding_fields(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    huge_text = "logic incorrect permission check " + ("permission narrative " * 1000)
    heavy_issue = {
        "id": "ISSUE_1",
        "function": "_check_file_permission",
        "location": "src/utils.c:169-170",
        "category": huge_text,
        "normalized_category": huge_text,
        "subcategory": "incorrect_permission_check",
        "dedup_key": huge_text * 3,
        "validation_status": "needs_review",
        "description": "Permission check uses file mode bits.",
    }
    report_path.write_text(
        json.dumps(
            {
                "issues": [],
                "report_views": {
                    "with_needs_review": {
                        "issue_count": 1,
                        "included_needs_review_count": 1,
                        "issues": [heavy_issue],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    service = ReportFeedbackService(report_filename=str(report_path))

    payload = service.selected_view_payload("/api/findings?view=with_needs_review")
    finding = payload["findings"][0]
    encoded = json.dumps(payload, ensure_ascii=False)

    assert finding["dedup_key"].startswith("sha256:")
    assert finding["category"] == "incorrect_permission_check"
    assert finding["normalized_category"] == "incorrect_permission_check"
    assert len(encoded) < 10000


def test_report_feedback_service_findings_payload_can_return_full_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "issues": [{"id": "ISSUE_1", "function": "entry", "location": "src/demo.c:42"}],
                "report_views": {
                    "default": {
                        "issue_count": 1,
                        "issues": [
                            {"id": "ISSUE_1", "function": "entry", "location": "src/demo.c:42"}
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    service = ReportFeedbackService(report_filename=str(report_path))

    payload = service.selected_view_payload("/api/findings?view=default&full_report=1")

    assert payload["report"]["report_views"]["default"]["issues"][0]["id"] == "ISSUE_1"


def test_source_snippet_service_resolves_only_configured_roots(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_file = source_root / "demo.c"
    source_file.write_text("int a;\nint b;\nint c;\n", encoding="utf-8")
    project_config = type(
        "ProjectConfig",
        (),
        {"project_root": tmp_path, "source_root": source_root, "include_paths": []},
    )()
    service = SourceSnippetService(project_config)

    status, payload = service.snippet_payload("path=demo.c&start=2&end=2&context=0")

    assert status == 200
    assert payload["lines"] == [{"no": 2, "text": "int b;"}]


def test_user_config_service_crud_round_trips_external_function(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    service = UserConfigService(store)

    status, payload = service.upsert_resource(
        "external_functions",
        {
            "func_name": "ZipAlloc",
            "description": "zip allocator",
            "library": "zip",
            "return_semantics": "returns owned memory",
        },
    )

    assert status == 200
    assert payload == {"success": True}
    status, listed = service.list_resource("external_functions")
    assert status == 200
    assert listed["items"][0]["func_name"] == "ZipAlloc"

    status, payload = service.delete_resource("external_functions", {"func_name": "ZipAlloc"})

    assert status == 200
    assert payload == {"success": True}
    assert service.list_resource("external_functions")[1]["items"] == []


def test_user_config_service_reports_missing_fields_and_unknown_resources(tmp_path: Path) -> None:
    service = UserConfigService(UserConfigStore(tmp_path / "user_config.xlsx"))

    status, payload = service.upsert_resource("external_functions", {"description": "missing name"})
    assert status == 400
    assert "Missing field" in payload["error"]

    status, payload = service.list_resource("unknown")
    assert status == 404
    assert payload["success"] is False


def test_user_config_service_warning_helpers(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    store.add_config_warning("test_warning", "ctx", "message")
    service = UserConfigService(store)

    assert service.warnings_payload()["items"][0]["warning_type"] == "test_warning"

    status, payload = service.clear_warnings()

    assert status == 200
    assert payload == {"success": True}
    assert service.warnings_payload()["items"] == []


def test_cpg_service_reports_unavailable_backend() -> None:
    service = CpgService()

    assert service.status_payload() == {"status": "unavailable", "error": None}
    status, payload = service.build()
    assert status == 400
    assert payload["error"] == "Backend not available"


def test_cpg_service_starts_async_build_when_backend_supports_it(tmp_path: Path) -> None:
    calls = {}

    class FakeJoernClient:
        cpg_error = "last warning"

        def import_cpg_async(self, source_path, project_root, compile_commands_path):
            calls["args"] = (source_path, project_root, compile_commands_path)

    class FakeBackend:
        joern_client = FakeJoernClient()

        def status(self):
            return "ready"

    code_index = type("CodeIndex", (), {"backend": FakeBackend()})()
    project_config = type(
        "ProjectConfig",
        (),
        {
            "source_root": tmp_path / "src",
            "project_root": tmp_path,
            "compile_commands_path": tmp_path / "compile_commands.json",
        },
    )()
    service = CpgService(code_index, project_config)

    assert service.status_payload() == {"status": "ready", "error": "last warning"}

    status, payload = service.build()

    assert status == 200
    assert payload == {"success": True, "status": "building"}
    assert calls["args"] == (
        str(tmp_path / "src"),
        str(tmp_path),
        str(tmp_path / "compile_commands.json"),
    )
