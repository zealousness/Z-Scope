from __future__ import annotations

import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
import yaml

from zscope.reporting.issue_markdown import (
    REVIEW_END,
    REVIEW_START,
    build_document,
    digest,
    issue_identity,
    parse_document,
    parse_location,
    review_revision,
)
from zscope.web.review_reports import ReportReviewService
from zscope.web.services import ReportFeedbackService, SourceSnippetService


def finding(number=1):
    return {
        "id": f"ISSUE_{number}",
        "function": f"entry_{number}",
        "location": f"src/demo.c:{number + 6}",
        "subcategory": "double_free",
        "defect_class": "double_free",
        "impact_level": "high",
        "confidence": 0.8,
        "description": "中文问题 **描述**",
        "root_cause": "生命周期提前结束",
        "suggested_fix": "修复建议",
        "validation_status": "validated",
        "validation_reasoning": "Validator 原始说明",
        "user_rebuttal": "已有历史复核",
        "dedup_key": f"double_free|entry_{number}|src/demo.c:{number + 6}",
        "code_snippet": "free(p);\nuse(p);",
        "evidence_refs": ["ir_path_slices:149"],
        "positive_evidence": ["第一份证据", "尾部证据"],
    }


def edited(content, *, status="rejected", note="本次复核依据", **meta_updates):
    parsed = parse_document(content)
    meta = parsed["metadata"]
    meta.update(validation_status=status, **meta_updates)
    body = parsed["body"].replace(
        REVIEW_START + "\n\n" + REVIEW_END, REVIEW_START + "\n" + note + "\n" + REVIEW_END
    )
    return "---\n" + yaml.safe_dump(meta, allow_unicode=True, sort_keys=False) + "---\n" + body


@pytest.fixture
def service(tmp_path):
    path = tmp_path / "report.json"
    issues = [finding(1), finding(2)]
    report = {
        "issues": issues,
        "report_views": {
            "default": {"issues": copy.deepcopy(issues)},
            "with_needs_review": {"issues": copy.deepcopy(issues)},
        },
    }
    path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    (snapshots / "entry_final.json").write_text(json.dumps(report), encoding="utf-8")
    feedback = ReportFeedbackService(
        snapshot_store=SimpleNamespace(snapshot_dir=snapshots), report_filename=str(path)
    )
    return ReportReviewService(feedback)


def documents(service):
    _, _, issues, _, _ = service.catalog()
    return [
        {"path": f"issues/{key}.md", "content": service.issue_report(key)["markdown"]}
        for key in issues
    ]


def test_markdown_complete_text_and_review_is_separate():
    issue = finding()
    issue["validation_reasoning"] = "长说明" * 12000 + "VALIDATOR_END"
    issue["positive_evidence"] = [f"证据 {i}" for i in range(100)]
    raw = build_document(issue, digest("report"))
    data = parse_document(raw)
    assert data["user_rebuttal"] == ""
    assert data["metadata"]["base_user_rebuttal"] == "已有历史复核"
    assert "VALIDATOR_END" in raw and "证据 99" in raw
    assert '"numbers":[]' in raw
    assert "ir_path_slices:149（未定位）" in raw
    assert data["metadata"]["base_revision"] == review_revision(issue)


@pytest.mark.parametrize("note", ["", " \t\n \u3000", "\n\n"])
def test_empty_review_never_writes_any_persistence(service, note, monkeypatch):
    docs = documents(service)
    for doc in docs:
        doc["content"] = edited(doc["content"], note=note)
    original = Path(service.feedback.report_filename).read_bytes()

    def forbidden(*args, **kwargs):
        pytest.fail("Empty review reached persistence")

    monkeypatch.setattr(service.feedback, "save_validation_feedback", forbidden)
    result = service.import_reviews({"documents": docs})
    assert result["counts"] == {"skipped_empty": 2}
    assert Path(service.feedback.report_filename).read_bytes() == original


def test_missing_review_region_skips_even_with_history(service, monkeypatch):
    doc = documents(service)[0]
    doc["content"] = (
        edited(doc["content"], note="").replace(REVIEW_START, "").replace(REVIEW_END, "")
    )
    monkeypatch.setattr(service.feedback, "save_report", lambda _: pytest.fail("unexpected write"))
    assert service.import_reviews({"documents": [doc]})["counts"] == {"skipped_empty": 1}


def test_independent_reviewers_merge_only_reviewed_items_and_preserve_validator(service):
    a, b = documents(service)
    a["content"] = edited(a["content"], note="A 复核")
    assert service.import_reviews({"documents": [a]})["counts"] == {"updated": 1}
    b["content"] = edited(b["content"], status="validated", note="B 复核").replace(
        "Validator 原始说明", "篡改正文"
    )
    assert service.import_reviews({"documents": [b]})["counts"] == {"updated": 1}
    issues = service.feedback.load_report()["issues"]
    assert [(i["validation_status"], i["user_rebuttal"]) for i in issues] == [
        ("rejected", "A 复核"),
        ("validated", "B 复核"),
    ]
    assert all(i["validation_reasoning"] == "Validator 原始说明" for i in issues)
    snapshot = json.loads(
        next(service.feedback.snapshot_store.snapshot_dir.glob("*_final.json")).read_text()
    )
    assert snapshot["issues"][0]["user_rebuttal"] == "A 复核"
    assert service.import_reviews({"documents": [a]})["counts"] == {"unchanged": 1}


def test_conflict_requires_latest_revision_and_rechecks_resolution(service):
    original = documents(service)[0]
    a = {**original, "content": edited(original["content"], note="A")}
    b = {**original, "content": edited(original["content"], status="uncertain", note="B")}
    service.import_reviews({"documents": [a]})
    conflict = service.import_reviews({"documents": [b]})["results"][0]
    assert conflict["status"] == "conflict" and conflict["current"]["user_rebuttal"] == "A"
    newer = documents(service)[0]
    newer["content"] = edited(newer["content"], note="C")
    service.import_reviews({"documents": [newer]})
    resolution = {**b, "expected_revision": conflict["expected_revision"]}
    next_conflict = service.import_reviews({"documents": [resolution]}, resolve=True)["results"][0]
    assert next_conflict["status"] == "conflict"
    resolution["expected_revision"] = next_conflict["expected_revision"]
    assert service.import_reviews({"documents": [resolution]}, resolve=True)["counts"] == {
        "updated": 1
    }
    assert service.feedback.load_report()["issues"][0]["user_rebuttal"] == "B"


def test_context_change_conflicts_and_empty_resolution_cannot_force_update(service):
    doc = documents(service)[0]
    doc["content"] = edited(doc["content"])
    report = service.feedback.load_report()
    for issue in [report["issues"][0], *[v["issues"][0] for v in report["report_views"].values()]]:
        issue["validation_reasoning"] = "新证据结论"
    service.feedback.save_report(report)
    result = service.import_reviews({"documents": [doc]})["results"][0]
    assert result["status"] == "conflict" and result["context_changed"]
    empty = documents(service)[0]
    empty["content"] = edited(empty["content"], note="")
    empty["expected_revision"] = result["expected_revision"]
    assert service.import_reviews({"documents": [empty]}, resolve=True)["counts"] == {
        "skipped_empty": 1
    }


@pytest.mark.parametrize("change", ["foreign", "unknown", "duplicate", "path", "status"])
def test_invalid_import_never_applies(service, change):
    doc = documents(service)[0]
    doc["content"] = edited(doc["content"])
    if change == "foreign":
        doc["content"] = edited(doc["content"], report_id=digest("foreign"))
    if change == "unknown":
        doc["content"] = edited(doc["content"], issue_id=digest("unknown"))
    if change == "path":
        doc["path"] = "../issue.md"
    if change == "status":
        doc["content"] = doc["content"].replace(
            "validation_status: rejected", "validation_status: bad"
        )
    docs = [doc, doc] if change == "duplicate" else [doc]
    before = Path(service.feedback.report_filename).read_bytes()
    result = service.import_reviews({"documents": docs})
    assert not result["counts"].get("updated")
    assert Path(service.feedback.report_filename).read_bytes() == before


def test_fences_unicode_and_yaml_duplicates():
    raw = build_document(finding(), digest("report"))
    note = "## 人工标题\n\n````md\n```c\n" + REVIEW_END + "\n```\n````\n结论 ✓"
    assert parse_document(edited(raw, note=note))["user_rebuttal"] == note
    assert parse_document("\ufeff" + raw.replace("\n", "\r\n"))["user_rebuttal"] == ""
    with pytest.raises(ValueError):
        parse_document(
            raw.replace("schema_version:", "validation_status: pending\nschema_version:", 1)
        )
    with pytest.raises(ValueError):
        parse_document(edited(raw, note=REVIEW_END))


def test_source_coordinates_and_unknown_ids(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "demo.c").write_text("\n".join(f"line_{n};" for n in range(1, 31)), encoding="utf-8")
    reader = SourceSnippetService(
        SimpleNamespace(project_root=tmp_path, source_root=src, include_paths=[])
    )
    feedback = ReportFeedbackService(report_filename=str(tmp_path / "report.json"))
    feedback.save_report({"issues": [finding()]})
    raw = ReportReviewService(feedback, reader).issue_report(issue_identity(finding()))["markdown"]
    assert '"numbers":[1,2,3,4,5,6,7,8,9,10,11,12,13]' in raw
    assert '"highlight":[7]' in raw
    assert "line_7;" in raw and "ir_path_slices:149（未定位）" in raw
    assert parse_location("ir_path_slices:149") is None
    assert parse_location("C:/中文 目录/demo.cpp:12-14")["start"] == 12
    assert parse_location({"file": "a.java", "line": 3})["path"] == "a.java"


def test_export_structure_all_views_and_embedded_assets(service):
    archive = zipfile.ZipFile(io.BytesIO(service.offline_report()))
    names = archive.namelist()
    assert len(names) == 3 and "zscope-report/index.html" in names
    html = archive.read("zscope-report/index.html").decode()
    assert "__ASSET_" not in html and "__ZSCOPE_MANIFEST__" not in html
    assert "<script src=" not in html and "connect-src 'none'" in html
    docs = [name for name in names if name.endswith(".md")]
    assert len(docs) == 2
    assert all(parse_document(archive.read(name).decode())["user_rebuttal"] == "" for name in docs)


def test_new_online_save_preserves_complete_server_fields(service):
    item = service.feedback.selected_view_payload("/api/findings")["findings"][0]
    item.update(
        validation_status="uncertain", user_rebuttal="线上说明", validation_reasoning="truncated"
    )
    service.feedback.save_validation_feedback([item])
    saved = service.feedback.load_report()["issues"][0]
    assert saved["validation_reasoning"] == "Validator 原始说明"
    assert saved["user_rebuttal"] == "线上说明"


def test_unfinished_machine_markdown_cannot_swallow_review_section():
    issue = finding()
    issue["validation_reasoning"] = "原始代码：\n```c\nfree(p);"
    raw = build_document(issue, digest("report"))
    assert "free(p);\n```" in raw
    assert parse_document(edited(raw, note="复核依据"))["user_rebuttal"] == "复核依据"


def test_export_keeps_review_only_view_and_rejects_ambiguous_identity(service):
    report = service.feedback.load_report()
    extra = finding(3)
    extra["validation_status"] = "needs_review"
    report["report_views"]["with_needs_review"]["issues"].append(extra)
    service.feedback.save_report(report)
    archive = zipfile.ZipFile(io.BytesIO(service.offline_report()))
    assert len([name for name in archive.namelist() if name.endswith(".md")]) == 3
    _, _, _, views, _ = service.catalog()
    assert issue_identity(extra) not in views["default"]
    assert issue_identity(extra) in views["with_needs_review"]
    report["report_views"]["with_needs_review"]["issues"][0]["user_rebuttal"] = "歧义副本"
    service.feedback.save_report(report)
    with pytest.raises(ValueError, match="歧义"):
        service.offline_report()


def test_identity_uses_complete_key_and_export_is_within_import_limits(service, monkeypatch):
    a, b = finding(), finding()
    a["dedup_key"] = "same" * 1000 + "a"
    b["dedup_key"] = "same" * 1000 + "b"
    assert issue_identity(a) != issue_identity(b)
    monkeypatch.setattr("zscope.web.review_reports.MAX_IMPORT_BYTES", 32)
    with pytest.raises(ValueError, match="总大小"):
        service.offline_report()


def test_import_does_not_update_unreviewed_issue_with_same_legacy_key(service):
    report = service.feedback.load_report()
    first = finding()
    second = dict(first, dedup_key="different-full-stable-key", finding_root_uid="other-root")
    report["issues"] = [first, second]
    for view in report["report_views"].values():
        view["issues"] = copy.deepcopy(report["issues"])
    service.feedback.save_report(report)
    snapshot_path = service.feedback.snapshot_store.snapshot_dir / "entry_final.json"
    snapshot = copy.deepcopy(report)
    snapshot["issues"][0]["validation_reasoning"] = "入口 snapshot 的 Validator 原文"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    a, b = documents(service)
    a["content"] = edited(a["content"], note="只复核第一条")
    b["content"] = edited(b["content"], note="")
    assert service.import_reviews({"documents": [a, b]})["counts"] == {
        "updated": 1,
        "skipped_empty": 1,
    }
    assert service.feedback.load_report()["issues"][1] == second
    assert json.loads(snapshot_path.read_text())["issues"][1] == second
    assert (
        json.loads(snapshot_path.read_text())["issues"][0]["validation_reasoning"]
        == "入口 snapshot 的 Validator 原文"
    )


def test_import_updates_legacy_nested_reports(service):
    issue = finding()
    service.feedback.save_report({"results": {"entry": {"issues": [issue]}}})
    doc = documents(service)[0]
    doc["content"] = edited(doc["content"], note="旧格式也按条回写")
    assert service.import_reviews({"documents": [doc]})["counts"] == {"updated": 1}
    saved = service.feedback.load_report()["results"]["entry"]["issues"][0]
    assert saved["user_rebuttal"] == "旧格式也按条回写"
