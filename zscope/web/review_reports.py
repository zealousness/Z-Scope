"""Markdown report delivery and optimistic, per-issue offline review merging."""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlencode
import zipfile

from ..reporting.issue_markdown import (
    MAX_DOCUMENT_BYTES,
    build_document,
    context_revision,
    digest,
    issue_identity,
    parse_document,
    review_revision,
    review_state,
)
from ..reporting.views import findings_for_view

STATIC = Path(__file__).parent / "static"
MAX_IMPORT_BYTES = 128 * 1024 * 1024
MAX_IMPORT_DOCUMENTS = 10000
VIEWS = ("default", "with_needs_review")


def report_identity(report: dict[str, Any], filename: str) -> str:
    manifest = report.get("run_manifest") or {}
    metadata = report.get("metadata") or {}
    return digest(
        {
            "scope": str(Path(filename).resolve()),
            "project": manifest.get("project_id") or metadata.get("project_id"),
            "run": manifest.get("run_id") or metadata.get("run_id"),
        }
    )


def safe_document_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")
    return (
        bool(normalized)
        and not PurePosixPath(normalized).is_absolute()
        and all(
            part not in {"", ".", ".."} and ":" not in part and "\x00" not in part for part in parts
        )
        and normalized.lower().endswith(".md")
    )


class ReportReviewService:
    def __init__(self, feedback: Any, snippets: Any = None):
        self.feedback = feedback
        self.snippets = snippets

    def catalog(
        self,
    ) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]], dict[str, list[str]], set[str]]:
        report = self.feedback.load_report()
        report_id = report_identity(report, self.feedback.report_filename)
        issues: dict[str, dict[str, Any]] = {}
        views: dict[str, list[str]] = {}
        ambiguous: set[str] = set()
        for view in VIEWS:
            views[view] = []
            for issue in findings_for_view(report, view):
                key = issue_identity(issue)
                if key in issues and review_revision(issues[key]) != review_revision(issue):
                    ambiguous.add(key)
                issues.setdefault(key, issue)
                if key not in views[view]:
                    views[view].append(key)
        return report, report_id, issues, views, ambiguous

    def _snippet(self, location: dict[str, Any]) -> dict[str, Any] | None:
        if self.snippets is None:
            return None
        query = urlencode(
            {**location, "end": min(location["end"], location["start"] + 199), "context": 6}
        )
        status, payload = self.snippets.snippet_payload(query)
        return payload if status == 200 and payload.get("success") else None

    def issue_report(self, key: str) -> dict[str, Any]:
        _, report_id, issues, _, ambiguous = self.catalog()
        if key not in issues:
            raise KeyError("issue 不存在，请刷新列表")
        if key in ambiguous:
            raise ValueError("issue 身份存在歧义，无法生成可回写报告")
        issue = issues[key]
        return {
            "report_id": report_id,
            "issue_id": key,
            "base_revision": review_revision(issue),
            "markdown": build_document(issue, report_id, snippet_reader=self._snippet),
            "review": review_state(issue),
        }

    def offline_report(self) -> bytes:
        _, report_id, issues, views, ambiguous = self.catalog()
        if ambiguous:
            raise ValueError("报告中存在身份歧义，请刷新或重新生成报告后导出")
        if len(issues) > MAX_IMPORT_DOCUMENTS:
            raise ValueError("报告超过 10000 条，无法生成可回写离线包")
        manifest = {
            "schema_version": "zscope.offline-report.v1",
            "report_id": report_id,
            "views": views,
            "issues": [{"issue_id": key, "path": f"issues/{key}.md"} for key in issues],
        }
        page = (STATIC / "offline_template.html").read_text(encoding="utf-8")
        page = page.replace(
            "__ZSCOPE_MANIFEST__", json.dumps(manifest, ensure_ascii=False).replace("<", "\\u003c")
        )
        licenses = {
            name: (STATIC / "vendor" / name).read_text(encoding="utf-8")
            for name in (
                "markdown-it.LICENSE",
                "js-yaml.LICENSE",
                "fflate.LICENSE",
                "prism.LICENSE",
            )
        }
        page = page.replace(
            "__ZSCOPE_LICENSES__", json.dumps(licenses, ensure_ascii=False).replace("<", "\\u003c")
        )
        for name in ("prism.css", "report_view.css"):
            path = STATIC / ("vendor" if name == "prism.css" else "") / name
            page = page.replace(f"__ASSET_{name}__", path.read_text(encoding="utf-8"))
        for name in (
            "markdown-it.js",
            "js-yaml.js",
            "fflate.js",
            "prism.js",
            "prism-c.js",
            "prism-cpp.js",
            "prism-java.js",
            "report_view.js",
            "offline_review.js",
        ):
            path = (
                STATIC
                / ("" if name in {"report_view.js", "offline_review.js"} else "vendor")
                / name
            )
            page = page.replace(
                f"__ASSET_{name}__",
                path.read_text(encoding="utf-8").replace("</script", "<\\/script"),
            )
        output = io.BytesIO()
        total_bytes = 0
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("zscope-report/index.html", page.encode("utf-8"))
            for key, issue in issues.items():
                document = build_document(issue, report_id, snippet_reader=self._snippet)
                encoded = document.encode("utf-8")
                if len(encoded) > MAX_DOCUMENT_BYTES:
                    raise ValueError("单条报告超过 16 MiB，无法生成可回写离线包")
                total_bytes += len(encoded)
                if total_bytes > MAX_IMPORT_BYTES:
                    raise ValueError("Markdown 总大小超过 128 MiB，无法生成可回写离线包")
                archive.writestr(f"zscope-report/issues/{key}.md", encoded)
        return output.getvalue()

    def import_reviews(self, payload: Any, *, resolve: bool = False) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("导入参数必须为对象")
        documents = payload.get("documents")
        if (
            not isinstance(documents, list)
            or not documents
            or len(documents) > MAX_IMPORT_DOCUMENTS
        ):
            raise ValueError("请选择 1–10000 个 Markdown 报告文件")
        if (
            sum(
                len(str(doc.get("content", "")).encode("utf-8"))
                for doc in documents
                if isinstance(doc, dict)
            )
            > MAX_IMPORT_BYTES
        ):
            raise ValueError("导入内容超过 128 MiB")
        parsed: list[dict[str, Any] | None] = []
        results: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        occurrences: dict[str, list[int]] = {}
        for index, document in enumerate(documents):
            result: dict[str, Any] = {"index": index}
            results.append(result)
            try:
                if not isinstance(document, dict) or not safe_document_path(
                    str(document.get("path", ""))
                ):
                    raise ValueError("仅支持安全相对路径下的 .md；旧 HTML 请重新导出")
                content = document.get("content", "")
                if not isinstance(content, str):
                    raise ValueError("Markdown 内容必须为文本")
                data = parse_document(content)
                parsed.append(data)
                key = data["metadata"]["issue_id"]
                result["issue_id"] = key
                occurrences.setdefault(key, []).append(index)
            except (ValueError, TypeError) as exc:
                parsed.append(None)
                result.update(status="invalid", message=str(exc))
        # The HTTP server serializes requests. Read after parsing the entire import so the
        # optimistic check also sees report changes made on disk during a large parse.
        self.feedback._report_cache_key = None
        _, report_id, issues, _, ambiguous = self.catalog()
        updates = []
        for index, parsed_document in enumerate(parsed):
            if parsed_document is None:
                continue
            data = parsed_document
            result = results[index]
            meta = data["metadata"]
            key = meta["issue_id"]
            if not data["user_rebuttal"]:
                result.update(status="skipped_empty", message="本次人工说明为空，未更新")
                continue
            if len(occurrences[key]) > 1:
                result.update(
                    status="invalid", message="同一批次包含重复 issue，请只保留一个复核版本"
                )
                continue
            if meta["report_id"] != report_id or key not in issues or key in ambiguous:
                result.update(status="unmatched", message="报告或 issue 身份不匹配，无法自动回写")
                continue
            current = issues[key]
            desired = {
                "validation_status": meta["validation_status"],
                "user_rebuttal": data["user_rebuttal"],
            }
            if review_state(current) == desired:
                result.update(status="unchanged", message="相同复核已存在，未重复写入")
                continue
            expected = (
                documents[index].get("expected_revision") if resolve else meta["base_revision"]
            )
            revision = review_revision(current)
            if not expected or expected != revision:
                result.update(
                    status="conflict",
                    message="线上结果或证据已变化",
                    expected_revision=revision,
                    baseline={
                        "validation_status": meta["base_status"],
                        "user_rebuttal": meta["base_user_rebuttal"],
                    },
                    current=review_state(current),
                    incoming=desired,
                    context_changed=meta["base_context"] != context_revision(current),
                    validation_reasoning=str(current.get("validation_reasoning") or ""),
                )
                continue
            update = copy.deepcopy(current)
            update.update(desired)
            updates.append(update)
            result.update(status="updated", message="已回写本次人工复核")
        persistence = None
        if updates:
            # Only server-owned findings reach the existing report/snapshot/baseline pipeline.
            persistence = self.feedback.save_validation_feedback(
                updates, save_scope="offline_import"
            )
        for result in results:
            counts[result["status"]] = counts.get(result["status"], 0) + 1
        return {"success": True, "results": results, "counts": counts, "persistence": persistence}
