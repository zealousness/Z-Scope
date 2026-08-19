from __future__ import annotations

import ast
from pathlib import Path

from zscope.compat.reports import read_legacy_report_view
from zscope.compat.usage import map_legacy_usage_stage


def test_legacy_report_view_is_detached_and_read_only() -> None:
    report = {
        "issues": [{"id": "OLD_CONFIRMED", "candidate_disposition": "confirmed"}],
        "audit_observations": [{"id": "OLD_REVIEW", "candidate_disposition": "needs_review"}],
    }

    view = read_legacy_report_view(report, view="with_needs_review")
    view["issues"][0]["id"] = "CHANGED"

    assert report["issues"][0]["id"] == "OLD_CONFIRMED"
    assert {
        item["id"] for item in read_legacy_report_view(report, view="with_needs_review")["issues"]
    } == {
        "OLD_CONFIRMED",
        "OLD_REVIEW",
    }


def test_legacy_usage_dimensions_map_to_p1_accounting_stages() -> None:
    assert map_legacy_usage_stage("vulnerability-analyzer") == "hypothesis_hunter"
    assert map_legacy_usage_stage("deep worker") == "hypothesis_hunter"
    assert map_legacy_usage_stage("semantic enricher") == "security_spec_miner"
    assert map_legacy_usage_stage("validator") == "proof_engine"
    assert map_legacy_usage_stage("issue reconciler") == "history_maintenance_agent"


def test_compat_modules_have_no_live_execution_imports() -> None:
    compat_root = Path(__file__).resolve().parents[1] / "zscope" / "compat"
    forbidden = {"agents", "llm_client", "workflow_executor", "promotion"}
    imported_parts = set()
    for path in compat_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_parts.update(
                    part for alias in node.names for part in alias.name.split(".")
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_parts.update(node.module.split("."))

    assert forbidden.isdisjoint(imported_parts)
