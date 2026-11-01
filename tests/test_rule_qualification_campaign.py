from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.rule_qualification_campaign import assemble, prepare, verify
from zscope.rules.catalog import RuleCatalogError


def test_campaign_prepare_covers_every_default_cpp_rule_without_claiming_qualification(
    tmp_path: Path,
) -> None:
    root = tmp_path / "campaign"

    manifest = prepare(root)
    report = verify(root)

    assert manifest["rule_count"] == 166
    assert report["rule_count"] == 166
    assert report["qualified_count"] == 0
    assert report["pending_or_failed_count"] == 166
    assert report["complete"] is False
    assert {row["status"] for row in report["rules"]} == {"pending_external_evidence"}


def test_campaign_assemble_refuses_incomplete_external_evidence(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    prepare(root)

    with pytest.raises(RuleCatalogError, match="campaign is incomplete"):
        assemble(root, tmp_path / "qualification_registry.json")


def test_campaign_verify_reports_a_removed_current_rule(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    prepare(root)
    campaign_path = root / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    removed = campaign["rules"].pop()
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")

    report = verify(root)

    missing = [row for row in report["rules"] if row["status"] == "missing_campaign_rule"]
    assert missing == [
        {
            "rule_id": removed["rule_id"],
            "revision": removed["revision"],
            "status": "missing_campaign_rule",
            "passed": False,
        }
    ]
    assert report["complete"] is False


def test_campaign_verify_rejects_path_escape(tmp_path: Path) -> None:
    root = tmp_path / "campaign"
    prepare(root)
    campaign_path = root / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign["rules"][0]["campaign_file"] = "../outside.json"
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")

    with pytest.raises(RuleCatalogError, match="invalid campaign-relative path"):
        verify(root)
