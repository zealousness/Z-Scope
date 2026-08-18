from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import socket

from click.testing import CliRunner

from zscope.cli.cli import main as zscope_main
from zscope.config.config import ConfigLoader, yaml
from zscope.framework.llm_client import LLMClient
from zscope.mcp.provider import ZScopeMcpProvider
from zscope.web.services import SecuritySpecReviewService


FIXTURE = Path(__file__).parent / "fixtures" / "p5_cjson"


def test_cjson_source_snapshot_is_unmodified_answer_free_and_content_addressed() -> None:
    manifest = json.loads((FIXTURE / "source-manifest.json").read_text(encoding="utf-8"))
    files = []
    for expected in manifest["source_tree"]["files"]:
        path = FIXTURE / expected["path"]
        data = path.read_bytes()
        actual = {
            "path": expected["path"],
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        assert actual == expected
        files.append(actual)
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode()).hexdigest() == manifest["source_tree"]["sha256"]
    assert manifest["upstream"]["commit"] == "c859b25da02955fef659d658b8f324b5cde87be3"
    assert manifest["license"]["spdx"] == "MIT"
    assert set(manifest["answer_isolation"].values()) == {False}


def test_cjson_qualification_config_is_fast_regex_and_answer_free() -> None:
    config = ConfigLoader.load(str(FIXTURE / "zscope.yaml"))
    assert config.scan.depth == "fast"
    assert config.indexing.backend == "regex"
    assert config.project.project_root == (FIXTURE / "source").resolve()
    text = (FIXTURE / "zscope.yaml").read_text(encoding="utf-8").lower()
    for forbidden in ("ground_truth", "expected_finding", "scorer", "cve-"):
        assert forbidden not in text


def _forbid_external_call(*_args, **_kwargs):
    raise AssertionError("P5 cJSON qualification must not call a model or the network")


def _report_projection(report: dict) -> dict:
    def findings(name: str) -> list[tuple[str, str, str]]:
        rows = report.get(name)
        rows = rows if isinstance(rows, list) else []
        return sorted(
            (
                str(row.get("candidate_uid") or row.get("id") or ""),
                str(row.get("candidate_disposition") or ""),
                str(row.get("location") or ""),
            )
            for row in rows
            if isinstance(row, dict)
        )

    manifest = report.get("run_manifest")
    manifest = manifest if isinstance(manifest, dict) else {}
    return {
        "issues": findings("issues"),
        "observations": findings("observations"),
        "schema_version": report.get("schema_version"),
        "authority_schema": (manifest.get("runtime_authority_manifest") or {}).get(
            "schema_version"
        ),
        "cache_epoch": manifest.get("cache_epoch"),
        "source_tree_hash": manifest.get("source_tree_hash"),
        "runtime_authority_sha256": manifest.get("runtime_authority_sha256"),
    }


def test_cjson_cold_repeat_fast_and_public_surfaces_are_zero_model(
    tmp_path: Path, monkeypatch
) -> None:
    project_root = tmp_path / "cjson"
    shutil.copytree(FIXTURE / "source", project_root)
    raw_config = yaml.safe_load((FIXTURE / "zscope.yaml").read_text(encoding="utf-8"))
    raw_config["project"]["root"] = str(project_root)
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text(
        yaml.safe_dump(raw_config, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )

    monkeypatch.setattr(LLMClient, "chat_completion", _forbid_external_call)
    monkeypatch.setattr(LLMClient, "run_conversation_with_tools", _forbid_external_call)
    monkeypatch.setattr(socket, "create_connection", _forbid_external_call)

    cli = CliRunner()
    first = cli.invoke(
        zscope_main,
        ["--config", str(config_path), "--exit-policy", "confirmed"],
    )
    assert first.exit_code == 0, first.output
    reports = sorted(project_root.glob("zscope_*report*.json"))
    assert reports, first.output
    first_report = json.loads(reports[-1].read_text(encoding="utf-8"))
    assert first_report["run_manifest"]["llm_usage"]["successful_calls"] == 0
    assert first_report["run_manifest"]["runtime_authority_manifest"]["modes"] == {
        "security_spec": "authoritative",
        "hypothesis_hunter": "active",
        "hypothesis_hunter_effect": "candidate_registration_only",
        "proof_engine": "authoritative",
    }

    second = cli.invoke(
        zscope_main,
        ["--config", str(config_path), "--exit-policy", "confirmed"],
    )
    assert second.exit_code == 0, second.output
    second_report = json.loads(reports[-1].read_text(encoding="utf-8"))
    assert _report_projection(second_report) == _report_projection(first_report)
    assert second_report["run_manifest"]["llm_usage"]["successful_calls"] == 0
    assert second_report["run_manifest"]["decision_trace"]["complete"] is True

    sarif_path = tmp_path / "external.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "qualification", "rules": []}},
                        "results": [
                            {
                                "ruleId": "external-signal",
                                "level": "warning",
                                "message": {"text": "unverified external signal"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "cJSON.c"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    alert = cli.invoke(
        zscope_main,
        [
            "--config",
            str(config_path),
            "--mode",
            "alert-verify",
            "--sarif",
            str(sarif_path),
            "--exit-policy",
            "confirmed",
        ],
    )
    assert alert.exit_code == 0, alert.output
    alert_report = json.loads(
        (project_root / "zscope_alert_verify_report.json").read_text(encoding="utf-8")
    )
    assert alert_report["observations"][0]["candidate_disposition"] == "needs_review"
    assert "model_verdict" not in alert_report["observations"][0]

    config = ConfigLoader.load(str(config_path))
    provider = ZScopeMcpProvider(config)
    try:
        listed = provider.call_tool("list_known_functions", {"limit": 10})
        assert listed["success"] is True
        assert listed.get("data")
    finally:
        provider.close()

    web_service = SecuritySpecReviewService(project_root / ".zscope_specs")
    web_payload = web_service.list_payload("")
    assert web_payload["read_only"] is True
    assert web_payload["security_spec_mode"] == "authoritative"
