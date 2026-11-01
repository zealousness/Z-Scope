"""Export Z-SCOPE reports to SARIF v2.1.0."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from ..common.defect_cwe_map import cwe_tokens
from ..common.issue_identity import canonical_issue_key, stable_issue_fingerprint


_LEVEL_BY_IMPACT = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def save_sarif_report(
    report_or_path: Any,
    output_path: Path,
    *,
    source_root: Optional[Path] = None,
) -> Path:
    """Write a SARIF file for a report dict or JSON report path."""
    report = _load_report(report_or_path)
    sarif = report_to_sarif(report, source_root=source_root)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output_path


def report_to_sarif(
    report: Dict[str, Any],
    *,
    source_root: Optional[Path] = None,
) -> Dict[str, Any]:
    issues = _report_issues(report)
    rules = _build_rules(issues)
    results = [_issue_to_result(issue, source_root=source_root) for issue in issues]
    results = [item for item in results if item]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Z-SCOPE",
                        "informationUri": "https://github.com/zealousness/Z-Scope",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _load_report(report_or_path: Any) -> Dict[str, Any]:
    if isinstance(report_or_path, (str, Path)):
        from .json_io import read_report

        loaded = read_report(Path(report_or_path))
        if isinstance(loaded, dict):
            return loaded
        raise TypeError("SARIF report JSON root must be an object")
    if isinstance(report_or_path, dict):
        return report_or_path
    raise TypeError("report_or_path must be a report dict or JSON path")


def _report_issues(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    def security_finding(item: Any) -> bool:
        return bool(
            isinstance(item, dict)
            and str(item.get("record_role") or "") != "operational_obligation"
            and str(item.get("candidate_disposition") or "").lower()
            not in {"deferred_budget", "engine_failed", "interrupted"}
        )

    if isinstance(report.get("issues"), list):
        return [item for item in report["issues"] if security_finding(item)]
    issues: List[Dict[str, Any]] = []
    for result in report.get("function_results") or []:
        if isinstance(result, dict) and isinstance(result.get("issues"), list):
            issues.extend(item for item in result["issues"] if security_finding(item))
    results = report.get("results")
    if isinstance(results, dict):
        for result in results.values():
            if isinstance(result, dict) and isinstance(result.get("issues"), list):
                issues.extend(item for item in result["issues"] if security_finding(item))
    return issues


def _build_rules(issues: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    rules: Dict[str, Dict[str, Any]] = {}
    for issue in issues:
        rule_id = _rule_id(issue)
        if rule_id in rules:
            continue
        name = str(
            issue.get("defect_class")
            or issue.get("subcategory")
            or issue.get("category")
            or rule_id
        )
        cwe = str(issue.get("cwe") or "").strip()
        cwes = _issue_cwes(issue)
        tags = ["security", name.replace("_", "-")]
        tags.extend(cwes)
        properties: Dict[str, Any] = {
            "tags": tags,
            "legacyRuleId": _legacy_rule_id(issue),
        }
        if cwe:
            properties["cwe"] = cwe
        if cwes:
            properties["cwes"] = cwes
        for field in (
            "rule_engine",
            "rule_revision",
            "skill",
            "rule_catalog_sha256",
        ):
            value = _rule_metadata(issue, field)
            if value not in (None, ""):
                properties[field] = value
        rules[rule_id] = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": name.replace("_", " ")},
            "fullDescription": {
                "text": str(issue.get("root_cause") or issue.get("description") or name)
            },
            "help": {"text": str(issue.get("suggested_fix") or "Review the finding evidence.")},
            "properties": properties,
        }
    return rules


def _issue_to_result(
    issue: Dict[str, Any],
    *,
    source_root: Optional[Path],
) -> Optional[Dict[str, Any]]:
    file_path, line = _issue_file_and_line(issue)
    if not file_path:
        return None
    rule_id = _rule_id(issue)
    message = str(issue.get("description") or issue.get("root_cause") or rule_id)
    stable_identity = stable_issue_fingerprint(issue)
    identity_basis = stable_identity or str(
        issue.get("dedup_key")
        or issue.get("candidate_id")
        or issue.get("id")
        or canonical_issue_key(issue)
        or message
    )
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVEL_BY_IMPACT.get(
            str(issue.get("impact_level") or "medium").lower(), "warning"
        ),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(file_path, source_root)},
                    "region": {"startLine": max(1, int(line or 1))},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": _fingerprint(identity_basis),
            "zscopeStableIssueFingerprint": _fingerprint(identity_basis),
        },
        "properties": {
            "zscope": {
                "candidate_id": issue.get("candidate_id") or issue.get("id"),
                "candidate_uid": issue.get("candidate_uid"),
                "occurrence_uid": issue.get("occurrence_uid"),
                "history_key": issue.get("history_key"),
                "evidence_hash": issue.get("evidence_hash"),
                "run_issue_uid": issue.get("run_issue_uid"),
                "candidate_disposition": issue.get("candidate_disposition"),
                "evidence_completeness": issue.get("evidence_completeness"),
                "dedup_key": issue.get("dedup_key"),
                "stable_fingerprint": stable_identity,
                "baseline_match_strategy": issue.get("baseline_match_strategy"),
                "suppression_source": issue.get("suppression_source"),
                "candidate_source": issue.get("candidate_source")
                or (
                    issue.get("evidence_pack", {}).get("candidate_source")
                    if isinstance(issue.get("evidence_pack"), dict)
                    else None
                ),
                "validation_status": issue.get("validation_status"),
                "validator_verdict": issue.get("validator_verdict"),
                "finding_kind": issue.get("finding_kind"),
                "confidence": issue.get("confidence"),
                "final_score": issue.get("final_score"),
                "positive_evidence": issue.get("positive_evidence") or [],
                "negative_evidence": issue.get("negative_evidence") or [],
                "path_constraints": issue.get("path_constraints") or [],
            }
        },
    }
    code_flows = _code_flows(issue, source_root=source_root)
    if code_flows:
        result["codeFlows"] = code_flows
    return result


def _code_flows(issue: Dict[str, Any], *, source_root: Optional[Path]) -> List[Dict[str, Any]]:
    raw_evidence_pack = issue.get("evidence_pack")
    evidence_pack: Dict[str, Any] = raw_evidence_pack if isinstance(raw_evidence_pack, dict) else {}
    steps: List[Dict[str, Any]] = []
    for key in ("source", "sink"):
        item = evidence_pack.get(key)
        if not isinstance(item, dict):
            continue
        file_path = str(item.get("file") or "")
        line = int(item.get("line") or 0)
        if not file_path or line <= 0:
            continue
        steps.append(
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _artifact_uri(file_path, source_root)},
                        "region": {"startLine": line},
                    },
                    "message": {
                        "text": str(item.get("expression") or item.get("operation") or key)
                    },
                }
            }
        )
    if len(steps) < 2:
        return []
    return [{"threadFlows": [{"locations": steps}]}]


def _issue_file_and_line(issue: Dict[str, Any]) -> Tuple[str, int]:
    file_path = str(issue.get("file_path") or issue.get("file") or "")
    explicit_line = issue.get("line") or issue.get("start_line")
    if file_path and explicit_line:
        return file_path, int(explicit_line)
    location = str(issue.get("location") or issue.get("file") or "")
    match = re.fullmatch(
        r"(?P<file>[^\n]+?):(?P<line>\d+)(?:-\d+|:\d+)?", location
    )
    if match:
        return match.group("file"), int(match.group("line"))
    line = int(explicit_line or 1)
    return file_path, line


def _artifact_uri(file_path: str, source_root: Optional[Path]) -> str:
    path = Path(file_path)
    if path.is_absolute() and source_root:
        try:
            return quote(path.resolve().relative_to(source_root.resolve()).as_posix(), safe="/:")
        except ValueError:
            pass
    return quote(str(file_path).replace("\\", "/"), safe="/:")


def _rule_id(issue: Dict[str, Any]) -> str:
    return str(
        issue.get("rule_id")
        or issue.get("rule")
        or issue.get("defect_class")
        or issue.get("subcategory")
        or "zscope-finding"
    ).strip()


def _issue_cwes(issue: Dict[str, Any]) -> List[str]:
    """Ordered CWE labels: the primary first, then the full multi-CWE set."""

    ordered: List[str] = []
    values: List[Any] = [issue.get("cwe"), issue.get("cwes")]
    evidence_pack = issue.get("evidence_pack")
    if isinstance(evidence_pack, dict):
        values.append(evidence_pack.get("cwes"))
    for value in values:
        for token in cwe_tokens(value):
            if token not in ordered:
                ordered.append(token)
    return ordered


def _legacy_rule_id(issue: Dict[str, Any]) -> str:
    """Return the composite identifier emitted before canonical rule IDs."""
    cwe = str(issue.get("cwe") or "").strip()
    rule = str(
        issue.get("rule")
        or issue.get("defect_class")
        or issue.get("subcategory")
        or "zscope-finding"
    ).strip()
    return f"{cwe}:{rule}" if cwe else f"zscope:{rule}"


def _rule_metadata(issue: Dict[str, Any], field: str) -> Any:
    """Read rule-governance metadata from an issue or its evidence descriptor."""
    if issue.get(field) not in (None, ""):
        return issue[field]
    evidence_pack = issue.get("evidence_pack")
    if not isinstance(evidence_pack, dict):
        return None
    if evidence_pack.get(field) not in (None, ""):
        return evidence_pack[field]
    descriptor = evidence_pack.get("rule_descriptor")
    if isinstance(descriptor, dict):
        return descriptor.get(field)
    return None


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
