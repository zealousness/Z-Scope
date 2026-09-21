"""Adapt current semantic snapshot observations into unconfirmed obligations."""

from __future__ import annotations

import re
import json
from typing import Any

from ..reporting.attribution import FindingAttribution
from ..semantics.contracts import digest, code_tokens
from .candidates import CandidateRegistrar
from .semantic_modeling import SessionSemanticResult


def _source_lines(snapshot: dict[str, Any]) -> dict[int, str]:
    start = int(snapshot.get("start_line") or 0)
    lines = {}
    for offset, text in enumerate(str(snapshot.get("code") or "").splitlines()):
        match = re.match(r"^\s*(\d+)\s*\| ?(.*)$", text)
        lines[int(match[1]) if match else start + offset] = match[2] if match else text
    return lines


def resolve_point_line(point: dict[str, Any], snapshot: dict[str, Any]) -> tuple[int | None, str]:
    source = _source_lines(snapshot)
    raw = str(point.get("lines") or point.get("line") or "").strip()
    # The current schema is a string containing absolute lines, a range, or
    # actual source text. Never use the point's ordinal as a source coordinate.
    if re.fullmatch(r"(?:[Ll]ines?\s*)?\d+(?:\s*[-,:–]\s*\d+)*(?:\s*[|:].*)?", raw):
        line = int(re.search(r"\d+", raw)[0])  # type: ignore[index]
        if line > 0 and line in source and source[line].strip():
            return line, "absolute_line"
    snippets = [raw, *re.findall(r"`([^`]+)`", str(point.get("description") or ""))]
    for snippet in snippets:
        tokens = code_tokens(snippet)
        if not tokens or len(tokens) < 2:
            continue
        matches = [
            line for line, text in source.items() if line > 0 and tokens == code_tokens(text)
        ]
        if len(matches) == 1:
            return matches[0], "unique_source_match"
    return None, "snapshot_point_location_unresolved"


def snapshot_candidates(
    result: SessionSemanticResult,
    *,
    entry: str = "",
    entry_file: str = "",
    entry_signature: str = "",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {
        "total": 0,
        "registered": 0,
        "merged": 0,
        "unresolved": 0,
        "unresolved_points": [],
    }
    for identity, snapshot in result.snapshots.items():
        paths = result.entry_paths.get(identity) or []
        entry_symbols = result.entry_symbols.get(identity) or []
        symbol_paths = result.symbol_paths.get(identity) or []
        if entry:
            selected = []
            selected_symbols = []
            for index, path in enumerate(paths):
                if not path or path[0] != entry:
                    continue
                symbol = json.loads(entry_symbols[index]) if index < len(entry_symbols) else {}
                if (
                    entry_file
                    and symbol.get("file_path")
                    and symbol["file_path"] != entry_file.replace("\\", "/")
                ):
                    continue
                if (
                    entry_signature
                    and symbol.get("signature")
                    and code_tokens(symbol["signature"]) != code_tokens(entry_signature)
                ):
                    continue
                selected.append(path)
                if index < len(symbol_paths):
                    selected_symbols.append(symbol_paths[index])
            paths = selected
            symbol_paths = selected_symbols
            if not paths:
                continue
        snapshot_version = digest(snapshot)
        for point in snapshot.get("suspicious_points", []) or []:
            metrics["total"] += 1
            if not isinstance(point, dict):
                metrics["unresolved"] += 1
                metrics["unresolved_points"].append(
                    {"symbol": identity, "reason": "invalid_point_schema"}
                )
                continue
            line, reason = resolve_point_line(point, snapshot)
            if line is None or not paths:
                metrics["unresolved"] += 1
                metrics["unresolved_points"].append(
                    {
                        "symbol": identity,
                        "snapshot_version": snapshot_version,
                        "point": dict(point),
                        "reason": reason if line is None else "entry_path_unresolved",
                    }
                )
                continue
            category = str(point.get("category") or "other")
            name = str(snapshot.get("func_name") or "")
            location = f"{snapshot.get('file_path')}:{line}"
            point_id = digest(
                {
                    "symbol": identity,
                    "category": category,
                    "anchor": code_tokens(_source_lines(snapshot)[line]),
                    "description": point.get("description"),
                }
            )
            issues.append(
                {
                    "id": "semantic_snapshot_" + point_id[:20],
                    "candidate_id": "semantic_snapshot_" + point_id[:20],
                    "candidate_source": "semantic_snapshot",
                    "candidate_kind": "semantic_snapshot_hypothesis",
                    "category": category,
                    "defect_class": category,
                    "subcategory": category,
                    "description": str(point.get("description") or ""),
                    "severity": "medium",
                    "confidence": 0.5,
                    "location": location,
                    "file_path": str(snapshot.get("file_path") or ""),
                    "line": line,
                    "line_number": line,
                    "function": name,
                    "function_name": name,
                    "entry_function": paths[0][0],
                    "call_paths": paths,
                    "call_path_symbols": [
                        [json.loads(symbol) for symbol in path] for path in symbol_paths
                    ],
                    "code_snippet": _source_lines(snapshot)[line],
                    "snapshot_version": snapshot_version,
                    "semantic_contract_version": result.contract_version,
                    "semantic_contracts": {
                        key: result.overlay.get(key, []) for key in ("api_contracts", "api_pairs")
                    },
                    "discovery_status": "hypothesis",
                    "candidate_disposition": "needs_review",
                    "missing_fact_kinds": ["path_feasibility", "violation_witness"],
                    "attribution": FindingAttribution(
                        discovered_by=("semantic_modeling",),
                        discovery_details=(
                            {
                                "kind": "semantic_modeling",
                                "source_id": identity,
                                "snapshot_version": snapshot_version,
                                "snapshot_kind": str(snapshot.get("snapshot_kind") or "unknown"),
                            },
                        ),
                    ).to_dict(),
                    "evidence_pack": {
                        "candidate_source": "semantic_snapshot",
                        "snapshot_version": snapshot_version,
                        "snapshot_symbol": identity,
                        "suspicious_point": dict(point),
                        "location_resolution": reason,
                        "semantic_contract_version": result.contract_version,
                        "proof_status": "unproven",
                    },
                }
            )
    return issues, metrics


def register_snapshot_candidates(
    result: SessionSemanticResult,
    registrar: CandidateRegistrar,
    *,
    entry: str = "",
    entry_file: str = "",
    entry_signature: str = "",
) -> list[dict[str, Any]]:
    issues, metrics = snapshot_candidates(
        result, entry=entry, entry_file=entry_file, entry_signature=entry_signature
    )
    registration = registrar.register_issues(
        issues, source="semantic_snapshot", force_unconfirmed=True
    )
    metrics["registered"] = registration.submitted_issue_count
    metrics["merged"] = max(0, registration.submitted_issue_count - registration.new_validation_group_count)
    metrics["registered_occurrences"] = registration.registered_occurrence_count
    result.suspicious_metrics = metrics
    return issues


def update_snapshot_outcomes(result: SessionSemanticResult, ledger: Any) -> None:
    """Count terminal validation obligations, including merged rule provenance."""
    outcomes: dict[str, int] = {}
    for record in ledger.records():
        if (
            "semantic_snapshot" not in record.sources
            or record.record_role != "validation_obligation"
        ):
            continue
        status = record.disposition or "pending"
        outcomes[status] = outcomes.get(status, 0) + 1
    result.suspicious_metrics["validation_outcomes"] = outcomes
