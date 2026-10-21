"""Adapt current semantic snapshot observations into unconfirmed obligations."""

from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Any

from ..reporting.attribution import FindingAttribution
from ..semantics.contracts import SymbolIdentity, digest, code_tokens
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


def register_conditional_snapshot_candidates(
    result: SessionSemanticResult,
    registrar: CandidateRegistrar,
    *,
    mode: str = "off",
    project_root: str | Path | None = None,
    entry: str = "",
    entry_file: str = "",
    entry_signature: str = "",
) -> list[dict[str, Any]]:
    """Register only current, explicitly conditional observations as shadow.

    Legacy suspicious_points remain context. This entry point runs after blind
    discovery and before the caller freezes its existing candidate ledger.
    """
    if mode == "off":
        return []
    if mode != "shadow":
        raise ValueError("snapshot observation mode must be off or shadow")
    from .snapshot_observations import (
        ObservationBinding,
        check_observation_binding,
        observation_qualification,
        source_rows,
    )

    root = project_root or registrar.project_root
    metrics: dict[str, Any] = {
        "mode": "shadow",
        "policy_version": "conditional-snapshot-shadow.v1",
        "total": 0,
        "eligible": 0,
        "registered": 0,
        "registered_occurrences": 0,
        "new_validation_groups": 0,
        "repeated_or_overlapping": 0,
        "same_source_repeated_obligations": 0,
        "cross_source_overlap_obligations": 0,
        "pending_shadow_obligations": 0,
        "terminal_shadow_obligations": 0,
        "background_only": 0,
        "rejected": [],
        "uncovered_symbols": [],
        "exclusive_true_positives": "not_measured",
        "additional_model_cost": "unknown",
        "proof_authority": False,
    }
    issues: list[dict[str, Any]] = []

    def reject(symbol: str, reason: str) -> None:
        metrics["rejected"].append({"symbol": symbol, "reason": reason})
        metrics["uncovered_symbols"].append(symbol)

    for symbol, snapshot in sorted(result.snapshots.items()):
        points = snapshot.get("conditional_observations", [])
        metrics["background_only"] += len(snapshot.get("suspicious_points") or [])
        if not isinstance(points, list):
            reject(symbol, "invalid_observation_array")
            continue
        metrics["total"] += len(points)
        if not points:
            continue
        if len(points) > 16:
            reject(symbol, "observation_budget_exceeded")
            continue
        binding = getattr(result, "observation_bindings", {}).get(symbol)
        state = (
            check_observation_binding(
                binding,
                snapshot,
                symbol=symbol,
                contract_version=result.contract_version,
                project_root=root,
            )
            if root
            else "snapshot_project_unavailable"
        )
        if state != "current" or not isinstance(binding, ObservationBinding):
            reject(symbol, state)
            continue
        paths = result.entry_paths.get(symbol) or []
        symbols = result.symbol_paths.get(symbol) or []
        selected: list[list[str]] = []
        selected_symbols: list[list[dict[str, Any]]] = []
        try:
            for index, path in enumerate(paths):
                if not path or index >= len(symbols):
                    continue
                route = [json.loads(value) for value in symbols[index]]
                if (
                    not route
                    or len(route) != len(path)
                    or any(not isinstance(value, dict) for value in route)
                ):
                    continue
                if any(value.get("name") != name for value, name in zip(route, path)):
                    continue
                if SymbolIdentity.from_value(route[-1]).key != symbol:
                    continue
                if entry and path[0] != entry:
                    continue
                if entry_file and str(route[0].get("file_path") or "").replace(
                    "\\", "/"
                ) != entry_file.replace("\\", "/"):
                    continue
                if entry_signature and code_tokens(
                    str(route[0].get("signature") or "")
                ) != code_tokens(entry_signature):
                    continue
                selected.append(path)
                selected_symbols.append(route)
        except (ValueError, TypeError):
            reject(symbol, "entry_identity_unverifiable")
            continue
        if not selected:
            reject(symbol, "entry_path_unresolved")
            continue
        for point in points:
            line, reason, applicability = observation_qualification(point, snapshot)
            if line is None:
                reject(symbol, reason)
                continue
            identity = digest(
                {
                    "symbol": symbol,
                    "line": line,
                    "anchor": code_tokens(source_rows(snapshot)[line]),
                    "object": point["object"],
                    "source": point["source"],
                    "sink": point["sink"],
                    "property": point["violated_property"],
                    "conditions": point["conditions"],
                }
            )
            category = {
                "resource_not_released": "resource_leak",
                "use_after_release": "use_after_free",
                "double_release": "double_free",
                "bounds_not_established": "buffer_overflow",
                "ownership_not_established": "ownership_violation",
                "lock_not_balanced": "lock_misuse",
                "error_path_cleanup_missing": "resource_leak",
            }[point["violated_property"]]
            issue = {
                "id": "snapshot_observation_" + identity[:20],
                "candidate_id": "snapshot_observation_" + identity[:20],
                "candidate_source": "semantic_snapshot",
                "candidate_kind": "conditional_snapshot_observation",
                "category": category,
                "subcategory": category,
                "defect_class": category,
                "description": point["description"],
                "severity": "medium",
                "confidence": 0.5,
                "location": f"{snapshot['file_path']}:{line}",
                "file_path": snapshot["file_path"],
                "line": line,
                "line_number": line,
                "function": snapshot["func_name"],
                "function_name": snapshot["func_name"],
                "resource": point["object"],
                "source": point["source"],
                "sink": point["sink"],
                "root_cause": point["violated_property"],
                "entry_function": selected[0][0],
                "call_paths": selected,
                "call_path_symbols": selected_symbols,
                "code_snippet": source_rows(snapshot)[line],
                "discovery_status": "hypothesis",
                "candidate_disposition": "needs_review",
                "missing_fact_kinds": list(point["missing_facts"]),
                "rollout_visibility": "shadow",
                "candidate_promotion_eligible": False,
                "candidate_promotion_reason": "conditional_snapshot_shadow",
                "candidate_promotion_terminal_status": "shadow_observation",
                "validator_contract": {
                    "visibility": "shadow",
                    "producer": "conditional_snapshot_observation",
                    "proof_authority": False,
                },
                "attribution": FindingAttribution(
                    discovered_by=("semantic_modeling",),
                    discovery_details=(
                        {
                            "kind": "semantic_modeling",
                            "source_id": symbol,
                            "method": "conditional_snapshot_observation",
                            "visibility": "shadow",
                        },
                    ),
                ).to_dict(),
                "evidence_pack": {
                    "producer": "conditional_snapshot_observation",
                    "snapshot_symbol": symbol,
                    "snapshot_version": binding.snapshot_hash,
                    "source_revision": binding.source_revision,
                    "modeling_spec": binding.modeling_spec,
                    "observation_schema": binding.schema_hash,
                    "semantic_contract_version": result.contract_version,
                    "violated_property": point["violated_property"],
                    "object": point["object"],
                    "conditions": point["conditions"],
                    "condition_evaluation": applicability,
                    "condition_proven": False,
                    "ownership_observation": point["ownership"],
                    "exit_kind": point["exit_kind"],
                    "missing_facts": list(point["missing_facts"]),
                    "proof_authority": False,
                    "location_resolution": "exact_source_anchor",
                },
            }
            # Source may change while observations are checked. No registration
            # is allowed until the original binding is still current.
            state = check_observation_binding(
                binding,
                snapshot,
                symbol=symbol,
                contract_version=result.contract_version,
                project_root=root,
            )
            if state != "current":
                reject(symbol, state)
                continue
            issues.append(issue)
            metrics["eligible"] += 1
    current_issues = []
    for issue in issues:
        symbol = issue["evidence_pack"]["snapshot_symbol"]
        state = check_observation_binding(
            getattr(result, "observation_bindings", {}).get(symbol),
            result.snapshots[symbol],
            symbol=symbol,
            contract_version=result.contract_version,
            project_root=root,
        )
        if state == "current":
            current_issues.append(issue)
        else:
            reject(symbol, state)
    issues = current_issues
    metrics["eligible"] = len(issues)
    previous_shadow = set()
    previous_other = set()
    for record in registrar.ledger.records():
        if record.record_role != "validation_obligation":
            continue
        if "semantic_snapshot" in record.sources:
            previous_shadow.add(record.obligation_uid)
        if any(source != "semantic_snapshot" for source in record.sources):
            previous_other.add(record.obligation_uid)
    registration = registrar.register_issues(
        issues, source="semantic_snapshot", force_unconfirmed=True
    )
    registered = [
        record
        for record in registrar.ledger.records()
        if record.candidate_id in registration.candidate_ids
    ]
    obligations = {record.obligation_uid for record in registered}
    metrics.update(
        same_source_repeated_obligations=len(obligations & previous_shadow),
        cross_source_overlap_obligations=len(obligations & previous_other),
        pending_shadow_obligations=sum(not record.disposition for record in registered),
        terminal_shadow_obligations=sum(bool(record.disposition) for record in registered),
    )
    metrics.update(
        registered=registration.submitted_issue_count,
        registered_occurrences=registration.registered_occurrence_count,
        new_validation_groups=registration.new_validation_group_count,
        repeated_or_overlapping=max(
            0, registration.submitted_issue_count - registration.new_validation_group_count
        ),
    )
    metrics["uncovered_symbols"] = sorted(set(metrics["uncovered_symbols"]))
    result.suspicious_metrics["conditional_observations"] = metrics
    return issues
