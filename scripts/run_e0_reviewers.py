#!/usr/bin/env python3
"""Run isolated E0 truth reviewers against pre-built minimal packets.

This command never reads scanner reports or scores.  Each model subprocess runs
in a temporary directory containing only the current packet (and, for Opus,
the two primary structured decisions).  Raw command envelopes are intended for
protected workflow artifacts and must not be committed to the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Mapping, Sequence

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from e0_review_governance import (
    DECISION_SCHEMA_VERSION,
    E0GovernanceError,
    load_json_strict,
    review_decision_contract_issues,
    sha256_file,
    sha256_value,
    validate_review_decision,
    validate_review_packet,
)


DISPUTED_IDS = {
    "ISSUE42-020",
    "ISSUE42-024",
    "RANGE-020",
    "RANGE-022",
    "RANGE-036",
    "RANGE-040",
    "RANGE-048",
    "RANGE-053",
    "REAL-016",
}

DSH_VERSION = "0.1.0-rc.6"
DEEPSEEK_PROVIDER_ID = "deepseek"
DEEPSEEK_MODEL_ID = "deepseek-v4-pro-0813"
DEEPSEEK_MODEL_IDENTITY = f"{DEEPSEEK_MODEL_ID}:max"
FORMAT_VALIDATION_SCHEMA_VERSION = "zscope.range-v16-format-validation.v3"
PRIMARY_CHECKPOINT_SCHEMA_VERSION = "zscope.range-v16-primary-checkpoint.v1"
PRIMARY_FAILURE_SCHEMA_VERSION = "zscope.range-v16-primary-failure.v1"
ARBITRATION_CHECKPOINT_SCHEMA_VERSION = "zscope.range-v16-arbitration-checkpoint.v1"
ARBITRATION_SHARD_SCHEMA_VERSION = "zscope.range-v16-arbitration-shard.v1"
SEMANTIC_ENVELOPE_REPAIR_SCHEMA_VERSION = "zscope.range-v16-semantic-envelope-repair.v1"

MATERIAL_DECISION_FIELDS = (
    "contract_kind",
    "disposition",
    "confidence",
    "defect_taxonomy_id",
    "cwe_ids",
    "structured_anchors",
    "required_evidence_clauses",
    "evidence_refs",
    "trigger_summary",
    "threat_assumptions",
    "safe_pair_recommendation",
    "reason_codes",
)

FROZEN_DECISION_BINDING_FIELDS = (
    "schema_version",
    "packet_uid",
    "packet_sha256",
    "reviewer_role",
    "reviewer_model",
)

_CONTRACT_ERROR_MATERIAL_FIELDS = {
    "review decision contract kind is invalid": "contract_kind",
    "review decision disposition is invalid": "disposition",
    "review decision confidence must be numeric": "confidence",
    "review decision confidence is outside [0,1]": "confidence",
    "review decision defect taxonomy ID is invalid": "defect_taxonomy_id",
    "review decision CWE identities are invalid": "cwe_ids",
    "review decision CWE identities are duplicate": "cwe_ids",
    "review decision structured_anchors must be non-empty": "structured_anchors",
    "review decision structured anchor fields are invalid": "structured_anchors",
    "review decision structured anchor kind is invalid": "structured_anchors",
    "review decision anchor correction flag is invalid": "structured_anchors",
    "review decision structured anchor file is invalid": "structured_anchors",
    "review decision structured anchor path is not canonical": "structured_anchors",
    "review decision structured anchor function is invalid": "structured_anchors",
    "review decision structured anchor range is invalid": "structured_anchors",
    "review decision required evidence clauses must be non-empty": ("required_evidence_clauses"),
    "review decision evidence clause fields are invalid": "required_evidence_clauses",
    "review decision evidence clause ID is invalid or duplicate": ("required_evidence_clauses"),
    "review decision evidence clause predicate is invalid": "required_evidence_clauses",
    "review decision evidence clause refs are invalid": "required_evidence_clauses",
    "review decision evidence refs are invalid": "evidence_refs",
    "review decision trigger summary is invalid": "trigger_summary",
    "review decision threat assumptions are invalid": "threat_assumptions",
    "review decision reason codes are invalid": "reason_codes",
    "review decision safe pair recommendation is invalid": "safe_pair_recommendation",
    "review decision safe pair kind is invalid": "safe_pair_recommendation",
    "review decision safe pair invariant_summary is invalid": "safe_pair_recommendation",
    "review decision safe pair vulnerable_summary is invalid": "safe_pair_recommendation",
    "review decision safe pair safe_summary is invalid": "safe_pair_recommendation",
    "review decision compile requirements are invalid": "safe_pair_recommendation",
}

_HIDDEN_REASONING_KEYS = {
    "analysis",
    "chain_of_thought",
    "chainofthought",
    "hidden_reasoning",
    "reasoning_content",
    "thinking",
    "thinking_content",
}


def decision_disagreement_fields(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> tuple[str, ...]:
    """Return every material adjudication field that requires Opus."""

    return tuple(field for field in MATERIAL_DECISION_FIELDS if left.get(field) != right.get(field))


DECISION_FIELDS = {
    "schema_version": DECISION_SCHEMA_VERSION,
    "packet_uid": "copy from packet",
    "packet_sha256": "copy from packet",
    "reviewer_role": "assigned by harness",
    "reviewer_model": "assigned model identity",
    "contract_kind": "concrete_trigger|public_api_contract|pattern_model|retired",
    "disposition": "keep|correct|retire|unresolved",
    "confidence": "number 0..1",
    "defect_taxonomy_id": "lowercase normalized defect category",
    "cwe_ids": ["CWE-123"],
    "structured_anchors": [
        {
            "kind": "primary|secondary|additional",
            "corrected": "boolean indicating a v15 anchor correction",
            "file": "repository-relative POSIX path",
            "function": "function name",
            "start_line": "positive integer",
            "end_line": "integer >= start_line",
        }
    ],
    "required_evidence_clauses": [
        {
            "clause_id": "stable lowercase identifier",
            "predicate": "short, auditable evidence requirement",
            "evidence_refs": ["file:start-end"],
        }
    ],
    "evidence_refs": [],
    "trigger_summary": "concise evidence-grounded trigger or model summary",
    "threat_assumptions": ["explicit answer-free assumption reviewed from the packet"],
    "safe_pair_recommendation": {
        "kind": "fixed|near_miss",
        "invariant_summary": "the invariant isolated by the pair",
        "vulnerable_summary": "behavior of the vulnerable side",
        "safe_summary": "behavior of the fixed or near-miss side",
        "compile_requirements": ["standalone compilation requirement"],
    },
    "reason_codes": [],
}


def _json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")


def _packet_id(packet: Mapping[str, Any]) -> str:
    record = packet.get("truth_record")
    if not isinstance(record, Mapping):
        raise E0GovernanceError("review packet truth_record is invalid")
    value = str(record.get("id") or record.get("truth_id") or "").strip()
    if not value:
        raise E0GovernanceError("review packet has no source truth ID")
    return value


def _decision_schema_for_model() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(DECISION_FIELDS),
        "properties": {
            "schema_version": {"const": DECISION_SCHEMA_VERSION},
            "packet_uid": {"type": "string"},
            "packet_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "reviewer_role": {"enum": ["primary_fable", "primary_deepseek", "arbiter_opus"]},
            "reviewer_model": {"type": "string"},
            "contract_kind": {
                "enum": [
                    "concrete_trigger",
                    "public_api_contract",
                    "pattern_model",
                    "retired",
                ]
            },
            "disposition": {"enum": ["keep", "correct", "retire", "unresolved"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "defect_taxonomy_id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9_]{1,127}$",
            },
            "cwe_ids": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"type": "string", "pattern": "^CWE-[0-9]+$"},
            },
            "structured_anchors": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "kind",
                        "corrected",
                        "file",
                        "function",
                        "start_line",
                        "end_line",
                    ],
                    "properties": {
                        "kind": {"enum": ["primary", "secondary", "additional"]},
                        "corrected": {"type": "boolean"},
                        "file": {"type": "string", "minLength": 1},
                        "function": {"type": "string", "minLength": 1},
                        "start_line": {"type": "integer", "minimum": 1},
                        "end_line": {"type": "integer", "minimum": 1},
                    },
                },
            },
            "required_evidence_clauses": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["clause_id", "predicate", "evidence_refs"],
                    "properties": {
                        "clause_id": {
                            "type": "string",
                            "pattern": "^[a-z][a-z0-9_]{2,63}$",
                        },
                        "predicate": {"type": "string", "minLength": 1},
                        "evidence_refs": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1},
                        },
                    },
                },
            },
            "evidence_refs": {"type": "array", "items": {"type": "string"}},
            "trigger_summary": {"type": "string", "minLength": 1},
            "threat_assumptions": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "safe_pair_recommendation": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "kind",
                    "invariant_summary",
                    "vulnerable_summary",
                    "safe_summary",
                    "compile_requirements",
                ],
                "properties": {
                    "kind": {"enum": ["fixed", "near_miss"]},
                    "invariant_summary": {"type": "string", "minLength": 1},
                    "vulnerable_summary": {"type": "string", "minLength": 1},
                    "safe_summary": {"type": "string", "minLength": 1},
                    "compile_requirements": {
                        "type": "array",
                        "minItems": 1,
                        "items": {"type": "string", "minLength": 1},
                    },
                },
            },
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "enum": [
                        "TRIGGER_PRESENT",
                        "PUBLIC_CONTRACT_SUPPORTED",
                        "TRIGGER_INCOMPLETE",
                        "THREAT_ASSUMPTION_UNSUPPORTED",
                        "ANCHOR_CORRECTION_REQUIRED",
                        "CATEGORY_CORRECTION_REQUIRED",
                        "DUPLICATE_TRUTH",
                        "CODE_COUNTEREVIDENCE",
                        "SAFE_PAIR_REQUIRED",
                        "INSUFFICIENT_EVIDENCE",
                    ]
                },
            },
        },
    }


def _bound_decision_schema(
    packet: Mapping[str, Any],
    *,
    role: str,
    model: str,
) -> dict[str, Any]:
    """Bind the isolated schema file to the exact packet and reviewer identity."""

    schema = _decision_schema_for_model()
    properties = schema["properties"]
    properties["packet_uid"] = {"const": str(packet["packet_uid"])}
    properties["packet_sha256"] = {"const": str(packet["packet_sha256"])}
    properties["reviewer_role"] = {"const": role}
    properties["reviewer_model"] = {"const": model}
    return schema


def _prompt(
    packet: Mapping[str, Any],
    *,
    role: str,
    model: str,
    primary_decisions: Sequence[Mapping[str, Any]] = (),
) -> str:
    arbitration = ""
    if primary_decisions:
        arbitration = (
            "\nThe following two primary decisions are supplied only for independent "
            "arbitration. Resolve their disagreement from the packet evidence; do not "
            "average confidence or defer to either reviewer.\nPRIMARY_DECISIONS:\n"
            + json.dumps(list(primary_decisions), ensure_ascii=False, sort_keys=True)
        )
    return f"""You are an independent benchmark truth-contract reviewer.
Review only the packet below. Never use tools, files, network access, web search,
or knowledge outside the packet. Do not infer product findings, benchmark scores,
rule behavior, or desired recall. A confirmable contract requires evidence in
the supplied code/contract; unsupported deployment assumptions must remain a
pattern_model. Retire only if the record is positively disproved, duplicate, or
incorrect. Recommend a vulnerable/fixed or near-miss safe pair without changing
the product implementation. Use exactly one primary anchor. Every anchor must
fall wholly inside a supplied code window; do not combine a file from one window
with line numbers from another. Every non-empty evidence_refs item must be the
exact canonical ``path:start-end`` of one supplied window or a contained range,
with no label or prose prefix. Return exactly one JSON object matching the
stated nested fields, with no markdown, prose wrapper, external citation, or
hidden reasoning transcript.

Assigned reviewer_role: {role}
Assigned reviewer_model: {model}
Required fields: {json.dumps(DECISION_FIELDS, ensure_ascii=False, sort_keys=True)}
PACKET:
{json.dumps(packet, ensure_ascii=False, sort_keys=True)}
{arbitration}
"""


def _extract_claude_decision(stdout: str) -> Mapping[str, Any]:
    envelope = json.loads(stdout)
    if isinstance(envelope, Mapping) and isinstance(envelope.get("structured_output"), Mapping):
        return dict(envelope["structured_output"])
    if isinstance(envelope, Mapping) and isinstance(envelope.get("result"), str):
        result = json.loads(str(envelope["result"]))
        if isinstance(result, Mapping):
            return dict(result)
    if isinstance(envelope, Mapping) and set(DECISION_FIELDS).issubset(envelope):
        return dict(envelope)
    raise E0GovernanceError("Claude did not return a structured review decision")


def _normalize_deepseek_json_artifact(stdout: str) -> str:
    """Accept direct JSON or one exact JSON fence, never prose extraction."""

    stripped = stdout.strip()
    try:
        json.loads(stripped)
        return stripped
    except json.JSONDecodeError:
        pass

    match = re.fullmatch(
        r"```(?:json)?[ \t]*\r?\n(?P<body>.*?)(?:\r?\n)?```",
        stripped,
        flags=re.DOTALL,
    )
    if match is None or "```" in match.group("body"):
        raise E0GovernanceError("reviewer output is not a JSON artifact")
    body = match.group("body").strip()
    try:
        json.loads(body)
    except json.JSONDecodeError as exc:
        raise E0GovernanceError("reviewer output is not a JSON artifact") from exc
    return body


def _extract_deepseek_decision(stdout: str) -> Mapping[str, Any]:
    value = json.loads(stdout.strip())
    if not isinstance(value, Mapping):
        raise E0GovernanceError("DeepSeek did not return a JSON object")
    return dict(value)


def assert_no_hidden_reasoning_output(stdout: str) -> None:
    """Fail closed if a provider emits hidden reasoning in its JSON envelope."""

    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise E0GovernanceError("reviewer output is not a JSON artifact") from exc

    def visit(item: Any, *, path: str) -> None:
        if isinstance(item, Mapping):
            for raw_key, nested in item.items():
                key = re.sub(r"[^a-z0-9]+", "_", str(raw_key).strip().lower()).strip("_")
                if key in _HIDDEN_REASONING_KEYS:
                    raise E0GovernanceError(
                        f"reviewer output contains hidden reasoning at {path}.{raw_key}"
                    )
                visit(nested, path=f"{path}.{raw_key}")
        elif isinstance(item, list):
            for index, nested in enumerate(item):
                visit(nested, path=f"{path}[{index}]")

    visit(value, path="$")


def _validated_decision_from_stdout(stdout: str, *, reviewer: str) -> Mapping[str, Any]:
    artifact = _normalize_deepseek_json_artifact(stdout) if reviewer == "deepseek" else stdout
    assert_no_hidden_reasoning_output(artifact)
    return (
        _extract_deepseek_decision(artifact)
        if reviewer == "deepseek"
        else _extract_claude_decision(artifact)
    )


def _validated_bound_decision_from_stdout(
    stdout: str,
    *,
    reviewer: str,
    packet: Mapping[str, Any],
    role: str,
    model: str,
) -> Mapping[str, Any]:
    """Parse a decision and enforce its frozen packet and reviewer identity."""

    decision = _validated_decision_from_stdout(stdout, reviewer=reviewer)
    validate_review_decision(
        decision,
        expected_packet_uid=str(packet["packet_uid"]),
        expected_packet_sha256=str(packet["packet_sha256"]),
        expected_role=role,
    )
    if decision.get("reviewer_model") != model:
        raise E0GovernanceError("reviewer model identity mismatch")
    return decision


def _json_schema_type_matches(value: Any, expected_type: str) -> bool:
    if expected_type == "object":
        return isinstance(value, Mapping)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "null":
        return value is None
    return True


def _json_value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def _schema_shape_errors(
    value: Any,
    schema: Mapping[str, Any],
    *,
    path: str = "$",
) -> list[dict[str, Any]]:
    """Report schema paths, field names, and types without retaining values."""

    raw_types = schema.get("type")
    expected_types = (
        [raw_types]
        if isinstance(raw_types, str)
        else [str(item) for item in raw_types] if isinstance(raw_types, list) else []
    )
    if expected_types and not any(
        _json_schema_type_matches(value, expected_type) for expected_type in expected_types
    ):
        return [
            {
                "path": path,
                "expected_types": expected_types,
                "actual_type": _json_value_type(value),
                "missing_fields": [],
                "unexpected_fields": [],
            }
        ]

    errors: list[dict[str, Any]] = []
    violated_constraints: list[str] = []
    if "const" in schema and value != schema["const"]:
        violated_constraints.append("const")
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and value not in enum_values:
        violated_constraints.append("enum")
    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            violated_constraints.append("minLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            violated_constraints.append("pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            violated_constraints.append("finite")
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and value < minimum:
            violated_constraints.append("minimum")
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and value > maximum:
            violated_constraints.append("maximum")
    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            violated_constraints.append("minItems")
        if schema.get("uniqueItems") is True:
            canonical_items = [
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(canonical_items) != len(set(canonical_items)):
                violated_constraints.append("uniqueItems")
    if violated_constraints:
        errors.append(
            {
                "path": path,
                "expected_types": expected_types,
                "actual_type": _json_value_type(value),
                "missing_fields": [],
                "unexpected_fields": [],
                "violated_constraints": sorted(set(violated_constraints)),
            }
        )
    if isinstance(value, Mapping):
        properties = schema.get("properties")
        properties = properties if isinstance(properties, Mapping) else {}
        required = schema.get("required")
        required_fields = (
            {str(field) for field in required if isinstance(field, str)}
            if isinstance(required, list)
            else set()
        )
        actual_fields = {str(field) for field in value}
        missing_fields = sorted(required_fields - actual_fields)
        unexpected_fields = (
            sorted(actual_fields - set(properties))
            if schema.get("additionalProperties") is False
            else []
        )
        if missing_fields or unexpected_fields:
            errors.append(
                {
                    "path": path,
                    "expected_types": expected_types,
                    "actual_type": "object",
                    "missing_fields": missing_fields,
                    "unexpected_fields": unexpected_fields,
                }
            )
        for field in sorted(actual_fields & set(properties)):
            child_schema = properties[field]
            if isinstance(child_schema, Mapping):
                errors.extend(
                    _schema_shape_errors(
                        value[field],
                        child_schema,
                        path=f"{path}.{field}",
                    )
                )
    elif isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                errors.extend(
                    _schema_shape_errors(
                        item,
                        item_schema,
                        path=f"{path}[{index}]",
                    )
                )
    return errors


def _format_validation_feedback(
    stdout: str,
    *,
    reviewer: str,
    validation_error: Exception,
    packet: Mapping[str, Any] | None = None,
    role: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """Describe strict format failures without retaining substantive output."""

    required_fields = sorted(DECISION_FIELDS)
    actual_fields: list[str] = []
    parsed_object = False
    try:
        decision = _validated_decision_from_stdout(stdout, reviewer=reviewer)
    except (json.JSONDecodeError, E0GovernanceError):
        pass
    else:
        parsed_object = True
        actual_fields = sorted(str(field) for field in decision)
    schema = (
        _bound_decision_schema(packet, role=role, model=model)
        if packet is not None and role is not None and model is not None
        else _decision_schema_for_model()
    )
    shape_errors = _schema_shape_errors(decision, schema) if parsed_object else []
    material_issue_fields = list(_schema_issue_material_fields(decision)) if parsed_object else []
    binding_issue_fields: list[str] = []
    semantic_contract_issues: list[dict[str, str]] = []
    if parsed_object and packet is not None and role is not None and model is not None:
        issues = review_decision_contract_issues(
            decision,
            expected_packet_uid=str(packet["packet_uid"]),
            expected_packet_sha256=str(packet["packet_sha256"]),
            expected_role=role,
        )
        semantic_contract_issues = [
            {"code": issue["code"], "path": issue["path"]} for issue in issues
        ]
        material_issue_fields = sorted(
            set(material_issue_fields)
            | {
                issue["material_field"]
                for issue in issues
                if issue.get("material_field") in MATERIAL_DECISION_FIELDS
            }
        )
        expected_bindings = {
            "schema_version": DECISION_SCHEMA_VERSION,
            "packet_uid": str(packet["packet_uid"]),
            "packet_sha256": str(packet["packet_sha256"]),
            "reviewer_role": role,
            "reviewer_model": model,
        }
        binding_issue_fields = sorted(
            {
                field
                for field, expected in expected_bindings.items()
                if decision.get(field) != expected
            }
            | {issue["binding_field"] for issue in issues if "binding_field" in issue}
        )
    return {
        "schema_version": FORMAT_VALIDATION_SCHEMA_VERSION,
        "validation_error": str(validation_error),
        "parsed_object": parsed_object,
        "required_top_level_fields": required_fields,
        "actual_top_level_fields": actual_fields,
        "missing_top_level_fields": sorted(set(required_fields) - set(actual_fields)),
        "unexpected_top_level_fields": sorted(set(actual_fields) - set(required_fields)),
        "schema_shape_errors": shape_errors,
        "semantic_contract_issues": semantic_contract_issues,
        "binding_issue_fields": binding_issue_fields,
        "material_issue_fields": material_issue_fields,
    }


def _schema_issue_material_fields(decision: Mapping[str, Any]) -> tuple[str, ...]:
    """Return every material field implicated by answer-free schema diagnostics."""

    fields: set[str] = set()
    for issue in _schema_shape_errors(decision, _decision_schema_for_model()):
        path = str(issue.get("path") or "")
        if path == "$":
            fields.update(
                field
                for field in issue.get("missing_fields") or []
                if field in MATERIAL_DECISION_FIELDS
            )
            continue
        match = re.match(r"^\$\.([A-Za-z0-9_]+)", path)
        if match is not None and match.group(1) in MATERIAL_DECISION_FIELDS:
            fields.add(match.group(1))
    return tuple(sorted(fields))


def validate_decision_against_packet(
    decision: Mapping[str, Any],
    packet: Mapping[str, Any],
    *,
    require_resolvable_evidence: bool,
) -> None:
    """Bind corrected anchors and final evidence refs to supplied code windows."""

    windows = packet.get("code_windows")
    if not isinstance(windows, list) or not windows:
        raise E0GovernanceError("review packet has no code windows")
    anchors = decision.get("structured_anchors")
    if (
        not isinstance(anchors, list)
        or sum(
            1
            for anchor in anchors
            if isinstance(anchor, Mapping) and anchor.get("kind") == "primary"
        )
        != 1
    ):
        raise E0GovernanceError("review decision requires exactly one primary anchor")
    source_functions = {
        str(value)
        for key, value in dict(packet.get("truth_record") or {}).items()
        if "function" in str(key).lower() and isinstance(value, str) and value
    }
    for anchor in anchors:
        if not isinstance(anchor, Mapping):
            raise E0GovernanceError("review decision anchor is invalid")
        file_name = str(anchor.get("file") or "")
        function = str(anchor.get("function") or "")
        start = anchor.get("start_line")
        end = anchor.get("end_line")
        contained = any(
            isinstance(window, Mapping)
            and window.get("path") == file_name
            and isinstance(start, int)
            and isinstance(end, int)
            and int(window.get("start_line", 0)) <= start
            and end <= int(window.get("end_line", 0))
            for window in windows
        )
        function_grounded = function in source_functions or any(
            isinstance(window, Mapping)
            and window.get("path") == file_name
            and isinstance(window.get("content"), str)
            and function in str(window["content"])
            for window in windows
        )
        if not contained or not function_grounded:
            raise E0GovernanceError("review decision anchor is outside the supplied code windows")

    direct_refs = list(decision.get("evidence_refs") or [])
    if (
        require_resolvable_evidence
        and decision.get("contract_kind") in {"concrete_trigger", "public_api_contract"}
        and not direct_refs
    ):
        raise E0GovernanceError("confirmable review decision requires direct trigger evidence refs")
    refs = list(direct_refs)
    for clause in decision.get("required_evidence_clauses") or []:
        if isinstance(clause, Mapping):
            refs.extend(clause.get("evidence_refs") or [])
    window_paths = {str(window["path"]) for window in windows if isinstance(window, Mapping)}
    for ref in refs:
        if not isinstance(ref, str):
            raise E0GovernanceError("review decision evidence ref is invalid")
        match = re.fullmatch(r"([^:\\]+(?:/[^:\\]+)*):(\d+)(?:-(\d+))?", ref)
        if not match or match.group(1) not in window_paths:
            raise E0GovernanceError("review decision evidence ref is not canonical")
        start = int(match.group(2))
        end = int(match.group(3) or start)
        if end < start or not any(
            isinstance(window, Mapping)
            and window.get("path") == match.group(1)
            and int(window.get("start_line", 0)) <= start
            and end <= int(window.get("end_line", 0))
            for window in windows
        ):
            raise E0GovernanceError("review decision evidence ref is outside the supplied windows")


def _semantic_retry_substantive_projection(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze every substantive field across a grounding-only retry."""

    projection = dict(decision)
    projection.pop("structured_anchors", None)
    projection.pop("evidence_refs", None)
    clauses: list[Any] = []
    for clause in decision.get("required_evidence_clauses") or []:
        if isinstance(clause, Mapping):
            projected_clause = dict(clause)
            projected_clause.pop("evidence_refs", None)
            clauses.append(projected_clause)
        else:
            clauses.append(clause)
    projection["required_evidence_clauses"] = clauses
    return projection


def _contract_retry_substantive_projection(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze all material fields across an envelope-identity correction."""

    return {
        field: {"present": field in decision, "value": decision.get(field)}
        for field in MATERIAL_DECISION_FIELDS
    }


def _identity_contract_error(exc: Exception) -> bool:
    """Return whether a strict failure is limited to frozen envelope identity."""

    return str(exc) in {
        "review decision schema_version is invalid",
        "review decision packet UID mismatch",
        "review decision packet hash mismatch",
        "review decision role mismatch",
        "reviewer model identity mismatch",
    }


def _contract_validation_failure_code(exc: Exception) -> str:
    """Classify retry validation failures without retaining reviewer material."""

    message = str(exc)
    if isinstance(exc, json.JSONDecodeError) or message in {
        "reviewer output is not a JSON artifact",
        "DeepSeek did not return a JSON object",
        "Claude did not return a structured review decision",
    }:
        return "json_artifact_invalid"
    if "hidden reasoning" in message:
        return "hidden_reasoning_forbidden"
    if _identity_contract_error(exc):
        return "decision_binding_invalid"
    return "decision_contract_invalid"


def _contract_retry_mutable_material_fields(
    decision: Mapping[str, Any],
    validation_error: Exception,
    *,
    expected_packet_uid: str | None = None,
    expected_packet_sha256: str | None = None,
    expected_role: str | None = None,
) -> tuple[str, ...] | None:
    """Identify the smallest material repair surface from a strict contract error.

    Returning ``None`` means the harness cannot prove a bounded material repair and
    therefore must not claim that any material projection was preserved.  An empty
    tuple means that only frozen envelope identity or non-material extra fields may
    change.
    """

    schema_fields = set(_schema_issue_material_fields(decision))
    schema_fields.update(
        issue["material_field"]
        for issue in review_decision_contract_issues(
            decision,
            expected_packet_uid=expected_packet_uid,
            expected_packet_sha256=expected_packet_sha256,
            expected_role=expected_role,
        )
        if issue.get("material_field") in MATERIAL_DECISION_FIELDS
    )
    if _identity_contract_error(validation_error):
        return tuple(sorted(schema_fields))
    message = str(validation_error)
    if message == "review decision fields do not match v1 contract":
        schema_fields.update(field for field in MATERIAL_DECISION_FIELDS if field not in decision)
        return tuple(sorted(schema_fields))
    field = _CONTRACT_ERROR_MATERIAL_FIELDS.get(message)
    if field is not None:
        schema_fields.add(field)
    return tuple(sorted(schema_fields)) if schema_fields else None


def _contract_retry_locked_projection(
    decision: Mapping[str, Any],
    mutable_material_fields: Sequence[str],
) -> dict[str, Any]:
    """Project material fields that a bounded contract repair may not change."""

    mutable = set(mutable_material_fields)
    return {
        field: {"present": field in decision, "value": decision.get(field)}
        for field in MATERIAL_DECISION_FIELDS
        if field not in mutable
    }


def _rebind_grounding_decision_identity(
    decision: Mapping[str, Any],
    packet: Mapping[str, Any],
    *,
    role: str,
    model: str,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Rebind only frozen envelope identity after one grounding decision.

    This is not semantic normalization: every material field is hash-locked,
    and any independently detectable non-binding defect fails closed without a
    further model call.
    """

    expected_bindings = {
        "schema_version": DECISION_SCHEMA_VERSION,
        "packet_uid": str(packet["packet_uid"]),
        "packet_sha256": str(packet["packet_sha256"]),
        "reviewer_role": role,
        "reviewer_model": model,
    }
    expected_fields = set(DECISION_FIELDS)
    actual_fields = set(decision)
    missing_fields = expected_fields - actual_fields
    unexpected_fields = actual_fields - expected_fields
    top_level_identity_only = not unexpected_fields and missing_fields.issubset(
        FROZEN_DECISION_BINDING_FIELDS
    )
    issues = review_decision_contract_issues(
        decision,
        expected_packet_uid=str(packet["packet_uid"]),
        expected_packet_sha256=str(packet["packet_sha256"]),
        expected_role=role,
    )
    non_binding_issues = [
        issue
        for issue in issues
        if "binding_field" not in issue
        and not (issue.get("code") == "top_level_fields_invalid" and top_level_identity_only)
    ]
    if non_binding_issues:
        raise E0GovernanceError("grounding correction has non-binding decision-contract defects")
    rebound_fields = {
        field for field, expected in expected_bindings.items() if decision.get(field) != expected
    }
    if not rebound_fields:
        raise E0GovernanceError(
            "grounding correction failure is not an identity-only envelope defect"
        )
    original_projection_sha256 = sha256_value(_contract_retry_substantive_projection(decision))
    rebound = dict(decision)
    rebound.update(expected_bindings)
    validate_review_decision(
        rebound,
        expected_packet_uid=str(packet["packet_uid"]),
        expected_packet_sha256=str(packet["packet_sha256"]),
        expected_role=role,
    )
    if rebound.get("reviewer_model") != model:
        raise E0GovernanceError("reviewer model identity mismatch")
    if sha256_value(_contract_retry_substantive_projection(rebound)) != original_projection_sha256:
        raise E0GovernanceError("grounding identity rebind changed material fields")
    return rebound, tuple(sorted(rebound_fields))


def _claude_arguments(reviewer: str) -> list[str]:
    if reviewer not in {"fable", "opus"}:
        raise E0GovernanceError("Claude reviewer identity is invalid")
    return [
        "--print",
        "--model",
        "claude-fable-5" if reviewer == "fable" else "claude-opus-5",
        "--effort",
        "high" if reviewer == "fable" else "max",
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(_decision_schema_for_model(), separators=(",", ":")),
        "--permission-mode",
        "plan",
        "--tools",
        "",
        "--no-session-persistence",
        "--disable-slash-commands",
    ]


def _deepseek_patch_text() -> str:
    """Return the sealed DSH overlay, including its auditable provider route."""
    return (
        "- id: agent-default-model\n"
        "  config:\n"
        f"    provider: {DEEPSEEK_PROVIDER_ID}\n"
        f"    model: {DEEPSEEK_MODEL_ID}\n"
        "    reasoningEffort: max\n"
        "- id: system-prompt\n"
        "  config:\n"
        "    persona: >-\n"
        "      You are an isolated benchmark contract reviewer. Only use the\n"
        "      read-only packet.json and decision-schema.json in the current directory,\n"
        "      plus prior-output.txt and format-validation.json when they are present for\n"
        "      a bounded format-only retry. Never use external knowledge or any other\n"
        "      tool. Return exactly the requested JSON object with no markdown or prose\n"
        "      wrapper.\n"
        "- id: tool-web\n"
        "  disabled: true\n"
        "- id: tool-fs-search\n"
        "  disabled: true\n"
        "- id: tool-pwsh\n"
        "  disabled: true\n"
        "- id: tool-jobs\n"
        "  disabled: true\n"
        "- id: tool-subagent\n"
        "  disabled: true\n"
        "- id: tool-subagent-fork\n"
        "  disabled: true\n"
        "- id: tool-workflow\n"
        "  disabled: true\n"
        "- id: tool-ralph\n"
        "  disabled: true\n"
        "- id: tool-str-replace-editor\n"
        "  disabled: true\n"
        "- id: tool-todo\n"
        "  disabled: true\n"
        "- id: tool-goal\n"
        "  disabled: true\n"
    )


def _deepseek_patch_sha256() -> str:
    return hashlib.sha256(_deepseek_patch_text().encode("utf-8")).hexdigest()


def _run_model(
    packet: Mapping[str, Any],
    *,
    reviewer: str,
    primary_decisions: Sequence[Mapping[str, Any]] = (),
    raw_output_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if reviewer == "fable":
        role, model = "primary_fable", "claude-fable-5"
    elif reviewer == "deepseek":
        role, model = "primary_deepseek", DEEPSEEK_MODEL_IDENTITY
    elif reviewer == "opus":
        role, model = "arbiter_opus", "claude-opus-5"
    else:
        raise E0GovernanceError(f"unsupported reviewer: {reviewer}")

    claude_command = shutil.which("claude.cmd" if os.name == "nt" else "claude")
    dsh_command = shutil.which("dsh.cmd" if os.name == "nt" else "dsh")
    if reviewer in {"fable", "opus"} and not claude_command:
        raise E0GovernanceError("Claude Code executable is unavailable")
    if reviewer == "deepseek" and not dsh_command:
        raise E0GovernanceError("DeepSeek Harness executable is unavailable")

    prompt = _prompt(packet, role=role, model=model, primary_decisions=primary_decisions)
    with tempfile.TemporaryDirectory(prefix="zscope-e0-review-") as raw_temp:
        temp_root = Path(raw_temp)
        _json_dump(temp_root / "packet.json", packet)
        _json_dump(
            temp_root / "decision-schema.json",
            _bound_decision_schema(packet, role=role, model=model),
        )
        (temp_root / "review-instructions.txt").write_text(prompt, encoding="utf-8")
        if primary_decisions:
            _json_dump(temp_root / "primary-decisions.json", list(primary_decisions))

        patch_path: Path | None = None
        if reviewer in {"fable", "opus"}:
            command = [str(claude_command), *_claude_arguments(reviewer)]
        else:
            patch_path = temp_root / "deepseek-max.patch.yml"
            patch_path.write_text(
                _deepseek_patch_text(),
                encoding="utf-8",
                newline="\n",
            )
            command = [
                str(dsh_command),
                "--profile",
                "headless",
                "--patch",
                str(patch_path),
                "Read review-instructions.txt, packet.json, and decision-schema.json from "
                "the isolated current directory. Follow those instructions, review only "
                "that packet, and return exactly one JSON object matching the schema. Set "
                "reviewer_role=primary_deepseek and "
                f"reviewer_model={DEEPSEEK_MODEL_IDENTITY}. "
                "Do not use web search or external knowledge.",
            ]

        env = {
            key: value
            for key, value in os.environ.items()
            if "GROUND_TRUTH" not in key.upper()
            and "BENCHMARK_TRUTH" not in key.upper()
            and "SCORER" not in key.upper()
        }
        env["DSH_PERMISSION_MODE"] = "read-only"
        completed = subprocess.run(
            command,
            input=prompt if reviewer in {"fable", "opus"} else None,
            cwd=temp_root,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
            timeout=1800,
        )
        transport_retry: dict[str, Any] | None = None
        if completed.returncode != 0:
            transport_retry = {
                "initial_exit_code": completed.returncode,
                "initial_stdout_sha256": sha256_value(completed.stdout),
                "initial_stdout_retained": False,
                "initial_stderr_sha256": sha256_value(completed.stderr),
            }
            completed = subprocess.run(
                command,
                input=prompt if reviewer in {"fable", "opus"} else None,
                cwd=temp_root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                check=False,
                timeout=1800,
            )
        deepseek_patch_sha256 = sha256_file(patch_path) if patch_path is not None else ""
        if reviewer == "deepseek" and deepseek_patch_sha256 != _deepseek_patch_sha256():
            raise E0GovernanceError("DeepSeek patch bytes do not match the frozen identity")
        raw = {
            "schema_version": "zscope.range-v16-review-raw-envelope.v1",
            "reviewer_role": role,
            "reviewer_model": model,
            "packet_uid": packet["packet_uid"],
            "packet_sha256": packet["packet_sha256"],
            "input_delivery": (
                "embedded_prompt" if reviewer in {"fable", "opus"} else "isolated_files"
            ),
            "command_identity": (
                [Path(command[0]).name, *command[1:]]
                if reviewer in {"fable", "opus"}
                else [
                    "dsh",
                    "--profile",
                    "headless",
                    "--patch",
                    f"<ephemeral-patch-sha256:{deepseek_patch_sha256}>",
                ]
            ),
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr_sha256": sha256_value(completed.stderr),
        }
        if transport_retry is not None:
            raw["transport_retry"] = transport_retry
        if completed.returncode != 0:
            raise E0GovernanceError(
                f"{reviewer} reviewer failed for {packet['packet_uid']}; "
                f"stderr_sha256={raw['stderr_sha256']}"
            )
        decision: Mapping[str, Any] | None = None
        contract_error: Exception | None = None
        try:
            decision = _validated_bound_decision_from_stdout(
                completed.stdout,
                reviewer=reviewer,
                packet=packet,
                role=role,
                model=model,
            )
        except (json.JSONDecodeError, E0GovernanceError) as exc:
            contract_error = exc
        if contract_error is not None and reviewer == "deepseek":
            format_prompts = (
                "Read prior-output.txt, decision-schema.json, and format-validation.json "
                "in the isolated current directory. Reformat the prior answer as exactly "
                "one JSON object matching the schema without changing its substantive "
                "decision. Copy every required top-level field name character-for-character "
                "from format-validation.json and emit no unexpected field. Your entire "
                "final response must be that object: the first non-whitespace character "
                "must be { and the last must be }. Do not add prose, Markdown, or backticks. "
                "Set reviewer_role=primary_deepseek and "
                f"reviewer_model={DEEPSEEK_MODEL_IDENTITY}.",
                "The previous formatting attempt still failed strict validation. Read "
                "prior-output.txt, decision-schema.json, and the updated "
                "format-validation.json in the isolated current directory. Correct every "
                "reported missing or unexpected field, including every path in "
                "schema_shape_errors, by copying the required field names exactly; do not "
                "change the substantive decision. Return one "
                "schema-matching JSON object with no explanation or Markdown. The first "
                "non-whitespace character of your entire response must be { and the last "
                "must be }. Set reviewer_role=primary_deepseek and "
                f"reviewer_model={DEEPSEEK_MODEL_IDENTITY}.",
            )
            prior_stdout = completed.stdout
            validation_error = contract_error
            for attempt_index, format_prompt in enumerate(format_prompts):
                (temp_root / "prior-output.txt").write_text(
                    prior_stdout,
                    encoding="utf-8",
                )
                feedback_path = temp_root / "format-validation.json"
                _json_dump(
                    feedback_path,
                    _format_validation_feedback(
                        prior_stdout,
                        reviewer="deepseek",
                        validation_error=validation_error,
                        packet=packet,
                        role=role,
                        model=model,
                    ),
                )
                retry = subprocess.run(
                    [
                        str(dsh_command),
                        "--profile",
                        "headless",
                        "--patch",
                        str(patch_path),
                        format_prompt,
                    ],
                    cwd=temp_root,
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="strict",
                    check=False,
                    timeout=300,
                )
                retry_key = "format_retry" if attempt_index == 0 else "format_retry_second"
                raw[retry_key] = {
                    "exit_code": retry.returncode,
                    "original_stdout_sha256": sha256_value(prior_stdout),
                    "original_stdout_retained": False,
                    "validation_feedback_sha256": sha256_file(feedback_path),
                    "stderr_sha256": sha256_value(retry.stderr),
                }
                raw["stdout"] = retry.stdout
                if retry.returncode != 0:
                    if raw_output_path is not None:
                        _json_dump(raw_output_path, raw)
                    raise E0GovernanceError(
                        "DeepSeek format-only retry failed"
                    ) from validation_error
                try:
                    decision = _validated_bound_decision_from_stdout(
                        retry.stdout,
                        reviewer="deepseek",
                        packet=packet,
                        role=role,
                        model=model,
                    )
                    contract_error = None
                    break
                except (json.JSONDecodeError, E0GovernanceError) as retry_exc:
                    prior_stdout = retry.stdout
                    validation_error = retry_exc
                    contract_error = retry_exc

        if contract_error is not None:
            prior_stdout = str(raw["stdout"])
            preserved_projection_sha256: str | None = None
            mutable_material_fields: tuple[str, ...] | None = None
            prior_decision: Mapping[str, Any] | None = None
            prior_artifact: str | None = None
            try:
                prior_decision = _validated_decision_from_stdout(
                    prior_stdout,
                    reviewer=reviewer,
                )
            except (json.JSONDecodeError, E0GovernanceError):
                pass
            else:
                prior_artifact = json.dumps(
                    prior_decision,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                mutable_material_fields = _contract_retry_mutable_material_fields(
                    prior_decision,
                    contract_error,
                    expected_packet_uid=str(packet["packet_uid"]),
                    expected_packet_sha256=str(packet["packet_sha256"]),
                    expected_role=role,
                )
                if mutable_material_fields is not None:
                    preserved_projection_sha256 = sha256_value(
                        _contract_retry_locked_projection(
                            prior_decision,
                            mutable_material_fields,
                        )
                    )
            feedback_path = temp_root / "format-validation.json"
            _json_dump(
                feedback_path,
                _format_validation_feedback(
                    prior_stdout,
                    reviewer=reviewer,
                    validation_error=contract_error,
                    packet=packet,
                    role=role,
                    model=model,
                ),
            )
            contract_instruction = (
                "The prior response failed the strict review-decision contract. Perform "
                "one bounded replacement review using only the same frozen packet and "
                "decision schema. Copy packet_uid and packet_sha256 exactly from the "
                "packet, and copy the assigned reviewer_role and reviewer_model exactly "
                "from the instructions. Return a complete schema-valid decision with no "
                "prose, Markdown, external knowledge, or hidden reasoning. The machine "
                "validation feedback is answer-free and may be used only to correct the "
                "contract. It enumerates every detected schema constraint, material field, "
                "and frozen binding field; correct all listed issues in this single "
                "regeneration."
            )
            if preserved_projection_sha256 is not None:
                if mutable_material_fields:
                    contract_instruction += (
                        " Preserve every material field from the parsed prior decision "
                        "except this exact repair allowlist: "
                        + json.dumps(list(mutable_material_fields), separators=(",", ":"))
                        + ". Correct all invalid or missing fields in that allowlist and "
                        "the frozen envelope identity; do not revise any other review "
                        "judgment."
                    )
                else:
                    contract_instruction += (
                        " The prior response parsed successfully and has no detected "
                        "material-contract issue. Preserve every substantive decision field "
                        "exactly; correct only schema_version, packet_uid, packet_sha256, "
                        "reviewer_role, reviewer_model, or non-material unexpected fields."
                    )
            if reviewer == "deepseek":
                if preserved_projection_sha256 is not None:
                    if prior_artifact is None:
                        raise E0GovernanceError("bounded contract retry has no parsed decision")
                    (temp_root / "prior-output.txt").write_text(
                        prior_artifact + "\n",
                        encoding="utf-8",
                    )
                    contract_instruction += (
                        " Read prior-output.txt as the canonical parsed prior decision; it "
                        "contains no provider transport envelope."
                    )
                retry_command = [
                    str(dsh_command),
                    "--profile",
                    "headless",
                    "--patch",
                    str(patch_path),
                    "Read packet.json, decision-schema.json, and format-validation.json "
                    "from the isolated current directory. When prior-output.txt is "
                    "present, use it only for the bounded correction described below. "
                    + contract_instruction,
                ]
                retry_input = None
            else:
                retry_command = [str(claude_command), *_claude_arguments(reviewer)]
                retry_input = (
                    prompt
                    + "\nCONTRACT_RETRY:\n"
                    + contract_instruction
                    + "\nVALIDATION_FEEDBACK:\n"
                    + json.dumps(
                        load_json_strict(feedback_path),
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    + (
                        "\nPRIOR_PARSED_DECISION:\n" + str(prior_artifact)
                        if preserved_projection_sha256 is not None
                        else ""
                    )
                )
            retry = subprocess.run(
                retry_command,
                input=retry_input,
                cwd=temp_root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                check=False,
                timeout=1800,
            )
            raw["contract_retry"] = {
                "exit_code": retry.returncode,
                "original_stdout_sha256": sha256_value(prior_stdout),
                "original_stdout_retained": False,
                "validation_feedback_sha256": sha256_file(feedback_path),
                "preserved_substantive_projection_sha256": preserved_projection_sha256,
                "mutable_material_fields": (
                    list(mutable_material_fields) if mutable_material_fields is not None else None
                ),
                "stderr_sha256": sha256_value(retry.stderr),
            }
            raw["stdout"] = retry.stdout
            if retry.returncode != 0:
                if raw_output_path is not None:
                    _json_dump(raw_output_path, raw)
                raise E0GovernanceError(
                    f"{reviewer} contract regeneration retry failed"
                ) from contract_error
            try:
                decision = _validated_bound_decision_from_stdout(
                    retry.stdout,
                    reviewer=reviewer,
                    packet=packet,
                    role=role,
                    model=model,
                )
            except (json.JSONDecodeError, E0GovernanceError) as retry_exc:
                raw["contract_retry"]["validation_failure_code"] = (
                    _contract_validation_failure_code(retry_exc)
                )
                raw["contract_retry"]["validation_error_sha256"] = sha256_value(str(retry_exc))
                if raw_output_path is not None:
                    _json_dump(raw_output_path, raw)
                raise E0GovernanceError(
                    f"{reviewer} contract regeneration did not produce a valid decision"
                ) from retry_exc
            if (
                preserved_projection_sha256 is not None
                and mutable_material_fields is not None
                and sha256_value(
                    _contract_retry_locked_projection(decision, mutable_material_fields)
                )
                != preserved_projection_sha256
            ):
                if raw_output_path is not None:
                    _json_dump(raw_output_path, raw)
                raise E0GovernanceError(
                    f"{reviewer} contract regeneration changed substantive fields"
                )

        if decision is None:
            raise E0GovernanceError(f"{reviewer} did not produce a review decision")

        try:
            validate_decision_against_packet(
                decision,
                packet,
                require_resolvable_evidence=reviewer == "opus",
            )
        except E0GovernanceError as exc:
            original_stdout = str(raw["stdout"])
            original_projection_sha256 = sha256_value(
                _semantic_retry_substantive_projection(decision)
            )
            semantic_prompt = (
                "The prior decision and its complete packet are embedded below. The prior "
                "decision passed the strict decision "
                "schema but failed deterministic packet grounding. Return one complete "
                "replacement JSON object. You may change only structured_anchors, "
                "evidence_refs, and evidence_refs inside required_evidence_clauses. "
                "Every anchor line span must be contained in a supplied code window for "
                "the same file, and its function must either appear exactly in that "
                "window or equal a function-valued truth_record field. Every evidence "
                "reference must be contained in a supplied code window. Preserve every "
                "other field exactly, including reviewer identity, disposition, contract "
                "kind, taxonomy, predicates, summaries, assumptions, safe-pair content, "
                "and reason codes. Do not add markdown, prose, or external knowledge.\n"
                "PRIOR_DECISION:\n"
                + json.dumps(decision, ensure_ascii=False, sort_keys=True)
                + "\nPACKET:\n"
                + json.dumps(packet, ensure_ascii=False, sort_keys=True)
            )
            if reviewer == "deepseek":
                retry_command = [
                    str(dsh_command),
                    "--profile",
                    "headless",
                    "--patch",
                    str(patch_path),
                    semantic_prompt,
                ]
                retry_input = None
            else:
                retry_command = [str(claude_command), *_claude_arguments(reviewer)]
                retry_input = semantic_prompt
            retry = subprocess.run(
                retry_command,
                input=retry_input,
                cwd=temp_root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                check=False,
                timeout=600,
            )
            raw["semantic_retry"] = {
                "exit_code": retry.returncode,
                "original_stdout_sha256": sha256_value(original_stdout),
                "original_stdout_retained": False,
                "validation_error_sha256": sha256_value(str(exc)),
                "substantive_projection_sha256": original_projection_sha256,
                "stderr_sha256": sha256_value(retry.stderr),
            }
            if retry.returncode != 0:
                if raw_output_path is not None:
                    _json_dump(raw_output_path, raw)
                raise E0GovernanceError(f"{reviewer} grounding-only retry failed") from exc
            raw["stdout"] = retry.stdout
            try:
                decision = _validated_bound_decision_from_stdout(
                    retry.stdout,
                    reviewer=reviewer,
                    packet=packet,
                    role=role,
                    model=model,
                )
            except (json.JSONDecodeError, E0GovernanceError) as semantic_contract_error:
                semantic_contract_resolved = False
                if reviewer == "deepseek":
                    try:
                        _validated_decision_from_stdout(
                            retry.stdout,
                            reviewer=reviewer,
                        )
                    except (json.JSONDecodeError, E0GovernanceError):
                        prior_semantic_stdout = retry.stdout
                        semantic_format_prompts = (
                            "Read prior-output.txt, decision-schema.json, and "
                            "format-validation.json. Reformat the prior grounding "
                            "correction as exactly one complete JSON object. This is a "
                            "transport-only correction: do not perform another review and "
                            "do not change any decision field. Return no prose or Markdown.",
                            "The previous grounding transport formatting attempt still "
                            "failed strict validation. Read prior-output.txt, "
                            "decision-schema.json, and the updated format-validation.json. "
                            "Reformat that prior output as exactly one complete JSON object, "
                            "correcting every reported schema path and frozen binding field. "
                            "This remains transport-only: do not perform another review, do "
                            "not change any material decision field, and return no prose, "
                            "Markdown, or code fence.",
                        )
                        for attempt_index, semantic_format_prompt in enumerate(
                            semantic_format_prompts
                        ):
                            (temp_root / "prior-output.txt").write_text(
                                prior_semantic_stdout,
                                encoding="utf-8",
                            )
                            semantic_format_feedback_path = temp_root / "format-validation.json"
                            _json_dump(
                                semantic_format_feedback_path,
                                _format_validation_feedback(
                                    prior_semantic_stdout,
                                    reviewer=reviewer,
                                    validation_error=semantic_contract_error,
                                    packet=packet,
                                    role=role,
                                    model=model,
                                ),
                            )
                            semantic_format_retry = subprocess.run(
                                [
                                    str(dsh_command),
                                    "--profile",
                                    "headless",
                                    "--patch",
                                    str(patch_path),
                                    semantic_format_prompt,
                                ],
                                cwd=temp_root,
                                env=env,
                                capture_output=True,
                                text=True,
                                encoding="utf-8",
                                errors="strict",
                                check=False,
                                timeout=600,
                            )
                            retry_key = (
                                "semantic_format_retry"
                                if attempt_index == 0
                                else "semantic_format_retry_second"
                            )
                            raw[retry_key] = {
                                "exit_code": semantic_format_retry.returncode,
                                "original_stdout_sha256": sha256_value(prior_semantic_stdout),
                                "original_stdout_retained": False,
                                "validation_feedback_sha256": sha256_file(
                                    semantic_format_feedback_path
                                ),
                                "substantive_projection_sha256": (original_projection_sha256),
                                "stderr_sha256": sha256_value(semantic_format_retry.stderr),
                            }
                            raw["stdout"] = semantic_format_retry.stdout
                            if semantic_format_retry.returncode != 0:
                                if raw_output_path is not None:
                                    _json_dump(raw_output_path, raw)
                                raise E0GovernanceError(
                                    f"{reviewer} grounding format retry failed"
                                ) from semantic_contract_error
                            try:
                                decision = _validated_bound_decision_from_stdout(
                                    semantic_format_retry.stdout,
                                    reviewer=reviewer,
                                    packet=packet,
                                    role=role,
                                    model=model,
                                )
                            except (
                                json.JSONDecodeError,
                                E0GovernanceError,
                            ) as format_retry_exc:
                                prior_semantic_stdout = semantic_format_retry.stdout
                                semantic_contract_error = format_retry_exc
                                continue
                            semantic_contract_resolved = True
                            break
                if semantic_contract_resolved:
                    unbound_semantic_decision = None
                else:
                    try:
                        unbound_semantic_decision = _validated_decision_from_stdout(
                            str(raw["stdout"]),
                            reviewer=reviewer,
                        )
                    except (json.JSONDecodeError, E0GovernanceError):
                        if raw_output_path is not None:
                            _json_dump(raw_output_path, raw)
                        if "semantic_format_retry" in raw:
                            raise E0GovernanceError(
                                f"{reviewer} grounding format retries did not produce "
                                "a valid decision"
                            ) from semantic_contract_error
                        raise semantic_contract_error
                if unbound_semantic_decision is not None:
                    prior_semantic_artifact = str(raw["stdout"])
                    semantic_material_sha256 = sha256_value(
                        _contract_retry_substantive_projection(unbound_semantic_decision)
                    )
                    semantic_feedback_path = temp_root / "format-validation.json"
                    _json_dump(
                        semantic_feedback_path,
                        _format_validation_feedback(
                            prior_semantic_artifact,
                            reviewer=reviewer,
                            validation_error=semantic_contract_error,
                            packet=packet,
                            role=role,
                            model=model,
                        ),
                    )
                    if reviewer == "deepseek":
                        try:
                            rebound_decision, rebound_fields = _rebind_grounding_decision_identity(
                                unbound_semantic_decision,
                                packet,
                                role=role,
                                model=model,
                            )
                        except E0GovernanceError:
                            if raw_output_path is not None:
                                _json_dump(raw_output_path, raw)
                            raise
                        rebound_stdout = json.dumps(
                            rebound_decision,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        raw["semantic_envelope_repair"] = {
                            "schema_version": SEMANTIC_ENVELOPE_REPAIR_SCHEMA_VERSION,
                            "algorithm": "frozen_identity_rebind_v1",
                            "original_stdout_sha256": sha256_value(prior_semantic_artifact),
                            "original_stdout_retained": False,
                            "validation_feedback_sha256": sha256_file(semantic_feedback_path),
                            "rebound_fields": list(rebound_fields),
                            "substantive_projection_sha256": semantic_material_sha256,
                            "rebound_stdout_sha256": sha256_value(rebound_stdout),
                        }
                        raw["stdout"] = rebound_stdout
                        decision = rebound_decision
                    else:
                        semantic_contract_instruction = (
                            "The grounding correction parsed as an object but failed only the "
                            "strict decision envelope contract. Reissue that same correction as "
                            "a complete schema-valid decision. Preserve every material field "
                            "exactly, including anchors and evidence. Correct only "
                            "schema_version, packet_uid, packet_sha256, reviewer_role, or "
                            "reviewer_model by copying their frozen values from the packet and "
                            "instructions. Return no prose, Markdown, external knowledge, or "
                            "hidden reasoning."
                        )
                        semantic_contract_command = [
                            str(claude_command),
                            *_claude_arguments(reviewer),
                        ]
                        semantic_contract_input = (
                            semantic_prompt
                            + "\nSEMANTIC_CONTRACT_RETRY:\n"
                            + semantic_contract_instruction
                            + "\nVALIDATION_FEEDBACK:\n"
                            + json.dumps(
                                load_json_strict(semantic_feedback_path),
                                ensure_ascii=False,
                                sort_keys=True,
                            )
                            + "\nPRIOR_SEMANTIC_RESPONSE:\n"
                            + prior_semantic_artifact
                        )
                        semantic_contract_retry = subprocess.run(
                            semantic_contract_command,
                            input=semantic_contract_input,
                            cwd=temp_root,
                            env=env,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="strict",
                            check=False,
                            timeout=600,
                        )
                        raw["semantic_contract_retry"] = {
                            "exit_code": semantic_contract_retry.returncode,
                            "original_stdout_sha256": sha256_value(prior_semantic_artifact),
                            "original_stdout_retained": False,
                            "validation_feedback_sha256": sha256_file(semantic_feedback_path),
                            "substantive_projection_sha256": semantic_material_sha256,
                            "stderr_sha256": sha256_value(semantic_contract_retry.stderr),
                        }
                        raw["stdout"] = semantic_contract_retry.stdout
                        if semantic_contract_retry.returncode != 0:
                            if raw_output_path is not None:
                                _json_dump(raw_output_path, raw)
                            raise E0GovernanceError(
                                f"{reviewer} grounding contract retry failed"
                            ) from semantic_contract_error
                        try:
                            decision = _validated_bound_decision_from_stdout(
                                semantic_contract_retry.stdout,
                                reviewer=reviewer,
                                packet=packet,
                                role=role,
                                model=model,
                            )
                        except (json.JSONDecodeError, E0GovernanceError) as retry_exc:
                            if raw_output_path is not None:
                                _json_dump(raw_output_path, raw)
                            raise E0GovernanceError(
                                f"{reviewer} grounding contract retry remained invalid"
                            ) from retry_exc
                        if (
                            sha256_value(_contract_retry_substantive_projection(decision))
                            != semantic_material_sha256
                        ):
                            if raw_output_path is not None:
                                _json_dump(raw_output_path, raw)
                            raise E0GovernanceError(
                                f"{reviewer} grounding contract retry changed material fields"
                            )
            if (
                sha256_value(_semantic_retry_substantive_projection(decision))
                != original_projection_sha256
            ):
                if raw_output_path is not None:
                    _json_dump(raw_output_path, raw)
                raise E0GovernanceError(
                    f"{reviewer} grounding-only retry changed substantive fields"
                )
            try:
                validate_decision_against_packet(
                    decision,
                    packet,
                    require_resolvable_evidence=reviewer == "opus",
                )
            except E0GovernanceError:
                if raw_output_path is not None:
                    _json_dump(raw_output_path, raw)
                raise

        if raw_output_path is not None:
            _json_dump(raw_output_path, raw)

    return dict(decision), raw


def _packet_files(path: Path) -> list[Path]:
    files = sorted(path.glob("*.json"))
    if len(files) != 136:
        raise E0GovernanceError(f"E0 requires exactly 136 packets, found {len(files)}")
    return files


def _reviewer_identity(reviewer: str) -> tuple[str, str]:
    if reviewer == "fable":
        return "primary_fable", "claude-fable-5"
    if reviewer == "deepseek":
        return "primary_deepseek", DEEPSEEK_MODEL_IDENTITY
    if reviewer == "opus":
        return "arbiter_opus", "claude-opus-5"
    raise E0GovernanceError(f"unsupported reviewer: {reviewer}")


def _validate_command_identity(values: Any, *, reviewer: str) -> None:
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise E0GovernanceError("review command identity is invalid")
    if reviewer == "deepseek":
        expected_patch_identity = f"<ephemeral-patch-sha256:{_deepseek_patch_sha256()}>"
        if (
            len(values) != 5
            or values[:4] != ["dsh", "--profile", "headless", "--patch"]
            or values[4] != expected_patch_identity
        ):
            raise E0GovernanceError("DeepSeek command identity is invalid")
        return
    if (
        len(values) != 16
        or values[0] not in {"claude", "claude.cmd"}
        or values[1:] != _claude_arguments(reviewer)
    ):
        raise E0GovernanceError("Claude command identity is invalid")


def _validate_existing_primary(
    packet: Mapping[str, Any],
    *,
    reviewer: str,
    decision_path: Path,
    raw_path: Path,
) -> None:
    role, model = _reviewer_identity(reviewer)
    decision = _load_decision(decision_path)
    validate_review_decision(
        decision,
        expected_packet_uid=str(packet["packet_uid"]),
        expected_packet_sha256=str(packet["packet_sha256"]),
        expected_role=role,
    )
    if decision.get("reviewer_model") != model:
        raise E0GovernanceError("existing reviewer model identity mismatch")
    validate_decision_against_packet(
        decision,
        packet,
        require_resolvable_evidence=reviewer == "opus",
    )
    raw = load_json_strict(raw_path)
    if not isinstance(raw, Mapping):
        raise E0GovernanceError("existing raw review envelope must be an object")
    required_raw_fields = {
        "schema_version",
        "reviewer_role",
        "reviewer_model",
        "packet_uid",
        "packet_sha256",
        "input_delivery",
        "command_identity",
        "exit_code",
        "stdout",
        "stderr_sha256",
    }
    raw_fields = set(raw)
    optional_raw_fields = {
        "transport_retry",
        "format_retry",
        "format_retry_second",
        "contract_retry",
        "semantic_retry",
        "semantic_format_retry",
        "semantic_format_retry_second",
        "semantic_envelope_repair",
        "semantic_contract_retry",
    }
    if not required_raw_fields.issubset(raw_fields) or not (
        raw_fields - required_raw_fields
    ).issubset(optional_raw_fields):
        raise E0GovernanceError("existing raw review envelope fields are invalid")
    expected_delivery = "embedded_prompt" if reviewer in {"fable", "opus"} else "isolated_files"
    if (
        raw.get("schema_version") != "zscope.range-v16-review-raw-envelope.v1"
        or raw.get("reviewer_role") != role
        or raw.get("reviewer_model") != model
        or raw.get("packet_uid") != packet["packet_uid"]
        or raw.get("packet_sha256") != packet["packet_sha256"]
        or raw.get("input_delivery") != expected_delivery
        or raw.get("exit_code") != 0
        or not isinstance(raw.get("stdout"), str)
        or not isinstance(raw.get("stderr_sha256"), str)
        or len(raw["stderr_sha256"]) != 64
    ):
        raise E0GovernanceError("existing raw review envelope is invalid")
    _validate_command_identity(raw.get("command_identity"), reviewer=reviewer)
    raw_decision = _validated_decision_from_stdout(
        str(raw["stdout"]),
        reviewer=reviewer,
    )
    if dict(raw_decision) != dict(decision):
        raise E0GovernanceError("existing raw review output does not match decision")
    transport_retry = raw.get("transport_retry")
    if transport_retry is not None:
        if (
            not isinstance(transport_retry, Mapping)
            or set(transport_retry)
            != {
                "initial_exit_code",
                "initial_stdout_sha256",
                "initial_stdout_retained",
                "initial_stderr_sha256",
            }
            or not isinstance(transport_retry.get("initial_exit_code"), int)
            or isinstance(transport_retry.get("initial_exit_code"), bool)
            or transport_retry.get("initial_exit_code") == 0
            or transport_retry.get("initial_stdout_retained") is not False
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", str(transport_retry.get(field) or ""))
                for field in ("initial_stdout_sha256", "initial_stderr_sha256")
            )
        ):
            raise E0GovernanceError("existing transport retry envelope is invalid")
    if raw.get("format_retry_second") is not None and raw.get("format_retry") is None:
        raise E0GovernanceError("existing second format retry lacks the first retry")
    for retry_name in ("format_retry", "format_retry_second"):
        retry = raw.get(retry_name)
        if retry is None:
            continue
        retry_fields = {
            "exit_code",
            "original_stdout_sha256",
            "original_stdout_retained",
            "stderr_sha256",
        }
        retry_fields_with_feedback = retry_fields | {"validation_feedback_sha256"}
        if (
            reviewer != "deepseek"
            or not isinstance(retry, Mapping)
            or frozenset(retry)
            not in {frozenset(retry_fields), frozenset(retry_fields_with_feedback)}
            or retry.get("exit_code") != 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(retry.get("original_stdout_sha256") or ""))
            or retry.get("original_stdout_retained") is not False
            or (
                "validation_feedback_sha256" in retry
                and not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(retry.get("validation_feedback_sha256") or ""),
                )
            )
            or not isinstance(retry.get("stderr_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(retry["stderr_sha256"]))
        ):
            raise E0GovernanceError("existing format retry envelope is invalid")
    contract_retry = raw.get("contract_retry")
    if contract_retry is not None:
        preserved_projection_sha256 = (
            contract_retry.get("preserved_substantive_projection_sha256")
            if isinstance(contract_retry, Mapping)
            else None
        )
        legacy_contract_fields = {
            "exit_code",
            "original_stdout_sha256",
            "original_stdout_retained",
            "validation_feedback_sha256",
            "preserved_substantive_projection_sha256",
            "stderr_sha256",
        }
        contract_fields = set(contract_retry) if isinstance(contract_retry, Mapping) else set()
        mutable_material_fields = (
            contract_retry.get("mutable_material_fields")
            if isinstance(contract_retry, Mapping) and "mutable_material_fields" in contract_retry
            else None
        )
        mutable_fields_valid = mutable_material_fields is None or (
            isinstance(mutable_material_fields, list)
            and all(isinstance(field, str) for field in mutable_material_fields)
            and mutable_material_fields == sorted(set(mutable_material_fields))
            and set(mutable_material_fields).issubset(MATERIAL_DECISION_FIELDS)
        )
        if (
            not isinstance(contract_retry, Mapping)
            or frozenset(contract_fields)
            not in {
                frozenset(legacy_contract_fields),
                frozenset(legacy_contract_fields | {"mutable_material_fields"}),
            }
            or contract_retry.get("exit_code") != 0
            or contract_retry.get("original_stdout_retained") is not False
            or not mutable_fields_valid
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", str(contract_retry.get(field) or ""))
                for field in (
                    "original_stdout_sha256",
                    "validation_feedback_sha256",
                    "stderr_sha256",
                )
            )
            or (
                preserved_projection_sha256 is not None
                and not re.fullmatch(r"[0-9a-f]{64}", str(preserved_projection_sha256))
            )
            or (
                preserved_projection_sha256 is not None
                and (
                    sha256_value(
                        _contract_retry_locked_projection(
                            decision,
                            mutable_material_fields,
                        )
                    )
                    if "mutable_material_fields" in contract_fields
                    and isinstance(mutable_material_fields, list)
                    else sha256_value(_contract_retry_substantive_projection(decision))
                )
                != preserved_projection_sha256
            )
            or (
                "mutable_material_fields" in contract_fields
                and (mutable_material_fields is None) != (preserved_projection_sha256 is None)
            )
        ):
            raise E0GovernanceError("existing contract retry envelope is invalid")
    semantic_retry = raw.get("semantic_retry")
    if semantic_retry is not None:
        if (
            not isinstance(semantic_retry, Mapping)
            or set(semantic_retry)
            != {
                "exit_code",
                "original_stdout_sha256",
                "original_stdout_retained",
                "validation_error_sha256",
                "substantive_projection_sha256",
                "stderr_sha256",
            }
            or semantic_retry.get("exit_code") != 0
            or semantic_retry.get("original_stdout_retained") is not False
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", str(semantic_retry.get(field) or ""))
                for field in (
                    "original_stdout_sha256",
                    "validation_error_sha256",
                    "substantive_projection_sha256",
                    "stderr_sha256",
                )
            )
            or sha256_value(_semantic_retry_substantive_projection(decision))
            != semantic_retry.get("substantive_projection_sha256")
        ):
            raise E0GovernanceError("existing semantic retry envelope is invalid")
    if (
        raw.get("semantic_format_retry_second") is not None
        and raw.get("semantic_format_retry") is None
    ):
        raise E0GovernanceError("existing second semantic format retry lacks the first retry")
    for retry_name in ("semantic_format_retry", "semantic_format_retry_second"):
        semantic_format_retry = raw.get(retry_name)
        if semantic_format_retry is None:
            continue
        if (
            reviewer != "deepseek"
            or semantic_retry is None
            or not isinstance(semantic_format_retry, Mapping)
            or set(semantic_format_retry)
            != {
                "exit_code",
                "original_stdout_sha256",
                "original_stdout_retained",
                "validation_feedback_sha256",
                "substantive_projection_sha256",
                "stderr_sha256",
            }
            or semantic_format_retry.get("exit_code") != 0
            or semantic_format_retry.get("original_stdout_retained") is not False
            or any(
                not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(semantic_format_retry.get(field) or ""),
                )
                for field in (
                    "original_stdout_sha256",
                    "validation_feedback_sha256",
                    "substantive_projection_sha256",
                    "stderr_sha256",
                )
            )
            or sha256_value(_semantic_retry_substantive_projection(decision))
            != semantic_format_retry.get("substantive_projection_sha256")
        ):
            raise E0GovernanceError("existing semantic format retry envelope is invalid")
    semantic_envelope_repair = raw.get("semantic_envelope_repair")
    if semantic_envelope_repair is not None:
        rebound_fields = (
            semantic_envelope_repair.get("rebound_fields")
            if isinstance(semantic_envelope_repair, Mapping)
            else None
        )
        if (
            reviewer != "deepseek"
            or semantic_retry is None
            or raw.get("semantic_contract_retry") is not None
            or not isinstance(semantic_envelope_repair, Mapping)
            or set(semantic_envelope_repair)
            != {
                "schema_version",
                "algorithm",
                "original_stdout_sha256",
                "original_stdout_retained",
                "validation_feedback_sha256",
                "rebound_fields",
                "substantive_projection_sha256",
                "rebound_stdout_sha256",
            }
            or semantic_envelope_repair.get("schema_version")
            != SEMANTIC_ENVELOPE_REPAIR_SCHEMA_VERSION
            or semantic_envelope_repair.get("algorithm") != "frozen_identity_rebind_v1"
            or semantic_envelope_repair.get("original_stdout_retained") is not False
            or not isinstance(rebound_fields, list)
            or not rebound_fields
            or rebound_fields != sorted(set(rebound_fields))
            or not set(rebound_fields).issubset(FROZEN_DECISION_BINDING_FIELDS)
            or any(
                not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(semantic_envelope_repair.get(field) or ""),
                )
                for field in (
                    "original_stdout_sha256",
                    "validation_feedback_sha256",
                    "substantive_projection_sha256",
                    "rebound_stdout_sha256",
                )
            )
            or sha256_value(_contract_retry_substantive_projection(decision))
            != semantic_envelope_repair.get("substantive_projection_sha256")
            or sha256_value(str(raw["stdout"]))
            != semantic_envelope_repair.get("rebound_stdout_sha256")
        ):
            raise E0GovernanceError("existing semantic envelope repair is invalid")
    semantic_contract_retry = raw.get("semantic_contract_retry")
    if semantic_contract_retry is not None:
        if (
            semantic_retry is None
            or not isinstance(semantic_contract_retry, Mapping)
            or set(semantic_contract_retry)
            != {
                "exit_code",
                "original_stdout_sha256",
                "original_stdout_retained",
                "validation_feedback_sha256",
                "substantive_projection_sha256",
                "stderr_sha256",
            }
            or semantic_contract_retry.get("exit_code") != 0
            or semantic_contract_retry.get("original_stdout_retained") is not False
            or any(
                not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(semantic_contract_retry.get(field) or ""),
                )
                for field in (
                    "original_stdout_sha256",
                    "validation_feedback_sha256",
                    "substantive_projection_sha256",
                    "stderr_sha256",
                )
            )
            or sha256_value(_contract_retry_substantive_projection(decision))
            != semantic_contract_retry.get("substantive_projection_sha256")
        ):
            raise E0GovernanceError("existing semantic contract retry envelope is invalid")


def _run_primary_packet(
    packet: Mapping[str, Any],
    *,
    reviewer: str,
    output: Path,
    resume: bool,
) -> dict[str, Any]:
    truth_id = _packet_id(packet)
    decision_path = output / "decisions" / f"{truth_id}.json"
    raw_path = output / "raw" / f"{truth_id}.json"
    if decision_path.exists() or raw_path.exists():
        if not resume or not decision_path.is_file() or not raw_path.is_file():
            raise E0GovernanceError(f"incomplete or unexpected existing review: {truth_id}")
        _validate_existing_primary(
            packet,
            reviewer=reviewer,
            decision_path=decision_path,
            raw_path=raw_path,
        )
        status = "reused"
    else:
        try:
            decision, raw = _run_model(
                packet,
                reviewer=reviewer,
                raw_output_path=raw_path,
            )
        except Exception as exc:
            _json_dump(
                output / "failures" / f"{truth_id}.json",
                _primary_failure_marker(
                    packet,
                    reviewer=reviewer,
                    exc=exc,
                    decision_path=decision_path,
                    raw_path=raw_path,
                ),
            )
            raise E0GovernanceError(f"{reviewer} review failed for {truth_id}: {exc}") from exc
        _json_dump(decision_path, decision)
        _json_dump(raw_path, raw)
        status = "reviewed"
    return {
        "truth_id": truth_id,
        "packet_sha256": packet["packet_sha256"],
        "decision_file_sha256": sha256_file(decision_path),
        "raw_file_sha256": sha256_file(raw_path),
        "status": status,
    }


_PRIMARY_FAILURE_CODES = {
    "reviewer_process_nonzero",
    "format_retry_process_nonzero",
    "format_retry_validation_failure",
    "contract_retry_process_nonzero",
    "contract_retry_validation_failure",
    "contract_retry_substantive_change",
    "grounding_retry_process_nonzero",
    "grounding_retry_substantive_change",
    "grounding_format_retry_process_nonzero",
    "grounding_format_retry_validation_failure",
    "grounding_contract_retry_process_nonzero",
    "grounding_contract_retry_validation_failure",
    "grounding_contract_retry_substantive_change",
    "grounding_validation_failure",
    "governance_validation_failure",
}


def _primary_failure_code(message: str) -> str:
    lowered = message.lower()
    if "reviewer failed for" in lowered and "stderr_sha256=" in lowered:
        return "reviewer_process_nonzero"
    if "grounding format retry failed" in lowered:
        return "grounding_format_retry_process_nonzero"
    if "grounding format retries did not produce" in lowered:
        return "grounding_format_retry_validation_failure"
    if "format-only retry failed" in lowered:
        return "format_retry_process_nonzero"
    if "format retries did not produce" in lowered:
        return "format_retry_validation_failure"
    if "contract regeneration retry failed" in lowered:
        return "contract_retry_process_nonzero"
    if "contract regeneration did not produce" in lowered:
        return "contract_retry_validation_failure"
    if "contract regeneration changed substantive fields" in lowered:
        return "contract_retry_substantive_change"
    if "grounding contract retry failed" in lowered:
        return "grounding_contract_retry_process_nonzero"
    if "grounding contract retry remained invalid" in lowered:
        return "grounding_contract_retry_validation_failure"
    if "grounding contract retry changed material fields" in lowered:
        return "grounding_contract_retry_substantive_change"
    if "grounding-only retry failed" in lowered:
        return "grounding_retry_process_nonzero"
    if "grounding-only retry changed substantive fields" in lowered:
        return "grounding_retry_substantive_change"
    if "grounding" in lowered or "outside the supplied windows" in lowered:
        return "grounding_validation_failure"
    return "governance_validation_failure"


def _primary_failure_marker(
    packet: Mapping[str, Any],
    *,
    reviewer: str,
    exc: Exception,
    decision_path: Path,
    raw_path: Path,
) -> dict[str, Any]:
    message = str(exc)
    stderr_match = re.search(r"stderr_sha256=([0-9a-f]{64})", message)
    marker: dict[str, Any] = {
        "schema_version": PRIMARY_FAILURE_SCHEMA_VERSION,
        "reviewer": reviewer,
        "packet_uid": packet["packet_uid"],
        "packet_sha256": packet["packet_sha256"],
        "failure_code": _primary_failure_code(message),
        "error_sha256": sha256_value(message),
        "stderr_sha256": stderr_match.group(1) if stderr_match else None,
        "decision_file_sha256": sha256_file(decision_path) if decision_path.is_file() else None,
        "raw_file_sha256": sha256_file(raw_path) if raw_path.is_file() else None,
        "answer_material_present": False,
    }
    marker["content_sha256"] = _checkpoint_manifest_content_sha256(marker)
    return marker


def _validate_primary_failure_marker(
    marker: Any,
    *,
    reviewer: str,
    packet_by_uid: Mapping[str, Mapping[str, Any]],
) -> None:
    required_fields = {
        "schema_version",
        "reviewer",
        "packet_uid",
        "packet_sha256",
        "failure_code",
        "error_sha256",
        "stderr_sha256",
        "decision_file_sha256",
        "raw_file_sha256",
        "answer_material_present",
        "content_sha256",
    }
    if not isinstance(marker, Mapping) or set(marker) != required_fields:
        raise E0GovernanceError("primary failure marker fields are invalid")
    packet = packet_by_uid.get(str(marker.get("packet_uid") or ""))
    optional_hashes = (
        marker.get("stderr_sha256"),
        marker.get("decision_file_sha256"),
        marker.get("raw_file_sha256"),
    )
    if (
        marker.get("schema_version") != PRIMARY_FAILURE_SCHEMA_VERSION
        or marker.get("reviewer") != reviewer
        or packet is None
        or marker.get("packet_sha256") != packet["packet_sha256"]
        or marker.get("failure_code") not in _PRIMARY_FAILURE_CODES
        or not re.fullmatch(r"[0-9a-f]{64}", str(marker.get("error_sha256") or ""))
        or any(
            value is not None and not re.fullmatch(r"[0-9a-f]{64}", str(value))
            for value in optional_hashes
        )
        or marker.get("answer_material_present") is not False
        or marker.get("content_sha256") != _checkpoint_manifest_content_sha256(marker)
    ):
        raise E0GovernanceError("primary failure marker is invalid")


def _checkpoint_raw_signals(path: Path) -> dict[str, Any]:
    """Return answer-free retry/process signals without retaining reviewer output."""

    try:
        raw = load_json_strict(path)
    except (E0GovernanceError, OSError, json.JSONDecodeError):
        return {"raw_envelope_status": "unreadable", "retry_stages": []}
    if not isinstance(raw, Mapping):
        return {"raw_envelope_status": "invalid_type", "retry_stages": []}
    retry_stages: list[dict[str, Any]] = []
    for name in (
        "transport_retry",
        "format_retry",
        "format_retry_second",
        "contract_retry",
        "semantic_retry",
        "semantic_format_retry",
        "semantic_format_retry_second",
        "semantic_contract_retry",
    ):
        value = raw.get(name)
        if not isinstance(value, Mapping):
            continue
        exit_field = "initial_exit_code" if name == "transport_retry" else "exit_code"
        exit_code = value.get(exit_field)
        stage = {
            "stage": name,
            "exit_code": (
                exit_code
                if isinstance(exit_code, int) and not isinstance(exit_code, bool)
                else None
            ),
        }
        failure_code = value.get("validation_failure_code")
        failure_hash = value.get("validation_error_sha256")
        if isinstance(failure_code, str) and failure_code in {
            "json_artifact_invalid",
            "hidden_reasoning_forbidden",
            "decision_binding_invalid",
            "decision_contract_invalid",
        }:
            stage["validation_failure_code"] = failure_code
        if isinstance(failure_hash, str) and re.fullmatch(r"[0-9a-f]{64}", failure_hash):
            stage["validation_error_sha256"] = failure_hash
        retry_stages.append(stage)
    top_level_exit_code = raw.get("exit_code")
    return {
        "raw_envelope_status": "parsed_object",
        "top_level_exit_code": (
            top_level_exit_code
            if isinstance(top_level_exit_code, int) and not isinstance(top_level_exit_code, bool)
            else None
        ),
        "retry_stages": retry_stages,
    }


def _checkpoint_manifest_content_sha256(manifest: Mapping[str, Any]) -> str:
    unsigned = dict(manifest)
    unsigned.pop("content_sha256", None)
    return sha256_value(unsigned)


def build_primary_checkpoint(args: argparse.Namespace) -> int:
    """Copy only strictly verified pairs into a non-formal resume checkpoint."""

    if os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") != "sealed-benchmark":
        raise E0GovernanceError("primary checkpoint requires sealed-benchmark environment")
    if not re.fullmatch(r"[0-9a-f]{40}", str(args.packet_source_sha)):
        raise E0GovernanceError("primary checkpoint packet source SHA is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(args.retained_source_sha)):
        raise E0GovernanceError("primary checkpoint retained source SHA is invalid")
    if not str(args.workflow_run_id).isdigit():
        raise E0GovernanceError("primary checkpoint workflow run ID is invalid")

    retained = args.retained_dir.resolve()
    retained_decisions = retained / "decisions"
    retained_raw = retained / "raw"
    if not retained_decisions.is_dir() or not retained_raw.is_dir():
        raise E0GovernanceError("retained primary review directories are unavailable")
    output = args.output_dir.resolve()
    if output.exists():
        raise E0GovernanceError(f"checkpoint output already exists: {output}")
    output_decisions = output / "decisions"
    output_raw = output / "raw"
    output_decisions.mkdir(parents=True)
    output_raw.mkdir()

    packets: list[Mapping[str, Any]] = []
    for path in _packet_files(args.packet_dir.resolve()):
        packet = load_json_strict(path)
        if not isinstance(packet, Mapping):
            raise E0GovernanceError(f"packet must be an object: {path}")
        validate_review_packet(packet)
        packets.append(packet)
    packet_by_uid = {str(packet["packet_uid"]): packet for packet in packets}
    failure_records: list[dict[str, Any]] = []
    retained_failures = retained / "failures"
    if retained_failures.exists() and not retained_failures.is_dir():
        raise E0GovernanceError("retained primary failure path is invalid")
    if retained_failures.is_dir():
        for failure_path in sorted(retained_failures.glob("*.json")):
            marker = load_json_strict(failure_path)
            _validate_primary_failure_marker(
                marker,
                reviewer=args.reviewer,
                packet_by_uid=packet_by_uid,
            )
            failure_records.append(dict(marker))
        expected_failure_names = {
            f"{_packet_id(packet_by_uid[str(marker['packet_uid'])])}.json"
            for marker in failure_records
        }
        if {path.name for path in retained_failures.glob("*.json")} != expected_failure_names:
            raise E0GovernanceError("retained primary failure marker name is invalid")

    verified_records: list[dict[str, Any]] = []
    invalid_records: list[dict[str, Any]] = []
    incomplete_records: list[dict[str, Any]] = []
    retained_bindings: list[dict[str, Any]] = []
    unverified_ids: list[str] = []
    for packet in packets:
        truth_id = _packet_id(packet)
        decision_path = retained_decisions / f"{truth_id}.json"
        raw_path = retained_raw / f"{truth_id}.json"
        decision_present = decision_path.is_file()
        raw_present = raw_path.is_file()
        retained_bindings.append(
            {
                "truth_id": truth_id,
                "decision_sha256": sha256_file(decision_path) if decision_present else None,
                "raw_sha256": sha256_file(raw_path) if raw_present else None,
                "failure_sha256": (
                    sha256_file(retained_failures / f"{truth_id}.json")
                    if (retained_failures / f"{truth_id}.json").is_file()
                    else None
                ),
            }
        )
        if decision_present and raw_present:
            try:
                _validate_existing_primary(
                    packet,
                    reviewer=args.reviewer,
                    decision_path=decision_path,
                    raw_path=raw_path,
                )
            except (E0GovernanceError, OSError, json.JSONDecodeError) as exc:
                invalid_records.append(
                    {"truth_id": truth_id, "error_sha256": sha256_value(str(exc))}
                )
                unverified_ids.append(truth_id)
                continue
            shutil.copy2(decision_path, output_decisions / decision_path.name)
            shutil.copy2(raw_path, output_raw / raw_path.name)
            verified_records.append(
                {
                    "truth_id": truth_id,
                    "packet_sha256": packet["packet_sha256"],
                    "decision_file_sha256": sha256_file(decision_path),
                    "raw_file_sha256": sha256_file(raw_path),
                }
            )
            continue
        if decision_present or raw_present:
            record: dict[str, Any] = {
                "truth_id": truth_id,
                "present_files": [
                    name
                    for name, present in (
                        ("decision", decision_present),
                        ("raw", raw_present),
                    )
                    if present
                ],
            }
            if raw_present:
                record["raw_signals"] = _checkpoint_raw_signals(raw_path)
            incomplete_records.append(record)
        unverified_ids.append(truth_id)

    missing_pair_count = (
        len(packets) - len(verified_records) - len(invalid_records) - len(incomplete_records)
    )
    if getattr(args, "require_complete", False) and (
        len(verified_records) != len(packets)
        or invalid_records
        or incomplete_records
        or missing_pair_count
        or failure_records
        or unverified_ids
    ):
        raise E0GovernanceError("retained primary artifact is not a complete verified review")
    manifest: dict[str, Any] = {
        "schema_version": PRIMARY_CHECKPOINT_SCHEMA_VERSION,
        "reviewer": args.reviewer,
        "packet_source_sha": str(args.packet_source_sha),
        "retained_source_sha": str(args.retained_source_sha),
        "workflow_run_id": str(args.workflow_run_id),
        "environment": "sealed-benchmark",
        "record_count": len(packets),
        "verified_record_count": len(verified_records),
        "invalid_pair_count": len(invalid_records),
        "incomplete_pair_count": len(incomplete_records),
        "missing_pair_count": missing_pair_count,
        "failure_record_count": len(failure_records),
        "first_unverified_batch_ids": unverified_ids[: args.workers],
        "failure_records": failure_records,
        "invalid_records": invalid_records,
        "incomplete_records": incomplete_records,
        "verified_records": verified_records,
        "retained_input_sha256": sha256_value(retained_bindings),
        "checkpoint_contains_review_material": True,
        "diagnostic_answer_material_present": False,
        "formal_evidence": False,
        "requires_resume_revalidation": True,
    }
    manifest["content_sha256"] = _checkpoint_manifest_content_sha256(manifest)
    _json_dump(output / "checkpoint-manifest.json", manifest)
    return 0


def _validate_primary_checkpoint(
    root: Path,
    *,
    reviewer: str,
    packet_source_sha: str,
    packets: Sequence[Mapping[str, Any]],
) -> None:
    manifest_path = root / "checkpoint-manifest.json"
    manifest = load_json_strict(manifest_path)
    required_fields = {
        "schema_version",
        "reviewer",
        "packet_source_sha",
        "retained_source_sha",
        "workflow_run_id",
        "environment",
        "record_count",
        "verified_record_count",
        "invalid_pair_count",
        "incomplete_pair_count",
        "missing_pair_count",
        "failure_record_count",
        "first_unverified_batch_ids",
        "failure_records",
        "invalid_records",
        "incomplete_records",
        "verified_records",
        "retained_input_sha256",
        "checkpoint_contains_review_material",
        "diagnostic_answer_material_present",
        "formal_evidence",
        "requires_resume_revalidation",
        "content_sha256",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != required_fields:
        raise E0GovernanceError("primary checkpoint manifest fields are invalid")
    if (
        manifest.get("schema_version") != PRIMARY_CHECKPOINT_SCHEMA_VERSION
        or manifest.get("reviewer") != reviewer
        or manifest.get("packet_source_sha") != packet_source_sha
        or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("retained_source_sha") or ""))
        or not str(manifest.get("workflow_run_id") or "").isdigit()
        or manifest.get("environment") != "sealed-benchmark"
        or manifest.get("record_count") != len(packets)
        or manifest.get("checkpoint_contains_review_material") is not True
        or manifest.get("diagnostic_answer_material_present") is not False
        or manifest.get("formal_evidence") is not False
        or manifest.get("requires_resume_revalidation") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("retained_input_sha256") or ""))
        or manifest.get("content_sha256") != _checkpoint_manifest_content_sha256(manifest)
    ):
        raise E0GovernanceError("primary checkpoint manifest is invalid")
    count_fields = (
        "verified_record_count",
        "invalid_pair_count",
        "incomplete_pair_count",
        "missing_pair_count",
    )
    if any(
        not isinstance(manifest.get(field), int)
        or isinstance(manifest.get(field), bool)
        or manifest.get(field, -1) < 0
        for field in count_fields
    ) or sum(int(manifest[field]) for field in count_fields) != len(packets):
        raise E0GovernanceError("primary checkpoint counts are invalid")
    if not isinstance(manifest.get("invalid_records"), list) or len(
        manifest["invalid_records"]
    ) != manifest.get("invalid_pair_count"):
        raise E0GovernanceError("primary checkpoint invalid-pair records are invalid")
    if not isinstance(manifest.get("incomplete_records"), list) or len(
        manifest["incomplete_records"]
    ) != manifest.get("incomplete_pair_count"):
        raise E0GovernanceError("primary checkpoint incomplete-pair records are invalid")
    failure_records = manifest.get("failure_records")
    if (
        not isinstance(manifest.get("failure_record_count"), int)
        or isinstance(manifest.get("failure_record_count"), bool)
        or manifest.get("failure_record_count", -1) < 0
        or not isinstance(failure_records, list)
        or len(failure_records) != manifest.get("failure_record_count")
    ):
        raise E0GovernanceError("primary checkpoint failure records are invalid")
    if not isinstance(manifest.get("first_unverified_batch_ids"), list) or any(
        not isinstance(value, str) for value in manifest["first_unverified_batch_ids"]
    ):
        raise E0GovernanceError("primary checkpoint unverified batch is invalid")

    packet_by_id = {_packet_id(packet): packet for packet in packets}
    packet_by_uid = {str(packet["packet_uid"]): packet for packet in packets}
    failure_uids: set[str] = set()
    for marker in failure_records:
        _validate_primary_failure_marker(
            marker,
            reviewer=reviewer,
            packet_by_uid=packet_by_uid,
        )
        packet_uid = str(marker["packet_uid"])
        if packet_uid in failure_uids:
            raise E0GovernanceError("primary checkpoint failure record is duplicated")
        failure_uids.add(packet_uid)
    records = manifest.get("verified_records")
    if not isinstance(records, list) or len(records) != manifest.get("verified_record_count"):
        raise E0GovernanceError("primary checkpoint verified records are invalid")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping) or set(record) != {
            "truth_id",
            "packet_sha256",
            "decision_file_sha256",
            "raw_file_sha256",
        }:
            raise E0GovernanceError("primary checkpoint verified record fields are invalid")
        truth_id = str(record.get("truth_id") or "")
        packet = packet_by_id.get(truth_id)
        if packet is None or truth_id in seen:
            raise E0GovernanceError("primary checkpoint verified record identity is invalid")
        seen.add(truth_id)
        decision_path = root / "decisions" / f"{truth_id}.json"
        raw_path = root / "raw" / f"{truth_id}.json"
        if (
            record.get("packet_sha256") != packet["packet_sha256"]
            or not decision_path.is_file()
            or not raw_path.is_file()
            or record.get("decision_file_sha256") != sha256_file(decision_path)
            or record.get("raw_file_sha256") != sha256_file(raw_path)
        ):
            raise E0GovernanceError("primary checkpoint verified record hash is invalid")
        _validate_existing_primary(
            packet,
            reviewer=reviewer,
            decision_path=decision_path,
            raw_path=raw_path,
        )
    expected_names = {f"{truth_id}.json" for truth_id in seen}
    if {path.name for path in (root / "decisions").glob("*.json")} != expected_names or {
        path.name for path in (root / "raw").glob("*.json")
    } != expected_names:
        raise E0GovernanceError("primary checkpoint contains unbound review files")


def run_primary(args: argparse.Namespace) -> int:
    output = args.output_dir.resolve()
    if output.exists() and not args.resume:
        raise E0GovernanceError(f"output already exists: {output}")
    (output / "decisions").mkdir(parents=True, exist_ok=args.resume)
    (output / "raw").mkdir(exist_ok=args.resume)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        raise E0GovernanceError("primary review is already complete")
    seen: set[str] = set()
    packets: list[Mapping[str, Any]] = []
    for path in _packet_files(args.packet_dir.resolve()):
        packet = load_json_strict(path)
        if not isinstance(packet, Mapping):
            raise E0GovernanceError(f"packet must be an object: {path}")
        validate_review_packet(packet)
        truth_id = _packet_id(packet)
        if truth_id in seen:
            raise E0GovernanceError(f"duplicate truth ID: {truth_id}")
        seen.add(truth_id)
        packets.append(packet)
    checkpoint_source_sha = getattr(args, "checkpoint_source_sha", None)
    if checkpoint_source_sha is not None:
        if not args.resume:
            raise E0GovernanceError("primary checkpoint validation requires resume mode")
        _validate_primary_checkpoint(
            output,
            reviewer=args.reviewer,
            packet_source_sha=str(checkpoint_source_sha),
            packets=packets,
        )
        (output / "checkpoint-manifest.json").unlink()
    records: list[dict[str, Any]] = []
    completed_count = 0
    for offset in range(0, len(packets), args.workers):
        batch = packets[offset : offset + args.workers]
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _run_primary_packet,
                    packet,
                    reviewer=args.reviewer,
                    output=output,
                    resume=args.resume,
                ): _packet_id(packet)
                for packet in batch
            }
            for future in as_completed(futures):
                truth_id = futures[future]
                records.append(future.result())
                completed_count += 1
                print(
                    f"{args.reviewer}: {completed_count}/{len(packets)} complete ({truth_id})",
                    flush=True,
                )
    records.sort(key=lambda value: str(value["truth_id"]))
    _json_dump(
        manifest_path,
        {
            "schema_version": "zscope.range-v16-primary-review-run.v1",
            "reviewer": args.reviewer,
            "record_count": len(seen),
            "records": records,
            "packet_catalog_sha256": sha256_value(
                [
                    {
                        "truth_id": item["truth_id"],
                        "packet_sha256": item["packet_sha256"],
                    }
                    for item in records
                ]
            ),
        },
    )
    return 0


def _load_decision(path: Path) -> Mapping[str, Any]:
    value = load_json_strict(path)
    if not isinstance(value, Mapping):
        raise E0GovernanceError(f"review decision must be an object: {path}")
    return value


def _primary_decisions(
    packet: Mapping[str, Any],
    *,
    truth_id: str,
    fable_dir: Path,
    deepseek_dir: Path,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    for reviewer, root in (("fable", fable_dir), ("deepseek", deepseek_dir)):
        _validate_existing_primary(
            packet,
            reviewer=reviewer,
            decision_path=root / "decisions" / f"{truth_id}.json",
            raw_path=root / "raw" / f"{truth_id}.json",
        )
    return (
        _load_decision(fable_dir / "decisions" / f"{truth_id}.json"),
        _load_decision(deepseek_dir / "decisions" / f"{truth_id}.json"),
    )


def _run_arbitration_packet(
    packet: Mapping[str, Any],
    *,
    truth_id: str,
    primary_decisions: Sequence[Mapping[str, Any]],
    output: Path,
    resume: bool,
) -> dict[str, Any]:
    decision_path = output / "decisions" / f"{truth_id}.json"
    raw_path = output / "raw" / f"{truth_id}.json"
    if decision_path.exists() or raw_path.exists():
        if not resume or not decision_path.is_file() or not raw_path.is_file():
            raise E0GovernanceError(f"incomplete or unexpected Opus review: {truth_id}")
        _validate_existing_primary(
            packet,
            reviewer="opus",
            decision_path=decision_path,
            raw_path=raw_path,
        )
        status = "reused"
    else:
        try:
            decision, raw = _run_model(
                packet,
                reviewer="opus",
                primary_decisions=primary_decisions,
                raw_output_path=raw_path,
            )
        except Exception as exc:
            _json_dump(
                output / "failures" / f"{truth_id}.json",
                _primary_failure_marker(
                    packet,
                    reviewer="opus",
                    exc=exc,
                    decision_path=decision_path,
                    raw_path=raw_path,
                ),
            )
            raise E0GovernanceError(f"opus review failed for {truth_id}: {exc}") from exc
        _json_dump(decision_path, decision)
        _json_dump(raw_path, raw)
        status = "reviewed"
    return {
        "truth_id": truth_id,
        "packet_sha256": packet["packet_sha256"],
        "decision_file_sha256": sha256_file(decision_path),
        "raw_file_sha256": sha256_file(raw_path),
        "status": status,
    }


def _arbitration_shard_for(truth_id: str, shard_count: int) -> int:
    if shard_count < 1 or shard_count > 32:
        raise E0GovernanceError("arbitration shard count is invalid")
    digest = hashlib.sha256(truth_id.encode("utf-8")).hexdigest()
    return int(digest[:16], 16) % shard_count


def _validate_arbitration_shard_identity(shard_index: int, shard_count: int) -> None:
    if shard_count < 1 or shard_count > 32 or shard_index < 0 or shard_index >= shard_count:
        raise E0GovernanceError("arbitration shard identity is invalid")


def _load_arbitration_plan(
    packet_dir: Path,
    *,
    fable_dir: Path,
    deepseek_dir: Path,
) -> tuple[
    list[tuple[Mapping[str, Any], str, tuple[Mapping[str, Any], Mapping[str, Any]]]],
    set[str],
    set[str],
    str,
]:
    """Revalidate both primaries and derive one content-bound arbitration plan."""

    disagreements: set[str] = set()
    evidence_deficits: set[str] = set()
    work: list[tuple[Mapping[str, Any], str, tuple[Mapping[str, Any], Mapping[str, Any]]]] = []
    plan_bindings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in _packet_files(packet_dir):
        packet = load_json_strict(path)
        if not isinstance(packet, Mapping):
            raise E0GovernanceError(f"packet must be an object: {path}")
        validate_review_packet(packet)
        truth_id = _packet_id(packet)
        if truth_id in seen:
            raise E0GovernanceError(f"duplicate truth ID: {truth_id}")
        seen.add(truth_id)
        fable, deepseek = _primary_decisions(
            packet,
            truth_id=truth_id,
            fable_dir=fable_dir,
            deepseek_dir=deepseek_dir,
        )
        disagreement_fields = decision_disagreement_fields(fable, deepseek)
        if disagreement_fields:
            disagreements.add(truth_id)
        evidence_deficit = any(
            decision.get("contract_kind") in {"concrete_trigger", "public_api_contract"}
            and not decision.get("evidence_refs")
            for decision in (fable, deepseek)
        )
        if evidence_deficit:
            evidence_deficits.add(truth_id)
        selected = truth_id in DISPUTED_IDS or bool(disagreement_fields) or evidence_deficit
        plan_bindings.append(
            {
                "truth_id": truth_id,
                "packet_sha256": packet["packet_sha256"],
                "fable_decision_sha256": sha256_file(fable_dir / "decisions" / f"{truth_id}.json"),
                "fable_raw_sha256": sha256_file(fable_dir / "raw" / f"{truth_id}.json"),
                "deepseek_decision_sha256": sha256_file(
                    deepseek_dir / "decisions" / f"{truth_id}.json"
                ),
                "deepseek_raw_sha256": sha256_file(deepseek_dir / "raw" / f"{truth_id}.json"),
                "disagreement_fields": list(disagreement_fields),
                "evidence_deficit": evidence_deficit,
                "mandatory_disputed": truth_id in DISPUTED_IDS,
                "selected": selected,
            }
        )
        if selected:
            work.append((packet, truth_id, (fable, deepseek)))
    return work, disagreements, evidence_deficits, sha256_value(plan_bindings)


def _arbitration_shard_work(
    work: Sequence[tuple[Mapping[str, Any], str, tuple[Mapping[str, Any], Mapping[str, Any]]]],
    *,
    shard_index: int,
    shard_count: int,
) -> list[tuple[Mapping[str, Any], str, tuple[Mapping[str, Any], Mapping[str, Any]]]]:
    _validate_arbitration_shard_identity(shard_index, shard_count)
    return [item for item in work if _arbitration_shard_for(item[1], shard_count) == shard_index]


def _arbitration_checkpoint_required_fields() -> set[str]:
    return {
        "schema_version",
        "reviewer",
        "packet_source_sha",
        "retained_source_sha",
        "workflow_run_id",
        "environment",
        "shard_index",
        "shard_count",
        "plan_record_count",
        "plan_sha256",
        "planned_ids",
        "record_count",
        "verified_record_count",
        "invalid_pair_count",
        "incomplete_pair_count",
        "missing_pair_count",
        "failure_record_count",
        "first_unverified_batch_ids",
        "failure_records",
        "invalid_records",
        "incomplete_records",
        "verified_records",
        "retained_input_sha256",
        "checkpoint_contains_review_material",
        "diagnostic_answer_material_present",
        "formal_evidence",
        "requires_resume_revalidation",
        "content_sha256",
    }


def build_arbitration_checkpoint(args: argparse.Namespace) -> int:
    """Copy only revalidated Opus pairs for one deterministic shard."""

    if os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") != "sealed-benchmark":
        raise E0GovernanceError("arbitration checkpoint requires sealed-benchmark environment")
    if not re.fullmatch(r"[0-9a-f]{40}", str(args.packet_source_sha)):
        raise E0GovernanceError("arbitration checkpoint packet source SHA is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(args.retained_source_sha)):
        raise E0GovernanceError("arbitration checkpoint retained source SHA is invalid")
    if not str(args.workflow_run_id).isdigit():
        raise E0GovernanceError("arbitration checkpoint workflow run ID is invalid")
    _validate_arbitration_shard_identity(args.shard_index, args.shard_count)

    fable_dir = args.fable_dir.resolve(strict=True)
    deepseek_dir = args.deepseek_dir.resolve(strict=True)
    work, _, _, plan_sha256 = _load_arbitration_plan(
        args.packet_dir.resolve(),
        fable_dir=fable_dir,
        deepseek_dir=deepseek_dir,
    )
    shard_work = _arbitration_shard_work(
        work,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
    )
    planned_ids = [truth_id for _, truth_id, _ in shard_work]
    planned_id_set = set(planned_ids)
    packet_by_id = {truth_id: packet for packet, truth_id, _ in shard_work}
    packet_by_uid = {str(packet["packet_uid"]): packet for packet, _, _ in shard_work}

    retained = args.retained_dir.resolve()
    retained_decisions = retained / "decisions"
    retained_raw = retained / "raw"
    if not retained_decisions.is_dir() or not retained_raw.is_dir():
        raise E0GovernanceError("retained arbitration review directories are unavailable")
    for root, label in ((retained_decisions, "decision"), (retained_raw, "raw")):
        extra = {path.stem for path in root.glob("*.json")} - planned_id_set
        if extra:
            raise E0GovernanceError(f"retained arbitration {label} files cross shard boundary")

    output = args.output_dir.resolve()
    if output.exists():
        raise E0GovernanceError(f"checkpoint output already exists: {output}")
    output_decisions = output / "decisions"
    output_raw = output / "raw"
    output_decisions.mkdir(parents=True)
    output_raw.mkdir()

    failure_records: list[dict[str, Any]] = []
    retained_failures = retained / "failures"
    if retained_failures.exists() and not retained_failures.is_dir():
        raise E0GovernanceError("retained arbitration failure path is invalid")
    if retained_failures.is_dir():
        for failure_path in sorted(retained_failures.glob("*.json")):
            marker = load_json_strict(failure_path)
            _validate_primary_failure_marker(
                marker,
                reviewer="opus",
                packet_by_uid=packet_by_uid,
            )
            truth_id = _packet_id(packet_by_uid[str(marker["packet_uid"])])
            if failure_path.name != f"{truth_id}.json":
                raise E0GovernanceError("retained arbitration failure marker name is invalid")
            failure_records.append(dict(marker))

    verified_records: list[dict[str, Any]] = []
    invalid_records: list[dict[str, Any]] = []
    incomplete_records: list[dict[str, Any]] = []
    retained_bindings: list[dict[str, Any]] = []
    unverified_ids: list[str] = []
    for truth_id in planned_ids:
        packet = packet_by_id[truth_id]
        decision_path = retained_decisions / f"{truth_id}.json"
        raw_path = retained_raw / f"{truth_id}.json"
        decision_present = decision_path.is_file()
        raw_present = raw_path.is_file()
        failure_path = retained_failures / f"{truth_id}.json"
        retained_bindings.append(
            {
                "truth_id": truth_id,
                "decision_sha256": sha256_file(decision_path) if decision_present else None,
                "raw_sha256": sha256_file(raw_path) if raw_present else None,
                "failure_sha256": sha256_file(failure_path) if failure_path.is_file() else None,
            }
        )
        if decision_present and raw_present:
            try:
                _validate_existing_primary(
                    packet,
                    reviewer="opus",
                    decision_path=decision_path,
                    raw_path=raw_path,
                )
            except (E0GovernanceError, OSError, json.JSONDecodeError) as exc:
                invalid_records.append(
                    {"truth_id": truth_id, "error_sha256": sha256_value(str(exc))}
                )
                unverified_ids.append(truth_id)
                continue
            shutil.copy2(decision_path, output_decisions / decision_path.name)
            shutil.copy2(raw_path, output_raw / raw_path.name)
            verified_records.append(
                {
                    "truth_id": truth_id,
                    "packet_sha256": packet["packet_sha256"],
                    "decision_file_sha256": sha256_file(decision_path),
                    "raw_file_sha256": sha256_file(raw_path),
                }
            )
            continue
        if decision_present or raw_present:
            record: dict[str, Any] = {
                "truth_id": truth_id,
                "present_files": [
                    name
                    for name, present in (("decision", decision_present), ("raw", raw_present))
                    if present
                ],
            }
            if raw_present:
                record["raw_signals"] = _checkpoint_raw_signals(raw_path)
            incomplete_records.append(record)
        unverified_ids.append(truth_id)

    missing_pair_count = (
        len(planned_ids) - len(verified_records) - len(invalid_records) - len(incomplete_records)
    )
    manifest: dict[str, Any] = {
        "schema_version": ARBITRATION_CHECKPOINT_SCHEMA_VERSION,
        "reviewer": "opus",
        "packet_source_sha": str(args.packet_source_sha),
        "retained_source_sha": str(args.retained_source_sha),
        "workflow_run_id": str(args.workflow_run_id),
        "environment": "sealed-benchmark",
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "plan_record_count": len(work),
        "plan_sha256": plan_sha256,
        "planned_ids": planned_ids,
        "record_count": len(planned_ids),
        "verified_record_count": len(verified_records),
        "invalid_pair_count": len(invalid_records),
        "incomplete_pair_count": len(incomplete_records),
        "missing_pair_count": missing_pair_count,
        "failure_record_count": len(failure_records),
        "first_unverified_batch_ids": unverified_ids[: args.workers],
        "failure_records": failure_records,
        "invalid_records": invalid_records,
        "incomplete_records": incomplete_records,
        "verified_records": verified_records,
        "retained_input_sha256": sha256_value(retained_bindings),
        "checkpoint_contains_review_material": True,
        "diagnostic_answer_material_present": False,
        "formal_evidence": False,
        "requires_resume_revalidation": True,
    }
    manifest["content_sha256"] = _checkpoint_manifest_content_sha256(manifest)
    _json_dump(output / "checkpoint-manifest.json", manifest)
    return 0


def _validate_arbitration_checkpoint(
    root: Path,
    *,
    packet_source_sha: str,
    work: Sequence[tuple[Mapping[str, Any], str, tuple[Mapping[str, Any], Mapping[str, Any]]]],
    plan_sha256: str,
    shard_index: int,
    shard_count: int,
) -> None:
    _validate_arbitration_shard_identity(shard_index, shard_count)
    shard_work = _arbitration_shard_work(
        work,
        shard_index=shard_index,
        shard_count=shard_count,
    )
    planned_ids = [truth_id for _, truth_id, _ in shard_work]
    packet_by_id = {truth_id: packet for packet, truth_id, _ in shard_work}
    packet_by_uid = {str(packet["packet_uid"]): packet for packet, _, _ in shard_work}
    manifest = load_json_strict(root / "checkpoint-manifest.json")
    if (
        not isinstance(manifest, Mapping)
        or set(manifest) != _arbitration_checkpoint_required_fields()
    ):
        raise E0GovernanceError("arbitration checkpoint manifest fields are invalid")
    if (
        manifest.get("schema_version") != ARBITRATION_CHECKPOINT_SCHEMA_VERSION
        or manifest.get("reviewer") != "opus"
        or manifest.get("packet_source_sha") != packet_source_sha
        or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("retained_source_sha") or ""))
        or not str(manifest.get("workflow_run_id") or "").isdigit()
        or manifest.get("environment") != "sealed-benchmark"
        or manifest.get("shard_index") != shard_index
        or manifest.get("shard_count") != shard_count
        or manifest.get("plan_record_count") != len(work)
        or manifest.get("plan_sha256") != plan_sha256
        or manifest.get("planned_ids") != planned_ids
        or manifest.get("record_count") != len(planned_ids)
        or manifest.get("checkpoint_contains_review_material") is not True
        or manifest.get("diagnostic_answer_material_present") is not False
        or manifest.get("formal_evidence") is not False
        or manifest.get("requires_resume_revalidation") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("retained_input_sha256") or ""))
        or manifest.get("content_sha256") != _checkpoint_manifest_content_sha256(manifest)
    ):
        raise E0GovernanceError("arbitration checkpoint manifest is invalid")
    count_fields = (
        "verified_record_count",
        "invalid_pair_count",
        "incomplete_pair_count",
        "missing_pair_count",
    )
    if any(
        not isinstance(manifest.get(field), int)
        or isinstance(manifest.get(field), bool)
        or int(manifest[field]) < 0
        for field in count_fields
    ) or sum(int(manifest[field]) for field in count_fields) != len(planned_ids):
        raise E0GovernanceError("arbitration checkpoint counts are invalid")
    for name, count_name in (
        ("invalid_records", "invalid_pair_count"),
        ("incomplete_records", "incomplete_pair_count"),
        ("verified_records", "verified_record_count"),
        ("failure_records", "failure_record_count"),
    ):
        if not isinstance(manifest.get(name), list) or len(manifest[name]) != manifest.get(
            count_name
        ):
            raise E0GovernanceError(f"arbitration checkpoint {name} are invalid")
    if (
        not isinstance(manifest.get("failure_record_count"), int)
        or isinstance(manifest.get("failure_record_count"), bool)
        or manifest.get("failure_record_count", -1) < 0
        or not isinstance(manifest.get("first_unverified_batch_ids"), list)
        or any(not isinstance(value, str) for value in manifest["first_unverified_batch_ids"])
    ):
        raise E0GovernanceError("arbitration checkpoint diagnostics are invalid")
    if len(set(manifest["first_unverified_batch_ids"])) != len(
        manifest["first_unverified_batch_ids"]
    ) or not set(manifest["first_unverified_batch_ids"]).issubset(planned_ids):
        raise E0GovernanceError("arbitration checkpoint unverified batch is invalid")
    diagnostic_ids: set[str] = set()
    for record in manifest["invalid_records"]:
        if (
            not isinstance(record, Mapping)
            or set(record) != {"truth_id", "error_sha256"}
            or record.get("truth_id") not in planned_ids
            or record.get("truth_id") in diagnostic_ids
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("error_sha256") or ""))
        ):
            raise E0GovernanceError("arbitration checkpoint invalid-pair record is invalid")
        diagnostic_ids.add(str(record["truth_id"]))
    for record in manifest["incomplete_records"]:
        if not isinstance(record, Mapping) or set(record) not in (
            {"truth_id", "present_files"},
            {"truth_id", "present_files", "raw_signals"},
        ):
            raise E0GovernanceError("arbitration checkpoint incomplete-pair record is invalid")
        truth_id = str(record.get("truth_id") or "")
        present_files = record.get("present_files")
        if (
            truth_id not in planned_ids
            or truth_id in diagnostic_ids
            or not isinstance(present_files, list)
            or not present_files
            or len(set(present_files)) != len(present_files)
            or not set(present_files).issubset({"decision", "raw"})
            or ("raw_signals" in record and not isinstance(record["raw_signals"], Mapping))
        ):
            raise E0GovernanceError("arbitration checkpoint incomplete-pair record is invalid")
        diagnostic_ids.add(truth_id)
    failure_uids: set[str] = set()
    for marker in manifest["failure_records"]:
        _validate_primary_failure_marker(
            marker,
            reviewer="opus",
            packet_by_uid=packet_by_uid,
        )
        packet_uid = str(marker["packet_uid"])
        if packet_uid in failure_uids:
            raise E0GovernanceError("arbitration checkpoint failure record is duplicated")
        failure_uids.add(packet_uid)
    seen: set[str] = set()
    for record in manifest["verified_records"]:
        if not isinstance(record, Mapping) or set(record) != {
            "truth_id",
            "packet_sha256",
            "decision_file_sha256",
            "raw_file_sha256",
        }:
            raise E0GovernanceError("arbitration checkpoint verified record fields are invalid")
        truth_id = str(record.get("truth_id") or "")
        packet = packet_by_id.get(truth_id)
        if packet is None or truth_id in seen:
            raise E0GovernanceError("arbitration checkpoint verified record identity is invalid")
        seen.add(truth_id)
        decision_path = root / "decisions" / f"{truth_id}.json"
        raw_path = root / "raw" / f"{truth_id}.json"
        if (
            record.get("packet_sha256") != packet["packet_sha256"]
            or not decision_path.is_file()
            or not raw_path.is_file()
            or record.get("decision_file_sha256") != sha256_file(decision_path)
            or record.get("raw_file_sha256") != sha256_file(raw_path)
        ):
            raise E0GovernanceError("arbitration checkpoint verified record hash is invalid")
        _validate_existing_primary(
            packet,
            reviewer="opus",
            decision_path=decision_path,
            raw_path=raw_path,
        )
    expected_names = {f"{truth_id}.json" for truth_id in seen}
    if {path.name for path in (root / "decisions").glob("*.json")} != expected_names or {
        path.name for path in (root / "raw").glob("*.json")
    } != expected_names:
        raise E0GovernanceError("arbitration checkpoint contains unbound review files")


def _arbitration_shard_manifest_fields() -> set[str]:
    return {
        "schema_version",
        "reviewer",
        "shard_index",
        "shard_count",
        "plan_record_count",
        "plan_sha256",
        "planned_ids",
        "reviewed_count",
        "disagreement_count",
        "evidence_deficit_count",
        "mandatory_disputed_ids",
        "reviewed_ids",
        "records",
    }


def _validate_arbitration_shard(
    root: Path,
    *,
    work: Sequence[tuple[Mapping[str, Any], str, tuple[Mapping[str, Any], Mapping[str, Any]]]],
    disagreements: set[str],
    evidence_deficits: set[str],
    plan_sha256: str,
    shard_index: int,
    shard_count: int,
) -> list[dict[str, Any]]:
    shard_work = _arbitration_shard_work(
        work,
        shard_index=shard_index,
        shard_count=shard_count,
    )
    planned_ids = [truth_id for _, truth_id, _ in shard_work]
    packet_by_id = {truth_id: packet for packet, truth_id, _ in shard_work}
    manifest = load_json_strict(root / "manifest.json")
    if not isinstance(manifest, Mapping) or set(manifest) != _arbitration_shard_manifest_fields():
        raise E0GovernanceError("arbitration shard manifest fields are invalid")
    if (
        manifest.get("schema_version") != ARBITRATION_SHARD_SCHEMA_VERSION
        or manifest.get("reviewer") != "opus"
        or manifest.get("shard_index") != shard_index
        or manifest.get("shard_count") != shard_count
        or manifest.get("plan_record_count") != len(work)
        or manifest.get("plan_sha256") != plan_sha256
        or manifest.get("planned_ids") != planned_ids
        or manifest.get("reviewed_count") != len(planned_ids)
        or manifest.get("disagreement_count") != len(disagreements)
        or manifest.get("evidence_deficit_count") != len(evidence_deficits)
        or manifest.get("mandatory_disputed_ids") != sorted(DISPUTED_IDS)
        or manifest.get("reviewed_ids") != planned_ids
    ):
        raise E0GovernanceError("arbitration shard manifest is invalid")
    records = manifest.get("records")
    if not isinstance(records, list) or len(records) != len(planned_ids):
        raise E0GovernanceError("arbitration shard records are invalid")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping) or set(record) != {
            "truth_id",
            "packet_sha256",
            "decision_file_sha256",
            "raw_file_sha256",
            "status",
        }:
            raise E0GovernanceError("arbitration shard record fields are invalid")
        truth_id = str(record.get("truth_id") or "")
        packet = packet_by_id.get(truth_id)
        decision_path = root / "decisions" / f"{truth_id}.json"
        raw_path = root / "raw" / f"{truth_id}.json"
        if (
            packet is None
            or truth_id in seen
            or record.get("status") not in {"reviewed", "reused"}
            or record.get("packet_sha256") != packet["packet_sha256"]
            or not decision_path.is_file()
            or not raw_path.is_file()
            or record.get("decision_file_sha256") != sha256_file(decision_path)
            or record.get("raw_file_sha256") != sha256_file(raw_path)
        ):
            raise E0GovernanceError("arbitration shard record binding is invalid")
        seen.add(truth_id)
        _validate_existing_primary(
            packet,
            reviewer="opus",
            decision_path=decision_path,
            raw_path=raw_path,
        )
    expected_names = {f"{truth_id}.json" for truth_id in planned_ids}
    if (
        seen != set(planned_ids)
        or {path.name for path in (root / "decisions").glob("*.json")} != expected_names
        or {path.name for path in (root / "raw").glob("*.json")} != expected_names
    ):
        raise E0GovernanceError("arbitration shard contains unbound review files")
    return [dict(record) for record in records]


def run_arbitration(args: argparse.Namespace) -> int:
    shard_index = int(getattr(args, "shard_index", 0))
    shard_count = int(getattr(args, "shard_count", 1))
    _validate_arbitration_shard_identity(shard_index, shard_count)
    output = args.output_dir.resolve()
    if output.exists() and not args.resume:
        raise E0GovernanceError(f"output already exists: {output}")
    (output / "decisions").mkdir(parents=True, exist_ok=args.resume)
    (output / "raw").mkdir(exist_ok=args.resume)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        raise E0GovernanceError("Opus arbitration is already complete")
    fable_dir = args.fable_dir.resolve(strict=True)
    deepseek_dir = args.deepseek_dir.resolve(strict=True)
    work, disagreements, evidence_deficits, plan_sha256 = _load_arbitration_plan(
        args.packet_dir.resolve(),
        fable_dir=fable_dir,
        deepseek_dir=deepseek_dir,
    )
    shard_work = _arbitration_shard_work(
        work,
        shard_index=shard_index,
        shard_count=shard_count,
    )
    checkpoint_source_sha = getattr(args, "checkpoint_source_sha", None)
    if args.resume:
        if checkpoint_source_sha is None:
            raise E0GovernanceError("arbitration resume requires a bound checkpoint")
        _validate_arbitration_checkpoint(
            output,
            packet_source_sha=str(checkpoint_source_sha),
            work=work,
            plan_sha256=plan_sha256,
            shard_index=shard_index,
            shard_count=shard_count,
        )
        (output / "checkpoint-manifest.json").unlink()
    elif checkpoint_source_sha is not None:
        raise E0GovernanceError("arbitration checkpoint validation requires resume mode")
    records: list[dict[str, Any]] = []
    completed_count = 0
    for offset in range(0, len(shard_work), args.workers):
        batch = shard_work[offset : offset + args.workers]
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _run_arbitration_packet,
                    packet,
                    truth_id=truth_id,
                    primary_decisions=primary_decisions,
                    output=output,
                    resume=args.resume,
                ): truth_id
                for packet, truth_id, primary_decisions in batch
            }
            for future in as_completed(futures):
                truth_id = futures[future]
                records.append(future.result())
                completed_count += 1
                print(
                    f"opus shard {shard_index}: {completed_count}/{len(shard_work)} "
                    f"complete ({truth_id})",
                    flush=True,
                )
    reviewed = {str(record["truth_id"]) for record in records}
    planned_ids = [truth_id for _, truth_id, _ in shard_work]
    if reviewed != set(planned_ids):
        raise E0GovernanceError("Opus did not complete the deterministic arbitration shard")
    records.sort(key=lambda value: str(value["truth_id"]))
    _json_dump(
        manifest_path,
        {
            "schema_version": ARBITRATION_SHARD_SCHEMA_VERSION,
            "reviewer": "opus",
            "shard_index": shard_index,
            "shard_count": shard_count,
            "plan_record_count": len(work),
            "plan_sha256": plan_sha256,
            "planned_ids": planned_ids,
            "reviewed_count": len(reviewed),
            "disagreement_count": len(disagreements),
            "evidence_deficit_count": len(evidence_deficits),
            "mandatory_disputed_ids": sorted(DISPUTED_IDS),
            "reviewed_ids": planned_ids,
            "records": records,
        },
    )
    return 0


def merge_arbitration_shards(args: argparse.Namespace) -> int:
    """Strictly revalidate and combine all deterministic Opus shard artifacts."""

    _validate_arbitration_shard_identity(0, args.shard_count)
    shard_dirs = [path.resolve(strict=True) for path in args.shard_dir]
    if len(shard_dirs) != args.shard_count:
        raise E0GovernanceError("arbitration merge requires exactly one directory per shard")
    fable_dir = args.fable_dir.resolve(strict=True)
    deepseek_dir = args.deepseek_dir.resolve(strict=True)
    work, disagreements, evidence_deficits, plan_sha256 = _load_arbitration_plan(
        args.packet_dir.resolve(),
        fable_dir=fable_dir,
        deepseek_dir=deepseek_dir,
    )
    output = args.output_dir.resolve()
    if output.exists():
        raise E0GovernanceError(f"arbitration merge output already exists: {output}")
    (output / "decisions").mkdir(parents=True)
    (output / "raw").mkdir()
    all_records: list[dict[str, Any]] = []
    reviewed: set[str] = set()
    seen_shards: set[int] = set()
    for root in shard_dirs:
        manifest = load_json_strict(root / "manifest.json")
        if not isinstance(manifest, Mapping):
            raise E0GovernanceError("arbitration shard manifest must be an object")
        shard_index = manifest.get("shard_index")
        if (
            not isinstance(shard_index, int)
            or isinstance(shard_index, bool)
            or shard_index in seen_shards
        ):
            raise E0GovernanceError("arbitration shard identity is duplicated or invalid")
        seen_shards.add(shard_index)
        records = _validate_arbitration_shard(
            root,
            work=work,
            disagreements=disagreements,
            evidence_deficits=evidence_deficits,
            plan_sha256=plan_sha256,
            shard_index=shard_index,
            shard_count=args.shard_count,
        )
        for record in records:
            truth_id = str(record["truth_id"])
            if truth_id in reviewed:
                raise E0GovernanceError("arbitration record is duplicated across shards")
            reviewed.add(truth_id)
            shutil.copy2(root / "decisions" / f"{truth_id}.json", output / "decisions")
            shutil.copy2(root / "raw" / f"{truth_id}.json", output / "raw")
            all_records.append(record)
    if seen_shards != set(range(args.shard_count)):
        raise E0GovernanceError("arbitration merge is missing a deterministic shard")
    expected = {truth_id for _, truth_id, _ in work}
    if (
        reviewed != expected
        or not DISPUTED_IDS.issubset(reviewed)
        or not disagreements.issubset(reviewed)
    ):
        raise E0GovernanceError("merged arbitration does not cover the complete plan")
    all_records.sort(key=lambda value: str(value["truth_id"]))
    _json_dump(
        output / "manifest.json",
        {
            "schema_version": "zscope.range-v16-arbitration-run.v1",
            "reviewer": "opus",
            "reviewed_count": len(reviewed),
            "disagreement_count": len(disagreements),
            "evidence_deficit_count": len(evidence_deficits),
            "mandatory_disputed_ids": sorted(DISPUTED_IDS),
            "reviewed_ids": sorted(reviewed),
            "records": all_records,
        },
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    primary = subparsers.add_parser("primary")
    primary.add_argument("--reviewer", required=True, choices=("fable", "deepseek"))
    primary.add_argument("--packet-dir", required=True, type=Path)
    primary.add_argument("--output-dir", required=True, type=Path)
    primary.add_argument("--workers", type=int, default=1, choices=range(1, 9))
    primary.add_argument("--resume", action="store_true")
    primary.add_argument("--checkpoint-source-sha")
    primary.set_defaults(handler=run_primary)
    checkpoint = subparsers.add_parser("checkpoint")
    checkpoint.add_argument("--reviewer", required=True, choices=("fable", "deepseek"))
    checkpoint.add_argument("--packet-dir", required=True, type=Path)
    checkpoint.add_argument("--retained-dir", required=True, type=Path)
    checkpoint.add_argument("--output-dir", required=True, type=Path)
    checkpoint.add_argument("--packet-source-sha", required=True)
    checkpoint.add_argument("--retained-source-sha", required=True)
    checkpoint.add_argument("--workflow-run-id", required=True)
    checkpoint.add_argument("--workers", type=int, default=4, choices=range(1, 9))
    checkpoint.add_argument("--require-complete", action="store_true")
    checkpoint.set_defaults(handler=build_primary_checkpoint)
    arbitration = subparsers.add_parser("arbitrate")
    arbitration.add_argument("--packet-dir", required=True, type=Path)
    arbitration.add_argument("--fable-dir", required=True, type=Path)
    arbitration.add_argument("--deepseek-dir", required=True, type=Path)
    arbitration.add_argument("--output-dir", required=True, type=Path)
    arbitration.add_argument("--workers", type=int, default=1, choices=range(1, 9))
    arbitration.add_argument("--shard-index", type=int, default=0)
    arbitration.add_argument("--shard-count", type=int, default=1)
    arbitration.add_argument("--resume", action="store_true")
    arbitration.add_argument("--checkpoint-source-sha")
    arbitration.set_defaults(handler=run_arbitration)
    arbitration_checkpoint = subparsers.add_parser("arbitration-checkpoint")
    arbitration_checkpoint.add_argument("--packet-dir", required=True, type=Path)
    arbitration_checkpoint.add_argument("--fable-dir", required=True, type=Path)
    arbitration_checkpoint.add_argument("--deepseek-dir", required=True, type=Path)
    arbitration_checkpoint.add_argument("--retained-dir", required=True, type=Path)
    arbitration_checkpoint.add_argument("--output-dir", required=True, type=Path)
    arbitration_checkpoint.add_argument("--packet-source-sha", required=True)
    arbitration_checkpoint.add_argument("--retained-source-sha", required=True)
    arbitration_checkpoint.add_argument("--workflow-run-id", required=True)
    arbitration_checkpoint.add_argument("--shard-index", required=True, type=int)
    arbitration_checkpoint.add_argument("--shard-count", required=True, type=int)
    arbitration_checkpoint.add_argument("--workers", type=int, default=4, choices=range(1, 9))
    arbitration_checkpoint.set_defaults(handler=build_arbitration_checkpoint)
    merge_arbitration = subparsers.add_parser("merge-arbitration")
    merge_arbitration.add_argument("--packet-dir", required=True, type=Path)
    merge_arbitration.add_argument("--fable-dir", required=True, type=Path)
    merge_arbitration.add_argument("--deepseek-dir", required=True, type=Path)
    merge_arbitration.add_argument("--shard-dir", required=True, type=Path, action="append")
    merge_arbitration.add_argument("--shard-count", required=True, type=int)
    merge_arbitration.add_argument("--output-dir", required=True, type=Path)
    merge_arbitration.set_defaults(handler=merge_arbitration_shards)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (E0GovernanceError, OSError, subprocess.SubprocessError) as exc:
        print(f"E0 review failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
