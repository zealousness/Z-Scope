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
FORMAT_VALIDATION_SCHEMA_VERSION = "zscope.range-v16-format-validation.v1"

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
    shape_errors = (
        _schema_shape_errors(decision, _decision_schema_for_model()) if parsed_object else []
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
    }


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
        _json_dump(temp_root / "decision-schema.json", _decision_schema_for_model())
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
        if reviewer == "deepseek" and completed.returncode != 0:
            transport_retry = {
                "initial_exit_code": completed.returncode,
                "initial_stdout_sha256": sha256_value(completed.stdout),
                "initial_stdout_retained": False,
                "initial_stderr_sha256": sha256_value(completed.stderr),
            }
            completed = subprocess.run(
                command,
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
        try:
            decision = _validated_bound_decision_from_stdout(
                completed.stdout,
                reviewer=reviewer,
                packet=packet,
                role=role,
                model=model,
            )
        except (json.JSONDecodeError, E0GovernanceError) as exc:
            if reviewer != "deepseek":
                if raw_output_path is not None:
                    _json_dump(raw_output_path, raw)
                raise
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
            validation_error: Exception = exc
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
                    raise E0GovernanceError("DeepSeek format-only retry failed") from exc
                try:
                    decision = _validated_bound_decision_from_stdout(
                        retry.stdout,
                        reviewer="deepseek",
                        packet=packet,
                        role=role,
                        model=model,
                    )
                    break
                except (json.JSONDecodeError, E0GovernanceError) as retry_exc:
                    if attempt_index == len(format_prompts) - 1:
                        if raw_output_path is not None:
                            _json_dump(raw_output_path, raw)
                        raise E0GovernanceError(
                            "DeepSeek format retries did not produce a schema-valid JSON "
                            "decision"
                        ) from retry_exc
                    prior_stdout = retry.stdout
                    validation_error = retry_exc

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
                decision = _validated_decision_from_stdout(
                    retry.stdout,
                    reviewer=reviewer,
                )
                validate_review_decision(
                    decision,
                    expected_packet_uid=str(packet["packet_uid"]),
                    expected_packet_sha256=str(packet["packet_sha256"]),
                    expected_role=role,
                )
                if decision.get("reviewer_model") != model:
                    raise E0GovernanceError("reviewer model identity mismatch")
                if (
                    sha256_value(_semantic_retry_substantive_projection(decision))
                    != original_projection_sha256
                ):
                    raise E0GovernanceError(
                        f"{reviewer} grounding-only retry changed substantive fields"
                    )
                validate_decision_against_packet(
                    decision,
                    packet,
                    require_resolvable_evidence=reviewer == "opus",
                )
            except (json.JSONDecodeError, E0GovernanceError):
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
        "semantic_retry",
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
            reviewer != "deepseek"
            or not isinstance(transport_retry, Mapping)
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


def run_arbitration(args: argparse.Namespace) -> int:
    output = args.output_dir.resolve()
    if output.exists() and not args.resume:
        raise E0GovernanceError(f"output already exists: {output}")
    (output / "decisions").mkdir(parents=True, exist_ok=args.resume)
    (output / "raw").mkdir(exist_ok=args.resume)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        raise E0GovernanceError("Opus arbitration is already complete")
    disagreements: set[str] = set()
    evidence_deficits: set[str] = set()
    work: list[tuple[Mapping[str, Any], str, tuple[Mapping[str, Any], Mapping[str, Any]]]] = []
    fable_dir = args.fable_dir.resolve(strict=True)
    deepseek_dir = args.deepseek_dir.resolve(strict=True)
    for path in _packet_files(args.packet_dir.resolve()):
        packet = load_json_strict(path)
        if not isinstance(packet, Mapping):
            raise E0GovernanceError(f"packet must be an object: {path}")
        validate_review_packet(packet)
        truth_id = _packet_id(packet)
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
        if truth_id not in DISPUTED_IDS and not disagreement_fields and not evidence_deficit:
            continue
        work.append((packet, truth_id, (fable, deepseek)))
    records: list[dict[str, Any]] = []
    completed_count = 0
    for offset in range(0, len(work), args.workers):
        batch = work[offset : offset + args.workers]
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
                    f"opus: {completed_count}/{len(work)} complete ({truth_id})",
                    flush=True,
                )
    reviewed = {str(record["truth_id"]) for record in records}
    if not DISPUTED_IDS.issubset(reviewed):
        raise E0GovernanceError("Opus did not review all nine mandatory disputed records")
    if not disagreements.issubset(reviewed):
        raise E0GovernanceError("Opus did not arbitrate every primary disagreement")
    records.sort(key=lambda value: str(value["truth_id"]))
    _json_dump(
        manifest_path,
        {
            "schema_version": "zscope.range-v16-arbitration-run.v1",
            "reviewer": "opus",
            "reviewed_count": len(reviewed),
            "disagreement_count": len(disagreements),
            "evidence_deficit_count": len(evidence_deficits),
            "mandatory_disputed_ids": sorted(DISPUTED_IDS),
            "reviewed_ids": sorted(reviewed),
            "records": records,
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
    primary.set_defaults(handler=run_primary)
    arbitration = subparsers.add_parser("arbitrate")
    arbitration.add_argument("--packet-dir", required=True, type=Path)
    arbitration.add_argument("--fable-dir", required=True, type=Path)
    arbitration.add_argument("--deepseek-dir", required=True, type=Path)
    arbitration.add_argument("--output-dir", required=True, type=Path)
    arbitration.add_argument("--workers", type=int, default=1, choices=range(1, 9))
    arbitration.add_argument("--resume", action="store_true")
    arbitration.set_defaults(handler=run_arbitration)
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
