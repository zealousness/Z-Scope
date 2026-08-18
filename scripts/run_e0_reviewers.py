#!/usr/bin/env python3
"""Run isolated E0 truth reviewers against pre-built minimal packets.

This command never reads scanner reports or scores.  Each model subprocess runs
in a temporary directory containing only the current packet (and, for Opus,
the two primary structured decisions).  Raw command envelopes are intended for
protected workflow artifacts and must not be committed to the repository.
"""

from __future__ import annotations

import argparse
import json
import os
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

DECISION_FIELDS = {
    "schema_version": DECISION_SCHEMA_VERSION,
    "packet_uid": "copy from packet",
    "packet_sha256": "copy from packet",
    "reviewer_role": "assigned by harness",
    "reviewer_model": "assigned model identity",
    "contract_kind": "concrete_trigger|public_api_contract|pattern_model|retired",
    "disposition": "keep|correct|retire|unresolved",
    "confidence": "number 0..1",
    "structured_anchors": [
        {
            "kind": "primary|secondary|additional|corrected",
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
            "reviewer_role": {
                "enum": ["primary_fable", "primary_deepseek", "arbiter_opus"]
            },
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
            "structured_anchors": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["kind", "file", "function", "start_line", "end_line"],
                    "properties": {
                        "kind": {
                            "enum": ["primary", "secondary", "additional", "corrected"]
                        },
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
the product implementation. Return exactly one JSON object matching the stated
nested fields, with no markdown, prose wrapper, external citation, or hidden
reasoning transcript.

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


def _extract_deepseek_decision(stdout: str) -> Mapping[str, Any]:
    value = json.loads(stdout.strip())
    if not isinstance(value, Mapping):
        raise E0GovernanceError("DeepSeek did not return a JSON object")
    return dict(value)


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
        role, model = "primary_deepseek", "deepseek-v4-pro:max"
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
        if primary_decisions:
            _json_dump(temp_root / "primary-decisions.json", list(primary_decisions))

        patch_path: Path | None = None
        if reviewer in {"fable", "opus"}:
            command = [
                str(claude_command),
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
                "--no-session-persistence",
                "--disable-slash-commands",
            ]
        else:
            patch_path = temp_root / "deepseek-max.patch.yml"
            patch_path.write_text(
                "- id: agent-default-model\n"
                "  config:\n"
                "    provider: deepseek-official\n"
                "    model: deepseek-v4-pro\n"
                "    reasoningEffort: max\n"
                "- id: system-prompt\n"
                "  config:\n"
                "    persona: >-\n"
                "      You are an isolated benchmark contract reviewer. Only use the\n"
                "      read-only packet.json and decision-schema.json in the current\n"
                "      directory. Never use external knowledge or any other tool. Return\n"
                "      exactly the requested JSON object with no markdown or prose wrapper.\n"
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
                "  disabled: true\n",
                encoding="utf-8",
            )
            command = [
                str(dsh_command),
                "--profile",
                "headless",
                "--patch",
                str(patch_path),
                "Read packet.json and decision-schema.json from the isolated current "
                "directory. Review only that packet and return exactly one JSON object "
                "matching the schema. Set reviewer_role=primary_deepseek and "
                "reviewer_model=deepseek-v4-pro:max. Do not use web search or external "
                "knowledge.",
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
        deepseek_patch_sha256 = sha256_file(patch_path) if patch_path is not None else ""
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
        if raw_output_path is not None:
            _json_dump(raw_output_path, raw)
        if completed.returncode != 0:
            raise E0GovernanceError(
                f"{reviewer} reviewer failed for {packet['packet_uid']}; "
                f"stderr_sha256={raw['stderr_sha256']}"
            )
        try:
            decision = (
                _extract_deepseek_decision(completed.stdout)
                if reviewer == "deepseek"
                else _extract_claude_decision(completed.stdout)
            )
        except (json.JSONDecodeError, E0GovernanceError) as exc:
            if reviewer != "deepseek":
                raise
            (temp_root / "prior-output.txt").write_text(completed.stdout, encoding="utf-8")
            format_prompt = (
                "Read prior-output.txt and decision-schema.json in the isolated current "
                "directory. Reformat the prior answer as exactly one JSON object matching "
                "the schema without changing its substantive decision. Set "
                "reviewer_role=primary_deepseek and "
                "reviewer_model=deepseek-v4-pro:max."
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
            raw["format_retry"] = {
                "exit_code": retry.returncode,
                "stdout": retry.stdout,
                "stderr_sha256": sha256_value(retry.stderr),
            }
            if raw_output_path is not None:
                _json_dump(raw_output_path, raw)
            if retry.returncode != 0:
                raise E0GovernanceError("DeepSeek format-only retry failed") from exc
            decision = _extract_deepseek_decision(retry.stdout)

    validate_review_decision(
        decision,
        expected_packet_uid=str(packet["packet_uid"]),
        expected_packet_sha256=str(packet["packet_sha256"]),
        expected_role=role,
    )
    if decision.get("reviewer_model") != model:
        raise E0GovernanceError("reviewer model identity mismatch")
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
        return "primary_deepseek", "deepseek-v4-pro:max"
    raise E0GovernanceError(f"unsupported primary reviewer: {reviewer}")


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
    if raw_fields != required_raw_fields and raw_fields != required_raw_fields | {
        "format_retry"
    }:
        raise E0GovernanceError("existing raw review envelope fields are invalid")
    expected_delivery = "embedded_prompt" if reviewer == "fable" else "isolated_files"
    if (
        raw.get("schema_version") != "zscope.range-v16-review-raw-envelope.v1"
        or raw.get("reviewer_role") != role
        or raw.get("reviewer_model") != model
        or raw.get("packet_uid") != packet["packet_uid"]
        or raw.get("packet_sha256") != packet["packet_sha256"]
        or raw.get("input_delivery") != expected_delivery
        or raw.get("exit_code") != 0
        or not isinstance(raw.get("stdout"), str)
        or not isinstance(raw.get("command_identity"), list)
        or not all(isinstance(value, str) for value in raw["command_identity"])
        or not isinstance(raw.get("stderr_sha256"), str)
        or len(raw["stderr_sha256"]) != 64
    ):
        raise E0GovernanceError("existing raw review envelope is invalid")


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
        decision, raw = _run_model(
            packet,
            reviewer=reviewer,
            raw_output_path=raw_path,
        )
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


def run_arbitration(args: argparse.Namespace) -> int:
    output = args.output_dir.resolve()
    if output.exists():
        raise E0GovernanceError(f"output already exists: {output}")
    (output / "decisions").mkdir(parents=True)
    (output / "raw").mkdir()
    reviewed: set[str] = set()
    disagreements: set[str] = set()
    for path in _packet_files(args.packet_dir.resolve()):
        packet = load_json_strict(path)
        if not isinstance(packet, Mapping):
            raise E0GovernanceError(f"packet must be an object: {path}")
        validate_review_packet(packet)
        truth_id = _packet_id(packet)
        fable = _load_decision(args.fable_dir / "decisions" / f"{truth_id}.json")
        deepseek = _load_decision(args.deepseek_dir / "decisions" / f"{truth_id}.json")
        disagreement = any(
            fable.get(field) != deepseek.get(field)
            for field in ("contract_kind", "disposition", "structured_anchors")
        )
        if disagreement:
            disagreements.add(truth_id)
        if truth_id not in DISPUTED_IDS and not disagreement:
            continue
        decision, raw = _run_model(
            packet,
            reviewer="opus",
            primary_decisions=(fable, deepseek),
            raw_output_path=output / "raw" / f"{truth_id}.json",
        )
        _json_dump(output / "decisions" / f"{truth_id}.json", decision)
        _json_dump(output / "raw" / f"{truth_id}.json", raw)
        reviewed.add(truth_id)
    if not DISPUTED_IDS.issubset(reviewed):
        raise E0GovernanceError("Opus did not review all nine mandatory disputed records")
    if not disagreements.issubset(reviewed):
        raise E0GovernanceError("Opus did not arbitrate every primary disagreement")
    _json_dump(
        output / "manifest.json",
        {
            "schema_version": "zscope.range-v16-arbitration-run.v1",
            "reviewer": "opus",
            "reviewed_count": len(reviewed),
            "disagreement_count": len(disagreements),
            "mandatory_disputed_ids": sorted(DISPUTED_IDS),
            "reviewed_ids": sorted(reviewed),
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
