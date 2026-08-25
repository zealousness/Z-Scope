#!/usr/bin/env python3
"""Author and materialize anonymous, independently compilable Range v16 pairs.

The protected ``author`` mode asks Codex only for two minimal C translation
units that embody an already-adjudicated invariant.  It cannot change the
truth decision.  ``materialize`` consumes the protected author artifact and
writes only validated source plus content-addressed manifests into Git.
"""

from __future__ import annotations

import argparse
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

from e0_review_governance import (  # noqa: E402
    E0GovernanceError,
    load_json_strict,
    sha256_file,
    sha256_value,
    validate_review_packet,
)
from validate_range_v16_truth import (  # noqa: E402
    compile_pair_manifest,
    validate_normalized_decisions,
    validate_pair_manifest,
)
from run_e0_reviewers import (  # noqa: E402
    CODEX_MODEL_IDENTITY,
    _codex_arguments,
    _reviewer_environment,
    assert_no_hidden_reasoning_output,
)


AUTHOR_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author.v1"
RAW_AUTHOR_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author-raw.v3"
AUTHOR_MODEL = CODEX_MODEL_IDENTITY
_FORBIDDEN_SOURCE = re.compile(
    r"(?i)(?:#\s*(?:include|pragma)|\b(?:system|popen|fork|exec[a-z]*|__asm__|asm)\s*\()"
)
_GENERIC_C_CALLS = {
    "_Alignof",
    "_Static_assert",
    "calloc",
    "free",
    "if",
    "main",
    "malloc",
    "memchr",
    "memcmp",
    "memcpy",
    "memmove",
    "memset",
    "realloc",
    "sizeof",
    "switch",
    "while",
}
_GENERIC_C_MACROS = {"NULL", "CHAR_BIT", "INT_MAX", "INT_MIN", "SIZE_MAX"}
_C11_KEYWORDS = {
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
}
_C_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_REPAIRABLE_AUTHOR_VALIDATION_CLASSES = {
    "decision_identity_mismatch",
    "fields_or_schema_invalid",
    "forbidden_c_facilities",
    "invariant_missing",
    "kind_invalid",
    "main_contract_invalid",
    "model_identity_mismatch",
    "packet_identity_mismatch",
    "source_invalid",
    "source_not_anonymous",
    "sources_identical",
}


def _json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")


def _object(path: Path) -> Mapping[str, Any]:
    value = load_json_strict(path.resolve(strict=True))
    if not isinstance(value, Mapping):
        raise E0GovernanceError(f"artifact must be an object: {path}")
    return value


def _json_schema_regex_escape(value: str) -> str:
    """Escape a literal for an ECMA-262-compatible JSON Schema pattern."""

    escaped: list[str] = []
    for character in value:
        if character in r"\^$.*+?()[]{}|":
            escaped.append("\\" + character)
        elif character == "\n":
            escaped.append(r"\n")
        elif character == "\r":
            escaped.append(r"\r")
        elif character == "\t":
            escaped.append(r"\t")
        elif ord(character) < 0x20:
            escaped.append(rf"\x{ord(character):02x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _source_anonymity_pattern(forbidden_identifiers: set[str]) -> str:
    """Return a stable JSON-Schema pattern excluding the complete catalog.

    JSON Schema uses search semantics for ``pattern``.  Anchor the expression
    and use ``[\\s\\S]`` so the same constraint covers both complete multiline
    source fields, including comments, literals, and preprocessor text.  The
    negative lookahead avoids relying on lookbehind support in the structured
    output validator while preserving the validator's complete-token boundary
    for C identifiers and literal matching for non-identifiers.
    """

    conflicts: list[str] = []
    for identifier in sorted(item for item in forbidden_identifiers if item):
        escaped = _json_schema_regex_escape(identifier)
        if _C_IDENTIFIER.fullmatch(identifier):
            conflicts.append(rf"(?:^|[^A-Za-z0-9_]){escaped}(?:$|[^A-Za-z0-9_])")
        else:
            conflicts.append(escaped)
    if not conflicts:
        return r"^[\s\S]*$"
    return rf"^(?![\s\S]*(?:{'|'.join(conflicts)}))[\s\S]*$"


def _author_schema(
    forbidden_identifiers: set[str] | None = None,
    *,
    truth_id: str | None = None,
    packet_sha256: str | None = None,
    final_decision_sha256: str | None = None,
) -> dict[str, Any]:
    identity_values = (truth_id, packet_sha256, final_decision_sha256)
    if any(value is not None for value in identity_values) and not all(
        isinstance(value, str) and value for value in identity_values
    ):
        raise ValueError("safe-pair author schema identity must be fully bound")
    source_pattern = _source_anonymity_pattern(forbidden_identifiers or set())
    truth_id_schema: dict[str, Any] = {"type": "string", "minLength": 1}
    packet_sha256_schema: dict[str, Any] = {
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    }
    final_decision_sha256_schema: dict[str, Any] = {
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    }
    if truth_id is not None:
        truth_id_schema = {"const": truth_id}
        packet_sha256_schema = {"const": packet_sha256}
        final_decision_sha256_schema = {"const": final_decision_sha256}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "truth_id",
            "packet_sha256",
            "final_decision_sha256",
            "author_role",
            "author_model",
            "kind",
            "invariant_summary",
            "vulnerable_source",
            "fixed_or_near_miss_source",
        ],
        "properties": {
            "schema_version": {"const": AUTHOR_SCHEMA_VERSION},
            "truth_id": truth_id_schema,
            "packet_sha256": packet_sha256_schema,
            "final_decision_sha256": final_decision_sha256_schema,
            "author_role": {"const": "safe_pair_author"},
            "author_model": {"const": AUTHOR_MODEL},
            "kind": {"enum": ["fixed", "near_miss"]},
            "invariant_summary": {"type": "string", "minLength": 1},
            "vulnerable_source": {
                "type": "string",
                "minLength": 1,
                "maxLength": 32768,
                "pattern": source_pattern,
            },
            "fixed_or_near_miss_source": {
                "type": "string",
                "minLength": 1,
                "maxLength": 32768,
                "pattern": source_pattern,
            },
        },
    }


def _source_identifiers(packet: Mapping[str, Any], truth_id: str) -> set[str]:
    identifiers = {truth_id}
    record = packet.get("truth_record")
    if isinstance(record, Mapping):
        for key, value in record.items():
            if "function" in str(key).lower() and isinstance(value, str) and value:
                identifiers.add(value)
    windows = packet.get("code_windows")
    if isinstance(windows, list):
        for window in windows:
            if not isinstance(window, Mapping) or not isinstance(window.get("content"), str):
                continue
            content = str(window["content"])
            identifiers.update(
                match
                for match in re.findall(r"\b([A-Za-z_]\w*)\s*\(", content)
                if match not in _GENERIC_C_CALLS and match not in _C11_KEYWORDS
            )
            identifiers.update(
                match
                for match in re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", content)
                if match not in _GENERIC_C_MACROS
            )
    return identifiers


def _forbidden_identifier_matches(
    source: str,
    forbidden_identifiers: set[str],
) -> dict[str, int]:
    """Return every match using complete C tokens or literal non-identifiers.

    Packet-derived function and macro names are C identifiers. Treating them
    as arbitrary substrings makes a short project name reject an unrelated,
    freshly authored identifier that merely contains the same characters.
    Truth IDs and any other non-C identifiers remain exact literal bans.
    """

    matches: dict[str, int] = {}
    for identifier in sorted(item for item in forbidden_identifiers if item):
        if _C_IDENTIFIER.fullmatch(identifier):
            pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(identifier)}(?![A-Za-z0-9_])")
            count = len(pattern.findall(source))
        else:
            count = source.count(identifier)
        if count:
            matches[identifier] = count
    return matches


def _repair_constraints(
    validation_class: str,
    forbidden_identifiers: set[str],
    rejected_author: Mapping[str, Any],
) -> Mapping[str, Any]:
    if validation_class != "source_not_anonymous":
        return {}
    detected_conflicts: dict[str, list[dict[str, Any]]] = {}
    for field in ("vulnerable_source", "fixed_or_near_miss_source"):
        source = rejected_author.get(field)
        if not isinstance(source, str):
            continue
        matches = _forbidden_identifier_matches(source, forbidden_identifiers)
        if matches:
            detected_conflicts[field] = [
                {
                    "identifier": identifier,
                    "match_count": count,
                    "match_kind": (
                        "complete_c_token"
                        if _C_IDENTIFIER.fullmatch(identifier)
                        else "literal_non_identifier"
                    ),
                }
                for identifier, count in matches.items()
            ]
    return {
        "identifier_match": "exact_c_token_or_literal_non_identifier",
        "forbidden_identifiers": sorted(
            identifier for identifier in forbidden_identifiers if identifier
        ),
        "detected_conflicts_by_source_field": detected_conflicts,
        "required_postcondition": (
            "zero forbidden-identifier matches across the complete text of both source fields"
        ),
        "required_correction": (
            "Remove every detected conflict from both complete source texts. Rename C "
            "identifier tokens and all of their uses consistently; remove literal non-C "
            "identifiers wherever they occur. Matches in declarations, uses, comments, "
            "string or character literals, and preprocessor text all count. Do not alter "
            "main or identity fields."
        ),
    }


def validate_author_record(
    value: Mapping[str, Any],
    *,
    truth_id: str,
    packet_sha256: str,
    final_decision_sha256: str,
    forbidden_identifiers: set[str],
) -> None:
    expected = set(_author_schema()["required"])
    if set(value) != expected or value.get("schema_version") != AUTHOR_SCHEMA_VERSION:
        raise E0GovernanceError("safe-pair author fields or schema are invalid")
    if value.get("truth_id") != truth_id or value.get("packet_sha256") != packet_sha256:
        raise E0GovernanceError("safe-pair author packet identity mismatch")
    if value.get("final_decision_sha256") != final_decision_sha256:
        raise E0GovernanceError("safe-pair author decision identity mismatch")
    if value.get("author_role") != "safe_pair_author" or value.get("author_model") != AUTHOR_MODEL:
        raise E0GovernanceError("safe-pair author model identity mismatch")
    if value.get("kind") not in {"fixed", "near_miss"}:
        raise E0GovernanceError("safe-pair author kind is invalid")
    if (
        not isinstance(value.get("invariant_summary"), str)
        or not value["invariant_summary"].strip()
    ):
        raise E0GovernanceError("safe-pair author invariant is missing")
    sources: list[str] = []
    for field in ("vulnerable_source", "fixed_or_near_miss_source"):
        source = value.get(field)
        if (
            not isinstance(source, str)
            or not source.strip()
            or len(source) > 32768
            or "\x00" in source
        ):
            raise E0GovernanceError(f"safe-pair author {field} is invalid")
        if _FORBIDDEN_SOURCE.search(source):
            raise E0GovernanceError(f"safe-pair author {field} uses forbidden C facilities")
        matches = _forbidden_identifier_matches(source, forbidden_identifiers)
        if matches:
            identifier = next(iter(matches))
            raise E0GovernanceError(f"safe-pair author {field} is not anonymous: {identifier}")
        if len(re.findall(r"\bint\s+main\s*\(\s*void\s*\)", source)) != 1:
            raise E0GovernanceError(f"safe-pair author {field} requires exactly one C11 main")
        sources.append(source.replace("\r\n", "\n").replace("\r", "\n"))
    if sources[0] == sources[1]:
        raise E0GovernanceError("safe-pair vulnerable and safe sources are identical")


def _extract(stdout: str) -> Mapping[str, Any]:
    value = json.loads(stdout)
    if isinstance(value, Mapping) and set(_author_schema()["required"]).issubset(value):
        return dict(value)
    raise E0GovernanceError("Codex did not return a safe-pair author object")


def _author_validation_class(error: E0GovernanceError) -> str:
    message = str(error)
    classes = (
        ("fields or schema", "fields_or_schema_invalid"),
        ("packet identity", "packet_identity_mismatch"),
        ("decision identity", "decision_identity_mismatch"),
        ("model identity", "model_identity_mismatch"),
        ("kind is invalid", "kind_invalid"),
        ("invariant is missing", "invariant_missing"),
        ("uses forbidden C facilities", "forbidden_c_facilities"),
        ("is not anonymous", "source_not_anonymous"),
        ("requires exactly one C11 main", "main_contract_invalid"),
        ("sources are identical", "sources_identical"),
        ("is invalid", "source_invalid"),
    )
    for fragment, validation_class in classes:
        if fragment in message:
            return validation_class
    return "unclassified_validation_failure"


def _run_author_command(
    command: Sequence[str],
    *,
    prompt: str,
    env: Mapping[str, str],
    output_schema: Mapping[str, Any],
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="zscope-e0-pair-author-") as raw_temp:
        _json_dump(Path(raw_temp) / "author-schema.json", output_schema)
        return subprocess.run(
            command,
            input=prompt,
            cwd=raw_temp,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=1800,
        )


def _raw_attempt(
    completed: subprocess.CompletedProcess[str],
    *,
    attempt: int,
    kind: str,
    validation_class: str | None,
) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "kind": kind,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr_sha256": sha256_value(completed.stderr),
        "validation_class": validation_class,
    }


def _raw_author_envelope(
    *,
    truth_id: str,
    packet_sha256: str,
    final_decision_sha256: str,
    command: Sequence[str],
    output_schema: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    accepted_attempt: int | None,
) -> dict[str, Any]:
    return {
        "schema_version": RAW_AUTHOR_SCHEMA_VERSION,
        "truth_id": truth_id,
        "packet_sha256": packet_sha256,
        "final_decision_sha256": final_decision_sha256,
        "author_model": AUTHOR_MODEL,
        "command_identity": [Path(command[0]).name, *command[1:]],
        "output_schema_sha256": sha256_value(output_schema),
        "attempts": list(attempts),
        "accepted_attempt": accepted_attempt,
    }


def _author_one(
    packet: Mapping[str, Any],
    normalized_record: Mapping[str, Any],
    *,
    output: Path,
    resume: bool,
) -> dict[str, Any]:
    truth_id = str(normalized_record["truth_id"])
    decision = normalized_record["final_decision"]
    final_sha = str(normalized_record["final_decision_sha256"])
    author_path = output / "authors" / f"{truth_id}.json"
    raw_path = output / "raw" / f"{truth_id}.json"
    forbidden = _source_identifiers(packet, truth_id)
    if author_path.exists() or raw_path.exists():
        if not resume or not author_path.is_file() or not raw_path.is_file():
            raise E0GovernanceError(f"incomplete or unexpected safe-pair author: {truth_id}")
        author = _object(author_path)
        validate_author_record(
            author,
            truth_id=truth_id,
            packet_sha256=str(packet["packet_sha256"]),
            final_decision_sha256=final_sha,
            forbidden_identifiers=forbidden,
        )
        status = "reused"
    else:
        codex = shutil.which("codex.cmd" if os.name == "nt" else "codex")
        if not codex:
            raise E0GovernanceError("Codex CLI executable is unavailable")
        request = {
            "packet": packet,
            "final_decision": decision,
            "final_decision_sha256": final_sha,
        }
        prompt = (
            "Author a minimal anonymous vulnerable/fixed-or-near-miss C11 pair for the "
            "already-adjudicated invariant below. Do not reconsider or change the truth "
            "decision. Each source must be one standalone translation unit, use no includes, "
            "pragmas, assembly, process/network/file APIs, original function names, truth IDs, "
            "or project-specific identifiers. Use generic names. Both sides must compile with "
            "-std=c11 -Wall -Wextra -Werror; express only the reviewed invariant and include "
            "int main(void). Return exactly the JSON schema. REQUEST:\n"
            + json.dumps(request, ensure_ascii=False, sort_keys=True)
        )
        author_schema = _author_schema(
            forbidden,
            truth_id=truth_id,
            packet_sha256=str(packet["packet_sha256"]),
            final_decision_sha256=final_sha,
        )
        command = [
            str(codex),
            *_codex_arguments(output_schema="author-schema.json"),
        ]
        env = _reviewer_environment()
        completed = _run_author_command(
            command,
            prompt=prompt,
            env=env,
            output_schema=author_schema,
        )
        if completed.returncode != 0:
            raise E0GovernanceError(f"safe-pair author failed: {truth_id}")
        assert_no_hidden_reasoning_output(completed.stdout)
        author = dict(_extract(completed.stdout))
        attempts: list[dict[str, Any]] = []
        try:
            validate_author_record(
                author,
                truth_id=truth_id,
                packet_sha256=str(packet["packet_sha256"]),
                final_decision_sha256=final_sha,
                forbidden_identifiers=forbidden,
            )
        except E0GovernanceError as error:
            validation_class = _author_validation_class(error)
            if validation_class not in _REPAIRABLE_AUTHOR_VALIDATION_CLASSES:
                raise
            attempts.append(
                _raw_attempt(
                    completed,
                    attempt=1,
                    kind="initial",
                    validation_class=validation_class,
                )
            )
            _json_dump(
                raw_path,
                _raw_author_envelope(
                    truth_id=truth_id,
                    packet_sha256=str(packet["packet_sha256"]),
                    final_decision_sha256=final_sha,
                    command=command,
                    output_schema=author_schema,
                    attempts=attempts,
                    accepted_attempt=None,
                ),
            )
            repair_prompt = (
                "Repair only the rejected safe-pair author object below. The adjudicated "
                "decision and the schema, packet, decision, role, and model identity fields "
                "are immutable. Do not add facts or reconsider the decision. Apply the "
                "smallest complete correction for the supplied validation class. Each source "
                "must remain a standalone C11 translation unit and must use no includes, "
                "pragmas, assembly, process/network/file APIs, original function names, truth "
                "IDs, or project-specific identifiers. Return exactly the JSON schema. "
                "REPAIR_REQUEST:\n"
                + json.dumps(
                    {
                        "request": request,
                        "rejected_author": author,
                        "validation_class": validation_class,
                        "deterministic_constraints": _repair_constraints(
                            validation_class,
                            forbidden,
                            author,
                        ),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            repaired = _run_author_command(
                command,
                prompt=repair_prompt,
                env=env,
                output_schema=author_schema,
            )
            if repaired.returncode != 0:
                raise E0GovernanceError(
                    f"safe-pair author contract repair failed: {validation_class}"
                )
            assert_no_hidden_reasoning_output(repaired.stdout)
            repaired_author = dict(_extract(repaired.stdout))
            try:
                validate_author_record(
                    repaired_author,
                    truth_id=truth_id,
                    packet_sha256=str(packet["packet_sha256"]),
                    final_decision_sha256=final_sha,
                    forbidden_identifiers=forbidden,
                )
            except E0GovernanceError as repair_error:
                attempts.append(
                    _raw_attempt(
                        repaired,
                        attempt=2,
                        kind="contract_repair",
                        validation_class=_author_validation_class(repair_error),
                    )
                )
                _json_dump(
                    raw_path,
                    _raw_author_envelope(
                        truth_id=truth_id,
                        packet_sha256=str(packet["packet_sha256"]),
                        final_decision_sha256=final_sha,
                        command=command,
                        output_schema=author_schema,
                        attempts=attempts,
                        accepted_attempt=None,
                    ),
                )
                raise E0GovernanceError(
                    "safe-pair author contract repair exhausted: "
                    + _author_validation_class(repair_error)
                ) from repair_error
            attempts.append(
                _raw_attempt(
                    repaired,
                    attempt=2,
                    kind="contract_repair",
                    validation_class=None,
                )
            )
            author = repaired_author
            accepted_attempt = 2
        else:
            attempts.append(
                _raw_attempt(
                    completed,
                    attempt=1,
                    kind="initial",
                    validation_class=None,
                )
            )
            accepted_attempt = 1
        _json_dump(
            raw_path,
            _raw_author_envelope(
                truth_id=truth_id,
                packet_sha256=str(packet["packet_sha256"]),
                final_decision_sha256=final_sha,
                command=command,
                output_schema=author_schema,
                attempts=attempts,
                accepted_attempt=accepted_attempt,
            ),
        )
        _json_dump(author_path, author)
        status = "authored"
    return {
        "truth_id": truth_id,
        "packet_sha256": packet["packet_sha256"],
        "final_decision_sha256": final_sha,
        "author_sha256": sha256_file(author_path),
        "raw_sha256": sha256_file(raw_path),
        "status": status,
    }


def author_pairs(args: argparse.Namespace) -> int:
    output = args.output_dir.resolve()
    if output.exists() and not args.resume:
        raise E0GovernanceError(f"safe-pair author output already exists: {output}")
    (output / "authors").mkdir(parents=True, exist_ok=args.resume)
    (output / "raw").mkdir(exist_ok=args.resume)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        raise E0GovernanceError("safe-pair author run is already complete")
    normalized = _object(args.normalized_decisions)
    validate_normalized_decisions(normalized)
    confirmable = [
        record
        for record in normalized["records"]
        if record["final_decision"]["contract_kind"] in {"concrete_trigger", "public_api_contract"}
    ]
    packet_dir = args.packet_dir.resolve(strict=True)
    work: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for record in confirmable:
        truth_id = str(record["truth_id"])
        packet = _object(packet_dir / f"{truth_id}.json")
        validate_review_packet(packet)
        if packet.get("packet_sha256") != record.get("packet_sha256"):
            raise E0GovernanceError(f"safe-pair packet binding mismatch: {truth_id}")
        work.append((packet, record))
    records: list[dict[str, Any]] = []
    for offset in range(0, len(work), args.workers):
        batch = work[offset : offset + args.workers]
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _author_one,
                    packet,
                    record,
                    output=output,
                    resume=args.resume,
                ): str(record["truth_id"])
                for packet, record in batch
            }
            for future in as_completed(futures):
                truth_id = futures[future]
                records.append(future.result())
                print(f"safe-pair: {len(records)}/{len(work)} complete ({truth_id})", flush=True)
    records.sort(key=lambda item: str(item["truth_id"]))
    _json_dump(
        manifest_path,
        {
            "schema_version": "zscope.range-v16-safe-pair-author-run.v1",
            "author_model": AUTHOR_MODEL,
            "record_count": len(records),
            "normalized_decisions_sha256": sha256_file(args.normalized_decisions),
            "records": records,
            "content_sha256": sha256_value(records),
        },
    )
    return 0


def validate_author_run(
    *,
    author_root: Path,
    normalized_path: Path,
    expected_records: Mapping[str, Mapping[str, Any]],
    packet_dir: Path,
) -> Mapping[str, Mapping[str, Any]]:
    manifest = _object(author_root / "manifest.json")
    records = manifest.get("records")
    if (
        set(manifest)
        != {
            "schema_version",
            "author_model",
            "record_count",
            "normalized_decisions_sha256",
            "records",
            "content_sha256",
        }
        or manifest.get("schema_version") != "zscope.range-v16-safe-pair-author-run.v1"
        or manifest.get("author_model") != AUTHOR_MODEL
        or not isinstance(records, list)
        or manifest.get("record_count") != len(records)
        or len(records) != len(expected_records)
        or manifest.get("normalized_decisions_sha256")
        != sha256_file(normalized_path.resolve(strict=True))
        or manifest.get("content_sha256") != sha256_value(records)
    ):
        raise E0GovernanceError("safe-pair author run manifest is invalid")
    by_truth: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping) or set(record) != {
            "truth_id",
            "packet_sha256",
            "final_decision_sha256",
            "author_sha256",
            "raw_sha256",
            "status",
        }:
            raise E0GovernanceError("safe-pair author run record fields are invalid")
        truth_id = str(record.get("truth_id") or "")
        if truth_id not in expected_records or truth_id in by_truth:
            raise E0GovernanceError("safe-pair author run truth coverage is invalid")
        expected = expected_records[truth_id]
        packet = _object(packet_dir.resolve(strict=True) / f"{truth_id}.json")
        validate_review_packet(packet)
        if packet.get("packet_sha256") != expected.get("packet_sha256"):
            raise E0GovernanceError(f"safe-pair packet binding mismatch: {truth_id}")
        expected_author_schema = _author_schema(
            _source_identifiers(packet, truth_id),
            truth_id=truth_id,
            packet_sha256=str(expected["packet_sha256"]),
            final_decision_sha256=str(expected["final_decision_sha256"]),
        )
        if (
            record.get("packet_sha256") != expected.get("packet_sha256")
            or record.get("final_decision_sha256") != expected.get("final_decision_sha256")
            or record.get("status") not in {"authored", "reused"}
        ):
            raise E0GovernanceError(f"safe-pair author run identity mismatch: {truth_id}")
        author_path = (author_root / "authors" / f"{truth_id}.json").resolve(strict=True)
        raw_path = (author_root / "raw" / f"{truth_id}.json").resolve(strict=True)
        if author_path.is_symlink() or raw_path.is_symlink():
            raise E0GovernanceError("safe-pair author run cannot contain symlink artifacts")
        if sha256_file(author_path) != record.get("author_sha256") or sha256_file(
            raw_path
        ) != record.get("raw_sha256"):
            raise E0GovernanceError(f"safe-pair author artifact hash mismatch: {truth_id}")
        raw = _object(raw_path)
        raw_fields = {
            "schema_version",
            "truth_id",
            "packet_sha256",
            "final_decision_sha256",
            "author_model",
            "command_identity",
            "output_schema_sha256",
            "attempts",
            "accepted_attempt",
        }
        command_identity = raw.get("command_identity")
        command_valid = (
            isinstance(command_identity, list)
            and bool(command_identity)
            and command_identity[0] in {"codex", "codex.cmd"}
            and command_identity[1:] == _codex_arguments(output_schema="author-schema.json")
        )
        if (
            set(raw) != raw_fields
            or raw.get("schema_version") != RAW_AUTHOR_SCHEMA_VERSION
            or raw.get("truth_id") != truth_id
            or raw.get("packet_sha256") != expected.get("packet_sha256")
            or raw.get("final_decision_sha256") != expected.get("final_decision_sha256")
            or raw.get("author_model") != AUTHOR_MODEL
            or raw.get("output_schema_sha256") != sha256_value(expected_author_schema)
            or not command_valid
        ):
            raise E0GovernanceError(f"safe-pair raw author envelope is invalid: {truth_id}")
        attempts = raw.get("attempts")
        accepted_attempt = raw.get("accepted_attempt")
        if (
            not isinstance(attempts, list)
            or len(attempts) not in {1, 2}
            or accepted_attempt != len(attempts)
        ):
            raise E0GovernanceError(f"safe-pair raw author attempts are invalid: {truth_id}")
        for index, attempt in enumerate(attempts, start=1):
            expected_kind = "initial" if index == 1 else "contract_repair"
            validation_class = (
                attempt.get("validation_class") if isinstance(attempt, Mapping) else None
            )
            expected_validation = index < len(attempts)
            if (
                not isinstance(attempt, Mapping)
                or set(attempt)
                != {
                    "attempt",
                    "kind",
                    "exit_code",
                    "stdout",
                    "stderr_sha256",
                    "validation_class",
                }
                or attempt.get("attempt") != index
                or attempt.get("kind") != expected_kind
                or attempt.get("exit_code") != 0
                or not isinstance(attempt.get("stdout"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", str(attempt.get("stderr_sha256") or ""))
                or (
                    expected_validation
                    and validation_class not in _REPAIRABLE_AUTHOR_VALIDATION_CLASSES
                )
                or (not expected_validation and validation_class is not None)
            ):
                raise E0GovernanceError(f"safe-pair raw author attempt is invalid: {truth_id}")
            assert_no_hidden_reasoning_output(str(attempt["stdout"]))
        accepted_author = dict(_extract(str(attempts[-1]["stdout"])))
        if accepted_author != _object(author_path):
            raise E0GovernanceError(f"safe-pair raw accepted author binding is invalid: {truth_id}")
        by_truth[truth_id] = record
    if set(by_truth) != set(expected_records):
        raise E0GovernanceError("safe-pair author run is incomplete")
    return by_truth


def materialize_pairs(args: argparse.Namespace) -> int:
    output = args.output_dir.resolve()
    if output.exists():
        raise E0GovernanceError(f"safe-pair output already exists: {output}")
    normalized = _object(args.normalized_decisions)
    validate_normalized_decisions(normalized)
    records = {
        str(record["truth_id"]): record
        for record in normalized["records"]
        if record["final_decision"]["contract_kind"] in {"concrete_trigger", "public_api_contract"}
    }
    author_root = args.author_dir.resolve(strict=True)
    validate_author_run(
        author_root=author_root,
        normalized_path=args.normalized_decisions,
        expected_records=records,
        packet_dir=args.packet_dir,
    )
    output.mkdir(parents=True)
    for truth_id, record in sorted(records.items()):
        author_path = author_root / "authors" / f"{truth_id}.json"
        author = _object(author_path)
        packet = _object(args.packet_dir.resolve(strict=True) / f"{truth_id}.json")
        validate_author_record(
            author,
            truth_id=truth_id,
            packet_sha256=str(record["packet_sha256"]),
            final_decision_sha256=str(record["final_decision_sha256"]),
            forbidden_identifiers=_source_identifiers(packet, truth_id),
        )
        pair_root = output / truth_id
        vulnerable_path = pair_root / "vulnerable" / "case.c"
        safe_path = pair_root / "fixed_or_near_miss" / "case.c"
        vulnerable_path.parent.mkdir(parents=True)
        safe_path.parent.mkdir(parents=True)
        vulnerable_path.write_bytes(
            str(author["vulnerable_source"])
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .encode("utf-8")
        )
        safe_path.write_bytes(
            str(author["fixed_or_near_miss_source"])
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .encode("utf-8")
        )
        pair_manifest: dict[str, Any] = {
            "schema_version": "zscope.range-v16-safe-pair.v1",
            "truth_id": truth_id,
            "pair_uid": f"range-v16-pair:{truth_id}",
            "contract_kind": record["final_decision"]["contract_kind"],
            "kind": author["kind"],
            "invariant_summary": author["invariant_summary"],
            "review_decision_sha256": record["final_decision_sha256"],
            "compiler_contract": {
                "language": "c",
                "standard": "c11",
                "compiler": args.compiler,
                "arguments": [],
            },
            "vulnerable": {
                "path": "vulnerable/case.c",
                "sha256": sha256_file(vulnerable_path),
            },
            "fixed_or_near_miss": {
                "path": "fixed_or_near_miss/case.c",
                "sha256": sha256_file(safe_path),
            },
            "content_sha256": "",
        }
        unsigned = dict(pair_manifest)
        unsigned.pop("content_sha256")
        pair_manifest["content_sha256"] = sha256_value(unsigned)
        _json_dump(pair_root / "manifest.json", pair_manifest)
        validate_pair_manifest(pair_manifest, pair_root=pair_root)
        if args.compile:
            compile_pair_manifest(pair_manifest, pair_root=pair_root)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    author = sub.add_parser("author")
    author.add_argument("--packet-dir", required=True, type=Path)
    author.add_argument("--normalized-decisions", required=True, type=Path)
    author.add_argument("--output-dir", required=True, type=Path)
    author.add_argument("--workers", type=int, choices=range(1, 9), default=4)
    author.add_argument("--resume", action="store_true")
    author.set_defaults(handler=author_pairs)
    materialize = sub.add_parser("materialize")
    materialize.add_argument("--packet-dir", required=True, type=Path)
    materialize.add_argument("--normalized-decisions", required=True, type=Path)
    materialize.add_argument("--author-dir", required=True, type=Path)
    materialize.add_argument("--output-dir", required=True, type=Path)
    materialize.add_argument("--compiler", choices=("cc", "gcc", "clang"), default="cc")
    materialize.add_argument("--compile", action="store_true")
    materialize.set_defaults(handler=materialize_pairs)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (E0GovernanceError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"Range v16 safe-pair generation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
