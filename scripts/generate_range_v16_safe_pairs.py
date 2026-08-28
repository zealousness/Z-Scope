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
    _codex_transport_schema,
    _reviewer_environment,
    assert_no_hidden_reasoning_output,
)


AUTHOR_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author.v1"
AUTHOR_REQUEST_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author-request.v1"
RAW_AUTHOR_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author-raw.v5"
AUTHOR_FAILURE_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author-failure.v1"
AUTHOR_CHECKPOINT_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author-checkpoint.v1"
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
    "independent_compile_failure",
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

_AUTHOR_SOURCE_FIELDS = ("vulnerable_source", "fixed_or_near_miss_source")
_AUTHOR_COMPILER_ARGUMENTS = ("-std=c11", "-Werror", "-Wall", "-Wextra", "-c")


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
        truth_id_schema = {"type": "string", "const": truth_id}
        packet_sha256_schema = {
            "type": "string",
            "const": packet_sha256,
            "pattern": "^[0-9a-f]{64}$",
        }
        final_decision_sha256_schema = {
            "type": "string",
            "const": final_decision_sha256,
            "pattern": "^[0-9a-f]{64}$",
        }
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
            "schema_version": {"type": "string", "const": AUTHOR_SCHEMA_VERSION},
            "truth_id": truth_id_schema,
            "packet_sha256": packet_sha256_schema,
            "final_decision_sha256": final_decision_sha256_schema,
            "author_role": {"type": "string", "const": "safe_pair_author"},
            "author_model": {"type": "string", "const": AUTHOR_MODEL},
            "kind": {"type": "string", "enum": ["fixed", "near_miss"]},
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


def _author_request(
    packet: Mapping[str, Any], normalized_record: Mapping[str, Any]
) -> dict[str, Any]:
    """Project the immutable adjudication into the least-authority author input."""

    decision = normalized_record.get("final_decision")
    if not isinstance(decision, Mapping):
        raise E0GovernanceError("safe-pair final decision is invalid")
    recommendation = decision.get("safe_pair_recommendation")
    if not isinstance(recommendation, Mapping):
        raise E0GovernanceError("safe-pair recommendation is invalid")
    return {
        "schema_version": AUTHOR_REQUEST_SCHEMA_VERSION,
        "truth_id": normalized_record["truth_id"],
        "packet_uid": normalized_record["packet_uid"],
        "packet_sha256": normalized_record["packet_sha256"],
        "final_decision_sha256": normalized_record["final_decision_sha256"],
        "contract_kind": decision["contract_kind"],
        "safe_pair_recommendation": dict(recommendation),
    }


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
    *,
    validation_error: E0GovernanceError | None = None,
    compiler: str | None = None,
) -> Mapping[str, Any]:
    if validation_class == "independent_compile_failure":
        failing_fields = (
            list(validation_error.failing_source_fields)
            if isinstance(validation_error, _SafePairCompilationError)
            else list(_AUTHOR_SOURCE_FIELDS)
        )
        return {
            "compiler_contract": {
                "language": "c",
                "standard": "c11",
                "compiler": compiler or "cc",
                "arguments": list(_AUTHOR_COMPILER_ARGUMENTS[1:]),
            },
            "failing_source_fields": failing_fields,
            "required_postcondition": (
                "both complete source fields compile independently with the frozen compiler "
                "contract and zero warnings promoted to errors"
            ),
            "required_correction": (
                "Apply the smallest source-only correction needed for every failing field to "
                "compile cleanly. Remove or use unused declarations, preserve exactly one "
                "reachable int main(void), and do not change identity fields, the adjudicated "
                "invariant, or add facts beyond the frozen request."
            ),
        }
    if validation_class == "sources_identical":
        vulnerable = rejected_author.get("vulnerable_source")
        fixed = rejected_author.get("fixed_or_near_miss_source")
        normalized_equal = (
            isinstance(vulnerable, str)
            and isinstance(fixed, str)
            and vulnerable.replace("\r\n", "\n").replace("\r", "\n")
            == fixed.replace("\r\n", "\n").replace("\r", "\n")
        )
        return {
            "detected_condition": (
                "sources_equal_after_newline_normalization"
                if normalized_equal
                else "sources_reported_identical_by_validator"
            ),
            "required_postcondition": (
                "vulnerable_source and fixed_or_near_miss_source differ after normalizing "
                "CRLF and CR newlines to LF"
            ),
            "required_correction": (
                "Keep vulnerable_source as the minimal violating baseline. Rewrite only "
                "fixed_or_near_miss_source so it applies exactly the frozen request's "
                "safe_pair_recommendation to the same minimal setup. The difference must "
                "change the reviewed behavior; comments, formatting, identifier renaming, "
                "or unreachable code alone do not satisfy this correction. Do not alter "
                "identity fields or add facts beyond the frozen request."
            ),
        }
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


class _SafePairCompilationError(E0GovernanceError):
    def __init__(self, failing_source_fields: Sequence[str]) -> None:
        self.failing_source_fields = tuple(failing_source_fields)
        super().__init__(
            "safe-pair author independent compilation failed: "
            + ",".join(self.failing_source_fields)
        )


def _compile_author_source_fields(
    value: Mapping[str, Any],
    *,
    compiler: str,
) -> tuple[str, ...]:
    compiler_path = shutil.which(compiler)
    if not compiler_path:
        raise E0GovernanceError("safe-pair author compiler is unavailable")
    failing: list[str] = []
    for field in _AUTHOR_SOURCE_FIELDS:
        source = value.get(field)
        if not isinstance(source, str):
            raise E0GovernanceError(f"safe-pair author {field} is invalid")
        with tempfile.TemporaryDirectory(prefix="zscope-e0-pair-compile-") as raw_temp:
            source_path = Path(raw_temp) / "case.c"
            output_path = Path(raw_temp) / "case.o"
            source_path.write_text(
                source.replace("\r\n", "\n").replace("\r", "\n"),
                encoding="utf-8",
            )
            try:
                completed = subprocess.run(
                    [
                        str(compiler_path),
                        *_AUTHOR_COMPILER_ARGUMENTS,
                        str(source_path),
                        "-o",
                        str(output_path),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise E0GovernanceError("safe-pair author compiler execution failed") from exc
            if completed.returncode != 0 or not output_path.is_file():
                failing.append(field)
    return tuple(failing)


def validate_author_record(
    value: Mapping[str, Any],
    *,
    truth_id: str,
    packet_sha256: str,
    final_decision_sha256: str,
    forbidden_identifiers: set[str],
    compiler: str | None = None,
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
    for field in _AUTHOR_SOURCE_FIELDS:
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
    if compiler is not None:
        failing_fields = _compile_author_source_fields(value, compiler=compiler)
        if failing_fields:
            raise _SafePairCompilationError(failing_fields)


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
        ("independent compilation failed", "independent_compile_failure"),
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


def _transport_retry_signal(
    completed: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    return {
        "initial_exit_code": completed.returncode,
        "initial_stdout_sha256": sha256_value(completed.stdout),
        "initial_stdout_retained": False,
        "initial_stderr_sha256": sha256_value(completed.stderr),
    }


def _raw_author_envelope(
    *,
    truth_id: str,
    packet_sha256: str,
    final_decision_sha256: str,
    command: Sequence[str],
    output_schema: Mapping[str, Any],
    contract_schema: Mapping[str, Any],
    author_request: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    accepted_attempt: int | None,
    transport_retry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "schema_version": RAW_AUTHOR_SCHEMA_VERSION,
        "truth_id": truth_id,
        "packet_sha256": packet_sha256,
        "final_decision_sha256": final_decision_sha256,
        "author_model": AUTHOR_MODEL,
        "command_identity": [Path(command[0]).name, *command[1:]],
        "output_schema_sha256": sha256_value(output_schema),
        "contract_schema_sha256": sha256_value(contract_schema),
        "author_request_schema_version": AUTHOR_REQUEST_SCHEMA_VERSION,
        "author_request_sha256": sha256_value(author_request),
        "attempts": list(attempts),
        "accepted_attempt": accepted_attempt,
    }
    if transport_retry is not None:
        envelope["transport_retry"] = dict(transport_retry)
    return envelope


class _SafePairAuthorProcessError(E0GovernanceError):
    def __init__(
        self,
        truth_id: str,
        *,
        initial: Mapping[str, Any],
        retry: subprocess.CompletedProcess[str],
    ) -> None:
        self.failure_record = {
            "truth_id": truth_id,
            "failure_code": "reviewer_process_nonzero",
            **dict(initial),
            "retry_exit_code": retry.returncode,
            "retry_stdout_sha256": sha256_value(retry.stdout),
            "retry_stdout_retained": False,
            "retry_stderr_sha256": sha256_value(retry.stderr),
            "answer_material_present": False,
        }
        super().__init__(
            f"safe-pair author failed after transport retry: {truth_id}; "
            f"stderr_sha256={self.failure_record['retry_stderr_sha256']}"
        )


def _validate_transport_retry(value: Any) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "initial_exit_code",
            "initial_stdout_sha256",
            "initial_stdout_retained",
            "initial_stderr_sha256",
        }
        or not isinstance(value.get("initial_exit_code"), int)
        or isinstance(value.get("initial_exit_code"), bool)
        or value.get("initial_exit_code") == 0
        or value.get("initial_stdout_retained") is not False
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", str(value.get(field) or ""))
            for field in ("initial_stdout_sha256", "initial_stderr_sha256")
        )
    ):
        raise E0GovernanceError("safe-pair author transport retry is invalid")


def _validate_raw_author_envelope(
    raw: Mapping[str, Any],
    author: Mapping[str, Any],
    *,
    truth_id: str,
    packet: Mapping[str, Any],
    normalized_record: Mapping[str, Any],
) -> None:
    forbidden = _source_identifiers(packet, truth_id)
    expected_author_schema = _author_schema(
        forbidden,
        truth_id=truth_id,
        packet_sha256=str(normalized_record["packet_sha256"]),
        final_decision_sha256=str(normalized_record["final_decision_sha256"]),
    )
    expected_output_schema = _codex_transport_schema(expected_author_schema)
    expected_author_request = _author_request(packet, normalized_record)
    raw_fields = {
        "schema_version",
        "truth_id",
        "packet_sha256",
        "final_decision_sha256",
        "author_model",
        "command_identity",
        "output_schema_sha256",
        "contract_schema_sha256",
        "author_request_schema_version",
        "author_request_sha256",
        "attempts",
        "accepted_attempt",
    }
    if "transport_retry" in raw:
        raw_fields.add("transport_retry")
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
        or raw.get("packet_sha256") != normalized_record.get("packet_sha256")
        or raw.get("final_decision_sha256") != normalized_record.get("final_decision_sha256")
        or raw.get("author_model") != AUTHOR_MODEL
        or raw.get("output_schema_sha256") != sha256_value(expected_output_schema)
        or raw.get("contract_schema_sha256") != sha256_value(expected_author_schema)
        or raw.get("author_request_schema_version") != AUTHOR_REQUEST_SCHEMA_VERSION
        or raw.get("author_request_sha256") != sha256_value(expected_author_request)
        or not command_valid
    ):
        raise E0GovernanceError(f"safe-pair raw author envelope is invalid: {truth_id}")
    if "transport_retry" in raw:
        _validate_transport_retry(raw["transport_retry"])
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
        validation_class = attempt.get("validation_class") if isinstance(attempt, Mapping) else None
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
    if accepted_author != dict(author):
        raise E0GovernanceError(f"safe-pair raw accepted author binding is invalid: {truth_id}")


def _validated_existing_author_pair(
    root: Path,
    packet: Mapping[str, Any],
    normalized_record: Mapping[str, Any],
    *,
    status: str,
    compiler: str | None = None,
) -> dict[str, Any]:
    truth_id = str(normalized_record["truth_id"])
    author_dir = root / "authors"
    raw_dir = root / "raw"
    author_candidate = author_dir / f"{truth_id}.json"
    raw_candidate = raw_dir / f"{truth_id}.json"
    if (
        author_dir.is_symlink()
        or raw_dir.is_symlink()
        or author_candidate.is_symlink()
        or raw_candidate.is_symlink()
    ):
        raise E0GovernanceError("safe-pair author run cannot contain symlink artifacts")
    author_path = author_candidate.resolve(strict=True)
    raw_path = raw_candidate.resolve(strict=True)
    if author_path.parent != author_dir.resolve(strict=True) or raw_path.parent != raw_dir.resolve(
        strict=True
    ):
        raise E0GovernanceError("safe-pair author artifact escaped its bound directory")
    author = _object(author_path)
    validate_author_record(
        author,
        truth_id=truth_id,
        packet_sha256=str(normalized_record["packet_sha256"]),
        final_decision_sha256=str(normalized_record["final_decision_sha256"]),
        forbidden_identifiers=_source_identifiers(packet, truth_id),
        compiler=compiler,
    )
    raw = _object(raw_path)
    _validate_raw_author_envelope(
        raw,
        author,
        truth_id=truth_id,
        packet=packet,
        normalized_record=normalized_record,
    )
    return {
        "truth_id": truth_id,
        "packet_sha256": normalized_record["packet_sha256"],
        "final_decision_sha256": normalized_record["final_decision_sha256"],
        "author_sha256": sha256_file(author_path),
        "raw_sha256": sha256_file(raw_path),
        "status": status,
    }


def _author_one(
    packet: Mapping[str, Any],
    normalized_record: Mapping[str, Any],
    *,
    output: Path,
    resume: bool,
    compiler: str | None = None,
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
        return _validated_existing_author_pair(
            output,
            packet,
            normalized_record,
            status="reused",
            compiler=compiler,
        )
    else:
        codex = shutil.which("codex.cmd" if os.name == "nt" else "codex")
        if not codex:
            raise E0GovernanceError("Codex CLI executable is unavailable")
        request = _author_request(packet, normalized_record)
        prompt = (
            "This is authorized defensive static-analysis benchmark construction. Author a "
            "minimal anonymous vulnerable/fixed-or-near-miss C11 pair only from the frozen, "
            "already-adjudicated contract below. Do not reconsider or change the decision, "
            "provide exploitation guidance, or introduce any real target details. Each source "
            "must be an inert, local-only standalone translation unit, use no includes, pragmas, "
            "assembly, process/network/file APIs, original function names, truth IDs, or "
            "project-specific identifiers. Use generic names. Both sides must compile with "
            "-std=c11 -Wall -Wextra -Werror; express only the reviewed invariant and include "
            "int main(void). Return exactly the JSON schema. REQUEST:\n"
            + json.dumps(request, ensure_ascii=False, sort_keys=True)
        )
        contract_schema = _author_schema(
            forbidden,
            truth_id=truth_id,
            packet_sha256=str(packet["packet_sha256"]),
            final_decision_sha256=final_sha,
        )
        output_schema = _codex_transport_schema(contract_schema)
        command = [
            str(codex),
            *_codex_arguments(output_schema="author-schema.json"),
        ]
        env = _reviewer_environment()
        completed = _run_author_command(
            command,
            prompt=prompt,
            env=env,
            output_schema=output_schema,
        )
        transport_retry: dict[str, Any] | None = None
        if completed.returncode != 0:
            transport_retry = _transport_retry_signal(completed)
            completed = _run_author_command(
                command,
                prompt=prompt,
                env=env,
                output_schema=output_schema,
            )
        if completed.returncode != 0:
            if transport_retry is None:
                raise E0GovernanceError("safe-pair transport retry state is invalid")
            raise _SafePairAuthorProcessError(
                truth_id,
                initial=transport_retry,
                retry=completed,
            )
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
                compiler=compiler,
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
                    output_schema=output_schema,
                    contract_schema=contract_schema,
                    author_request=request,
                    attempts=attempts,
                    accepted_attempt=None,
                    transport_retry=transport_retry,
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
                            validation_error=error,
                            compiler=compiler,
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
                output_schema=output_schema,
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
                    compiler=compiler,
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
                        output_schema=output_schema,
                        contract_schema=contract_schema,
                        author_request=request,
                        attempts=attempts,
                        accepted_attempt=None,
                        transport_retry=transport_retry,
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
                output_schema=output_schema,
                contract_schema=contract_schema,
                author_request=request,
                attempts=attempts,
                accepted_attempt=accepted_attempt,
                transport_retry=transport_retry,
            ),
        )
        _json_dump(author_path, author)
        status = "authored"
    return _validated_existing_author_pair(
        output,
        packet,
        normalized_record,
        status=status,
        compiler=compiler,
    )


def _confirmable_work(
    normalized: Mapping[str, Any],
    *,
    packet_dir: Path,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    work: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for record in normalized["records"]:
        if record["final_decision"]["contract_kind"] not in {
            "concrete_trigger",
            "public_api_contract",
        }:
            continue
        truth_id = str(record["truth_id"])
        packet = _object(packet_dir / f"{truth_id}.json")
        validate_review_packet(packet)
        if packet.get("packet_sha256") != record.get("packet_sha256"):
            raise E0GovernanceError(f"safe-pair packet binding mismatch: {truth_id}")
        work.append((packet, record))
    return work


def _failure_manifest_content_sha256(value: Mapping[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("content_sha256", None)
    return str(sha256_value(unsigned))


def _failure_code(exc: BaseException) -> str:
    if isinstance(exc, _SafePairAuthorProcessError):
        return "reviewer_process_nonzero"
    message = str(exc)
    if "contract repair" in message:
        return "contract_repair_failure"
    if isinstance(exc, (json.JSONDecodeError, UnicodeError)):
        return "reviewer_output_invalid"
    if isinstance(exc, subprocess.TimeoutExpired):
        return "reviewer_timeout"
    if isinstance(exc, E0GovernanceError):
        return "author_contract_failure"
    return "author_harness_failure"


def _author_failure_record(truth_id: str, exc: BaseException) -> dict[str, Any]:
    process = exc.failure_record if isinstance(exc, _SafePairAuthorProcessError) else {}
    record = {
        "truth_id": truth_id,
        "failure_code": _failure_code(exc),
        "error_sha256": sha256_value(str(exc)),
        "initial_exit_code": process.get("initial_exit_code"),
        "initial_stdout_sha256": process.get("initial_stdout_sha256"),
        "initial_stdout_retained": process.get("initial_stdout_retained", False),
        "initial_stderr_sha256": process.get("initial_stderr_sha256"),
        "retry_exit_code": process.get("retry_exit_code"),
        "retry_stdout_sha256": process.get("retry_stdout_sha256"),
        "retry_stdout_retained": process.get("retry_stdout_retained", False),
        "retry_stderr_sha256": process.get("retry_stderr_sha256"),
        "answer_material_present": False,
    }
    return record


def _validate_failure_record(value: Any) -> None:
    fields = {
        "truth_id",
        "failure_code",
        "error_sha256",
        "initial_exit_code",
        "initial_stdout_sha256",
        "initial_stdout_retained",
        "initial_stderr_sha256",
        "retry_exit_code",
        "retry_stdout_sha256",
        "retry_stdout_retained",
        "retry_stderr_sha256",
        "answer_material_present",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or not isinstance(value.get("truth_id"), str)
        or not value["truth_id"]
        or value.get("failure_code")
        not in {
            "reviewer_process_nonzero",
            "contract_repair_failure",
            "reviewer_output_invalid",
            "reviewer_timeout",
            "author_contract_failure",
            "author_harness_failure",
        }
        or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("error_sha256") or ""))
        or value.get("initial_stdout_retained") is not False
        or value.get("retry_stdout_retained") is not False
        or value.get("answer_material_present") is not False
    ):
        raise E0GovernanceError("safe-pair failure record is invalid")
    transport_fields = (
        "initial_stdout_sha256",
        "initial_stderr_sha256",
        "retry_stdout_sha256",
        "retry_stderr_sha256",
    )
    if value["failure_code"] == "reviewer_process_nonzero":
        if (
            not isinstance(value.get("initial_exit_code"), int)
            or isinstance(value.get("initial_exit_code"), bool)
            or value.get("initial_exit_code") == 0
            or not isinstance(value.get("retry_exit_code"), int)
            or isinstance(value.get("retry_exit_code"), bool)
            or value.get("retry_exit_code") == 0
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", str(value.get(field) or ""))
                for field in transport_fields
            )
        ):
            raise E0GovernanceError("safe-pair transport failure record is invalid")
    elif any(value.get(field) is not None for field in transport_fields) or any(
        value.get(field) is not None for field in ("initial_exit_code", "retry_exit_code")
    ):
        raise E0GovernanceError("safe-pair non-transport failure signals are invalid")


def _write_failure_manifest(
    output: Path,
    *,
    normalized_sha256: str,
    expected_record_count: int,
    verified_record_count: int,
    failure_records: Sequence[Mapping[str, Any]],
) -> None:
    ordered = sorted(
        (dict(record) for record in failure_records), key=lambda item: item["truth_id"]
    )
    for record in ordered:
        _validate_failure_record(record)
    manifest = {
        "schema_version": AUTHOR_FAILURE_SCHEMA_VERSION,
        "author_model": AUTHOR_MODEL,
        "normalized_decisions_sha256": normalized_sha256,
        "expected_record_count": expected_record_count,
        "verified_record_count": verified_record_count,
        "failure_record_count": len(ordered),
        "failure_records": ordered,
        "diagnostic_answer_material_present": False,
        "requires_resume_revalidation": True,
    }
    manifest["content_sha256"] = _failure_manifest_content_sha256(manifest)
    _json_dump(output / "failure-manifest.json", manifest)


def _load_failure_manifest(
    path: Path,
    *,
    normalized_sha256: str,
    expected_record_count: int,
) -> list[Mapping[str, Any]]:
    if not path.is_file():
        return []
    manifest = _object(path)
    fields = {
        "schema_version",
        "author_model",
        "normalized_decisions_sha256",
        "expected_record_count",
        "verified_record_count",
        "failure_record_count",
        "failure_records",
        "diagnostic_answer_material_present",
        "requires_resume_revalidation",
        "content_sha256",
    }
    records = manifest.get("failure_records")
    if (
        set(manifest) != fields
        or manifest.get("schema_version") != AUTHOR_FAILURE_SCHEMA_VERSION
        or manifest.get("author_model") != AUTHOR_MODEL
        or manifest.get("normalized_decisions_sha256") != normalized_sha256
        or manifest.get("expected_record_count") != expected_record_count
        or not isinstance(manifest.get("verified_record_count"), int)
        or not isinstance(records, list)
        or manifest.get("failure_record_count") != len(records)
        or manifest.get("diagnostic_answer_material_present") is not False
        or manifest.get("requires_resume_revalidation") is not True
        or manifest.get("content_sha256") != _failure_manifest_content_sha256(manifest)
    ):
        raise E0GovernanceError("safe-pair failure manifest is invalid")
    seen: set[str] = set()
    for record in records:
        _validate_failure_record(record)
        truth_id = str(record["truth_id"])
        if truth_id in seen:
            raise E0GovernanceError("safe-pair failure record is duplicated")
        seen.add(truth_id)
    return records


def _checkpoint_manifest_content_sha256(value: Mapping[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("content_sha256", None)
    return str(sha256_value(unsigned))


def build_author_checkpoint(args: argparse.Namespace) -> int:
    if os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") != "sealed-benchmark":
        raise E0GovernanceError("safe-pair checkpoint requires sealed-benchmark environment")
    if not re.fullmatch(r"[0-9a-f]{40}", str(args.packet_source_sha)):
        raise E0GovernanceError("safe-pair checkpoint packet source SHA is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(args.retained_source_sha)):
        raise E0GovernanceError("safe-pair checkpoint retained source SHA is invalid")
    if args.packet_source_sha != args.retained_source_sha:
        raise E0GovernanceError("safe-pair checkpoint cannot cross source commits")
    if not str(args.workflow_run_id).isdigit():
        raise E0GovernanceError("safe-pair checkpoint workflow run ID is invalid")
    retained = args.retained_dir.resolve(strict=True)
    compiler = getattr(args, "compiler", None)
    output = args.output_dir.resolve()
    if output.exists():
        raise E0GovernanceError(f"safe-pair checkpoint output already exists: {output}")
    normalized = _object(args.normalized_decisions)
    validate_normalized_decisions(normalized)
    normalized_sha256 = sha256_file(args.normalized_decisions)
    work = _confirmable_work(normalized, packet_dir=args.packet_dir.resolve(strict=True))
    output.mkdir(parents=True)
    (output / "authors").mkdir()
    (output / "raw").mkdir()
    verified: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    incomplete: list[dict[str, Any]] = []
    for packet, record in work:
        truth_id = str(record["truth_id"])
        author_path = retained / "authors" / f"{truth_id}.json"
        raw_path = retained / "raw" / f"{truth_id}.json"
        if not author_path.exists() and not raw_path.exists():
            continue
        if not author_path.is_file() or not raw_path.is_file():
            incomplete.append(
                {
                    "truth_id": truth_id,
                    "author_present": author_path.is_file(),
                    "raw_present": raw_path.is_file(),
                }
            )
            continue
        try:
            verified_record = _validated_existing_author_pair(
                retained,
                packet,
                record,
                status="reused",
                compiler=compiler,
            )
        except (E0GovernanceError, OSError, json.JSONDecodeError) as exc:
            invalid.append({"truth_id": truth_id, "error_sha256": sha256_value(str(exc))})
            continue
        shutil.copy2(author_path, output / "authors" / author_path.name)
        shutil.copy2(raw_path, output / "raw" / raw_path.name)
        verified.append(verified_record)
    failure_records = _load_failure_manifest(
        retained / "failure-manifest.json",
        normalized_sha256=normalized_sha256,
        expected_record_count=len(work),
    )
    verified.sort(key=lambda item: item["truth_id"])
    invalid.sort(key=lambda item: item["truth_id"])
    incomplete.sort(key=lambda item: item["truth_id"])
    manifest = {
        "schema_version": AUTHOR_CHECKPOINT_SCHEMA_VERSION,
        "author_model": AUTHOR_MODEL,
        "packet_source_sha": args.packet_source_sha,
        "retained_source_sha": args.retained_source_sha,
        "workflow_run_id": str(args.workflow_run_id),
        "normalized_decisions_sha256": normalized_sha256,
        "expected_record_count": len(work),
        "verified_record_count": len(verified),
        "verified_records": verified,
        "invalid_records": invalid,
        "incomplete_records": incomplete,
        "failure_records": list(failure_records),
        "checkpoint_contains_author_material": bool(verified),
        "diagnostic_answer_material_present": False,
        "requires_resume_revalidation": True,
    }
    manifest["content_sha256"] = _checkpoint_manifest_content_sha256(manifest)
    _json_dump(output / "checkpoint-manifest.json", manifest)
    return 0


def _validate_author_checkpoint(
    root: Path,
    *,
    normalized_path: Path,
    packet_dir: Path,
    packet_source_sha: str,
    workflow_run_id: str,
    compiler: str | None = None,
) -> None:
    normalized = _object(normalized_path)
    validate_normalized_decisions(normalized)
    work = _confirmable_work(normalized, packet_dir=packet_dir.resolve(strict=True))
    manifest = _object(root / "checkpoint-manifest.json")
    fields = {
        "schema_version",
        "author_model",
        "packet_source_sha",
        "retained_source_sha",
        "workflow_run_id",
        "normalized_decisions_sha256",
        "expected_record_count",
        "verified_record_count",
        "verified_records",
        "invalid_records",
        "incomplete_records",
        "failure_records",
        "checkpoint_contains_author_material",
        "diagnostic_answer_material_present",
        "requires_resume_revalidation",
        "content_sha256",
    }
    verified = manifest.get("verified_records")
    if (
        set(manifest) != fields
        or manifest.get("schema_version") != AUTHOR_CHECKPOINT_SCHEMA_VERSION
        or manifest.get("author_model") != AUTHOR_MODEL
        or manifest.get("packet_source_sha") != packet_source_sha
        or manifest.get("retained_source_sha") != packet_source_sha
        or manifest.get("workflow_run_id") != workflow_run_id
        or manifest.get("normalized_decisions_sha256") != sha256_file(normalized_path)
        or manifest.get("expected_record_count") != len(work)
        or not isinstance(verified, list)
        or manifest.get("verified_record_count") != len(verified)
        or not isinstance(manifest.get("invalid_records"), list)
        or not isinstance(manifest.get("incomplete_records"), list)
        or not isinstance(manifest.get("failure_records"), list)
        or manifest.get("checkpoint_contains_author_material") is not bool(verified)
        or manifest.get("diagnostic_answer_material_present") is not False
        or manifest.get("requires_resume_revalidation") is not True
        or manifest.get("content_sha256") != _checkpoint_manifest_content_sha256(manifest)
    ):
        raise E0GovernanceError("safe-pair checkpoint manifest is invalid")
    by_truth = {str(record["truth_id"]): (packet, record) for packet, record in work}
    seen: set[str] = set()
    for checkpoint_record in verified:
        if not isinstance(checkpoint_record, Mapping):
            raise E0GovernanceError("safe-pair checkpoint verified record is invalid")
        truth_id = str(checkpoint_record.get("truth_id") or "")
        if truth_id not in by_truth or truth_id in seen:
            raise E0GovernanceError("safe-pair checkpoint truth coverage is invalid")
        packet, normalized_record = by_truth[truth_id]
        actual = _validated_existing_author_pair(
            root,
            packet,
            normalized_record,
            status="reused",
            compiler=compiler,
        )
        if actual != dict(checkpoint_record):
            raise E0GovernanceError("safe-pair checkpoint record binding is invalid")
        seen.add(truth_id)
    author_names = {path.stem for path in (root / "authors").glob("*.json")}
    raw_names = {path.stem for path in (root / "raw").glob("*.json")}
    if author_names != seen or raw_names != seen:
        raise E0GovernanceError("safe-pair checkpoint contains unbound author files")
    for record in manifest["failure_records"]:
        _validate_failure_record(record)
        if str(record["truth_id"]) not in by_truth:
            raise E0GovernanceError("safe-pair checkpoint failure record is unbound")
    for record in manifest["invalid_records"]:
        if (
            not isinstance(record, Mapping)
            or set(record) != {"truth_id", "error_sha256"}
            or str(record.get("truth_id") or "") not in by_truth
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("error_sha256") or ""))
        ):
            raise E0GovernanceError("safe-pair checkpoint invalid record is invalid")
    for record in manifest["incomplete_records"]:
        if (
            not isinstance(record, Mapping)
            or set(record) != {"truth_id", "author_present", "raw_present"}
            or str(record.get("truth_id") or "") not in by_truth
            or not isinstance(record.get("author_present"), bool)
            or not isinstance(record.get("raw_present"), bool)
            or record["author_present"] == record["raw_present"]
        ):
            raise E0GovernanceError("safe-pair checkpoint incomplete record is invalid")


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
    packet_dir = args.packet_dir.resolve(strict=True)
    compiler = getattr(args, "compiler", None)
    work = _confirmable_work(normalized, packet_dir=packet_dir)
    checkpoint_source_sha = getattr(args, "checkpoint_source_sha", None)
    checkpoint_workflow_run_id = getattr(args, "checkpoint_workflow_run_id", None)
    if args.resume:
        if checkpoint_source_sha is None or checkpoint_workflow_run_id is None:
            raise E0GovernanceError("safe-pair resume requires a bound checkpoint")
        _validate_author_checkpoint(
            output,
            normalized_path=args.normalized_decisions,
            packet_dir=packet_dir,
            packet_source_sha=str(checkpoint_source_sha),
            workflow_run_id=str(checkpoint_workflow_run_id),
            compiler=compiler,
        )
        (output / "checkpoint-manifest.json").unlink()
    elif checkpoint_source_sha is not None or checkpoint_workflow_run_id is not None:
        raise E0GovernanceError("safe-pair checkpoint validation requires resume mode")
    records: list[dict[str, Any]] = []
    for offset in range(0, len(work), args.workers):
        batch = work[offset : offset + args.workers]
        failures: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _author_one,
                    packet,
                    record,
                    output=output,
                    resume=args.resume,
                    compiler=compiler,
                ): str(record["truth_id"])
                for packet, record in batch
            }
            for future in as_completed(futures):
                truth_id = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    failures.append(_author_failure_record(truth_id, exc))
                    continue
                records.append(result)
                print(
                    f"safe-pair: {len(records)}/{len(work)} complete ({truth_id})",
                    flush=True,
                )
        if failures:
            _write_failure_manifest(
                output,
                normalized_sha256=sha256_file(args.normalized_decisions),
                expected_record_count=len(work),
                verified_record_count=len(records),
                failure_records=failures,
            )
            first = sorted(failures, key=lambda item: item["truth_id"])[0]
            raise E0GovernanceError(
                "safe-pair author batch failed: "
                f"failure_code={first['failure_code']}; truth_id={first['truth_id']}; "
                f"failure_count={len(failures)}"
            )
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
    compiler: str | None = None,
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
        if (
            record.get("packet_sha256") != expected.get("packet_sha256")
            or record.get("final_decision_sha256") != expected.get("final_decision_sha256")
            or record.get("status") not in {"authored", "reused"}
        ):
            raise E0GovernanceError(f"safe-pair author run identity mismatch: {truth_id}")
        author_path = (author_root / "authors" / f"{truth_id}.json").resolve(strict=True)
        raw_path = (author_root / "raw" / f"{truth_id}.json").resolve(strict=True)
        if sha256_file(author_path) != record.get("author_sha256") or sha256_file(
            raw_path
        ) != record.get("raw_sha256"):
            raise E0GovernanceError(f"safe-pair author artifact hash mismatch: {truth_id}")
        actual = _validated_existing_author_pair(
            author_root,
            packet,
            expected,
            status=str(record["status"]),
            compiler=compiler,
        )
        if actual != dict(record):
            raise E0GovernanceError(f"safe-pair author artifact hash mismatch: {truth_id}")
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
        compiler=args.compiler if args.compile else None,
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
    author.add_argument("--compiler", choices=("cc", "gcc", "clang"), default="cc")
    author.add_argument("--resume", action="store_true")
    author.add_argument("--checkpoint-source-sha")
    author.add_argument("--checkpoint-workflow-run-id")
    author.set_defaults(handler=author_pairs)
    checkpoint = sub.add_parser("checkpoint")
    checkpoint.add_argument("--packet-dir", required=True, type=Path)
    checkpoint.add_argument("--normalized-decisions", required=True, type=Path)
    checkpoint.add_argument("--retained-dir", required=True, type=Path)
    checkpoint.add_argument("--output-dir", required=True, type=Path)
    checkpoint.add_argument("--packet-source-sha", required=True)
    checkpoint.add_argument("--retained-source-sha", required=True)
    checkpoint.add_argument("--workflow-run-id", required=True)
    checkpoint.add_argument("--compiler", choices=("cc", "gcc", "clang"), default="cc")
    checkpoint.set_defaults(handler=build_author_checkpoint)
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
