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
from collections import Counter
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
AUTHOR_DIAGNOSTIC_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author-diagnostic.v3"
AUTHOR_MODEL = CODEX_MODEL_IDENTITY
_AUTHOR_DIAGNOSTIC_REJECTION_CODES = {
    "checkpoint_failure_record_contract_invalid",
    "checkpoint_failure_record_duplicate",
    "checkpoint_failure_record_projection_invalid",
    "checkpoint_incomplete_record_contract_invalid",
    "checkpoint_invalid_record_contract_invalid",
    "checkpoint_manifest_contract_invalid",
    "checkpoint_manifest_unreadable",
    "checkpoint_record_classes_overlap",
    "checkpoint_verified_record_contract_invalid",
    "checkpoint_without_diagnostic_signal",
}
_FORBIDDEN_LANGUAGE_TOKENS = frozenset({"_Pragma", "__asm", "__asm__", "asm"})
_FORBIDDEN_EXTERNAL_CALLS_BY_CLASS = {
    "process_execution_api": frozenset(
        {
            "_Exit",
            "abort",
            "clone",
            "dlclose",
            "dlerror",
            "dlopen",
            "dlsym",
            "execl",
            "execle",
            "execlp",
            "execv",
            "execve",
            "execveat",
            "execvp",
            "execvpe",
            "exit",
            "fork",
            "kill",
            "pclose",
            "popen",
            "posix_spawn",
            "posix_spawnp",
            "pthread_create",
            "quick_exit",
            "raise",
            "system",
            "syscall",
            "vfork",
            "wait",
            "waitid",
            "waitpid",
        }
    ),
    "network_api": frozenset(
        {
            "accept",
            "accept4",
            "epoll_create",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "bind",
            "connect",
            "freeaddrinfo",
            "getaddrinfo",
            "gethostbyname",
            "getnameinfo",
            "getsockname",
            "getsockopt",
            "listen",
            "poll",
            "ppoll",
            "recv",
            "recvfrom",
            "recvmsg",
            "send",
            "sendmsg",
            "sendto",
            "select",
            "setsockopt",
            "shutdown",
            "socket",
            "socketpair",
        }
    ),
    "file_or_stream_io_api": frozenset(
        {
            "chmod",
            "chown",
            "clearerr",
            "close",
            "closedir",
            "creat",
            "dup",
            "dup2",
            "dup3",
            "dprintf",
            "fclose",
            "fcntl",
            "fdopen",
            "fflush",
            "fgetc",
            "fgets",
            "fgetpos",
            "fileno",
            "fopen",
            "fprintf",
            "fputc",
            "fputs",
            "fread",
            "freopen",
            "fscanf",
            "fseek",
            "fsetpos",
            "fstat",
            "ftell",
            "ftruncate",
            "fwrite",
            "getc",
            "getchar",
            "ioctl",
            "link",
            "lseek",
            "lstat",
            "mkdir",
            "mkstemp",
            "open",
            "openat",
            "opendir",
            "perror",
            "pipe",
            "pipe2",
            "pread",
            "printf",
            "putc",
            "putchar",
            "puts",
            "pwrite",
            "read",
            "readdir",
            "remove",
            "rename",
            "rewind",
            "rmdir",
            "scanf",
            "setbuf",
            "setvbuf",
            "snprintf",
            "sprintf",
            "sscanf",
            "stat",
            "symlink",
            "tmpfile",
            "tmpnam",
            "truncate",
            "ungetc",
            "unlink",
            "write",
            "vfprintf",
            "vfscanf",
            "vprintf",
            "vscanf",
            "vsnprintf",
            "vsprintf",
            "vsscanf",
        }
    ),
}
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
_C_LEXEME = re.compile(
    r"(?P<comment>//[^\r\n]*|/\*.*?\*/)"
    r'|(?P<string>"(?:\\.|[^"\\])*")'
    r"|(?P<char>'(?:\\.|[^'\\])*')"
    r"|(?P<token>[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?[A-Za-z]*|"
    r">>=|<<=|\+\+|--|->|&&|\|\||<=|>=|==|!=|<<|>>|[^\s])",
    re.DOTALL,
)
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
_CONTRACT_REPAIR_FAILURE_V1_VALIDATION_CLASSES = frozenset(
    {
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
)

_AUTHOR_SOURCE_FIELDS = ("vulnerable_source", "fixed_or_near_miss_source")
_AUTHOR_COMPILER_ARGUMENTS = ("-std=c11", "-Werror", "-Wall", "-Wextra", "-c")
_C_TRIGRAPHS = {
    "??=": "#",
    "??/": "\\",
    "??'": "^",
    "??(": "[",
    "??)": "]",
    "??!": "|",
    "??<": "{",
    "??>": "}",
    "??-": "~",
}


def _c_phase2_source(source: str) -> str:
    translated = source.removeprefix("\ufeff")
    for trigraph, replacement in _C_TRIGRAPHS.items():
        translated = translated.replace(trigraph, replacement)
    spliced = re.sub(r"\\(?:\r\n|\n|\r)", "", translated)
    return spliced.replace("\r\n", "\n").replace("\r", "\n")


def _c_tokens(source: str) -> tuple[str, ...]:
    source = _c_phase2_source(source)
    return tuple(
        match.group(0) for match in _C_LEXEME.finditer(source) if match.lastgroup != "comment"
    )


def _comments_as_whitespace(source: str) -> str:
    source = _c_phase2_source(source)
    projected: list[str] = []
    cursor = 0
    for match in _C_LEXEME.finditer(source):
        projected.append(source[cursor : match.start()])
        token = match.group(0)
        if match.lastgroup == "comment":
            projected.append(
                "".join(character if character in "\r\n" else " " for character in token)
            )
        else:
            projected.append(token)
        cursor = match.end()
    projected.append(source[cursor:])
    return "".join(projected)


def _has_preprocessor_directive(source: str) -> bool:
    return re.search(r"(?m)^[ \t\f\v]*(?:#|%:)", _comments_as_whitespace(source)) is not None


def _forbidden_language_tokens(source: str) -> tuple[str, ...]:
    tokens = set(_c_tokens(source))
    return tuple(sorted(tokens & _FORBIDDEN_LANGUAGE_TOKENS))


def _forbidden_external_api_identifiers(source: str) -> dict[str, list[str]]:
    tokens = _c_tokens(source)
    identifiers = {token for token in tokens if _C_IDENTIFIER.fullmatch(token)}
    detected: dict[str, list[str]] = {}
    for facility_class, names in _FORBIDDEN_EXTERNAL_CALLS_BY_CLASS.items():
        matches = {
            identifier
            for identifier in identifiers
            if identifier in names
            or (
                identifier.startswith("__builtin_")
                and identifier.removeprefix("__builtin_") in names
            )
        }
        if matches:
            detected[facility_class] = sorted(matches)
    return detected


def _uses_forbidden_c_facilities(source: str) -> bool:
    return bool(
        _has_preprocessor_directive(source)
        or _forbidden_language_tokens(source)
        or _forbidden_external_api_identifiers(source)
    )


def _without_preprocessor_directives(source: str) -> str:
    projected: list[str] = []
    in_directive = False
    for line in _comments_as_whitespace(source).splitlines(keepends=True):
        if not in_directive and line.lstrip().startswith(("#", "%:", "??=")):
            in_directive = True
        if not in_directive:
            projected.append(line)
            continue
        projected.append("\n" if line.endswith(("\n", "\r")) else "")
        in_directive = line.rstrip("\r\n").endswith("\\")
    return "".join(projected)


def _main_definition_count(source: str) -> int:
    tokens = _c_tokens(_without_preprocessor_directives(source))
    signature = ("int", "main", "(", "void", ")", "{")
    width = len(signature)
    return sum(
        tokens[index : index + width] == signature for index in range(len(tokens) - width + 1)
    )


def _contract_repair_failure_message(repair_outcome: str, validation_class: str) -> str:
    allowed_classes = set(_CONTRACT_REPAIR_FAILURE_V1_VALIDATION_CLASSES)
    if repair_outcome == "process_nonzero":
        prefix = "safe-pair author contract repair failed: "
    elif repair_outcome == "validation_exhausted":
        prefix = "safe-pair author contract repair exhausted: "
        allowed_classes.add("unclassified_validation_failure")
    else:
        raise E0GovernanceError("safe-pair repair outcome is invalid")
    if validation_class not in allowed_classes:
        raise E0GovernanceError("safe-pair repair validation class is invalid")
    return prefix + validation_class


def _contract_repair_failure_projection(error_sha256: str) -> tuple[str, str] | None:
    """Project a bound fixed-message digest without reading author material."""

    candidates: dict[str, tuple[str, str]] = {}
    outcomes = (
        ("process_nonzero", _CONTRACT_REPAIR_FAILURE_V1_VALIDATION_CLASSES),
        (
            "validation_exhausted",
            _CONTRACT_REPAIR_FAILURE_V1_VALIDATION_CLASSES | {"unclassified_validation_failure"},
        ),
    )
    for repair_outcome, validation_classes in outcomes:
        for validation_class in sorted(validation_classes):
            projection = (repair_outcome, validation_class)
            digest = str(
                sha256_value(_contract_repair_failure_message(repair_outcome, validation_class))
            )
            if digest in candidates and candidates[digest] != projection:
                raise E0GovernanceError("safe-pair repair diagnostic vocabulary is ambiguous")
            candidates[digest] = projection
    return candidates.get(error_sha256)


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
    expected_kind: str | None = None,
    expected_invariant_summary: str | None = None,
) -> dict[str, Any]:
    identity_values = (truth_id, packet_sha256, final_decision_sha256)
    if any(value is not None for value in identity_values) and not all(
        isinstance(value, str) and value for value in identity_values
    ):
        raise ValueError("safe-pair author schema identity must be fully bound")
    recommendation_values = (expected_kind, expected_invariant_summary)
    if any(value is not None for value in recommendation_values) and not (
        expected_kind in {"fixed", "near_miss"}
        and isinstance(expected_invariant_summary, str)
        and expected_invariant_summary.strip()
    ):
        raise ValueError("safe-pair author schema recommendation must be fully bound")
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
    kind_schema: dict[str, Any] = {
        "type": "string",
        "enum": ["fixed", "near_miss"],
    }
    invariant_schema: dict[str, Any] = {"type": "string", "minLength": 1}
    if expected_kind is not None:
        kind_schema = {"type": "string", "const": expected_kind}
        invariant_schema = {
            "type": "string",
            "const": expected_invariant_summary,
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
            "kind": kind_schema,
            "invariant_summary": invariant_schema,
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


def _frozen_author_recommendation(
    normalized_record: Mapping[str, Any],
) -> tuple[str, str]:
    decision = normalized_record.get("final_decision")
    recommendation = (
        decision.get("safe_pair_recommendation") if isinstance(decision, Mapping) else None
    )
    if not isinstance(recommendation, Mapping):
        raise E0GovernanceError("safe-pair recommendation is invalid")
    kind = recommendation.get("kind")
    invariant_summary = recommendation.get("invariant_summary")
    if (
        kind not in {"fixed", "near_miss"}
        or not isinstance(invariant_summary, str)
        or not invariant_summary.strip()
    ):
        raise E0GovernanceError("safe-pair recommendation contract is invalid")
    return str(kind), invariant_summary


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
    expected_identity: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    if validation_class == "fields_or_schema_invalid":
        required_fields = set(_author_schema()["required"])
        actual_fields = set(rejected_author)
        return {
            "required_schema_version": AUTHOR_SCHEMA_VERSION,
            "required_fields": sorted(required_fields),
            "missing_fields": sorted(required_fields - actual_fields),
            "unexpected_fields": sorted(actual_fields - required_fields),
            "schema_version_mismatch": (
                rejected_author.get("schema_version") != AUTHOR_SCHEMA_VERSION
            ),
            "required_postcondition": (
                "the repaired object has exactly the required fields and schema version"
            ),
        }
    if validation_class in {
        "packet_identity_mismatch",
        "decision_identity_mismatch",
        "model_identity_mismatch",
    }:
        expected = {
            "author_role": "safe_pair_author",
            "author_model": AUTHOR_MODEL,
            **dict(expected_identity or {}),
        }
        fields_by_class = {
            "packet_identity_mismatch": ("truth_id", "packet_sha256"),
            "decision_identity_mismatch": ("final_decision_sha256",),
            "model_identity_mismatch": ("author_role", "author_model"),
        }
        compared_fields = fields_by_class[validation_class]
        return {
            "mismatched_identity_fields": [
                field
                for field in compared_fields
                if field in expected and rejected_author.get(field) != expected[field]
            ],
            "required_postcondition": (
                "all identity fields exactly match the frozen request and output schema"
            ),
        }
    if validation_class == "kind_invalid":
        return {
            "allowed_values": ["fixed", "near_miss"],
            "required_value_source": "request.safe_pair_recommendation.kind",
            "required_postcondition": (
                "kind exactly matches the frozen recommendation in the request"
            ),
        }
    if validation_class == "invariant_missing":
        return {
            "required_value_source": "request.safe_pair_recommendation.invariant_summary",
            "required_postcondition": (
                "invariant_summary exactly matches the frozen recommendation in the request"
            ),
        }
    if validation_class == "source_invalid":
        invalid_fields = []
        for field in _AUTHOR_SOURCE_FIELDS:
            source = rejected_author.get(field)
            if (
                not isinstance(source, str)
                or not source.strip()
                or len(source) > 32768
                or "\x00" in source
            ):
                invalid_fields.append(field)
        return {
            "invalid_source_fields": invalid_fields,
            "required_postcondition": (
                "both source fields are nonempty complete C11 translation units of at most "
                "32768 characters with no NUL bytes"
            ),
        }
    if validation_class == "forbidden_c_facilities":
        failing_fields = [
            field
            for field in _AUTHOR_SOURCE_FIELDS
            if isinstance(rejected_author.get(field), str)
            and _uses_forbidden_c_facilities(str(rejected_author[field]))
        ]
        detected_api_identifiers = {
            field: _forbidden_external_api_identifiers(str(rejected_author[field]))
            for field in failing_fields
            if _forbidden_external_api_identifiers(str(rejected_author[field]))
        }
        detected_language_tokens = {
            field: list(_forbidden_language_tokens(str(rejected_author[field])))
            for field in failing_fields
            if _forbidden_language_tokens(str(rejected_author[field]))
        }
        return {
            "failing_source_fields": failing_fields,
            "forbidden_facility_classes": [
                "preprocessor_directive",
                "process_execution_api",
                "network_api",
                "file_or_stream_io_api",
                "inline_assembly",
                "pragma_operator",
            ],
            "detected_external_api_identifiers_by_source_field": detected_api_identifiers,
            "detected_language_tokens_by_source_field": detected_language_tokens,
            "required_postcondition": (
                "both source fields use none of the frozen forbidden C facility classes"
            ),
        }
    if validation_class == "main_contract_invalid":
        main_counts = {}
        for field in _AUTHOR_SOURCE_FIELDS:
            source = rejected_author.get(field)
            if isinstance(source, str):
                count = _main_definition_count(source)
                if count != 1:
                    main_counts[field] = count
        return {
            "detected_main_counts_by_source_field": main_counts,
            "required_postcondition": (
                "each source field contains exactly one int main(void) definition"
            ),
        }
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
        token_projection_equal = (
            isinstance(vulnerable, str)
            and isinstance(fixed, str)
            and _c_tokens(vulnerable) == _c_tokens(fixed)
        )
        return {
            "detected_condition": (
                "sources_equal_after_newline_normalization"
                if normalized_equal
                else (
                    "sources_equal_after_comment_whitespace_token_projection"
                    if token_projection_equal
                    else "sources_reported_identical_by_validator"
                )
            ),
            "required_postcondition": (
                "vulnerable_source and fixed_or_near_miss_source have different C token "
                "projections after ignoring comments and whitespace"
            ),
            "required_correction": (
                "Keep vulnerable_source as the minimal violating baseline. Rewrite only "
                "fixed_or_near_miss_source so it applies exactly the frozen request's "
                "safe_pair_recommendation to the same minimal setup. The difference must "
                "change the reviewed behavior; comments or formatting alone do not satisfy "
                "this correction. Do not alter identity fields or add facts beyond the frozen "
                "request."
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


def _author_validation_errors(
    value: Mapping[str, Any],
    *,
    truth_id: str,
    packet_sha256: str,
    final_decision_sha256: str,
    forbidden_identifiers: set[str],
    compiler: str | None = None,
    expected_kind: str,
    expected_invariant_summary: str,
) -> tuple[E0GovernanceError, ...]:
    """Collect every currently detectable contract error in validator order."""

    errors: list[E0GovernanceError] = []
    expected = set(_author_schema()["required"])
    if set(value) != expected or value.get("schema_version") != AUTHOR_SCHEMA_VERSION:
        errors.append(E0GovernanceError("safe-pair author fields or schema are invalid"))
    if value.get("truth_id") != truth_id or value.get("packet_sha256") != packet_sha256:
        errors.append(E0GovernanceError("safe-pair author packet identity mismatch"))
    if value.get("final_decision_sha256") != final_decision_sha256:
        errors.append(E0GovernanceError("safe-pair author decision identity mismatch"))
    if value.get("author_role") != "safe_pair_author" or value.get("author_model") != AUTHOR_MODEL:
        errors.append(E0GovernanceError("safe-pair author model identity mismatch"))
    if value.get("kind") not in {"fixed", "near_miss"} or value.get("kind") != expected_kind:
        errors.append(E0GovernanceError("safe-pair author kind is invalid"))
    if (
        not isinstance(value.get("invariant_summary"), str)
        or not value["invariant_summary"].strip()
        or value.get("invariant_summary") != expected_invariant_summary
    ):
        errors.append(E0GovernanceError("safe-pair author invariant is missing or mismatched"))

    string_sources: dict[str, str] = {}
    precompile_safe = True
    for field in _AUTHOR_SOURCE_FIELDS:
        source = value.get(field)
        if not isinstance(source, str):
            errors.append(E0GovernanceError(f"safe-pair author {field} is invalid"))
            precompile_safe = False
            continue
        string_sources[field] = source.replace("\r\n", "\n").replace("\r", "\n")
        if not source.strip() or len(source) > 32768 or "\x00" in source:
            errors.append(E0GovernanceError(f"safe-pair author {field} is invalid"))
            precompile_safe = False
        if _uses_forbidden_c_facilities(source):
            errors.append(
                E0GovernanceError(f"safe-pair author {field} uses forbidden C facilities")
            )
            precompile_safe = False
        matches = _forbidden_identifier_matches(source, forbidden_identifiers)
        if matches:
            identifier = next(iter(matches))
            errors.append(
                E0GovernanceError(f"safe-pair author {field} is not anonymous: {identifier}")
            )
        if _main_definition_count(source) != 1:
            errors.append(
                E0GovernanceError(f"safe-pair author {field} requires exactly one C11 main")
            )

    if len(string_sources) == len(_AUTHOR_SOURCE_FIELDS) and _c_tokens(
        string_sources[_AUTHOR_SOURCE_FIELDS[0]]
    ) == _c_tokens(string_sources[_AUTHOR_SOURCE_FIELDS[1]]):
        errors.append(E0GovernanceError("safe-pair vulnerable and safe sources are identical"))

    if (
        compiler is not None
        and precompile_safe
        and len(string_sources) == len(_AUTHOR_SOURCE_FIELDS)
    ):
        failing_fields = _compile_author_source_fields(value, compiler=compiler)
        if failing_fields:
            errors.append(_SafePairCompilationError(failing_fields))
    return tuple(errors)


def validate_author_record(
    value: Mapping[str, Any],
    *,
    truth_id: str,
    packet_sha256: str,
    final_decision_sha256: str,
    forbidden_identifiers: set[str],
    compiler: str | None = None,
    expected_kind: str,
    expected_invariant_summary: str,
) -> None:
    errors = _author_validation_errors(
        value,
        truth_id=truth_id,
        packet_sha256=packet_sha256,
        final_decision_sha256=final_decision_sha256,
        forbidden_identifiers=forbidden_identifiers,
        compiler=compiler,
        expected_kind=expected_kind,
        expected_invariant_summary=expected_invariant_summary,
    )
    if errors:
        raise errors[0]


def _extract(stdout: str) -> Mapping[str, Any]:
    value = json.loads(stdout)
    if isinstance(value, Mapping):
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


def _author_repair_plan(
    value: Mapping[str, Any],
    *,
    primary_validation_class: str,
    validation_errors: Sequence[E0GovernanceError],
    expected_identity: Mapping[str, str],
    forbidden_identifiers: set[str],
    compiler: str | None = None,
) -> dict[str, Any]:
    if (
        not validation_errors
        or _author_validation_class(validation_errors[0]) != primary_validation_class
    ):
        raise E0GovernanceError("safe-pair author repair plan is inconsistent")

    detected_classes: list[str] = []
    first_errors: dict[str, E0GovernanceError] = {}
    for error in validation_errors:
        validation_class = _author_validation_class(error)
        if validation_class not in _REPAIRABLE_AUTHOR_VALIDATION_CLASSES:
            raise error
        if validation_class not in first_errors:
            detected_classes.append(validation_class)
            first_errors[validation_class] = error
    if not detected_classes or detected_classes[0] != primary_validation_class:
        raise E0GovernanceError("safe-pair author repair plan is invalid")

    constraints_by_class = {
        validation_class: dict(
            _repair_constraints(
                validation_class,
                forbidden_identifiers,
                value,
                validation_error=first_errors[validation_class],
                compiler=compiler,
                expected_identity=expected_identity,
            )
        )
        for validation_class in detected_classes
    }
    plan = dict(constraints_by_class[primary_validation_class])
    plan["detected_validation_classes"] = detected_classes
    plan["constraints_by_validation_class"] = constraints_by_class
    plan["baseline_postconditions"] = {
        "compiler_contract": {
            "language": "c",
            "standard": "c11",
            "compiler": compiler or "cc",
            "arguments": list(_AUTHOR_COMPILER_ARGUMENTS[1:]),
        },
        "source_fields": list(_AUTHOR_SOURCE_FIELDS),
        "each_source_has_exactly_one_main_definition": True,
        "preprocessor_or_forbidden_facility_present": False,
        "forbidden_identifier_matches_present": False,
        "sources_have_distinct_comment_whitespace_free_token_projections": True,
    }
    return plan


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
    expected_kind, expected_invariant_summary = _frozen_author_recommendation(normalized_record)
    expected_author_schema = _author_schema(
        forbidden,
        truth_id=truth_id,
        packet_sha256=str(normalized_record["packet_sha256"]),
        final_decision_sha256=str(normalized_record["final_decision_sha256"]),
        expected_kind=expected_kind,
        expected_invariant_summary=expected_invariant_summary,
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
        expected_attempt_kind = "initial" if index == 1 else "contract_repair"
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
            or attempt.get("kind") != expected_attempt_kind
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
    expected_kind, expected_invariant_summary = _frozen_author_recommendation(normalized_record)
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
        expected_kind=expected_kind,
        expected_invariant_summary=expected_invariant_summary,
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
    expected_kind, expected_invariant_summary = _frozen_author_recommendation(normalized_record)
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
            "must be an inert, local-only standalone translation unit, use no preprocessor "
            "directives, assembly, process/network/file APIs, original function names, truth IDs, or "
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
            expected_kind=expected_kind,
            expected_invariant_summary=expected_invariant_summary,
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
        validation_errors = _author_validation_errors(
            author,
            truth_id=truth_id,
            packet_sha256=str(packet["packet_sha256"]),
            final_decision_sha256=final_sha,
            forbidden_identifiers=forbidden,
            compiler=compiler,
            expected_kind=expected_kind,
            expected_invariant_summary=expected_invariant_summary,
        )
        try:
            if validation_errors:
                raise validation_errors[0]
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
            repair_constraints = _author_repair_plan(
                author,
                primary_validation_class=validation_class,
                validation_errors=validation_errors,
                expected_identity={
                    "truth_id": truth_id,
                    "packet_sha256": str(packet["packet_sha256"]),
                    "final_decision_sha256": final_sha,
                },
                forbidden_identifiers=forbidden,
                compiler=compiler,
            )
            repair_prompt = (
                "Repair only the rejected safe-pair author object below. The adjudicated "
                "decision and the schema, packet, decision, role, and model identity fields "
                "are immutable. Do not add facts or reconsider the decision. Apply the "
                "smallest complete correction for every supplied detected validation class. "
                "Each source must remain a standalone C11 translation unit and must use no "
                "preprocessor directives, assembly, process/network/file APIs, original function "
                "names, truth IDs, or project-specific identifiers. Each source must contain "
                "exactly one int main(void) definition and compile independently with "
                "-std=c11 -Wall -Wextra -Werror. Return exactly the JSON schema. "
                "REPAIR_REQUEST:\n"
                + json.dumps(
                    {
                        "request": request,
                        "rejected_author": author,
                        "validation_class": validation_class,
                        "deterministic_constraints": repair_constraints,
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
                    _contract_repair_failure_message("process_nonzero", validation_class)
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
                    expected_kind=expected_kind,
                    expected_invariant_summary=expected_invariant_summary,
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
                    _contract_repair_failure_message(
                        "validation_exhausted",
                        _author_validation_class(repair_error),
                    )
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
        compiler=None,
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


def _emit_author_diagnostic(message: str) -> None:
    """Emit only the fixed answer-free diagnostic projection.

    GitHub Actions consumers are required to monitor annotations instead of
    job logs, so publish the same fixed projection as a notice when the
    harness is running there.  ``message`` is constructed exclusively from
    the closed failure-code vocabulary and integer counts below.
    """

    print(f"safe-pair answer-free diagnostic: {message}", flush=True)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(
            f"::notice title=Range v16 safe-pair author diagnostic::{message}",
            flush=True,
        )


def _write_author_diagnostic_rejection(
    output: Path,
    *,
    source_sha: str,
    workflow_run_id: str,
    failure_code: str,
) -> int:
    if failure_code not in _AUTHOR_DIAGNOSTIC_REJECTION_CODES:
        raise E0GovernanceError("safe-pair diagnostic rejection code is invalid")
    diagnostic = {
        "schema_version": AUTHOR_DIAGNOSTIC_SCHEMA_VERSION,
        "diagnostic_status": "rejected",
        "diagnostic_failure_code": failure_code,
        "checkpoint_workflow_run_id": workflow_run_id,
        "checkpoint_packet_source_sha": source_sha,
        "diagnostic_answer_material_present": False,
    }
    diagnostic["content_sha256"] = sha256_value(diagnostic)
    _json_dump(output, diagnostic)
    _emit_author_diagnostic(
        "diagnostic_status=rejected; " f"diagnostic_failure_code={failure_code}"
    )
    return 0


def diagnose_author_checkpoint(args: argparse.Namespace) -> int:
    """Project a verified checkpoint into fixed answer-free diagnostics only."""

    if os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") != "sealed-benchmark":
        raise E0GovernanceError("safe-pair diagnosis requires sealed-benchmark environment")
    source_sha = str(args.expected_source_sha)
    workflow_run_id = str(args.expected_workflow_run_id)
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise E0GovernanceError("safe-pair diagnostic source SHA is invalid")
    if not workflow_run_id.isdigit():
        raise E0GovernanceError("safe-pair diagnostic workflow run ID is invalid")

    root = args.checkpoint_dir.resolve(strict=True)
    output = args.output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        raise E0GovernanceError("safe-pair diagnostic output cannot modify the checkpoint")
    if output.exists():
        raise E0GovernanceError("safe-pair diagnostic output already exists")
    try:
        manifest = _object(root / "checkpoint-manifest.json")
    except (E0GovernanceError, OSError, json.JSONDecodeError, UnicodeError):
        return _write_author_diagnostic_rejection(
            output,
            source_sha=source_sha,
            workflow_run_id=workflow_run_id,
            failure_code="checkpoint_manifest_unreadable",
        )
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
    invalid = manifest.get("invalid_records")
    incomplete = manifest.get("incomplete_records")
    failures = manifest.get("failure_records")
    if (
        set(manifest) != fields
        or manifest.get("schema_version") != AUTHOR_CHECKPOINT_SCHEMA_VERSION
        or manifest.get("author_model") != AUTHOR_MODEL
        or manifest.get("packet_source_sha") != source_sha
        or manifest.get("retained_source_sha") != source_sha
        or manifest.get("workflow_run_id") != workflow_run_id
        or not isinstance(manifest.get("expected_record_count"), int)
        or isinstance(manifest.get("expected_record_count"), bool)
        or int(manifest["expected_record_count"]) <= 0
        or not isinstance(verified, list)
        or manifest.get("verified_record_count") != len(verified)
        or not isinstance(invalid, list)
        or not isinstance(incomplete, list)
        or not isinstance(failures, list)
        or manifest.get("checkpoint_contains_author_material") is not bool(verified)
        or manifest.get("diagnostic_answer_material_present") is not False
        or manifest.get("requires_resume_revalidation") is not True
        or manifest.get("content_sha256") != _checkpoint_manifest_content_sha256(manifest)
    ):
        return _write_author_diagnostic_rejection(
            output,
            source_sha=source_sha,
            workflow_run_id=workflow_run_id,
            failure_code="checkpoint_manifest_contract_invalid",
        )

    verified_ids: set[str] = set()
    for record in verified:
        if not isinstance(record, Mapping) or not isinstance(record.get("truth_id"), str):
            return _write_author_diagnostic_rejection(
                output,
                source_sha=source_sha,
                workflow_run_id=workflow_run_id,
                failure_code="checkpoint_verified_record_contract_invalid",
            )
        truth_id = str(record["truth_id"])
        if not truth_id or truth_id in verified_ids:
            return _write_author_diagnostic_rejection(
                output,
                source_sha=source_sha,
                workflow_run_id=workflow_run_id,
                failure_code="checkpoint_verified_record_contract_invalid",
            )
        verified_ids.add(truth_id)

    invalid_ids: set[str] = set()
    for record in invalid:
        if (
            not isinstance(record, Mapping)
            or set(record) != {"truth_id", "error_sha256"}
            or not isinstance(record.get("truth_id"), str)
            or not record["truth_id"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("error_sha256") or ""))
            or str(record["truth_id"]) in invalid_ids
        ):
            return _write_author_diagnostic_rejection(
                output,
                source_sha=source_sha,
                workflow_run_id=workflow_run_id,
                failure_code="checkpoint_invalid_record_contract_invalid",
            )
        invalid_ids.add(str(record["truth_id"]))

    incomplete_ids: set[str] = set()
    for record in incomplete:
        if (
            not isinstance(record, Mapping)
            or set(record) != {"truth_id", "author_present", "raw_present"}
            or not isinstance(record.get("truth_id"), str)
            or not record["truth_id"]
            or not isinstance(record.get("author_present"), bool)
            or not isinstance(record.get("raw_present"), bool)
            or record["author_present"] == record["raw_present"]
            or str(record["truth_id"]) in incomplete_ids
        ):
            return _write_author_diagnostic_rejection(
                output,
                source_sha=source_sha,
                workflow_run_id=workflow_run_id,
                failure_code="checkpoint_incomplete_record_contract_invalid",
            )
        incomplete_ids.add(str(record["truth_id"]))

    failure_ids: set[str] = set()
    failure_counts: Counter[str] = Counter()
    contract_repair_counts: Counter[tuple[str, str]] = Counter()
    for record in failures:
        try:
            _validate_failure_record(record)
        except E0GovernanceError:
            return _write_author_diagnostic_rejection(
                output,
                source_sha=source_sha,
                workflow_run_id=workflow_run_id,
                failure_code="checkpoint_failure_record_contract_invalid",
            )
        truth_id = str(record["truth_id"])
        if truth_id in failure_ids:
            return _write_author_diagnostic_rejection(
                output,
                source_sha=source_sha,
                workflow_run_id=workflow_run_id,
                failure_code="checkpoint_failure_record_duplicate",
            )
        failure_ids.add(truth_id)
        failure_code = str(record["failure_code"])
        failure_counts[failure_code] += 1
        if failure_code == "contract_repair_failure":
            projection = _contract_repair_failure_projection(str(record["error_sha256"]))
            if projection is None:
                return _write_author_diagnostic_rejection(
                    output,
                    source_sha=source_sha,
                    workflow_run_id=workflow_run_id,
                    failure_code="checkpoint_failure_record_projection_invalid",
                )
            contract_repair_counts[projection] += 1

    if not failure_counts and not invalid_ids and not incomplete_ids:
        return _write_author_diagnostic_rejection(
            output,
            source_sha=source_sha,
            workflow_run_id=workflow_run_id,
            failure_code="checkpoint_without_diagnostic_signal",
        )
    if (
        verified_ids & invalid_ids
        or verified_ids & incomplete_ids
        or verified_ids & failure_ids
        or invalid_ids & incomplete_ids
    ):
        return _write_author_diagnostic_rejection(
            output,
            source_sha=source_sha,
            workflow_run_id=workflow_run_id,
            failure_code="checkpoint_record_classes_overlap",
        )

    diagnostic: dict[str, Any] = {
        "schema_version": AUTHOR_DIAGNOSTIC_SCHEMA_VERSION,
        "diagnostic_status": "classified",
        "diagnostic_failure_code": None,
        "checkpoint_workflow_run_id": workflow_run_id,
        "checkpoint_packet_source_sha": source_sha,
        "checkpoint_content_sha256": manifest["content_sha256"],
        "expected_record_count": manifest["expected_record_count"],
        "verified_record_count": len(verified_ids),
        "invalid_record_count": len(invalid_ids),
        "incomplete_record_count": len(incomplete_ids),
        "failure_record_count": sum(failure_counts.values()),
        "failure_classes": [
            {"failure_code": code, "count": failure_counts[code]} for code in sorted(failure_counts)
        ],
        "contract_repair_classes": [
            {
                "repair_outcome": repair_outcome,
                "validation_class": validation_class,
                "count": contract_repair_counts[(repair_outcome, validation_class)],
            }
            for repair_outcome, validation_class in sorted(contract_repair_counts)
        ],
        "diagnostic_answer_material_present": False,
    }
    diagnostic["content_sha256"] = sha256_value(diagnostic)
    _json_dump(output, diagnostic)
    classes = (
        ",".join(f"{row['failure_code']}:{row['count']}" for row in diagnostic["failure_classes"])
        or "none"
    )
    contract_repair_classes = (
        ",".join(
            f"{row['repair_outcome']}.{row['validation_class']}:{row['count']}"
            for row in diagnostic["contract_repair_classes"]
        )
        or "none"
    )
    _emit_author_diagnostic(
        f"diagnostic_status=classified; failure_classes={classes}; "
        f"contract_repair_classes={contract_repair_classes}; "
        f"invalid_records={len(invalid_ids)}; "
        f"incomplete_records={len(incomplete_ids)}"
    )
    return 0


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
    verified: list[dict[str, Any]] = []
    verified_paths: list[tuple[Path, Path]] = []
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
        except (E0GovernanceError, OSError, json.JSONDecodeError, UnicodeError) as exc:
            invalid.append({"truth_id": truth_id, "error_sha256": sha256_value(str(exc))})
            continue
        verified.append(verified_record)
        verified_paths.append((author_path, raw_path))
    failure_records = _load_failure_manifest(
        retained / "failure-manifest.json",
        normalized_sha256=normalized_sha256,
        expected_record_count=len(work),
    )
    verified.sort(key=lambda item: item["truth_id"])
    invalid.sort(key=lambda item: item["truth_id"])
    incomplete.sort(key=lambda item: item["truth_id"])
    if getattr(args, "require_complete", False) and (
        len(verified) != len(work) or invalid or incomplete or failure_records
    ):
        raise E0GovernanceError(
            "safe-pair complete checkpoint requires every expected record to be verified"
        )
    output.mkdir(parents=True)
    (output / "authors").mkdir()
    (output / "raw").mkdir()
    for author_path, raw_path in verified_paths:
        shutil.copy2(author_path, output / "authors" / author_path.name)
        shutil.copy2(raw_path, output / "raw" / raw_path.name)
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
    records: list[dict[str, Any]] = []
    pending_work = work
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
        pending_work = []
        for packet, record in work:
            truth_id = str(record["truth_id"])
            author_path = output / "authors" / f"{truth_id}.json"
            raw_path = output / "raw" / f"{truth_id}.json"
            author_present = author_path.exists() or author_path.is_symlink()
            raw_present = raw_path.exists() or raw_path.is_symlink()
            if not author_present and not raw_present:
                pending_work.append((packet, record))
                continue
            if not author_path.is_file() or not raw_path.is_file():
                raise E0GovernanceError(f"incomplete or unexpected safe-pair author: {truth_id}")
            records.append(
                _validated_existing_author_pair(
                    output,
                    packet,
                    record,
                    status="reused",
                    compiler=compiler,
                )
            )
            print(
                f"safe-pair: {len(records)}/{len(work)} complete ({truth_id})",
                flush=True,
            )
        (output / "checkpoint-manifest.json").unlink()
    elif checkpoint_source_sha is not None or checkpoint_workflow_run_id is not None:
        raise E0GovernanceError("safe-pair checkpoint validation requires resume mode")
    for offset in range(0, len(pending_work), args.workers):
        batch = pending_work[offset : offset + args.workers]
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
            failure_classes = Counter(str(item["failure_code"]) for item in failures)
            projected_classes = ",".join(
                f"{code}:{failure_classes[code]}" for code in sorted(failure_classes)
            )
            raise E0GovernanceError(
                "safe-pair author batch failed: "
                f"failure_classes={projected_classes}; failure_count={len(failures)}"
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
        expected_kind, expected_invariant_summary = _frozen_author_recommendation(record)
        validate_author_record(
            author,
            truth_id=truth_id,
            packet_sha256=str(record["packet_sha256"]),
            final_decision_sha256=str(record["final_decision_sha256"]),
            forbidden_identifiers=_source_identifiers(packet, truth_id),
            expected_kind=expected_kind,
            expected_invariant_summary=expected_invariant_summary,
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
    author.add_argument("--workers", type=int, choices=range(1, 9), default=8)
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
    checkpoint.add_argument("--require-complete", action="store_true")
    checkpoint.set_defaults(handler=build_author_checkpoint)
    diagnose = sub.add_parser("diagnose-checkpoint")
    diagnose.add_argument("--checkpoint-dir", required=True, type=Path)
    diagnose.add_argument("--expected-source-sha", required=True)
    diagnose.add_argument("--expected-workflow-run-id", required=True)
    diagnose.add_argument("--output", required=True, type=Path)
    diagnose.set_defaults(handler=diagnose_author_checkpoint)
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
