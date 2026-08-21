#!/usr/bin/env python3
"""Author and materialize anonymous, independently compilable Range v16 pairs.

The protected ``author`` mode asks Opus only for two minimal C translation
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
from run_e0_reviewers import assert_no_hidden_reasoning_output  # noqa: E402


AUTHOR_SCHEMA_VERSION = "zscope.range-v16-safe-pair-author.v1"
AUTHOR_MODEL = "claude-opus-5"
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


def _json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")


def _object(path: Path) -> Mapping[str, Any]:
    value = load_json_strict(path.resolve(strict=True))
    if not isinstance(value, Mapping):
        raise E0GovernanceError(f"artifact must be an object: {path}")
    return value


def _author_schema() -> dict[str, Any]:
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
            "truth_id": {"type": "string", "minLength": 1},
            "packet_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "final_decision_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "author_role": {"const": "safe_pair_author"},
            "author_model": {"const": AUTHOR_MODEL},
            "kind": {"enum": ["fixed", "near_miss"]},
            "invariant_summary": {"type": "string", "minLength": 1},
            "vulnerable_source": {"type": "string", "minLength": 1, "maxLength": 32768},
            "fixed_or_near_miss_source": {
                "type": "string",
                "minLength": 1,
                "maxLength": 32768,
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
        for identifier in forbidden_identifiers:
            if identifier and identifier in source:
                raise E0GovernanceError(f"safe-pair author {field} is not anonymous: {identifier}")
        if len(re.findall(r"\bint\s+main\s*\(\s*void\s*\)", source)) != 1:
            raise E0GovernanceError(f"safe-pair author {field} requires exactly one C11 main")
        sources.append(source.replace("\r\n", "\n").replace("\r", "\n"))
    if sources[0] == sources[1]:
        raise E0GovernanceError("safe-pair vulnerable and safe sources are identical")


def _extract(stdout: str) -> Mapping[str, Any]:
    value = json.loads(stdout)
    if isinstance(value, Mapping) and isinstance(value.get("structured_output"), Mapping):
        return dict(value["structured_output"])
    if isinstance(value, Mapping) and isinstance(value.get("result"), str):
        nested = json.loads(str(value["result"]))
        if isinstance(nested, Mapping):
            return dict(nested)
    if isinstance(value, Mapping) and set(_author_schema()["required"]).issubset(value):
        return dict(value)
    raise E0GovernanceError("Opus did not return a safe-pair author object")


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
        claude = shutil.which("claude.cmd" if os.name == "nt" else "claude")
        if not claude:
            raise E0GovernanceError("Claude Code executable is unavailable")
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
        command = [
            str(claude),
            "--print",
            "--model",
            AUTHOR_MODEL,
            "--effort",
            "max",
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(_author_schema(), separators=(",", ":")),
            "--permission-mode",
            "plan",
            "--tools",
            "",
            "--no-session-persistence",
            "--disable-slash-commands",
        ]
        env = {
            key: item
            for key, item in os.environ.items()
            if "GROUND_TRUTH" not in key.upper()
            and "BENCHMARK_TRUTH" not in key.upper()
            and "SCORER" not in key.upper()
        }
        with tempfile.TemporaryDirectory(prefix="zscope-e0-pair-author-") as raw_temp:
            completed = subprocess.run(
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
        if completed.returncode != 0:
            raise E0GovernanceError(f"safe-pair author failed: {truth_id}")
        assert_no_hidden_reasoning_output(completed.stdout)
        raw = {
            "schema_version": "zscope.range-v16-safe-pair-author-raw.v1",
            "truth_id": truth_id,
            "packet_sha256": packet["packet_sha256"],
            "final_decision_sha256": final_sha,
            "author_model": AUTHOR_MODEL,
            "command_identity": [Path(command[0]).name, *command[1:]],
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr_sha256": sha256_value(completed.stderr),
        }
        _json_dump(raw_path, raw)
        author = dict(_extract(completed.stdout))
        validate_author_record(
            author,
            truth_id=truth_id,
            packet_sha256=str(packet["packet_sha256"]),
            final_decision_sha256=final_sha,
            forbidden_identifiers=forbidden,
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
            "exit_code",
            "stdout",
            "stderr_sha256",
        }
        command_identity = raw.get("command_identity")
        expected_command_prefix = [
            "--print",
            "--model",
            AUTHOR_MODEL,
            "--effort",
            "max",
            "--output-format",
            "json",
            "--json-schema",
        ]
        command_valid = False
        if (
            isinstance(command_identity, list)
            and len(command_identity) == 16
            and command_identity[0] in {"claude", "claude.cmd"}
            and command_identity[1:9] == expected_command_prefix
            and command_identity[10:]
            == [
                "--permission-mode",
                "plan",
                "--tools",
                "",
                "--no-session-persistence",
                "--disable-slash-commands",
            ]
            and isinstance(command_identity[9], str)
        ):
            try:
                command_valid = json.loads(command_identity[9]) == _author_schema()
            except json.JSONDecodeError:
                command_valid = False
        if (
            set(raw) != raw_fields
            or raw.get("schema_version") != "zscope.range-v16-safe-pair-author-raw.v1"
            or raw.get("truth_id") != truth_id
            or raw.get("packet_sha256") != expected.get("packet_sha256")
            or raw.get("final_decision_sha256") != expected.get("final_decision_sha256")
            or raw.get("author_model") != AUTHOR_MODEL
            or raw.get("exit_code") != 0
            or not command_valid
            or not isinstance(raw.get("stdout"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(raw.get("stderr_sha256") or ""))
        ):
            raise E0GovernanceError(f"safe-pair raw author envelope is invalid: {truth_id}")
        assert_no_hidden_reasoning_output(str(raw["stdout"]))
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
