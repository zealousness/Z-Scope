"""Audit compilation coverage without treating file counts as TU coverage."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .indexing_identity import (
    command_identity,
    digest_json,
    file_digest,
    load_commands,
    source_path,
    InputValidator,
)


def compilation_contexts(
    compile_commands: Path, *, selected_contexts: Optional[Iterable[str]] = None
) -> Dict[str, Any]:
    """Describe every original command without inventing variant equivalence.

    The identity is exactly the one used by native extraction and LLVM builds.
    Only identical command/environment/response-file identities share a context;
    a different macro, include order or ABI flag remains an uncovered variant.
    Selection is supplied by an observed plan, never inferred from source count.
    """
    commands = load_commands(compile_commands)
    selected = set(selected_contexts) if selected_contexts is not None else None
    contexts: Dict[str, Dict[str, Any]] = {}
    command_rows = []
    invalid = []
    for ordinal, command in enumerate(commands):
        try:
            if not command.get("file"):
                raise ValueError("command has no source file")
            identity = command_identity(command, compile_commands.parent)
            if not identity["arguments"]:
                raise ValueError("command has no compiler arguments")
            context = digest_json(identity)
            row = contexts.setdefault(
                context,
                {
                    "context": context,
                    "source": identity["source"],
                    "identity": identity,
                    "command_indices": [],
                },
            )
            duplicate = row["command_indices"][0] if row["command_indices"] else None
            row["command_indices"].append(ordinal)
            selection = (
                "unverified"
                if selected is None
                else "selected" if context in selected else "uncovered"
            )
            row["selection_status"] = selection
            command_rows.append(
                {
                    "command_index": ordinal,
                    "context": context,
                    "source": identity["source"],
                    "selection_status": (
                        "equivalent"
                        if duplicate is not None and selection == "selected"
                        else selection
                    ),
                    "equivalent_to_command": duplicate,
                    "equivalence_basis": (
                        "identical_command_identity" if duplicate is not None else None
                    ),
                }
            )
        except (ValueError, OSError) as exc:
            invalid.append({"command_index": ordinal, "reason": str(exc)})
    by_source: Dict[str, list[str]] = {}
    for key, row in contexts.items():
        by_source.setdefault(row["source"], []).append(key)
    return {
        "command_entries": len(commands),
        "compile_contexts": len(contexts),
        "contexts": list(contexts.values()),
        "command_records": command_rows,
        "invalid_commands": invalid,
        "source_variants": [
            {
                "source": source,
                "contexts": keys,
                "selected_contexts": (
                    None if selected is None else [key for key in keys if key in selected]
                ),
                "uncovered_contexts": (
                    None if selected is None else [key for key in keys if key not in selected]
                ),
            }
            for source, keys in sorted(by_source.items())
        ],
        "selection_verified": selected is not None
        and not invalid
        and not (selected - contexts.keys()),
        "unrecognized_selected_contexts": sorted((selected or set()) - contexts.keys()),
        "equivalence_note": "Identical invocation identities only; no semantic equivalence is inferred.",
    }


def inventory(
    compile_commands: Path, bitcode_directory: Path, manifest: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    commands = load_commands(compile_commands)
    if manifest is None:
        try:
            manifest = json.loads(
                (bitcode_directory / "bitcode_manifest.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            manifest = {}
    attempts = manifest.get("attempts", {})
    artifacts = manifest.get("bitcode", {})
    selection = compilation_contexts(
        compile_commands,
        selected_contexts=(
            [
                key
                for key, attempt in attempts.items()
                if attempt.get("status") not in {None, "not_selected"}
            ]
            if attempts
            else None
        ),
    )
    contexts = {row["context"]: row for row in selection["contexts"]}
    invalid = selection["invalid_commands"]
    rows = []
    validator = InputValidator([bitcode_directory])
    for key, context in contexts.items():
        attempt = dict(attempts.get(key, {}))
        status = str(attempt.get("status") or "unverified")
        row = dict(context, status=status, reason=attempt.get("reason", "no_context_manifest"))
        artifact = attempt.get("bitcode")
        if not artifact and status in {"compiled", "reused"}:
            row.update(status="unverified", reason="artifact_not_recorded")
        if artifact:
            path = Path(artifact)
            path = path if path.is_absolute() else bitcode_directory / path
            row["bitcode"] = str(path)
            row["artifact_sha256"] = file_digest(path)
            entry = artifacts.get(str(path.resolve()), {})
            expected = entry.get("bitcode_hash")
            if not path.is_file():
                row.update(status="missing", reason="artifact_missing")
            elif not expected or expected != row["artifact_sha256"]:
                row.update(status="unverified", reason="artifact_identity_mismatch")
            elif status in {"compiled", "reused"}:
                checkpoint = entry.get("checkpoint")
                if checkpoint:
                    checkpoint_path = Path(checkpoint)
                    try:
                        if file_digest(checkpoint_path) != entry.get("checkpoint_hash"):
                            raise ValueError("checkpoint changed")
                        entry = json.loads(checkpoint_path.read_text(encoding="utf-8"))["entry"]
                    except (OSError, ValueError, KeyError, TypeError):
                        entry = {}
                if not entry.get("dependencies_complete"):
                    row.update(status="unverified", reason="dependency_manifest_incomplete")
                elif not validator.dependencies(
                    entry.get("dependencies")
                ) or not validator.searches(entry.get("search_directories")):
                    row.update(status="stale", reason="source_or_dependency_changed")
        rows.append(row)
    groups = []
    for task in manifest.get("analysis_tasks", []):
        group = dict(task)
        path = Path(str(group["bitcode"]))
        path = path if path.is_absolute() else bitcode_directory / path
        group.update(
            bitcode=str(path),
            sha256=file_digest(path),
            size_bytes=path.stat().st_size if path.is_file() else None,
        )
        groups.append(group)
    # Old manifests cannot prove which tool consumed a file or whether all
    # commands succeeded. Expose their artifacts with an explicit unknown role.
    known = {str(Path(group["bitcode"]).resolve()) for group in groups}
    for name, data in manifest.get("linked", {}).items():
        raw = data.get("path") or data.get("output") or data.get("merged_path")
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute():
            path = bitcode_directory / path
        if str(path.resolve()) in known:
            continue
        groups.append(
            {
                "group": name,
                "tool": "unverified",
                "bitcode": str(path),
                "sha256": file_digest(path),
                "size_bytes": path.stat().st_size if path.is_file() else None,
                "inputs": data.get("inputs", []),
            }
        )
    if not groups:
        for path in sorted(bitcode_directory.glob("merged*.bc")):
            groups.append(
                {
                    "group": path.stem,
                    "tool": "unverified",
                    "bitcode": str(path),
                    "sha256": file_digest(path),
                    "size_bytes": path.stat().st_size,
                    "inputs": [],
                }
            )
    duplicates: Dict[str, list[str]] = {}
    for group in groups:
        if group["sha256"] != "missing":
            duplicates.setdefault(group["sha256"], []).append(group["group"])
    counts = Counter(row["status"] for row in rows)
    try:
        analysis_run = json.loads(
            (bitcode_directory / "svf_run_report.json").read_text(encoding="utf-8")
        )
        analysis_run["current_manifest"] = analysis_run.get("manifest_sha256") == file_digest(
            bitcode_directory / "bitcode_manifest.json"
        )
    except (OSError, ValueError, TypeError):
        analysis_run = {"status": "unverified"}
    return {
        "schema": "zscope.indexing-inventory.v1",
        "compile_commands": str(compile_commands.resolve()),
        "compile_commands_sha256": file_digest(compile_commands),
        "command_entries": len(commands),
        "unique_source_files": len(
            {str(source_path(row, compile_commands.parent)) for row in commands if row.get("file")}
        ),
        "compile_contexts": len(contexts),
        "selected_compile_contexts": (
            sum(
                1
                for key in contexts
                if attempts.get(key, {}).get("status") not in {None, "not_selected"}
            )
            if attempts
            else None
        ),
        "invalid_commands": invalid,
        "command_records": selection["command_records"],
        "source_variants": selection["source_variants"],
        "selection_verified": selection["selection_verified"],
        "unrecognized_selected_contexts": selection["unrecognized_selected_contexts"],
        "equivalence_note": selection["equivalence_note"],
        "status_counts": dict(counts),
        "contexts": rows,
        "coverage_verified": bool(rows)
        and not invalid
        and not selection["unrecognized_selected_contexts"]
        and all(row["status"] in {"compiled", "reused"} for row in rows),
        "groups": groups,
        "tasks_by_tool": dict(Counter(group["tool"] for group in groups)),
        "analysis_run": analysis_run,
        "equal_content_groups": [names for names in duplicates.values() if len(names) > 1],
        "scope_note": "Compilation contexts, files and linked analysis tasks are distinct. "
        "Equal bytes alone do not prove equivalent analysis options.",
    }
