"""Read-only reconciliation of expected compile commands against stored contexts.

The exact-context store answers "which compilation instances exist"; it cannot
prove that every command the current compile database and path selection
expect has actually been indexed. This module computes that expected command
set with the same primitives the batch indexer used (``load_commands`` +
``command_identity`` + the backend path selection) and reconciles it command
identity by command identity against the contexts really present in the
store. Equal totals, a shared source path or a shared function name never
authorize coverage: only an exact ``command_id`` match backed by a manifest-
naming ``BuildContext`` identity and a current ``context_input_status``
receipt does, and extra or stale contexts never fill a missing command.

Command identities bind directory, source, arguments, response files and the
observing process environment exactly as the indexer's planning bound them in
its own process; an environment or response-file change therefore surfaces as
missing plus unexpected identities, never as silent reuse.

This is command-level reconciliation only. It derives nothing about link
membership, entry presence, or Analyzer/Validator execution, and
``scan_coverage_complete`` stays ``False`` at this stage by contract.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..retrieval.build_context import BuildContext, context_input_status
from ..retrieval.indexing_identity import (
    command_identity,
    digest_json,
    file_digest,
    load_commands,
)

logger = logging.getLogger(__name__)

ENTRY_INSTANCE_COVERAGE_SCHEMA = "zscope.entry-instance-coverage.v1"

GAP_COMPILE_DATABASE_MISSING = "compile_database_missing"
GAP_COMPILE_DATABASE_UNREADABLE = "compile_database_unreadable"
GAP_COMPILE_DATABASE_INVALID = "compile_database_invalid"
GAP_COMPILE_DATABASE_EMPTY = "compile_database_empty"
GAP_COMPILE_DATABASE_CHANGED = "compile_database_changed_during_reconciliation"
GAP_SELECTION_ROOT_UNAVAILABLE = "selection_root_unavailable"
GAP_COMMAND_IDENTITY_FAILED = "command_identity_failed"
GAP_STORED_CONTEXTS_UNAVAILABLE = "stored_contexts_unavailable"
GAP_COMMAND_NOT_INDEXED = "command_not_indexed"
GAP_UNEXPECTED_STORED_CONTEXT = "unexpected_stored_context"
GAP_DUPLICATE_STORED_CONTEXT = "duplicate_stored_context"
GAP_BUILD_CONTEXT_IDENTITY_MISMATCH = "build_context_identity_mismatch"
GAP_TOOL_RECEIPT_MISSING = "tool_receipt_missing"

# Must mirror BatchIndexer._jobs: only these source suffixes become native jobs.
_JOB_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})

_NOTE_COMMAND_SCOPE = (
    "Command reconciliation is index-level: it proves that every expected "
    "compile command has a current stored compilation context. It does not "
    "derive link membership, entry presence, or Analyzer/Validator execution."
)
_NOTE_SELECTION_SCOPE = (
    "The expected denominator replicates the batch indexer's selection "
    "(compile database rows, C/C++ job suffixes, include/exclude path filter) "
    "from the parameters given. Stored-versus-expected mismatches are the "
    "filter-consistency gaps; a denominator that cannot be established is "
    "reported as null, never as an empty complete set."
)


def _gap(
    reason: str,
    detail: str = "",
    *,
    source: str = "",
    command_id: str = "",
    build_context_id: str = "",
) -> Dict[str, Any]:
    return {
        "source": source,
        "command_id": command_id,
        "build_context_id": build_context_id,
        "reason": reason,
        "detail": detail,
    }


def _payload(
    status: str,
    *,
    reasons: Sequence[str] = (),
    gaps: Sequence[Dict[str, Any]] = (),
    expected: Optional[List[Dict[str, Any]]] = None,
    current: Sequence[Dict[str, Any]] = (),
    missing: Sequence[Dict[str, Any]] = (),
    stale: Sequence[Dict[str, Any]] = (),
    unexpected: Sequence[Dict[str, Any]] = (),
    stats: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    gap_list = list(gaps)
    counters = dict(stats or {})
    return {
        "schema": ENTRY_INSTANCE_COVERAGE_SCHEMA,
        "status": status,
        "reasons": list(reasons),
        "expected_commands": expected,
        "current_commands": list(current),
        "missing_commands": list(missing),
        "stale_contexts": list(stale),
        "unexpected_contexts": list(unexpected),
        "gaps": gap_list,
        "command_entries": int(counters.get("command_entries", 0)),
        "duplicate_command_entries": int(counters.get("duplicate_command_entries", 0)),
        "filtered_command_entries": int(counters.get("filtered_command_entries", 0)),
        "stored_contexts": int(counters.get("stored_contexts", 0)),
        "command_coverage_complete": bool(status == "reconciled" and not gap_list),
        "scan_coverage_complete": False,
        "scan_coverage_reasons": ["command_reconciliation_only"],
        "notes": [_NOTE_COMMAND_SCOPE, _NOTE_SELECTION_SCOPE],
    }


def _denominator_unknown(reason: str, detail: str, *, command_entries: int = 0) -> Dict[str, Any]:
    return _payload(
        "unknown",
        reasons=[reason],
        gaps=[_gap(reason, detail)],
        expected=None,
        stats={"command_entries": command_entries},
    )


def _not_applicable(reason: str) -> Dict[str, Any]:
    return _payload("not_applicable", reasons=[reason], expected=None)


def _search_bases(source_root: Path, include_paths: Optional[Sequence[Path]]) -> List[Path]:
    """Replicate the indexer's base dedup so the checked set is the read set."""

    raw = [Path(p).absolute() for p in (include_paths or [])] or [Path(source_root).absolute()]
    ordered = sorted({Path(base).resolve() for base in raw}, key=lambda base: len(base.parts))
    bases: List[Path] = []
    for base in ordered:
        if not any(base == parent or parent in base.parents for parent in bases):
            bases.append(base)
    return bases


class _SelectionScope:
    """Duck-typed backend state so the indexer's own selection code runs.

    ``ClangBackend._collect_source_files`` and ``_is_path_allowed`` are the
    authoritative selection implementation; running them against this scope
    keeps the expected denominator identical to the index's by construction
    instead of duplicating the rules. A backend refactor that renames these
    members fails loudly here rather than silently drifting.
    """

    def __init__(
        self,
        source_root: Path,
        include_paths: Optional[Sequence[Path]],
        exclude_paths: Optional[Sequence[Path]],
    ) -> None:
        from ..retrieval.clang_backend import ClangBackend

        # Deliberately untyped: the calls below are the backend's own code.
        self._backend: Any = ClangBackend
        self._source_path = Path(source_root).absolute()
        self._include_paths = [Path(p).absolute() for p in (include_paths or [])]
        self._exclude_paths = [Path(p).absolute() for p in (exclude_paths or [])]

    def _is_path_allowed(self, path: Path) -> bool:
        return bool(self._backend._is_path_allowed(self, path))

    def collect(self) -> Any:
        return self._backend._collect_source_files(self)


def _allowed_sources(
    source_root: Path,
    include_paths: Optional[Sequence[Path]],
    exclude_paths: Optional[Sequence[Path]],
) -> Optional[Set[str]]:
    """Run the backend's own selection so the scope cannot drift from indexing."""

    try:
        collected = _SelectionScope(source_root, include_paths, exclude_paths).collect()
    except Exception as exc:  # a broken selection proves nothing either way
        logger.warning("Path selection unavailable during coverage reconcile: %s", exc)
        return None
    return {str(path.resolve()) for path in collected}


def _stored_source(context: Dict[str, Any]) -> str:
    command = context.get("command")
    if isinstance(command, dict):
        source = str(command.get("source") or "")
        if source:
            return source
    return str(context.get("source") or "")


def _failure_detail(context: Dict[str, Any]) -> str:
    failure = context.get("failure")
    if isinstance(failure, dict):
        code = str(failure.get("code") or "")
        exception = str(failure.get("exception") or "")
        if code or exception:
            return (
                f"recorded indexing failure {code or '<no code>'}: "
                f"{exception or '<no exception>'}"
            )
    return ""


def _build_identity_reason(context: Dict[str, Any]) -> Tuple[str, str]:
    """The declared identity must name exactly this manifest.

    The stored manifest is rebuilt through ``BuildContext.create`` — the
    existing generation/digest contract, not a second identity algorithm —
    from the base-manifest fields only. Publisher-added presentation fields
    (the root-relative ``source``, ``status``, ``failure``, search and
    compilation-database receipts) are not part of the identity, so correct
    native contexts keep passing. A cleared, foreign, swapped or otherwise
    non-corresponding ``build_context_id`` never names the manifest it is
    attached to and must not fill the expected command denominator; the
    stored ``command_id`` must likewise name the stored command identity.
    """

    declared = str(context.get("build_context_id") or "")
    if not declared:
        return GAP_BUILD_CONTEXT_IDENTITY_MISMATCH, "stored context has no build_context_id"
    try:
        rebuilt = BuildContext.create(
            context["command"],
            tool=context["tool"],
            dependencies=context["dependencies"],
            dependencies_complete=context["dependencies_complete"],
            target=context["target"],
            link_target=context.get("link_target"),
            include_probes=context.get("include_probes"),
            # The publish side stores the native include-lookups receipt and
            # ``BuildContext.create`` makes it identity-bearing, so a
            # reconciler that dropped it would reject every native id.
            include_lookups=context.get("include_lookups"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        return (
            GAP_BUILD_CONTEXT_IDENTITY_MISMATCH,
            f"stored manifest cannot be rebuilt: {type(exc).__name__}: {exc}",
        )
    if rebuilt.context_id != declared:
        return (
            GAP_BUILD_CONTEXT_IDENTITY_MISMATCH,
            f"declared build_context_id {declared} does not name this manifest "
            f"(BuildContext.create yields {rebuilt.context_id})",
        )
    if rebuilt.command_id != str(context.get("command_id") or ""):
        return (
            GAP_BUILD_CONTEXT_IDENTITY_MISMATCH,
            "stored command_id does not name the stored command identity",
        )
    return "", ""


def _stored_context_reason(context: Dict[str, Any]) -> Tuple[str, str]:
    """Conservative receipt check for one stored context; ``""`` means current.

    The declared BuildContext identity must name exactly this manifest, then
    ``context_input_status`` re-validates the negative dependencies (source,
    headers, response files, compile database, include searches, probes)
    against the current filesystem without executing anything, and finally
    the tool receipt is checked: a manifest without a usable producer
    identity cannot bind its facts to the tool that produced them.
    """

    reason, detail = _build_identity_reason(context)
    if reason:
        return reason, detail
    status = context_input_status(context)
    if status != "current":
        return status, _failure_detail(context)
    tool = context.get("tool")
    binary = tool.get("binary") if isinstance(tool, dict) else None
    receipt = binary.get("sha256") if isinstance(binary, dict) else None
    if not isinstance(receipt, str) or receipt in ("", "missing"):
        return GAP_TOOL_RECEIPT_MISSING, "current inputs but no usable tool.sha256 receipt"
    return "", ""


def reconcile_entry_instance_coverage(
    code_index: Any,
    *,
    compile_commands_path: Path,
    source_root: Path,
    include_paths: Optional[Sequence[Path]] = None,
    exclude_paths: Optional[Sequence[Path]] = None,
) -> Dict[str, Any]:
    """Reconcile expected compile-database commands with stored contexts.

    Read-only: no command from the database is executed and no stored state is
    modified. Returns ``zscope.entry-instance-coverage.v1`` with the expected
    command denominator (``None`` when it cannot be established), the
    per-command reconciliation outcome and explicit gaps. A command counts as
    covered only when a stored context carries its exact identity and passes
    the build-identity and current-input receipts; ``scan_coverage_complete``
    is always ``False``.
    """

    if str(getattr(code_index, "language", "c_cpp") or "c_cpp") == "java":
        return _not_applicable("java_scan_has_no_compilation_instances")
    backend_name = str(getattr(code_index, "backend_name", "") or "").lower()
    if backend_name in {"regex", "joern"}:
        return _not_applicable(f"{backend_name}_backend_has_no_compilation_instances")

    getter = getattr(code_index, "get_build_contexts", None)
    if not callable(getter):
        return _denominator_unknown(
            GAP_STORED_CONTEXTS_UNAVAILABLE,
            "code_index does not expose get_build_contexts",
        )
    try:
        stored = getter("")
    except Exception as exc:
        return _denominator_unknown(
            GAP_STORED_CONTEXTS_UNAVAILABLE,
            f"get_build_contexts failed: {type(exc).__name__}: {exc}",
        )
    if not isinstance(stored, list):
        return _denominator_unknown(
            GAP_STORED_CONTEXTS_UNAVAILABLE,
            f"get_build_contexts returned {type(stored).__name__}, expected a list",
        )

    database = Path(compile_commands_path)
    digest_before = file_digest(database)
    if digest_before == "missing":
        return _denominator_unknown(
            GAP_COMPILE_DATABASE_MISSING, f"{database} is not readable as a file"
        )
    try:
        rows = load_commands(database)
    except FileNotFoundError:
        return _denominator_unknown(
            GAP_COMPILE_DATABASE_MISSING, f"{database} disappeared while reconciling"
        )
    except OSError as exc:
        return _denominator_unknown(GAP_COMPILE_DATABASE_UNREADABLE, f"{type(exc).__name__}: {exc}")
    except ValueError as exc:
        return _denominator_unknown(GAP_COMPILE_DATABASE_INVALID, f"{type(exc).__name__}: {exc}")
    if file_digest(database) != digest_before:
        return _denominator_unknown(
            GAP_COMPILE_DATABASE_CHANGED, "compile database changed while reconciling"
        )

    bases = _search_bases(source_root, include_paths)
    unavailable = sorted(str(base) for base in bases if not base.is_dir())
    if unavailable:
        return _denominator_unknown(
            GAP_SELECTION_ROOT_UNAVAILABLE,
            "selection base directories are not readable: " + ", ".join(unavailable),
            command_entries=len(rows),
        )
    allowed = _allowed_sources(source_root, include_paths, exclude_paths)
    if allowed is None:
        return _denominator_unknown(
            GAP_SELECTION_ROOT_UNAVAILABLE,
            "path selection could not be evaluated",
            command_entries=len(rows),
        )

    gaps: List[Dict[str, Any]] = []
    if not rows:
        gaps.append(_gap(GAP_COMPILE_DATABASE_EMPTY, "compile database has no command entries"))

    expected: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    duplicates = 0
    filtered = 0
    for row in rows:
        try:
            identity = command_identity(row, database.parent)
        except (OSError, ValueError) as exc:
            return _denominator_unknown(
                GAP_COMMAND_IDENTITY_FAILED,
                f"row for {str(row.get('file') or '<unknown file>')!r}: "
                f"{type(exc).__name__}: {exc}",
                command_entries=len(rows),
            )
        source = Path(identity["source"])
        if source.suffix.lower() not in _JOB_SOURCE_SUFFIXES or str(source) not in allowed:
            filtered += 1
            continue
        command_id = digest_json(identity)
        if command_id in seen_ids:
            duplicates += 1
            continue
        seen_ids.add(command_id)
        expected.append(
            {
                "source": identity["source"],
                "command_id": command_id,
                "directory": identity["directory"],
            }
        )

    contexts = [value if isinstance(value, dict) else {} for value in stored]
    by_command: Dict[str, List[Dict[str, Any]]] = {}
    for context in contexts:
        by_command.setdefault(str(context.get("command_id") or ""), []).append(context)

    current: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []
    stale: List[Dict[str, Any]] = []
    for entry in expected:
        command_id = str(entry["command_id"])
        candidates = by_command.get(command_id, [])
        if not candidates:
            missing.append({"source": entry["source"], "command_id": command_id})
            gaps.append(
                _gap(
                    GAP_COMMAND_NOT_INDEXED,
                    "compile database expects this command; no stored compilation "
                    "context carries its identity",
                    source=str(entry["source"]),
                    command_id=command_id,
                )
            )
            continue
        covered = False
        for context in candidates:
            context_id = str(context.get("build_context_id") or "")
            reason, detail = _stored_context_reason(context)
            if reason:
                stale.append(
                    {
                        "source": entry["source"],
                        "command_id": command_id,
                        "build_context_id": context_id,
                        "reason": reason,
                    }
                )
                gaps.append(
                    _gap(
                        reason,
                        detail,
                        source=str(entry["source"]),
                        command_id=command_id,
                        build_context_id=context_id,
                    )
                )
            elif not covered:
                covered = True
                current.append(
                    {
                        "source": entry["source"],
                        "command_id": command_id,
                        "build_context_id": context_id,
                    }
                )
            else:
                gaps.append(
                    _gap(
                        GAP_DUPLICATE_STORED_CONTEXT,
                        "command already covered by another current context",
                        source=str(entry["source"]),
                        command_id=command_id,
                        build_context_id=context_id,
                    )
                )

    unexpected: List[Dict[str, Any]] = []
    for context in contexts:
        command_id = str(context.get("command_id") or "")
        if command_id in seen_ids:
            continue
        context_id = str(context.get("build_context_id") or "")
        detail = (
            "stored compilation context has no command_id to reconcile"
            if not command_id
            else "stored compilation context does not correspond to any expected "
            "command in the current selection"
        )
        unexpected.append(
            {
                "source": _stored_source(context),
                "command_id": command_id,
                "build_context_id": context_id,
            }
        )
        gaps.append(
            _gap(
                GAP_UNEXPECTED_STORED_CONTEXT,
                detail,
                source=_stored_source(context),
                command_id=command_id,
                build_context_id=context_id,
            )
        )

    reasons: List[str] = []
    for gap in gaps:
        if gap["reason"] not in reasons:
            reasons.append(gap["reason"])

    return _payload(
        "reconciled",
        reasons=reasons,
        gaps=gaps,
        expected=expected,
        current=current,
        missing=missing,
        stale=stale,
        unexpected=unexpected,
        stats={
            "command_entries": len(rows),
            "duplicate_command_entries": duplicates,
            "filtered_command_entries": filtered,
            "stored_contexts": len(contexts),
        },
    )
