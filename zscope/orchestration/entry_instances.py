"""Entry-level compile-instance enumeration forming the scan scheduling boundary.

Each precise ``(BuildContext, USR)`` pair is one independent analysis instance.
Unknown is never a wildcard: variants that cannot be enumerated, failed
extraction, or an entry absent from a variant stay explicit coverage gaps.
No first-command or first-context fallback exists here; every program-facts
query carries the exact build context it serves, and an accepted instance
must carry a returned identity that names exactly that context. An explicit
entry file is never bypassed by a same-name file-less re-query: only a
precisely mapped definition file authorizes, otherwise the gap names the
unselected file.
"""

from __future__ import annotations

import logging
import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..config.function_entry import FunctionEntry

logger = logging.getLogger(__name__)

ENTRY_INSTANCE_SCHEMA = "zscope.entry-instances.v1"

GAP_INCOMPLETE_INSTANCE = "incomplete_compilation_instance"
GAP_ENTRY_ABSENT = "entry_absent_in_variant"
GAP_NO_INSTANCE = "no_compilation_instance"
GAP_INSTANCES_UNAVAILABLE = "compilation_instances_unavailable"
GAP_INVALID_INSTANCE = "invalid_compilation_instance"

_NOTE_SCOPE_THREADING = (
    "Instance scheduling is boundary-level: entry analysis still consumes the "
    "file navigation projection unless the caller dispatches "
    "``zscope.retrieval.instance_index.run_instance_analysis``, which analyzes "
    "each scheduled instance with program facts pinned to its exact build "
    "context. Migrating the remaining navigation/graph/semantic consumers is "
    "remaining S01 wiring."
)


@dataclass
class EntryInstance:
    """One scheduled analysis instance: an exact build context plus USR."""

    build_context_id: str
    usr: str
    identity: str
    source: str
    definition_file: str = ""
    selected_by: str = "entry_file"
    function_names: List[str] = field(default_factory=list)

    def to_payload(self) -> Dict[str, Any]:
        return {
            "identity": self.identity,
            "build_context_id": self.build_context_id,
            "usr": self.usr,
            "source": self.source,
            "definition_file": self.definition_file,
            "selected_by": self.selected_by,
            "function_names": list(self.function_names),
        }


@dataclass
class VariantGap:
    """A precise coverage gap scoped to one entry and one build context."""

    function_name: str
    reason: str
    build_context_id: str = ""
    source: str = ""
    detail: str = ""

    def to_payload(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "build_context_id": self.build_context_id,
            "source": self.source,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class EntryInstancePlan:
    """The scheduling boundary between scan entries and compile instances."""

    status: str
    reasons: List[str] = field(default_factory=list)
    instances: List[EntryInstance] = field(default_factory=list)
    gaps: List[VariantGap] = field(default_factory=list)
    entry_records: List[Dict[str, Any]] = field(default_factory=list)
    entry_count: int = 0
    variant_entry_count: int = 0
    fact_queries: int = 0
    compile_database: Optional[Dict[str, Any]] = None
    notes: List[str] = field(default_factory=lambda: [_NOTE_SCOPE_THREADING])

    @property
    def boundary_coverage_complete(self) -> bool:
        if self.status != "planned":
            return False
        return not self.gaps and all(
            bool(record.get("coverage_complete")) for record in self.entry_records
        )

    def to_payload(self, analysis: Any = None) -> Dict[str, Any]:
        analysis_payload = _analysis_payload(analysis)
        scheduled_instances: Optional[int] = None
        scan_coverage_complete = False
        scan_coverage_reasons = ["entry_analysis_not_instance_scoped"]
        if analysis_payload is not None:
            scheduled = analysis_payload.get("scheduled_instances")
            scheduled_instances = int(scheduled) if isinstance(scheduled, int) else None
            scan_coverage_complete = bool(analysis_payload.get("scan_coverage_complete"))
            scan_coverage_reasons = [
                str(reason) for reason in (analysis_payload.get("reasons") or [])
            ]
        payload: Dict[str, Any] = {
            "schema": ENTRY_INSTANCE_SCHEMA,
            "status": self.status,
            "reasons": list(self.reasons),
            "entries": self.entry_count,
            "variant_entries": self.variant_entry_count,
            "planned_instances": len(self.instances),
            "scheduled_instances": scheduled_instances,
            "instances": [instance.to_payload() for instance in self.instances],
            "gaps": [gap.to_payload() for gap in self.gaps],
            "entry_records": [dict(record) for record in self.entry_records],
            "fact_queries": self.fact_queries,
            "boundary_coverage_complete": self.boundary_coverage_complete,
            "scan_coverage_complete": scan_coverage_complete,
            "scan_coverage_reasons": scan_coverage_reasons,
            "compile_database": self.compile_database,
            "notes": list(self.notes),
        }
        if analysis_payload is not None:
            payload["instance_analysis"] = analysis_payload
        return payload


def _not_applicable(reasons: List[str], entry_count: int = 0) -> EntryInstancePlan:
    return EntryInstancePlan(status="not_applicable", reasons=reasons, entry_count=entry_count)


def _normalized_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if not text:
        return ""
    text = posixpath.normpath(text)
    if text == ".":
        return ""
    return text.lower() if os.name == "nt" else text


def _files_equal(left: Any, right: Any) -> bool:
    """Exact normalized equality; no suffix tolerance may authorize mapping."""

    a, b = _normalized_path(left), _normalized_path(right)
    return bool(a) and bool(b) and a == b


def _unique_entries(entries: Sequence[FunctionEntry]) -> List[FunctionEntry]:
    unique: List[FunctionEntry] = []
    seen = set()
    for entry in entries:
        key = (
            entry.function_name,
            _normalized_path(entry.file_path),
            FunctionEntry.normalize_signature(entry.signature),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def _context_list(values: Any) -> List[Dict[str, Any]]:
    if not isinstance(values, list):
        return []
    return [dict(value) for value in values if isinstance(value, dict)]


def _definition_file(facts: Dict[str, Any]) -> str:
    for body in facts.get("functions") or []:
        if not isinstance(body, dict):
            continue
        owner = body.get("owner") or {}
        if isinstance(owner, dict) and owner.get("file"):
            return str(owner["file"])
    return ""


def _identity_from_facts(facts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    identity = facts.get("function_identity")
    return identity if isinstance(identity, dict) else None


def _verified_identity(
    facts: Dict[str, Any], context_id: str
) -> Tuple[Optional[Tuple[str, str]], str]:
    """Return ``(usr, key)`` only when the returned identity names this context.

    The query parameter alone proves nothing: a getter that answers for
    another build context, or returns an identity without one, must not have
    its identity mixed into this context's scheduling scope.
    """

    envelope = str(facts.get("build_context_id") or "")
    if envelope and envelope != context_id:
        return None, "identity_context_mismatch"
    identity = _identity_from_facts(facts)
    if not identity or not str(identity.get("usr") or ""):
        return None, "identity_context_unverified"
    identity_context = str(identity.get("build_context_id") or "")
    if not identity_context:
        return None, "identity_context_unverified"
    if identity_context != context_id:
        return None, "identity_context_mismatch"
    usr = str(identity["usr"])
    key = str(identity.get("key") or "") or f"{context_id}:{usr}"
    return (usr, key), ""


def _query_context_instances(
    facts_getter: Any,
    function_name: str,
    file_path: str,
    context: Dict[str, Any],
) -> Tuple[List[Tuple[str, str, str, str]], Optional[str], str, int]:
    """Resolve the entry inside one exact build context.

    Every query carries ``build_context_id`` and every accepted instance must
    carry a returned identity that names exactly that context. The file-less
    retry stays inside the same context, but it cannot bypass an explicit
    entry file: its result is authorized only when the recorded definition
    file maps precisely to the entry's own file, otherwise the entry keeps a
    conservative gap with the unselected file named.
    """

    context_id = str(context.get("build_context_id") or "")
    queries = 0
    normalized_file = _normalized_path(file_path)
    if normalized_file == ".." or normalized_file.startswith("../"):
        return [], GAP_ENTRY_ABSENT, f"entry file {file_path} is outside the project", queries
    facts = (
        facts_getter(function_name, file_path, build_context_id=context_id)
        if file_path
        else facts_getter(function_name, "", build_context_id=context_id)
    )
    queries += 1
    facts = facts if isinstance(facts, dict) else {}
    retried = False
    if file_path and str(facts.get("reason") or "") == "function_identity_not_found":
        facts = facts_getter(function_name, "", build_context_id=context_id)
        queries += 1
        facts = facts if isinstance(facts, dict) else {}
        retried = True

    if facts.get("complete"):
        verified, verify_reason = _verified_identity(facts, context_id)
        if not verified:
            detail = (
                f"requested build context {context_id}; "
                f"returned identity names {str(facts.get('build_context_id') or '<none>')}"
            )
            return [], verify_reason, detail, queries
        usr, key = verified
        definition_file = _definition_file(facts)
        if not file_path:
            return [(usr, key, definition_file, "function_query")], None, "", queries
        if not retried:
            # The file-scoped query already enforced the entry file on the
            # exact-context store; the returned identity is context-verified.
            return [(usr, key, definition_file, "entry_file")], None, "", queries
        if _files_equal(definition_file, file_path):
            # Precise source mapping: the recorded definition file is exactly
            # the entry's own file.
            return [(usr, key, definition_file, "definition_file_match")], None, "", queries
        return (
            [],
            GAP_ENTRY_ABSENT,
            f"same-name definition recorded at {definition_file or '<unknown file>'}; "
            f"entry file {file_path} has no definition in this build context",
            queries,
        )

    reason = str(facts.get("reason") or "")
    if reason == "ambiguous_function_identity":
        choices = [c for c in facts.get("function_choices") or [] if isinstance(c, dict)]
        if file_path and retried:
            # The retry was not file-constrained: only an exactly mapped
            # definition file may select choices here.
            matching = [c for c in choices if _files_equal(c.get("file"), file_path)]
            if not matching:
                unselected = ", ".join(
                    sorted({_normalized_path(c.get("file")) or "<unknown>" for c in choices})
                )
                return (
                    [],
                    GAP_ENTRY_ABSENT,
                    f"same-name definitions recorded at {unselected}; entry file "
                    f"{file_path} has no definition in this build context",
                    queries,
                )
            choices = matching
        found: List[Tuple[str, str, str, str]] = []
        unresolved: List[str] = []
        for choice in choices:
            usr = str(choice.get("usr") or "")
            if not usr:
                continue
            choice_facts = facts_getter(usr, "", build_context_id=context_id)
            queries += 1
            choice_facts = choice_facts if isinstance(choice_facts, dict) else {}
            if choice_facts.get("complete"):
                choice_verified, choice_reason = _verified_identity(choice_facts, context_id)
                if choice_verified:
                    choice_usr, choice_key = choice_verified
                    found.append(
                        (
                            choice_usr,
                            choice_key,
                            _definition_file(choice_facts),
                            "function_choice",
                        )
                    )
                    continue
                unresolved.append(f"{usr}:{choice_reason}")
                continue
            unresolved.append(f"{usr}:{choice_facts.get('reason') or 'incomplete'}")
        if found:
            detail = f"unresolved choices: {'; '.join(unresolved)}" if unresolved else ""
            return found, None, detail, queries
        return (
            [],
            "ambiguous_function_identity",
            "; ".join(unresolved) or "no overload choice resolved to complete facts",
            queries,
        )
    if reason == "function_identity_not_found":
        return [], GAP_ENTRY_ABSENT, "", queries
    if reason == "build_context_not_found":
        return [], "build_context_not_found", "", queries
    return [], "facts_incomplete", reason or "complete_program_facts", queries


def _function_contexts(code_index: Any, function_name: str, file_path: str) -> List[Dict[str, Any]]:
    getter = getattr(code_index, "get_function_build_contexts", None)
    if not callable(getter):
        return []
    values = getter(function_name, file_path)
    return _context_list(values)


def _compile_database_summary(compile_commands_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if compile_commands_path is None:
        return None
    database = Path(compile_commands_path)
    if not database.is_file():
        return None
    try:
        from ..retrieval.indexing_inventory import compilation_contexts

        selection = compilation_contexts(database)
        variant_sources = {
            str(row.get("source")): len(row.get("contexts") or [])
            for row in selection.get("source_variants") or []
            if len(row.get("contexts") or []) > 1
        }
        return {
            "path": str(database),
            "command_entries": int(selection.get("command_entries") or 0),
            "compile_contexts": int(selection.get("compile_contexts") or 0),
            "unique_source_files": len(
                {str(row.get("source")) for row in selection.get("contexts") or []}
            ),
            "variant_sources": variant_sources,
            "invalid_commands": len(selection.get("invalid_commands") or []),
        }
    except Exception as exc:  # inventory must not fabricate coverage either way
        logger.warning("Compile database inventory unavailable: %s", exc)
        return {"path": str(database), "error": f"inventory_unavailable: {exc}"}


def _analysis_payload(analysis: Any) -> Optional[Dict[str, Any]]:
    """Normalize an instance-analysis report into its payload mapping."""

    if analysis is None:
        return None
    if isinstance(analysis, dict):
        return dict(analysis)
    to_payload = getattr(analysis, "to_payload", None)
    if callable(to_payload):
        value = to_payload()
        return dict(value) if isinstance(value, dict) else None
    return None


def _unavailable_plan(
    reasons: List[str],
    entries: Sequence[FunctionEntry],
    compile_commands_path: Optional[Path],
) -> EntryInstancePlan:
    gaps = [
        VariantGap(entry.function_name, GAP_INSTANCES_UNAVAILABLE)
        for entry in _unique_entries(entries)
    ]
    return EntryInstancePlan(
        status="unavailable",
        reasons=reasons,
        gaps=gaps,
        entry_count=len(gaps),
        compile_database=_compile_database_summary(compile_commands_path),
    )


def plan_entry_instances(
    code_index: Any,
    entries: Sequence[FunctionEntry],
    *,
    compile_commands_path: Optional[Path] = None,
) -> EntryInstancePlan:
    """Enumerate per-entry compile instances without any wildcard fallback.

    The returned plan is the scheduling boundary: every scheduled instance is
    an exact ``(build_context_id, usr)`` pair verified through a scoped
    program-facts query, and everything unverifiable stays a gap.
    """

    if str(getattr(code_index, "language", "c_cpp") or "c_cpp") == "java":
        return _not_applicable(["java_scan_has_no_compilation_instances"], len(entries))
    backend_name = str(getattr(code_index, "backend_name", "") or "").lower()
    if backend_name in {"regex", "joern"}:
        return _not_applicable(
            [f"{backend_name}_backend_has_no_compilation_instances"], len(entries)
        )

    contexts_getter = getattr(code_index, "get_build_contexts", None)
    facts_getter = getattr(code_index, "get_function_program_facts", None)
    if not callable(contexts_getter) or not callable(facts_getter):
        return _unavailable_plan(
            ["compilation_instance_queries_unsupported"], entries, compile_commands_path
        )
    if not _context_list(contexts_getter("")):
        return _unavailable_plan(
            ["compilation_instances_unavailable"], entries, compile_commands_path
        )

    instances: Dict[Tuple[str, str], EntryInstance] = {}
    gaps: List[VariantGap] = []
    records: List[Dict[str, Any]] = []
    fact_queries = 0
    variant_entry_count = 0
    unique_entries = _unique_entries(entries)

    for entry in unique_entries:
        name = entry.function_name
        file_path = str(entry.file_path or "")
        scoped = False
        note = ""
        if file_path:
            variants = _context_list(contexts_getter(file_path))
            if variants:
                scoped = True
                if len(variants) > 1:
                    variant_entry_count += 1
            else:
                # The entry source is not itself a compiled TU (for example a
                # header); anchor on contexts whose facts contain the function.
                variants = _function_contexts(code_index, name, file_path)
                note = "entry_source_not_compiled"
        else:
            variants = _function_contexts(code_index, name, "")
            note = "entry_source_unresolved"

        entry_instances: List[EntryInstance] = []
        entry_gaps: List[VariantGap] = []
        for context in variants:
            context_id = str(context.get("build_context_id") or "")
            source = str(context.get("source") or "")
            if not context_id:
                entry_gaps.append(
                    VariantGap(
                        name,
                        GAP_INVALID_INSTANCE,
                        source=source,
                        detail="stored compilation instance has no build_context_id",
                    )
                )
                continue
            if str(context.get("status") or "") != "indexed" or not bool(
                context.get("dependencies_complete")
            ):
                entry_gaps.append(VariantGap(name, GAP_INCOMPLETE_INSTANCE, context_id, source))
                continue
            found, reason, detail, queries = _query_context_instances(
                facts_getter, name, file_path, context
            )
            fact_queries += queries
            if found:
                for usr, identity, definition_file, selected_by in found:
                    key = (context_id, usr)
                    instance = instances.get(key)
                    if instance is None:
                        instance = EntryInstance(
                            build_context_id=context_id,
                            usr=usr,
                            identity=identity,
                            source=source,
                            definition_file=definition_file,
                            selected_by=selected_by,
                        )
                        instances[key] = instance
                    if name not in instance.function_names:
                        instance.function_names.append(name)
                    entry_instances.append(instance)
            else:
                entry_gaps.append(VariantGap(name, str(reason), context_id, source, detail))

        if not scoped and not variants and not entry_instances:
            entry_gaps.append(
                VariantGap(
                    name,
                    GAP_NO_INSTANCE,
                    detail=note or "no compilation instance contains the function",
                )
            )
        record: Dict[str, Any] = {
            "function_name": name,
            "file_path": file_path,
            "signature": FunctionEntry.normalize_signature(entry.signature),
            "variants": len(variants),
            "instances": [instance.identity for instance in entry_instances],
            "gaps": len(entry_gaps),
            "coverage_complete": scoped and bool(entry_instances) and not entry_gaps,
        }
        if note and not record["coverage_complete"]:
            record["note"] = note
        records.append(record)
        gaps.extend(entry_gaps)

    return EntryInstancePlan(
        status="planned",
        instances=list(instances.values()),
        gaps=gaps,
        entry_records=records,
        entry_count=len(unique_entries),
        variant_entry_count=variant_entry_count,
        fact_queries=fact_queries,
    )
