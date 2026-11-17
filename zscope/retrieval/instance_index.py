"""Per-instance analysis scope: one exact ``(BuildContext, native USR)``.

An analysis instance is a single precise compilation instance of one entry: an
exact build context plus the native USR that names the entry inside it.  The
scoped ``CodeIndex`` facade here pins every program-facts query to that single
context so the real Analyzer consumes only the facts of the instance being
analyzed.

Unknown is never a wildcard.  A query for another build context, a returned
identity that names a different context, a missing identity, or a program-facts
answer that is not complete all stay explicit scope gaps and never fall back to
the first instance, a bare function name, or another build.  Navigation, graph
and semantic consumers that cannot be bound to one build are *declared* in
``unscoped_consumers`` rather than silently trusted; they never receive a build
identity from this facade.

This module only defines the scope, the facade and the result shapes.  The real
execution path lives on ``ParallelAnalyzer.analyze_entry_instances`` so that it
reuses the existing Analyzer, candidate ledger, cache and validation chain.
"""

from __future__ import annotations

import logging
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, cast

logger = logging.getLogger(__name__)

INSTANCE_ANALYSIS_SCHEMA = "zscope.instance-analysis.v1"

# Scope gap reasons.  ``identity_context_mismatch`` and
# ``identity_context_unverified`` mirror the planning boundary so a caller that
# sees the same token knows the instance was not authorized for analysis.
GAP_FOREIGN_BUILD_CONTEXT = "foreign_build_context"
GAP_UNKNOWN_BUILD_CONTEXT = "unknown_build_context"
GAP_IDENTITY_CONTEXT_MISMATCH = "identity_context_mismatch"
GAP_IDENTITY_CONTEXT_UNVERIFIED = "identity_context_unverified"
GAP_INSTANCE_FACTS_INCOMPLETE = "instance_facts_incomplete"
GAP_STALE_BUILD_CONTEXT = "stale_build_context"
GAP_INSTANCE_NOT_ANALYZED = "instance_not_analyzed"
GAP_UNSCOPED_CONSUMER = "unscoped_consumer"
GAP_AMBIGUOUS_FUNCTION_IDENTITY = "ambiguous_function_identity"

_NOTE_UNSCOPED_CONSUMERS = (
    "Graph/semantic/navigation consumers that cannot be bound to one build are "
    "blocked at the scoped index: they return an empty result and a recorded "
    "gap, so they never feed another variant's data into candidates, validation "
    "or rebuttal.  Their per-instance migration is remaining S01 consumer work."
)
_NOTE_FIRST_SLICE = (
    "This slice schedules the real Analyzer per scheduled instance with program "
    "facts pinned to that instance.  It never runs the project-wide semantic "
    "model, deterministic fact pass or active discovery; contract-derived "
    "recall beyond the generator's standard roots is a declared bounded gap.  "
    "Link targets and full-variant modeling are not claimed."
)


@dataclass(frozen=True)
class InstanceScope:
    """One analysis instance pinned to an exact build context and native USR."""

    build_context_id: str
    usr: str
    identity: str
    source: str = ""
    function_names: Tuple[str, ...] = ()
    selected_by: str = ""

    @classmethod
    def from_entry_instance(cls, instance: Any) -> "InstanceScope":
        names = tuple(
            str(name)
            for name in (getattr(instance, "function_names", ()) or ())
            if str(name).strip()
        )
        return cls(
            build_context_id=str(getattr(instance, "build_context_id", "") or ""),
            usr=str(getattr(instance, "usr", "") or ""),
            identity=str(getattr(instance, "identity", "") or ""),
            source=str(getattr(instance, "source", "") or ""),
            function_names=names,
            selected_by=str(getattr(instance, "selected_by", "") or ""),
        )

    def names_entry(self, func_name: str, file_path: str = "") -> bool:
        """Whether a query names the pinned entry symbol (never a bare guess)."""

        text = str(func_name or "").strip()
        if not text:
            return False
        if self.usr and text == self.usr:
            return True
        return text in self.function_names

    def wrap(self, base: Any) -> Any:
        return wrap_scoped_code_index(base, self)

    def to_payload(self) -> Dict[str, Any]:
        return {
            "identity": self.identity,
            "build_context_id": self.build_context_id,
            "usr": self.usr,
            "source": self.source,
            "function_names": list(self.function_names),
            "selected_by": self.selected_by,
        }


def _incomplete_facts(reason: str, *, detail: str = "", **extra: Any) -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "complete": False,
        "events": [],
        "accesses": [],
        "functions": [],
        "reason": reason,
        "scope_rejected": reason,
    }
    if detail:
        value["detail"] = detail
    value.update(extra)
    return value


def _same_text_path(left: Any, right: Any) -> bool:
    """Exact normalized path equality; no suffix tolerance may authorize a body."""

    a = posixpath.normpath(str(left or "").replace("\\", "/").strip())
    b = posixpath.normpath(str(right or "").replace("\\", "/").strip())
    if not a or not b or a == "." or b == ".":
        return False
    if os.name == "nt":
        return a.lower() == b.lower()
    return a == b


def _empty_store(kind: str) -> Any:
    if kind == "dict":
        return {}
    if kind == "set":
        return set()
    if kind == "list":
        return []
    return None


def _as_positive_int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def _store_kind_for_name(name: str) -> str:
    """Best-effort typed empty for an unlisted raw store/cache attribute."""

    lowered = str(name or "").lower()
    if lowered.endswith("db") or lowered.endswith("handle") or lowered.endswith("client"):
        return "none"
    if "miss_cache" in lowered:
        return "set"
    if lowered.endswith("records") or lowered.endswith("registrations") or lowered.endswith("list"):
        return "list"
    if (
        lowered.endswith("paths")
        or lowered.endswith("functions")
        or lowered.endswith("names")
        or lowered.endswith("entries")
        or lowered.endswith("occurrences")
    ):
        return "list"
    if (
        lowered.endswith("index")
        or lowered.endswith("cache")
        or lowered.endswith("map")
        or lowered.endswith("lru")
    ):
        return "dict"
    return "none"


def _iter_build_ids(value: Any) -> Iterator[str]:
    """Yield every non-empty ``build_context_id`` receipt inside a payload."""

    if isinstance(value, dict):
        for key, item in value.items():
            if key == "build_context_id":
                text = str(item or "")
                if text:
                    yield text
            else:
                yield from _iter_build_ids(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_build_ids(item)


class ScopedCodeIndex:
    """A ``CodeIndex`` facade that only serves exactly scoped data.

    Program-facts queries are pinned to the instance's build context and the
    entry function body is resolved to the pinned symbol.  Graph, semantic,
    navigation and raw-store consumers that cannot be bound to one exact build
    **return an explicit, typed empty result and record a gap** instead of
    delegating to the first projection; a consumer that feeds candidates,
    validation, rebuttal or an LLM tool therefore never receives another
    variant's data.  Only an explicit scope-neutral allowlist (paths, language,
    backend profile metadata, locks, source reads) still delegates.  ``close``
    is a no-op because the owner of the underlying index closes it.
    """

    # Scope-neutral source/metadata access that cannot carry another build's
    # symbol facts and may still delegate unchanged.
    _SCOPE_NEUTRAL_METHODS = frozenset(
        {
            "get_file_snippet",
            "get_file_line_count",
            "resolve_existing_file",
            "capability_status",
        }
    )
    # Scope-neutral plain attributes (paths, language/profile metadata, locks).
    _SCOPE_NEUTRAL_ATTRIBUTES = frozenset(
        {
            "project_root",
            "source_root",
            "language",
            "backend_name",
            "compile_commands_path",
            "indexing_config",
            "include_paths",
            "exclude_paths",
            "backend",
            "_index_ready",
            "_index_epoch",
            "_capability_lock",
            "_cache_lock",
            "_declaration_comment_index_lock",
            "_macro_definition_index_lock",
            "_global_definition_index_lock",
        }
    )
    # Raw navigation stores, caches and database handles: denied and replaced
    # with a usable empty value of the right type (never None causing an
    # AttributeError that would be mistaken for isolation).
    _BLOCKED_STORES: Dict[str, str] = {
        "_backend": "none",
        "_db": "none",
        "db": "none",
        "linked_targets": "none",
        "joern_client": "none",
        "_function_index": "dict",
        "_function_alias_index": "dict",
        "_function_query_index": "dict",
        "_function_file_index": "dict",
        "_function_file_resolution_cache": "dict",
        "_declaration_comment_index": "dict",
        "_regex_type_definition_cache": "dict",
        "_file_lines_cache": "dict",
        "_function_impl_cache": "dict",
        "_macro_definition_index": "dict",
        "_global_definition_index": "dict",
        "_type_definition_index": "dict",
        "_shared_cache_lru": "dict",
        "_macro_definition_miss_cache": "set",
        "_callback_registrations": "list",
    }
    # Graph/semantic/enumeration consumers that span the whole navigation index
    # and cannot be bound to one build.  They return an empty list plus a gap.
    _BLOCKED_LIST_METHODS = frozenset(
        {
            "find_function_identities",
            "find_function_callers",
            "find_function_pointers",
            "find_type_infos",
            "find_java_methods_by_tokens",
            "get_header_declared_functions",
            "callback_registrations",
        }
    )
    # Consumers that return a mapping; they return ``{}`` plus a gap.
    _BLOCKED_DICT_METHODS = frozenset(
        {
            "get_data_flow",
        }
    )

    def __init__(self, base: Any, scope: InstanceScope):
        object.__setattr__(self, "_base", base)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "_fact_queries", [])
        object.__setattr__(self, "_scope_gaps", [])
        object.__setattr__(self, "_blocked_calls", {})

    # -- consumer policy ---------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        base = object.__getattribute__(self, "_base")
        if name in ScopedCodeIndex._SCOPE_NEUTRAL_ATTRIBUTES:
            return getattr(base, name, None)
        store_kind = ScopedCodeIndex._BLOCKED_STORES.get(name)
        if store_kind is not None:
            self._record_blocked(name, detail=f"unscoped store '{name}' is not per-instance")
            return _empty_store(store_kind)
        value = getattr(base, name, None)
        if value is None:
            # The base has no such attribute; nothing to leak.
            return None
        if not callable(value):
            # Any other data attribute is a raw cache/store: denied by default.
            self._record_blocked(
                name, detail=f"unscoped data attribute '{name}' is not per-instance"
            )
            return _empty_store(_store_kind_for_name(name))
        if name in ScopedCodeIndex._SCOPE_NEUTRAL_METHODS:
            return value
        return self._blocked_consumer(name)

    def _blocked_consumer(self, name: str) -> Any:
        def _blocked(*args: Any, **kwargs: Any) -> Any:
            self._record_blocked(
                name,
                detail=f"'{name}' cannot be bound to one exact build; empty result",
            )
            if name in ScopedCodeIndex._BLOCKED_LIST_METHODS:
                return []
            if name in ScopedCodeIndex._BLOCKED_DICT_METHODS:
                return {}
            return None

        _blocked.__name__ = name
        return _blocked

    def close(self) -> None:  # the owner closes the shared index
        return None

    def base_index(self) -> Any:
        """The unwrapped index this scope delegates to."""

        return self.__dict__["_base"]

    def has_scoped_function_body(self, func_name: str) -> bool:
        """Whether current native receipts name one body in this instance.

        This is a negative preflight for graph traversal: system/external
        callees are ordinary non-project edges and must not be reported as a
        blocked body consumer.  A positive answer is not authority by itself;
        ``get_function_impl`` still performs all currentness, navigation and
        source-range checks.
        """

        return (
            not self._receipt_scope_problem()
            and self._resolve_instance_identity(str(func_name or "").strip()) is not None
        )

    def coverage_index(self) -> Any:
        """The unwrapped index a coverage consumer must read.

        Scoped enumeration (``get_build_contexts``) is pinned to one instance on
        purpose: instance semantics require exactly one current build context.
        Coverage bookkeeping needs the opposite view — every stored instance of
        the source — so it asks for the base index instead of widening the
        scoped enumeration.
        """

        return self.__dict__["_base"]

    @property
    def pinned_build_context_id(self) -> str:
        """The one build context this facade is allowed to serve."""

        return str(self.scope.build_context_id or "")

    # -- scoped program facts ---------------------------------------------

    def get_function_program_facts(
        self, func_name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        pinned = self.scope.build_context_id
        if build_context_id and build_context_id != pinned:
            self._record_gap(
                GAP_FOREIGN_BUILD_CONTEXT,
                func_name,
                detail=(
                    f"query requested build context {build_context_id}; this "
                    f"instance is {pinned or '<none>'}"
                ),
            )
            return _incomplete_facts(
                GAP_FOREIGN_BUILD_CONTEXT,
                detail=f"requested {build_context_id}",
                observed_build_context_id=build_context_id,
            )
        if not pinned:
            self._record_gap(
                GAP_UNKNOWN_BUILD_CONTEXT, func_name, detail="instance has no build context"
            )
            return _incomplete_facts(GAP_UNKNOWN_BUILD_CONTEXT)

        context_status = self._context_status()
        if context_status != "current":
            self._record_gap(
                context_status,
                func_name,
                detail="instance source/header inputs are no longer current",
            )
            return _incomplete_facts(context_status, detail="instance context is not current")

        is_entry = self.scope.names_entry(func_name, file_path)
        query_name = self.scope.usr if (is_entry and self.scope.usr) else func_name
        facts = self._base.get_function_program_facts(
            query_name, file_path, build_context_id=pinned
        )
        facts = facts if isinstance(facts, dict) else {}
        observed = str(facts.get("build_context_id") or "")
        complete = bool(facts.get("complete"))
        record: Dict[str, Any] = {
            "function_name": str(func_name or ""),
            "queried_usr": query_name if query_name != func_name else "",
            "is_entry": bool(is_entry),
            "file_path": str(file_path or ""),
            "requested_build_context_id": pinned,
            "observed_build_context_id": observed,
            "complete": complete,
            "reason": str(facts.get("reason") or ""),
        }
        self.__dict__["_fact_queries"].append(record)

        # A returned answer that names another build context is never usable,
        # whether it is the entry or a callee.
        if observed and observed != pinned:
            self._record_gap(
                GAP_IDENTITY_CONTEXT_MISMATCH,
                func_name,
                detail=f"requested {pinned}; returned identity names {observed}",
            )
            return _incomplete_facts(
                GAP_IDENTITY_CONTEXT_MISMATCH,
                detail=f"returned identity names {observed}",
                observed_build_context_id=observed,
            )

        if not is_entry:
            # A callee/other symbol that simply has no recorded facts in this
            # one instance is an ordinary miss, not a scope violation.  An
            # incomplete answer never carries another build's identity.
            if complete and not observed:
                return _incomplete_facts(GAP_IDENTITY_CONTEXT_UNVERIFIED)
            return facts

        # The entry itself must resolve to complete facts under its exact USR.
        if not complete:
            reason = str(facts.get("reason") or GAP_INSTANCE_FACTS_INCOMPLETE)
            self._record_gap(reason, func_name, detail="entry facts not complete")
            return _incomplete_facts(reason)
        if not observed:
            self._record_gap(
                GAP_IDENTITY_CONTEXT_UNVERIFIED,
                func_name,
                detail="complete entry facts carry no build context identity",
            )
            return _incomplete_facts(GAP_IDENTITY_CONTEXT_UNVERIFIED)
        identity = facts.get("function_identity")
        identity = identity if isinstance(identity, dict) else {}
        identity_usr = str(identity.get("usr") or "")
        identity_context = str(identity.get("build_context_id") or "")
        if identity_usr != self.scope.usr or identity_context != pinned:
            self._record_gap(
                GAP_IDENTITY_CONTEXT_UNVERIFIED,
                func_name,
                detail=(
                    f"entry identity {identity_usr or '<none>'}@"
                    f"{identity_context or '<none>'} does not match {self.scope.usr}@{pinned}"
                ),
            )
            return _incomplete_facts(GAP_IDENTITY_CONTEXT_UNVERIFIED)
        # Macro calls keep their source spelling while Clang's CallExpr names
        # the expanded wrapper.  Carry the exact per-function macro-reference
        # receipts beside the AST/CFG facts so contract consumers can bind
        # ``LOCK(x)``/``SAFE_FREE(x)`` to the reviewed macro USR instead of
        # guessing from a name.  These rows have already passed the same
        # BuildContext and (USR,file,line) owner checks as the function body.
        symbol_receipts = self._receipt_symbol_members_from_current_facts(facts)
        facts = dict(facts)
        facts["referenced_macros"] = list(symbol_receipts["referenced_macros"])
        facts["referenced_globals"] = list(symbol_receipts["referenced_globals"])
        self.__dict__["_entry_facts_complete"] = True
        return facts

    def get_function_impl(
        self,
        func_name: str,
        max_lines: Optional[int] = 500,
        warn_missing: bool = True,
        include_context: bool = True,
        file_path: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Return a body authorized by this exact compilation instance.

        The pinned entry is resolved directly.  A reachable same-instance
        callee is resolved through a child scope only when native receipts name
        one unique ``(BuildContext, USR, file, line)`` owner.  The child then
        performs the same navigation/body-range checks as an entry.  Unknown,
        external, cross-TU, or ambiguous callees remain empty; the shared
        navigation projection is never used as authority by itself.
        """

        if not self._entry_query_matches(func_name, file_path):
            child = self._scoped_callee_view(func_name, file_path)
            if child is None:
                self._record_blocked(
                    "get_function_impl",
                    detail="body has no unique same-instance native function receipt",
                )
                return None
            impl = child.get_function_impl(
                func_name,
                max_lines=max_lines,
                warn_missing=warn_missing,
                include_context=include_context,
                file_path=child.scope.source,
            )
            self._absorb_child_scope(child)
            if impl is not None:
                self._record_served("get_function_impl", 1)
            return impl
        if not self._file_matches_source(file_path):
            self._record_blocked(
                "get_function_impl", detail="explicit file is not the instance source"
            )
            return None
        problem = self._entry_scope_problem()
        if problem:
            self._record_gap(
                problem, func_name, detail="no exact native instance receipt for the body"
            )
            return None
        source = self.scope.source
        identity = self._entry_navigation_identity()
        if identity is None:
            return None
        expected_index = str(identity.get("index_name") or "")

        impl = self._base.get_function_impl(
            func_name,
            max_lines=max_lines,
            warn_missing=warn_missing,
            include_context=False,
            file_path=source,
        )
        if not isinstance(impl, dict):
            self._record_gap(
                GAP_INSTANCE_FACTS_INCOMPLETE, func_name, detail="no body for the pinned symbol"
            )
            return None
        actual_index = str(impl.get("index_name") or "")
        accepted = {value for value in (expected_index, str(func_name or "").strip()) if value}
        if actual_index and accepted and actual_index not in accepted:
            self._record_gap(
                GAP_AMBIGUOUS_FUNCTION_IDENTITY,
                func_name,
                detail="resolved body is not the pinned navigation identity",
            )
            return None
        resolved_file = str(impl.get("file") or "")
        if resolved_file and source and not self._source_matches(resolved_file):
            self._record_gap(
                GAP_IDENTITY_CONTEXT_MISMATCH,
                func_name,
                detail="resolved body lives in another file",
            )
            return None
        range_problem = self._native_body_range_problem(impl.get("start_line"))
        if range_problem:
            self._record_gap(
                range_problem,
                func_name,
                detail=(
                    f"navigation body start_line {impl.get('start_line')!r} does not "
                    "match the current native owner source range"
                ),
            )
            return None
        # The base navigation context contains its global call graph and
        # declaration comments.  Even a body at the exact native owner location
        # does not bind those separate projections to this compilation instance.
        # Copy before adjusting so the shared index's cached payload stays intact.
        impl = dict(impl)
        # Replace the base navigation call graph with this instance's own native
        # call receipts; declaration comments have no per-instance receipt.
        impl["callees"] = [
            record["name"]
            for record in self.get_callees(func_name, limit=200)
            if record.get("name")
        ]
        impl["comment_blocks"] = []
        if include_context:
            self._record_blocked(
                "get_function_impl",
                detail="declaration context has no per-instance receipt",
            )
        self.__dict__["_entry_body_resolved"] = True
        self._record_served("get_function_impl", 1)
        return impl

    def _scoped_callee_view(
        self, func_name: str, file_path: str = ""
    ) -> Optional["ScopedCodeIndex"]:
        """Build an exact child scope for one function defined in this TU.

        A call target alone is insufficient: the same BuildContext must also
        contain exactly one complete native function owner for the target.  The
        child facade re-runs the normal currentness, native-facts, navigation
        identity, and source-range checks before returning source.
        """

        problem = self._receipt_scope_problem()
        if problem:
            self._record_gap(
                problem,
                func_name,
                detail="no current exact native instance receipt for callee body",
            )
            return None
        owner = self._resolve_instance_identity(str(func_name or "").strip())
        if owner is None:
            return None
        usr = str(owner.get("usr") or "")
        name = str(owner.get("name") or "")
        source = str(owner.get("file") or "")
        line = _as_positive_int(owner.get("line"))
        if not usr or not name or not source or not line:
            self._record_gap(
                GAP_IDENTITY_CONTEXT_UNVERIFIED,
                func_name,
                detail="callee native owner is incomplete",
                severity="consumer",
            )
            return None
        if file_path and not _same_text_path(
            self._resolved_source(file_path) or file_path,
            self._resolved_source(source) or source,
        ):
            self._record_gap(
                GAP_IDENTITY_CONTEXT_MISMATCH,
                func_name,
                detail="explicit callee file does not match its native owner",
                severity="consumer",
            )
            return None
        identity = f"{self.scope.build_context_id}:{usr}"
        cached = self.__dict__.setdefault("_scoped_callee_views", {})
        child = cached.get(identity)
        if isinstance(child, ScopedCodeIndex):
            return child
        child = ScopedCodeIndex(
            self.__dict__["_base"],
            InstanceScope(
                build_context_id=self.scope.build_context_id,
                usr=usr,
                identity=identity,
                source=source,
                function_names=tuple(dict.fromkeys((name, str(func_name or "").strip()))),
                selected_by="same_instance_native_callee",
            ),
        )
        cached[identity] = child
        return child

    def _absorb_child_scope(self, child: "ScopedCodeIndex") -> None:
        """Retain callee query coverage on the parent entry's scope report."""

        report = child.scope_report()
        self.__dict__["_fact_queries"].extend(
            dict(item) for item in (report.get("fact_queries") or []) if isinstance(item, dict)
        )
        self.__dict__["_scope_gaps"].extend(
            dict(item) for item in (report.get("scope_gaps") or []) if isinstance(item, dict)
        )
        blocked = self.__dict__["_blocked_calls"]
        for consumer in report.get("blocked_consumers") or []:
            name = str(consumer or "")
            if name:
                blocked[name] = blocked.get(name, 0) + 1
        served = self.__dict__.setdefault("_served_calls", {})
        for consumer, count in (report.get("served_consumers") or {}).items():
            served[str(consumer)] = served.get(str(consumer), 0) + int(count or 0)

    def _resolved_source(self, file_path: str) -> str:
        resolver = getattr(self._base, "_resolve_file_path", None)
        if not callable(resolver) or not file_path:
            return ""
        try:
            return str(resolver(file_path))
        except Exception:
            return ""

    def _entry_navigation_identity(self) -> Optional[Dict[str, Any]]:
        """The single navigation record for the pinned entry, or an explicit gap.

        Overloads in the pinned source are refused rather than resolved to the
        first record; the decision is cached for the instance's lifetime.
        """

        cached = self.__dict__.get("_entry_nav_identity")
        if cached is not None:
            return cached or None
        names = list(self.scope.function_names)
        finder = getattr(self._base, "find_function_identities", None)
        if not callable(finder):
            object.__setattr__(self, "_entry_nav_identity", {})
            self._record_gap(
                GAP_INSTANCE_FACTS_INCOMPLETE,
                names[0] if names else "",
                detail="navigation identity query is unavailable in this index",
            )
            return None
        found: Optional[Dict[str, Any]] = None
        for name in names:
            matches = finder(name, file_path=self.scope.source)
            matches = [match for match in matches if isinstance(match, dict)]
            if len(matches) == 1:
                found = matches[0]
                break
            if len(matches) > 1:
                self._record_gap(
                    GAP_AMBIGUOUS_FUNCTION_IDENTITY,
                    name,
                    detail=f"{len(matches)} navigation records for the pinned source",
                )
                object.__setattr__(self, "_entry_nav_identity", {})
                return None
        object.__setattr__(self, "_entry_nav_identity", found or {})
        if found is None:
            self._record_gap(
                GAP_INSTANCE_FACTS_INCOMPLETE,
                names[0] if names else "",
                detail="no navigation record for the pinned source",
            )
            return None
        return found

    def _entry_query_matches(self, func_name: str, file_path: str = "") -> bool:
        """Whether a navigation query names the pinned entry (name or identity)."""

        if self.scope.names_entry(func_name, file_path):
            return True
        identity = self._entry_navigation_identity()
        if identity is None:
            return False
        index_name = str(identity.get("index_name") or "")
        return bool(index_name) and str(func_name or "").strip() == index_name

    def _file_matches_source(self, file_path: str) -> bool:
        if not file_path:
            return True
        return self._source_matches(file_path)

    def _source_matches(self, file_path: str) -> bool:
        """Compare a candidate path to the instance source after resolution.

        The compiled instance records a project-relative source while the index
        resolves to an absolute path (or vice versa), so both sides are resolved
        before the exact comparison; no suffix tolerance is allowed.
        """

        source = self.scope.source
        if not file_path or not source:
            return bool(not file_path)
        if _same_text_path(file_path, source):
            return True
        left = self._resolved_source(file_path) or file_path
        right = self._resolved_source(source) or source
        return _same_text_path(left, right)

    def find_function_infos(
        self,
        func_name: str,
        file_path: str = "",
        *,
        include_type_context: bool = True,
    ) -> List[Dict[str, Any]]:
        return self._scoped_function_infos(
            func_name, file_path, include_type_context=include_type_context
        )

    def find_function_metadata(self, func_name: str, file_path: str = "") -> List[Dict[str, Any]]:
        return self._scoped_function_infos(func_name, file_path, include_type_context=False)

    def _scoped_function_infos(
        self,
        func_name: str,
        file_path: str,
        *,
        include_type_context: bool = True,
    ) -> List[Dict[str, Any]]:
        """Metadata for the pinned entry only; anything else is refused.

        The explicit file hint is enforced here (a name that matches the entry
        must not return metadata for another file), an ambiguous set is refused
        at the point of consumption, and the surviving record must be bound to
        this instance by a complete native receipt.
        """

        if not self._entry_query_matches(func_name, file_path):
            child = self._scoped_callee_view(func_name, file_path)
            if child is None:
                self._record_blocked(
                    "find_function_infos",
                    detail="metadata has no unique same-instance native function receipt",
                )
                return []
            infos = child._scoped_function_infos(
                func_name,
                child.scope.source,
                include_type_context=include_type_context,
            )
            self._absorb_child_scope(child)
            if infos:
                self._record_served("find_function_infos", len(infos))
            return infos
        if not self._file_matches_source(file_path):
            self._record_blocked(
                "find_function_infos", detail="explicit file is not the instance source"
            )
            return []
        problem = self._entry_scope_problem()
        if problem:
            self._record_gap(
                problem, func_name, detail="no exact native instance receipt for metadata"
            )
            return []
        finder = getattr(self._base, "find_function_infos", None)
        if not callable(finder):
            self._record_gap(
                GAP_INSTANCE_FACTS_INCOMPLETE,
                func_name,
                detail="metadata query is unavailable in this index",
            )
            return []
        infos = finder(
            func_name, file_path=self.scope.source, include_type_context=include_type_context
        )
        infos = [info for info in (infos or []) if isinstance(info, dict)]
        infos = [
            info
            for info in infos
            if self._source_matches(
                str(info.get("file_path") or info.get("file") or self.scope.source)
            )
        ]
        if len(infos) != 1:
            self._record_gap(
                (
                    GAP_AMBIGUOUS_FUNCTION_IDENTITY
                    if len(infos) > 1
                    else GAP_INSTANCE_FACTS_INCOMPLETE
                ),
                func_name,
                detail=f"{len(infos)} navigation record(s) for the pinned source",
            )
            return []
        if any(bid != self.scope.build_context_id for bid in _iter_build_ids(infos[0])):
            self._record_gap(
                GAP_IDENTITY_CONTEXT_MISMATCH,
                func_name,
                detail="metadata carries a foreign build identity",
            )
            return []
        range_problem = self._native_body_range_problem(
            infos[0].get("start_line") or infos[0].get("lineNumber")
        )
        if range_problem:
            self._record_gap(
                range_problem,
                func_name,
                detail=(
                    "navigation record start_line does not match the current native "
                    "owner source range"
                ),
            )
            return []
        return [self._filter_member_facts(infos[0], func_name, drop_empty_optional=True)]

    _MEMBER_FACT_KEYS = (
        "referenced_types",
        "unresolved_referenced_types",
        "referenced_macros",
        "referenced_globals",
    )

    def _member_receipt_ok(self, item: Any) -> bool:
        """Whether a returned type/macro/global member is bound to this instance.

        A member is usable only when it carries its **own** receipt naming the
        pinned native USR *and* this exact build context (and, when it declares
        a file, this instance's source).  A parent build tag, a bare string name
        or a same-build id alone never authorizes a member fact.
        """

        if not isinstance(item, dict) or not self.scope.usr:
            return False
        identity = item.get("function_identity")
        if not isinstance(identity, dict):
            if "usr" not in item and "build_context_id" not in item:
                return False
            identity = item
        if str(identity.get("usr") or "") != self.scope.usr:
            return False
        if str(identity.get("build_context_id") or "") != self.scope.build_context_id:
            return False
        file_hint = str(item.get("file") or item.get("file_path") or identity.get("file") or "")
        if file_hint and not self._file_matches_source(file_hint):
            return False
        return True

    def _filter_member_facts(
        self,
        value: Dict[str, Any],
        func_name: str,
        *,
        drop_empty_optional: bool = False,
    ) -> Dict[str, Any]:
        """Keep only member facts carrying a receipt bound to this instance."""

        result = dict(value)
        dropped = False
        for key in self._MEMBER_FACT_KEYS:
            items = result.get(key)
            if not isinstance(items, list):
                continue
            # Optional member collections use presence to signal that there is
            # evidence to consume.  Keep the required referenced_types array,
            # but do not leak present-but-empty optional arrays into the
            # semantic snapshot contract (which deliberately rejects them).
            if not items and drop_empty_optional and key != "referenced_types":
                result.pop(key, None)
                continue
            kept = [item for item in items if self._member_receipt_ok(item)]
            if len(kept) == len(items):
                continue
            dropped = True
            if not kept and drop_empty_optional and key != "referenced_types":
                result.pop(key, None)
            else:
                result[key] = kept
        if dropped:
            self._record_gap(
                GAP_IDENTITY_CONTEXT_UNVERIFIED,
                func_name,
                detail="member facts lack a receipt bound to this instance",
                severity="consumer",
            )
        return result

    def get_function_type_context(
        self,
        func_name: str,
        file_path: str = "",
        start_line: int = 0,
    ) -> Dict[str, Any]:
        """Direct type context only with an exact instance receipt, else empty."""

        empty: Dict[str, Any] = {"referenced_types": []}
        if not self._entry_query_matches(func_name, file_path):
            child = self._scoped_callee_view(func_name, file_path)
            if child is None:
                self._record_blocked(
                    "get_function_type_context",
                    detail="types have no unique same-instance native function receipt",
                )
                return empty
            value = child.get_function_type_context(
                func_name,
                child.scope.source,
                start_line,
            )
            self._absorb_child_scope(child)
            self._record_served("get_function_type_context", 1)
            return value
        if not self._file_matches_source(file_path):
            self._record_blocked(
                "get_function_type_context", detail="explicit file is not the instance source"
            )
            return empty
        problem = self._entry_scope_problem()
        if problem:
            self._record_gap(
                problem, func_name, detail="no exact native instance receipt for types"
            )
            return empty
        value = self._base.get_function_type_context(
            func_name, file_path=self.scope.source, start_line=start_line
        )
        if not isinstance(value, dict):
            return empty
        if any(bid != self.scope.build_context_id for bid in _iter_build_ids(value)):
            self._record_gap(
                GAP_IDENTITY_CONTEXT_MISMATCH,
                func_name,
                detail="type context carries a foreign build identity",
                severity="consumer",
            )
            return empty
        # The canonical semantic-model input treats optional collections as a
        # presence contract: if unresolved types/macros/globals are present,
        # they must contain evidence.  Type context is merged over the already
        # filtered navigation record, so remove empty optional arrays here as
        # well; otherwise that second merge can reintroduce an invalid empty
        # unresolved_referenced_types field.
        value = self._filter_member_facts(value, func_name, drop_empty_optional=True)
        items = list(value.get("referenced_types") or [])
        items.extend(self._receipt_type_items())
        if items:
            value["referenced_types"] = items
            value.setdefault("function_identity", self._entry_type_identity())
        else:
            value["referenced_types"] = []
        return value

    def get_function_symbol_context(
        self, func_name: str, file_path: str = ""
    ) -> Dict[str, List[Dict[str, Any]]]:
        empty: Dict[str, List[Dict[str, Any]]] = {
            "referenced_globals": [],
            "referenced_macros": [],
        }
        if not self._entry_query_matches(func_name, file_path):
            child = self._scoped_callee_view(func_name, file_path)
            if child is None:
                self._record_blocked(
                    "get_function_symbol_context",
                    detail="symbols have no unique same-instance native function receipt",
                )
                return empty
            value = child.get_function_symbol_context(func_name, child.scope.source)
            self._absorb_child_scope(child)
            self._record_served("get_function_symbol_context", 1)
            return value
        if not self._file_matches_source(file_path):
            self._record_blocked(
                "get_function_symbol_context", detail="explicit file is not the instance source"
            )
            return empty
        problem = self._entry_scope_problem()
        if problem:
            self._record_gap(
                problem, func_name, detail="no exact native instance receipt for symbols"
            )
            return empty
        getter = getattr(self._base, "get_function_symbol_context", None)
        value = getter(func_name, file_path=self.scope.source) if callable(getter) else {}
        if not isinstance(value, dict):
            value = {}
        if any(bid != self.scope.build_context_id for bid in _iter_build_ids(value)):
            self._record_gap(
                GAP_IDENTITY_CONTEXT_MISMATCH,
                func_name,
                detail="symbol context carries a foreign build identity",
                severity="consumer",
            )
            return empty
        value = self._filter_member_facts(value, func_name)
        receipts = self._receipt_symbol_members(func_name)
        for key in ("referenced_macros", "referenced_globals"):
            merged = list(value.get(key) or [])
            merged.extend(receipts.get(key, []))
            value[key] = merged
        return cast(Dict[str, List[Dict[str, Any]]], value)

    # -- exact-context receipts for symbol/type/macro/graph consumers --------
    #
    # The navigation projection cannot answer these for one compilation
    # instance.  The native producer stores its receipts under the exact
    # content-bound ``BuildContext`` and every receipt names the compiler
    # ``owner`` (USR + file + line) that produced it, so the scoped facade can
    # serve a member only when that owner is the pinned instance itself.

    _CALL_RECEIPT_KINDS = ("call",)
    _SYMBOL_RECEIPT_KINDS = ("macro_reference", "symbol_reference")
    _TYPE_RECEIPT_KINDS = ("type_reference",)
    _FUNCTION_RECEIPT_KINDS = ("program_function", "function")

    def _context_rows(self, kinds: Sequence[str], *, symbol: str = "") -> List[Dict[str, Any]]:
        cached = self.__dict__.setdefault("_context_row_cache", {})
        key = (tuple(kinds), str(symbol or ""))
        if key in cached:
            return list(cached[key])
        pinned = self.scope.build_context_id
        rows: List[Dict[str, Any]] = []
        getter = getattr(self._base, "get_compilation_facts", None)
        if pinned and callable(getter):
            try:
                values = getter(pinned, kinds=tuple(kinds), symbol=str(symbol or ""))
            except Exception:
                values = []
            rows = [row for row in (values or []) if isinstance(row, dict)]
        cached[key] = rows
        return list(rows)

    @staticmethod
    def _row_owner(row: Dict[str, Any]) -> Dict[str, Any]:
        owner = row.get("owner")
        return owner if isinstance(owner, dict) else {}

    @staticmethod
    def _row_target(row: Dict[str, Any]) -> Dict[str, Any]:
        target = row.get("target")
        return target if isinstance(target, dict) else {}

    @staticmethod
    def _target_name(target: Dict[str, Any]) -> str:
        return str(target.get("qualified_name") or target.get("name") or "")

    def _owner_is_entry(self, owner: Dict[str, Any]) -> bool:
        """Whether a receipt row was produced by the pinned entry function.

        The compiler owner must name the pinned USR *and* a file and source line
        that match the entry's current native owner location; a missing file or
        line is never a wildcard.
        """

        if not self.scope.usr or str(owner.get("usr") or "") != self.scope.usr:
            return False
        owner_file = str(owner.get("file") or "")
        owner_line = _as_positive_int(owner.get("line"))
        if not owner_file or not owner_line:
            return False
        native_file, native_line = self._native_entry_location()
        if not native_line:
            return False
        if native_file and not self._source_matches(owner_file):
            return False
        if owner_line != native_line:
            return False
        return True

    @staticmethod
    def _same_owner(owner: Dict[str, Any], identity: Dict[str, Any]) -> bool:
        """Exact ``(usr, file, line)`` compiler-owner equality."""

        return (
            str(owner.get("usr") or "") == str(identity.get("usr") or "")
            and str(owner.get("file") or "") == str(identity.get("file") or "")
            and _as_positive_int(owner.get("line")) == _as_positive_int(identity.get("line"))
        )

    def _resolve_instance_identity(self, query: str) -> Optional[Dict[str, Any]]:
        """The unique instance owner a query names, or ``None``.

        The entry answers as its pinned ``(usr, file, line)``.  Any other symbol
        must resolve to exactly one distinct owner inside this instance, by
        native USR or by bare name, and ambiguity is refused instead of picking
        the first row.  A ``name@...`` alias only matches the pinned navigation
        identity.
        """

        text = str(query or "").strip()
        if not text:
            return None
        if self._entry_query_matches(text):
            if self._receipt_scope_problem():
                return None
            native_file, native_line = self._native_entry_location()
            if not native_line:
                return None
            return {"usr": self.scope.usr, "file": native_file, "line": native_line}
        is_usr = text.startswith("c:")
        owners: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        for row in self._context_rows(self._FUNCTION_RECEIPT_KINDS) + self._context_rows(
            self._CALL_RECEIPT_KINDS
        ):
            owner = self._row_owner(row)
            usr = str(owner.get("usr") or "")
            name = str(owner.get("name") or "")
            if not usr or not name:
                continue
            if usr != text if is_usr else name != text:
                continue
            key = (usr, str(owner.get("file") or ""), _as_positive_int(owner.get("line")))
            owners[key] = owner
        if len(owners) != 1:
            return None
        return next(iter(owners.values()))

    def _resolve_target_identity(
        self, query: str, callee_file: str = ""
    ) -> Optional[Dict[str, Any]]:
        """The unique callee identity a query names inside this instance."""

        text = str(query or "").strip()
        if not text:
            return None
        is_usr = text.startswith("c:")
        base_name = "" if is_usr else text.split("@", 1)[0]
        targets: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in self._context_rows(self._CALL_RECEIPT_KINDS):
            target = self._row_target(row)
            usr = str(target.get("usr") or target.get("referenced_usr") or "")
            name = self._target_name(target)
            if is_usr:
                if usr != text:
                    continue
            elif name != base_name:
                continue
            declaration = target.get("declaration")
            declaration = declaration if isinstance(declaration, dict) else {}
            decl_file = str(declaration.get("file") or "")
            targets[(usr, decl_file)] = target
        matches = list(targets.values())
        if callee_file:
            declared = [
                target for target in matches if self._callee_file_matches(callee_file, target)
            ]
            if not declared:
                return None
            matches = declared
        if len(matches) != 1:
            return None
        return matches[0]

    def _callee_file_matches(self, callee_file: str, target: Dict[str, Any]) -> bool:
        """An explicit callee file must equal the callee's own declaration file.

        Unknown declaration files are not a wildcard: the hint may only fall
        back to the instance source, never to another variant's file.
        """

        declaration = target.get("declaration")
        declaration = declaration if isinstance(declaration, dict) else {}
        declared_file = str(declaration.get("file") or "")
        if declared_file:
            if _same_text_path(callee_file, declared_file):
                return True
            return self._source_matches(declared_file) and _same_text_path(
                callee_file, self.scope.source
            )
        return _same_text_path(callee_file, self.scope.source)

    def _same_target(self, target: Dict[str, Any], identity: Dict[str, Any]) -> bool:
        usr = str(target.get("usr") or target.get("referenced_usr") or "")
        identity_usr = str(identity.get("usr") or "")
        if identity_usr and usr:
            return usr == identity_usr
        return self._target_name(target) == self._target_name(identity)

    def _owner_receipt(self, owner: Dict[str, Any]) -> Dict[str, Any]:
        """The compiler identity of a receipt row as a member receipt."""

        return {
            "usr": str(owner.get("usr") or ""),
            "build_context_id": self.scope.build_context_id,
            "file": str(owner.get("file") or ""),
        }

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Callees of one symbol from the pinned instance's own call receipts."""
        requested = max(0, int(limit))
        if requested == 0:
            return []
        query = str(func_name or "").strip()
        if not query:
            return []
        problem = self._receipt_scope_problem()
        if problem:
            self._record_gap(
                problem, query, detail="no current exact native instance receipt for callees"
            )
            return []
        identity = self._resolve_instance_identity(query)
        if identity is None:
            self._record_gap(
                GAP_IDENTITY_CONTEXT_UNVERIFIED,
                query,
                detail="callee query does not name one instance owner",
                severity="consumer",
            )
            return []
        records: List[Dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for row in self._context_rows(self._CALL_RECEIPT_KINDS):
            owner = self._row_owner(row)
            if not self._same_owner(owner, identity):
                continue
            target = self._row_target(row)
            name = self._target_name(target)
            if not name:
                continue
            location = row.get("location")
            location = location if isinstance(location, dict) else {}
            declaration = target.get("declaration")
            declaration = declaration if isinstance(declaration, dict) else {}
            key = (name, _as_positive_int(location.get("line")))
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "name": name,
                    "callee_name": name,
                    "usr": str(target.get("usr") or target.get("referenced_usr") or ""),
                    "filename": str(declaration.get("file") or ""),
                    "call_type": str(row.get("call_type") or row.get("callee_kind") or "direct"),
                    "line": _as_positive_int(location.get("line")),
                    "build_context_id": self.scope.build_context_id,
                    "owner_usr": str(owner.get("usr") or ""),
                }
            )
            if len(records) >= requested:
                break
        self._record_served("get_callees", len(records))
        return records

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        """Callers of one symbol from the pinned instance's own call receipts."""
        requested = max(0, int(limit))
        query = str(func_name or "").strip()
        if requested == 0 or not query:
            return []
        problem = self._receipt_scope_problem()
        if problem:
            self._record_gap(
                problem, query, detail="no current exact native instance receipt for callers"
            )
            return []
        identity = self._resolve_target_identity(query, callee_file)
        if identity is None:
            self._record_gap(
                GAP_IDENTITY_CONTEXT_UNVERIFIED,
                query,
                detail="callee identity is unknown or ambiguous in this instance",
                severity="consumer",
            )
            return []
        records: List[Dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for row in self._context_rows(self._CALL_RECEIPT_KINDS):
            if not self._same_target(self._row_target(row), identity):
                continue
            owner = self._row_owner(row)
            name = str(owner.get("name") or "")
            if (
                not name
                or not str(owner.get("file") or "")
                or not _as_positive_int(owner.get("line"))
            ):
                continue
            location = row.get("location")
            location = location if isinstance(location, dict) else {}
            key = (name, _as_positive_int(owner.get("line")))
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "name": name,
                    "caller_name": name,
                    "usr": str(owner.get("usr") or ""),
                    "filename": str(owner.get("file") or ""),
                    "line": _as_positive_int(location.get("line")),
                    "build_context_id": self.scope.build_context_id,
                }
            )
            if len(records) >= requested:
                break
        self._record_served("get_callers", len(records))
        return records

    def list_functions(
        self,
        pattern: Optional[str] = None,
        limit: Optional[int] = 50,
        file_root: Any = None,
        offset: int = 0,
    ) -> List[str]:
        """Functions that actually have facts in the pinned compilation instance."""
        del file_root  # the instance is already a single translation unit
        problem = self._receipt_scope_problem()
        if problem:
            self._record_gap(
                problem, "", detail="no current exact native instance receipt for functions"
            )
            return []
        names: List[str] = []
        seen: set[str] = set()
        for row in self._context_rows(self._FUNCTION_RECEIPT_KINDS):
            owner = self._row_owner(row)
            name = str(owner.get("name") or row.get("name") or "")
            if not name or name in seen:
                continue
            seen.add(name)
            names.append(name)
        ordered = sorted(names)
        self._record_served("list_functions", len(ordered))
        if pattern:
            try:
                matcher = re.compile(pattern)
                ordered = [name for name in ordered if matcher.search(name)]
            except re.error:
                ordered = [name for name in ordered if name.startswith(pattern)]
        start = max(0, int(offset or 0))
        if limit is None:
            return ordered[start:]
        parsed = int(limit)
        if parsed <= 0:
            return ordered[start:]
        return ordered[start : start + parsed]

    def list_function_instances(self) -> List[InstanceScope]:
        """Enumerate exact function identities in the pinned compilation unit.

        Fast project analysis needs an identity stronger than a bare function
        name so overloaded symbols and compile variants never share facts or
        cache entries.  The returned scopes are derived only from current
        native ``program_function``/``function`` owner receipts in this build;
        the navigation projection is not used to invent members.
        """

        problem = self._receipt_scope_problem()
        if problem:
            self._record_gap(
                problem,
                "",
                detail="no current exact native instance receipt for function instances",
            )
            return []
        instances: Dict[Tuple[str, str, int], InstanceScope] = {}
        for row in self._context_rows(self._FUNCTION_RECEIPT_KINDS):
            owner = self._row_owner(row)
            usr = str(owner.get("usr") or "")
            name = str(owner.get("name") or "")
            source = str(owner.get("file") or "")
            line = _as_positive_int(owner.get("line"))
            if not usr or not name or not source or not line:
                self._record_gap(
                    GAP_IDENTITY_CONTEXT_UNVERIFIED,
                    name,
                    detail="function owner receipt is incomplete",
                    severity="consumer",
                )
                continue
            key = (usr, source, line)
            instances.setdefault(
                key,
                InstanceScope(
                    build_context_id=self.scope.build_context_id,
                    usr=usr,
                    identity=f"{self.scope.build_context_id}:{usr}",
                    source=source,
                    function_names=(name,),
                    selected_by="fast_static_function_inventory",
                ),
            )
        ordered = [instances[key] for key in sorted(instances)]
        self._record_served("list_function_instances", len(ordered))
        return ordered

    def _receipt_symbol_members(self, func_name: str) -> Dict[str, List[Dict[str, Any]]]:
        """Macro/global references produced by the pinned entry, with receipts."""

        problem = self._receipt_scope_problem()
        if problem:
            self._record_gap(
                problem, func_name, detail="no current exact native instance receipt for symbols"
            )
            return {"referenced_macros": [], "referenced_globals": []}
        macros: List[Dict[str, Any]] = []
        globals_: List[Dict[str, Any]] = []
        for row in self._context_rows(self._SYMBOL_RECEIPT_KINDS):
            owner = self._row_owner(row)
            if not self._owner_is_entry(owner):
                continue
            target = self._row_target(row)
            name = self._target_name(target)
            if not name:
                continue
            location = row.get("location")
            location = location if isinstance(location, dict) else {}
            member = {
                "name": name,
                "qualified_name": name,
                "usr": str(target.get("usr") or ""),
                "kind": str(row.get("kind") or ""),
                "access_kind": str(row.get("access_kind") or ""),
                "line": _as_positive_int(location.get("line")),
                "function_identity": self._owner_receipt(owner),
            }
            if str(row.get("kind") or "") == "macro_reference":
                replacement = row.get("invocation")
                if isinstance(replacement, str) and replacement:
                    member["replacement_text"] = replacement
                macros.append(member)
            else:
                globals_.append(member)
        del func_name
        self._record_served("get_function_symbol_context", len(macros) + len(globals_))
        return {"referenced_macros": macros, "referenced_globals": globals_}

    def _receipt_symbol_members_from_current_facts(
        self, facts: Dict[str, Any]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Attach symbol receipts after the caller verified this exact body.

        Unlike the public symbol-context accessor, this helper must not run a
        second native body probe: ``get_function_program_facts`` has already
        checked the complete function identity and BuildContext immediately
        before calling it.  Receipt owners are still required to equal the
        verified body owner in all of (USR,file,line).
        """

        bodies = [body for body in facts.get("functions", []) or [] if isinstance(body, dict)]
        if len(bodies) != 1:
            return {"referenced_macros": [], "referenced_globals": []}
        raw_owner = bodies[0].get("owner")
        expected_owner = raw_owner if isinstance(raw_owner, dict) else {}
        macros: List[Dict[str, Any]] = []
        globals_: List[Dict[str, Any]] = []
        for row in self._context_rows(self._SYMBOL_RECEIPT_KINDS):
            owner = self._row_owner(row)
            if not self._same_owner(owner, expected_owner):
                continue
            target = self._row_target(row)
            name = self._target_name(target)
            if not name:
                continue
            location = row.get("location")
            location = location if isinstance(location, dict) else {}
            member = {
                "name": name,
                "qualified_name": name,
                "usr": str(target.get("usr") or ""),
                "kind": str(row.get("kind") or ""),
                "access_kind": str(row.get("access_kind") or ""),
                "line": _as_positive_int(location.get("line")),
                "function_identity": self._owner_receipt(owner),
            }
            if str(row.get("kind") or "") == "macro_reference":
                replacement = row.get("invocation")
                if isinstance(replacement, str) and replacement:
                    member["replacement_text"] = replacement
                macros.append(member)
            else:
                globals_.append(member)
        self._record_served("get_function_program_facts.symbols", len(macros) + len(globals_))
        return {"referenced_macros": macros, "referenced_globals": globals_}

    def _receipt_type_items(self) -> List[Dict[str, Any]]:
        """Type references produced by the pinned entry, in the modelling shape."""

        problem = self._receipt_scope_problem()
        if problem:
            self._record_gap(
                problem, "", detail="no current exact native instance receipt for types"
            )
            return []
        items: List[Dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for row in self._context_rows(self._TYPE_RECEIPT_KINDS):
            owner = self._row_owner(row)
            if not self._owner_is_entry(owner):
                continue
            target = self._row_target(row)
            name = self._target_name(target)
            if not name:
                continue
            location = row.get("location")
            location = location if isinstance(location, dict) else {}
            line = _as_positive_int(location.get("line"))
            if (name, line) in seen:
                continue
            seen.add((name, line))
            items.append(
                {
                    "type_index_name": name,
                    "kind": str(row.get("reference_kind") or "reference"),
                    "full_definition": "",
                    "reference_kinds": [str(row.get("reference_kind") or "reference")],
                    "reference_lines": [line] if line else [],
                }
            )
        self._record_served("get_function_type_context", len(items))
        return items

    def _entry_type_identity(self) -> Dict[str, Any]:
        facts: Dict[str, Any] = self._native_probe()[0]
        bodies = [body for body in (facts.get("functions") or []) if isinstance(body, dict)]
        owner = self._row_owner(bodies[0]) if len(bodies) == 1 else {}
        return self._owner_receipt(owner)

    def get_build_contexts(self, file_path: str = "") -> List[Dict[str, Any]]:
        base = self._base.get_build_contexts(file_path)
        pinned = self.scope.build_context_id
        return [
            dict(value)
            for value in (base if isinstance(base, list) else [])
            if isinstance(value, dict) and str(value.get("build_context_id") or "") == pinned
        ]

    def get_instance_backend_signals(
        self,
        *,
        build_context_id: str = "",
        func_names: Optional[Sequence[str]] = None,
        limit: int = 200,
    ) -> Dict[str, Any]:
        """Saber signals produced by *this* instance's compile command.

        The producer stores a signal's compile-command identity
        (``command_id``) and an attribution verdict. This accessor accepts a row
        only when the verdict is ``exact``, the command id belongs to the pinned
        context, and the pinned context is the *only* stored context built with
        that command. Anything else is reported as a typed refusal instead of
        being inherited — an ambiguous command id can never authorize instance
        evidence.

        Returns a closed DTO: callers must branch on ``status`` and never treat a
        missing ``rows`` key as success.
        """

        pinned = str(self.scope.build_context_id or "")
        payload: Dict[str, Any] = {
            "schema": "zscope.instance-svf-signals.v1",
            "status": "unavailable",
            "reason": "",
            "build_context_id": pinned,
            "command_id": "",
            "rows": [],
            "exact_rows": 0,
            "ambiguous_rows": 0,
            "unattributed_rows": 0,
        }
        if build_context_id and build_context_id != pinned:
            self._record_gap(
                GAP_FOREIGN_BUILD_CONTEXT,
                "instance_backend_signals",
                detail=(
                    f"query requested build context {build_context_id}; this "
                    f"instance is {pinned or '<none>'}"
                ),
                severity="consumer",
            )
            payload.update(status="foreign_build_context", reason=GAP_FOREIGN_BUILD_CONTEXT)
            return payload
        if not pinned:
            self._record_gap(
                GAP_UNKNOWN_BUILD_CONTEXT,
                "instance_backend_signals",
                detail="instance has no build context",
                severity="consumer",
            )
            payload.update(status="unavailable", reason=GAP_UNKNOWN_BUILD_CONTEXT)
            return payload

        context_status = self._fresh_context_status()
        if context_status != "current":
            payload.update(status="stale", reason=context_status)
            return payload

        # The facade refuses a raw ``db`` handle on purpose. This accessor reads
        # the base handle itself and applies the instance filter below, so no
        # unscoped store ever reaches a caller.
        base = self.__dict__["_base"]
        backend = getattr(base, "_backend", None)
        signal_owner = backend if backend is not None else base
        current_signals = getattr(signal_owner, "svf_signals_current", None)
        if not callable(current_signals) or not current_signals():
            payload.update(status="unavailable", reason="svf_run_not_current")
            return payload
        db = getattr(base, "db", None)
        if db is None:
            # Production ``CodeIndex`` owns the configured backend rather than
            # publishing its raw KnowledgeDB as a public attribute.  Resolve
            # that owner only inside this scoped accessor; callers still never
            # receive the unscoped store.  Test/minimal indexes may continue to
            # expose ``db`` directly.
            backend = getattr(base, "_backend", None)
            db = getattr(backend, "db", None) if backend is not None else None
        if db is None or not hasattr(db, "get_instance_taint_signals"):
            payload.update(status="unavailable", reason="signal_store_unavailable")
            return payload

        context = self._pinned_context(
            self._base.get_build_contexts(self.scope.source) if self.scope.source else [],
            pinned,
        )
        if context is None and self.scope.source:
            context = self._pinned_context(self._base.get_build_contexts(""), pinned)
        command_id = str((context or {}).get("command_id") or "")
        payload["command_id"] = command_id
        if not command_id:
            payload.update(status="unavailable", reason="instance_command_identity_missing")
            self._record_gap(
                "instance_command_identity_missing",
                "instance_backend_signals",
                detail="pinned build context carries no command identity",
                severity="consumer",
            )
            return payload

        owners = (
            db.get_command_context_map([command_id]).get(command_id, [])
            if hasattr(db, "get_command_context_map")
            else []
        )
        if owners and owners != [pinned]:
            payload.update(
                status="ambiguous_command",
                reason="command_id_resolves_to_multiple_contexts",
            )
            self._record_gap(
                "ambiguous_command_identity",
                "instance_backend_signals",
                detail=f"command {command_id} is shared by {len(owners)} build contexts",
                severity="consumer",
            )
            return payload

        counts = (
            db.count_taint_signal_attribution(command_id)
            if hasattr(db, "count_taint_signal_attribution")
            else {}
        )
        payload["exact_rows"] = int(counts.get("exact_for_command", 0))
        payload["ambiguous_rows"] = int(counts.get("ambiguous", 0))
        payload["unattributed_rows"] = int(counts.get("unattributed", 0))
        rows = db.get_instance_taint_signals(
            command_id=command_id,
            func_names=list(func_names or []),
            limit=limit,
        )
        payload["rows"] = [dict(row) for row in rows]
        payload["status"] = "complete"
        self._record_served("svf_taint_query", len(payload["rows"]) or 1)
        return payload

    def dependencies_current_status(self) -> str:
        """Whether the pinned instance's source/header inputs are still current.

        A header, response-file or source edit changes a dependency digest, so
        the stored instance can no longer be treated as current evidence.  This
        reads real recorded digests and never re-runs a compiler.
        """

        pinned = self.scope.build_context_id
        getter = getattr(self._base, "get_build_contexts", None)
        if not callable(getter):
            return GAP_UNKNOWN_BUILD_CONTEXT
        contexts = getter(self.scope.source) if self.scope.source else getter("")
        context = self._pinned_context(contexts, pinned)
        if context is None and self.scope.source:
            context = self._pinned_context(getter(""), pinned)
        if context is None:
            return GAP_UNKNOWN_BUILD_CONTEXT
        if str(context.get("status") or "") != "indexed" or not bool(
            context.get("dependencies_complete")
        ):
            return "incomplete_compilation_instance"
        try:
            from .indexing_identity import dependencies_current

            if not dependencies_current(context.get("dependencies")):
                return GAP_STALE_BUILD_CONTEXT
        except Exception as exc:  # never promote an unverifiable context
            logger.warning("Instance dependency check unavailable: %s", exc)
            return GAP_STALE_BUILD_CONTEXT
        return "current"

    @staticmethod
    def _pinned_context(contexts: Any, pinned: str) -> Optional[Dict[str, Any]]:
        for value in contexts if isinstance(contexts, list) else []:
            if isinstance(value, dict) and str(value.get("build_context_id") or "") == pinned:
                return value
        return None

    def _context_status(self) -> str:
        cached = self.__dict__.get("_context_status_value")
        if cached is None:
            cached = self.dependencies_current_status()
            object.__setattr__(self, "_context_status_value", cached)
        return str(cached)

    def _fresh_context_status(self) -> str:
        """Re-read current build dependencies before publishing any receipt.

        A cached status would keep authorizing rows fetched before a header or
        source edit; every publish/reuse path therefore re-checks here.
        """

        status = self.dependencies_current_status()
        object.__setattr__(self, "_context_status_value", status)
        return str(status)

    def _native_entry_receipt_problem(self) -> str:
        """Whether the pinned memory USR has an exact native receipt here.

        The receipt is a complete program-facts answer for the instance's own
        ``(build_context_id, USR)``.  Missing, foreign or mismatching evidence
        means the navigation/semantic projection cannot be bound to this
        instance and must not be served.
        """

        cached = self.__dict__.get("_native_receipt_problem")
        if cached is not None:
            return str(cached)
        problem = self._native_probe()[1]
        object.__setattr__(self, "_native_receipt_problem", problem)
        return problem

    def _native_probe(self) -> Tuple[Dict[str, Any], str]:
        """The exact native receipt facts and the reason they are unusable."""

        cached = self.__dict__.get("_native_probe_cache")
        if cached is not None:
            return cast(Tuple[Dict[str, Any], str], cached)
        facts, problem = self._compute_native_probe()
        object.__setattr__(self, "_native_probe_cache", (facts, problem))
        return facts, problem

    def _compute_native_probe(self) -> Tuple[Dict[str, Any], str]:
        if not self.scope.usr:
            return {}, GAP_IDENTITY_CONTEXT_UNVERIFIED
        getter = getattr(self._base, "get_function_program_facts", None)
        if not callable(getter):
            return {}, GAP_INSTANCE_FACTS_INCOMPLETE
        try:
            facts = getter(
                self.scope.usr,
                self.scope.source,
                build_context_id=self.scope.build_context_id,
            )
        except Exception:
            return {}, GAP_INSTANCE_FACTS_INCOMPLETE
        if not isinstance(facts, dict) or not facts.get("complete"):
            return {}, GAP_INSTANCE_FACTS_INCOMPLETE
        observed = str(facts.get("build_context_id") or "")
        if observed != self.scope.build_context_id:
            return {}, GAP_IDENTITY_CONTEXT_MISMATCH
        identity = facts.get("function_identity")
        identity = identity if isinstance(identity, dict) else {}
        if str(identity.get("usr") or "") != self.scope.usr:
            return {}, GAP_IDENTITY_CONTEXT_UNVERIFIED
        return facts, ""

    def _native_entry_location(self) -> Tuple[str, int]:
        """The current native owner file and start line for the pinned USR.

        This is the only source-range receipt a returned body or record can be
        bound to; a same-file/same-USR navigation projection is not enough when
        a source holds several conditional definitions of one symbol.
        """

        facts: Dict[str, Any] = self._native_probe()[0]
        bodies = [body for body in (facts.get("functions") or []) if isinstance(body, dict)]
        if len(bodies) != 1:
            return "", 0
        body = bodies[0]
        owner_raw = body.get("owner")
        owner: Dict[str, Any] = owner_raw if isinstance(owner_raw, dict) else {}
        location_raw = body.get("location")
        location: Dict[str, Any] = location_raw if isinstance(location_raw, dict) else {}
        file_hint = str(owner.get("file") or location.get("file") or "")
        raw_line = owner.get("line") or location.get("line")
        return file_hint, _as_positive_int(raw_line)

    def _native_body_range_problem(self, start_line: Any) -> str:
        """Whether a navigation body/record start line matches the native range."""

        native_file, native_line = self._native_entry_location()
        if not native_line or not native_file:
            return GAP_INSTANCE_FACTS_INCOMPLETE
        if not self._source_matches(native_file):
            return GAP_IDENTITY_CONTEXT_MISMATCH
        if _as_positive_int(start_line) != native_line:
            return GAP_IDENTITY_CONTEXT_MISMATCH
        return ""

    def _entry_scope_problem(self) -> str:
        """The reason this instance cannot authorize a navigation projection."""

        status = self._fresh_context_status()
        if status != "current":
            return status
        return self._native_entry_receipt_problem()

    def _receipt_scope_problem(self) -> str:
        """The reason this instance cannot serve native member receipts now."""

        return self._entry_scope_problem()

    # -- gap recording ------------------------------------------------------

    def _record_gap(
        self,
        reason: str,
        func_name: str,
        *,
        detail: str = "",
        severity: str = "identity",
    ) -> None:
        self.__dict__["_scope_gaps"].append(
            {
                "reason": reason,
                "detail": detail,
                "function_name": str(func_name or ""),
                "build_context_id": self.scope.build_context_id,
                "severity": severity,
            }
        )

    def _record_blocked(self, consumer: str, *, detail: str = "") -> None:
        counts = self.__dict__["_blocked_calls"]
        counts[consumer] = counts.get(consumer, 0) + 1
        self._record_gap(GAP_UNSCOPED_CONSUMER, consumer, detail=detail, severity="consumer")

    def _record_served(self, consumer: str, count: int) -> None:
        """Count member facts actually served from this instance's receipts."""

        if count <= 0:
            return
        served = self.__dict__.setdefault("_served_calls", {})
        served[consumer] = served.get(consumer, 0) + int(count)

    def scope_report(self) -> Dict[str, Any]:
        gaps = [dict(item) for item in self.__dict__["_scope_gaps"]]
        identity_gaps = [item for item in gaps if item.get("severity") != "consumer"]
        blocked = sorted(self.__dict__["_blocked_calls"])
        facts_complete = bool(self.__dict__.get("_entry_facts_complete")) and not identity_gaps
        return {
            "scope": self.scope.to_payload(),
            "context_status": self._context_status(),
            "fact_queries": [dict(item) for item in self.__dict__["_fact_queries"]],
            "scope_gaps": gaps,
            "identity_gaps": identity_gaps,
            "blocked_consumers": blocked,
            "unscoped_consumers": blocked,
            "served_consumers": dict(self.__dict__.get("_served_calls") or {}),
            "facts_complete": facts_complete,
        }


def wrap_scoped_code_index(base: Any, scope: InstanceScope) -> Any:
    """Wrap ``base`` so facts resolve to ``scope`` without re-wrapping twice."""

    if base is None:
        return None
    if isinstance(base, ScopedCodeIndex):
        if base.scope.identity == scope.identity:
            return base
        return ScopedCodeIndex(base.__dict__["_base"], scope)
    return ScopedCodeIndex(base, scope)


def instance_scope_from_entry_instance(instance: Any) -> InstanceScope:
    return InstanceScope.from_entry_instance(instance)


@dataclass
class InstanceAnalysisOutcome:
    """The consumed result of analyzing one scheduled instance."""

    identity: str
    build_context_id: str
    usr: str
    source: str
    function_name: str
    status: str
    verdict: str = ""
    entry_identity: str = ""
    issues: List[Dict[str, Any]] = field(default_factory=list)
    candidate_build_context_ids: List[str] = field(default_factory=list)
    # Identity/precondition gaps only.  A blocked unscoped consumer is recorded
    # separately and does not make the instance's build scope unsound.
    scope_gaps: List[Dict[str, Any]] = field(default_factory=list)
    blocked_consumers: List[str] = field(default_factory=list)
    context_status: str = ""
    semantics: str = ""
    fact_queries: int = 0
    duration_seconds: float = 0.0
    error: str = ""

    @property
    def unscoped_consumers(self) -> List[str]:
        return list(self.blocked_consumers)

    @property
    def scope_preserved(self) -> bool:
        return self.status == "analyzed" and not self.scope_gaps

    def to_payload(self) -> Dict[str, Any]:
        return {
            "identity": self.identity,
            "build_context_id": self.build_context_id,
            "usr": self.usr,
            "source": self.source,
            "function_name": self.function_name,
            "status": self.status,
            "verdict": self.verdict,
            "entry_identity": self.entry_identity,
            "candidate_count": len(self.issues),
            "candidates": [dict(item) for item in self.issues],
            "candidate_build_context_ids": list(self.candidate_build_context_ids),
            "scope_gaps": [dict(item) for item in self.scope_gaps],
            "blocked_consumers": list(self.blocked_consumers),
            "unscoped_consumers": list(self.blocked_consumers),
            "context_status": self.context_status,
            "semantics": self.semantics,
            "fact_queries": self.fact_queries,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


@dataclass
class InstanceAnalysisReport:
    """Aggregate of per-instance analysis for one entry instance plan."""

    status: str
    outcomes: List[InstanceAnalysisOutcome] = field(default_factory=list)
    planned_instances: int = 0
    plan_gaps: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=lambda: [_NOTE_UNSCOPED_CONSUMERS, _NOTE_FIRST_SLICE])

    @property
    def scheduled_instances(self) -> int:
        return len(self.outcomes)

    @property
    def analyzed_instances(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.status == "analyzed")

    @property
    def unscoped_consumers(self) -> List[str]:
        found = set()
        for outcome in self.outcomes:
            found.update(outcome.unscoped_consumers)
        return sorted(found)

    @property
    def instance_scope_complete(self) -> bool:
        if self.status != "analyzed":
            return False
        if self.planned_instances != len(self.outcomes):
            return False
        if self.plan_gaps:
            return False
        return all(outcome.scope_preserved for outcome in self.outcomes)

    @property
    def consumer_scope_complete(self) -> bool:
        return not self.unscoped_consumers

    @property
    def scan_coverage_complete(self) -> bool:
        return self.instance_scope_complete and self.consumer_scope_complete

    def coverage_reasons(self) -> List[str]:
        if self.reasons:
            return list(self.reasons)
        reasons: List[str] = []
        if self.plan_gaps:
            reasons.append("plan_coverage_gaps")
        if self.planned_instances != len(self.outcomes):
            reasons.append("scheduled_instances_incomplete")
        for outcome in self.outcomes:
            if outcome.status != "analyzed":
                reasons.append(f"instance_{outcome.status}:{outcome.build_context_id}")
            for gap in outcome.scope_gaps:
                reasons.append(f"{gap.get('reason')}:{outcome.build_context_id}")
        if self.unscoped_consumers:
            reasons.append("blocked_consumers:" + ",".join(self.unscoped_consumers))
        return reasons

    def to_payload(self) -> Dict[str, Any]:
        return {
            "schema": INSTANCE_ANALYSIS_SCHEMA,
            "status": self.status,
            "planned_instances": self.planned_instances,
            "scheduled_instances": self.scheduled_instances,
            "analyzed_instances": self.analyzed_instances,
            "instance_scope_complete": self.instance_scope_complete,
            "consumer_scope_complete": self.consumer_scope_complete,
            "scan_coverage_complete": self.scan_coverage_complete,
            "reasons": self.coverage_reasons(),
            "blocked_consumers": self.unscoped_consumers,
            "unscoped_consumers": self.unscoped_consumers,
            "plan_gaps": [dict(item) for item in self.plan_gaps],
            "instances": [outcome.to_payload() for outcome in self.outcomes],
            "notes": list(self.notes),
        }


def run_instance_analysis(
    analyzer: Any,
    plan: Any,
    *,
    progress_callback: Any = None,
) -> InstanceAnalysisReport:
    """Coordinator entry point: analyze every scheduled instance in ``plan``.

    ``analyzer`` is a ``ParallelAnalyzer``; the call is delegated so this module
    does not import the orchestration layer.
    """

    runner = getattr(analyzer, "analyze_entry_instances", None)
    if not callable(runner):
        raise TypeError("analyzer does not expose analyze_entry_instances")
    return cast(InstanceAnalysisReport, runner(plan, progress_callback=progress_callback))


def merge_outcomes_for_payload(outcomes: Sequence[InstanceAnalysisOutcome]) -> List[Dict[str, Any]]:
    return [outcome.to_payload() for outcome in outcomes]


__all__ = [
    "INSTANCE_ANALYSIS_SCHEMA",
    "GAP_FOREIGN_BUILD_CONTEXT",
    "GAP_UNKNOWN_BUILD_CONTEXT",
    "GAP_IDENTITY_CONTEXT_MISMATCH",
    "GAP_IDENTITY_CONTEXT_UNVERIFIED",
    "GAP_INSTANCE_FACTS_INCOMPLETE",
    "GAP_STALE_BUILD_CONTEXT",
    "GAP_INSTANCE_NOT_ANALYZED",
    "GAP_UNSCOPED_CONSUMER",
    "GAP_AMBIGUOUS_FUNCTION_IDENTITY",
    "InstanceScope",
    "ScopedCodeIndex",
    "InstanceAnalysisOutcome",
    "InstanceAnalysisReport",
    "wrap_scoped_code_index",
    "instance_scope_from_entry_instance",
    "run_instance_analysis",
    "merge_outcomes_for_payload",
]
