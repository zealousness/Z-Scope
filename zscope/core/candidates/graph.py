"""Graph-shaped C memory/concurrency candidate generation.

This module complements the local lexical rules in ``regex_candidates``.
It looks across function boundaries and protocol-like source shapes that a
single-line rule tends to miss: helper calls under locks, wrong cleanup
contracts, container lifecycle gaps, opposite lock order, and stale tree/list
links.  The output intentionally has the same issue dictionary shape as other
Z-SCOPE candidates so the existing analyzer, validator, and report
paths can consume it without a special tier.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Sequence, Tuple, cast

from ...retrieval.code_index import CodeIndex
from ...retrieval.analysis_facts import scan_fact_cache, index_context_key
from .cpp_domains.models import GraphLine, FunctionView, LockOrderEdge
from .cpp_domains.resource_lifecycle import GraphResourceLifecycleRules
from .cpp_domains.memory_bounds_integer import GraphMemoryBoundsIntegerRules
from .cpp_domains.concurrency_shared_state import GraphConcurrencySharedStateRules
from .cpp_domains.protocol_ownership_logic import GraphProtocolOwnershipLogicRules

from .cpp_domains import (
    GraphBatchRuleContext,
    GraphViewRuleContext,
    resolve_rule_descriptor,
    rule_policy_allows_emit,
    run_detector_plan,
)

if TYPE_CHECKING:
    from ...semantics.models import LocalPatternSemantics


class GraphCandidateGenerator(
    GraphResourceLifecycleRules,
    GraphMemoryBoundsIntegerRules,
    GraphConcurrencySharedStateRules,
    GraphProtocolOwnershipLogicRules,
):
    """Generate evidence-backed candidates from call and protocol relationships."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

    def __init__(
        self,
        code_index: CodeIndex,
        semantics: Optional["LocalPatternSemantics"] = None,
        semantic_overlay: Optional[Dict[str, Any]] = None,
        rule_policy: Optional[Any] = None,
        *,
        restrict_to_semantics: bool = False,
    ):
        from .regex import _restricted_semantics

        self.code_index = code_index
        self.restrict_to_semantics = restrict_to_semantics
        self.semantics = (
            _restricted_semantics(semantics) if restrict_to_semantics else self._default_semantics()
        )
        if semantics is not None and not restrict_to_semantics:
            self.semantics.merge(semantics)
        self.rule_policy = rule_policy
        # The exact instance local is the sole effect input. A parallel overlay
        # is advisory and must not add roles, carriers or inferred effects.
        self.semantic_overlay = {} if restrict_to_semantics else (semantic_overlay or {})
        self.semantics.merge_overlay(self.semantic_overlay)
        self.pointer_target_models = self._pointer_target_models(self.semantic_overlay)
        self.dispatcher_models = self._dispatcher_models(self.semantic_overlay)
        self._impl_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        self._view_cache: Dict[str, Optional[FunctionView]] = {}
        self._callee_evidence: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.last_deferred_functions: List[Dict[str, Any]] = []
        self.last_query_errors: List[Dict[str, str]] = []
        self._compile_semantic_patterns()
        self.fact_cache = scan_fact_cache(code_index)
        self.fact_context = (
            "graph-facts.v2",
            index_context_key(code_index),
            hashlib.sha256(
                json.dumps(
                    [vars(self.semantics), self.semantic_overlay, self.restrict_to_semantics],
                    sort_keys=True,
                    default=str,
                ).encode()
            ).hexdigest(),
        )

    def generate_for_entry(
        self,
        func_name: str,
        impl: Optional[Dict[str, Any]] = None,
        *,
        max_depth: int = 1,
        max_functions: int = 32,
    ) -> List[Dict[str, Any]]:
        views = self._reachable_views(
            func_name, impl, max_depth=max_depth, max_functions=max_functions
        )
        return self.generate_for_views(views)

    def _compile_semantic_patterns(self) -> None:
        from ...semantics.contracts import return_acquisition_names

        lock_names = set(self.semantics.lock_apis) | self._checker_defaults("extended_lock_apis")
        unlock_names = set(self.semantics.unlock_apis) | self._checker_defaults(
            "extended_unlock_apis"
        )
        alloc_names = (
            set(self.semantics.allocators)
            | set(self.semantics.calloc_allocators)
            | set(self.semantics.reallocators)
            | self._checker_defaults("extended_allocators")
        )
        free_names = self._checker_defaults("graph_release_apis") | self._overlay_semantics_names(
            "deallocators"
        )
        if self.restrict_to_semantics:
            free_names = set(self.semantics.deallocators)
        self._lock_names = lock_names
        self._unlock_names = unlock_names
        self._alloc_names = alloc_names
        self._free_names = free_names
        self._lock_call_re = re.compile(
            rf"\b(?P<api>{self._names_pattern(lock_names)})\s*\((?P<arg>[^)]*)\)"
        )
        self._unlock_call_re = re.compile(
            rf"\b(?P<api>{self._names_pattern(unlock_names)})\s*\((?P<arg>[^)]*)\)"
        )
        return_allocators = set().union(
            return_acquisition_names(self.semantics, self.semantics.allocators, "allocator"),
            return_acquisition_names(self.semantics, self.semantics.calloc_allocators, "calloc"),
            return_acquisition_names(self.semantics, self.semantics.reallocators, "reallocator"),
            {
                name
                for name in alloc_names
                if not self.restrict_to_semantics and not self.semantics.contracts.find(name)
            },
        )
        self._alloc_assign_re = re.compile(
            rf"(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
            rf"(?P<api>{self._names_pattern(return_allocators)})\s*\("
        )
        self._free_re = re.compile(
            rf"\b(?P<api>{self._names_pattern(free_names)})\s*\((?P<arg>[^)]*)\)",
        )

    def _semantic_api_pattern(self, pattern: str) -> str:
        from .regex import _consumer_api_pattern

        return _consumer_api_pattern(pattern, self.semantics, self.restrict_to_semantics)

    def _literal_api_pattern(self, pattern: str) -> str:
        from .regex import _consumer_api_pattern

        return _consumer_api_pattern(
            pattern, self.semantics, self.restrict_to_semantics, expand_slots=False
        )

    def _semantic_call_allowed(self, name: str, *roles: str) -> bool:
        from .regex import _semantic_call_allowed

        return _semantic_call_allowed(self.semantics, self.restrict_to_semantics, name, *roles)

    @staticmethod
    def _default_semantics() -> "LocalPatternSemantics":
        from ...semantics.defaults import default_local_pattern_semantics

        return default_local_pattern_semantics()

    def _checker_defaults(self, role_name: str) -> set[str]:
        from ...semantics.defaults import default_checker_api_names

        return set() if self.restrict_to_semantics else set(default_checker_api_names(role_name))

    def _overlay_semantics_names(self, attr: str) -> set[str]:
        from ...semantics.defaults import DEFAULT_SEMANTICS_SOURCE

        values = getattr(self.semantics, attr, {})
        if not isinstance(values, dict):
            return set()
        return {
            str(name)
            for name, sources in values.items()
            if str(name).strip()
            and any(str(source) != DEFAULT_SEMANTICS_SOURCE for source in (sources or []))
        }

    @staticmethod
    def _pointer_target_models(overlay: Dict[str, Any]) -> List[Dict[str, Any]]:
        rows = overlay.get("pointer_target_models") if isinstance(overlay, dict) else []
        if not isinstance(rows, list):
            return []
        return [dict(row) for row in rows if isinstance(row, dict)]

    @staticmethod
    def _dispatcher_models(overlay: Dict[str, Any]) -> List[Dict[str, Any]]:
        rows = overlay.get("dispatcher_models") if isinstance(overlay, dict) else []
        if not isinstance(rows, list):
            return []
        return [dict(row) for row in rows if isinstance(row, dict)]

    def generate_for_functions(
        self,
        function_names: Iterable[str],
        *,
        max_functions: int = 500,
    ) -> List[Dict[str, Any]]:
        views: List[FunctionView] = []
        seen = set()
        for name in function_names:
            if not name or name in seen:
                continue
            seen.add(name)
            view = self._view_for(str(name))
            if view:
                views.append(view)
            if len(views) >= max_functions:
                break
        return self.generate_for_views(views)

    def generate_for_views(self, views: Sequence[FunctionView]) -> List[Dict[str, Any]]:
        self.last_semantic_events = [
            event
            for view in views
            for event in self.semantics.contracts.trace_calls(
                {
                    "func_name": view.name,
                    "file_path": view.file_path,
                    "signature": view.signature,
                    "code": "\n".join(line.text for line in view.lines),
                }
            )
        ]
        by_name = {view.name: view for view in views}
        issues: List[Dict[str, Any]] = []
        for view in views:
            from ...semantics.call_context import bind_call_context

            with bind_call_context(
                {
                    "func_name": view.name,
                    "file_path": view.file_path,
                    "signature": view.signature,
                    "code": "\n".join(line.text for line in view.lines),
                },
                self.semantics.contracts,
            ):
                run_detector_plan(
                    "graph",
                    "view",
                    GraphViewRuleContext(
                        generator=self,
                        view=view,
                        by_name=by_name,
                        issues=issues,
                    ),
                )

        run_detector_plan(
            "graph",
            "batch",
            GraphBatchRuleContext(generator=self, views=views, issues=issues),
        )
        if self.rule_policy is not None:
            filtered: List[Dict[str, Any]] = []
            for issue in issues:
                if issue.get("_zscope_rule_policy_filtered"):
                    continue
                rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
                # Leave malformed candidates visible to the strict pipeline gate.
                # The generator policy is only an early disabled-rule shortcut.
                if not rule_id or rule_policy_allows_emit(self.rule_policy, rule_id):
                    filtered.append(issue)
            issues = filtered
        return self._dedupe(issues)

    def issue_to_ticket(self, issue: Dict[str, Any]) -> Any:
        from .regex import RegexCandidateGenerator

        return RegexCandidateGenerator().issue_to_ticket(issue)

    def _reachable_views(
        self,
        func_name: str,
        impl: Optional[Dict[str, Any]],
        *,
        max_depth: int,
        max_functions: int,
    ) -> List[FunctionView]:
        self.last_deferred_functions = []
        self.last_query_errors = []
        views: List[FunctionView] = []
        queue: List[Tuple[str, Optional[Dict[str, Any]], int]] = [(func_name, impl, 0)]
        seen = set()
        while queue and len(views) < max_functions:
            current, current_impl, depth = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            view = self._view_for(current, current_impl)
            if not view:
                continue
            views.append(view)
            expand_dispatcher_siblings = (
                depth >= max_depth
                and depth < max_depth + 1
                and (
                    self._looks_like_dispatcher_view(view)
                    or self._looks_like_boundary_fanout_view(view)
                )
            )
            if depth >= max_depth and not expand_dispatcher_siblings:
                for callee in view.callees:
                    if callee not in seen:
                        self.last_deferred_functions.append(
                            {
                                "function_name": callee,
                                "reason": "graph_max_depth",
                                "parent": current,
                            }
                        )
                continue
            for callee in view.callees:
                if callee in seen:
                    continue
                callee_impl = self._impl_for(callee)
                if callee_impl:
                    queue.append((callee, callee_impl, depth + 1))
        if queue:
            for current, _impl, _depth in queue:
                if current not in seen:
                    self.last_deferred_functions.append(
                        {
                            "function_name": current,
                            "reason": "graph_max_functions",
                        }
                    )
        deduped: Dict[str, Dict[str, Any]] = {}
        for item in self.last_deferred_functions:
            name = str(item.get("function_name") or "")
            if name:
                deduped.setdefault(name, item)
        self.last_deferred_functions = list(deduped.values())
        return views

    def _view_for(
        self,
        func_name: str,
        impl: Optional[Dict[str, Any]] = None,
    ) -> Optional[FunctionView]:
        if impl is None and func_name in self._view_cache:
            return self._view_cache[func_name]
        impl = impl or self._impl_for(func_name)
        if impl and impl.get("truncated"):
            impl = self._impl_for(func_name)
        if not impl:
            self._view_cache[func_name] = None
            return None
        source_hash = hashlib.sha256(
            json.dumps(impl, sort_keys=True, default=str).encode()
        ).hexdigest()

        def build() -> Any:
            lines = tuple(self._parse_lines(str(impl.get("code") or "")))
            file_path = str(impl.get("file") or "")
            direct_callees = [str(item) for item in impl.get("callees") or [] if item]
            view = FunctionView(
                name=func_name,
                file_path=file_path,
                signature=self._signature_from_impl(func_name, impl),
                lines=lines,
                callees=tuple(
                    self._merged_callee_names(func_name, file_path, lines, direct_callees)
                ),
            )
            return view, {
                key: value for key, value in self._callee_evidence.items() if key[0] == func_name
            }

        view, evidence = self.fact_cache.compute(
            (self.fact_context, "view", func_name, source_hash), build
        )
        self._callee_evidence.update(evidence)
        self._view_cache[func_name] = view
        return cast(Optional[FunctionView], view)

    def _function_fact_key(self, func_name: str) -> Any:
        index = getattr(self.code_index, "_function_index", {})
        info = index.get(func_name) or {}
        if not info:
            aliases = getattr(self.code_index, "_function_alias_index", {}).get(func_name, [])
            if len(aliases) == 1:
                info = index.get(next(iter(aliases))) or {}
        source_file = info.get("file") or info.get("file_path")
        fingerprint = getattr(self.code_index, "_source_fingerprint", None)
        token = (
            fingerprint(source_file)
            if source_file and callable(fingerprint)
            else getattr(self.code_index, "_index_epoch", 0)
        )
        return self.fact_context, "impl", func_name, token

    def _impl_for(self, func_name: str) -> Optional[Dict[str, Any]]:
        if func_name not in self._impl_cache:
            getter = getattr(self.code_index, "get_function_impl", None)
            if not callable(getter):
                self._impl_cache[func_name] = None
            else:
                try:
                    self._impl_cache[func_name] = self.fact_cache.compute(
                        self._function_fact_key(func_name),
                        lambda: getter(func_name, max_lines=None, warn_missing=False),
                    )
                    if (self._impl_cache[func_name] or {}).get("truncated"):
                        raise ValueError("source_truncated")
                except Exception as exc:
                    self.last_query_errors.append(
                        {
                            "function_name": func_name,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
                    self._impl_cache[func_name] = None
        return self._impl_cache[func_name]

    def _merged_callee_names(
        self,
        func_name: str,
        file_path: str,
        lines: Sequence[GraphLine],
        direct_callees: Sequence[str],
    ) -> List[str]:
        merged: List[str] = []
        for callee in direct_callees:
            self._add_callee(func_name, callee, {"source": "lexical_call", "kind": "direct"})
            if callee not in merged:
                merged.append(callee)

        get_callees = getattr(self.code_index, "get_callees", None)
        if callable(get_callees):
            try:
                records = get_callees(func_name, limit=80)
            except Exception as exc:
                self.last_query_errors.append(
                    {
                        "function_name": func_name,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                records = []
            for record in records or []:
                if not isinstance(record, dict):
                    continue
                if record.get("call_type") == "callback_registration":
                    # Registration grants external reachability, not a nested
                    # synchronous acquisition under the registering thread's locks.
                    continue
                callee = str(record.get("name") or record.get("callee_name") or "").strip()
                if not callee:
                    continue
                evidence = {
                    "source": str(record.get("source") or "backend_call_graph"),
                    "kind": "backend_call_graph",
                    "call_line": record.get("call_line") or record.get("lineNumber"),
                    "confidence": record.get("confidence"),
                }
                self._add_callee(func_name, callee, evidence)
                if callee not in merged:
                    merged.append(callee)

        for target in self._configured_pointer_targets(func_name, file_path, lines):
            callee = str(target.get("target") or "").strip()
            if not callee:
                continue
            self._add_callee(func_name, callee, target)
            if callee not in merged:
                merged.append(callee)
        for target in self._configured_dispatcher_targets(func_name, file_path):
            callee = str(target.get("target") or "").strip()
            if not callee:
                continue
            self._add_callee(func_name, callee, target)
            if callee not in merged:
                merged.append(callee)
        return merged

    def _add_callee(self, caller: str, callee: str, evidence: Dict[str, Any]) -> None:
        if not caller or not callee:
            return
        current = self._callee_evidence.setdefault((caller, callee), {})
        current.update({k: v for k, v in evidence.items() if v not in (None, "", [], {})})

    def _configured_pointer_targets(
        self,
        func_name: str,
        file_path: str,
        lines: Sequence[GraphLine],
    ) -> List[Dict[str, Any]]:
        if not self.pointer_target_models:
            return []
        text = "\n".join(line.text for line in lines)
        targets: List[Dict[str, Any]] = []
        for row in self.pointer_target_models:
            scope = str(row.get("scope") or "*").strip()
            pointer_location = str(row.get("pointer_location") or "").strip()
            if not self._pointer_scope_matches(scope, func_name, file_path):
                continue
            if pointer_location and pointer_location not in text:
                continue
            for target in self._target_functions(row.get("target_functions")):
                targets.append(
                    {
                        "target": target,
                        "source": "user_config:pointer_targets",
                        "kind": "configured_indirect_call",
                        "pointer_location": pointer_location,
                        "scope": scope,
                    }
                )
        return targets

    def _configured_dispatcher_targets(
        self, func_name: str, file_path: str
    ) -> List[Dict[str, Any]]:
        if not self.dispatcher_models:
            return []
        targets: List[Dict[str, Any]] = []
        for row in self.dispatcher_models:
            dispatcher = str(row.get("dispatcher_name") or "").strip()
            handler = str(row.get("handler_name") or "").strip()
            scope_file = str(row.get("file_path") or "").strip()
            if not dispatcher or not handler:
                continue
            if dispatcher != func_name:
                continue
            if scope_file and not self._pointer_scope_matches(scope_file, func_name, file_path):
                continue
            targets.append(
                {
                    "target": handler,
                    "source": "user_config:dispatcher",
                    "kind": "configured_dispatcher_edge",
                    "dispatcher_name": dispatcher,
                    "message_type": row.get("message_type"),
                    "handler_kind": row.get("handler_kind"),
                }
            )
        return targets

    @staticmethod
    def _pointer_scope_matches(scope: str, func_name: str, file_path: str) -> bool:
        if not scope or scope == "*":
            return True
        scope_norm = scope.replace("\\", "/")
        file_norm = file_path.replace("\\", "/")
        return scope == func_name or scope_norm == file_norm or scope_norm in file_norm

    @staticmethod
    def _target_functions(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if not value:
            return []
        try:
            parsed = json.loads(str(value))
        except json.JSONDecodeError:
            parsed = [part.strip() for part in str(value).split(",")]
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
        return [str(parsed).strip()] if str(parsed).strip() else []

    def _issue(
        self,
        *,
        defect_class: str,
        rule: str,
        view: FunctionView,
        line: GraphLine,
        description: str,
        root_cause: str,
        suggested_fix: str,
        source: str,
        sink: str,
        confidence: float,
        impact_level: str,
        positive: List[str],
        negative: Optional[List[str]] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        # Graph detectors share this emitter.  Apply the policy before building
        # candidate identity/evidence so disabled or backend-unavailable rules
        # cannot fail descriptor enrichment or leak a partial candidate into
        # the central pipeline.  Unknown IDs remain visible and are rejected by
        # the authoritative Analyzer gate.
        if not rule_policy_allows_emit(self.rule_policy, rule):
            return {
                "_zscope_rule_policy_filtered": True,
                "rule_id": rule,
            }
        descriptor = resolve_rule_descriptor(
            self.rule_policy,
            rule,
            defect_class=defect_class,
        )
        cwe = descriptor.cwe if descriptor is not None else ""
        skill = descriptor.skill if descriptor is not None else ""
        candidate_id = self._candidate_id(
            view.name, view.file_path, defect_class, line.number, rule, sink
        )
        dedup_key = "|".join(
            [
                defect_class,
                view.file_path.replace("\\", "/").lower(),
                str(line.number),
                rule,
                self._stable_fragment(sink),
            ]
        )
        pack: Dict[str, Any] = {
            "candidate_id": candidate_id,
            "candidate_source": "graph_rule",
            "defect_class": defect_class,
            "rule": rule,
            "rule_id": descriptor.rule_id if descriptor is not None else rule,
            "cwe": cwe,
            "skill": skill,
            "rule_confidence": confidence,
            "source": {"expression": source, "file": view.file_path, "line": line.number},
            "sink": {"operation": sink, "file": view.file_path, "line": line.number},
            "path": {"function": view.name, "complete_in_function": False},
            "object": {"id": source or sink or defect_class, "aliases": []},
            "positive_evidence": list(positive),
            "negative_evidence": list(negative or []),
            "evidence_refs": [],
        }
        if evidence:
            pack.update(evidence)
        return {
            "id": candidate_id,
            "candidate_id": candidate_id,
            "function": view.name,
            "location": f"{view.file_path}:{line.number}",
            "category": defect_class,
            "subcategory": defect_class,
            "defect_class": defect_class,
            "finding_kind": "graph_candidate",
            "candidate_source": "graph_rule",
            "rule": rule,
            "rule_id": descriptor.rule_id if descriptor is not None else rule,
            "cwe": cwe,
            "skill": skill,
            "description": description,
            "root_cause": root_cause,
            "suggested_fix": suggested_fix,
            "confidence": confidence,
            "rule_confidence": confidence,
            "impact_level": impact_level,
            "reasoning": "Graph candidate generated from cross-function C protocol evidence.",
            "code_snippet": self._context(view.lines, line.index - 5, line.index + 8),
            "source": source,
            "sink": sink,
            "dedup_key": dedup_key,
            "positive_evidence": list(positive),
            "negative_evidence": list(negative or []),
            "evidence_pack": pack,
            "evidence_refs": [],
            "path_constraints": (
                pack["path"].get("path_constraints", [])
                if isinstance(pack.get("path"), dict)
                else []
            ),
        }

    @classmethod
    def _parse_lines(cls, code: str) -> List[GraphLine]:
        lines: List[GraphLine] = []
        for idx, raw in enumerate(str(code or "").splitlines()):
            match = cls._LINE_RE.match(raw)
            if match:
                number = int(match.group(1))
                text = match.group(2).strip()
            else:
                number = idx + 1
                text = raw.strip()
            lines.append(GraphLine(number=number, text=text, raw=raw, index=idx))
        return lines

    @staticmethod
    def _signature_from_impl(func_name: str, impl: Dict[str, Any]) -> str:
        signature = str(impl.get("signature") or "")
        if signature and "..." not in signature:
            return signature
        code = str(impl.get("code") or "")
        for raw in code.splitlines()[:8]:
            clean = re.sub(r"^\s*\d+\s*\|\s*", "", raw).strip()
            if func_name in clean and "(" in clean:
                return clean.rstrip("{").strip()
        return signature or f"{func_name}(...)"

    @classmethod
    def _called_names(cls, text: str) -> List[str]:
        skip = {"if", "for", "while", "switch", "return", "sizeof"}
        return [m.group(1) for m in cls._CALL_NAME_RE.finditer(text) if m.group(1) not in skip]

    def _names_pattern(self, names: Iterable[str]) -> str:
        clean = sorted(
            {str(name).strip() for name in names if str(name).strip()}, key=len, reverse=True
        )
        pattern = "|".join(re.escape(name) for name in clean) or r"a^"
        return "(?-i:" + pattern + ")" if self.restrict_to_semantics else pattern

    @classmethod
    def _views_share_protocol_terms(cls, left: FunctionView, right: FunctionView) -> bool:
        left_terms = set(cls._identifier_terms(left.name))
        right_terms = set(cls._identifier_terms(right.name))
        shared = (left_terms & right_terms) - {
            "register",
            "unregister",
            "delete",
            "remove",
            "cleanup",
            "destroy",
            "add",
            "attach",
            "init",
            "create",
            "lifecycle",
        }
        if shared:
            return True
        left_text = "\n".join(line.text for line in left.lines)
        right_text = "\n".join(line.text for line in right.lines)
        type_terms = set(
            re.findall(r"\b[A-Z][A-Za-z0-9_]*(?:Node|Subscription|Session|Entry|Pipe)\b", left_text)
        )
        type_terms &= set(
            re.findall(
                r"\b[A-Z][A-Za-z0-9_]*(?:Node|Subscription|Session|Entry|Pipe)\b", right_text
            )
        )
        return bool(type_terms)

    @staticmethod
    def _looks_like_dispatcher_view(view: FunctionView) -> bool:
        if len(view.callees) < 3:
            return False
        text = "\n".join(line.text for line in view.lines)
        name_hint = re.search(
            r"(?:dispatch|handle|process|message|protocol|router|route)", view.name, re.I
        )
        switch_hint = "switch" in text or len(re.findall(r"\bcase\b|\bdefault\s*:", text)) >= 2
        branch_hint = len(re.findall(r"\b(?:if|else\s+if)\s*\(", text)) >= 3
        return bool(switch_hint or (name_hint and branch_hint))

    @staticmethod
    def _looks_like_boundary_fanout_view(view: FunctionView) -> bool:
        if not view.callees:
            return False
        text = "\n".join(line.text for line in view.lines)
        if len(view.callees) == 1 and re.search(r"\breturn\s+[A-Za-z_]\w+\s*\(", text):
            return True
        call_statements = sum(
            1 for line in view.lines if GraphCandidateGenerator._called_names(line.text)
        )
        if len(view.callees) >= 3 and call_statements >= 3:
            return True
        name_hint = re.search(
            r"(?:apply|configure|publish|schedule|refresh|accept|cycle|plan|record|maintenance|cases|worker|runtime)",
            view.name,
            re.I,
        )
        return bool(name_hint and len(view.callees) >= 2 and call_statements >= 2)

    @staticmethod
    def _first_line_matching(view: FunctionView, pattern: re.Pattern[str]) -> Optional[GraphLine]:
        return next(
            (
                line
                for line in view.lines
                if pattern.search(line.text)
                and not (re.search(rf"\b{re.escape(view.name)}\s*\([^;]*\)\s*\{{\s*$", line.text))
            ),
            None,
        )

    @staticmethod
    def _context(lines: Sequence[GraphLine], start: int, end: int) -> str:
        return "\n".join(line.raw for line in lines[max(0, start) : min(len(lines), end)])

    @staticmethod
    def _stable_fragment(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip().lower()[:120]

    @classmethod
    def _candidate_id(
        cls,
        func_name: str,
        file_path: str,
        defect_class: str,
        line: int,
        rule: str,
        sink: str,
    ) -> str:
        digest = hashlib.sha1(
            f"{func_name}|{file_path}|{defect_class}|{line}|{rule}|{sink}".encode("utf-8")
        ).hexdigest()[:10]
        return f"GRAPH_{defect_class.upper()}_{digest}"

    @staticmethod
    def _dedupe(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = str(issue.get("dedup_key") or issue.get("candidate_id") or issue.get("id"))
            deduped.setdefault(key, issue)
        return list(deduped.values())
