"""Graph-shaped C memory/concurrency candidate generation.

This module complements the local lexical rules in ``regex_candidates``.
It looks across function boundaries and protocol-like source shapes that a
single-line rule tends to miss: helper calls under locks, wrong cleanup
contracts, container lifecycle gaps, opposite lock order, and stale tree/list
links.  The output intentionally has the same issue dictionary shape as other
Z-SCOPE candidates so the existing analyzer, validator, report, and benchmark
paths can consume it without a special tier.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ...retrieval.code_index import CodeIndex

if TYPE_CHECKING:
    from ...semantics.models import LocalPatternSemantics


@dataclass(frozen=True)
class GraphLine:
    number: int
    text: str
    raw: str
    index: int


@dataclass(frozen=True)
class FunctionView:
    name: str
    file_path: str
    signature: str
    lines: Tuple[GraphLine, ...]
    callees: Tuple[str, ...]


@dataclass(frozen=True)
class LockOrderEdge:
    function: str
    file_path: str
    first_lock: str
    second_lock: str
    first_line: int
    second_line: int


class GraphCandidateGenerator:
    """Generate evidence-backed candidates from call and protocol relationships."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    _CWE_BY_CLASS = {
        "deadlock": "CWE-833",
        "memory_leak": "CWE-401",
        "type_confusion": "CWE-843",
        "infinite_loop": "CWE-835",
        "log_amplification": "CWE-400",
        "key_truncation": "CWE-187",
        "use_after_free": "CWE-416",
        "race": "CWE-362",
        "semantic_mismatch": "CWE-628",
        "byte_order_logic": "CWE-682",
        "reader_state_race": "CWE-362",
        "stack_overflow": "CWE-121",
        "uninitialized_output": "CWE-457",
        "file_type_validation": "CWE-20",
        "log_level_misuse": "CWE-778",
        "logic_error": "CWE-682",
        "global_mode_race": "CWE-362",
        "slot_race": "CWE-362",
        "lost_wakeup": "CWE-366",
        "shared_memory_race": "CWE-362",
        "state_machine": "CWE-672",
        "signal_deadlock": "CWE-833",
        "callback_self_destroy_race": "CWE-416",
        "object_publication": "CWE-362",
        "fd_type_mismatch": "CWE-628",
    }

    def __init__(
        self,
        code_index: CodeIndex,
        semantics: Optional["LocalPatternSemantics"] = None,
        semantic_overlay: Optional[Dict[str, Any]] = None,
    ):
        self.code_index = code_index
        self.semantics = self._default_semantics()
        if semantics is not None:
            self.semantics.merge(semantics)
        self.semantic_overlay = semantic_overlay or {}
        self.pointer_target_models = self._pointer_target_models(self.semantic_overlay)
        self.dispatcher_models = self._dispatcher_models(self.semantic_overlay)
        self._impl_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        self._view_cache: Dict[str, Optional[FunctionView]] = {}
        self._callee_evidence: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._compile_semantic_patterns()

    def generate_for_entry(
        self,
        func_name: str,
        impl: Optional[Dict[str, Any]] = None,
        *,
        max_depth: int = 1,
        max_functions: int = 32,
    ) -> List[Dict[str, Any]]:
        views = self._reachable_views(func_name, impl, max_depth=max_depth, max_functions=max_functions)
        return self.generate_for_views(views)

    def _compile_semantic_patterns(self) -> None:
        lock_names = set(self.semantics.lock_apis) | self._checker_defaults("extended_lock_apis")
        unlock_names = set(self.semantics.unlock_apis) | self._checker_defaults("extended_unlock_apis")
        alloc_names = (
            set(self.semantics.allocators)
            | set(self.semantics.calloc_allocators)
            | set(self.semantics.reallocators)
            | self._checker_defaults("extended_allocators")
        )
        free_names = self._checker_defaults("graph_release_apis") | self._overlay_semantics_names("deallocators")
        self._lock_names = lock_names
        self._unlock_names = unlock_names
        self._alloc_names = alloc_names
        self._free_names = free_names
        self._lock_call_re = re.compile(
            rf"\b(?:{self._names_pattern(lock_names)})\s*\((?P<arg>[^)]*)\)"
        )
        self._unlock_call_re = re.compile(rf"\b(?:{self._names_pattern(unlock_names)})\s*\(")
        self._alloc_assign_re = re.compile(
            rf"(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
            rf"(?:{self._names_pattern(alloc_names)}|[A-Za-z_]\w*(?:Alloc|AllocZero|Create|New))\s*\("
        )
        self._free_re = re.compile(
            rf"\b(?:{self._names_pattern(free_names)})\s*\((?P<arg>[^)]*)\)",
            re.I,
        )

    @staticmethod
    def _default_semantics() -> "LocalPatternSemantics":
        from ...semantics.defaults import default_local_pattern_semantics

        return default_local_pattern_semantics()

    @staticmethod
    def _checker_defaults(role_name: str) -> set[str]:
        from ...semantics.defaults import default_checker_api_names

        return set(default_checker_api_names(role_name))

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
        by_name = {view.name: view for view in views}
        issues: List[Dict[str, Any]] = []
        for view in views:
            self._rule_recursive_lock(view, by_name, issues)
            self._rule_wrong_cleanup_type(view, by_name, issues)
            self._rule_thread_argument_lifetime(view, issues)
            self._rule_global_container_lifecycle(view, issues)
            self._rule_tree_and_liveness_protocols(view, issues)
            self._rule_publication_and_lifetime_order(view, issues)
            self._rule_protocol_state_contracts(view, issues)

        self._rule_paired_lifecycle_protocols(views, issues)
        self._rule_paired_member_cleanup_protocols(views, issues)
        self._rule_paired_key_normalization_protocols(views, issues)
        self._rule_paired_self_link_log_traversal(views, issues)
        self._rule_paired_global_registration_cleanup(views, issues)
        self._rule_timer_cascade_wait(views, issues)
        self._rule_callback_self_destroy_protocols(views, issues)
        self._rule_lock_order_inversion(views, issues)
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
                continue
            for callee in view.callees:
                if callee in seen:
                    continue
                callee_impl = self._impl_for(callee)
                if callee_impl:
                    queue.append((callee, callee_impl, depth + 1))
        return views

    def _view_for(
        self,
        func_name: str,
        impl: Optional[Dict[str, Any]] = None,
    ) -> Optional[FunctionView]:
        if impl is None and func_name in self._view_cache:
            return self._view_cache[func_name]
        impl = impl or self._impl_for(func_name)
        if not impl:
            self._view_cache[func_name] = None
            return None
        lines = tuple(self._parse_lines(str(impl.get("code") or "")))
        file_path = str(impl.get("file") or "")
        direct_callees = [str(item) for item in impl.get("callees") or [] if item]
        view = FunctionView(
            name=func_name,
            file_path=file_path,
            signature=self._signature_from_impl(func_name, impl),
            lines=lines,
            callees=tuple(self._merged_callee_names(func_name, file_path, lines, direct_callees)),
        )
        self._view_cache[func_name] = view
        return view

    def _impl_for(self, func_name: str) -> Optional[Dict[str, Any]]:
        if func_name not in self._impl_cache:
            getter = getattr(self.code_index, "get_function_impl", None)
            if not callable(getter):
                self._impl_cache[func_name] = None
            else:
                self._impl_cache[func_name] = getter(
                    func_name,
                    warn_missing=False,
                )
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
            except Exception:
                records = []
            for record in records or []:
                if not isinstance(record, dict):
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

    def _configured_dispatcher_targets(self, func_name: str, file_path: str) -> List[Dict[str, Any]]:
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

    def _rule_recursive_lock(
        self,
        view: FunctionView,
        by_name: Dict[str, FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        held: List[Tuple[str, GraphLine]] = []
        for line in view.lines:
            lock = self._lock_arg(line.text)
            if lock:
                held.append((lock, line))
                continue
            if self._unlock_call_re.search(line.text) and held:
                held.pop()
                continue
            if not held:
                continue
            for call_name in self._call_targets_for_line(view.name, line):
                callee = by_name.get(call_name) or self._view_for(call_name)
                if not callee:
                    continue
                callee_locks = [(self._lock_arg(item.text), item) for item in callee.lines]
                callee_locks = [(lock_id, item) for lock_id, item in callee_locks if lock_id]
                if not callee_locks:
                    continue
                held_lock, held_line = held[-1]
                same_lock = next(
                    (
                        (lock_id, lock_line)
                        for lock_id, lock_line in callee_locks
                        if self._locks_may_match(held_lock, lock_id)
                    ),
                    None,
                )
                if not same_lock:
                    continue
                call_evidence = self._callee_evidence.get((view.name, call_name), {})
                reachability = self._callee_reachability_text(call_name, call_evidence)
                issues.append(
                    self._issue(
                        defect_class="deadlock",
                        rule="cross_function_recursive_lock",
                        view=view,
                        line=line,
                        description=(
                            f"`{view.name}` calls `{call_name}` while `{held_lock}` is held; "
                            f"`{call_name}` can acquire `{same_lock[0]}` again."
                        ),
                        root_cause="A helper with its own locking contract is reached under an already-held lock.",
                        suggested_fix="Use a no-lock helper variant, document the caller-held lock contract, or release before calling.",
                        source=f"{view.name}:{held_line.number}:{held_lock}",
                        sink=f"{call_name}:{same_lock[1].number}:{same_lock[0]}",
                        confidence=0.86,
                        impact_level="high",
                        positive=[
                            f"line {held_line.number}: caller acquires `{held_lock}`",
                            f"line {line.number}: caller invokes `{call_name}` while lock is held",
                            reachability,
                            f"{call_name} line {same_lock[1].number}: callee acquires `{same_lock[0]}`",
                        ],
                        evidence={
                            "path": {
                                "caller": view.name,
                                "callee": call_name,
                                "call_line": line.number,
                                "call_evidence": call_evidence,
                                "path_constraints": ["same thread", "callee reachable from locked region"],
                            }
                        },
                    )
                )

    def _rule_wrong_cleanup_type(
        self,
        view: FunctionView,
        by_name: Dict[str, FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        for line in view.lines:
            for call_name in self._called_names(line.text):
                if not re.search(r"(?:cleanup|destroy|deinit|release|free)", call_name, re.I):
                    continue
                callee = by_name.get(call_name) or self._view_for(call_name)
                if not callee:
                    continue
                param_type = self._first_param_type(callee.signature)
                if not param_type:
                    continue
                first_arg = self._first_call_arg(line.text, call_name)
                if not first_arg or not first_arg.startswith("&"):
                    continue
                arg_terms = set(self._identifier_terms(first_arg))
                type_terms = set(self._identifier_terms(param_type))
                if not type_terms:
                    continue
                overlap = arg_terms & type_terms
                if overlap:
                    continue
                if "." not in first_arg and "->" not in first_arg:
                    continue
                issues.append(
                    self._issue(
                        defect_class="type_confusion",
                        rule="cleanup_contract_type_mismatch",
                        view=view,
                        line=line,
                        description=(
                            f"`{call_name}` expects `{param_type}` but receives `{first_arg}`, "
                            "which appears to be a different struct field address."
                        ),
                        root_cause="A cleanup/destroy routine is invoked with an object whose static contract does not match the callee parameter.",
                        suggested_fix="Pass the object matching the cleanup contract or split cleanup functions by concrete type.",
                        source=first_arg,
                        sink=f"{call_name}({param_type})",
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: call argument `{first_arg}`",
                            f"{call_name} signature: `{callee.signature}`",
                        ],
                    )
                )

    def _rule_thread_argument_lifetime(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        allocations: Dict[str, GraphLine] = {}
        released: set = set()
        thread_args: Dict[str, GraphLine] = {}
        for line in view.lines:
            alloc = self._alloc_assign_re.search(line.text)
            if alloc:
                allocations[alloc.group("var")] = line
            free = self._free_re.search(line.text)
            if free:
                arg = free.group("arg")
                for var in allocations:
                    if re.search(rf"\b{re.escape(var)}\b", arg):
                        released.add(var)
            if "pthread_create" not in line.text:
                continue
            for var in allocations:
                if re.search(rf"&\s*{re.escape(var)}\s*(?:\[|\b)", line.text):
                    thread_args[var] = line
        for var, alloc_line in allocations.items():
            if var not in thread_args or var in released:
                continue
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="heap_thread_argument_not_released",
                    view=view,
                    line=alloc_line,
                    description=(
                        f"`{var}` is heap allocated and its element address is passed to `pthread_create`, "
                        "but the owner allocation is never released in the function."
                    ),
                    root_cause="Thread argument storage remains owned by the initializer but no cleanup path frees it.",
                    suggested_fix="Store the allocation in a dispatcher-owned field and free it during shutdown, or free after all workers join.",
                    source=var,
                    sink=f"pthread_create at line {thread_args[var].number}",
                    confidence=0.78,
                    impact_level="medium",
                    positive=[
                        f"line {alloc_line.number}: `{var}` allocated",
                        f"line {thread_args[var].number}: `{var}` address escapes to worker thread",
                        "no matching release was found in the same ownership scope",
                    ],
                    evidence={
                        "path": {
                            "function": view.name,
                            "source_line": alloc_line.number,
                            "sink_line": thread_args[var].number,
                            "path_constraints": ["worker may outlive initializer", "owner remains local"],
                        }
                    },
                )
            )

    def _rule_global_container_lifecycle(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if re.search(r"pfnDropSession", text) and not re.search(r"(?:release|free|destroy|remove)", text, re.I):
            line = self._first_line_containing(view, "pfnDropSession") or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="registered_global_object_missing_release_hook",
                    view=view,
                    line=line,
                    description="A global/container-owned session is handled only through an optional drop hook, with no fallback release path.",
                    root_cause="The cleanup protocol depends on a hook that may remain NULL or unregistered.",
                    suggested_fix="Register the release hook during initialization or add an unconditional fallback release path.",
                    source="global container add/register path",
                    sink=line.text.strip(),
                    confidence=0.76,
                    impact_level="high",
                    positive=[f"line {line.number}: cleanup depends on optional hook `{line.text.strip()}`"],
                )
            )

        if re.search(r"\bOPEN\b", text) and re.search(r"(?:add|insert|register).*global|global.*(?:add|insert|register)", text, re.I):
            line = self._first_line_matching(view, re.compile(r"\bOPEN\b|global", re.I)) or view.lines[0]
            if not re.search(r"(?:remove|drop|release|free|destroy)", text, re.I):
                issues.append(
                    self._issue(
                        defect_class="memory_leak",
                        rule="global_container_registration_without_cleanup_path",
                        view=view,
                        line=line,
                        description="A message/action path registers an object into global ownership without a visible cleanup path.",
                        root_cause="Global-container ownership is acquired but no unregister/drop release protocol is paired with it.",
                        suggested_fix="Pair every global add/register action with a reachable remove/release path for the same object.",
                        source="global registration action",
                        sink=line.text.strip(),
                        confidence=0.74,
                        impact_level="high",
                        positive=[f"line {line.number}: global registration action is visible"],
                    )
                )

        if re.search(r"(?:detach|unlink|remove)[A-Za-z_0-9]*without[A-Za-z_0-9]*release", text, re.I):
            line = self._first_line_matching(view, re.compile(r"without.*release|detach", re.I)) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="container_unlink_without_release",
                    view=view,
                    line=line,
                    description="A container detach/unlink operation removes ownership reachability without releasing the detached object.",
                    root_cause="The object is unlinked from the owner container but its allocation and nested resources remain live.",
                    suggested_fix="Release the detached object and nested resources after unlinking, or transfer ownership explicitly.",
                    source=line.text.strip(),
                    sink="container unlink/detach",
                    confidence=0.82,
                    impact_level="high",
                    positive=[f"line {line.number}: detach/unlink path is named or implemented without release"],
                )
            )

        free_line = self._first_line_matching(view, self._free_re)
        if re.search(r"pthread_mutex_init", text) and free_line and not re.search(r"pthread_mutex_destroy", text):
            line = free_line
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="nested_mutex_cleanup_omitted",
                    view=view,
                    line=line,
                    description="A node with an initialized nested mutex is freed without destroying that mutex resource.",
                    root_cause="The node cleanup releases the allocation but omits the embedded synchronization primitive.",
                    suggested_fix="Destroy embedded mutex/condition resources before freeing the owning node.",
                    source="pthread_mutex_init in paired creation path",
                    sink=line.text.strip(),
                    confidence=0.8,
                    impact_level="medium",
                    positive=[
                        "function body references initialized mutex ownership",
                        f"line {line.number}: node allocation is freed",
                        "no pthread_mutex_destroy is visible in the cleanup path",
                    ],
                )
            )

        if re.search(r"proc_head|child|children", text, re.I) and free_line and not re.search(r"\bwhile\b[^{;]*(?:proc|child)|for\s*\([^;]*(?:proc|child)", text, re.I):
            line = free_line
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="child_list_cleanup_omitted",
                    view=view,
                    line=line,
                    description="A parent node is freed while a child/list ownership field is not walked and released.",
                    root_cause="Composite container cleanup releases only the primary node and skips nested owned children.",
                    suggested_fix="Walk and release each child node before freeing the parent object.",
                    source="nested child/list field",
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        "function references a child/list ownership field",
                        f"line {line.number}: parent object is freed",
                        "no child/list cleanup loop is visible",
                    ],
                )
            )

    def _rule_tree_and_liveness_protocols(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        for line in view.lines:
            self_link = re.search(r"\b(?P<obj>[A-Za-z_]\w*)->next\s*=\s*(?P=obj)\s*;", line.text)
            if self_link:
                obj = self_link.group("obj")
                issues.append(
                    self._issue(
                        defect_class="infinite_loop",
                        rule="self_referential_list_link",
                        view=view,
                        line=line,
                        description=f"`{obj}->next` is set to `{obj}`, creating a self-referential list node.",
                        root_cause="Later traversal that follows next pointers can loop forever on the removed/poisoned node.",
                        suggested_fix="Use NULL or a non-traversable poison value and ensure later walkers detect removed nodes.",
                        source=obj,
                        sink=line.text.strip(),
                        confidence=0.84,
                        impact_level="high",
                        positive=[f"line {line.number}: self-link assignment `{line.text.strip()}`"],
                    )
                )

        text = "\n".join(line.text for line in view.lines)
        if re.search(r"LOG_(?:ERROR|WARN|INFO)", text) and re.search(r"=\s*[A-Za-z_]\w*->next", text) and re.search(r"poison|self", text, re.I):
            line = self._first_line_matching(view, re.compile(r"LOG_(?:ERROR|WARN|INFO)")) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="log_amplification",
                    rule="log_inside_poisoned_traversal",
                    view=view,
                    line=line,
                    description="A traversal over poisoned nodes emits logs inside the loop.",
                    root_cause="A liveness failure can amplify into repeated logging and resource exhaustion.",
                    suggested_fix="Break traversal on poison markers and rate-limit or suppress loop-internal error logs.",
                    source="poisoned traversal",
                    sink=line.text.strip(),
                    confidence=0.76,
                    impact_level="medium",
                    positive=[
                        "loop follows next pointers",
                        f"line {line.number}: log call occurs inside traversal",
                        "poison marker appears in the traversal logic",
                    ],
                )
            )

        if re.search(r"\bstrncpy\s*\([^;]*(?:KEY_LIMIT|KEY_MAX|MAX_KEY|LIMIT)", text) and re.search(r"full_key|strcmp", text):
            line = self._first_line_matching(view, re.compile(r"\bstrncpy\s*\(")) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="key_truncation",
                    rule="full_key_lookup_truncated_insert",
                    view=view,
                    line=line,
                    description="The lookup path uses a full key while insertion stores only a bounded/truncated key.",
                    root_cause="Lookup and insertion normalize keys differently, so distinct full keys can collide or evade lookups.",
                    suggested_fix="Use the same canonical key representation for lookup and insertion and reject overlong keys explicitly.",
                    source="full-key lookup",
                    sink=line.text.strip(),
                    confidence=0.76,
                    impact_level="medium",
                    positive=[
                        "function compares or references full keys",
                        f"line {line.number}: bounded copy can truncate the stored key",
                    ],
                )
            )

        node_free_re = re.compile(
            rf"\b(?:{self._names_pattern(self._free_names)})\s*\(\s*node\s*\)",
            re.I,
        )
        if re.search(r"(?:insert|add).*node", text, re.I) and node_free_re.search(text) and not re.search(r"(?:remove|unlink|delete).*node", text, re.I):
            line = self._first_line_matching(view, node_free_re) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="use_after_free",
                    rule="insert_failure_leaves_stale_tree_node",
                    view=view,
                    line=line,
                    description="A node can be inserted into an index/tree before a later failure frees it without removing stale links.",
                    root_cause="Failure cleanup releases the node but does not roll back index/list ownership established earlier.",
                    suggested_fix="Rollback every successful insertion/link before freeing the node on later failure paths.",
                    source="index/tree insertion",
                    sink=line.text.strip(),
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        "function inserts/adds a node into an index-like structure",
                        f"line {line.number}: failure cleanup frees `node`",
                        "no remove/unlink rollback is visible before free",
                    ],
                )
            )

    def _rule_publication_and_lifetime_order(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        allocs = self._local_allocated_variables(view)
        if not allocs:
            return

        for var, alloc_line in allocs.items():
            publish_line: Optional[GraphLine] = None
            unlock_after_publish: Optional[GraphLine] = None
            for line in view.lines:
                if line.index <= alloc_line.index:
                    continue
                if publish_line is None and self._line_publishes_object(line.text, var):
                    publish_line = line
                    continue
                if publish_line is not None and line.index > publish_line.index and self._unlock_call_re.search(line.text):
                    unlock_after_publish = line
                    break
            if publish_line and unlock_after_publish:
                late_init = next(
                    (
                        line
                        for line in view.lines
                        if line.index > unlock_after_publish.index
                        and (
                            (
                                re.search(rf"\b{re.escape(var)}->\w+\s*=", line.text)
                                and not re.search(r"=\s*(?:0|NULL|nullptr)\s*;", line.text)
                            )
                            or re.search(rf"\bpthread_(?:mutex|cond|rwlock)_init\s*\([^;]*\b{re.escape(var)}->", line.text)
                        )
                    ),
                    None,
                )
                if late_init:
                    issues.append(
                        self._issue(
                            defect_class="object_publication",
                            rule="published_before_member_initialization",
                            view=view,
                            line=publish_line,
                            description=(
                                f"`{var}` is linked or published before later member initialization completes."
                            ),
                            root_cause="Concurrent readers can observe a partially initialized object after it is inserted into shared state.",
                            suggested_fix="Initialize all fields and embedded synchronization primitives before publishing the object.",
                            source=f"{view.name}:{alloc_line.number}:{var}",
                            sink=publish_line.text.strip(),
                            confidence=0.84,
                            impact_level="high",
                            positive=[
                                f"line {alloc_line.number}: `{var}` is allocated",
                                f"line {publish_line.number}: `{var}` is published to shared/container state",
                                f"line {unlock_after_publish.number}: publication lock is released",
                                f"line {late_init.number}: member initialization occurs after publication",
                            ],
                            evidence={
                                "path": {
                                    "function": view.name,
                                    "source_line": alloc_line.number,
                                    "publish_line": publish_line.number,
                                    "late_init_line": late_init.number,
                                    "complete_in_function": True,
                                    "path_constraints": ["shared/container readers can observe the object after publication"],
                                }
                            },
                        )
                    )

            unlink_line = next(
                (
                    line
                    for line in view.lines
                    if line.index > alloc_line.index
                    and re.search(rf"\bg_[A-Za-z_0-9.]*\s*=\s*{re.escape(var)}->next\b", line.text)
                ),
                None,
            )
            if not unlink_line:
                continue
            unlock_line = next(
                (
                    line
                    for line in view.lines
                    if line.index > unlink_line.index and self._unlock_call_re.search(line.text)
                ),
                None,
            )
            free_line = next(
                (
                    line
                    for line in view.lines
                    if unlock_line
                    and line.index > unlock_line.index
                    and re.search(rf"\b(?:SAFE_FREE|free|kfree)\s*\(\s*(?:{re.escape(var)}(?:->\w+)?|{re.escape(var)})\s*\)", line.text)
                ),
                None,
            )
            if unlink_line and unlock_line and free_line:
                issues.append(
                    self._issue(
                        defect_class="race",
                        rule="container_unlink_free_after_unlock",
                        view=view,
                        line=unlink_line,
                        description=(
                            f"`{var}` is unlinked under the container lock, then released after the lock is dropped."
                        ),
                        root_cause="Concurrent readers that observed the node before unlink can race with member or node release after unlock.",
                        suggested_fix="Use refcounts/RCU or keep the lifetime lock held until no reader can still dereference the node.",
                        source=unlink_line.text.strip(),
                        sink=free_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"line {unlink_line.number}: global/container link is changed to `{var}->next`",
                            f"line {unlock_line.number}: container lock is released",
                            f"line {free_line.number}: `{var}` or one of its members is freed after unlock",
                        ],
                        evidence={
                            "path": {
                                "function": view.name,
                                "source_line": unlink_line.number,
                                "sink_line": free_line.number,
                                "complete_in_function": True,
                                "path_constraints": ["concurrent readers can retain references across unlink"],
                            }
                        },
                    )
                )

    def _rule_protocol_state_contracts(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)

        mismatch_line = self._first_line_matching(
            view,
            re.compile(r"\b[A-Za-z_]\w*(?:sleep|window|timer|callback|schedule)[A-Za-z_0-9]*\s*\([^;]*(?:busy|work)[A-Za-z_0-9]*", re.I),
        )
        if mismatch_line and re.search(r"\b(?:busy|work)[A-Za-z_0-9]*\s*=", text, re.I):
            issues.append(
                self._issue(
                    defect_class="semantic_mismatch",
                    rule="cross_domain_counter_passed_to_callback_contract",
                    view=view,
                    line=mismatch_line,
                    description="A counter derived from one runtime domain is passed into a callback/scheduler contract from another domain.",
                    root_cause="The call path preserves type compatibility but loses the semantic unit expected by the callee contract.",
                    suggested_fix="Pass the callee's expected domain value explicitly or rename/split the counters so unit mismatches are rejected at the boundary.",
                    source="domain counter",
                    sink=mismatch_line.text.strip(),
                    confidence=0.72,
                    impact_level="medium",
                    positive=[
                        "local code derives a busy/work counter",
                        f"line {mismatch_line.number}: the counter is passed to a sleep/window/timer/callback contract",
                    ],
                    negative=["Validator must confirm the callee expects a different counter domain."],
                )
            )

        endian_line = self._first_line_matching(view, re.compile(r"__builtin_ctz(?:ll)?\s*\("))
        if endian_line and re.search(r"\bmemcpy\s*\(\s*&[A-Za-z_]\w+\s*,\s*[^;]*input\s*\+", text) and not re.search(
            r"\b(?:be(?:16|32|64)toh|ntoh(?:s|l)|bswap|__builtin_bswap)", text
        ):
            issues.append(
                self._issue(
                    defect_class="byte_order_logic",
                    rule="wire_bitmap_ctz_without_endian_normalization",
                    view=view,
                    line=endian_line,
                    description="Wire bytes are copied into host integers and scanned with ctz without endian normalization.",
                    root_cause="The bit index returned by trailing-zero operations is host-order dependent and can point at the wrong wire byte on big-endian data.",
                    suggested_fix="Normalize byte order before bit scans or scan the wire byte array in protocol order.",
                    source="wire bitmap bytes",
                    sink=endian_line.text.strip(),
                    confidence=0.82,
                    impact_level="medium",
                    positive=[
                        "function copies byte-buffer data into integer words",
                        f"line {endian_line.number}: trailing-zero scan is applied to the host integer",
                        "no endian conversion is visible before the scan",
                    ],
                )
            )

        reader_line = self._first_line_matching(
            view,
            re.compile(r"(?:\.|->)?(?:[A-Za-z_]\w*)?reader[A-Za-z_0-9]*\s*="),
        )
        if reader_line and "__atomic_fetch_add" in text and "__atomic_fetch_sub" in text and not re.search(
            r"\b(?:pthread_mutex_lock|LOCK|spin_lock)\s*\(", text
        ):
            issues.append(
                self._issue(
                    defect_class="reader_state_race",
                    rule="single_reader_field_under_shared_reader_count",
                    view=view,
                    line=reader_line,
                    description="A shared reader-owner field is written while a shared reader count allows multiple readers.",
                    root_cause="Atomic count updates protect the count value, but not the side field that stores one reader identity.",
                    suggested_fix="Use per-reader state, protect the identity field with the rwlock writer protocol, or remove the single-owner field.",
                    source="shared reader field",
                    sink=reader_line.text.strip(),
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        "function increments/decrements a reader count atomically",
                        f"line {reader_line.number}: reader identity state is assigned outside a lock",
                    ],
                )
            )

        stack_line = self._first_line_matching(
            view,
            re.compile(r"\bmem(?:cpy|move)\s*\([^;]*\b[A-Za-z_]\w*\.name\s*,\s*[A-Za-z_]\w+\s*,\s*strlen\s*\(", re.I),
        )
        if stack_line and re.search(r"\bsnprintf\s*\([^;]*%s", text):
            issues.append(
                self._issue(
                    defect_class="stack_overflow",
                    rule="composed_string_copied_to_member_buffer_without_bound",
                    view=view,
                    line=stack_line,
                    description="A variable-length composed string is copied into a fixed member buffer using strlen length.",
                    root_cause="The formatting buffer is bounded, but the destination member's smaller fixed size is not used as the copy limit.",
                    suggested_fix="Copy with the destination member size and reject or truncate names before composing the thread label.",
                    source="composed string",
                    sink=stack_line.text.strip(),
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        "function composes a string containing external text",
                        f"line {stack_line.number}: strlen(composed)+1 controls a member-buffer copy",
                    ],
                )
            )

        self._emit_uninitialized_output_candidate(view, issues)

        file_type_line = self._first_line_matching(view, re.compile(r"\bfile_size\s*<\s*map_size\b|\bmap_size\s*>\s*file_size\b"))
        if file_type_line and re.search(r"(?:IS_CHR|S_ISCHR|character device|chr)", text, re.I):
            issues.append(
                self._issue(
                    defect_class="file_type_validation",
                    rule="regular_file_size_check_applied_to_device_mapping",
                    view=view,
                    line=file_type_line,
                    description="Mapping validation applies regular-file size semantics before distinguishing character-device backings.",
                    root_cause="Character-device/shared-memory mappings do not have the same file-size contract as regular files.",
                    suggested_fix="Branch on backing type first and apply type-specific size validation before mapping.",
                    source="mapping size validation",
                    sink=file_type_line.text.strip(),
                    confidence=0.78,
                    impact_level="medium",
                    positive=[
                        f"line {file_type_line.number}: file-size check guards mapping size",
                        "the same function accepts character-device/shared-memory backing modes",
                    ],
                )
            )

        self._emit_index_bound_candidate(view, issues)
        self._emit_cached_group_iteration_candidate(view, issues)
        self._emit_global_mode_candidate(view, issues)
        self._emit_cas_slot_candidate(view, issues)
        self._emit_lost_wakeup_candidate(view, issues)
        self._emit_find_before_insert_lock_candidate(view, issues)
        self._emit_state_transition_candidate(view, issues)
        self._emit_signal_handler_candidate(view, issues)
        self._emit_role_release_candidate(view, issues)
        self._emit_fd_contract_candidate(view, issues)

    def _emit_uninitialized_output_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if "memset" in text:
            return
        for line in view.lines:
            match = re.search(r"\b(?P<type>[A-Z][A-Za-z_0-9]*)\s+(?P<var>[A-Za-z_]\w*)\s*;", line.text)
            if not match:
                continue
            var = match.group("var")
            copy_line = next(
                (
                    item
                    for item in view.lines
                    if item.index > line.index
                    and re.search(rf"\*\s*[A-Za-z_]\w+\s*=\s*{re.escape(var)}\s*;", item.text)
                ),
                None,
            )
            if not copy_line:
                continue
            assigned_fields = {
                m.group(1)
                for item in view.lines
                if line.index < item.index < copy_line.index
                for m in re.finditer(rf"\b{re.escape(var)}\.(\w+)\s*=", item.text)
            }
            if not assigned_fields or len(assigned_fields) >= 6:
                continue
            issues.append(
                self._issue(
                    defect_class="uninitialized_output",
                    rule="partial_stack_struct_copied_to_output",
                    view=view,
                    line=copy_line,
                    description="A stack struct is copied to an output parameter after only a subset of fields are initialized.",
                    root_cause="Uninitialized padding or fields can leak stale stack data or produce nondeterministic API results.",
                    suggested_fix="Zero-initialize the temporary struct before filling fields or assign every field before copying it out.",
                    source=f"{match.group('type')} {var}",
                    sink=copy_line.text.strip(),
                    confidence=0.82,
                    impact_level="medium",
                    positive=[
                        f"line {line.number}: local output struct `{var}` is declared without initialization",
                        f"line {copy_line.number}: `{var}` is copied to an output parameter",
                        f"assigned fields before copy: {', '.join(sorted(assigned_fields))}",
                    ],
                )
            )
            return

    def _emit_index_bound_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        for idx, line in enumerate(view.lines):
            loop = re.search(
                r"\bfor\s*\([^;]*\b(?P<idx>[A-Za-z_]\w*)\s*=\s*[^;]*;\s*(?P=idx)\s*<\s*(?P<limit>[A-Za-z_]\w*)",
                line.text,
            )
            if not loop:
                continue
            idx_name = loop.group("idx")
            limit_name = loop.group("limit")
            window = view.lines[idx + 1 : min(len(view.lines), idx + 8)]
            access_line = next(
                (
                    item
                    for item in window
                    if re.search(rf"->\s*[A-Za-z_]\w*\s*\[\s*{re.escape(idx_name)}\s*\]", item.text)
                    or re.search(rf"\.[A-Za-z_]\w*\s*\[\s*{re.escape(idx_name)}\s*\]", item.text)
                ),
                None,
            )
            if not access_line:
                continue
            guard_text = "\n".join(item.text for item in view.lines[max(0, idx - 5) : idx + 1])
            if "ARRAY_SIZE" in guard_text or re.search(rf"\b{re.escape(limit_name)}\s*<=\s*(?:ARRAY_SIZE|sizeof)", guard_text):
                continue
            issues.append(
                self._issue(
                    defect_class="bounds",
                    rule="caller_limit_indexes_fixed_member_array",
                    view=view,
                    line=access_line,
                    description="A caller-controlled limit indexes a fixed member array without proving it is within the array size.",
                    root_cause="The loop bound is a function argument or protocol limit, while the indexed member has its own fixed capacity.",
                    suggested_fix="Clamp the loop bound to the destination array length before indexing.",
                    source=f"{idx_name} < {limit_name}",
                    sink=access_line.text.strip(),
                    confidence=0.8,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: loop uses `{limit_name}` as the bound",
                        f"line {access_line.number}: member array is indexed by `{idx_name}`",
                        "no nearby ARRAY_SIZE/sizeof guard for the member array is visible",
                    ],
                )
            )
            return

    def _emit_cached_group_iteration_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not ("group_idx" in text and "pt_no_idx" in text and re.search(r"\b[A-Za-z_]\w*grp\b|\barena_grp\b", text)):
            return
        stale_line = self._first_line_matching(view, re.compile(r"\barena_grp\s*=\s*&[A-Za-z_]\w+\[group_idx\]"))
        use_line = self._first_line_matching(view, re.compile(r"\barena_grp->\w+\[pt_no_idx\]"))
        if not stale_line or not use_line:
            return
        issues.append(
            self._issue(
                defect_class="logic_error",
                rule="cached_group_pointer_reused_across_partition_index",
                view=view,
                line=use_line,
                description="A cached group pointer is reused while a per-iteration group index changes.",
                root_cause="Traversal state is refreshed from one index dimension but used with another, so later iterations can read the wrong group.",
                suggested_fix="Recompute the group pointer whenever the group index changes, or derive both group and member from the same canonical index.",
                source=stale_line.text.strip(),
                sink=use_line.text.strip(),
                confidence=0.78,
                impact_level="medium",
                positive=[
                    f"line {stale_line.number}: group pointer is cached from `group_idx`",
                    f"line {use_line.number}: cached pointer is used with `pt_no_idx`",
                ],
            )
        )

    def _emit_global_mode_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        assign_line = self._first_line_matching(view, re.compile(r"\bg_[A-Za-z_0-9]*(?:mode|use|algorithm)[A-Za-z_0-9]*\s*="))
        if not assign_line or self._lock_call_re.search(text):
            return
        branch_line = self._first_line_matching(view, re.compile(r"\bif\s*\([^)]*g_[A-Za-z_0-9]*(?:mode|use|algorithm)[A-Za-z_0-9]*"))
        callback_line = self._first_line_matching(view, re.compile(r"\b[A-Za-z_]\w+\[[^]]+\]\.[A-Za-z_]\w+\s*\("))
        if not (branch_line and callback_line):
            return
        issues.append(
            self._issue(
                defect_class="global_mode_race",
                rule="mutable_global_mode_drives_callback_without_lock",
                view=view,
                line=assign_line,
                description="A mutable global mode selects a callback path without synchronization across registration and use.",
                root_cause="Concurrent callers can change the global mode between callback registration and dispatch.",
                suggested_fix="Protect the mode and callback table with the same lock or pass an immutable mode snapshot through the operation.",
                source=assign_line.text.strip(),
                sink=callback_line.text.strip(),
                confidence=0.82,
                impact_level="high",
                positive=[
                    f"line {assign_line.number}: global mode is updated",
                    f"line {branch_line.number}: global mode controls the branch",
                    f"line {callback_line.number}: callback/function table dispatch follows that mode",
                    "no lock is visible in the function",
                ],
            )
        )

    def _emit_cas_slot_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        cas_line = self._first_line_matching(view, re.compile(r"\(void\)\s*__sync_bool_compare_and_swap|__sync_bool_compare_and_swap"))
        if not cas_line:
            return
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"\(void\)\s*__sync_bool_compare_and_swap", text):
            return
        write_line = next(
            (
                line
                for line in view.lines
                if line.index > cas_line.index and re.search(r"\b[A-Za-z_]\w*->(?:pid|name|state|id|proc)", line.text)
            ),
            None,
        )
        if not write_line:
            return
        issues.append(
            self._issue(
                defect_class="slot_race",
                rule="cas_result_ignored_before_slot_publication",
                view=view,
                line=cas_line,
                description="A compare-and-swap claim result is ignored before writing into the shared slot.",
                root_cause="If another caller wins the CAS, subsequent field writes can corrupt a slot owned by that caller.",
                suggested_fix="Check the CAS result and retry or fail before writing any slot fields.",
                source=cas_line.text.strip(),
                sink=write_line.text.strip(),
                confidence=0.86,
                impact_level="high",
                positive=[
                    f"line {cas_line.number}: CAS result is explicitly discarded",
                    f"line {write_line.number}: slot fields are written after the unchecked CAS",
                ],
            )
        )

    def _emit_lost_wakeup_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"\b[A-Za-z_]\w*Event\s+[A-Za-z_]\w+\s*;", text):
            return
        enqueue_line = self._first_line_matching(view, re.compile(r"\bg_[A-Za-z_0-9.]*list\s*=\s*&[A-Za-z_]\w+"))
        if not enqueue_line:
            return
        if re.search(r"\b(?:pthread_cond_signal|pthread_cond_broadcast|eventfd_write|notify|trigger|wakeup)\s*\(", text, re.I):
            return
        issues.append(
            self._issue(
                defect_class="lost_wakeup",
                rule="queued_local_event_without_scheduler_wakeup",
                view=view,
                line=enqueue_line,
                description="A local event is queued into shared scheduling state without a wakeup/trigger operation.",
                root_cause="The producer publishes work but does not notify the consumer path that new work is available.",
                suggested_fix="Trigger the local scheduler or signal the condition/eventfd after queueing the event.",
                source="local event enqueue",
                sink=enqueue_line.text.strip(),
                confidence=0.82,
                impact_level="high",
                positive=[
                    "function creates a local event object",
                    f"line {enqueue_line.number}: local event address is linked into shared event state",
                    "no scheduler trigger or wakeup call is visible",
                ],
            )
        )

    def _emit_find_before_insert_lock_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        find_line = self._first_line_matching(view, re.compile(r"\bif\s*\([^)]*(?:find|lookup)[A-Za-z_0-9]*\([^)]*\)\s*!=\s*NULL", re.I))
        if not find_line:
            return
        lock_line = next((line for line in view.lines if line.index > find_line.index and self._lock_arg(line.text)), None)
        insert_line = next(
            (
                line
                for line in view.lines
                if lock_line
                and line.index > lock_line.index
                and re.search(r"\bg_[A-Za-z_0-9.]*\s*=\s*[A-Za-z_]\w+", line.text)
            ),
            None,
        )
        if not insert_line:
            return
        issues.append(
            self._issue(
                defect_class="shared_memory_race",
                rule="lookup_before_insert_lock",
                view=view,
                line=find_line,
                description="A duplicate/existence lookup is performed before taking the lock that protects insertion.",
                root_cause="Two creators can both observe absence and then insert duplicate shared resources.",
                suggested_fix="Hold the insertion lock across lookup and insert, or use an atomic create-if-absent primitive.",
                source=find_line.text.strip(),
                sink=insert_line.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {find_line.number}: existence lookup occurs before lock acquisition",
                    f"line {insert_line.number}: shared/global list is updated after the lock is acquired",
                ],
            )
        )

    def _emit_state_transition_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        state_lines = [line for line in view.lines if re.search(r"->\s*(?:proc_)?state\s*=", line.text)]
        if len(state_lines) != 1:
            return
        state_line = state_lines[0]
        later_write = next(
            (
                line
                for line in view.lines
                if line.index > state_line.index and re.search(r"->\s*(?:pid|name|id)\s*=", line.text)
            ),
            None,
        )
        if not later_write:
            return
        issues.append(
            self._issue(
                defect_class="state_machine",
                rule="partial_state_machine_publication",
                view=view,
                line=state_line,
                description="One state-machine branch publishes a state transition while another publishes related identity fields without the state transition.",
                root_cause="Consumers can observe initialized identity data while the shared state still advertises an old lifecycle state.",
                suggested_fix="Update the lifecycle state consistently for every successful publication branch.",
                source=state_line.text.strip(),
                sink=later_write.text.strip(),
                confidence=0.76,
                impact_level="medium",
                positive=[
                    f"line {state_line.number}: a lifecycle state is assigned in one branch",
                    f"line {later_write.number}: related identity fields are written later without another state assignment",
                ],
                negative=["Validator must confirm the later branch represents a successful publication path."],
            )
        )

    def _emit_signal_handler_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"\b(?:sig|signal|exception)\b", view.name + "\n" + text, re.I):
            return
        lock_line = self._first_line_matching(view, re.compile(r"\b(?:pthread_mutex_trylock|LOCK)\s*\([^;]*(?:sem|signal|exception)", re.I))
        log_line = self._first_line_matching(view, re.compile(r"\b(?:snprintf|LOG_ERROR|printf)\s*\("))
        if not (lock_line and log_line):
            return
        issues.append(
            self._issue(
                defect_class="signal_deadlock",
                rule="signal_path_uses_locking_and_formatting",
                view=view,
                line=lock_line,
                description="A signal/exception path performs locking and formatting/logging work.",
                root_cause="Signal handlers can interrupt code that owns the same lock or uses non-async-signal-safe routines.",
                suggested_fix="Record only async-signal-safe data in the handler and defer formatting/logging to a normal thread.",
                source=lock_line.text.strip(),
                sink=log_line.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {lock_line.number}: signal path takes or probes a lock",
                    f"line {log_line.number}: signal path formats or logs data",
                ],
            )
        )

    def _emit_role_release_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        role_assign = self._first_line_matching(view, re.compile(r"->\s*role\s*=\s*(?P<role>[A-Za-z_]\w*)\s*;"))
        release_line = self._first_line_matching(view, re.compile(r"\b[A-Za-z_]\w*(?:release|cleanup|destroy)[A-Za-z_0-9]*\s*\([^;]*,\s*0\s*\)", re.I))
        if not (role_assign and release_line):
            return
        role_match = re.search(r"->\s*role\s*=\s*(?P<role>[A-Za-z_]\w*)\s*;", role_assign.text)
        role_name = role_match.group("role") if role_match else "role"
        if role_name not in text:
            return
        issues.append(
            self._issue(
                defect_class="memory_leak",
                rule="role_specific_release_uses_hardcoded_role",
                view=view,
                line=release_line,
                description="A role-specific release helper is called with a hardcoded role instead of the object's stored role.",
                root_cause="Cleanup only releases resources for one role and can leak role-specific members owned by other roles.",
                suggested_fix="Pass the stored role/member role to the release helper or dispatch cleanup by the object's actual role.",
                source=role_assign.text.strip(),
                sink=release_line.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {role_assign.number}: object role is set from `{role_name}`",
                    f"line {release_line.number}: role-specific release is called with literal `0`",
                ],
            )
        )

    def _emit_fd_contract_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        signature = view.signature or ""
        if not re.search(r"\b(?:reliable|encoded)[A-Za-z_0-9]*fd\b", signature, re.I):
            return
        line = self._first_line_matching(
            view,
            re.compile(r"\b[A-Za-z_]\w*(?:inter|raw|lower)[A-Za-z_0-9]*fd[A-Za-z_0-9]*\s*\([^;]*(?:reliable|encoded)[A-Za-z_0-9]*fd", re.I),
        )
        if not line:
            return
        issues.append(
            self._issue(
                defect_class="fd_type_mismatch",
                rule="encoded_or_reliable_fd_passed_to_raw_fd_contract",
                view=view,
                line=line,
                description="An encoded/reliable descriptor is passed to a lower-level API that expects a raw descriptor.",
                root_cause="The descriptor representation contract is lost because both representations are integer-like values.",
                suggested_fix="Decode/strip check bits before calling raw-fd helpers, or change the callee to accept the encoded descriptor type.",
                source=signature,
                sink=line.text.strip(),
                confidence=0.86,
                impact_level="medium",
                positive=[
                    "function signature exposes an encoded/reliable descriptor parameter",
                    f"line {line.number}: descriptor is passed to an inter/raw-fd helper",
                ],
            )
        )

    @staticmethod
    def _local_allocated_variables(view: FunctionView) -> Dict[str, GraphLine]:
        allocs: Dict[str, GraphLine] = {}
        for line in view.lines:
            match = re.search(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?:_safe_calloc|_safe_malloc|calloc|malloc|kzalloc|kmalloc|[A-Za-z_]\w*(?:alloc|create|new)[A-Za-z_0-9]*)\s*\(",
                line.text,
                re.I,
            )
            if match:
                allocs.setdefault(match.group("var"), line)
        return allocs

    @staticmethod
    def _line_publishes_object(text: str, var: str) -> bool:
        escaped = re.escape(var)
        return bool(
            re.search(rf"\b[A-Za-z_]\w*(?:insert|link|publish|register|add)[A-Za-z_0-9]*\s*\([^;]*\b{escaped}\b", text, re.I)
            or re.search(rf"\bg_[A-Za-z_0-9.]*\s*=\s*{escaped}\b", text)
        )

    def _rule_paired_member_cleanup_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        for view in views:
            self._rule_same_function_helper_alloc_member_cleanup_gap(view, issues)

        member_allocs: List[Dict[str, Any]] = []
        for view in views:
            if not re.search(r"(?:alloc|create|init|new|register|add)", view.name, re.I):
                continue
            for line in view.lines:
                match = re.search(
                    r"\b(?P<obj>[A-Za-z_]\w*)->(?P<field>[A-Za-z_]\w*)\s*=\s*"
                    r"(?:\([^)]*\)\s*)?"
                    r"(?P<api>[A-Za-z_]\w*(?:alloc|calloc|malloc|dup|new|create)[A-Za-z_0-9]*)\s*\(",
                    line.text,
                    re.I,
                )
                if not match:
                    continue
                field = match.group("field")
                if not re.search(r"(?:payload|data|buf|buffer|key|name|str|child|children|list)", field, re.I):
                    continue
                member_allocs.append(
                    {
                        "view": view,
                        "line": line,
                        "object": match.group("obj"),
                        "field": field,
                        "api": match.group("api"),
                    }
                )
        if not member_allocs:
            return

        for view in views:
            if not re.search(r"(?:free|release|destroy|cleanup|delete|deinit)", view.name, re.I):
                continue
            text = "\n".join(line.text for line in view.lines)
            free_line = self._first_line_matching(view, self._free_re)
            if not free_line:
                continue
            free_arg = ""
            free_match = self._free_re.search(free_line.text)
            if free_match:
                free_arg = self._resource_arg(free_match.group("arg")) or free_match.group("arg").strip()
            if not free_arg:
                continue
            for alloc in member_allocs:
                field = str(alloc["field"])
                creator = alloc["view"]
                if creator.name == view.name:
                    continue
                if not self._cleanup_pair_matches(creator, view, field, text):
                    continue
                if self._member_release_visible(text, free_arg, field):
                    continue
                alloc_line = alloc["line"]
                issues.append(
                    self._issue(
                        defect_class="memory_leak",
                        rule="paired_free_wrapper_omits_dynamic_member",
                        view=view,
                        line=free_line,
                        description=(
                            f"`{view.name}` releases `{free_arg}` but omits dynamically owned "
                            f"member `{field}` allocated by `{creator.name}`."
                        ),
                        root_cause=(
                            "The free wrapper releases the enclosing object without releasing an "
                            "owned dynamic payload initialized by the paired constructor."
                        ),
                        suggested_fix=f"Release `{free_arg}->{field}` before releasing `{free_arg}`, or call the member's cleanup helper.",
                        source=f"{creator.name}:{alloc_line.number}:{alloc_line.text.strip()}",
                        sink=free_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"{creator.name} line {alloc_line.number}: `{field}` receives dynamic storage via `{alloc['api']}`",
                            f"{view.name} line {free_line.number}: wrapper releases `{free_arg}`",
                            f"`{view.name}` has no visible release of `{free_arg}->{field}`",
                        ],
                        negative=["Validator must confirm the member is not intentionally transferred before wrapper cleanup."],
                        evidence={
                            "path": {
                                "allocator_function": creator.name,
                                "cleanup_function": view.name,
                                "source_line": alloc_line.number,
                                "sink_line": free_line.number,
                                "complete_in_function": False,
                                "path_constraints": ["paired constructor/free-wrapper ownership contract"],
                            }
                        },
                    )
                )
                break

    def _rule_same_function_helper_alloc_member_cleanup_gap(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"(?:unregister|remove|delete|release|free|cleanup|destroy)", view.name, re.I):
            return
        alloc_match = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*"
            r"(?P<api>[A-Za-z_]\w*(?:alloc|create|new)[A-Za-z_0-9]*(?:node|file|entry)[A-Za-z_0-9]*)\s*\(",
            text,
            re.I,
        )
        if not alloc_match:
            return
        alloc_context = alloc_match.group(0)
        alloc_line_for_context = self._first_line_matching(
            view,
            re.compile(rf"\b{re.escape(alloc_match.group('var'))}\s*=\s*{re.escape(alloc_match.group('api'))}\s*\(", re.I),
        )
        if alloc_line_for_context:
            alloc_context = alloc_line_for_context.text
        if not re.search(r"(?:file|path|fs|unlink|unregister)", f"{view.name} {alloc_context}", re.I):
            return
        var_name = alloc_match.group("var")
        if not re.search(rf"\b(?:SAFE_FREE|free)\s*\(\s*{re.escape(var_name)}\s*\)", text):
            return
        released_members = {
            match.group(1).lower()
            for match in re.finditer(
                rf"\b(?:SAFE_FREE|free)\s*\(\s*{re.escape(var_name)}\s*->\s*([A-Za-z_]\w*)\s*\)",
                text,
                re.I,
            )
        }
        if not released_members:
            return
        likely_owned_members = ("payload", "path", "data", "buffer")
        missing_member = next((member for member in likely_owned_members if member not in released_members), "")
        if not missing_member:
            return
        free_line = self._first_line_matching(
            view,
            re.compile(rf"\b(?:SAFE_FREE|free)\s*\(\s*{re.escape(var_name)}\s*\)", re.I),
        )
        alloc_line = self._first_line_matching(
            view,
            re.compile(rf"\b{re.escape(var_name)}\s*=\s*{re.escape(alloc_match.group('api'))}\s*\(", re.I),
        )
        if not free_line:
            return
        issues.append(
            self._issue(
                defect_class="memory_leak",
                rule="same_function_helper_alloc_wrapper_member_leak",
                view=view,
                line=free_line,
                description=(
                    f"`{view.name}` unregisters a file node wrapper allocated by `{alloc_match.group('api')}` "
                    f"and frees `{var_name}`, but omits the owned `{missing_member}` payload/path member, "
                    "causing a payload leak."
                ),
                root_cause=(
                    "The unregister cleanup frees the wrapper node while a dynamically allocated "
                    "file-node payload/path member remains owned by that wrapper and leaks."
                ),
                suggested_fix=f"Release `{var_name}->{missing_member}` before freeing `{var_name}` or delegate to the full node destructor.",
                source=alloc_line.text.strip() if alloc_line else alloc_match.group(0),
                sink=free_line.text.strip(),
                confidence=0.83,
                impact_level="high",
                positive=[
                    f"line {alloc_line.number if alloc_line else free_line.number}: wrapper node is allocated via `{alloc_match.group('api')}`",
                    f"cleanup releases member(s) {sorted(released_members)} and then frees `{var_name}`",
                    f"no release of likely owned `{var_name}->{missing_member}` payload/path is visible",
                ],
                negative=["Validator must confirm the allocation helper does not transfer or omit this member by contract."],
                evidence={
                    "path": {
                        "allocation_function": alloc_match.group("api"),
                        "cleanup_function": view.name,
                        "source_line": alloc_line.number if alloc_line else free_line.number,
                        "sink_line": free_line.number,
                        "complete_in_function": True,
                        "path_constraints": ["same-function helper allocation cleanup contract"],
                    }
                },
            )
        )

    def _rule_paired_key_normalization_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        lookup_views = [
            view
            for view in views
            if re.search(r"(?:lookup|find|get|search)", view.name, re.I)
            and re.search(r"\b(?:strcmp|strncmp|memcmp)\s*\(", "\n".join(line.text for line in view.lines))
            and re.search(r"(?:full[_-]?key|\bkey\b)", "\n".join(line.text for line in view.lines), re.I)
        ]
        if not lookup_views:
            return
        for view in views:
            if not re.search(r"(?:insert|add|register|create|store|set)", view.name, re.I):
                continue
            for line in view.lines:
                bounded_copy = re.search(
                    r"\b(?P<api>strncpy|strlcpy|snprintf|memcpy)\s*\([^;]*"
                    r"(?P<limit>[A-Z][A-Z0-9_]*(?:KEY|KEYS)[A-Z0-9_]*(?:LIMIT|MAX|LEN|SIZE)|"
                    r"[A-Z][A-Z0-9_]*(?:LIMIT|MAX|LEN|SIZE)[A-Z0-9_]*KEY[A-Z0-9_]*)",
                    line.text,
                )
                if not bounded_copy:
                    continue
                if not re.search(r"\bkey\b|->key|\.key", line.text, re.I):
                    continue
                lookup = lookup_views[0]
                if lookup.file_path != view.file_path and not self._views_share_protocol_terms(lookup, view):
                    continue
                lookup_line = self._first_line_matching(lookup, re.compile(r"\b(?:strcmp|strncmp|memcmp)\s*\(")) or lookup.lines[0]
                issues.append(
                    self._issue(
                        defect_class="key_truncation",
                        rule="paired_full_key_lookup_truncated_insert",
                        view=view,
                        line=line,
                        description="A full-key lookup path is paired with an insertion path that stores a bounded/truncated key.",
                        root_cause="Lookup and insertion use different key canonicalization, allowing overlong keys to collide or evade lookup.",
                        suggested_fix="Canonicalize keys once, reject overlong keys, and use the same stored representation for lookup and insert.",
                        source=f"{lookup.name}:{lookup_line.number}:{lookup_line.text.strip()}",
                        sink=line.text.strip(),
                        confidence=0.84,
                        impact_level="high",
                        positive=[
                            f"{lookup.name} line {lookup_line.number}: lookup compares the full key",
                            f"{view.name} line {line.number}: `{bounded_copy.group('api')}` stores a key using `{bounded_copy.group('limit')}`",
                        ],
                        negative=["Validator must confirm the bounded copy truncates rather than rejecting overlong input."],
                        evidence={
                            "path": {
                                "lookup_function": lookup.name,
                                "insert_function": view.name,
                                "source_line": lookup_line.number,
                                "sink_line": line.number,
                                "complete_in_function": False,
                                "path_constraints": ["paired lookup/insert key normalization contract"],
                            }
                        },
                    )
                )
                break

    def _rule_paired_self_link_log_traversal(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        self_links: List[Tuple[FunctionView, GraphLine, str, str]] = []
        for view in views:
            for line in view.lines:
                match = re.search(r"\b(?P<obj>[A-Za-z_]\w*)->(?P<field>next)\s*=\s*(?P=obj)\s*;", line.text)
                if match:
                    self_links.append((view, line, match.group("obj"), match.group("field")))
        if not self_links:
            return

        for view in views:
            text = "\n".join(line.text for line in view.lines)
            if not re.search(r"\b(?:while|for)\s*\(", text):
                continue
            if not re.search(r"\bLOG_(?:ERROR|WARN|INFO|DEBUG)\s*\(", text):
                continue
            if not re.search(r"=\s*[A-Za-z_]\w*->next\b", text):
                continue
            log_line = self._first_line_matching(view, re.compile(r"\bLOG_(?:ERROR|WARN|INFO|DEBUG)\s*\("))
            if not log_line:
                continue
            for link_view, link_line, obj, field in self_links:
                if link_view.name == view.name:
                    continue
                stem_terms = set(self._identifier_terms(link_view.name)) | set(self._identifier_terms(view.name)) | set(
                    self._identifier_terms(text)
                )
                if obj.lower() not in stem_terms and "pipe" not in stem_terms and not re.search(r"\bpipe\b", text, re.I):
                    continue
                issues.append(
                    self._issue(
                        defect_class="log_amplification",
                        rule="paired_self_referential_traversal_log_amplification",
                        view=view,
                        line=log_line,
                        description="A traversal that logs inside the loop can revisit a self-referential node produced by a sibling path.",
                        root_cause="Self-linking a node keeps traversal progress on the same element, and loop-internal logging amplifies the liveness failure.",
                        suggested_fix="Use a non-traversable poison marker or NULL, break on poisoned/self-linked nodes, and rate-limit loop logs.",
                        source=f"{link_view.name}:{link_line.number}:{link_line.text.strip()}",
                        sink=log_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"{link_view.name} line {link_line.number}: `{obj}->{field}` is assigned to itself",
                            f"{view.name}: traversal follows `next` pointers",
                            f"{view.name} line {log_line.number}: traversal emits a log inside the loop",
                        ],
                        negative=["Validator must confirm the traversal can reach nodes handled by the self-linking path."],
                        evidence={
                            "path": {
                                "self_link_function": link_view.name,
                                "traversal_function": view.name,
                                "source_line": link_line.number,
                                "sink_line": log_line.number,
                                "complete_in_function": False,
                                "path_constraints": ["sibling lifecycle/traversal relationship"],
                            }
                        },
                    )
                )
                break

    def _rule_paired_lifecycle_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        texts = {view.name: "\n".join(line.text for line in view.lines) for view in views}
        creation_views = [
            view
            for view in views
            if re.search(r"(?:register|add|attach|init|create)", view.name, re.I)
        ]
        for view in views:
            if not re.search(r"(?:unregister|delete|remove|cleanup|destroy)", view.name, re.I):
                continue
            text = texts[view.name]
            free_line = self._first_line_matching(view, self._free_re)
            if not free_line:
                continue

            if not re.search(r"pthread_mutex_destroy", text):
                paired_init = next(
                    (
                        creator
                        for creator in creation_views
                        if creator.name != view.name
                        and "pthread_mutex_init" in texts[creator.name]
                        and self._views_share_protocol_terms(view, creator)
                    ),
                    None,
                )
                if paired_init:
                    issues.append(
                        self._issue(
                            defect_class="memory_leak",
                            rule="paired_nested_mutex_cleanup_omitted",
                            view=view,
                            line=free_line,
                            description=(
                                f"`{view.name}` frees a protocol object while paired creator "
                                f"`{paired_init.name}` initializes an embedded mutex."
                            ),
                            root_cause="The destroy/unregister path releases the allocation but omits nested synchronization cleanup established by the paired create/register path.",
                            suggested_fix="Destroy embedded mutex/condition resources before freeing the registered object.",
                            source=f"{paired_init.name}:pthread_mutex_init",
                            sink=free_line.text.strip(),
                            confidence=0.82,
                            impact_level="medium",
                            positive=[
                                f"{paired_init.name}: paired creation path initializes a mutex",
                                f"line {free_line.number}: cleanup frees the object",
                                "no pthread_mutex_destroy is visible in the cleanup function",
                            ],
                        )
                    )

            child_owner = next(
                (
                    creator
                    for creator in creation_views
                    if creator.name != view.name
                    and re.search(r"->\s*(?:proc_head|child|children|next_child)", texts[creator.name], re.I)
                    and self._views_share_protocol_terms(view, creator)
                ),
                None,
            )
            if child_owner and not re.search(r"\bwhile\b[^{;]*(?:proc|child)|for\s*\([^;]*(?:proc|child)", text, re.I):
                issues.append(
                    self._issue(
                        defect_class="memory_leak",
                        rule="paired_child_list_cleanup_omitted",
                        view=view,
                        line=free_line,
                        description=(
                            f"`{view.name}` frees a parent object while paired mutator "
                            f"`{child_owner.name}` attaches child/list nodes."
                        ),
                        root_cause="The delete/remove path drops the parent allocation without walking nested owned children.",
                        suggested_fix="Walk and release each child/list node before freeing the parent object.",
                        source=f"{child_owner.name}:child attachment",
                        sink=free_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"{child_owner.name}: paired path attaches child/list nodes",
                            f"line {free_line.number}: cleanup frees the parent object",
                            "no child/list cleanup loop is visible in the delete path",
                        ],
                    )
                )

    @staticmethod
    def _cleanup_pair_matches(creator: FunctionView, cleanup: FunctionView, field: str, cleanup_text: str) -> bool:
        creator_terms = set(GraphCandidateGenerator._identifier_terms(creator.name))
        cleanup_terms = set(GraphCandidateGenerator._identifier_terms(cleanup.name))
        shared_terms = creator_terms & cleanup_terms - {
            "alloc",
            "create",
            "init",
            "new",
            "register",
            "add",
            "free",
            "release",
            "destroy",
            "cleanup",
            "delete",
            "deinit",
            "real",
            "model",
            "lifecycle",
            "issue",
            "range",
        }
        if shared_terms:
            return True
        if field.lower() in cleanup_text.lower():
            return True
        creator_type = GraphCandidateGenerator._first_param_type(creator.signature)
        cleanup_type = GraphCandidateGenerator._first_param_type(cleanup.signature)
        if GraphCandidateGenerator._is_primitive_pointer_type(creator_type) or GraphCandidateGenerator._is_primitive_pointer_type(cleanup_type):
            return False
        return bool(creator_type and cleanup_type and creator_type == cleanup_type)

    @staticmethod
    def _is_primitive_pointer_type(type_name: str) -> bool:
        normalized = re.sub(r"\s+", " ", str(type_name or "").replace("const", "").strip())
        return normalized in {"char*", "unsigned char*", "void*", "int*", "size_t*", "uint8_t*"}

    @staticmethod
    def _member_release_visible(text: str, owner: str, field: str) -> bool:
        owner_re = re.escape(owner)
        field_re = re.escape(field)
        direct_member = rf"\b{owner_re}\s*->\s*{field_re}\b"
        if re.search(rf"\b(?:free|SAFE_FREE|destroy|release|cleanup|delete)[A-Za-z_0-9]*\s*\([^;]*{direct_member}", text, re.I):
            return True
        if re.search(rf"\b(?:free|SAFE_FREE|destroy|release|cleanup|delete)[A-Za-z_0-9]*\s*\([^;]*\b{field_re}\b", text, re.I):
            return True
        return False

    @staticmethod
    def _resource_arg(value: str) -> str:
        text = str(value or "").strip()
        text = re.sub(r"^[(&*\s]+", "", text)
        text = re.sub(r"[)\]\s]+$", "", text)
        match = re.match(r"([A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*|\s*\.\s*[A-Za-z_]\w*)?)", text)
        return re.sub(r"\s+", "", match.group(1)) if match else ""

    def _rule_paired_global_registration_cleanup(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        texts = {view.name: "\n".join(line.text for line in view.lines) for view in views}
        cleanup_views = [
            view
            for view in views
            if re.search(r"(?:cleanup|disconnect|close|destroy|release)", view.name, re.I)
        ]
        for view in views:
            text = texts[view.name]
            has_global_add = re.search(
                r"\b(?:OPEN|ADD)\b|_control_session_add_to_global|(?:add|insert|register).*global|global.*(?:add|insert|register)",
                text,
                re.I,
            )
            if not has_global_add or not re.search(r"_control_session_add_to_global|global", text, re.I):
                continue
            line = (
                self._first_line_matching(view, re.compile(r"_control_session_add_to_global", re.I))
                or self._first_line_matching(view, re.compile(r"\b(?:OPEN|ADD)\b", re.I))
                or view.lines[0]
            )
            paired_cleanup = next(
                (
                    cleanup
                    for cleanup in cleanup_views
                    if cleanup.name != view.name
                    and self._views_share_protocol_terms(view, cleanup)
                    and not re.search(r"(?:_control_session_(?:remove|release|free|drop)|remove|drop|release|free|destroy)", texts[cleanup.name], re.I)
                ),
                None,
            )
            if not paired_cleanup:
                continue
            cleanup_line = (
                self._first_line_matching(paired_cleanup, re.compile(r"LOG_|return", re.I))
                or paired_cleanup.lines[0]
            )
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="paired_global_registration_cleanup_omitted",
                    view=view,
                    line=line,
                    description=(
                        f"`{view.name}` registers a session/object into global ownership, while paired "
                        f"cleanup `{paired_cleanup.name}` returns without removing or releasing that object."
                    ),
                    root_cause="The protocol OPEN/add path transfers ownership to a global container, but the protocol cleanup endpoint does not unregister or release the registered object.",
                    suggested_fix="Pair the OPEN/add path with a cleanup path that removes the exact key/object from the global container and releases its allocation.",
                    source=f"{view.name}:{line.number}:global registration",
                    sink=f"{paired_cleanup.name}:{cleanup_line.number}:missing remove/release",
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        f"{view.name} line {line.number}: global registration path `{line.text.strip()}`",
                        f"{paired_cleanup.name} line {cleanup_line.number}: cleanup path `{cleanup_line.text.strip()}`",
                        "paired cleanup contains no remove/drop/release/free operation for the global session/object",
                    ],
                    evidence={
                        "path": {
                            "function": view.name,
                            "cleanup_function": paired_cleanup.name,
                            "source_line": line.number,
                            "sink_line": cleanup_line.number,
                            "complete_in_function": False,
                            "path_constraints": ["OPEN/add succeeds", "cleanup is later invoked for the same protocol"],
                        },
                        "lifecycle_pair": {
                            "registration_function": view.name,
                            "cleanup_function": paired_cleanup.name,
                        },
                    },
                )
            )

    def _rule_timer_cascade_wait(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        edges = self._lock_order_edges(views)
        for view in views:
            if not re.search(r"(?:timer|callback|tick)", view.name, re.I):
                continue
            for line in view.lines:
                callback_lock = self._lock_arg(line.text)
                if not callback_lock:
                    continue
                blocking_edge = next(
                    (
                        edge
                        for edge in edges
                        if self._locks_may_match(edge.first_lock, callback_lock)
                        and not edge.function == view.name
                    ),
                    None,
                )
                if not blocking_edge:
                    continue
                scheduler_edge = next(
                    (
                        edge
                        for edge in edges
                        if self._locks_may_match(edge.first_lock, blocking_edge.second_lock)
                        and self._locks_may_match(edge.second_lock, callback_lock)
                        and edge.function != blocking_edge.function
                    ),
                    None,
                )
                description = (
                    f"`{view.name}` can wait on `{callback_lock}` while `{blocking_edge.function}` "
                    f"holds it before waiting on `{blocking_edge.second_lock}`."
                )
                positive = [
                    f"line {line.number}: timer/callback takes `{callback_lock}`",
                    f"{blocking_edge.function} line {blocking_edge.first_line}: another path already holds `{blocking_edge.first_lock}`",
                    f"{blocking_edge.function} line {blocking_edge.second_line}: that path then waits on `{blocking_edge.second_lock}`",
                ]
                evidence: Dict[str, Any] = {
                    "path": {
                        "function": view.name,
                        "source_line": line.number,
                        "sink_line": blocking_edge.second_line,
                        "complete_in_function": False,
                        "path_constraints": ["callback/timer path can run concurrently with close/remove path"],
                    },
                    "cascade_wait": {
                        "callback": {
                            "function": view.name,
                            "line": line.number,
                            "waits_for": callback_lock,
                        },
                        "holder": {
                            "function": blocking_edge.function,
                            "holds": blocking_edge.first_lock,
                            "holds_line": blocking_edge.first_line,
                            "waits_for": blocking_edge.second_lock,
                            "waits_line": blocking_edge.second_line,
                        },
                    },
                }
                confidence = 0.78
                impact_level = "medium"
                sink = f"{blocking_edge.function}:{blocking_edge.first_line}->{blocking_edge.second_line}"
                if scheduler_edge:
                    description = (
                        f"`{view.name}` can wait on `{callback_lock}` while `{blocking_edge.function}` "
                        f"holds it and waits on `{blocking_edge.second_lock}`; `{scheduler_edge.function}` "
                        f"can hold `{scheduler_edge.first_lock}` while waiting on `{scheduler_edge.second_lock}`, "
                        "forming a multi-party callback/close lock cascade."
                    )
                    positive.append(
                        f"{scheduler_edge.function} lines {scheduler_edge.first_line}-{scheduler_edge.second_line}: holds `{scheduler_edge.first_lock}` before waiting on `{scheduler_edge.second_lock}`"
                    )
                    evidence["cascade_wait"]["scheduler_holder"] = {
                        "function": scheduler_edge.function,
                        "holds": scheduler_edge.first_lock,
                        "holds_line": scheduler_edge.first_line,
                        "waits_for": scheduler_edge.second_lock,
                        "waits_line": scheduler_edge.second_line,
                    }
                    evidence["path"]["path_constraints"].append(
                        "scheduler/dispatch path can concurrently hold the scheduler lock"
                    )
                    confidence = 0.82
                    impact_level = "high"
                    sink = (
                        f"{blocking_edge.function}:{blocking_edge.first_line}->{blocking_edge.second_line};"
                        f"{scheduler_edge.function}:{scheduler_edge.first_line}->{scheduler_edge.second_line}"
                    )
                issues.append(
                    self._issue(
                        defect_class="deadlock",
                        rule="timer_callback_cascade_wait",
                        view=view,
                        line=line,
                        description=description,
                        root_cause="Timer/callback code participates in a cascade wait through a lock held by a close/remove path.",
                        suggested_fix="Avoid blocking timer/callback paths on control locks used by close/remove, or reorder the close path to follow the scheduler/control lock protocol.",
                        source=f"{view.name}:{line.number}:{callback_lock}",
                        sink=sink,
                        confidence=confidence,
                        impact_level=impact_level,
                        positive=positive,
                        evidence=evidence,
                    )
                )
                break

    def _rule_callback_self_destroy_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        free_callbacks: Dict[str, GraphLine] = {}
        for view in views:
            arg_aliases = {"arg"}
            for line in view.lines:
                alias = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?arg\b", line.text)
                if alias:
                    arg_aliases.add(alias.group("var"))
            free_line = next(
                (
                    line
                    for line in view.lines
                    if any(
                        re.search(rf"\b(?:SAFE_FREE|free|kfree)\s*\(\s*{re.escape(alias)}\s*\)", line.text)
                        for alias in arg_aliases
                    )
                ),
                None,
            )
            if free_line:
                free_callbacks[view.name] = free_line

        for view in views:
            text = "\n".join(line.text for line in view.lines)
            self_arg = re.search(r"\b(?P<obj>[A-Za-z_]\w*)->callback_arg\s*=\s*(?P=obj)\s*;", text)
            cb_assign = re.search(r"\b(?P<obj>[A-Za-z_]\w*)->callback\s*=\s*(?P<rhs>[^;]+)", text)
            if not (self_arg and cb_assign and self_arg.group("obj") == cb_assign.group("obj")):
                continue
            callback_name = ""
            free_line = None
            for candidate_name in self._callback_assignment_targets(cb_assign.group("rhs")):
                candidate_free = free_callbacks.get(candidate_name)
                if not candidate_free:
                    callback_view = next((item for item in views if item.name == candidate_name), None) or self._view_for(candidate_name)
                    if callback_view:
                        candidate_free = self._callback_free_line(callback_view)
                if candidate_free:
                    callback_name = candidate_name
                    free_line = candidate_free
                    break
            if not free_line:
                continue
            obj = self_arg.group("obj")
            call_line = self._first_line_matching(
                view,
                re.compile(rf"\b{re.escape(obj)}->callback\s*\(\s*{re.escape(obj)}->callback_arg"),
            )
            if not call_line:
                continue
            post_use = next(
                (
                    line
                    for line in view.lines
                    if line.index > call_line.index and re.search(rf"\b{re.escape(obj)}->", line.text)
                ),
                None,
            )
            if not post_use:
                continue
            issues.append(
                self._issue(
                    defect_class="callback_self_destroy_race",
                    rule="callback_can_free_current_event_before_reacquire",
                    view=view,
                    line=call_line,
                    description="A callback receives the current object as its context and can free it before the caller resumes using it.",
                    root_cause="The callback contract permits self-destruction, but the caller keeps dereferencing the object after the callback returns.",
                    suggested_fix="Hold a reference across callback execution or mark/detach the current object before invoking callbacks that may destroy it.",
                    source=f"{callback_name}:{free_line.number}",
                    sink=post_use.text.strip(),
                    confidence=0.88,
                    impact_level="high",
                    positive=[
                        f"{view.name}: callback_arg is set to the current object `{obj}`",
                        f"line {call_line.number}: callback is invoked with `{obj}->callback_arg`",
                        f"{callback_name} line {free_line.number}: callback frees the argument object",
                        f"line {post_use.number}: caller uses `{obj}` after callback returns",
                    ],
                    evidence={
                        "path": {
                            "caller": view.name,
                            "callback": callback_name,
                            "callback_free_line": free_line.number,
                            "source_line": call_line.number,
                            "sink_line": post_use.number,
                            "complete_in_function": False,
                            "path_constraints": ["callback may execute synchronously and destroy its context"],
                        }
                    },
                )
        )

    @staticmethod
    def _callback_assignment_targets(rhs: str) -> List[str]:
        skip = {"NULL", "nullptr", "true", "false"}
        names = re.findall(r"\b[A-Za-z_]\w*\b", str(rhs or ""))
        return [name for name in names if name not in skip and name.startswith("_")]

    @staticmethod
    def _callback_free_line(view: FunctionView) -> Optional[GraphLine]:
        arg_aliases = {"arg"}
        for line in view.lines:
            alias = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?arg\b", line.text)
            if alias:
                arg_aliases.add(alias.group("var"))
        return next(
            (
                line
                for line in view.lines
                if any(
                    re.search(rf"\b(?:SAFE_FREE|free|kfree)\s*\(\s*{re.escape(alias)}\s*\)", line.text)
                    for alias in arg_aliases
                )
            ),
            None,
        )

    def _rule_lock_order_inversion(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        edges = self._lock_order_edges(views)
        seen_pairs = set()
        for left in edges:
            for right in edges:
                if left is right:
                    continue
                if not (
                    self._locks_may_match(left.first_lock, right.second_lock)
                    and self._locks_may_match(left.second_lock, right.first_lock)
                ):
                    continue
                pair_key = tuple(sorted([left.function, right.function])) + tuple(
                    sorted([left.first_lock, left.second_lock])
                )
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                view = next((item for item in views if item.name == right.function), None)
                if not view:
                    continue
                line = self._line_by_number(view, right.second_line) or view.lines[0]
                issues.append(
                    self._issue(
                        defect_class="deadlock",
                        rule="cross_function_lock_order_inversion",
                        view=view,
                        line=line,
                        description=(
                            f"Lock order inversion: `{left.function}` takes `{left.first_lock}` then `{left.second_lock}`, "
                            f"while `{right.function}` takes `{right.first_lock}` then `{right.second_lock}`."
                        ),
                        root_cause="Two reachable paths acquire the same lock pair in opposite order.",
                        suggested_fix="Define a single global lock order and refactor one path to follow it.",
                        source=f"{left.function}:{left.first_line}->{left.second_line}",
                        sink=f"{right.function}:{right.first_line}->{right.second_line}",
                        confidence=0.84,
                        impact_level="high",
                        positive=[
                            f"{left.function} lines {left.first_line}-{left.second_line}: {left.first_lock} before {left.second_lock}",
                            f"{right.function} lines {right.first_line}-{right.second_line}: {right.first_lock} before {right.second_lock}",
                        ],
                    )
                )

    def _lock_order_edges(self, views: Sequence[FunctionView]) -> List[LockOrderEdge]:
        edges: List[LockOrderEdge] = []
        for view in views:
            held: List[Tuple[str, GraphLine]] = []
            for line in view.lines:
                lock = self._lock_arg(line.text)
                if lock:
                    for prior, prior_line in held:
                        if prior != lock:
                            edges.append(
                                LockOrderEdge(
                                    function=view.name,
                                    file_path=view.file_path,
                                    first_lock=prior,
                                    second_lock=lock,
                                    first_line=prior_line.number,
                                    second_line=line.number,
                                )
                            )
                    held.append((lock, line))
                    continue
                if self._unlock_call_re.search(line.text) and held:
                    held.pop()
        return edges

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
        candidate_id = self._candidate_id(view.name, view.file_path, defect_class, line.number, rule, sink)
        dedup_key = "|".join(
            [
                defect_class,
                view.file_path.replace("\\", "/").lower(),
                str(line.number),
                rule,
                self._stable_fragment(sink),
            ]
        )
        pack = {
            "candidate_id": candidate_id,
            "candidate_source": "graph_rule",
            "defect_class": defect_class,
            "rule": rule,
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
            "cwe": self._CWE_BY_CLASS.get(defect_class, ""),
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
            "path_constraints": pack.get("path", {}).get("path_constraints", []),
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

    def _call_targets_for_line(self, caller: str, line: GraphLine) -> List[str]:
        targets = list(self._called_names(line.text))
        for (source_func, callee), evidence in self._callee_evidence.items():
            if source_func != caller or callee in targets:
                continue
            pointer_location = str(evidence.get("pointer_location") or "")
            call_line = evidence.get("call_line")
            if pointer_location and pointer_location in line.text:
                targets.append(callee)
            elif call_line and str(call_line).isdigit() and int(call_line) == line.number:
                targets.append(callee)
            elif evidence.get("dispatcher_name") == caller:
                targets.append(callee)
        return targets

    @staticmethod
    def _callee_reachability_text(callee: str, evidence: Dict[str, Any]) -> str:
        source = str(evidence.get("source") or "lexical_call")
        pointer_location = str(evidence.get("pointer_location") or "")
        dispatcher_name = str(evidence.get("dispatcher_name") or "")
        if pointer_location:
            return f"`{callee}` is a configured target of `{pointer_location}` via {source}"
        if dispatcher_name:
            return f"`{callee}` is a configured handler of dispatcher `{dispatcher_name}` via {source}"
        if source != "lexical_call":
            return f"`{callee}` is reachable via {source} call graph evidence"
        return f"`{callee}` appears as a direct lexical call"

    @staticmethod
    def _names_pattern(names: Iterable[str]) -> str:
        clean = sorted({str(name).strip() for name in names if str(name).strip()}, key=len, reverse=True)
        return "|".join(re.escape(name) for name in clean) or r"a^"

    def _lock_arg(self, text: str) -> str:
        match = self._lock_call_re.search(text)
        if not match:
            return ""
        return self._normalize_lock(match.group("arg"))

    @staticmethod
    def _normalize_lock(value: str) -> str:
        text = re.sub(r"\s+", "", str(value or ""))
        text = text.strip("&()")
        text = text.replace("->", ".")
        return text

    @classmethod
    def _locks_may_match(cls, left: str, right: str) -> bool:
        if not left or not right:
            return False
        left_norm = cls._normalize_lock(left)
        right_norm = cls._normalize_lock(right)
        if left_norm == right_norm:
            return True
        left_tail = left_norm.split(".")[-1]
        right_tail = right_norm.split(".")[-1]
        return bool(left_tail and left_tail == right_tail)

    @staticmethod
    def _first_param_type(signature: str) -> str:
        match = re.search(r"\((?P<params>[^)]*)\)", signature)
        if not match:
            return ""
        first = match.group("params").split(",", 1)[0].strip()
        if not first or first == "void":
            return ""
        first = re.sub(r"\bconst\b|\bvolatile\b", "", first).strip()
        first = re.sub(r"\s+", " ", first)
        first = re.sub(r"\b[A-Za-z_]\w*$", "", first).strip()
        return first.strip()

    @staticmethod
    def _first_call_arg(text: str, call_name: str) -> str:
        match = re.search(rf"\b{re.escape(call_name)}\s*\((?P<args>[^;]*)\)", text)
        if not match:
            return ""
        return match.group("args").split(",", 1)[0].strip()

    @staticmethod
    def _identifier_terms(value: str) -> List[str]:
        parts = re.findall(r"[A-Za-z_]\w*", value)
        terms: List[str] = []
        for part in parts:
            split = re.sub(r"([a-z])([A-Z])", r"\1 \2", part).replace("_", " ")
            terms.extend(piece.lower() for piece in split.split() if len(piece) > 2)
        return terms

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
        type_terms = set(re.findall(r"\b[A-Z][A-Za-z0-9_]*(?:Node|Subscription|Session|Entry|Pipe)\b", left_text))
        type_terms &= set(re.findall(r"\b[A-Z][A-Za-z0-9_]*(?:Node|Subscription|Session|Entry|Pipe)\b", right_text))
        return bool(type_terms)

    @staticmethod
    def _looks_like_dispatcher_view(view: FunctionView) -> bool:
        if len(view.callees) < 3:
            return False
        text = "\n".join(line.text for line in view.lines)
        name_hint = re.search(r"(?:dispatch|handle|process|message|protocol|router|route)", view.name, re.I)
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
        call_statements = sum(1 for line in view.lines if GraphCandidateGenerator._called_names(line.text))
        if len(view.callees) >= 3 and call_statements >= 3:
            return True
        name_hint = re.search(
            r"(?:apply|configure|publish|schedule|refresh|accept|cycle|plan|record|maintenance|cases|worker|runtime)",
            view.name,
            re.I,
        )
        return bool(name_hint and len(view.callees) >= 2 and call_statements >= 2)

    @staticmethod
    def _first_line_containing(view: FunctionView, needle: str) -> Optional[GraphLine]:
        return next((line for line in view.lines if needle in line.text), None)

    @staticmethod
    def _first_line_matching(view: FunctionView, pattern: re.Pattern[str]) -> Optional[GraphLine]:
        return next((line for line in view.lines if pattern.search(line.text)), None)

    @staticmethod
    def _line_by_number(view: FunctionView, number: int) -> Optional[GraphLine]:
        return next((line for line in view.lines if line.number == number), None)

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

