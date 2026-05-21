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

from ..retrieval.code_index import CodeIndex

if TYPE_CHECKING:
    from .regex_candidates import LocalPatternSemantics


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
    _DEFAULT_LOCK_APIS = {
        "LOCK",
        "LOCK_READ",
        "LOCK_WRITE",
        "pthread_mutex_lock",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_wrlock",
        "spin_lock",
        "mtx_lock",
    }
    _DEFAULT_UNLOCK_APIS = {
        "UNLOCK",
        "pthread_mutex_unlock",
        "pthread_rwlock_unlock",
        "spin_unlock",
        "mtx_unlock",
    }
    _DEFAULT_ALLOC_APIS = {
        "malloc",
        "calloc",
        "realloc",
        "strdup",
        "_safe_malloc",
        "_safe_calloc",
        "_safe_realloc",
    }
    _DEFAULT_FREE_APIS = {"free", "destroy", "release", "delete"}

    _CWE_BY_CLASS = {
        "deadlock": "CWE-833",
        "memory_leak": "CWE-401",
        "type_confusion": "CWE-843",
        "infinite_loop": "CWE-835",
        "log_amplification": "CWE-400",
        "key_truncation": "CWE-187",
        "use_after_free": "CWE-416",
        "race": "CWE-362",
    }

    def __init__(
        self,
        code_index: CodeIndex,
        semantics: Optional["LocalPatternSemantics"] = None,
        semantic_overlay: Optional[Dict[str, Any]] = None,
    ):
        self.code_index = code_index
        self.semantics = semantics
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
        lock_names = set(self._DEFAULT_LOCK_APIS)
        unlock_names = set(self._DEFAULT_UNLOCK_APIS)
        alloc_names = set(self._DEFAULT_ALLOC_APIS)
        free_names = set(self._DEFAULT_FREE_APIS)
        if self.semantics is not None:
            lock_names.update(self.semantics.lock_apis)
            unlock_names.update(self.semantics.unlock_apis)
            alloc_names.update(self.semantics.allocators)
            alloc_names.update(self.semantics.calloc_allocators)
            alloc_names.update(self.semantics.reallocators)
            free_names.update(self.semantics.deallocators)
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

        self._rule_paired_lifecycle_protocols(views, issues)
        self._rule_paired_global_registration_cleanup(views, issues)
        self._rule_timer_cascade_wait(views, issues)
        self._rule_lock_order_inversion(views, issues)
        return self._dedupe(issues)

    def issue_to_ticket(self, issue: Dict[str, Any]) -> Any:
        from .regex_candidates import RegexCandidateGenerator

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
                and self._looks_like_dispatcher_view(view)
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
            self._impl_cache[func_name] = self.code_index.get_function_impl(
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

