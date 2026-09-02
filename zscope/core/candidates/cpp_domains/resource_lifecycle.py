# mypy: disable-error-code="attr-defined"
"""Resource acquisition, release, and lifetime detector implementations."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .models import (
    ClangCfgLine,
    CodeLine,
    FunctionView,
    GraphLine,
    LockOrderEdge,
    LockState,
    ResourceState,
)

from .models import DetectorStage


STAGES = (
    DetectorStage(
        "regex",
        "function",
        20,
        "resource_lifecycle",
        "same_function_resource_leak",
        "_rule_same_function_resource_leak",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        30,
        "resource_lifecycle",
        "realloc_misuse",
        "_rule_realloc_misuse",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        140,
        "resource_lifecycle",
        "stale_resources",
        "_rule_stale_resources",
        ("lines", "emit"),
    ),
    DetectorStage(
        "clang_ast_cfg",
        "function",
        10,
        "resource_lifecycle",
        "resource_state_machines",
        "_run_resource_state_machines",
        ("issues", "func_name", "file_path", "lines", "allowed_skills"),
    ),
    DetectorStage(
        "graph",
        "view",
        20,
        "resource_lifecycle",
        "wrong_cleanup_type",
        "_rule_wrong_cleanup_type",
        ("view", "by_name", "issues"),
    ),
    DetectorStage(
        "graph",
        "view",
        30,
        "resource_lifecycle",
        "thread_argument_lifetime",
        "_rule_thread_argument_lifetime",
        ("view", "issues"),
        covers=("memory_bounds_integer",),
    ),
    DetectorStage(
        "graph",
        "view",
        40,
        "resource_lifecycle",
        "global_container_lifecycle",
        "_rule_global_container_lifecycle",
        ("view", "issues"),
    ),
    DetectorStage(
        "graph",
        "batch",
        10,
        "resource_lifecycle",
        "paired_lifecycle_protocols",
        "_rule_paired_lifecycle_protocols",
        ("views", "issues"),
        covers=("protocol_ownership_logic",),
    ),
    DetectorStage(
        "graph",
        "batch",
        20,
        "resource_lifecycle",
        "paired_member_cleanup_protocols",
        "_rule_paired_member_cleanup_protocols",
        ("views", "issues"),
        covers=("protocol_ownership_logic",),
    ),
    DetectorStage(
        "graph",
        "batch",
        50,
        "resource_lifecycle",
        "paired_global_registration_cleanup",
        "_rule_paired_global_registration_cleanup",
        ("views", "issues"),
        covers=("concurrency_shared_state",),
    ),
)


class RegexResourceLifecycleRules:
    def _rule_realloc_misuse(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            match = re.search(
                r"\b(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                rf"(?:{self._names_pattern(self._reallocator_names)})\s*\(\s*(?P=lhs)\s*,(?P<size>[^;]+)\)",
                line.text,
            )
            if not match:
                continue
            emit(
                defect_class="realloc_misuse",
                rule="direct_realloc_assignment",
                line=line,
                description=(
                    f"`{match.group('lhs')}` is overwritten by realloc; on failure the "
                    "original allocation is lost."
                ),
                root_cause="realloc result is assigned directly to the only owner pointer.",
                suggested_fix="Assign realloc to a temporary pointer and update the owner only after success.",
                source=match.group("lhs"),
                sink=line.text.strip(),
                confidence=0.86,
                positive=[f"line {line.number}: direct realloc assignment `{line.text.strip()}`"],
            )

    def _rule_same_function_resource_leak(self, lines: List[CodeLine], emit) -> None:
        allocations: Dict[str, CodeLine] = {}
        released: set[str] = set()
        escaped: set[str] = set()
        for line in lines:
            alloc = re.search(
                r"^\s*(?:[A-Za-z_][A-Za-z_0-9]*\s*\*?\s+)?(?P<var>[A-Za-z_]\w*)\s*="
                rf"\s*(?:\([^)]*\)\s*)?(?:{self._names_pattern(self._allocator_names | self._calloc_names)})\s*\(",
                line.text,
            )
            if alloc:
                allocations[alloc.group("var")] = line
            for var in list(allocations):
                if re.search(
                    rf"\b(?:{self._names_pattern(self._deallocator_names)})\s*\(\s*{re.escape(var)}\s*\)",
                    line.text,
                ):
                    released.add(var)
                if re.search(rf"\breturn\s+{re.escape(var)}\s*;", line.text):
                    escaped.add(var)
                if re.search(rf"\bg_[A-Za-z_0-9.]+\s*=\s*{re.escape(var)}\b", line.text):
                    escaped.add(var)
                if re.search(
                    rf"\b[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\s*=\s*{re.escape(var)}\b", line.text
                ):
                    escaped.add(var)
        if not allocations:
            return
        return_lines = [line for line in lines if re.search(r"\breturn\b", line.text)]
        sink_line = return_lines[-1] if return_lines else lines[-1]
        leaked: List[Tuple[str, CodeLine]] = []
        for var, alloc_line in allocations.items():
            if var in released or var in escaped:
                continue
            leaked.append((var, alloc_line))
        if not leaked:
            return
        _, first_line = leaked[0]
        leaked_names = ", ".join(f"`{var}`" for var, _ in leaked)
        emit(
            defect_class="memory_leak",
            rule="same_function_allocation_not_released",
            line=first_line,
            description=f"{leaked_names} allocated but no local release, return, or ownership transfer is visible.",
            root_cause="The function exits with an owned allocation still live.",
            suggested_fix="Release the allocation on every exit path or transfer ownership explicitly.",
            source=", ".join(var for var, _ in leaked),
            sink=f"return at line {sink_line.number}",
            confidence=0.72,
            positive=[
                *(
                    f"line {alloc_line.number}: allocation assigned to `{var}`"
                    for var, alloc_line in leaked
                ),
                "no matching release/return/ownership transfer found in the function body",
            ],
        )

    def _rule_stale_resources(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            close = re.search(r"\bclose\s*\(\s*(?P<fd>[A-Za-z_]\w*)\s*\)\s*;", line.text)
            if close:
                later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 7])
                if not self._previous_assignment_from_open(
                    lines, line.index, close.group("fd")
                ) and not re.search(r"(?:g_[A-Za-z_]\w*fd|fd)\s*=\s*-1", later):
                    emit(
                        defect_class="stale_fd",
                        rule="fd_closed_without_invalidation",
                        line=line,
                        description="File descriptor is closed without an adjacent owner invalidation.",
                        root_cause="Other paths may reuse the stale descriptor value after close.",
                        suggested_fix="Set the owning descriptor to -1 under the same synchronization after close.",
                        source=close.group("fd"),
                        sink=line.text.strip(),
                        confidence=0.62,
                        positive=[f"line {line.number}: close without nearby fd=-1 assignment"],
                    )

            if "munmap" in line.text:
                later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
                if "NULL" not in later:
                    emit(
                        defect_class="use_after_free",
                        rule="mapping_unmapped_without_pointer_clear",
                        line=line,
                        description="Memory mapping is unmapped without clearing the shared pointer/length nearby.",
                        root_cause="A later reader can observe a stale mapping pointer after munmap.",
                        suggested_fix="Clear the shared pointer and length while holding the protecting lock.",
                        source=line.text.strip(),
                        sink=line.text.strip(),
                        confidence=0.7,
                        impact_level="high",
                        positive=[f"line {line.number}: munmap without nearby NULL reset"],
                    )

    @staticmethod
    def _previous_assignment_from_open(lines: List[CodeLine], idx: int, fd: str) -> bool:
        previous = "\n".join(item.text for item in lines[max(0, idx - 12) : idx])
        return bool(
            re.search(rf"\b{re.escape(fd)}\s*=\s*(?:open|socket|accept|accept4)\s*\(", previous)
        )


class GraphResourceLifecycleRules:
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
                            "path_constraints": [
                                "worker may outlive initializer",
                                "owner remains local",
                            ],
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
        if re.search(r"pfnDropSession", text) and not re.search(
            r"(?:release|free|destroy|remove)", text, re.I
        ):
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
                    positive=[
                        f"line {line.number}: cleanup depends on optional hook `{line.text.strip()}`"
                    ],
                )
            )

        if re.search(r"\bOPEN\b", text) and re.search(
            r"(?:add|insert|register).*global|global.*(?:add|insert|register)", text, re.I
        ):
            line = (
                self._first_line_matching(view, re.compile(r"\bOPEN\b|global", re.I))
                or view.lines[0]
            )
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

        if re.search(
            r"(?:detach|unlink|remove)[A-Za-z_0-9]*without[A-Za-z_0-9]*release", text, re.I
        ):
            line = (
                self._first_line_matching(view, re.compile(r"without.*release|detach", re.I))
                or view.lines[0]
            )
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
                    positive=[
                        f"line {line.number}: detach/unlink path is named or implemented without release"
                    ],
                )
            )

        free_line = self._first_line_matching(view, self._free_re)
        if (
            re.search(r"pthread_mutex_init", text)
            and free_line
            and not re.search(r"pthread_mutex_destroy", text)
        ):
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

        if (
            re.search(r"proc_head|child|children", text, re.I)
            and free_line
            and not re.search(
                r"\bwhile\b[^{;]*(?:proc|child)|for\s*\([^;]*(?:proc|child)", text, re.I
            )
        ):
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

    def _emit_role_release_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        role_assign = self._first_line_matching(
            view, re.compile(r"->\s*role\s*=\s*(?P<role>[A-Za-z_]\w*)\s*;")
        )
        release_line = self._first_line_matching(
            view,
            re.compile(
                r"\b[A-Za-z_]\w*(?:release|cleanup|destroy)[A-Za-z_0-9]*\s*\([^;]*,\s*0\s*\)", re.I
            ),
        )
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

    def _emit_sigpipe_unhandled_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if "SIGPIPE" in text or "MSG_NOSIGNAL" in text:
            return
        line = self._first_line_matching(view, re.compile(r"\b(?:write|send)\s*\("))
        if not line:
            return
        if not re.search(
            r"(?:peer|socket|sock|fd|conn|control|reply)", view.signature + "\n" + line.text, re.I
        ):
            return
        issues.append(
            self._issue(
                defect_class="sigpipe_unhandled",
                rule="peer_write_without_sigpipe_handling",
                view=view,
                line=line,
                description="Peer write is issued without visible SIGPIPE suppression or handling.",
                root_cause="Writing to a closed peer can raise SIGPIPE before normal error handling returns.",
                suggested_fix="Use send(..., MSG_NOSIGNAL), ignore/handle SIGPIPE, or use platform-specific no-signal flags.",
                source=line.text.strip(),
                sink="closed peer write",
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {line.number}: peer/control fd is written with `{line.text.strip()}`",
                    "no SIGPIPE handler, ignore policy, or MSG_NOSIGNAL flag is visible in the function",
                ],
            )
        )

    def _emit_alloc_free_mismatch_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not ("mem_alloc_func" in text and "mem_free_func" in text):
            return
        alloc_assign = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\.mem_alloc_func\s*=")
        )
        free_assign = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\.mem_free_func\s*=")
        )
        alloc_call = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\.mem_alloc_func\s*\(")
        )
        free_call = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\.mem_free_func\s*\(")
        )
        if not (alloc_assign and free_assign and alloc_call and free_call):
            return
        if not re.search(r"\?|noop|free|header|pool|custom", text, re.I):
            return
        issues.append(
            self._issue(
                defect_class="alloc_free_mismatch",
                rule="callback_allocator_pair_not_enforced",
                view=view,
                line=alloc_assign,
                description="Allocation and free callbacks are selected independently without enforcing allocator pairing.",
                root_cause="A node allocated by one callback family can be released through an incompatible callback/no-op/free path.",
                suggested_fix="Store allocator identity with the allocation or register allocator/free callbacks as an atomic validated pair.",
                source=f"{alloc_assign.text.strip()} / {free_assign.text.strip()}",
                sink=free_call.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {alloc_assign.number}: allocator callback is selected",
                    f"line {free_assign.number}: free callback is selected separately",
                    f"line {alloc_call.number}: allocation uses the selected callback",
                    f"line {free_call.number}: release uses the selected free callback",
                ],
            )
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
                if not re.search(
                    r"(?:payload|data|buf|buffer|key|name|str|child|children|list)", field, re.I
                ):
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
                free_arg = (
                    self._resource_arg(free_match.group("arg")) or free_match.group("arg").strip()
                )
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
                        negative=[
                            "Validator must confirm the member is not intentionally transferred before wrapper cleanup."
                        ],
                        evidence={
                            "path": {
                                "allocator_function": creator.name,
                                "cleanup_function": view.name,
                                "source_line": alloc_line.number,
                                "sink_line": free_line.number,
                                "complete_in_function": False,
                                "path_constraints": [
                                    "paired constructor/free-wrapper ownership contract"
                                ],
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
        if not re.search(
            r"(?:unregister|remove|delete|release|free|cleanup|destroy)", view.name, re.I
        ):
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
            re.compile(
                rf"\b{re.escape(alloc_match.group('var'))}\s*=\s*{re.escape(alloc_match.group('api'))}\s*\(",
                re.I,
            ),
        )
        if alloc_line_for_context:
            alloc_context = alloc_line_for_context.text
        if not re.search(
            r"(?:file|path|fs|unlink|unregister)", f"{view.name} {alloc_context}", re.I
        ):
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
        missing_member = next(
            (member for member in likely_owned_members if member not in released_members), ""
        )
        if not missing_member:
            return
        free_line = self._first_line_matching(
            view,
            re.compile(rf"\b(?:SAFE_FREE|free)\s*\(\s*{re.escape(var_name)}\s*\)", re.I),
        )
        alloc_line = self._first_line_matching(
            view,
            re.compile(
                rf"\b{re.escape(var_name)}\s*=\s*{re.escape(alloc_match.group('api'))}\s*\(", re.I
            ),
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
                negative=[
                    "Validator must confirm the allocation helper does not transfer or omit this member by contract."
                ],
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
                    and re.search(
                        r"->\s*(?:proc_head|child|children|next_child)", texts[creator.name], re.I
                    )
                    and self._views_share_protocol_terms(view, creator)
                ),
                None,
            )
            if child_owner and not re.search(
                r"\bwhile\b[^{;]*(?:proc|child)|for\s*\([^;]*(?:proc|child)", text, re.I
            ):
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
    def _cleanup_pair_matches(
        creator: FunctionView, cleanup: FunctionView, field: str, cleanup_text: str
    ) -> bool:
        creator_terms = set(GraphResourceLifecycleRules._identifier_terms(creator.name))
        cleanup_terms = set(GraphResourceLifecycleRules._identifier_terms(cleanup.name))
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
        creator_type = GraphResourceLifecycleRules._first_param_type(creator.signature)
        cleanup_type = GraphResourceLifecycleRules._first_param_type(cleanup.signature)
        if GraphResourceLifecycleRules._is_primitive_pointer_type(
            creator_type
        ) or GraphResourceLifecycleRules._is_primitive_pointer_type(cleanup_type):
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
        if re.search(
            rf"\b(?:free|SAFE_FREE|destroy|release|cleanup|delete)[A-Za-z_0-9]*\s*\([^;]*{direct_member}",
            text,
            re.I,
        ):
            return True
        if re.search(
            rf"\b(?:free|SAFE_FREE|destroy|release|cleanup|delete)[A-Za-z_0-9]*\s*\([^;]*\b{field_re}\b",
            text,
            re.I,
        ):
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
            global_registration = re.compile(
                r"\b(?:OPEN|ADD)\b|"
                r"(?:add|insert|register)[A-Za-z_0-9]*(?:\s|_|\W){0,4}global|"
                r"global(?:\s|_|\W){0,4}(?:add|insert|register)",
                re.I,
            )
            if not global_registration.search(text) or not re.search(
                r"\bglobal\b|_global\b|global_", text, re.I
            ):
                continue
            line = (
                self._first_line_matching(view, global_registration)
                or self._first_line_matching(view, re.compile(r"\b(?:OPEN|ADD)\b", re.I))
                or view.lines[0]
            )
            paired_cleanup = next(
                (
                    cleanup
                    for cleanup in cleanup_views
                    if cleanup.name != view.name
                    and self._views_share_protocol_terms(view, cleanup)
                    and not re.search(
                        r"(?:remove|drop|release|free|destroy)[A-Za-z_0-9]*",
                        texts[cleanup.name],
                        re.I,
                    )
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
                            "path_constraints": [
                                "OPEN/add succeeds",
                                "cleanup is later invoked for the same protocol",
                            ],
                        },
                        "lifecycle_pair": {
                            "registration_function": view.name,
                            "cleanup_function": paired_cleanup.name,
                        },
                    },
                )
            )

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
    def _identifier_terms(value: str) -> List[str]:
        parts = re.findall(r"[A-Za-z_]\w*", value)
        terms: List[str] = []
        for part in parts:
            split = re.sub(r"([a-z])([A-Z])", r"\1 \2", part).replace("_", " ")
            terms.extend(piece.lower() for piece in split.split() if len(piece) > 2)
        return terms

    @staticmethod
    def _first_call_arg(text: str, call_name: str) -> str:
        match = re.search(rf"\b{re.escape(call_name)}\s*\((?P<args>[^;]*)\)", text)
        if not match:
            return ""
        return match.group("args").split(",", 1)[0].strip()

    @staticmethod
    def _first_line_containing(view: FunctionView, needle: str) -> Optional[GraphLine]:
        return next((line for line in view.lines if needle in line.text), None)


class ClangResourceLifecycleRules:
    def _run_resource_state_machines(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        live: Dict[str, ResourceState] = {}
        freed: Dict[str, Tuple[ClangCfgLine, str]] = {}
        terminal_branch_freed: Dict[Tuple[int, str], Tuple[ClangCfgLine, str]] = {}
        emitted_null_deref: Set[str] = set()
        emitted_uaf: Set[str] = set()
        emitted_realloc: Set[Tuple[str, int]] = set()
        emitted_status_misuse: Set[str] = set()

        for line in lines:
            terminal_branch_line = self._is_terminal_conditional_branch_line(lines, line)
            reset_var = self._match_null_reset(line.text)
            if reset_var:
                freed.pop(reset_var, None)

            reassigned = self._match_assignment_call(line.text, self._alloc_call_re)
            if reassigned:
                var, api, args = reassigned
                if api in self._reallocator_names:
                    first_arg = self._first_arg(args)
                    if first_arg == var and (var, line.number) not in emitted_realloc:
                        self._emit(
                            issues,
                            func_name,
                            file_path,
                            lines,
                            allowed_skills,
                            defect_class="realloc_misuse",
                            rule="clang_cfg_realloc_lost_original",
                            line=line,
                            description=(
                                f"`{var}` is overwritten by `{api}` before the original "
                                "pointer is known to be preserved."
                            ),
                            root_cause=(
                                "On realloc failure the original allocation remains live, "
                                "but the code loses the only local owner."
                            ),
                            suggested_fix=(
                                "Assign realloc to a temporary pointer and update the owner "
                                "only after the call succeeds."
                            ),
                            source=f"{api}({args})",
                            sink=f"{var} = {api}(...)",
                            confidence=0.83,
                            positive=[
                                f"line {line.number}: assignment overwrites `{var}` with `{api}` result",
                                f"line {line.number}: first `{api}` argument is `{var}`",
                            ],
                            negative=[],
                            ast_cfg=self._ast_cfg_pack(
                                lines,
                                [self._event("realloc_assign", line, var, api, line.text)],
                                [line.number],
                            ),
                        )
                        emitted_realloc.add((var, line.number))
                # Assignment directly into an explicit global lvalue transfers
                # this local acquisition to durable program ownership.  It may
                # still be subject to a separate global-lifetime analysis, but
                # it is not a leak on this function's return path.
                if self._is_global_owner_lvalue(var):
                    freed.pop(var, None)
                    continue
                live[var] = ResourceState(var=var, api=api, line=line, carrier="return_value")
                freed.pop(var, None)
                continue

            out_acquired = self._match_out_param_acquire(line.text)
            if out_acquired:
                var, api, args, status_var = out_acquired
                live[var] = ResourceState(
                    var=var,
                    api=api,
                    line=line,
                    carrier="output_argument",
                    status_var=status_var,
                )
                freed.pop(var, None)

            for state_var, state in list(live.items()):
                if self._is_null_guard(line.text, state_var):
                    live[state_var] = ResourceState(
                        var=state.var,
                        api=state.api,
                        line=state.line,
                        carrier=state.carrier,
                        status_var=state.status_var,
                        null_guarded=True,
                        status_guarded=state.status_guarded,
                        transferred=state.transferred,
                    )

            for state_var, state in list(live.items()):
                if not state.status_var:
                    continue
                if self._is_status_guard_line(line.text, state.status_var):
                    live[state_var] = ResourceState(
                        var=state.var,
                        api=state.api,
                        line=state.line,
                        carrier=state.carrier,
                        status_var=state.status_var,
                        null_guarded=state.null_guarded,
                        status_guarded=True,
                        transferred=state.transferred,
                    )

            for state_var, state in list(live.items()):
                if (
                    state.carrier != "output_argument"
                    or not state.status_var
                    or state.status_guarded
                    or state.var in emitted_status_misuse
                    or line.number <= state.line.number
                    or self._is_status_guard_line(line.text, state.status_var)
                ):
                    continue
                if self._uses_resource_value(line.text, state.var):
                    self._emit(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        defect_class="bad_parameter_or_api_misuse",
                        rule="clang_cfg_out_param_used_before_success_check",
                        line=line,
                        description=(
                            f"`{state.var}` is produced by output-parameter API `{state.api}` "
                            f"but is used before `{state.status_var}` is checked for success."
                        ),
                        root_cause=(
                            "The synthesized CFG path observes an output resource use before "
                            "the status return from the producing API constrains the success path."
                        ),
                        suggested_fix=(
                            "Check the status return before using or releasing the output resource, "
                            "and keep failure paths from consuming an undefined output value."
                        ),
                        source=f"{state.api}(..., &{state.var}) at line {state.line.number}",
                        sink=line.text,
                        confidence=0.78,
                        positive=[
                            f"line {state.line.number}: `{state.api}` writes `{state.var}` through an output argument",
                            f"line {line.number}: `{state.var}` is used before `{state.status_var}` success is established",
                        ],
                        negative=[
                            "Validator must confirm the API does not define the output argument on failure."
                        ],
                        ast_cfg=self._ast_cfg_pack(
                            lines,
                            [
                                self._event(
                                    "out_param_acquire",
                                    state.line,
                                    state.var,
                                    state.api,
                                    state.line.text,
                                ),
                                self._event(
                                    "use_before_status_guard", line, state.var, "", line.text
                                ),
                            ],
                            [state.line.number, line.number],
                        ),
                    )
                    emitted_status_misuse.add(state.var)

            release = self._match_release(line.text)
            if release:
                api, arg = release
                var = self._resource_expr(arg) or self._resource_var(arg)
                terminal_branch_release = bool(var and terminal_branch_line)
                terminal_key = (line.block_id, var) if terminal_branch_release and var else None
                if terminal_key and terminal_key in terminal_branch_freed:
                    previous_line, previous_api = terminal_branch_freed[terminal_key]
                    self._emit_double_free(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        var,
                        previous_line,
                        previous_api,
                        line,
                        api,
                        arg,
                    )
                elif var and var in freed:
                    previous_line, previous_api = freed[var]
                    self._emit_double_free(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        var,
                        previous_line,
                        previous_api,
                        line,
                        api,
                        arg,
                    )
                elif var:
                    if terminal_key:
                        terminal_branch_freed[terminal_key] = (line, api)
                    if not terminal_branch_release:
                        live.pop(var, None)
                    return_line = self._return_line_after_release(lines, line)
                    if return_line is not None and self._uses_freed_var(
                        return_line.text, var, release_api_names=self._release_names
                    ):
                        self._emit_use_after_release(
                            issues,
                            func_name,
                            file_path,
                            lines,
                            allowed_skills,
                            var,
                            line,
                            api,
                            return_line,
                        )
                        emitted_uaf.add(var)
                    if not terminal_branch_release and return_line is None:
                        freed[var] = (line, api)

            for var, (free_line, free_api) in list(freed.items()):
                if var in emitted_uaf:
                    continue
                if line.number <= free_line.number:
                    continue
                if (
                    self._is_var_redefined(line.text, var)
                    or self._match_null_reset(line.text) == var
                ):
                    freed.pop(var, None)
                    continue
                if self._uses_freed_var(line.text, var, release_api_names=self._release_names):
                    self._emit_use_after_release(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        var,
                        free_line,
                        free_api,
                        line,
                    )
                    emitted_uaf.add(var)

            for var, state in list(live.items()):
                if var in emitted_null_deref:
                    continue
                if line.number <= state.line.number:
                    continue
                if self._is_transfer(line.text, var):
                    live[var] = ResourceState(
                        var=state.var,
                        api=state.api,
                        line=state.line,
                        carrier=state.carrier,
                        status_var=state.status_var,
                        null_guarded=state.null_guarded,
                        status_guarded=state.status_guarded,
                        transferred=True,
                    )
                    continue
                if self._is_null_guard(line.text, var):
                    continue
                if self._is_direct_deref(line.text, var) and not state.null_guarded:
                    self._emit(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        defect_class="null_pointer_dereference",
                        rule="clang_cfg_alloc_result_deref_without_null_guard",
                        line=line,
                        description=f"`{var}` is dereferenced before a visible null check.",
                        root_cause=(
                            "The allocation/acquire result is consumed on the local CFG path "
                            "without a guard proving it is non-null."
                        ),
                        suggested_fix=(
                            "Check the allocation result before dereference and route failure "
                            "through cleanup/error handling."
                        ),
                        source=f"{state.api}(...) at line {state.line.number}",
                        sink=line.text,
                        confidence=0.74,
                        positive=[
                            f"line {state.line.number}: `{var}` receives `{state.api}` result",
                            f"line {line.number}: `{var}` is dereferenced",
                        ],
                        negative=[
                            "No null guard for the acquired value appears before the dereference."
                        ],
                        ast_cfg=self._ast_cfg_pack(
                            lines,
                            [
                                self._event("acquire", state.line, var, state.api, state.line.text),
                                self._event("deref", line, var, "", line.text),
                            ],
                            [state.line.number, line.number],
                        ),
                    )
                    emitted_null_deref.add(var)

            if self._is_return(line.text):
                for var, state in list(live.items()):
                    if (
                        state.transferred
                        or self._return_excludes_resource(line.text, var)
                        or self._return_exits_null_failure_path(lines, line, var)
                        or self._resource_released_in_terminal_branch_before_return(
                            lines, line, var
                        )
                    ):
                        continue
                    if state.carrier == "output_argument" and self._return_is_status_failure_exit(
                        lines, line, state.status_var
                    ):
                        continue
                    self._emit_leak_on_exit(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        state,
                        line,
                        is_return=True,
                    )
                    if not terminal_branch_line:
                        live.pop(var, None)
                if not terminal_branch_line:
                    live.clear()
                    freed.clear()

        if lines:
            exit_line = lines[-1]
            for state in list(live.values()):
                if state.transferred:
                    continue
                self._emit_leak_on_exit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    state,
                    exit_line,
                    is_return=False,
                )

    def _emit_double_free(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        var: str,
        previous_line: ClangCfgLine,
        previous_api: str,
        line: ClangCfgLine,
        api: str,
        arg: str,
    ) -> None:
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="double_free",
            rule="clang_cfg_same_object_released_twice",
            line=line,
            description=f"`{var}` is released twice on the same local CFG path.",
            root_cause=(
                "The resource state reaches a second release without an "
                "intervening reallocation, ownership transfer, or null reset."
            ),
            suggested_fix=(
                "Release the resource once, clear the owner after release, or "
                "merge cleanup paths through a single exit block."
            ),
            source=f"{previous_api}({var}) at line {previous_line.number}",
            sink=f"{api}({arg})",
            confidence=0.88,
            impact_level="high",
            positive=[
                f"line {previous_line.number}: first release of `{var}` via `{previous_api}`",
                f"line {line.number}: second release of `{var}` via `{api}`",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("release", previous_line, var, previous_api, previous_line.text),
                    self._event("release", line, var, api, line.text),
                ],
                [previous_line.number, line.number],
            ),
        )

    def _emit_container_unlink_lifecycle_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        """Find a detached container member that loses all visible ownership.

        This is deliberately based on the unlink/transfer/release protocol,
        not on container API names.  An unlink by itself is harmless when the
        member is returned, stored in another owner, or released locally.
        """

        for line in lines:
            unlink = re.search(
                r"(?P<link>[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)\s*=\s*"
                r"(?P<object>[A-Za-z_]\w*)\s*->\s*(?:next|prev)\s*;",
                line.text,
            )
            if not unlink:
                continue
            obj = unlink.group("object")
            tail = "\n".join(item.text for item in lines[line.index + 1 :])
            if re.search(
                rf"\b[A-Za-z_0-9]*(?:free|release|destroy|cleanup|close)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(obj)}\b",
                tail,
                re.IGNORECASE,
            ):
                continue
            if re.search(
                rf"\breturn\s+{re.escape(obj)}\s*;|"
                rf"\b[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\s*=\s*{re.escape(obj)}\s*;",
                tail,
            ):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="memory_leak",
                rule="clang_cfg_container_unlink_without_release",
                line=line,
                description=(
                    f"Container member `{obj}` is unlinked without a visible release or ownership transfer."
                ),
                root_cause=(
                    "The object becomes unreachable from its container and no subsequent local operation "
                    "establishes a new owner or releases it."
                ),
                suggested_fix="Release the detached object or transfer it to an explicit owner before returning.",
                source=f"{obj} ownership before line {line.number}",
                sink=line.text,
                confidence=0.86,
                impact_level="high",
                positive=[
                    f"line {line.number}: container link is reassigned around `{obj}`",
                    "no local release or ownership transfer follows the unlink",
                ],
                negative=[
                    "Validator must confirm no callee retains ownership of the detached object."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("container_unlink", line, obj, "unlink", line.text),
                        self._event("exit_without_release", lines[-1], obj, "", lines[-1].text),
                    ],
                    [line.number, lines[-1].number],
                ),
            )
            return

    def _emit_incomplete_owner_cleanup_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        """Emit only when initialized owner fields and cleanup are explicit."""

        initialized: Dict[Tuple[str, str], ClangCfgLine] = {}
        released: Dict[Tuple[str, str], ClangCfgLine] = {}
        for line in lines:
            assign = re.search(
                r"(?P<owner>[A-Za-z_]\w*)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*"
                r"[^;]*(?:malloc|calloc|realloc|strdup|open|create|dup(?:licate)?)\s*\(",
                line.text,
                re.IGNORECASE,
            )
            if assign:
                initialized[(assign.group("owner"), assign.group("field"))] = line
            release = re.search(
                r"\b[A-Za-z_0-9]*(?:free|release|destroy|cleanup|close)[A-Za-z_0-9]*\s*\(\s*"
                r"(?P<owner>[A-Za-z_]\w*)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)",
                line.text,
                re.IGNORECASE,
            )
            if release:
                released[(release.group("owner"), release.group("field"))] = line
        owners = sorted({owner for owner, _field in initialized})
        for owner in owners:
            owned = {
                (candidate_owner, field)
                for candidate_owner, field in initialized
                if candidate_owner == owner
            }
            cleaned = owned & set(released)
            missing = sorted(
                field for candidate_owner, field in owned - cleaned if candidate_owner == owner
            )
            if len(owned) < 2 or not cleaned or not missing:
                continue
            cleanup_line = min((released[item] for item in cleaned), key=lambda item: item.index)
            first_init = min((initialized[item] for item in owned), key=lambda item: item.index)
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="incomplete_cleanup",
                rule="clang_cfg_incomplete_owned_member_cleanup",
                line=cleanup_line,
                description=(
                    f"Owner `{owner}` initializes multiple resource fields but its visible cleanup omits "
                    f"`{', '.join(missing)}`."
                ),
                root_cause="A composite owner resets only part of the resources it explicitly acquires.",
                suggested_fix="Release or transfer every initialized owned field on the destroy/reset path.",
                source=f"{owner} owned fields at line {first_init.number}",
                sink=cleanup_line.text,
                confidence=0.88,
                impact_level="high",
                positive=[
                    f"line {first_init.number}: `{owner}` initializes {len(owned)} owned fields",
                    f"line {cleanup_line.number}: cleanup releases only a strict subset of those fields",
                ],
                negative=[
                    "Validator must confirm omitted fields are not released by an owner destructor called on this path."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("owner_init", first_init, owner, "", first_init.text),
                        self._event(
                            "partial_owner_cleanup", cleanup_line, owner, "", cleanup_line.text
                        ),
                    ],
                    [first_init.number, cleanup_line.number],
                ),
            )
            return

    def _track_heap_thread_argument_owner(
        self,
        line: ClangCfgLine,
        allocations: Dict[str, ClangCfgLine],
        released: Set[str],
        thread_sinks: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        alloc = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
            r"(?P<api>[A-Za-z_]\w*(?:alloc|calloc|malloc|new)[A-Za-z_0-9]*)\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if alloc:
            allocations.setdefault(alloc.group("var"), line)

        for api, args in self._calls(line.text):
            split = self._split_args(args)
            if api in self._release_names or api in {"free", "SAFE_FREE"}:
                if split:
                    var = self._resource_var(split[0])
                    if var:
                        released.add(var)
                continue
            if api != "pthread_create" or len(split) < 4:
                continue
            thread_arg = split[3]
            for var in allocations:
                if re.search(rf"&\s*{re.escape(var)}\s*(?:\[|\b)", thread_arg):
                    worker = split[2].strip() if len(split) >= 3 else ""
                    thread_sinks[var] = (line, worker)

    def _emit_heap_thread_argument_owner_leaks(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        allocations: Dict[str, ClangCfgLine],
        released: Set[str],
        thread_sinks: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        for var, alloc_line in allocations.items():
            sink_data = thread_sinks.get(var)
            if not sink_data or var in released:
                continue
            sink_line, worker = sink_data
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="memory_leak",
                rule="clang_cfg_heap_thread_argument_owner_not_released",
                line=alloc_line,
                description=(
                    f"`{var}` is heap allocated and its element address is passed to `pthread_create`, "
                    "but the owner allocation is never released in this ownership scope."
                ),
                root_cause="Thread argument storage remains owned by the initializer while worker threads only receive element addresses.",
                suggested_fix="Store the owner array in dispatcher state and free it during shutdown, or allocate per-thread arguments with a clear worker-side release contract.",
                source=f"{var} allocation at line {alloc_line.number}",
                sink=sink_line.text,
                confidence=0.82,
                impact_level="high",
                positive=[
                    f"line {alloc_line.number}: `{var}` receives heap storage",
                    f"line {sink_line.number}: `pthread_create` passes an address derived from `{var}` to `{worker}`",
                    "no matching free/SAFE_FREE for the owner allocation appears in the function",
                ],
                negative=[
                    "Validator must confirm ownership is not intentionally retained in a global field."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("heap_thread_arg_owner", alloc_line, var, "", alloc_line.text),
                        self._event("thread_arg_escape", sink_line, var, worker, sink_line.text),
                    ],
                    [alloc_line.number, sink_line.number],
                ),
            )

    def _maybe_emit_role_release_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        release = re.search(
            r"\b(?P<api>[A-Za-z_]\w*release_by_role)\s*\(\s*(?P<node>[A-Za-z_]\w*)\s*,\s*(?P<release_role>\d+)\s*\)",
            line.text,
        )
        if not release:
            return
        node = release.group("node")
        release_role = release.group("release_role")
        role_line = None
        role_value = ""
        for item in reversed(lines[max(0, line.index - 8) : line.index]):
            match = re.search(
                rf"\b{re.escape(node)}->role\s*==\s*(?P<role>\d+)",
                item.text,
            )
            if match:
                role_line = item
                role_value = match.group("role")
                break
        if role_line is None or role_value == release_role:
            return
        if any("release_by_role" in item.text for item in lines[role_line.index + 1 : line.index]):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_role_specific_release_argument_mismatch",
            line=line,
            description="Role-specific cleanup ignores the stored role and invokes a mismatched release path.",
            root_cause="The cleanup helper releases only the resource class selected by its literal role argument, leaving resources for the actual stored role behind.",
            suggested_fix="Pass the stored role to the release helper or release every role-owned member explicitly.",
            source=role_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {role_line.number}: branch checks stored role `{role_line.text.strip()}`",
                f"line {line.number}: `{release.group('api')}` is called with literal role `{release_role}`",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "role_check", role_line, f"{node}->role", role_value, role_line.text
                    ),
                    self._event("role_release", line, node, release_role, line.text),
                ],
                [role_line.number, line.number],
            ),
        )

    def _maybe_emit_owned_member_leak_on_parent_release(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        release = self._match_release(line.text)
        if not release:
            return
        _api, raw_parent = release
        parent = self._resource_var(raw_parent)
        if not parent or "->" in raw_parent or "." in raw_parent:
            return

        explicit = self._find_owned_member_assignment(lines, line, parent)
        if explicit is not None:
            member_line, member, rhs = explicit
            if self._owned_member_has_cleanup(
                lines, member_line.index + 1, line.index, parent, member
            ):
                return
            resource = f"{parent}->{member}"
            description = f"Parent object `{parent}` is released while owned member `{resource}` remains live."
            source = f"{resource} = {rhs} at line {member_line.number}"
            positive = [
                f"line {member_line.number}: `{resource}` receives an owned child/list resource",
                f"line {line.number}: parent `{parent}` is released without releasing `{resource}`",
            ]
        else:
            missing_common = self._find_missing_common_owned_member_cleanup(lines, line, parent)
            if missing_common is not None:
                member_line, member = missing_common
                resource = f"{parent}->{member}"
                description = f"Parent object `{parent}` is released while common owned member `{resource}` is not cleaned up."
                source = member_line.text
                positive = [
                    f"line {member_line.number}: `{parent}` is created by an allocator/helper that initializes owned members",
                    f"line {line.number}: parent `{parent}` is released without releasing `{resource}`",
                ]
            else:
                if not self._looks_like_parent_delete_without_member_cleanup(
                    func_name, lines, line, parent
                ):
                    return
                resource = f"{parent}->child_list"
                description = f"Parent object `{parent}` is released without visible cleanup of owned child/list members."
                source = self._parent_declaration_text(lines, line, parent) or parent
                positive = [
                    f"line {line.number}: parent `{parent}` is released in a delete/remove/destroy-style function",
                    "no visible walk or release of child/list members appears before the parent release",
                ]

        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_parent_release_without_owned_member_cleanup",
            line=line,
            description=description,
            root_cause="Freeing a container object does not release owned child/list members unless the cleanup walks and releases those members first.",
            suggested_fix="Release or transfer every owned child/list member before freeing the parent object.",
            source=source,
            sink=line.text,
            confidence=0.78,
            impact_level="high",
            positive=positive,
            negative=[
                "Validator must confirm the member is owned by the parent and no out-of-line destructor dominates this release."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("owned_member_leak", line, resource, "", line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_error_log_allocation_leak(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        alloc = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
            r"(?P<api>[A-Za-z_]\w*(?:alloc|calloc|malloc|dup|new)[A-Za-z_0-9]*)\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not alloc:
            return
        var = alloc.group("var")
        later = lines[line.index + 1 : line.index + 16]
        release_re = re.compile(rf"\b(?:free|SAFE_FREE)\s*\(\s*{re.escape(var)}\s*\)")
        log_line: Optional[ClangCfgLine] = None
        for item in later:
            if release_re.search(item.text):
                return
            if re.search(rf"\bLOG_[A-Z_]*\s*\([^;]*\b{re.escape(var)}\b", item.text):
                log_line = item
                continue
            if log_line and re.search(r"\breturn\s+-1\s*;", item.text):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="memory_leak",
                    rule="clang_cfg_log_error_path_allocation_not_released",
                    line=line,
                    description=f"`{var}` is allocated for logging and an error branch returns without releasing it.",
                    root_cause="The error logging path consumes the allocated message but does not transfer or release ownership before returning.",
                    suggested_fix="Release the allocated log buffer before the error return or use a stack/static logging buffer.",
                    source=line.text,
                    sink=item.text,
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: `{var}` receives allocated storage",
                        f"line {log_line.number}: error logging uses `{var}`",
                        f"line {item.number}: error return occurs before a matching free/SAFE_FREE",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event(
                                "log_buffer_alloc", line, var, alloc.group("api"), line.text
                            ),
                            self._event("log_error_use", log_line, var, "LOG", log_line.text),
                            self._event("error_return", item, var, "", item.text),
                        ],
                        [line.number, log_line.number, item.number],
                    ),
                )
                return

    def _maybe_emit_refcount_free_without_protocol(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        release = re.search(r"\b(?:free|SAFE_FREE)\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)", line.text)
        if not release:
            return
        var = release.group("var")
        window_lines = lines[max(0, idx - 18) : idx + 1]
        window = "\n".join(item.text for item in window_lines)
        ref_line = next(
            (
                item
                for item in reversed(window_lines)
                if re.search(rf"\b{re.escape(var)}->ref_count\s*=", item.text)
                or re.search(rf"\b{re.escape(var)}->ref_count\b", item.text)
            ),
            None,
        )
        if not ref_line:
            return
        if re.search(rf"\b{re.escape(var)}->ref_count\s*(?:--|-=)", window):
            return
        if re.search(rf"\b{re.escape(var)}->ref_count\s*(?:==|<=|<)\s*1", window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="missing_refcount",
            rule="clang_cfg_shared_resource_freed_without_refcount_protocol",
            line=line,
            description=f"Shared resource `{var}` is freed without checking or updating its reference-count protocol.",
            root_cause="The close path bypasses outstanding-reference accounting before releasing a shared/listed object.",
            suggested_fix="Decrement/check the reference count and unlink the resource before freeing it.",
            source=f"ref_count evidence at line {ref_line.number}",
            sink=line.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {ref_line.number}: `{var}->ref_count` is maintained for the resource",
                f"line {line.number}: `{var}` is freed without a visible ref_count decrement or zero/one check",
            ],
            negative=[
                "Validator must confirm no helper on the same path performs the refcount protocol."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("refcount_state", ref_line, var, "ref_count", ref_line.text),
                    self._event("free_without_refcount", line, var, "", line.text),
                ],
                [ref_line.number, line.number],
            ),
        )

    def _maybe_emit_fd_leak_on_error_return(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if not self._is_return(line.text):
            return
        fd_data = self._find_open_fd_without_close(lines, line)
        if fd_data is None:
            return
        open_line, fd, api = fd_data
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="fd_leak",
            rule="clang_cfg_fd_open_return_without_close",
            line=line,
            description=f"File descriptor `{fd}` opened by `{api}` can return from the function without a matching close.",
            root_cause="The error/early-return path exits while the descriptor owner remains live.",
            suggested_fix="Close the descriptor on every return path or route exits through shared cleanup.",
            source=open_line.text,
            sink=line.text,
            confidence=0.78,
            impact_level="high",
            positive=[
                f"line {open_line.number}: `{fd}` receives `{api}` descriptor",
                f"line {line.number}: return occurs before a visible `close({fd})`",
            ],
            negative=[
                "Validator must confirm the descriptor was not transferred to a durable owner before this return."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("fd_open", open_line, fd, api, open_line.text),
                    self._event("return_without_fd_close", line, fd, "", line.text),
                ],
                [open_line.number, line.number],
            ),
        )

    def _maybe_emit_slot_overwrite_leak(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        body_hint = f"{self._function_name_hint(func_name, lines)}\n" + "\n".join(
            item.text for item in lines[: min(len(lines), 6)]
        )
        if not re.search(
            r"(?:register|upsert|insert|set|install|add|registry|slot|plugin)",
            body_hint,
            re.IGNORECASE,
        ):
            return
        assign = re.search(
            r"\b(?P<slot>[A-Za-z_]\w*)\s*->\s*(?P<field>context|ctx|cleanup)\s*=\s*(?P<rhs>[^;]+);",
            line.text,
        )
        if not assign:
            return
        slot = assign.group("slot")
        if not self._slot_pointer_is_indexed_registry(lines, line, slot):
            return
        region = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index])
        if re.search(
            rf"\b(?:free|SAFE_FREE|cleanup|destroy|release)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(slot)}\s*->",
            region,
            re.I,
        ):
            return
        if re.search(
            rf"\bif\s*\([^)]*\b{re.escape(slot)}\s*->\s*(?:context|ctx|cleanup|handle|name)", region
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_slot_overwrite_without_existing_owner_cleanup",
            line=line,
            description=f"Registry slot `{slot}` is overwritten without cleaning its existing owned fields.",
            root_cause="A hash/registry slot update can orphan the previous plugin or context state when collisions or duplicate names reuse the slot.",
            suggested_fix="Check whether the slot is occupied and run the old cleanup/release path before overwriting owned fields.",
            source=self._slot_pointer_source(lines, line, slot) or slot,
            sink=line.text,
            confidence=0.76,
            impact_level="high",
            positive=[
                f"line {line.number}: `{slot}->{assign.group('field')}` is overwritten in a registration/update path",
                "no cleanup of the previous slot owner is visible before the overwrite",
            ],
            negative=[
                "Validator must confirm the slot can already contain an owned context or plugin instance."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("slot_overwrite", line, slot, assign.group("field"), line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_stale_fd(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(r"\bclose\s*\(\s*(?P<fd>[A-Za-z_]\w*)\s*\)\s*;", line.text)
        if not match:
            return
        fd = match.group("fd")
        if not fd.startswith("g_") and self._release_followed_by_failure_return(lines, line):
            return
        if not fd.startswith("g_") and not self._fd_has_shared_owner_or_later_use(lines, line, fd):
            return
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
        if re.search(r"(?:g_[A-Za-z_]\w*fd|fd)\s*=\s*-1", later):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="stale_fd",
            rule="clang_cfg_fd_closed_without_owner_invalidation",
            line=line,
            description="File descriptor is closed without invalidating the owning/watched descriptor nearby.",
            root_cause="Later event dispatch can reuse a stale fd value after close.",
            suggested_fix="Set the owning descriptor to -1 under the same synchronization immediately after close.",
            source=fd,
            sink=line.text,
            confidence=0.7,
            positive=[f"line {line.number}: close without nearby fd=-1 invalidation"],
            negative=["Validator must confirm whether the fd is stored in shared watcher state."],
            ast_cfg=self._ast_cfg_pack(
                lines, [self._event("fd_close", line, fd, "close", line.text)], [line.number]
            ),
        )

    def _emit_leak_on_exit(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        state: ResourceState,
        line: ClangCfgLine,
        *,
        is_return: bool,
    ) -> None:
        carrier_text = "output argument" if state.carrier == "output_argument" else "return value"
        exit_text = "return edge" if is_return else "function exit"
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_acquire_without_release_on_exit",
            line=line,
            description=f"`{state.var}` is acquired from `{state.api}` and reaches {exit_text} unreleased.",
            root_cause=(
                "The local CFG state has an acquire event but no matching release or "
                "ownership transfer before the exit edge."
            ),
            suggested_fix=(
                "Release the resource on all exit paths or explicitly transfer ownership "
                "to the caller/container."
            ),
            source=f"{state.api}(...) at line {state.line.number}",
            sink=line.text or exit_text,
            confidence=0.76 if is_return else 0.7,
            positive=[
                f"line {state.line.number}: `{state.var}` acquired from `{state.api}` ({carrier_text})",
                f"line {line.number}: {exit_text} without a matching release in this function",
            ],
            negative=[
                "Validator must confirm whether ownership is transferred outside this local body."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("acquire", state.line, state.var, state.api, state.line.text),
                    self._event("exit", line, state.var, "", line.text),
                ],
                [state.line.number, line.number],
            ),
            bind_unique_resource_acquisition=True,
        )

    def _allocation_is_short_lived(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> Tuple[bool, str, Optional[ClangCfgLine]]:
        assigned = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
            r"[A-Za-z_]\w*(?:alloc|malloc|calloc|realloc)[A-Za-z_0-9]*\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not assigned:
            return False, "", None
        var = assigned.group("var")
        for item in lines[line.index + 1 : line.index + 20]:
            if re.search(
                rf"\b(?:free|SAFE_FREE|safe_free|_safe_free)\s*\(\s*{re.escape(var)}\s*\)",
                item.text,
            ):
                return True, var, item
        return False, var, None

    def _allocation_has_total_local_lifetime_proof(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        count_expr: str,
    ) -> bool:
        short_lived, var, release_line = self._allocation_is_short_lived(lines, line)
        if not short_lived or not var or release_line is None:
            return False
        if self._is_lifetime_sensitive_allocation_expr(
            count_expr, line.text
        ) and not self._has_narrowing_bound_proof(lines, line, count_expr):
            return False
        later = lines[line.index + 1 : release_line.index + 1]
        later_text = "\n".join(item.text for item in later)
        escapes = re.search(
            rf"\b(?:return\s+{re.escape(var)}|g_[A-Za-z_0-9]+\s*=\s*{re.escape(var)}|"
            rf"[A-Za-z_]\w*(?:->|\.)[A-Za-z_0-9]+\s*=\s*{re.escape(var)}|"
            rf"\*\s*[A-Za-z_]\w+\s*=\s*{re.escape(var)})",
            later_text,
        )
        if escapes:
            return False
        for item in later:
            if item.index >= release_line.index:
                break
            text = item.text.strip()
            if re.search(
                rf"\bif\s*\(\s*(?:!\s*{re.escape(var)}|{re.escape(var)}\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr|0)\s*==\s*{re.escape(var)})\s*\)\s*return\b",
                text,
            ):
                continue
            if re.search(r"\b(?:return|goto|break|continue)\b", text):
                return False
            if self._is_conditional_branch_header(text):
                return False
        return True

    @staticmethod
    def _is_lifetime_sensitive_allocation_expr(count_expr: str, line_text: str = "") -> bool:
        text = f"{count_expr} {line_text}".lower()
        return bool(
            re.search(
                r"\b[a-z0-9_]*(?:quota|limit|reserve|reserved|segment|window|cache|tls|thread|pool|"
                r"global|session|client|wire|header|packet|frame|record|payload|mmap|map)[a-z0-9_]*\b",
                text,
            )
            and not re.search(r"\b(?:uint8_t|uint16_t|unsigned\s+char|unsigned\s+short)\b", text)
        )

    @staticmethod
    def _resolve_recent_assignment_expr(
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: str,
    ) -> str:
        name = str(expr or "").strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            return ""
        for item in reversed(lines[max(0, line.index - 10) : line.index]):
            match = re.search(
                rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);",
                item.text,
            )
            if match:
                return match.group("rhs").strip()
            decl = re.search(
                rf"\b(?:size_t|uint(?:32|64)_t|int|unsigned(?:\s+int)?|long|unsigned\s+long)\s+"
                rf"{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);",
                item.text,
            )
            if decl:
                return decl.group("rhs").strip()
        return ""

    def _is_owned_pointer_array_element_release(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: str,
    ) -> bool:
        match = re.match(r"(?P<base>.+?)\s*\[[^\]]+\]\s*$", expr.strip())
        if not match:
            return False
        base = re.sub(r"\s+", "", match.group("base"))
        previous = "\n".join(item.text for item in lines[max(0, line.index - 80) : line.index])
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 20])
        base_re = re.escape(base)
        element_allocated = re.search(
            rf"{base_re}\s*\[[^\]]+\]\s*=\s*(?:\([^)]*\)\s*)?"
            r"[A-Za-z_]\w*(?:alloc|calloc|malloc|dup|new)[A-Za-z_0-9]*\s*\(",
            previous,
            re.IGNORECASE,
        )
        base_released = re.search(
            rf"\b(?:free|SAFE_FREE)\s*\(\s*{base_re}\s*\)",
            later,
        )
        conventional_pointer_array = re.search(
            r"(?:args|argv|items|children|entries|array|list)$", base
        )
        return bool(element_allocated or (base_released and conventional_pointer_array))

    def _fd_has_shared_owner_or_later_use(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        fd: str,
    ) -> bool:
        before = "\n".join(item.text for item in lines[max(0, line.index - 16) : line.index])
        if re.search(
            rf"(?:\bg_[A-Za-z_0-9]*fd\b|->[A-Za-z_0-9]*fd\b|\.[A-Za-z_0-9]*fd\b)\s*=\s*{re.escape(fd)}\b",
            before,
        ):
            return True
        if re.search(
            rf"\b(?:watch|register|cache|store)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(fd)}\b",
            before,
            re.I,
        ):
            return True
        later_lines = []
        for item in lines[line.index + 1 : line.index + 10]:
            if self._is_return(item.text):
                break
            later_lines.append(item.text)
        later = "\n".join(later_lines)
        return bool(
            re.search(
                rf"\b(?:read|recv|write|send|close|dup|fcntl|ioctl|mmap|munmap|_net_[A-Za-z_0-9]+)\s*"
                rf"\([^;]*\b{re.escape(fd)}\b",
                later,
            )
            or re.search(rf"\bg_[A-Za-z_0-9]*fd\b", later)
        )

    def _emit_use_after_release(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        var: str,
        free_line: ClangCfgLine,
        free_api: str,
        use_line: ClangCfgLine,
    ) -> None:
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="use_after_free",
            rule="clang_cfg_use_after_release",
            line=use_line,
            description=f"`{var}` is used after it has been released.",
            root_cause=(
                "The local CFG state marks the resource as released and no "
                "reset, reallocation, or ownership reacquire appears before use."
            ),
            suggested_fix=(
                "Move the use before release, keep a valid owned reference, or "
                "clear and guard the pointer after release."
            ),
            source=f"{free_api}({var}) at line {free_line.number}",
            sink=use_line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {free_line.number}: `{var}` released via `{free_api}`",
                f"line {use_line.number}: `{var}` is dereferenced or passed after release",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("release", free_line, var, free_api, free_line.text),
                    self._event("use", use_line, var, "", use_line.text),
                ],
                [free_line.number, use_line.number],
            ),
        )

    def _slot_pointer_is_indexed_registry(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        slot: str,
    ) -> bool:
        return bool(self._slot_pointer_source(lines, line, slot))

    def _slot_pointer_source(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        slot: str,
    ) -> str:
        escaped = re.escape(slot)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            if re.search(
                rf"\b{escaped}\s*=\s*&?\s*[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\s*\[[^\]]+\]",
                item.text,
            ):
                return item.text
        return ""

    def _find_open_fd_without_close(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        for item in reversed(lines[max(0, line.index - 28) : line.index]):
            match = re.search(
                r"\b(?P<fd>[A-Za-z_]\w*)\s*=\s*(?P<api>open|creat|socket|accept|dup|eventfd|memfd_create)\s*\(",
                item.text,
            )
            if not match:
                continue
            fd = match.group("fd")
            between = "\n".join(next_line.text for next_line in lines[item.index + 1 : line.index])
            if re.search(rf"\b{re.escape(fd)}\s*(?:<\s*0|==\s*-1)\b[^;]*\breturn\b", line.text):
                continue
            if re.search(rf"\b(?:close|closesocket)\s*\(\s*{re.escape(fd)}\s*\)", between):
                return None
            if re.search(
                rf"\b(?:register|store|watch|cache|take|adopt)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(fd)}\b",
                between,
                re.IGNORECASE,
            ):
                return None
            return item, fd, match.group("api")
        return None

    def _match_assignment_call(
        self, text: str, call_re: re.Pattern[str]
    ) -> Optional[Tuple[str, str, str]]:
        call = call_re.search(text)
        if not call:
            return None
        prefix = text[: call.start()]
        assign = re.search(
            r"(?P<lhs>[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?)\s*=\s*(?:\([^)]*\)\s*)?$",
            prefix,
        )
        if not assign:
            return None
        lhs = re.sub(r"\s+", "", assign.group("lhs"))
        return lhs, call.group("api"), call.group("args")

    def _match_out_param_acquire(self, text: str) -> Optional[Tuple[str, str, str, str]]:
        if not self._out_param_acquirers:
            return None
        call = self._out_acquire_call_re.search(text)
        if not call:
            return None
        status_var = ""
        prefix = text[: call.start()]
        assign = re.search(r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?$", prefix)
        if assign:
            status_var = assign.group("lhs")
        for arg in self._split_args(call.group("args")):
            match = re.match(r"\s*&\s*(?P<var>[A-Za-z_]\w*)\s*$", arg)
            if match:
                return match.group("var"), call.group("api"), call.group("args"), status_var
        return None

    def _match_null_reset(self, text: str) -> str:
        match = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:NULL|nullptr|0)\s*;", text)
        return match.group("var") if match else ""

    def _uses_freed_var(self, text: str, var: str, *, release_api_names: Set[str]) -> bool:
        if self._is_call_to(text, release_api_names):
            return False
        if self._is_var_redefined(text, var):
            return False
        if self._is_direct_deref(text, var):
            return True
        for api, args in self._calls(text):
            if api in release_api_names:
                continue
            if any(
                self._resource_var(arg) == var or self._resource_expr(arg) == var
                for arg in self._split_args(args)
            ):
                return True
        return False

    def _is_direct_deref(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        if re.search(rf"\b{escaped}\s*->", text):
            return True
        if re.search(rf"\*\s*{escaped}\b", text):
            return True
        if re.search(rf"\b{escaped}\s*\[", text):
            return True
        return False

    def _return_excludes_resource(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        if re.search(rf"\breturn\s+{escaped}\s*;", text):
            return True
        if re.search(rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*return\b", text):
            return True
        return False

    def _return_exits_null_failure_path(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> bool:
        if not re.search(r"\breturn\s+(?:NULL|nullptr|0|-1)\s*;", line.text):
            return False
        escaped = re.escape(var)
        null_guard = rf"\bif\s*\([^)]*(?:!\s*{escaped}|{escaped}\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr|0)\s*==\s*{escaped})"
        if re.search(null_guard, line.text):
            return True
        branch_start = self._enclosing_branch_start(lines, line)
        return bool(branch_start and re.search(null_guard, branch_start.text))

    def _resource_released_in_terminal_branch_before_return(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> bool:
        if not self._is_terminal_conditional_branch_line(lines, line):
            return False
        branch_start = self._enclosing_branch_start(lines, line)
        start_idx = branch_start.index if branch_start is not None else line.index
        for item in lines[start_idx : line.index + 1]:
            if item.block_id != line.block_id:
                continue
            if self._line_releases_resource_before_return(item.text, var):
                return True
        return False

    def _line_releases_resource_before_return(self, text: str, var: str) -> bool:
        release = self._release_call_re.search(text)
        if not release:
            return False
        arg = self._first_arg(release.group("args"))
        released = self._resource_expr(arg) or self._resource_var(arg)
        if released != var:
            return False
        ret = re.search(r"\breturn\b", text)
        return ret is None or release.start() < ret.start()

    @staticmethod
    def _return_line_after_release(
        lines: Sequence[ClangCfgLine], line: ClangCfgLine
    ) -> Optional[ClangCfgLine]:
        for item in lines[line.index + 1 : line.index + 5]:
            text = item.text.strip()
            if not text or text in {"}", "};"}:
                continue
            if re.fullmatch(
                r"(?:UNLOCK|pthread_mutex_unlock|spin_unlock|mtx_unlock)\s*\([^;]*\)\s*;",
                text,
            ):
                continue
            return item if re.search(r"\breturn\b", text) else None
        return None

    @staticmethod
    def _release_followed_by_failure_return(
        lines: Sequence[ClangCfgLine], line: ClangCfgLine
    ) -> bool:
        for item in lines[line.index + 1 : line.index + 5]:
            text = item.text.strip()
            if not text or text in {"}", "};"}:
                continue
            return bool(re.search(r"\breturn\s+(?:NULL|nullptr|-1)\s*;", text))
        return False

    def _is_status_failure_return(self, text: str, status_var: str) -> bool:
        return self._is_status_failure_condition(text, status_var) and bool(
            re.search(r"\breturn\b", text)
        )

    def _return_is_status_failure_exit(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        status_var: str,
    ) -> bool:
        if self._is_status_failure_return(line.text, status_var):
            return True
        if not self._is_return(line.text):
            return False
        branch_start = self._enclosing_branch_start(lines, line)
        return bool(
            branch_start and self._is_status_failure_condition(branch_start.text, status_var)
        )

    def _is_status_guard_line(self, text: str, status_var: str) -> bool:
        return self._is_status_failure_condition(text, status_var) or self._is_status_success_guard(
            text, status_var
        )

    @staticmethod
    def _is_status_failure_condition(text: str, status_var: str) -> bool:
        if not status_var:
            return False
        escaped = re.escape(status_var)
        patterns = [
            rf"\bif\s*\(\s*{escaped}\s*!=\s*0\s*\)",
            rf"\bif\s*\(\s*0\s*!=\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*<\s*0\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*(?:FAILED|IS_ERR)\s*\(\s*{escaped}\s*\)\s*\)",
        ]
        return any(re.search(pattern, text) for pattern in patterns)

    @staticmethod
    def _is_status_success_guard(text: str, status_var: str) -> bool:
        if not status_var:
            return False
        escaped = re.escape(status_var)
        patterns = [
            rf"\bif\s*\(\s*{escaped}\s*==\s*0\s*\)",
            rf"\bif\s*\(\s*0\s*==\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*>=\s*0\s*\)",
            rf"\bif\s*\(\s*SUCCESS\s*==\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*==\s*SUCCESS\s*\)",
            rf"\bif\s*\(\s*(?:SUCCEEDED|OK)\s*\(\s*{escaped}\s*\)\s*\)",
        ]
        return any(re.search(pattern, text) for pattern in patterns)

    def _is_transfer(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        # Mutating the acquired object's contents does not rebind or transfer
        # the pointer identity.  In particular, ``p[0] = ...`` and ``*p = ...``
        # must remain ordinary pointee use.  Transfers to another out-param,
        # field, global, container, callback or callee are handled below.
        pointee_write = re.search(
            rf"(?:\*\s*{escaped}\b|\b{escaped}\s*(?:\[[^\]]+\]|->\s*[A-Za-z_]\w*|\.\s*[A-Za-z_]\w*))\s*=(?!=)",
            text,
        )
        if pointee_write:
            return False
        transfer_patterns = [
            rf"\breturn\s+{escaped}\s*;",
            rf"\*\s*[A-Za-z_]\w*\s*=\s*{escaped}\s*;",
            rf"\bg_[A-Za-z_]\w*\s*=\s*{escaped}\s*;",
            rf"\b[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+\s*=\s*{escaped}\s*;",
            rf"\b[A-Za-z_]\w*\s*\[[^\]]+\]\s*=\s*{escaped}\s*;",
        ]
        if any(re.search(pattern, text) for pattern in transfer_patterns):
            return True
        lower = text.lower()
        if var in text and re.search(
            r"\b(?:append|insert|push|enqueue|register|attach|set|put|add)\w*\s*\(", lower
        ):
            return True
        return False

    def _uses_resource_value(self, text: str, var: str) -> bool:
        if self._is_var_redefined(text, var):
            return False
        if self._is_direct_deref(text, var):
            return True
        for _api, args in self._calls(text):
            if any(self._resource_var(arg) == var for arg in self._split_args(args)):
                return True
        return False

    @staticmethod
    def _is_global_owner_lvalue(value: str) -> bool:
        """Identify explicit global storage, not a naming-only local alias."""

        return bool(
            re.fullmatch(
                r"g_[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*",
                re.sub(r"\s+", "", str(value or "")),
            )
        )

    def _is_call_to(self, text: str, names: Set[str]) -> bool:
        if not names:
            return False
        return any(api in names for api, _ in self._calls(text))
