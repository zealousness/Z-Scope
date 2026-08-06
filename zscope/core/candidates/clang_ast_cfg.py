"""Clang-profile AST/CFG candidate generation.

The Clang backend in this project gives us clangd-indexed functions, call
edges, and source ranges rather than a libclang AST.  This checker therefore
builds a small statement/CFG view from clangd function bodies and applies
classic intraprocedural SAST state machines over that view.  Its output is
evidence only: every candidate still goes through the Validator Agent.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

if TYPE_CHECKING:
    from ...semantics.models import LocalPatternSemantics
    from ...orchestration.subagents import SubAgentTicket


@dataclass(frozen=True)
class ClangCfgLine:
    number: int
    raw: str
    text: str
    index: int
    block_id: int


@dataclass(frozen=True)
class ResourceState:
    var: str
    api: str
    line: ClangCfgLine
    carrier: str
    status_var: str = ""
    null_guarded: bool = False
    status_guarded: bool = False
    transferred: bool = False


@dataclass(frozen=True)
class LockState:
    lock_id: str
    api: str
    line: ClangCfgLine


class ClangAstCfgCandidateGenerator:
    """Generate evidence-backed candidates from a Clang-style local CFG view."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
    _CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    _CONTROL_RE = re.compile(r"^\s*(?:if|else|for|while|switch|case|default)\b")

    _CWE_BY_CLASS = {
        "memory_leak": "CWE-401",
        "heap_overflow": "CWE-122",
        "buffer_overread": "CWE-126",
        "buffer_underread": "CWE-127",
        "buffer_underwrite": "CWE-124",
        "buffer_underflow": "CWE-127",
        "double_free": "CWE-415",
        "use_after_free": "CWE-416",
        "missing_unlock": "CWE-667",
        "lock_protocol_violation": "CWE-832",
        "null_pointer_dereference": "CWE-476",
        "unchecked_allocation": "CWE-690",
        "realloc_misuse": "CWE-401",
        "bad_parameter_or_api_misuse": "CWE-252",
        "bounds": "CWE-125",
        "protocol_validation": "CWE-20",
        "integer_overflow": "CWE-190",
        "format_string": "CWE-134",
        "command_injection": "CWE-78",
        "toctou": "CWE-367",
        "race": "CWE-362",
        "refcount_race": "CWE-362",
        "object_publication": "CWE-362",
        "double_checked_locking": "CWE-362",
        "lost_wakeup": "CWE-366",
        "signed_unsigned": "CWE-195",
        "off_by_one": "CWE-193",
        "alignment": "CWE-704",
        "stale_fd": "CWE-672",
        "unchecked_return": "CWE-252",
        "missing_refcount": "CWE-772",
        "held_lock_callback": "CWE-667",
        "stack_escape": "CWE-562",
        "uninitialized_read": "CWE-457",
        "invalid_free": "CWE-590",
        "out_of_bounds_write": "CWE-787",
        "untrusted_pointer": "CWE-822",
        "out_of_range_pointer_offset": "CWE-823",
        "uninitialized_pointer": "CWE-824",
        "resource_allocation_without_limits": "CWE-770",
        "fd_leak": "CWE-775",
        "stack_overflow": "CWE-121",
        "fd_encoding_mismatch": "CWE-587",
        "state_inconsistency": "CWE-672",
        "version_filtering": "CWE-20",
        "size_limit_mismatch": "CWE-131",
        "busy_loop": "CWE-835",
        "dynamic_array_race": "CWE-362",
        "file_type_validation": "CWE-20",
        "premature_destroy": "CWE-416",
        "unsynchronized_shared_state": "CWE-362",
        "permission": "CWE-732",
        "key_truncation": "CWE-187",
        "key_generation_race": "CWE-362",
    }
    _SKILL_BY_CLASS = {
        "memory_leak": "resource_lifecycle",
        "heap_overflow": "memory",
        "buffer_overread": "memory",
        "buffer_underread": "memory",
        "buffer_underwrite": "memory",
        "buffer_underflow": "memory",
        "double_free": "temporal_memory",
        "use_after_free": "temporal_memory",
        "missing_unlock": "concurrency_lock_order",
        "lock_protocol_violation": "concurrency_lock_order",
        "null_pointer_dereference": "memory",
        "unchecked_allocation": "null_and_failure",
        "realloc_misuse": "resource_lifecycle",
        "bad_parameter_or_api_misuse": "null_and_failure",
        "bounds": "memory",
        "protocol_validation": "ownership_contract",
        "integer_overflow": "memory",
        "format_string": "memory",
        "command_injection": "string_and_format",
        "toctou": "resource_lifecycle",
        "race": "concurrency_lock_order",
        "refcount_race": "shared_state_race",
        "object_publication": "concurrency_lock_order",
        "double_checked_locking": "concurrency_lock_order",
        "lost_wakeup": "concurrency_lock_order",
        "signed_unsigned": "bounds_and_integer",
        "off_by_one": "memory",
        "alignment": "memory",
        "stale_fd": "resource_lifecycle",
        "unchecked_return": "resource_lifecycle",
        "missing_refcount": "resource_lifecycle",
        "held_lock_callback": "concurrency_lock_order",
        "stack_escape": "temporal_memory",
        "uninitialized_read": "memory",
        "invalid_free": "temporal_memory",
        "out_of_bounds_write": "memory",
        "untrusted_pointer": "memory",
        "out_of_range_pointer_offset": "memory",
        "uninitialized_pointer": "memory",
        "resource_allocation_without_limits": "resource_lifecycle",
        "fd_leak": "resource_lifecycle",
        "stack_overflow": "memory",
        "fd_encoding_mismatch": "ownership_contract",
        "state_inconsistency": "resource_lifecycle",
        "version_filtering": "ownership_contract",
        "size_limit_mismatch": "bounds_and_integer",
        "busy_loop": "concurrency_lock_order",
        "dynamic_array_race": "shared_state_race",
        "file_type_validation": "ownership_contract",
        "premature_destroy": "temporal_memory",
        "unsynchronized_shared_state": "shared_state_race",
        "permission": "ownership_contract",
        "key_truncation": "ownership_contract",
        "key_generation_race": "shared_state_race",
    }
    _RESOURCE_BY_CLASS = {
        "memory_leak": "memory",
        "heap_overflow": "memory",
        "buffer_overread": "memory",
        "buffer_underread": "memory",
        "buffer_underwrite": "memory",
        "buffer_underflow": "memory",
        "double_free": "memory",
        "use_after_free": "memory",
        "missing_unlock": "lock",
        "lock_protocol_violation": "lock",
        "null_pointer_dereference": "memory",
        "unchecked_allocation": "memory",
        "realloc_misuse": "memory",
        "bad_parameter_or_api_misuse": "resource",
        "bounds": "memory",
        "protocol_validation": "protocol",
        "integer_overflow": "integer",
        "format_string": "format_string",
        "command_injection": "process",
        "toctou": "file",
        "race": "shared_state",
        "refcount_race": "shared_state",
        "object_publication": "shared_state",
        "double_checked_locking": "shared_state",
        "lost_wakeup": "condition_variable",
        "signed_unsigned": "memory",
        "off_by_one": "memory",
        "alignment": "memory",
        "stale_fd": "file_descriptor",
        "unchecked_return": "error_status",
        "missing_refcount": "resource_lifecycle",
        "held_lock_callback": "lock",
        "stack_escape": "memory",
        "uninitialized_read": "memory",
        "invalid_free": "memory",
        "out_of_bounds_write": "memory",
        "untrusted_pointer": "memory",
        "out_of_range_pointer_offset": "memory",
        "uninitialized_pointer": "memory",
        "resource_allocation_without_limits": "memory",
        "fd_leak": "file_descriptor",
        "stack_overflow": "memory",
        "fd_encoding_mismatch": "file_descriptor",
        "state_inconsistency": "shared_state",
        "version_filtering": "protocol",
        "size_limit_mismatch": "memory",
        "busy_loop": "cpu",
        "dynamic_array_race": "shared_state",
        "unsynchronized_shared_state": "shared_state",
        "permission": "file_permission",
        "key_truncation": "key",
        "key_generation_race": "shared_state",
    }
    _GENERIC_VALIDATION_BUDGET_CLASSES = {
        "integer_overflow",
        "protocol_validation",
        "resource_allocation_without_limits",
        "version_filtering",
    }
    _EXACT_SINK_CLASSES = {
        "bounds",
        "buffer_overflow",
        "heap_overflow",
        "buffer_overread",
        "buffer_underread",
        "buffer_underwrite",
        "buffer_underflow",
        "double_free",
        "fd_leak",
        "invalid_free",
        "memory_leak",
        "signed_unsigned",
        "stack_overflow",
        "use_after_free",
        "key_truncation",
    }

    def __init__(
        self,
        semantics: Optional["LocalPatternSemantics"] = None,
        semantic_overlay: Optional[Dict[str, Any]] = None,
        tooling_evidence_provider: Optional[Callable[..., Dict[str, Any]]] = None,
    ):
        self.semantics = self._default_semantics()
        if semantics is not None:
            self.semantics.merge(semantics)
        self.semantic_overlay = semantic_overlay or {}
        self.tooling_evidence_provider = tooling_evidence_provider
        self._compile_api_models()

    def generate_issues(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        lines = self._parse_lines(code)
        if not lines:
            return []
        allowed = set(allowed_skills) if allowed_skills is not None else None
        issues: List[Dict[str, Any]] = []
        self._run_resource_state_machines(issues, func_name, file_path, lines, allowed)
        self._run_lock_state_machine(issues, func_name, file_path, lines, allowed)
        self._run_common_sast_rules(issues, func_name, file_path, lines, allowed)
        return self._dedupe(issues)

    def generate_tickets(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List["SubAgentTicket"]:
        return [
            self.issue_to_ticket(issue)
            for issue in self.generate_issues(
                func_name,
                code,
                file_path,
                allowed_skills=allowed_skills,
            )
        ]

    def issue_to_ticket(self, issue: Dict[str, Any]) -> "SubAgentTicket":
        from ...orchestration.subagents import SubAgentTicket

        defect_class = str(issue.get("defect_class") or issue.get("subcategory") or "unknown")
        evidence = dict(issue.get("evidence_pack") or {})
        evidence.setdefault("positive_evidence", issue.get("positive_evidence") or [])
        evidence.setdefault("negative_evidence", issue.get("negative_evidence") or [])
        return SubAgentTicket(
            id=str(issue.get("candidate_id") or issue.get("id")),
            skill=self._SKILL_BY_CLASS.get(defect_class, "resource_lifecycle"),
            task=(
                f"Verify clang AST/CFG {defect_class} candidate. Confirm path "
                "feasibility, ownership or lock state transitions, and guard sufficiency."
            ),
            trigger=str(issue.get("rule") or defect_class),
            line=self._line_from_location(str(issue.get("location") or "")),
            context_slice=str(issue.get("code_snippet") or ""),
            priority_score=self._priority_for_issue(issue),
            priority_reasons=[
                "clang_ast_cfg_candidate",
                defect_class,
                f"priority_group={issue.get('candidate_priority_group', '')}",
                f"rule_confidence={issue.get('rule_confidence', issue.get('confidence', 0.5))}",
            ],
            origin=str(issue.get("source") or issue.get("location") or ""),
            sink=str(issue.get("sink") or issue.get("location") or ""),
            resource_kind=self._RESOURCE_BY_CLASS.get(defect_class, "unknown"),
            source="clang_ast_cfg",
            evidence=evidence,
        )

    def _compile_api_models(self) -> None:
        semantics = self.semantics
        self._allocator_names = self._semantics_names(semantics, "allocators") | self._checker_defaults("extended_allocators")
        self._calloc_names = self._semantics_names(semantics, "calloc_allocators")
        self._reallocator_names = self._semantics_names(semantics, "reallocators")
        self._deallocator_names = self._semantics_names(semantics, "deallocators")
        self._lock_names = self._semantics_names(semantics, "lock_apis") | self._checker_defaults("extended_lock_apis")
        self._unlock_names = self._semantics_names(semantics, "unlock_apis") | self._checker_defaults("extended_unlock_apis")
        self._copy_sink_names = self._semantics_names(semantics, "copy_sinks") | self._checker_defaults("string_copy_sinks")
        self._send_sink_names = {"send", "write", "sendto", "sendmsg", "_net_send_data"}
        self._format_sink_names = {"printf", "fprintf", "syslog", "vprintf", "vfprintf"}
        self._open_sink_names = {"open", "fopen", "creat"}
        self._macro_lock_names: Set[str] = set()
        self._macro_unlock_names: Set[str] = set()

        self._return_acquirers = set(self._allocator_names | self._calloc_names | self._reallocator_names)
        self._out_param_acquirers: Set[str] = set()
        self._release_names = set(self._deallocator_names)

        for row in self._overlay_rows("resource_models"):
            name = str(row.get("name") or "").strip()
            if not self._is_ident(name):
                continue
            kind = str(row.get("kind") or "").lower()
            carrier = str(row.get("carrier") or "").lower()
            text = " ".join(
                str(row.get(key) or "")
                for key in ("description", "return_semantics", "memory_behavior")
            ).lower()
            if kind in {"allocator", "calloc", "reallocator", "resource", "resource_acquire"}:
                if carrier == "return_value":
                    self._return_acquirers.add(name)
                if self._mentions_output_argument(text):
                    self._out_param_acquirers.add(name)
            if kind in {"deallocator", "resource_release"}:
                self._release_names.add(name)
            if kind == "copy" or carrier == "copy_arguments":
                self._copy_sink_names.add(name)

        for row in self._overlay_rows("macro_models"):
            name = str(row.get("name") or "").strip()
            if not self._is_ident(name):
                continue
            kind = str(row.get("kind") or "").lower()
            behavior = row.get("concurrency_behavior") if isinstance(row.get("concurrency_behavior"), dict) else {}
            description = str(row.get("description") or "").lower()
            haystack = " ".join([kind, description, " ".join(str(v).lower() for v in behavior.values())])
            if kind == "lock" or behavior.get("acquires_lock") or "acquire" in haystack and "lock" in haystack:
                self._macro_lock_names.add(name)
            if kind == "unlock" or behavior.get("releases_lock") or "release" in haystack and "lock" in haystack:
                self._macro_unlock_names.add(name)

        self._alloc_call_re = self._call_re(self._return_acquirers)
        self._out_acquire_call_re = self._call_re(self._out_param_acquirers)
        self._realloc_call_re = self._call_re(self._reallocator_names)
        self._release_call_re = self._call_re(self._release_names)
        self._lock_call_re = self._call_re(self._lock_names, extra_patterns=[r"pthread_rwlock_[rw]dlock"])
        self._unlock_call_re = self._call_re(self._unlock_names)

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
                        negative=["Validator must confirm the API does not define the output argument on failure."],
                        ast_cfg=self._ast_cfg_pack(
                            lines,
                            [
                                self._event("out_param_acquire", state.line, state.var, state.api, state.line.text),
                                self._event("use_before_status_guard", line, state.var, "", line.text),
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
                    if (
                        return_line is not None
                        and self._uses_freed_var(return_line.text, var, release_api_names=self._release_names)
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
                if self._is_var_redefined(line.text, var) or self._match_null_reset(line.text) == var:
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
                        negative=["No null guard for the acquired value appears before the dereference."],
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
                        or self._resource_released_in_terminal_branch_before_return(lines, line, var)
                    ):
                        continue
                    if state.carrier == "output_argument" and self._return_is_status_failure_exit(lines, line, state.status_var):
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

    def _run_lock_state_machine(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        signature = "\n".join(item.text for item in lines[:3])
        if (
            re.search(r"\b[A-Za-z_]\w*unlock[A-Za-z_]\w*\s*\(", signature, re.I)
            and any(
                re.search(r"\bpthread_(?:mutex|rwlock)_unlock\s*\(", item.text)
                for item in lines
            )
        ):
            return
        held: List[LockState] = []
        for line in lines:
            # Macro definitions and thin unlock wrappers describe a protocol;
            # they are not call sites that can establish whether a caller
            # holds the lock.  Treating their bodies as ordinary functions
            # produced one false candidate for every use of the macro.
            if line.text.lstrip().startswith("#"):
                continue
            if (
                "wrapper" in func_name.lower()
                and re.search(r"\b(?:unlock|pthread_mutex_unlock|pthread_rwlock_unlock)\b", line.text, re.I)
            ):
                continue
            lock = self._match_lock(line.text)
            if lock:
                api, lock_id = lock
                held.append(LockState(lock_id=lock_id, api=api, line=line))
            unlock = self._match_unlock(line.text)
            if unlock and not held:
                api, lock_id = unlock
                self._emit_unlock_without_matching_lock(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    line,
                    api,
                    lock_id,
                )
            elif unlock and held:
                _, lock_id = unlock
                # An unlock on a branch that returns does not release the
                # fall-through path.  Keeping it in the linear state machine
                # made the later normal-path unlock look unmatched.
                if not self._is_terminal_conditional_branch_line(lines, line):
                    match_idx = next(
                        (idx for idx in range(len(held) - 1, -1, -1) if held[idx].lock_id == lock_id),
                        len(held) - 1,
                    )
                    held.pop(match_idx)
            if not held or not self._is_return(line.text):
                continue
            if self._is_terminal_conditional_branch_line(lines, line):
                continue
            if self._return_is_error_guard_for_lock(line.text, held[-1].lock_id):
                continue
            lock_state = held[-1]
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="missing_unlock",
                rule="clang_cfg_return_with_lock_held",
                line=line,
                description=f"Function returns while `{lock_state.lock_id}` appears to be held.",
                root_cause=(
                    "The synthesized CFG path enters a return edge after a lock acquire "
                    "without a matching unlock event."
                ),
                suggested_fix=(
                    "Release the lock on every return path or route exits through a common "
                    "cleanup block."
                ),
                source=f"{lock_state.api}({lock_state.lock_id}) at line {lock_state.line.number}",
                sink=line.text,
                confidence=0.8,
                positive=[
                    f"line {lock_state.line.number}: lock acquired via `{lock_state.api}`",
                    f"line {line.number}: return edge reached before matching unlock",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("lock", lock_state.line, lock_state.lock_id, lock_state.api, lock_state.line.text),
                        self._event("return", line, lock_state.lock_id, "", line.text),
                    ],
                    [lock_state.line.number, line.number],
                ),
            )
            held.clear()

    def _emit_unlock_without_matching_lock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        api: str,
        lock_id: str,
    ) -> None:
        recent = "\n".join(item.text for item in lines[max(0, line.index - 8) : line.index])
        if re.search(r"\b(?:expects|requires|must_hold|held_by_caller)\b", recent, re.IGNORECASE):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="lock_protocol_violation",
            rule="clang_cfg_unlock_without_matching_lock",
            line=line,
            description=f"`{api}` releases `{lock_id}` without a visible matching acquire in the local function body.",
            root_cause=(
                "The local lock-state path reaches an unlock operation while no matching lock "
                "acquire has been observed."
            ),
            suggested_fix=(
                "Acquire the same lock before the unlock, remove the stray unlock, or document "
                "and enforce a caller-held-lock contract."
            ),
            source="local lock-state machine",
            sink=line.text,
            confidence=0.72,
            positive=[f"line {line.number}: `{api}` releases `{lock_id}` with no prior local acquire"],
            negative=["Validator must confirm the function is not exclusively called with this lock already held."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("unlock_without_local_lock", line, lock_id, api, line.text)],
                [line.number],
            ),
        )

    def _run_common_sast_rules(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        length_fields: Dict[str, Tuple[ClangCfgLine, str]] = {}
        permission_check_line: Optional[ClangCfgLine] = None
        unaligned_ptrs: Dict[str, ClangCfgLine] = {}
        held_locks: List[ClangCfgLine] = []
        emitted_shared_state: Set[str] = set()
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]] = {}
        aggregate_field_writes: Dict[str, Set[str]] = {}
        signed_io_reads: Dict[str, ClangCfgLine] = {}
        signed_size_casts: Dict[str, Tuple[ClangCfgLine, str]] = {}
        command_env_vars: Dict[str, ClangCfgLine] = {}
        heap_thread_allocs: Dict[str, ClangCfgLine] = {}
        heap_thread_released: Set[str] = set()
        heap_thread_sinks: Dict[str, Tuple[ClangCfgLine, str]] = {}

        for idx, line in enumerate(lines):
            text = line.text
            self._track_local_aggregate(line, local_aggregates, aggregate_field_writes)
            self._track_heap_thread_argument_owner(
                line,
                heap_thread_allocs,
                heap_thread_released,
                heap_thread_sinks,
            )

            length_def = re.search(
                r"\b(?:size_t|uint(?:32|64)_t|int|unsigned(?:\s+int)?)\s+"
                r"(?P<var>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*=\s*"
                r"(?P<src>[A-Za-z_]\w*(?:->|\.)[A-Za-z_0-9]*(?:len|length|size)[A-Za-z_0-9]*)\s*;",
                text,
                re.IGNORECASE,
            )
            if length_def:
                length_fields[length_def.group("var")] = (line, length_def.group("src"))

            for len_var, (src_line, src_expr) in list(length_fields.items()):
                if line.index <= src_line.index:
                    continue
                if not self._copy_uses_length(text, len_var):
                    continue
                guard_window = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index])
                if re.search(
                    rf"\b{re.escape(len_var)}\b\s*[<>]=?\s*[^;]*(?:data_len|buf_len|buffer_len|remaining|capacity|sizeof|len\s*-)",
                    guard_window,
                    re.IGNORECASE,
                ):
                    continue
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="bounds",
                    rule="clang_cfg_external_length_field_reaches_copy",
                    line=line,
                    description=f"Length field `{src_expr}` reaches a copy sink without a visible backing-buffer length guard.",
                    root_cause="A serialized or structured length field is trusted without proving the input buffer contains that many bytes.",
                    suggested_fix="Validate the field against the remaining input length before copying or indexing.",
                    source=f"{src_expr} at line {src_line.number}",
                    sink=text,
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        f"line {src_line.number}: `{len_var}` is loaded from `{src_expr}`",
                        f"line {line.number}: `{len_var}` controls a copy length",
                    ],
                    negative=["Validator must confirm no earlier whole-buffer guard constrains the field."],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event("length_field_load", src_line, len_var, "", src_line.text),
                            self._event("copy_length_use", line, len_var, "", text),
                        ],
                        [src_line.number, line.number],
                    ),
                )
                length_fields.pop(len_var, None)

            self._maybe_emit_integer_overflow(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_format_string(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_command_injection(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                command_env_vars,
            )
            self._maybe_emit_signed_unsigned(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                signed_io_reads,
                signed_size_casts,
            )
            self._maybe_emit_off_by_one(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_stack_array_overflow(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_heap_copy_length_mismatch(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_offset_length_copy_overread(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_pointer_backtrack_underflow(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_invalid_free(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_interior_free_alias(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_unchecked_allocation_result(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_fixed_array_count_overflow(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_key_truncation(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_wire_integer_pointer_deref(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_unchecked_object_offset_access(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_uninitialized_pointer_use(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_unbounded_heap_allocation(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_slot_overwrite_leak(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_key_generation_race(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_file_type_validation_order(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_active_owner_premature_destroy(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_fd_leak_on_error_return(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_unchecked_strchr_result(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_thread_stack_escape(issues, func_name, file_path, lines, allowed_skills, line, local_aggregates)
            self._maybe_emit_partial_aggregate_send(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                local_aggregates,
                aggregate_field_writes,
            )
            self._maybe_track_or_emit_alignment(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                unaligned_ptrs,
            )
            self._maybe_emit_macro_lock_race(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_fd_encoding_mismatch(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_global_state_not_restored_on_error(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_wide_count_without_magic_guard(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_fixed_limit_spec_mismatch(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_recv_retry_without_budget(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_global_dynamic_array_resize_race(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_ignored_protocol_version(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_unchecked_param_global_array_index(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )

            if self._match_lock(text):
                held_locks.append(line)
            self._maybe_emit_callback_under_lock(issues, func_name, file_path, lines, allowed_skills, line, held_locks)
            if self._match_unlock(text) and held_locks:
                held_locks.pop()

            if self._is_path_check(text):
                permission_check_line = line
            elif permission_check_line and re.search(r"\b(?:open|fopen|creat)\s*\(", text):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="toctou",
                    rule="clang_cfg_path_check_before_open",
                    line=line,
                    description="A pathname is checked separately from a later open/use operation.",
                    root_cause="The path can change between the permission/existence check and the later open.",
                    suggested_fix="Open the file first with secure flags, then validate the opened descriptor.",
                    source=f"path check at line {permission_check_line.number}",
                    sink=text,
                    confidence=0.8,
                    positive=[
                        f"line {permission_check_line.number}: pathname check",
                        f"line {line.number}: later pathname open/use",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event("path_check", permission_check_line, "path", "", permission_check_line.text),
                            self._event("path_use", line, "path", "", text),
                        ],
                        [permission_check_line.number, line.number],
                    ),
                )
                permission_check_line = None

            self._maybe_emit_concurrency_protocols(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
                emitted_shared_state,
            )
            self._maybe_emit_refcount_update_after_unlock(issues, func_name, file_path, lines, allowed_skills, line, idx)
            self._maybe_emit_stale_fd(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_borrowed_callback_global(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
            )
            self._maybe_emit_mapping_unmap_without_invalidation(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_error_log_allocation_leak(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_role_release_mismatch(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_registry_unlink_free_after_unlock(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_owned_member_leak_on_parent_release(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_unchecked_insert_handoff(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_protocol_length_copy_without_packet_bound(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_header_length_copy_without_wire_bound(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_probe_error_returns_success(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
            )
            self._maybe_emit_refcount_free_without_protocol(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
            )

        self._emit_heap_thread_argument_owner_leaks(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            heap_thread_allocs,
            heap_thread_released,
            heap_thread_sinks,
        )
        self._emit_unlocked_global_state_write_candidates(issues, func_name, file_path, lines, allowed_skills)
        self._emit_permission_mode_candidate(issues, func_name, file_path, lines, allowed_skills)
        self._emit_timer_callback_lock_order_candidate(issues, func_name, file_path, lines, allowed_skills)

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
                negative=["Validator must confirm ownership is not intentionally retained in a global field."],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("heap_thread_arg_owner", alloc_line, var, "", alloc_line.text),
                        self._event("thread_arg_escape", sink_line, var, worker, sink_line.text),
                    ],
                    [alloc_line.number, sink_line.number],
                ),
            )

    def _maybe_emit_unchecked_strchr_result(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        risky_use = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*(?:-|\[|->|\.)",
            line.text,
        )
        if not risky_use:
            return
        var = risky_use.group("var")
        assign_line = None
        for item in reversed(lines[max(0, line.index - 10) : line.index]):
            if re.search(rf"\b{re.escape(var)}\s*=\s*strchr\s*\(", item.text):
                assign_line = item
                break
        if assign_line is None:
            return
        between = lines[assign_line.index + 1 : line.index]
        if any(re.search(rf"\b{re.escape(var)}\s*(?:-|\[|->|\.)", item.text) for item in between):
            return
        guard_window = "\n".join(item.text for item in between)
        if re.search(rf"\b{re.escape(var)}\s*(?:!=\s*NULL|==\s*NULL|!=\s*0|==\s*0|\?)|!\s*{re.escape(var)}\b", guard_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="null_pointer_dereference",
            rule="clang_cfg_unchecked_strchr_result",
            line=line,
            description=f"`{var}` from `strchr` is used without a visible NULL check.",
            root_cause="When the delimiter is absent, `strchr` returns NULL and later pointer arithmetic or indexing dereferences that NULL-derived value.",
            suggested_fix=f"Check `{var}` for NULL before pointer arithmetic, indexing, or dereference.",
            source=f"strchr result at line {assign_line.number}",
            sink=line.text,
            confidence=0.88,
            impact_level="high",
            positive=[
                f"line {assign_line.number}: `{var}` receives `strchr(...)`",
                f"line {line.number}: `{var}` is used before any visible NULL guard",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("strchr_result", assign_line, var, "strchr", assign_line.text),
                    self._event("unchecked_pointer_use", line, var, "", line.text),
                ],
                [assign_line.number, line.number],
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
                    self._event("role_check", role_line, f"{node}->role", role_value, role_line.text),
                    self._event("role_release", line, node, release_role, line.text),
                ],
                [role_line.number, line.number],
            ),
        )

    def _maybe_emit_registry_unlink_free_after_unlock(
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
        _api, raw_released = release
        released = self._resource_expr(raw_released) or self._resource_var(raw_released)
        if not (released == "node" or released.startswith("node->")):
            return
        body = "\n".join(item.text for item in lines)
        if "children" in body:
            return
        prefix = lines[: line.index]
        insert_line = self._last_line_matching(prefix, re.compile(r"\b[A-Za-z_]\w*insert_locked\s*\(\s*node\s*\)"))
        unlink_line = self._last_line_matching(prefix, re.compile(r"\bg_[A-Za-z_0-9.]*registry[A-Za-z_0-9.]*\.head\s*=\s*node->next\s*;"))
        unlock_line = self._last_line_matching(prefix, re.compile(r"\bUNLOCK\s*\([^)]*registry[^)]*\)"))
        lock_line = self._last_line_matching(prefix, re.compile(r"\bLOCK\s*\([^)]*registry[^)]*\)"))
        if not (insert_line and unlink_line and unlock_line and lock_line):
            return
        if not (lock_line.index < insert_line.index < unlink_line.index < unlock_line.index < line.index):
            return
        for item in lines[unlock_line.index + 1 : line.index]:
            prior_release = self._match_release(item.text)
            if not prior_release:
                continue
            prior_arg = self._resource_expr(prior_release[1]) or self._resource_var(prior_release[1])
            if prior_arg == "node" or prior_arg.startswith("node->"):
                return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="race",
            rule="clang_cfg_registry_unlink_free_after_unlock",
            line=line,
            description="A shared registry node is unlinked under the registry lock but freed after the lock is released.",
            root_cause="Concurrent readers can retain a borrowed pointer from the registry while cleanup drops the lock and releases the node members.",
            suggested_fix="Hold the lifetime lock through the full removal/free protocol or add reference-counted handoff before freeing the node.",
            source=unlink_line.text,
            sink=line.text,
            confidence=0.82,
            impact_level="critical",
            positive=[
                f"line {insert_line.number}: node is inserted into shared registry state",
                f"line {unlink_line.number}: registry head is advanced to unlink `node`",
                f"line {unlock_line.number}: registry lock is released before cleanup",
                f"line {line.number}: node-owned storage is freed after the unlock window",
            ],
            negative=["Validator must confirm whether registry readers can retain borrowed node pointers across this unlock window."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("registry_insert", insert_line, "node", "", insert_line.text),
                    self._event("registry_unlink", unlink_line, "node", "", unlink_line.text),
                    self._event("registry_unlock", unlock_line, "registry", "", unlock_line.text),
                    self._event("post_unlock_release", line, released, "", line.text),
                ],
                [insert_line.number, unlink_line.number, unlock_line.number, line.number],
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
            if self._owned_member_has_cleanup(lines, member_line.index + 1, line.index, parent, member):
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
                if not self._looks_like_parent_delete_without_member_cleanup(func_name, lines, line, parent):
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
            negative=["Validator must confirm the member is owned by the parent and no out-of-line destructor dominates this release."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("owned_member_leak", line, resource, "", line.text)],
                [line.number],
            ),
        )

    def _emit_unlocked_global_state_write_candidates(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        writes: List[Tuple[ClangCfgLine, str, str, bool]] = []
        held: List[str] = []
        for line in lines:
            lock = self._match_lock(line.text)
            if lock:
                held.append(lock[1])
            lhs = self._global_write_lhs(line.text)
            if lhs:
                writes.append((line, lhs, self._global_state_family(lhs), bool(held)))
            unlock = self._match_unlock(line.text)
            if unlock and held:
                held.pop()

        families: Dict[str, List[Tuple[ClangCfgLine, str, bool]]] = {}
        for line, lhs, family, locked in writes:
            families.setdefault(family, []).append((line, lhs, locked))

        emitted: Set[str] = set()
        for family, family_writes in families.items():
            locked_writes = [item for item in family_writes if item[2]]
            unlocked_writes = [item for item in family_writes if not item[2]]
            if locked_writes and unlocked_writes and family not in emitted:
                locked_line, locked_lhs, _ = locked_writes[0]
                unlocked_line, unlocked_lhs, _ = unlocked_writes[0]
                self._emit_shared_state_candidate(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    rule="clang_cfg_global_state_written_with_and_without_lock",
                    line=unlocked_line,
                    source=locked_line.text,
                    sink=unlocked_line.text,
                    resource=family,
                    description=f"Global shared state `{family}` is written both with and without a lock.",
                    positive=[
                        f"line {locked_line.number}: `{locked_lhs}` is written while a lock appears held",
                        f"line {unlocked_line.number}: `{unlocked_lhs}` is written without the same local lock evidence",
                    ],
                )
                emitted.add(family)
                continue

            if self._is_global_pointer_length_publication(family_writes) and family not in emitted:
                first_line, first_lhs, _ = family_writes[0]
                last_line, last_lhs, _ = family_writes[-1]
                self._emit_shared_state_candidate(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    rule="clang_cfg_global_pointer_length_pair_published_without_lock",
                    line=last_line,
                    source=first_line.text,
                    sink=last_line.text,
                    resource=family,
                    description=f"Global pointer/length state `{family}` is published without visible synchronization.",
                    positive=[
                        f"line {first_line.number}: `{first_lhs}` is written as part of a global state pair",
                        f"line {last_line.number}: `{last_lhs}` is written without a common lock around the publication",
                    ],
                )
                emitted.add(family)

    def _emit_permission_mode_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        mode_assignment = None
        request_check = None
        special_name_branch = None
        body = "\n".join(line.text for line in lines)
        for line in lines:
            if mode_assignment is None and re.search(
                r"\b(?:g_[A-Za-z_0-9]+(?:\.|->))?(?:perm|mode|permission)\b\s*=\s*0[0-7]{2,4}u?\s*;",
                line.text,
                re.IGNORECASE,
            ):
                mode_assignment = line
            if request_check is None and re.search(
                r"\b(?:requested|request|desired|required)[A-Za-z_0-9]*(?:perm|permission|mode)\b[^;]*(?:&|==|!=)",
                line.text,
                re.IGNORECASE,
            ):
                request_check = line
            if special_name_branch is None and re.search(r"\bstrcmp\s*\([^;]*(?:pipe|segment|shm|shared|product)", line.text, re.IGNORECASE):
                special_name_branch = line

        if mode_assignment is None or request_check is None:
            return
        if re.search(r"\b(?:chmod|fchmod|open|creat|shm_open|mmap)\s*\([^;]*(?:requested|request|desired|required)[A-Za-z_0-9]*(?:perm|permission|mode)\b", body, re.IGNORECASE):
            return

        positive = [
            f"line {mode_assignment.number}: file/shared-memory permission or mode is hard-coded",
            f"line {request_check.number}: requested permission is only compared locally",
        ]
        if special_name_branch is not None:
            positive.append(f"line {special_name_branch.number}: special name/deployment branch does not update the mode policy")
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="permission",
            rule="clang_cfg_requested_permission_not_applied_to_mode",
            line=request_check,
            description="Requested file/shared-memory permission is compared against a hard-coded mode but is not applied to the backing object.",
            root_cause="The code treats permission as a local validation flag while the actual backing mode remains fixed.",
            suggested_fix="Derive the open/chmod/mmap mode from the validated request or reject unsupported requests before publishing the resource.",
            source=mode_assignment.text,
            sink=request_check.text,
            confidence=0.72,
            positive=positive,
            negative=["Validator must confirm no later platform-specific permission update applies the requested mode."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("hardcoded_permission", mode_assignment, "permission", "", mode_assignment.text),
                    self._event("requested_permission_check", request_check, "permission", "", request_check.text),
                ],
                [mode_assignment.number, request_check.number],
            ),
        )

    def _emit_timer_callback_lock_order_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        effective_name = self._function_name_hint(func_name, lines)
        if not re.search(r"(?:timer|tick|callback|cb)", effective_name, re.IGNORECASE):
            return
        global_walk = self._first_line_matching_in(
            lines,
            re.compile(r"\b[A-Za-z_]\w*\s*=\s*&?\s*g_[A-Za-z_0-9]+(?:\.|->)[A-Za-z_0-9]*(?:head|list|queue|scheduler)?", re.IGNORECASE),
        )
        object_lock = None
        for line in lines:
            lock = self._match_lock(line.text)
            if lock and re.search(r"(?:->|\.)[A-Za-z_0-9]*(?:lock|mutex)", line.text, re.IGNORECASE):
                object_lock = line
                break
        if global_walk is None or object_lock is None:
            return
        if any(self._match_lock(item.text) and "g_" in item.text for item in lines[: object_lock.index]):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="deadlock",
            rule="clang_cfg_timer_callback_object_lock_without_scheduler_lock",
            line=object_lock,
            description="Timer/callback path locks an object from a global scheduler/list without holding the scheduler lock.",
            root_cause="A close/destroy path can hold the object lock while waiting for the scheduler/global lock, creating a lock-order cycle with the callback path.",
            suggested_fix="Use one lock order for scheduler/list and per-object locks, or snapshot/refcount the object before dropping the scheduler lock.",
            source=global_walk.text,
            sink=object_lock.text,
            confidence=0.74,
            impact_level="high",
            positive=[
                f"line {global_walk.number}: callback path traverses a global scheduler/list",
                f"line {object_lock.number}: callback path then acquires a per-object lock",
            ],
            negative=["Validator must confirm a reachable close/destroy path takes these locks in the opposite order."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("global_scheduler_walk", global_walk, "scheduler", "", global_walk.text),
                    self._event("object_lock_in_callback", object_lock, "object_lock", "", object_lock.text),
                ],
                [global_walk.number, object_lock.number],
            ),
        )

    @staticmethod
    def _function_name_hint(func_name: str, lines: Sequence[ClangCfgLine]) -> str:
        signature = next((line.text for line in lines[:6] if "(" in line.text), "")
        match = re.search(r"\b(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*\{?", signature)
        parsed = match.group("name") if match else ""
        if parsed and parsed not in {"if", "for", "while", "switch"}:
            return parsed
        return str(func_name or "")

    def _find_owned_member_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        for item in reversed(lines[max(0, release_line.index - 80) : release_line.index]):
            match = re.search(
                rf"\b{re.escape(parent)}\s*->\s*(?P<member>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]+);",
                item.text,
            )
            if not match:
                continue
            member = match.group("member")
            rhs = match.group("rhs").strip()
            if not (self._is_owned_member_name(member) or self._looks_like_owned_member_rhs(rhs)):
                continue
            if re.fullmatch(r"(?:NULL|nullptr|0)", rhs):
                continue
            return item, member, rhs
        return None

    @staticmethod
    def _is_owned_member_name(member: str) -> bool:
        return bool(
            re.search(
                r"(?:child|children|proc_head|head$|_head$|list$|_list$|items$|_items$|entries$|_entries$)",
                str(member or ""),
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _looks_like_owned_member_rhs(rhs: str) -> bool:
        return bool(
            re.search(
                r"\b[A-Za-z_]\w*(?:alloc|calloc|malloc|dup|new|create|clone|open)[A-Za-z_0-9]*\s*\(",
                str(rhs or ""),
                re.IGNORECASE,
            )
        )

    def _owned_member_has_cleanup(
        self,
        lines: Sequence[ClangCfgLine],
        start_index: int,
        end_index: int,
        parent: str,
        member: str,
    ) -> bool:
        region = lines[start_index:end_index]
        member_expr = rf"{re.escape(parent)}\s*->\s*{re.escape(member)}"
        for item in region:
            release = self._match_release(item.text)
            if release and re.search(member_expr, release[1]):
                return True
            if re.search(member_expr, item.text) and re.search(r"\b(?:while|for)\b", item.text):
                return True
            if re.search(rf"\b(?:free|SAFE_FREE|safe_free|_safe_free)\s*\([^;]*{member_expr}", item.text):
                return True
        return False

    def _find_missing_common_owned_member_cleanup(
        self,
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> Optional[Tuple[ClangCfgLine, str]]:
        create_line = next(
            (
                item
                for item in reversed(lines[max(0, release_line.index - 40) : release_line.index])
                if re.search(
                    rf"\b{re.escape(parent)}\s*=\s*(?:\([^)]*\)\s*)?"
                    r"[A-Za-z_]\w*(?:alloc|calloc|malloc|new|create)[A-Za-z_0-9]*\s*\(",
                    item.text,
                    re.IGNORECASE,
                )
            ),
            None,
        )
        if create_line is None:
            return None
        region = "\n".join(item.text for item in lines[create_line.index + 1 : release_line.index])
        common_members = ("payload", "context", "ctx", "tag", "buffer", "data", "value")
        for member in common_members:
            member_expr = rf"{re.escape(parent)}\s*->\s*{member}"
            if re.search(member_expr, region) and not re.search(
                rf"\b(?:free|SAFE_FREE|safe_free|_safe_free|destroy|release)[A-Za-z_0-9]*\s*\([^;]*{member_expr}",
                region,
                re.IGNORECASE,
            ):
                return create_line, member
        if re.search(r"_alloc_node|create_node|new_node", create_line.text, re.IGNORECASE):
            for member in ("payload", "tag", "value"):
                if not re.search(
                    rf"\b(?:free|SAFE_FREE|safe_free|_safe_free|destroy|release)[A-Za-z_0-9]*\s*\([^;]*{re.escape(parent)}\s*->\s*{member}",
                    region,
                    re.IGNORECASE,
                ):
                    return create_line, member
        return None

    def _looks_like_parent_delete_without_member_cleanup(
        self,
        func_name: str,
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> bool:
        effective_name = self._function_name_hint(func_name, lines)
        if not re.search(r"(?:delete|remove|destroy|free|cleanup|unregister|release)", effective_name, re.IGNORECASE):
            return False
        declaration = self._parent_declaration_text(lines, release_line, parent)
        if not re.search(r"(?:Node|Entry|Record|Object|Item|Session|Subscription|Group|Container)", declaration):
            return False
        prefix = lines[max(0, release_line.index - 60) : release_line.index]
        if any(re.search(rf"\b{re.escape(parent)}\s*->", item.text) and self._match_release(item.text) for item in prefix):
            return False
        if any(re.search(r"\b(?:while|for)\b", item.text) and re.search(r"(?:child|children|head|list|next)", item.text, re.IGNORECASE) for item in prefix):
            return False
        return True

    @staticmethod
    def _parent_declaration_text(
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> str:
        for item in reversed(lines[max(0, release_line.index - 40) : release_line.index + 1]):
            if re.search(rf"\b[A-Za-z_]\w*\s*\*+\s*{re.escape(parent)}\b", item.text):
                return item.text
        return ""

    @staticmethod
    def _global_write_lhs(text: str) -> str:
        stripped = str(text or "")
        if re.search(r"\b(?:if|while|for|switch)\s*\(", stripped):
            return ""
        assign = re.search(
            r"\b(?P<lhs>g_[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?)\s*(?:=|\+=|-=|\*=|/=|%=)",
            stripped,
        )
        if assign and not re.search(r"[=!<>]=", stripped[max(0, assign.end() - 3) : assign.end() + 2]):
            return re.sub(r"\s+", "", assign.group("lhs"))
        inc = re.search(r"\b(?P<lhs>g_[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?)\s*(?:\+\+|--)", stripped)
        return re.sub(r"\s+", "", inc.group("lhs")) if inc else ""

    @staticmethod
    def _global_state_family(lhs: str) -> str:
        text = re.sub(r"\s+", "", str(lhs or ""))
        tail = text.split("->")[-1].split(".")[-1]
        for token in ("watermark", "rules", "map", "mode", "state", "len", "length", "size"):
            if token in tail.lower() or token in text.lower():
                if token in {"len", "length", "size", "map"}:
                    base = re.sub(r"_(?:map|len|length|size|bytes|count|num)$", "", text)
                    return base or text
                return token
        return re.sub(r"_(?:ptr|map|len|length|size|bytes|count|num)$", "", text)

    @staticmethod
    def _is_global_pointer_length_publication(
        family_writes: Sequence[Tuple[ClangCfgLine, str, bool]],
    ) -> bool:
        if len(family_writes) < 2 or any(locked for _line, _lhs, locked in family_writes):
            return False
        names = {lhs.lower() for _line, lhs, _locked in family_writes}
        has_pointer = any(re.search(r"(?:map|ptr|addr|base|buffer|window)", name) for name in names)
        has_length = any(re.search(r"(?:len|length|size|bytes|count|num)", name) for name in names)
        return has_pointer and has_length

    def _emit_shared_state_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        *,
        rule: str,
        line: ClangCfgLine,
        source: str,
        sink: str,
        resource: str,
        description: str,
        positive: List[str],
    ) -> None:
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="unsynchronized_shared_state",
            rule=rule,
            line=line,
            description=description,
            root_cause="Global shared state is updated without a single synchronization protocol protecting all related writes/readers.",
            suggested_fix="Protect all writes and readers of the state family with the same lock or publish an immutable snapshot atomically.",
            source=source,
            sink=sink,
            confidence=0.74,
            impact_level="high",
            positive=positive,
            negative=["Validator must confirm there is no higher-level serialization contract around these calls."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("unsynchronized_global_state", line, resource, "", line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_fd_encoding_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        validate = re.search(
            r"\b(?P<api>[A-Za-z_]\w*validate_encoded_fd)\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not validate:
            return
        arg = validate.group("arg")
        raw_line = None
        for item in reversed(lines[max(0, line.index - 8) : line.index + 1]):
            if re.search(rf"\b(?:int\s+)?{re.escape(arg)}\s*=\s*[A-Za-z_]\w*\s*(?:[+%-]|$)", item.text):
                raw_line = item
                break
        if raw_line is None and re.search(r"\braw_[A-Za-z_0-9]*fd\b", arg):
            raw_line = line
        if raw_line is None:
            return
        if re.search(r"ENCODE|CHECK_VALUE|encode_fd", raw_line.text, re.I):
            return
        audit_only = self._encoded_fd_validation_result_is_not_security_sink(lines, line)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="fd_encoding_mismatch",
            rule="clang_cfg_raw_fd_revalidated_as_encoded",
            line=raw_line,
            description="Raw fd arithmetic is later validated as if it were an encoded/check-value fd.",
            root_cause="The encoding/check bits are not constructed before the raw fd value reaches encoded-fd validation.",
            suggested_fix="Encode raw fds with the expected check value before calling encoded-fd validators.",
            source=raw_line.text,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {raw_line.number}: raw fd value is derived without encoding bits",
                f"line {line.number}: `{validate.group('api')}` validates `{arg}` as an encoded fd",
            ],
            negative=(
                [
                    "The encoded-fd validation result is not visibly consumed by a security-sensitive sink in this local body.",
                    "Keep as an audit observation unless a caller uses the return value to authorize a dangerous operation.",
                ]
                if audit_only
                else []
            ),
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("raw_fd_derive", raw_line, arg, "", raw_line.text),
                    self._event("encoded_fd_validate", line, arg, validate.group("api"), line.text),
                ],
                [raw_line.number, line.number],
            ),
            validation_required=not audit_only,
            finding_kind="audit_observation" if audit_only else "clang_ast_cfg_candidate",
            audit_observation_reason=(
                "raw fd/encoded fd semantic mismatch has no visible security sink in the local CFG"
                if audit_only
                else ""
            ),
        )

    def _maybe_emit_global_state_not_restored_on_error(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        assign = re.search(
            r"\b(?P<state>g_[A-Za-z_0-9.]*state[A-Za-z_0-9.]*)\s*=\s*(?P<value>[^;]+);",
            line.text,
        )
        if not assign:
            return
        state = assign.group("state")
        previous = next(
            (
                item
                for item in reversed(lines[max(0, line.index - 6) : line.index])
                if re.search(
                    rf"\b(?P<prev>[A-Za-z_]\w*)\s*=\s*{re.escape(state)}\s*;",
                    item.text,
                )
            ),
            None,
        )
        previous_var = ""
        if previous:
            previous_match = re.search(
                rf"\b(?P<prev>[A-Za-z_]\w*)\s*=\s*{re.escape(state)}\s*;",
                previous.text,
            )
            previous_var = previous_match.group("prev") if previous_match else ""
        later = lines[line.index + 1 : line.index + 12]
        error_return = next((item for item in later if re.search(r"\breturn\s+-1\s*;", item.text)), None)
        if not error_return:
            return
        branch_window = "\n".join(item.text for item in later[: max(1, error_return.index - line.index)])
        if not re.search(r"\b(?:fcntl|ioctl|setsockopt|getsockopt|validate|verify|check)\s*\(", branch_window):
            return
        if previous_var:
            restore_before_error = any(
                item.index < error_return.index
                and re.search(rf"\b{re.escape(state)}\s*=\s*{re.escape(previous_var)}\s*;", item.text)
                for item in later
            )
            if restore_before_error:
                return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="state_inconsistency",
            rule="clang_cfg_global_state_not_restored_on_error",
            line=line,
            description=f"`{state}` is changed before an error path that returns without restoring the previous value.",
            root_cause="A failed syscall or validation path can leave shared local registry state set to a transient value.",
            suggested_fix="Restore the saved previous state on every failure path before returning an error.",
            source=line.text,
            sink=error_return.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {line.number}: shared state `{state}` is overwritten",
                f"line {error_return.number}: error return is reachable after the syscall/validation check",
                "no restore of the saved previous state is visible before the error return",
            ],
            negative=["Validator must confirm the state value is observable outside this function."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    *(
                        [self._event("state_snapshot", previous, state, previous_var, previous.text)]
                        if previous
                        else []
                    ),
                    self._event("state_overwrite", line, state, "", line.text),
                    self._event("error_return_without_restore", error_return, state, "", error_return.text),
                ],
                [line.number, error_return.number],
            ),
        )

    def _maybe_emit_ignored_protocol_version(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        parse = re.search(
            r"\b(?:uint(?:8|16|32)_t|unsigned\s+char|int)\s+"
            r"(?P<var>[A-Za-z_]\w*)\s*=\s*"
            r"(?P<src>[A-Za-z_]\w*)\s*\[[^]]+\]\s*;",
            line.text,
            re.IGNORECASE,
        )
        if not parse:
            return
        var = parse.group("var")
        if not re.search(r"(?:version|ver)", var, re.IGNORECASE):
            return
        later = lines[line.index + 1 : line.index + 12]
        ignored = next(
            (
                item
                for item in later
                if re.search(rf"\(\s*void\s*\)\s*{re.escape(var)}\s*;", item.text)
            ),
            None,
        )
        if not ignored:
            return
        comparison_window = "\n".join(item.text for item in later[: max(1, ignored.index - line.index)])
        if re.search(rf"\b{re.escape(var)}\b\s*(?:==|!=|<|>|<=|>=)", comparison_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="version_filtering",
            rule="clang_cfg_parsed_protocol_version_is_ignored",
            line=line,
            description=f"Protocol version `{var}` is parsed from the message and then explicitly ignored.",
            root_cause="Messages from unsupported or low-version peers can pass state-only validation without a version gate.",
            suggested_fix="Validate the parsed version against the supported protocol set before processing state fields.",
            source=line.text,
            sink=ignored.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {line.number}: protocol version `{var}` is parsed from the report",
                f"line {ignored.number}: `{var}` is marked unused instead of checked",
                "no version comparison is visible before the ignored-version marker",
            ],
            negative=["Validator must confirm whether caller-side version filtering cannot cover this parser."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("protocol_version_parse", line, var, parse.group("src"), line.text),
                    self._event("protocol_version_ignored", ignored, var, "", ignored.text),
                ],
                [line.number, ignored.number],
            ),
        )

    def _maybe_emit_unchecked_param_global_array_index(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        params = set(self._signature_param_names(lines))
        if not params:
            return
        match = re.search(
            r"\b(?P<array>g_[A-Za-z_0-9]+)\s*\[\s*(?P<idx>[A-Za-z_]\w*)\s*\]",
            line.text,
        )
        if not match:
            return
        idx_name = match.group("idx")
        if idx_name not in params:
            return
        array_name = match.group("array")
        guard_window = "\n".join(item.text for item in lines[: line.index + 1])
        explicit_bound = re.search(
            rf"\b{re.escape(idx_name)}\s*(?:<|<=|>=|>)\s*"
            rf"(?:ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)|"
            r"[A-Z][A-Z0-9_]*(?:MAX|LIMIT|COUNT|NUM|CORES|SIZE)[A-Z0-9_]*)",
            guard_window,
        )
        validator_guard = re.search(
            rf"\b[A-Za-z_]\w*(?:is|valid|validate|check)[A-Za-z_0-9]*(?:fd|index|slot|core|bound)[A-Za-z_0-9]*\s*\(\s*{re.escape(idx_name)}\s*\)",
            guard_window,
            re.I,
        )
        if explicit_bound or validator_guard:
            return
        if self._has_dynamic_array_capacity_guard(lines, line, array_name, idx_name):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="bounds",
            rule="clang_cfg_unchecked_param_indexes_fixed_global_array",
            line=line,
            description="A caller-supplied index parameter directly indexes a fixed global array without a visible upper-bound check.",
            root_cause="The function trusts an index parameter before proving it is within the backing global array capacity.",
            suggested_fix="Reject or clamp the index against ARRAY_SIZE or the concrete global-array capacity before indexing.",
            source=idx_name,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"function signature exposes index parameter `{idx_name}`",
                f"line {line.number}: `{array_name}` is indexed by `{idx_name}`",
                "no prior ARRAY_SIZE/concrete-capacity guard or index validator is visible",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("global_array_index", line, idx_name, array_name, line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_wide_count_without_magic_guard(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        copy = re.search(
            r"\bmemcpy\s*\(\s*&\s*(?P<count>[A-Za-z_]\w*)\s*,\s*"
            r"(?P<src>[A-Za-z_]\w*)\s*\+\s*(?P<offset>\d+)\s*,\s*sizeof\s*\(\s*(?P=count)\s*\)\s*\)",
            line.text,
            re.IGNORECASE,
        )
        if not copy:
            return
        if not re.search(r"(?:count|cnt|num)", copy.group("count"), re.IGNORECASE):
            return
        offset = int(copy.group("offset"))
        if offset < 4:
            return
        before = "\n".join(item.text for item in lines[: line.index + 1])
        has_magic_symbol = re.search(r"(?:magic|signature|cookie)", before, re.IGNORECASE)
        has_magic_guard = re.search(
            r"\b(?:magic|signature|cookie)\b[^;\n]*(?:==|!=)|(?:==|!=)[^;\n]*\b(?:MAGIC|magic|signature|cookie)\b",
            before,
            re.IGNORECASE,
        )
        if has_magic_guard:
            return
        name_hint = self._function_name_hint(func_name, lines)
        if not has_magic_symbol and not re.search(r"(?:magic|header|protocol|parser|decode)", name_hint, re.IGNORECASE):
            return
        sink_line = self._find_dependent_count_sink(lines, line, copy.group("count"))
        concrete_sink = sink_line.text if sink_line is not None else f"{copy.group('count')} used before protocol magic validation"
        defect_class = "bounds" if sink_line is not None else "protocol_validation"
        rule = (
            "clang_cfg_wide_count_before_magic_reaches_memory_sink"
            if sink_line is not None
            else "clang_cfg_wide_count_read_without_magic_guard"
        )
        positive = [
            f"line {line.number}: protocol field is copied from a wire buffer offset",
            "no magic/signature comparison is visible before the count read",
        ]
        events = [self._event("wide_count_read", line, copy.group("count"), copy.group("src"), line.text)]
        cfg_path = [line.number]
        if sink_line is not None:
            positive.append(
                f"line {sink_line.number}: unchecked `{copy.group('count')}` reaches a memory/dispatch sink"
            )
            events.append(self._event("wide_count_sink", sink_line, copy.group("count"), "", sink_line.text))
            cfg_path.append(sink_line.number)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class=defect_class,
            rule=rule,
            line=sink_line or line,
            description=f"Protocol field `{copy.group('count')}` is read from `{copy.group('src')} + {offset}` without a visible magic/signature guard.",
            root_cause="The parser uses a dependent protocol field before proving the record layout with the expected magic value.",
            suggested_fix="Decode and validate the magic/signature field before reading dependent count fields.",
            source=line.text,
            sink=concrete_sink,
            confidence=0.82,
            impact_level="high",
            positive=positive,
            negative=["Validator must confirm whether a caller-side magic check dominates this parser."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                events,
                cfg_path,
            ),
        )

    def _maybe_emit_fixed_limit_spec_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        assign = re.search(
            r"\b(?P<len>[A-Za-z_]\w*(?:len|size)[A-Za-z_0-9]*)\s*=\s*"
            r"\([^;]*\)\s*(?P<count>[A-Za-z_]\w*(?:count|num|index)[A-Za-z_0-9]*)\s*\*\s*(?P<unit>[A-Z][A-Z0-9_]*(?:SIZE|LEN|BYTES))\b",
            line.text,
        )
        if not assign:
            return
        length_var = assign.group("len")
        count_var = assign.group("count")
        later_text = "\n".join(item.text for item in lines[line.index + 1 : line.index + 14])
        limit_match = re.search(rf"\b{re.escape(length_var)}\b\s*>\s*(?P<limit>[A-Z][A-Z0-9_]*(?:LIMIT|CAP|MAX))", later_text)
        spec_match = re.search(rf"\b{re.escape(count_var)}\b\s*<=\s*(?P<spec>[A-Z][A-Z0-9_]*(?:SPEC|MAX)[A-Z0-9_]*)", later_text)
        if not (limit_match and spec_match):
            return
        if limit_match.group("limit") == spec_match.group("spec"):
            return
        audit_only = not self._limit_mismatch_reaches_unsafe_sink(lines, line, length_var)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="size_limit_mismatch",
            rule="clang_cfg_fixed_byte_limit_before_spec_count_check",
            line=line,
            description=(
                f"`{length_var}` is constrained by `{limit_match.group('limit')}` before "
                f"`{count_var}` is checked against `{spec_match.group('spec')}`."
            ),
            root_cause="A fixed byte cache limit can reject or size the allocation differently from the stated element-count specification.",
            suggested_fix="Validate element count against the specification before computing bytes, and derive byte limits from the same contract.",
            source=line.text,
            sink=limit_match.group("limit"),
            confidence=0.84,
            impact_level="medium",
            positive=[
                f"line {line.number}: element count is converted to a byte length",
                f"later guard uses fixed byte limit `{limit_match.group('limit')}`",
                f"later return/contract uses separate spec `{spec_match.group('spec')}`",
            ],
            negative=(
                [
                    "The local CFG does not show the mismatched byte limit reaching an unsafe copy, index, or allocation sink.",
                    "Treat as a design/contract observation unless a downstream sink consumes the mismatched length.",
                ]
                if audit_only
                else []
            ),
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("spec_byte_limit_mismatch", line, length_var, count_var, line.text)],
                [line.number],
            ),
            validation_required=not audit_only,
            finding_kind="audit_observation" if audit_only else "clang_ast_cfg_candidate",
            audit_observation_reason=(
                "size/spec limit mismatch has no visible unsafe sink in the local CFG"
                if audit_only
                else ""
            ),
        )

    def _maybe_emit_recv_retry_without_budget(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if not re.search(r"\bwhile\s*\([^)]*<[^)]*\)", line.text):
            return
        window = lines[line.index : line.index + 16]
        text = "\n".join(item.text for item in window)
        if not re.search(r"\b(?:recv|read|_net_recv_data)\s*\(", text):
            return
        if not re.search(r"\bEAGAIN\b", text) or not re.search(r"\bEINTR\b", text):
            return
        if not re.search(r"\bcontinue\s*;", text):
            return
        if re.search(r"\b(?:timeout|deadline|retry|budget|max_attempt|sleep|usleep|poll|select)\b", text, re.IGNORECASE):
            return
        retry_line = self._first_line_matching_in(window, re.compile(r"\bEAGAIN\b|\bEINTR\b")) or line
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="busy_loop",
            rule="clang_cfg_recv_retry_loop_without_timeout_or_budget",
            line=line,
            description="Receive loop retries transient errors without a timeout, retry budget, or backoff.",
            root_cause="EAGAIN/EINTR paths can repeat forever and the outer loop continues on non-progressing reads.",
            suggested_fix="Add a retry budget, deadline, poll/select wait, or propagate transient failures to the caller.",
            source=retry_line.text,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {line.number}: receive loop waits for progress",
                f"line {retry_line.number}: transient EAGAIN/EINTR retry is visible",
                "no timeout, retry budget, or backoff is visible in the loop window",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("receive_loop", line, "recv", "", line.text),
                    self._event("transient_retry", retry_line, "EAGAIN/EINTR", "", retry_line.text),
                ],
                [line.number, retry_line.number],
            ),
        )

    def _maybe_emit_global_dynamic_array_resize_race(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        guard = re.search(
            r"\bif\s*\(\s*(?P<index>[A-Za-z_]\w*)\s*>=\s*(?P<cap>g_[A-Za-z_0-9]*(?:cap|capacity)[A-Za-z_0-9]*)\s*\)",
            line.text,
        )
        if not guard:
            return
        cap = guard.group("cap")
        stem = re.sub(r"(?:_cap|_capacity)$", "", cap)
        window = lines[line.index : line.index + 24]
        text = "\n".join(item.text for item in window)
        global_assign = re.search(rf"\b(?P<array>{re.escape(stem)}(?:_array|s|_list)?)\s*=\s*(?P<new>[A-Za-z_]\w*)\s*;", text)
        cap_assign = re.search(rf"\b{re.escape(cap)}\s*=\s*[A-Za-z_]\w*\s*;", text)
        old_free = re.search(r"\b(?:SAFE_FREE|free)\s*\(\s*(?:old_[A-Za-z_]\w*|old_array)\s*\)", text)
        if not (global_assign and cap_assign and old_free):
            return
        pre_window = "\n".join(item.text for item in lines[max(0, line.index - 5) : line.index])
        if re.search(r"\b(?:LOCK|pthread_mutex_lock|spin_lock|mtx_lock)\s*\(", pre_window):
            return
        assign_line = self._first_line_matching_in(window, re.compile(rf"\b{re.escape(global_assign.group('array'))}\s*=")) or line
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="dynamic_array_race",
            rule="clang_cfg_global_dynamic_array_resize_without_lock",
            line=line,
            description=f"Global dynamic array `{global_assign.group('array')}` is resized and the old storage is freed without a visible lock.",
            root_cause="Concurrent creators can race while publishing a new global array pointer/capacity pair and freeing the old array.",
            suggested_fix="Protect the capacity check, allocation handoff, pointer publish, and old-array free with the same mutex or atomic ownership protocol.",
            source=line.text,
            sink=assign_line.text,
            confidence=0.87,
            impact_level="high",
            positive=[
                f"line {line.number}: resize guard reads shared capacity `{cap}`",
                f"line {assign_line.number}: global array pointer is republished",
                "old array storage is freed in the resize window",
                "no lock acquisition is visible before the resize window",
            ],
            negative=["Validator must confirm there is no caller-held lock dominating this helper."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("dynamic_array_resize_guard", line, global_assign.group("array"), cap, line.text),
                    self._event("dynamic_array_publish", assign_line, global_assign.group("array"), "", assign_line.text),
                ],
                [line.number, assign_line.number],
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
                            self._event("log_buffer_alloc", line, var, alloc.group("api"), line.text),
                            self._event("log_error_use", log_line, var, "LOG", log_line.text),
                            self._event("error_return", item, var, "", item.text),
                        ],
                        [line.number, log_line.number, item.number],
                    ),
                )
                return

    def _maybe_emit_unchecked_insert_handoff(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if "=" in line.text.split("(", 1)[0] or re.search(r"\b(?:if|while|for)\s*\(", line.text):
            return
        for api, args in self._calls(line.text):
            if not re.search(r"(?:insert|link|attach|register|publish|add)", api, re.IGNORECASE):
                continue
            split = self._split_args(args)
            if not split:
                continue
            owner = self._resource_var(split[0])
            if not owner:
                continue
            previous = lines[max(0, line.index - 12) : line.index]
            alloc_line = next(
                (
                    item
                    for item in reversed(previous)
                    if re.search(
                        rf"\b{re.escape(owner)}\s*=\s*(?:\([^)]*\)\s*)?"
                        r"[A-Za-z_]\w*(?:alloc|calloc|malloc|new)[A-Za-z_0-9]*\s*\(",
                        item.text,
                        re.IGNORECASE,
                    )
                ),
                None,
            )
            if not alloc_line:
                continue
            later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
            if re.search(rf"\b(?:free|SAFE_FREE)\s*\(\s*{re.escape(owner)}\s*\)", later):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="memory_leak",
                rule="clang_cfg_unchecked_insert_after_ownership_handoff",
                line=line,
                description=f"Return value from ownership/linking helper `{api}` is ignored after `{owner}` is allocated.",
                root_cause="If the helper links the object and then reports failure, the caller loses cleanup/error-state ownership for the allocated node.",
                suggested_fix="Check the insert/link return value and either roll back the linked node or define a clear ownership transfer contract.",
                source=f"{owner} allocated at line {alloc_line.number}",
                sink=line.text,
                confidence=0.8,
                impact_level="high",
                positive=[
                    f"line {alloc_line.number}: `{owner}` is allocated before the handoff",
                    f"line {line.number}: `{api}` is called as a standalone statement and its return value is ignored",
                    "no immediate rollback/free is visible after the handoff call",
                ],
                negative=["Validator must inspect the callee contract to confirm whether failure can occur after linking."],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("owner_alloc", alloc_line, owner, "", alloc_line.text),
                        self._event("unchecked_handoff", line, owner, api, line.text),
                    ],
                    [alloc_line.number, line.number],
                ),
            )
            return

    def _maybe_emit_protocol_length_copy_without_packet_bound(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(
            r"\b(?:size_t|uint(?:32|64)_t|int)\s+(?P<len>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*="
            r"\s*(?:\([^)]*\)\s*)?\(?\s*(?P<src>[A-Za-z_]\w*)\s*(?:\*|<<)\s*[^;]+;",
            line.text,
            re.IGNORECASE,
        )
        if not match:
            return
        len_var = match.group("len")
        source_var = match.group("src")
        previous = "\n".join(item.text for item in lines[max(0, line.index - 8) : line.index + 1])
        if not re.search(rf"\b{re.escape(source_var)}\s*=\s*(?:packet|frame|wire|blob)\s*\[", previous):
            return
        later_lines = lines[line.index + 1 : line.index + 10]
        copy_line = next(
            (
                item
                for item in later_lines
                if self._copy_uses_length(item.text, len_var)
                and re.search(r"\b(?:packet|frame|wire|blob)\s*\+", item.text)
            ),
            None,
        )
        if not copy_line:
            return
        guard_window = "\n".join(item.text for item in lines[max(0, copy_line.index - 8) : copy_line.index])
        if re.search(
            rf"\b{re.escape(len_var)}\b\s*[<>]=?\s*[^;]*(?:packet_len|frame_len|wire_len|blob_len|remaining)",
            guard_window,
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="bounds",
            rule="clang_cfg_protocol_units_length_reaches_copy_without_packet_bound",
            line=line,
            description=f"Protocol-derived length `{len_var}` reaches a copy from the packet without being bounded by the received packet length.",
            root_cause="The code checks only destination capacity; it does not prove the source frame contains the derived number of bytes.",
            suggested_fix="Check the derived copy length against both destination capacity and remaining input packet bytes.",
            source=line.text,
            sink=copy_line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {line.number}: `{len_var}` is derived from a packet-controlled unit count",
                f"line {copy_line.number}: `{len_var}` controls a packet copy",
                "nearby guards do not bound the copy length by packet_len/frame_len/remaining bytes",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("protocol_length_derive", line, len_var, source_var, line.text),
                    self._event("packet_copy", copy_line, len_var, "", copy_line.text),
                ],
                [line.number, copy_line.number],
            ),
        )

    def _maybe_emit_header_length_copy_without_wire_bound(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        assign = re.search(
            r"\b(?:size_t|uint(?:32|64)_t|int)\s+(?P<len>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*="
            r"\s*(?:\([^)]*\)\s*)?(?P<header>[A-Za-z_]\w*)\s*\.\s*(?:len|length|size)\s*-\s*sizeof\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not assign:
            return
        len_var = assign.group("len")
        header_var = assign.group("header")
        prior = "\n".join(item.text for item in lines[max(0, line.index - 10) : line.index])
        if not re.search(rf"\bmemcpy\s*\(\s*&\s*{re.escape(header_var)}\s*,", prior):
            return
        later = lines[line.index + 1 : line.index + 12]
        copy_line = next((item for item in later if self._copy_uses_length(item.text, len_var)), None)
        if copy_line is None:
            return
        guard_window = "\n".join(item.text for item in lines[max(0, copy_line.index - 8) : copy_line.index])
        if re.search(rf"\b{re.escape(len_var)}\b\s*(?:<=|<)\s*(?:wire_len|packet_len|frame_len|payload_len|remaining)", guard_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="bounds",
            rule="clang_cfg_header_length_reaches_copy_without_wire_bound",
            line=copy_line,
            description=f"Header length `{len_var}` reaches a copy without being bounded by the input wire length.",
            root_cause="Validating a header magic does not prove the declared body length is present in the received buffer.",
            suggested_fix="Check declared body length against the remaining wire length before copying.",
            source=line.text,
            sink=copy_line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {line.number}: `{len_var}` is derived from `{header_var}.length`",
                f"line {copy_line.number}: `{len_var}` controls a copy sink",
            ],
            negative=["Validator must confirm no earlier full-frame length guard dominates the copy."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("header_length", line, len_var, header_var, line.text),
                    self._event("header_length_copy", copy_line, len_var, "", copy_line.text),
                ],
                [line.number, copy_line.number],
            ),
        )

    def _maybe_emit_probe_error_returns_success(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        cond = re.search(
            r"\bif\s*\(\s*(?P<status>[A-Za-z_]\w*)\s*!=\s*0\s*\|\|\s*(?P<flag>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not cond:
            return
        status = cond.group("status")
        previous = lines[max(0, idx - 8) : idx]
        recv_line = next(
            (
                item
                for item in reversed(previous)
                if re.search(rf"\b{re.escape(status)}\s*=\s*(?:recv|read|recvfrom|_net_recv_data)\s*\(", item.text)
            ),
            None,
        )
        if not recv_line:
            return
        branch = lines[idx + 1 : idx + 8]
        log_line = next((item for item in branch if "LOG_ERROR" in item.text), None)
        return_line = next((item for item in branch if re.search(rf"\breturn\s+{re.escape(status)}\s*;", item.text)), None)
        if not log_line or not return_line:
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="unchecked_return",
            rule="clang_cfg_probe_error_branch_can_return_success_status",
            line=line,
            description=f"Probe failure branch logs an error but returns `{status}`, which can still be zero when `{cond.group('flag')}` caused the branch.",
            root_cause="The branch conflates status-code failure with classifier failure and returns the transport status instead of an explicit error.",
            suggested_fix="Return a negative/error code when the classifier flag indicates failure, even if the receive call itself returned success.",
            source=recv_line.text,
            sink=return_line.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {recv_line.number}: `{status}` receives a receive/probe API status",
                f"line {line.number}: branch also fires on classifier flag `{cond.group('flag')}`",
                f"line {return_line.number}: branch returns `{status}` rather than a definite error",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("probe_status", recv_line, status, "", recv_line.text),
                    self._event("probe_error_condition", line, status, cond.group("flag"), line.text),
                    self._event("success_possible_return", return_line, status, "", return_line.text),
                ],
                [recv_line.number, line.number, return_line.number],
            ),
        )

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
            negative=["Validator must confirm no helper on the same path performs the refcount protocol."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("refcount_state", ref_line, var, "ref_count", ref_line.text),
                    self._event("free_without_refcount", line, var, "", line.text),
                ],
                [ref_line.number, line.number],
            ),
        )

    def _maybe_emit_integer_overflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        patterns = [
            (
                re.search(
                    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                    r"(?P<api>[A-Za-z_]\w*(?:alloc|malloc|calloc|realloc)[A-Za-z_0-9]*)\s*\((?P<expr>[^;]*(?:\+|\*)[^;]*)\)",
                    line.text,
                    re.IGNORECASE,
                ),
                "allocation_size_arithmetic_without_overflow_guard",
                "Allocation size is computed with arithmetic without a visible overflow guard.",
            ),
            (
                re.search(
                    r"\b(?:size_t|uint(?:32|64)_t|unsigned(?:\s+int)?|int)\s+"
                    r"(?P<var>[A-Za-z_]\w*(?:len|size|total)[A-Za-z_0-9]*)\s*=\s*(?P<expr>[^;]*(?:sizeof\s*\([^)]*\)|[A-Za-z_]\w*)\s*\+\s*[^;]+);",
                    line.text,
                    re.IGNORECASE,
                ),
                "size_addition_without_overflow_guard",
                "Size expression uses addition without a visible overflow guard.",
            ),
            (
                re.search(r"\(\s*uint32_t\s*\)\s*(?P<expr>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)", line.text),
                "narrowing_size_cast_without_range_guard",
                "A size-like value is narrowed to uint32_t without a visible range guard.",
            ),
        ]
        for match, rule, description in patterns:
            if not match:
                continue
            expr = match.groupdict().get("expr") or line.text
            guard_window = "\n".join(item.text for item in lines[max(0, line.index - 8) : line.index])
            if self._has_overflow_guard(guard_window, expr):
                continue
            if self._has_small_count_bound_proof(lines, line, expr):
                continue
            if self._has_narrowing_bound_proof(lines, line, expr):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="integer_overflow",
                rule=f"clang_cfg_{rule}",
                line=line,
                description=description,
                root_cause="Integer arithmetic on a size or length value can wrap before allocation, copy, or serialization.",
                suggested_fix="Check the arithmetic bound before evaluating the allocation/copy size or narrowing cast.",
                source=str(expr).strip(),
                sink=line.text,
                confidence=0.8,
                impact_level="high",
                positive=[f"line {line.number}: arithmetic/narrowing expression `{line.text}`"],
                negative=["Validator must confirm whether an equivalent range guard exists on all paths."],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [self._event("integer_size_arithmetic", line, "", "", line.text)],
                    [line.number],
                ),
            )
            break

    def _maybe_emit_format_string(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        api = ""
        arg = ""
        for call_api, args in self._calls(line.text):
            if call_api not in self._format_sink_names:
                continue
            split_args = self._split_args(args)
            arg_index = 1 if call_api in {"fprintf", "vfprintf"} else 0
            if len(split_args) <= arg_index:
                continue
            candidate = split_args[arg_index].strip()
            if self._is_string_literal(candidate):
                continue
            if not re.match(r"^[A-Za-z_]\w*(?:\[[^]]+\])?$", candidate):
                continue
            api = call_api
            arg = candidate
            break
        if not arg:
            return
        if self._is_format_forwarding_wrapper(func_name, lines, arg):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="format_string",
            rule="clang_cfg_nonliteral_format_string",
            line=line,
            description=f"`{arg}` is used as a printf-style format string.",
            root_cause="Percent sequences in attacker-controlled text can be interpreted as format directives.",
            suggested_fix=f"Use a literal format such as `printf(\"%s\", {arg})`.",
            source=arg,
            sink=line.text,
            confidence=0.88,
            impact_level="high",
            positive=[f"line {line.number}: printf-style call uses non-literal first format argument"],
            negative=[],
            ast_cfg=self._ast_cfg_pack(lines, [self._event("format_sink", line, arg, api, line.text)], [line.number]),
        )

    def _maybe_emit_command_injection(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        env_vars: Dict[str, ClangCfgLine],
    ) -> None:
        getenv = re.search(r"\b(?:const\s+char\s*\*\s*)?(?P<var>[A-Za-z_]\w*)\s*=\s*getenv\s*\(", line.text)
        if getenv:
            env_vars[getenv.group("var")] = line

        system_call = re.search(r"\bsystem\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", line.text)
        if system_call:
            arg = system_call.group("arg")
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="command_injection",
                rule="clang_cfg_system_with_nonliteral_command",
                line=line,
                description=f"`system` executes non-literal command buffer `{arg}`.",
                root_cause="Shell command text is constructed in process and can carry user or environment-controlled tokens.",
                suggested_fix="Avoid `system`; pass argv directly to execve/posix_spawn and validate each argument.",
                source=arg,
                sink=line.text,
                confidence=0.84,
                impact_level="critical",
                positive=[f"line {line.number}: `system` executes non-literal `{arg}`"],
                negative=["Validator must trace whether the command buffer is attacker-controlled."],
                ast_cfg=self._ast_cfg_pack(lines, [self._event("system_call", line, arg, "system", line.text)], [line.number]),
            )
            return

        concat = re.search(
            r"\bstrcat\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*(?P<src>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not concat or concat.group("src") not in env_vars:
            return
        src = concat.group("src")
        dst = concat.group("dst")
        env_line = env_vars[src]
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
        if not re.search(rf"\breturn\s+{re.escape(dst)}\s*;", later):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="command_injection",
            rule="clang_cfg_shell_command_concat_env",
            line=line,
            description=f"Environment-derived `{src}` is concatenated into command buffer `{dst}` and returned.",
            root_cause="Environment text can introduce shell metacharacters into a command later executed by a shell.",
            suggested_fix="Do not concatenate environment text into shell commands; build an argv vector or validate/escape arguments.",
            source=f"getenv at line {env_line.number}",
            sink=line.text,
            confidence=0.82,
            impact_level="critical",
            positive=[
                f"line {env_line.number}: `{src}` receives `getenv(...)`",
                f"line {line.number}: `{src}` is appended to `{dst}` with `strcat`",
                f"`{dst}` is returned by the command-builder function nearby",
            ],
            negative=["Validator must confirm the returned buffer reaches a shell execution sink."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("environment_source", env_line, src, "getenv", env_line.text),
                    self._event("command_concat", line, dst, "strcat", line.text),
                ],
                [env_line.number, line.number],
            ),
        )

    def _maybe_emit_signed_unsigned(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        signed_reads: Dict[str, ClangCfgLine],
        casts: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        read = re.search(
            r"\b(?:int|ssize_t)\s+(?P<var>[A-Za-z_]\w*)\s*=\s*"
            r"(?:recv|read|recvfrom|_net_recv_data)\s*\(",
            line.text,
        )
        if read:
            signed_reads[read.group("var")] = line

        cast = re.search(
            r"\bsize_t\s+(?P<size>[A-Za-z_]\w*)\s*=\s*\(size_t\)\s*(?P<src>[A-Za-z_]\w*)\s*;",
            line.text,
        )
        if cast and cast.group("src") in signed_reads:
            casts[cast.group("size")] = (line, cast.group("src"))

        for size_var, (cast_line, src_var) in list(casts.items()):
            if line.index <= cast_line.index:
                continue
            if not self._copy_uses_length(line.text, size_var):
                continue
            src_line = signed_reads[src_var]
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="signed_unsigned",
                rule="clang_cfg_negative_length_cast_to_size_t",
                line=cast_line,
                description=f"Signed IO length `{src_var}` is cast to `size_t` as `{size_var}` and reaches a copy length.",
                root_cause="Negative error returns can become very large unsigned sizes after the cast.",
                suggested_fix=f"Check `{src_var} >= 0` and the upper bound before casting to `size_t`.",
                source=f"{src_var} at line {src_line.number}",
                sink=line.text,
                confidence=0.88,
                impact_level="high",
                positive=[
                    f"line {src_line.number}: signed result `{src_var}` comes from an IO/read API",
                    f"line {cast_line.number}: `{src_var}` is cast to `size_t` as `{size_var}`",
                    f"line {line.number}: `{size_var}` is used as a copy/IO length",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("signed_io_result", src_line, src_var, "", src_line.text),
                        self._event("signed_to_unsigned_cast", cast_line, size_var, src_var, cast_line.text),
                        self._event("unsigned_length_sink", line, size_var, "", line.text),
                    ],
                    [src_line.number, cast_line.number, line.number],
                ),
            )
            casts.pop(size_var, None)

    def _maybe_emit_off_by_one(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(r"\b(?P<array>[A-Za-z_]\w*)\s*\[\s*sizeof\s*\(\s*(?P=array)\s*\)\s*\]\s*=", line.text)
        if not match:
            return
        array = match.group("array")
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="off_by_one",
            rule="clang_cfg_sizeof_index_write",
            line=line,
            description=f"`{array}[sizeof({array})]` writes one element past the end of the array.",
            root_cause="`sizeof(array)` is the byte count and is outside the zero-based index range.",
            suggested_fix=f"Use `sizeof({array}) - 1` for the terminator or a length-aware helper.",
            source=array,
            sink=line.text,
            confidence=0.9,
            impact_level="high",
            positive=[f"line {line.number}: writes at `sizeof({array})` index"],
            negative=[],
            ast_cfg=self._ast_cfg_pack(lines, [self._event("off_by_one_write", line, array, "", line.text)], [line.number]),
        )

    def _track_local_aggregate(
        self,
        line: ClangCfgLine,
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]],
        aggregate_field_writes: Dict[str, Set[str]],
    ) -> None:
        decl = re.search(
            r"^\s*(?P<type>(?:struct\s+)?[A-Z][A-Za-z_0-9]*|[A-Za-z_]\w*(?:Reply|Msg|Message|Packet|Header|Record|Job|Ctx|Context))\s+"
            r"(?P<var>[A-Za-z_]\w*)\s*;",
            line.text,
        )
        if decl:
            var = decl.group("var")
            local_aggregates[var] = (line, decl.group("type"))
            aggregate_field_writes.setdefault(var, set())
        field = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*\.\s*(?P<field>[A-Za-z_]\w*)\s*=", line.text)
        if field and field.group("var") in aggregate_field_writes:
            aggregate_field_writes[field.group("var")].add(field.group("field"))
        memset = re.search(r"\bmemset\s*\(\s*&?\s*(?P<var>[A-Za-z_]\w*)\s*,\s*0\s*,\s*sizeof\s*\(\s*(?P=var)\s*\)\s*\)", line.text)
        if memset and memset.group("var") in aggregate_field_writes:
            aggregate_field_writes[memset.group("var")].add("*zero_initialized*")

    def _maybe_emit_stack_array_overflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(
            r"\b(?:char|unsigned\s+char|uint8_t|int|uint32_t|size_t)\s+"
            r"(?P<array>[A-Za-z_]\w*)\s*\[\s*(?P<size>[^\]]*[A-Za-z_]\w*[^\]]*)\s*\]\s*;",
            line.text,
        )
        if not match:
            return
        size = match.group("size").strip()
        if self._is_compile_time_size_expr(size):
            return
        guard_window = "\n".join(item.text for item in lines[max(0, line.index - 8) : line.index])
        if re.search(rf"\b{re.escape(size)}\b\s*(?:<|<=)\s*\d+", guard_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="stack_overflow",
            rule="clang_cfg_unbounded_vla_or_stack_array",
            line=line,
            description=f"Stack array `{match.group('array')}` uses runtime size `{size}` without a visible cap.",
            root_cause="Caller-controlled or data-dependent stack allocation can exhaust or overflow the stack.",
            suggested_fix="Cap the size before stack allocation or allocate bounded heap storage.",
            source=size,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[f"line {line.number}: stack allocation size `{size}` is runtime-derived"],
            negative=["Validator must confirm no caller-side bound constrains this size."],
            ast_cfg=self._ast_cfg_pack(lines, [self._event("runtime_stack_array", line, match.group("array"), "", line.text)], [line.number]),
        )

    def _maybe_emit_heap_copy_length_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        copy_call = re.search(
            r"\b(?P<api>memcpy|memmove)\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*[^,]+,\s*(?P<len>[^)]+)\)",
            line.text,
        )
        if not copy_call:
            return
        dst = copy_call.group("dst")
        copy_len = copy_call.group("len").strip()
        alloc_data = self._find_allocation_size_assignment(lines, line, dst)
        if alloc_data is None:
            return
        alloc_line, alloc_size = alloc_data
        alloc_base = self._allocation_base_from_size(lines, alloc_line, alloc_size)
        copy_base = self._expression_origin_base(lines, line, copy_len)
        if not alloc_base or not copy_base or alloc_base != copy_base:
            if not self._looks_like_external_length_pair(lines, line, alloc_size, copy_len):
                return
        if self._copy_length_bounded_by_alloc(lines, line, copy_len, alloc_size):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="heap_overflow",
            rule="clang_cfg_narrowed_allocation_original_length_copy",
            line=line,
            description=(
                f"`{dst}` is allocated from narrowed size `{alloc_size}` but copied with original length `{copy_len}`."
            ),
            root_cause="A truncated allocation size can be smaller than the subsequent copy length.",
            suggested_fix="Allocate from the same checked length used by the copy, or reject values that do not fit the allocation type.",
            source=alloc_line.text,
            sink=line.text,
            confidence=0.88,
            impact_level="high",
            positive=[
                f"line {alloc_line.number}: allocation for `{dst}` uses narrowed size `{alloc_size}`",
                f"line {line.number}: `{copy_len}` reaches `{copy_call.group('api')}` as the copy length",
            ],
            negative=["Validator must confirm the original length can exceed the narrowed allocation length."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("narrowed_heap_allocation", alloc_line, dst, alloc_size, alloc_line.text),
                    self._event("original_length_heap_copy", line, dst, copy_len, line.text),
                ],
                [alloc_line.number, line.number],
            ),
        )

    def _maybe_emit_offset_length_copy_overread(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        copy_call = re.search(
            r"\b(?P<api>memcpy|memmove)\s*\(\s*[^,]+,\s*(?P<src>[A-Za-z_]\w*)\s*,\s*(?P<len>[^)]+)\)",
            line.text,
        )
        if not copy_call:
            return
        src = copy_call.group("src")
        copy_len = copy_call.group("len").strip()
        source_line = self._find_offset_pointer_assignment(lines, line, src)
        if source_line is None:
            return
        offset_expr = self._offset_expr_from_pointer_assignment(source_line.text, src)
        if not offset_expr:
            return
        guard_window = "\n".join(item.text for item in lines[max(0, source_line.index - 8) : line.index + 1])
        if re.search(
            rf"\b{re.escape(offset_expr)}\b\s*\+\s*{re.escape(copy_len)}\s*(?:<=|<)\s*(?:[A-Za-z_]\w*len|[A-Za-z_]\w*_len|sizeof\s*\()",
            guard_window,
        ):
            return
        if not re.search(r"(?:offset|digest|header|wire|len|length|size)", f"{offset_expr} {copy_len}", re.I):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="buffer_overread",
            rule="clang_cfg_offset_length_copy_without_source_bound",
            line=line,
            description=f"`{src}` is derived from unchecked offset `{offset_expr}` and copied with `{copy_len}`.",
            root_cause="The code validates neither the offset nor offset-plus-length against the backing input buffer.",
            suggested_fix="Require `offset <= buffer_len` and `copy_len <= buffer_len - offset` before deriving the source pointer.",
            source=source_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{src}` is derived from a buffer plus `{offset_expr}`",
                f"line {line.number}: `{src}` reaches `{copy_call.group('api')}` with length `{copy_len}`",
            ],
            negative=["Validator must confirm no caller-side packet bound dominates the offset and length."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("offset_pointer", source_line, src, offset_expr, source_line.text),
                    self._event("offset_length_copy", line, src, copy_len, line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_pointer_backtrack_underflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        sink = re.search(
            r"\b(?P<api>memcpy|memmove|memset|strncpy)\s*\(\s*(?P<args>.*)\)",
            line.text,
        )
        if not sink:
            return
        args = self._split_args(sink.group("args"))
        if not args:
            return
        api = sink.group("api")
        pointer_arg = args[1] if api in {"memcpy", "memmove", "strncpy"} and len(args) > 1 else args[0]
        pointer_arg = pointer_arg.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", pointer_arg):
            return
        source_line = self._find_pointer_backtrack_assignment(lines, line, pointer_arg)
        if source_line is None:
            return
        defect = "buffer_underwrite" if api == "memset" or (api in {"memcpy", "memmove", "strncpy"} and args[0].strip() == pointer_arg) else "buffer_underread"
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class=defect,
            rule="clang_cfg_unchecked_pointer_backtrack",
            line=line,
            description=f"`{pointer_arg}` is derived by subtracting an unchecked offset and then used by `{api}`.",
            root_cause="A caller- or wire-controlled backtrack can move a pointer before the start of the buffer.",
            suggested_fix="Validate the backtrack/offset against the available buffer length before deriving the pointer.",
            source=source_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{pointer_arg}` is derived with subtraction from a buffer pointer",
                f"line {line.number}: `{pointer_arg}` is used by `{api}`",
            ],
            negative=["Validator must confirm the subtracted offset is externally controlled and lacks a dominating bound."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("pointer_backtrack", source_line, pointer_arg, "", source_line.text),
                    self._event("backtracked_pointer_sink", line, pointer_arg, api, line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_invalid_free(
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
        api, arg = release
        cleaned = arg.strip()
        if re.fullmatch(r"[A-Za-z_]\w*", cleaned):
            return
        if not re.search(r"(?<!-)\+|\s-\s|-\s*\d|&\s*[A-Za-z_]|\[[^\]]+\]", cleaned):
            return
        if self._is_owned_pointer_array_element_release(lines, line, cleaned):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="invalid_free",
            rule="clang_cfg_free_non_owner_pointer_expression",
            line=line,
            description=f"`{api}` is called on non-owner pointer expression `{cleaned}`.",
            root_cause="A deallocator receives an interior, stack, or adjusted pointer rather than the owning allocation base.",
            suggested_fix="Free only the owning base pointer returned by the allocator.",
            source=cleaned,
            sink=line.text,
            confidence=0.9,
            impact_level="high",
            positive=[f"line {line.number}: deallocator argument is `{cleaned}`, not a plain owner variable"],
            negative=[],
            ast_cfg=self._ast_cfg_pack(lines, [self._event("invalid_free", line, cleaned, api, line.text)], [line.number]),
        )

    def _maybe_emit_interior_free_alias(
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
        api, arg = release
        var = arg.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", var):
            return
        derivation = self._find_pointer_derivation(lines, line, var)
        if derivation is None:
            return
        source_line, base, operation = derivation
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="invalid_free",
            rule="clang_cfg_free_derived_pointer_alias",
            line=line,
            description=f"`{api}` is called on `{var}`, which was derived from `{base}` by pointer arithmetic.",
            root_cause="The deallocator receives an alias to an interior/adjusted address rather than the owning allocation base.",
            suggested_fix=f"Keep `{base}` as the owner passed to `{api}` and use a separate non-owning cursor for offsets.",
            source=source_line.text,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{operation}` derives `{var}` from `{base}`",
                f"line {line.number}: `{api}` releases derived alias `{var}`",
            ],
            negative=["Validator must confirm the base object was heap-owned and the alias does not equal the allocation base on all paths."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("pointer_derivation", source_line, var, base, source_line.text),
                    self._event("invalid_free_alias", line, var, api, line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_unchecked_allocation_result(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        var = self._first_direct_deref_var(line.text)
        if not var:
            return
        alloc_line = self._find_allocation_assignment(lines, line, var)
        if alloc_line is None:
            return
        if self._has_terminating_null_guard(lines, alloc_line, line, var):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="unchecked_allocation",
            rule="clang_cfg_allocation_result_used_without_null_check",
            line=line,
            description=f"Allocation result `{var}` is used before a visible NULL check.",
            root_cause="The allocation return value can be NULL and the local path dereferences or indexes it first.",
            suggested_fix=f"Check `{var}` for NULL before any dereference, indexing, or write.",
            source=alloc_line.text,
            sink=line.text,
            confidence=0.76,
            impact_level="high",
            positive=[
                f"line {alloc_line.number}: `{var}` receives an allocation result",
                f"line {line.number}: `{var}` is consumed before a visible NULL guard",
            ],
            negative=["Validator must confirm no wrapper contract guarantees a non-NULL result."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("allocation_result", alloc_line, var, "", alloc_line.text),
                    self._event("unchecked_allocation_use", line, var, "", line.text),
                ],
                [alloc_line.number, line.number],
            ),
        )

    def _maybe_emit_fixed_array_count_overflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        write = re.search(
            r"\b(?P<array>[A-Za-z_]\w*)\s*\[\s*(?P<index>[A-Za-z_]\w*)\s*\]"
            r"\s*(?:\.|->)?\s*[A-Za-z_0-9]*\s*=",
            line.text,
        )
        if not write:
            return
        array = write.group("array")
        index_var = write.group("index")
        decl_line, array_size = self._find_fixed_array_decl(lines, line, array)
        if decl_line is None:
            return
        loop_line, count_expr = self._find_count_loop_for_index(lines, line, index_var)
        if loop_line is None:
            return
        if self._count_is_obviously_bounded(lines, line, array, array_size, count_expr):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="out_of_bounds_write",
            rule="clang_cfg_unbounded_count_indexes_fixed_array",
            line=line,
            description=f"Loop count `{count_expr}` indexes fixed array `{array}[{array_size}]` without a visible array-size guard.",
            root_cause="An externally derived count can drive writes past the local fixed-size buffer.",
            suggested_fix=f"Validate `{count_expr}` against `ARRAY_SIZE({array})` before the loop or clamp the loop bound.",
            source=f"{array} declaration at line {decl_line.number}; loop at line {loop_line.number}",
            sink=line.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {decl_line.number}: `{array}` is a fixed-size local array",
                f"line {loop_line.number}: loop bound is `{count_expr}`",
                f"line {line.number}: `{array}[{index_var}]` is written inside the loop",
            ],
            negative=["Validator must confirm the loop count is not constrained by a caller-side or earlier protocol guard."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("fixed_array", decl_line, array, array_size, decl_line.text),
                    self._event("count_loop", loop_line, index_var, count_expr, loop_line.text),
                    self._event("array_write", line, array, index_var, line.text),
                ],
                [decl_line.number, loop_line.number, line.number],
            ),
        )

    def _maybe_emit_key_truncation(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        trunc = re.search(
            r"\bstrncpy\s*\(\s*(?P<dst>[A-Za-z_]\w*\s*->\s*(?:key|name|id)|[A-Za-z_]\w*\.(?:key|name|id))\s*,\s*"
            r"(?P<src>[A-Za-z_]\w*)\s*,\s*(?P<limit>\d+|[A-Z_][A-Z0-9_]*)\s*\)",
            line.text,
        )
        if not trunc:
            return
        src = trunc.group("src")
        lookup_line = self._find_prior_full_key_lookup(lines, line, src)
        if lookup_line is None:
            return
        guard_window = "\n".join(item.text for item in lines[max(0, lookup_line.index - 4) : line.index + 1])
        if re.search(rf"\bstrlen\s*\(\s*{re.escape(src)}\s*\)\s*(?:<|<=)\s*{re.escape(trunc.group('limit'))}\b", guard_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="key_truncation",
            rule="clang_cfg_full_key_lookup_truncated_key_insert",
            line=line,
            description=f"`{src}` is looked up at full length but stored through fixed-length `{trunc.group('dst')}`.",
            root_cause="Lookup and insertion use different key equivalence domains, so long keys can collide or bypass an existing record.",
            suggested_fix="Validate key length before lookup or use the same bounded key representation for lookup and insertion.",
            source=lookup_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {lookup_line.number}: lookup/find uses full key `{src}`",
                f"line {line.number}: `{src}` is copied into `{trunc.group('dst')}` with fixed limit `{trunc.group('limit')}`",
            ],
            negative=["Validator must confirm the destination key length is shorter than accepted input keys."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("full_key_lookup", lookup_line, src, "", lookup_line.text),
                    self._event("truncated_key_store", line, src, trunc.group("limit"), line.text),
                ],
                [lookup_line.number, line.number],
            ),
        )

    def _maybe_emit_wire_integer_pointer_deref(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        direct = re.search(
            r"\*\s*\([^;)]*\*\s*\)\s*(?:\([^)]*\)\s*)?(?P<src>[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)",
            line.text,
        )
        if direct and self._looks_wire_pointer_source(direct.group("src")):
            source_line = line
            var = direct.group("src")
        else:
            var = self._first_direct_deref_var(line.text)
            if not var:
                return
            source_line = self._find_wire_pointer_assignment(lines, line, var)
            if source_line is None:
                return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="untrusted_pointer",
            rule="clang_cfg_wire_integer_cast_to_pointer_deref",
            line=line,
            description="A serialized/header integer is converted to a process pointer and dereferenced.",
            root_cause="Wire data cannot be trusted as an in-process address; dereferencing it can access arbitrary memory.",
            suggested_fix="Treat wire values as opaque offsets or handles and resolve them through a validated table.",
            source=source_line.text,
            sink=line.text,
            confidence=0.88,
            impact_level="critical",
            positive=[
                f"line {source_line.number}: wire/header-derived value is cast into pointer `{var}`",
                f"line {line.number}: the resulting pointer is dereferenced",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("wire_pointer_cast", source_line, var, "", source_line.text),
                    self._event("wire_pointer_deref", line, var, "", line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_unchecked_object_offset_access(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        var = self._first_direct_deref_var(line.text)
        if not var:
            return
        offset_data = self._find_object_offset_assignment(lines, line, var)
        if offset_data is None:
            return
        source_line, object_name, offset_expr = offset_data
        guard_window = "\n".join(item.text for item in lines[source_line.index + 1 : line.index + 1])
        if re.search(
            rf"\b{re.escape(offset_expr)}\b\s*(?:<|<=)\s*sizeof\s*\(\s*&?\s*{re.escape(object_name)}\s*\)",
            guard_window,
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="out_of_range_pointer_offset",
            rule="clang_cfg_unchecked_object_offset_deref",
            line=line,
            description=f"Offset `{offset_expr}` is applied inside local object `{object_name}` and then dereferenced without a `sizeof` guard.",
            root_cause="An external offset can form a pointer outside the local object before the later access.",
            suggested_fix=f"Validate `{offset_expr} < sizeof({object_name})` and the requested access width before deriving the pointer.",
            source=source_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{var}` is derived from `&{object_name}` plus `{offset_expr}`",
                f"line {line.number}: `{var}` is dereferenced",
            ],
            negative=["Validator must confirm the offset is externally controlled and not already range checked."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("object_offset_pointer", source_line, var, offset_expr, source_line.text),
                    self._event("object_offset_access", line, var, "", line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_uninitialized_pointer_use(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        var = self._first_direct_deref_var(line.text)
        if not var:
            return
        decl_line = self._find_uninitialized_pointer_decl(lines, line, var)
        if decl_line is None:
            return
        assigns = [
            item
            for item in lines[decl_line.index + 1 : line.index]
            if re.search(rf"\b{re.escape(var)}\s*=", item.text)
        ]
        if assigns and any(not self._is_conditional_statement(lines, item) for item in assigns):
            return
        if any(self._is_null_guard(item.text, var) for item in lines[decl_line.index + 1 : line.index + 1]):
            return
        assignment_note = "only conditional assignments appear before use" if assigns else "no assignment appears before use"
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="uninitialized_pointer",
            rule="clang_cfg_pointer_may_be_uninitialized_before_use",
            line=line,
            description=f"Pointer `{var}` may be read before being initialized on all local paths.",
            root_cause="The local CFG view finds a pointer declaration without an initializer and no unconditional assignment before use.",
            suggested_fix=f"Initialize `{var}` to NULL and gate every dereference on a successful assignment.",
            source=decl_line.text,
            sink=line.text,
            confidence=0.78,
            impact_level="high",
            positive=[
                f"line {decl_line.number}: `{var}` is declared without an initializer",
                f"line {line.number}: `{var}` is dereferenced; {assignment_note}",
            ],
            negative=["Validator must confirm no macro or control-flow contract initializes the pointer on all paths."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("uninitialized_pointer_decl", decl_line, var, "", decl_line.text),
                    self._event("uninitialized_pointer_use", line, var, "", line.text),
                ],
                [decl_line.number, line.number],
            ),
        )

    def _maybe_emit_unbounded_heap_allocation(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        for api, args in self._calls(line.text):
            if api not in self._return_acquirers and not re.search(r"(?:malloc|calloc|alloc|realloc)$", api, re.IGNORECASE):
                continue
            count_expr = self._allocation_count_expression(api, args)
            if not count_expr:
                continue
            resolved_count_expr = count_expr
            if not self._looks_external_size_expr(resolved_count_expr):
                resolved = self._resolve_recent_assignment_expr(lines, line, resolved_count_expr)
                if resolved and self._looks_external_size_expr(resolved):
                    resolved_count_expr = resolved
            if not self._looks_external_size_expr(resolved_count_expr):
                continue
            guard_window = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index])
            if self._has_allocation_limit_guard(guard_window, resolved_count_expr):
                continue
            if self._has_small_count_bound_proof(lines, line, resolved_count_expr):
                continue
            if self._has_narrowing_bound_proof(lines, line, resolved_count_expr) and self._allocation_has_total_local_lifetime_proof(lines, line, resolved_count_expr):
                continue
            if self._allocation_has_total_local_lifetime_proof(lines, line, resolved_count_expr):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="resource_allocation_without_limits",
                rule="clang_cfg_external_size_allocation_without_limit",
                line=line,
                description=f"Heap allocation size `{resolved_count_expr}` is externally/data derived without a visible quota or protocol cap.",
                root_cause="A caller- or wire-controlled size can allocate unbounded heap memory on this local path.",
                suggested_fix="Enforce a protocol, per-client, or global maximum before allocating.",
                source=resolved_count_expr,
                sink=line.text,
                confidence=0.7,
                positive=[f"line {line.number}: `{api}` allocation is driven by `{resolved_count_expr}`"],
                negative=["Validator must confirm the size is externally controlled and no earlier caller-side cap dominates this path."],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [self._event("unbounded_allocation", line, resolved_count_expr, api, line.text)],
                    [line.number],
                ),
            )
            return

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
            negative=["Validator must confirm the descriptor was not transferred to a durable owner before this return."],
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
        body_hint = f"{self._function_name_hint(func_name, lines)}\n" + "\n".join(item.text for item in lines[: min(len(lines), 6)])
        if not re.search(r"(?:register|upsert|insert|set|install|add|registry|slot|plugin)", body_hint, re.IGNORECASE):
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
        if re.search(rf"\b(?:free|SAFE_FREE|cleanup|destroy|release)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(slot)}\s*->", region, re.I):
            return
        if re.search(rf"\bif\s*\([^)]*\b{re.escape(slot)}\s*->\s*(?:context|ctx|cleanup|handle|name)", region):
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
            negative=["Validator must confirm the slot can already contain an owned context or plugin instance."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("slot_overwrite", line, slot, assign.group("field"), line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_key_generation_race(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        body_hint = f"{self._function_name_hint(func_name, lines)}\n" + "\n".join(item.text for item in lines)
        if not re.search(r"(?:key|ftok|_file_exists|file_exists)", body_hint, re.IGNORECASE):
            return
        if not re.search(r"\b[A-Za-z_]\w*\s*=\s*[^;]*(?:hash|ftok|project|path)[^;]*;", line.text, re.IGNORECASE):
            return
        prefix = lines[max(0, line.index - 12) : line.index]
        suffix = lines[line.index + 1 : min(len(lines), line.index + 12)]
        path_check = next((item for item in reversed(prefix) if re.search(r"\b(?:access|stat|lstat|_file_exists|file_exists)\s*\(", item.text)), None)
        locked_lookup = next(
            (
                item
                for item in suffix
                if re.search(r"\bLOCK\s*\(", item.text)
                and re.search(r"\b[A-Za-z_]\w*(?:find|lookup|register|zone)[A-Za-z_0-9]*\s*\(", item.text, re.I)
            ),
            None,
        )
        if path_check is None or locked_lookup is None:
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="key_generation_race",
            rule="clang_cfg_path_state_key_generation_before_locked_registration",
            line=line,
            description="Path/key state is checked and hashed before the locked registration lookup.",
            root_cause="A file/path based key can be generated from stale path state before the lock that protects registration and collision checks.",
            suggested_fix="Hold one lock or use an atomic create/register operation across path validation, key generation, and registration lookup.",
            source=path_check.text,
            sink=line.text,
            confidence=0.74,
            impact_level="high",
            positive=[
                f"line {path_check.number}: path state is checked before key generation",
                f"line {line.number}: key material is computed outside the registration lock",
                f"line {locked_lookup.number}: registration/collision lookup happens later under lock",
            ],
            negative=["Validator must confirm the path/key namespace is shared across concurrent callers."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("path_state_check", path_check, "", "", path_check.text),
                    self._event("key_generation", line, "", "", line.text),
                    self._event("locked_registration_lookup", locked_lookup, "", "", locked_lookup.text),
                ],
                [path_check.number, line.number, locked_lookup.number],
            ),
        )

    def _maybe_emit_file_type_validation_order(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if not self._is_file_type_check(line.text):
            return
        prior = lines[max(0, line.index - 28) : line.index]
        stat_line = self._last_line_matching(
            prior,
            re.compile(r"\b(?:fstat|stat|lstat|fstatat)\s*\(", re.IGNORECASE),
        )
        size_or_map_line = self._last_line_matching(
            lines[(stat_line.index + 1) if stat_line is not None else max(0, line.index - 28) : line.index],
            re.compile(
                r"\b(?:mmap|MapViewOfFile|st_size|file_size|map_size|mapping_size|length|len|size)\b.*(?:<|>|==|!=|<=|>=)",
                re.IGNORECASE,
            ),
        )
        if size_or_map_line is None:
            return
        earlier_start = (stat_line.index + 1) if stat_line is not None else max(0, line.index - 28)
        if any(self._is_file_type_check(item.text) for item in lines[earlier_start : size_or_map_line.index]):
            return
        metadata_line = stat_line or (lines[0] if lines else size_or_map_line)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="file_type_validation",
            rule="clang_cfg_file_type_validation_after_mapping_size_check",
            line=line,
            description="File size or mapping validation occurs before the file type is validated.",
            root_cause=(
                "The local path reasons about mapping size before proving the descriptor refers "
                "to an acceptable regular/device file type."
            ),
            suggested_fix="Validate the file type/mode immediately after stat/fstat and before size or mmap decisions.",
            source=size_or_map_line.text,
            sink=line.text,
            confidence=0.72,
            positive=[
                f"line {metadata_line.number}: file mode/size metadata is available",
                f"line {size_or_map_line.number}: mapping/size decision uses metadata before type validation",
                f"line {line.number}: file type is checked only later",
            ],
            negative=["Validator must confirm the earlier mapping/size decision can affect security before the type check."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("file_metadata", metadata_line, "", "stat_or_params", metadata_line.text),
                    self._event("mapping_size_decision", size_or_map_line, "", "", size_or_map_line.text),
                    self._event("late_file_type_validation", line, "", "", line.text),
                ],
                [metadata_line.number, size_or_map_line.number, line.number],
            ),
        )

    def _maybe_emit_active_owner_premature_destroy(
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
        api, arg = release
        resource = self._resource_expr(arg) or self._resource_var(arg)
        if not resource:
            return
        if not re.search(r"(?:^g_|->|\.|pool|cache|shared|global)", resource, re.IGNORECASE):
            return
        branch = self._enclosing_branch_start(lines, line)
        branch_text = branch.text if branch is not None else ""
        if not re.search(
            r"\b(?:active|users?|tasks?|refs?|refcount|inflight|pending|busy)[A-Za-z_0-9]*\b\s*(?:>|!=|>=)\s*0",
            branch_text,
            re.IGNORECASE,
        ):
            return
        guard_window = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index + 1])
        if re.search(r"\b(?:LOCK|pthread_mutex_lock|spin_lock|refcount_dec_and_test|atomic_dec_and_test)\s*\(", guard_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="premature_destroy",
            rule="clang_cfg_active_owner_destroy_without_quiescence",
            line=line,
            description=f"Shared resource `{resource}` is destroyed while an active-use guard is true.",
            root_cause=(
                "A pool/cache/global owner is released on a path that explicitly observes active users "
                "or tasks, without a visible quiescence/refcount guard."
            ),
            suggested_fix="Wait for active users to drain or transfer ownership through a refcounted shutdown path before freeing.",
            source=branch_text or line.text,
            sink=f"{api}({arg})",
            confidence=0.76,
            impact_level="high",
            positive=[
                f"line {branch.number if branch is not None else line.number}: active-use condition guards the branch",
                f"line {line.number}: `{resource}` is released inside that branch",
            ],
            negative=["Validator must confirm no external synchronization or quiescence contract dominates this release."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("active_use_branch", branch or line, resource, "", branch_text or line.text),
                    self._event("premature_destroy", line, resource, api, line.text),
                ],
                [branch.number if branch is not None else line.number, line.number],
            ),
        )

    def _maybe_emit_thread_stack_escape(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        for api, args in self._calls(line.text):
            if api != "pthread_create":
                continue
            split = self._split_args(args)
            if len(split) < 4:
                continue
            arg = split[3].strip()
            match = re.match(r"&\s*(?P<var>[A-Za-z_]\w*)$", arg)
            if not match:
                continue
            var = match.group("var")
            decl_line, type_name = local_aggregates.get(var, (None, ""))  # type: ignore[assignment]
            if decl_line is None:
                continue
            worker = split[2].strip()
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="stack_escape",
                rule="clang_cfg_stack_address_passed_to_thread",
                line=line,
                description=f"Stack object `{var}` is passed to thread entry `{worker}`.",
                root_cause="The spawned thread can outlive the caller's stack frame and dereference a dangling thread argument.",
                suggested_fix="Allocate the thread argument with an ownership handoff or join before returning.",
                source=f"{type_name} {var} at line {decl_line.number}",
                sink=line.text,
                confidence=0.9,
                impact_level="high",
                positive=[
                    f"line {decl_line.number}: `{var}` is a local stack object",
                    f"line {line.number}: `pthread_create` passes `&{var}` to `{worker}`",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("stack_object", decl_line, var, type_name, decl_line.text),
                        self._event("thread_arg_escape", line, var, worker, line.text),
                    ],
                    [decl_line.number, line.number],
                ),
            )

    def _maybe_emit_partial_aggregate_send(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]],
        aggregate_field_writes: Dict[str, Set[str]],
    ) -> None:
        for api, args in self._calls(line.text):
            split = self._split_args(args)
            if api not in self._send_sink_names and api not in self._copy_sink_names:
                continue
            for var, (decl_line, type_name) in local_aggregates.items():
                if not any(re.search(rf"&\s*{re.escape(var)}\b", arg) for arg in split):
                    continue
                if not any(re.search(rf"sizeof\s*\(\s*{re.escape(var)}\s*\)", arg) for arg in split):
                    continue
                writes = aggregate_field_writes.get(var, set())
                if "*zero_initialized*" in writes:
                    continue
                if len(writes) == 0:
                    continue
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="uninitialized_read",
                    rule="clang_cfg_partial_aggregate_sent_with_sizeof",
                    line=line,
                    description=f"Partially initialized local aggregate `{var}` is sent/copied with `sizeof({var})`.",
                    root_cause="Padding or unassigned fields can leak stale stack bytes when the whole object is serialized.",
                    suggested_fix="Zero-initialize the aggregate or serialize only initialized fields.",
                    source=f"{type_name} {var} at line {decl_line.number}",
                    sink=line.text,
                    confidence=0.86,
                    impact_level="high",
                    positive=[
                        f"line {decl_line.number}: local aggregate `{var}` is declared without initializer",
                        f"fields assigned before send: {', '.join(sorted(writes))}",
                        f"line {line.number}: `{api}` consumes `&{var}` with `sizeof({var})`",
                    ],
                    negative=["Validator must confirm the type has padding or unassigned fields relevant to the serialized boundary."],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event("aggregate_decl", decl_line, var, type_name, decl_line.text),
                            self._event("aggregate_send", line, var, api, line.text),
                        ],
                        [decl_line.number, line.number],
                    ),
                )
                return

    def _maybe_track_or_emit_alignment(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        unaligned_ptrs: Dict[str, ClangCfgLine],
    ) -> None:
        cast = re.search(
            r"\b(?:const\s+)?(?:uint(?:16|32|64)_t|int(?:16|32|64)_t|unsigned\s+int|int)\s*\*\s*"
            r"(?P<var>[A-Za-z_]\w*)\s*=\s*\([^;]*\*\s*\)\s*\([^;]*\+\s*1\s*\)",
            line.text,
        )
        if cast:
            unaligned_ptrs[cast.group("var")] = line
        for var, cast_line in list(unaligned_ptrs.items()):
            if line.index <= cast_line.index:
                continue
            if not re.search(rf"\*\s*{re.escape(var)}\b", line.text):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="alignment",
                rule="clang_cfg_unaligned_integer_pointer_cast",
                line=cast_line,
                description="Byte-buffer data is cast to an integer pointer at an unaligned offset and later dereferenced.",
                root_cause="The cast requires alignment that `packet + 1` style byte offsets do not guarantee.",
                suggested_fix="Use memcpy into an aligned integer object or decode bytes explicitly.",
                source=cast_line.text,
                sink=line.text,
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {cast_line.number}: integer pointer formed from byte offset",
                    f"line {line.number}: pointer is dereferenced",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("unaligned_pointer_cast", cast_line, var, "", cast_line.text),
                        self._event("unaligned_deref", line, var, "", line.text),
                    ],
                    [cast_line.number, line.number],
                ),
            )
            unaligned_ptrs.pop(var, None)

    def _maybe_emit_macro_lock_race(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        macro_locks = self._macro_guard_names(lines, lock=True)
        macro_unlocks = self._macro_guard_names(lines, lock=False)
        if not macro_locks or not macro_unlocks:
            return
        match = re.search(r"\b(?P<global>g_[A-Za-z_0-9]*(?:counter|state|flag)[A-Za-z_0-9]*)\s*=", line.text)
        if not match:
            return
        if not self._line_between_macro_guards(lines, line, macro_locks, macro_unlocks):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="race",
            rule="clang_cfg_macro_guarded_lock_may_compile_to_noop",
            line=line,
            description=f"`{match.group('global')}` is updated under a macro-like lock guard that may compile to a no-op on some targets.",
            root_cause="Configuration-sensitive macro locking can disappear on unsupported builds while the shared state remains mutable.",
            suggested_fix="Use a lock implementation that is present on every supported target or reject unsupported builds.",
            source=", ".join(sorted(macro_locks)),
            sink=line.text,
            confidence=0.74,
            positive=[
                "function uses macro-like lock/unlock guards",
                f"line {line.number}: shared global state is updated",
            ],
            negative=["Validator must confirm the active build configuration includes a no-op macro variant."],
            ast_cfg=self._ast_cfg_pack(lines, [self._event("macro_guarded_write", line, match.group("global"), "", line.text)], [line.number]),
        )

    def _maybe_emit_callback_under_lock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        held_locks: Sequence[ClangCfgLine],
    ) -> None:
        if not held_locks:
            return
        if not re.search(r"\b[A-Za-z_]\w*(?:callback|cb|handler)[A-Za-z_0-9]*\s*\(", line.text, re.IGNORECASE):
            return
        lock_line = held_locks[-1]
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="held_lock_callback",
            rule="clang_cfg_callback_while_lock_held",
            line=line,
            description="Callback/function-pointer style call is made while a lock is held.",
            root_cause="A callback contract can re-enter the same subsystem or acquire conflicting locks if callers can register nontrivial callback code.",
            suggested_fix="Copy required state under the lock, release the lock, then invoke the callback.",
            source=f"lock at line {lock_line.number}",
            sink=line.text,
            confidence=0.68,
            impact_level="medium",
            positive=[
                f"line {lock_line.number}: lock acquired",
                f"line {line.number}: callback-like call before unlock",
            ],
            negative=["Validator must confirm whether callback registration is externally controllable or can re-enter this lock domain."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("lock", lock_line, "lock", "", lock_line.text),
                    self._event("callback_call", line, "callback", "", line.text),
                ],
                [lock_line.number, line.number],
            ),
        )

    def _maybe_emit_concurrency_protocols(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
        emitted_shared_state: Set[str],
    ) -> None:
        dcl = re.search(r"\bif\s*\(\s*!\s*(?P<obj>g_[A-Za-z_]\w*)\s*\)", line.text)
        if dcl:
            obj = dcl.group("obj")
            window = "\n".join(item.text for item in lines[idx + 1 : idx + 10])
            if self._lock_call_re.search(window) and re.search(rf"\bif\s*\(\s*!\s*{re.escape(obj)}\s*\)", window):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="double_checked_locking",
                    rule="clang_cfg_double_checked_global_without_atomic",
                    line=line,
                    description=f"`{obj}` is checked outside the mutex before lazy initialization.",
                    root_cause="Readers outside the lock can observe stale or partially initialized shared state.",
                    suggested_fix="Guard all accesses with the same lock or use atomic acquire/release publication.",
                    source=obj,
                    sink="double checked locking",
                    confidence=0.78,
                    impact_level="high",
                    positive=[f"line {line.number}: first `{obj}` check occurs outside the lock"],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(lines, [self._event("double_checked_read", line, obj, "", line.text)], [line.number]),
                )

        publish = re.search(r"\b(?P<global>g_[A-Za-z_0-9.]+)\s*=\s*(?P<obj>[A-Za-z_]\w*)\s*;", line.text)
        if publish:
            obj = publish.group("obj")
            later = lines[idx + 1 : idx + 9]
            if any(re.search(rf"\b{re.escape(obj)}->[A-Za-z_]\w*\s*=", item.text) for item in later):
                last_init = max(
                    (
                        item.index
                        for item in later
                        if re.search(rf"\b{re.escape(obj)}->[A-Za-z_]\w*\s*=", item.text)
                    ),
                    default=line.index,
                )
                if self._same_lock_region_without_escape(lines, idx, last_init):
                    return
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="object_publication",
                    rule="clang_cfg_object_published_before_initialization",
                    line=line,
                    description=f"`{obj}` is linked into shared state before later field initialization completes.",
                    root_cause="Concurrent readers can observe a partially initialized object after publication.",
                    suggested_fix="Initialize all fields before inserting the object into global/shared containers.",
                    source=obj,
                    sink=line.text,
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: object is published to `{publish.group('global')}`",
                        "later statements initialize fields after publication",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(lines, [self._event("unsafe_publication", line, obj, "", line.text)], [line.number]),
                )

        if "pthread_cond_wait" in line.text:
            previous = lines[max(0, idx - 4) : idx]
            if any(re.search(r"\bif\s*\(", item.text) for item in previous) and not any(
                re.search(r"\bwhile\s*\(", item.text) for item in previous
            ):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="lost_wakeup",
                    rule="clang_cfg_cond_wait_guarded_by_if",
                    line=line,
                    description="Condition variable wait is guarded by `if` rather than a predicate loop.",
                    root_cause="Spurious wakeups or missed predicate changes can let execution continue with a false predicate.",
                    suggested_fix="Guard pthread_cond_wait with a while loop that rechecks the shared predicate.",
                    source="condition predicate",
                    sink=line.text,
                    confidence=0.86,
                    impact_level="high",
                    positive=[
                        "nearby branch uses `if` before pthread_cond_wait",
                        f"line {line.number}: condition variable wait",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(lines, [self._event("cond_wait", line, "cond", "pthread_cond_wait", line.text)], [line.number]),
                )

        self._maybe_emit_borrowed_return_after_unlock(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            line,
        )

        race = re.search(
            r"\b(?P<global>g_[A-Za-z_0-9]*(?:counter|flag|running|shutdown|state|status|ready|stop|done|active|enabled)[A-Za-z_0-9]*)\b",
            line.text,
            re.IGNORECASE,
        )
        if not race or self._match_lock(line.text) or self._match_unlock(line.text):
            return
        global_name = race.group("global")
        if global_name in emitted_shared_state:
            return
        if re.search(r"\+\+|--|while\s*\(|if\s*\(|=[^=]", line.text):
            emitted_shared_state.add(global_name)
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="race",
                rule="clang_cfg_unsynchronized_shared_flag_or_counter",
                line=line,
                description=f"`{global_name}` is accessed without an evident lock or atomic operation.",
                root_cause="Shared flag/counter access is not consistently synchronized across threads.",
                suggested_fix="Use a mutex or atomic operations for all reads and writes of the shared state.",
                source=global_name,
                sink=line.text,
                confidence=0.72,
                positive=[f"line {line.number}: unsynchronized shared global access"],
                negative=["Validator must confirm the variable is shared across threads or signal paths."],
                ast_cfg=self._ast_cfg_pack(lines, [self._event("shared_state_access", line, global_name, "", line.text)], [line.number]),
            )

    def _maybe_emit_borrowed_return_after_unlock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(r"\breturn\s+(?P<ret>[A-Za-z_]\w*)\s*;", line.text)
        if not match:
            return
        ret = match.group("ret")
        previous = list(reversed(lines[max(0, line.index - 14) : line.index]))
        assigned: Optional[ClangCfgLine] = None
        saw_unlock = False
        for item in previous:
            if self._match_unlock(item.text):
                saw_unlock = True
            if re.search(rf"\b{re.escape(ret)}\s*=\s*[^;]*->[A-Za-z_]\w*", item.text):
                assigned = item
                break
        if not assigned or not saw_unlock:
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="use_after_free",
            rule="clang_cfg_borrowed_pointer_returned_after_unlock",
            line=line,
            description=f"Borrowed pointer `{ret}` is returned after the protecting lock is released.",
            root_cause="Concurrent mutation can free or replace the pointee after unlock and before caller use.",
            suggested_fix="Return an owned copy or keep a protected reference before releasing the lock.",
            source=f"borrowed pointer assigned at line {assigned.number}",
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {assigned.number}: borrowed pointer is read from a shared object",
                "an unlock appears before the return",
                f"line {line.number}: borrowed pointer escapes to caller",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("borrowed_pointer_read", assigned, ret, "", assigned.text),
                    self._event("borrowed_pointer_return", line, ret, "", line.text),
                ],
                [assigned.number, line.number],
            ),
        )

    def _maybe_emit_refcount_update_after_unlock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        find_locked = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*(?:find|lookup|get)[A-Za-z_0-9]*locked\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not find_locked:
            return
        var = find_locked.group("var")
        later = lines[idx + 1 : idx + 14]
        unlock_line = next((item for item in later if self._match_unlock(item.text)), None)
        if not unlock_line:
            return
        for item in later:
            if item.index <= unlock_line.index:
                continue
            if not re.search(rf"\b{re.escape(var)}->ref_count\s*(?:\+\+|--|\+=|-=)", item.text):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="refcount_race",
                rule="clang_cfg_refcount_update_after_unlock",
                line=item,
                description=f"`{var}->ref_count` is modified after releasing the lock used for lookup.",
                root_cause="The object reference is found under a mutex, but the reference count update happens after the protection is dropped.",
                suggested_fix="Increment/decrement the reference count under the same lock or use atomic reference counting.",
                source=f"lookup at line {line.number}",
                sink=item.text,
                confidence=0.88,
                impact_level="high",
                positive=[
                    f"line {line.number}: `{var}` is found by a locked lookup helper",
                    f"line {unlock_line.number}: protecting lock is released",
                    f"line {item.number}: `{var}->ref_count` is updated after unlock",
                ],
                negative=["Validator must confirm the lookup helper's lock matches the object lifetime lock."],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("locked_lookup", line, var, "", line.text),
                        self._event("unlock", unlock_line, "lock", "", unlock_line.text),
                        self._event("refcount_update", item, var, "ref_count", item.text),
                    ],
                    [line.number, unlock_line.number, item.number],
                ),
            )
            return

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
            ast_cfg=self._ast_cfg_pack(lines, [self._event("fd_close", line, fd, "close", line.text)], [line.number]),
        )

    def _maybe_emit_borrowed_callback_global(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        match = re.search(
            r"\b(?P<global>g_[A-Za-z_0-9]*(?:callback|cb)?[A-Za-z_0-9]*(?:entry|ctx|context|object|node)[A-Za-z_0-9]*)\s*=\s*"
            r"(?P<lookup>[A-Za-z_]\w*(?:find|lookup|get)[A-Za-z_0-9]*)\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not match:
            return
        window = "\n".join(item.text for item in lines[max(0, idx - 6) : idx + 8])
        if not self._match_lock(window) and "LOCK" not in window:
            return
        if not re.search(r"\bg_[A-Za-z_0-9]*(?:callback|cb|handler)[A-Za-z_0-9]*\s*=", window, re.IGNORECASE):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="use_after_free",
            rule="clang_cfg_global_callback_stores_borrowed_object",
            line=line,
            description=f"Global callback context `{match.group('global')}` stores a borrowed object returned by `{match.group('lookup')}`.",
            root_cause="A global callback can later use the borrowed object after another path removes or frees it.",
            suggested_fix="Store an owned reference for callback context and release it during unregister/remove.",
            source=line.text,
            sink="global callback context",
            confidence=0.78,
            impact_level="high",
            positive=[
                f"line {line.number}: global callback context stores lookup result `{match.group('lookup')}`",
                "nearby code also stores a global callback/handler",
            ],
            negative=["Validator must confirm a reachable remove/unregister path can free the stored object."],
            ast_cfg=self._ast_cfg_pack(lines, [self._event("callback_borrow_store", line, match.group("global"), match.group("lookup"), line.text)], [line.number]),
        )

    def _maybe_emit_mapping_unmap_without_invalidation(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        for api, args in self._calls(line.text):
            if api not in {"munmap", "UnmapViewOfFile"}:
                continue
            first = self._resource_var(self._first_arg(args))
            if not first or not first.startswith("g_"):
                continue
            later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
            if re.search(rf"\b{re.escape(first)}\s*=\s*(?:NULL|nullptr|0|MAP_FAILED)\s*;", later):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="use_after_free",
                rule="clang_cfg_global_mapping_unmapped_without_invalidation",
                line=line,
                description=f"Global mapping pointer `{first}` is unmapped without nearby invalidation.",
                root_cause="Later readers can pass non-null guards and dereference an unmapped global mapping.",
                suggested_fix="Clear the global mapping pointer and length under the same synchronization after unmap.",
                source=first,
                sink=line.text,
                confidence=0.84,
                impact_level="high",
                positive=[f"line {line.number}: `{api}` releases global mapping `{first}` without setting it to NULL nearby"],
                negative=["Validator must confirm a reachable later reader uses the global mapping."],
                ast_cfg=self._ast_cfg_pack(lines, [self._event("global_unmap_without_clear", line, first, api, line.text)], [line.number]),
            )
            return

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
            negative=["Validator must confirm whether ownership is transferred outside this local body."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("acquire", state.line, state.var, state.api, state.line.text),
                    self._event("exit", line, state.var, "", line.text),
                ],
                [state.line.number, line.number],
            ),
        )

    def _encoded_fd_validation_result_is_not_security_sink(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> bool:
        validate = re.search(
            r"\b(?P<api>[A-Za-z_]\w*validate_encoded_fd)\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not validate:
            return False
        arg = validate.group("arg")
        window = "\n".join(item.text for item in lines[line.index : line.index + 10])
        dangerous_use = re.search(
            rf"\b(?:read|recv|write|send|close|dup|fcntl|ioctl|mmap|munmap|_net_[A-Za-z_0-9]+)\s*"
            rf"\([^;]*\b{re.escape(arg)}\b",
            window,
        )
        if dangerous_use:
            return False
        return True

    def _has_dynamic_array_capacity_guard(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        array_name: str,
        idx_name: str,
    ) -> bool:
        cap_candidates = {
            f"{array_name}_cap",
            f"{array_name}_capacity",
            re.sub(r"(?:_array|s|_list)$", "", array_name) + "_cap",
            re.sub(r"(?:_array|s|_list)$", "", array_name) + "_capacity",
        }
        window = lines[max(0, line.index - 28) : line.index + 1]
        for cap in cap_candidates:
            guard_line = self._last_line_matching(
                window,
                re.compile(
                    rf"\bif\s*\(\s*{re.escape(idx_name)}\s*>=\s*{re.escape(cap)}\s*\)"
                ),
            )
            if not guard_line:
                continue
            guarded_text = "\n".join(item.text for item in lines[guard_line.index : line.index + 1])
            if not re.search(rf"\b{re.escape(cap)}\s*=", guarded_text):
                continue
            if not re.search(rf"\b{re.escape(array_name)}\s*=", guarded_text):
                continue
            if not re.search(r"\b(?:calloc|malloc|realloc|_safe_calloc|_safe_malloc|_safe_realloc)\s*\(", guarded_text):
                continue
            if re.search(rf"\bnew_[A-Za-z_0-9]*(?:cap|capacity)\b\s*=.*\b{re.escape(idx_name)}\b", guarded_text):
                return True
            if re.search(rf"\b{re.escape(idx_name)}\s*/\s*\d+u?\s*\)\s*\+\s*1u?\s*\)\s*\*", guarded_text):
                return True
        return False

    def _has_small_count_bound_proof(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: Any,
    ) -> bool:
        text = str(expr or "")
        vars_in_expr = {
            name
            for name in re.findall(r"\b[A-Za-z_]\w*\b", text)
            if name not in {"sizeof", "size_t", "uint32_t", "uint64_t", "int"}
        }
        if not vars_in_expr:
            return False
        window = "\n".join(item.text for item in lines[max(0, line.index - 14) : line.index])
        for var in vars_in_expr:
            parser_bound = re.search(
                rf"\b{re.escape(var)}\s*=\s*[A-Za-z_]\w*(?:parse|split|count)[A-Za-z_0-9]*\s*"
                r"\([^;]*,\s*(?P<limit>\d+)u?\s*\)",
                window,
                re.IGNORECASE,
            )
            if parser_bound and int(parser_bound.group("limit")) < 1000000:
                return True
            explicit_bound = re.search(
                rf"\b{re.escape(var)}\s*(?:<=|<)\s*(?P<limit>\d+)u?\b",
                window,
            )
            if explicit_bound and int(explicit_bound.group("limit")) < 1000000:
                return True
        return False

    def _has_narrowing_bound_proof(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: Any,
    ) -> bool:
        text = str(expr or "")
        if self._narrowed_origin_base(text):
            return True
        for name in self._expr_identifiers(text):
            for item in reversed(lines[max(0, line.index - 16) : line.index]):
                assign = re.search(rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);", item.text)
                if assign and self._narrowed_origin_base(assign.group("rhs")):
                    return True
                decl = re.search(
                    rf"\b(?:uint8_t|uint16_t|unsigned\s+short|unsigned\s+char)\s+{re.escape(name)}\b",
                    item.text,
                )
                if decl:
                    return True
        return False

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
            if re.search(rf"\b(?:free|SAFE_FREE|safe_free|_safe_free)\s*\(\s*{re.escape(var)}\s*\)", item.text):
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
        if self._is_lifetime_sensitive_allocation_expr(count_expr, line.text) and not self._has_narrowing_bound_proof(lines, line, count_expr):
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
        conventional_pointer_array = re.search(r"(?:args|argv|items|children|entries|array|list)$", base)
        return bool(element_allocated or (base_released and conventional_pointer_array))

    def _same_lock_region_without_escape(
        self,
        lines: Sequence[ClangCfgLine],
        start_idx: int,
        end_idx: int,
    ) -> bool:
        lock_idx = None
        for item in reversed(lines[max(0, start_idx - 12) : start_idx + 1]):
            if self._match_unlock(item.text):
                break
            if self._match_lock(item.text):
                lock_idx = item.index
                break
        if lock_idx is None:
            return False
        region = lines[lock_idx : end_idx + 1]
        if any(self._match_unlock(item.text) for item in region[:-1]):
            return False
        between = "\n".join(item.text for item in lines[start_idx : end_idx + 1])
        if re.search(r"\b(?:pthread_create|thrd_create|VOS_TaskCreate|CreateThread|_beginthreadex)\s*\(", between):
            return False
        if re.search(r"\b[A-Za-z_]\w*(?:callback|cb|handler)\s*\(", between, re.IGNORECASE):
            return False
        return True

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
        if re.search(rf"\b(?:watch|register|cache|store)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(fd)}\b", before, re.I):
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

    def _limit_mismatch_reaches_unsafe_sink(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        length_var: str,
    ) -> bool:
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 16])
        return bool(
            re.search(
                rf"\b(?:memcpy|memmove|strncpy|read|recv|fread|malloc|calloc|_safe_malloc|_safe_calloc)\s*"
                rf"\([^;]*\b{re.escape(length_var)}\b",
                later,
            )
        )

    def _emit(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        *,
        defect_class: str,
        rule: str,
        line: ClangCfgLine,
        description: str,
        root_cause: str,
        suggested_fix: str,
        source: str,
        sink: str,
        confidence: float,
        positive: List[str],
        negative: List[str],
        ast_cfg: Dict[str, Any],
        impact_level: str = "medium",
        validation_required: bool = True,
        finding_kind: str = "clang_ast_cfg_candidate",
        audit_observation_reason: str = "",
        proofs: Optional[Dict[str, Any]] = None,
    ) -> None:
        skill = self._SKILL_BY_CLASS.get(defect_class, "resource_lifecycle")
        if allowed_skills is not None and skill not in allowed_skills:
            return
        priority_group = self._candidate_priority_group(defect_class, finding_kind)
        validation_budget_class = (
            "generic"
            if defect_class in self._GENERIC_VALIDATION_BUDGET_CLASSES
            else "exact"
            if priority_group == "exact_sink"
            else priority_group
        )
        candidate_id = self._candidate_id(func_name, file_path, defect_class, line.number, rule, sink)
        tooling_evidence = self._collect_tooling_evidence(func_name, file_path, lines)
        if tooling_evidence:
            ast_cfg = dict(ast_cfg)
            ast_cfg["clang_tooling"] = tooling_evidence
        dedup_key = "|".join(
            [
                defect_class,
                file_path.replace("\\", "/").lower(),
                str(line.number),
                self._normalize_key(sink or rule),
            ]
        )
        evidence_pack = {
            "candidate_id": candidate_id,
            "candidate_source": "clang_ast_cfg",
            "checker": "clang_ast_cfg_checker",
            "defect_class": defect_class,
            "rule": rule,
            "rule_confidence": confidence,
            "source": {
                "expression": source,
                "file": file_path,
                "line": self._line_from_text(source) or line.number,
            },
            "sink": {
                "operation": sink,
                "file": file_path,
                "line": line.number,
            },
            "path": {
                "function": func_name,
                "complete_in_function": True,
                "backend": "Clang function body plus synthesized local CFG",
                "path_constraints": ast_cfg.get("path_constraints", []),
                "cfg_path": ast_cfg.get("cfg_path", []),
            },
            "ast_cfg": ast_cfg,
            "positive_evidence": list(positive),
            "negative_evidence": list(negative),
            "evidence_refs": [],
            "validation_required": bool(validation_required),
            "proofs": dict(proofs or {}),
            "candidate_priority_group": priority_group,
            "validation_budget_class": validation_budget_class,
        }
        if audit_observation_reason:
            evidence_pack["audit_observation_reason"] = audit_observation_reason
        reasoning = self._readable_reasoning(
            defect_class,
            rule,
            func_name,
            file_path,
            line.number,
            description,
            source,
            sink,
            positive,
            negative,
        )
        issues.append(
            {
                "id": candidate_id,
                "candidate_id": candidate_id,
                "function": func_name,
                "location": f"{file_path}:{line.number}",
                "category": defect_class,
                "subcategory": defect_class,
                "defect_class": defect_class,
                "finding_kind": finding_kind,
                "candidate_source": "clang_ast_cfg",
                "candidate_priority_group": priority_group,
                "validation_budget_class": validation_budget_class,
                "evidence_checker": "clang_ast_cfg_checker",
                "rule": rule,
                "cwe": self._CWE_BY_CLASS.get(defect_class, ""),
                "description": description,
                "root_cause": root_cause,
                "suggested_fix": suggested_fix,
                "confidence": confidence,
                "rule_confidence": confidence,
                "impact_level": impact_level,
                "reasoning": reasoning,
                "code_snippet": self._context(lines, max(0, line.index - 4), line.index + 7),
                "source": source,
                "sink": sink,
                "dedup_key": dedup_key,
                "positive_evidence": list(positive),
                "negative_evidence": list(negative),
                "evidence_pack": evidence_pack,
                "evidence_refs": [],
                "validation_required": bool(validation_required),
                "proofs": dict(proofs or {}),
            }
        )
        if audit_observation_reason:
            issues[-1]["audit_observation_reason"] = audit_observation_reason

    def _candidate_priority_group(self, defect_class: str, finding_kind: str = "") -> str:
        if str(finding_kind or "").lower() == "audit_observation":
            return "generic_audit"
        if defect_class in self._GENERIC_VALIDATION_BUDGET_CLASSES:
            return "generic_audit"
        if defect_class in self._EXACT_SINK_CLASSES:
            return "exact_sink"
        if defect_class in {"race", "deadlock", "held_lock_callback", "lock_protocol_violation", "unsynchronized_shared_state"}:
            return "graph_structural"
        return "semantic_suspicious_point"

    def _parse_lines(self, code: str) -> List[ClangCfgLine]:
        result: List[ClangCfgLine] = []
        block_id = 0
        depth = 0
        for idx, raw in enumerate(str(code or "").splitlines()):
            match = self._LINE_RE.match(raw)
            if match:
                number = int(match.group(1))
                source = match.group(2)
            else:
                number = idx + 1
                source = raw
            text = self._strip_comments(source).strip()
            if not text:
                continue
            if text.startswith("}") or self._CONTROL_RE.search(text):
                block_id += 1
            result.append(
                ClangCfgLine(
                    number=number,
                    raw=raw,
                    text=text,
                    index=len(result),
                    block_id=max(0, block_id),
                )
            )
            depth += text.count("{") - text.count("}")
            if depth < 0:
                depth = 0
            if self._is_return(text) or text.endswith(":"):
                block_id += 1
        return result

    def _first_direct_deref_var(self, text: str) -> str:
        patterns = [
            r"\b(?P<var>[A-Za-z_]\w*)\s*->",
            r"\b(?P<var>[A-Za-z_]\w*)\s*\[",
            r"\*\s*(?P<var>[A-Za-z_]\w*)\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group("var")
        return ""

    def _find_allocation_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            prev = lines[item.index - 1] if item.index > 0 else None
            if (
                prev
                and re.search(rf"\b{escaped}\s*=\s*$", prev.text)
                and re.search(r"\b[A-Za-z_]\w*(?:alloc|calloc|malloc|realloc)[A-Za-z_0-9]*\s*\(", item.text, re.IGNORECASE)
            ):
                return item
            for api, _args in self._calls(item.text):
                if api not in self._return_acquirers and not re.search(r"(?:malloc|calloc|alloc|realloc)$", api, re.IGNORECASE):
                    continue
                if re.search(rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)?\b{re.escape(api)}\s*\(", item.text):
                    return item
                if prev and re.search(rf"\b{escaped}\s*=\s*$", prev.text):
                    return item
        return None

    def _find_allocation_size_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[Tuple[ClangCfgLine, str]]:
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            match = re.search(
                rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(var)}\s*=\s*"
                r"(?:\([^)]*\)\s*)?(?P<api>[A-Za-z_]\w*(?:alloc|malloc|calloc|realloc)[A-Za-z_0-9]*)"
                r"\s*\((?P<args>[^;]*)\)",
                item.text,
                re.IGNORECASE,
            )
            if not match:
                continue
            size_expr = self._allocation_count_expression(match.group("api"), match.group("args"))
            if size_expr:
                return item, size_expr
        return None

    def _allocation_base_from_size(
        self,
        lines: Sequence[ClangCfgLine],
        alloc_line: ClangCfgLine,
        size_expr: str,
    ) -> str:
        direct = self._narrowed_origin_base(size_expr)
        if direct:
            return direct
        for name in self._expr_identifiers(size_expr):
            for item in reversed(lines[max(0, alloc_line.index - 24) : alloc_line.index]):
                assign = re.search(
                    rf"\b{re.escape(name)}\s*=\s*(?P<expr>[^;]+);",
                    item.text,
                )
                if assign:
                    base = self._narrowed_origin_base(assign.group("expr")) or self._expr_base_token(assign.group("expr"))
                    if base:
                        return base
        return ""

    def _expression_origin_base(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: str,
    ) -> str:
        base = self._expr_base_token(expr)
        if base and not re.fullmatch(r"[A-Za-z_]\w*", str(expr).strip()):
            return base
        name = str(expr or "").strip()
        if re.fullmatch(r"[A-Za-z_]\w*", name):
            for item in reversed(lines[max(0, line.index - 24) : line.index]):
                assign = re.search(rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);", item.text)
                if assign:
                    return self._expr_base_token(assign.group("rhs"))
        return base

    def _looks_like_external_length_pair(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        alloc_size: str,
        copy_len: str,
    ) -> bool:
        text = f"{alloc_size} {copy_len}"
        for name in self._expr_identifiers(f"{alloc_size} {copy_len}"):
            for item in reversed(lines[max(0, line.index - 24) : line.index]):
                assign = re.search(rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);", item.text)
                if assign:
                    text += " " + assign.group("rhs")
        return bool(re.search(r"(?:header|wire|packet|payload|fragment|copy|len|length|size|count)", text, re.I))

    @staticmethod
    def _narrowed_origin_base(expr: str) -> str:
        match = re.search(
            r"\(\s*(?:u?int(?:8|16)_t|unsigned\s+short|unsigned\s+char|short|char)\s*\)\s*(?P<src>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)",
            str(expr or ""),
        )
        return ClangAstCfgCandidateGenerator._expr_base_token(match.group("src")) if match else ""

    @staticmethod
    def _expr_base_token(expr: str) -> str:
        text = re.sub(r"\([^)]*\)", " ", str(expr or ""))
        candidates = re.findall(r"[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)?", text)
        ignored = {
            "sizeof",
            "size_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "int",
            "char",
            "short",
            "unsigned",
            "const",
        }
        candidates = [item for item in candidates if item not in ignored]
        if not candidates:
            return ""
        member_candidates = [item for item in candidates if "->" in item or "." in item]
        return (member_candidates[-1] if member_candidates else candidates[-1]).lower()

    @staticmethod
    def _expr_identifiers(expr: str) -> List[str]:
        ignored = {
            "sizeof",
            "size_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "int",
            "char",
            "short",
            "unsigned",
            "const",
        }
        return [
            item
            for item in re.findall(r"\b[A-Za-z_]\w*\b", str(expr or ""))
            if item not in ignored
        ]

    def _copy_length_bounded_by_alloc(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        copy_len: str,
        alloc_size: str,
    ) -> bool:
        window = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index + 1])
        copy_token = re.escape(str(copy_len).strip())
        alloc_token = re.escape(str(alloc_size).strip())
        return bool(
            re.search(rf"\b{copy_token}\b\s*(?:<=|<)\s*\b{alloc_token}\b", window)
            or re.search(rf"\bmin\s*\(\s*{copy_token}\s*,\s*{alloc_token}\s*\)", window)
            or re.search(rf"\bmin\s*\(\s*{alloc_token}\s*,\s*{copy_token}\s*\)", window)
        )

    def _find_pointer_backtrack_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        for item in reversed(lines[max(0, line.index - 20) : line.index]):
            decrement = re.search(rf"\b{re.escape(var)}\s*-=\s*(?P<offset>[^;]+);", item.text)
            if decrement:
                offset = decrement.group("offset")
                if re.search(r"(?:offset|backtrack|prefix|count|size|len|length|window)", offset, re.I):
                    guard_window = "\n".join(row.text for row in lines[max(0, item.index - 10) : item.index])
                    if not re.search(rf"\b{re.escape(offset.strip())}\b\s*(?:<=|<)\s*(?:[A-Za-z_]\w*len|[A-Za-z_]\w*_len|sizeof\s*\()", guard_window):
                        return item
            match = re.search(
                rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(var)}\s*=\s*(?P<expr>[^;]*-[^;]+);",
                item.text,
            )
            if not match:
                continue
            expr = match.group("expr")
            if re.search(r"\bsizeof\s*\(", expr):
                continue
            offset_names = [
                token
                for token in self._expr_identifiers(expr.split("-", 1)[-1])
                if re.search(r"(?:len|length|offset|backtrack|prefix|count|size|window)", token, re.I)
            ]
            if not offset_names:
                continue
            guard_window = "\n".join(row.text for row in lines[max(0, item.index - 10) : item.index])
            if any(
                re.search(rf"\b{re.escape(name)}\b\s*(?:<=|<)\s*(?:[A-Za-z_]\w*len|[A-Za-z_]\w*_len|sizeof\s*\()", guard_window)
                for name in offset_names
            ):
                continue
            return item
        return None

    def _find_offset_pointer_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 24) : line.index]):
            match = re.search(
                rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{escaped}\s*=\s*"
                r"(?P<base>[A-Za-z_]\w*)\s*\+\s*(?P<offset>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)\s*;",
                item.text,
            )
            if match:
                return item
        return None

    @staticmethod
    def _offset_expr_from_pointer_assignment(text: str, var: str) -> str:
        match = re.search(
            rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(var)}\s*=\s*"
            r"[A-Za-z_]\w*\s*\+\s*(?P<offset>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)\s*;",
            str(text or ""),
        )
        return match.group("offset") if match else ""

    def _find_pointer_derivation(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        escaped = re.escape(var)
        recent = lines[max(0, line.index - 18) : line.index]
        for item in reversed(recent):
            assign = re.search(
                rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)*(?P<base>[A-Za-z_]\w*)\s*(?P<op>[+-])\s*(?P<offset>[^;]+)\s*;",
                item.text,
            )
            if assign:
                return item, assign.group("base"), f"{var} = {assign.group('base')} {assign.group('op')} {assign.group('offset').strip()}"
            object_addr = re.search(
                rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)*[^;]*&\s*(?P<base>[A-Za-z_]\w*)[^;]*(?:\+|-)\s*(?P<offset>[A-Za-z_]\w*|\d+)",
                item.text,
            )
            if object_addr:
                return item, object_addr.group("base"), f"{var} derived from &{object_addr.group('base')}"
            inc = re.search(rf"\b{escaped}\s*(?:\+=|=\s*{escaped}\s*\+)\s*(?P<offset>[^;]+)\s*;", item.text)
            if inc:
                base = self._find_pointer_alias_base(lines, item, var)
                return item, base or var, f"{var} += {inc.group('offset').strip()}"
        return None

    def _find_pointer_alias_base(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> str:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 12) : line.index]):
            assign = re.search(rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)?(?P<base>[A-Za-z_]\w*)\s*;", item.text)
            if assign and assign.group("base") != var:
                return assign.group("base")
        return ""

    def _find_fixed_array_decl(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        array: str,
    ) -> Tuple[Optional[ClangCfgLine], str]:
        escaped = re.escape(array)
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            match = re.search(rf"\b{escaped}\s*\[\s*(?P<size>[A-Za-z_]\w*|\d+)\s*\]\s*(?:=|;)", item.text)
            if match:
                return item, match.group("size")
        return None, ""

    def _find_count_loop_for_index(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        index_var: str,
    ) -> Tuple[Optional[ClangCfgLine], str]:
        escaped = re.escape(index_var)
        for item in reversed(lines[max(0, line.index - 12) : line.index]):
            match = re.search(
                rf"\bfor\s*\([^;]*\b{escaped}\b[^;]*;\s*\b{escaped}\b\s*<\s*(?P<count>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)",
                item.text,
            )
            if match:
                return item, match.group("count")
        return None, ""

    def _find_prior_full_key_lookup(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        key_var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(key_var)
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            if re.search(
                rf"\b[A-Za-z_]\w*(?:find|lookup|get|search)[A-Za-z_0-9]*\s*\([^;]*\b{escaped}\b",
                item.text,
                re.IGNORECASE,
            ):
                return item
        return None

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

    def _count_is_obviously_bounded(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        array: str,
        array_size: str,
        count_expr: str,
    ) -> bool:
        window = "\n".join(item.text for item in lines[max(0, line.index - 16) : line.index])
        count = re.escape(count_expr)
        array_escaped = re.escape(array)
        size_escaped = re.escape(array_size)
        if re.fullmatch(r"\d+", count_expr) and re.fullmatch(r"\d+", array_size):
            return int(count_expr) <= int(array_size)
        patterns = [
            rf"\b{count}\b\s*(?:<|<=)\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|sizeof\s*\(\s*{array_escaped}\s*\)|{size_escaped})",
            rf"\bif\s*\([^)]*\b{count}\b\s*>\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|sizeof\s*\(\s*{array_escaped}\s*\)|{size_escaped})[^)]*\)\s*(?:return|goto|break)",
            rf"\b{count}\b\s*=\s*(?:MIN|min)\s*\(\s*\b{count}\b\s*,\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|{size_escaped})",
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _looks_wire_pointer_source(expr: str) -> bool:
        return bool(re.search(r"\b(?:wire|header|hdr|packet|pkt|frame|request|req|msg|message|payload)\b", expr, re.IGNORECASE))

    def _find_wire_pointer_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            if not re.search(rf"\b{escaped}\s*=", item.text):
                continue
            if not re.search(r"\([^)]*\*\s*\)|uintptr_t|intptr_t|uint64_t|uint32_t|size_t", item.text):
                continue
            rhs = item.text.split("=", 1)[1]
            if self._looks_wire_pointer_source(rhs):
                return item
        return None

    def _find_object_offset_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            if not re.search(rf"\b{escaped}\s*=", item.text):
                continue
            match = re.search(
                r"&\s*(?P<object>[A-Za-z_]\w*)[^;]*\+\s*(?P<offset>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)",
                item.text,
            )
            if match:
                return item, match.group("object"), match.group("offset")
        return None

    @staticmethod
    def _find_uninitialized_pointer_decl(
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            if re.search(rf"\b(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+\w+\s+)*[A-Za-z_]\w*(?:\s*\*)+\s*{escaped}\s*;", item.text):
                return item
        return None

    @staticmethod
    def _is_conditional_statement(lines: Sequence[ClangCfgLine], line: ClangCfgLine) -> bool:
        if re.search(r"\b(?:if|else|switch|case)\b", line.text):
            return True
        for item in reversed(lines[max(0, line.index - 3) : line.index]):
            stripped = item.text.strip()
            if not stripped or stripped in {"{", "}"}:
                continue
            return bool(re.match(r"(?:if|else|switch|case)\b", stripped))
        return False

    def _allocation_count_expression(self, api: str, args: str) -> str:
        split = self._split_args(args)
        if not split:
            return ""
        if api in {"calloc", "_safe_calloc"} and len(split) >= 2:
            return f"{split[0]} * {split[1]}"
        return split[0]

    @staticmethod
    def _looks_external_size_expr(expr: str) -> bool:
        clean = re.sub(r"sizeof\s*\([^)]*\)", "", expr)
        identifiers = re.findall(r"\b[A-Za-z_]\w*\b", clean)
        count_names = [
            name
            for name in identifiers
            if re.search(r"(?:count|cnt|num|nr|len|length|size|window|batch|segment|entry|item|client|quota)", name, re.IGNORECASE)
        ]
        if not count_names:
            return False
        return not re.fullmatch(r"\d+\s*(?:\*\s*\d+)?", clean.strip())

    @staticmethod
    def _has_allocation_limit_guard(guard_window: str, expr: str) -> bool:
        lowered = guard_window.lower()
        if re.search(r"\b(?:max|limit|cap|quota|budget|threshold)\b", lowered):
            return True
        identifiers = re.findall(r"\b[A-Za-z_]\w*\b", expr)
        for name in identifiers:
            if re.search(r"(?:sizeof|malloc|calloc)", name, re.IGNORECASE):
                continue
            if re.search(rf"\b{re.escape(name)}\b\s*(?:<|<=|>|>=)\s*(?:\d+|[A-Za-z_]\w*MAX|MAX_[A-Za-z_]\w*)", guard_window):
                return True
        return False

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
            if re.search(rf"\b(?:register|store|watch|cache|take|adopt)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(fd)}\b", between, re.IGNORECASE):
                return None
            return item, fd, match.group("api")
        return None

    def _match_assignment_call(self, text: str, call_re: re.Pattern[str]) -> Optional[Tuple[str, str, str]]:
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

    def _match_release(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._release_call_re.search(text)
        if not call:
            return None
        return call.group("api"), self._first_arg(call.group("args"))

    def _match_lock(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._lock_call_re.search(text)
        if not call:
            return None
        return call.group("api"), self._resource_var(self._first_arg(call.group("args"))) or "global_lock"

    def _match_unlock(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._unlock_call_re.search(text)
        if not call:
            return None
        return call.group("api"), self._resource_var(self._first_arg(call.group("args"))) or "global_lock"

    def _match_null_reset(self, text: str) -> str:
        match = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:NULL|nullptr|0)\s*;", text)
        return match.group("var") if match else ""

    def _is_var_redefined(self, text: str, var: str) -> bool:
        return bool(re.search(rf"\b{re.escape(var)}\s*=", text))

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

    def _is_null_guard(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        patterns = [
            rf"\bif\s*\(\s*!\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*==\s*(?:NULL|nullptr|0)\s*\)",
            rf"\bif\s*\(\s*(?:NULL|nullptr|0)\s*==\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*!=\s*(?:NULL|nullptr|0)\s*\)",
            rf"\bif\s*\(\s*(?:NULL|nullptr|0)\s*!=\s*{escaped}\s*\)",
            rf"\bif\s*\([^)]*(?:->|\.){escaped}\b[^)]*\)",
        ]
        return any(re.search(pattern, text) for pattern in patterns)

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

    def _is_terminal_conditional_branch_line(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> bool:
        branch_start = self._enclosing_branch_start(lines, line)
        if branch_start is None:
            return False
        for item in lines[line.index :]:
            if item.block_id != line.block_id:
                break
            if self._is_return(item.text):
                return True
        return False

    def _enclosing_branch_start(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> Optional[ClangCfgLine]:
        for item in reversed(lines[: line.index + 1]):
            if item.block_id != line.block_id:
                continue
            if self._is_conditional_branch_header(item.text):
                return item
        return None

    @staticmethod
    def _is_conditional_branch_header(text: str) -> bool:
        stripped = str(text or "").strip()
        return bool(
            re.match(r"(?:}\s*)?(?:else\s+)?if\b", stripped)
            or re.match(r"(?:}\s*)?else\b", stripped)
            or re.match(r"(?:case\b|default\b)", stripped)
        )

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
    def _release_followed_by_return(lines: Sequence[ClangCfgLine], line: ClangCfgLine) -> bool:
        for item in lines[line.index + 1 : line.index + 5]:
            text = item.text.strip()
            if not text or text in {"}", "};"}:
                continue
            if re.fullmatch(
                r"(?:UNLOCK|pthread_mutex_unlock|spin_unlock|mtx_unlock)\s*\([^;]*\)\s*;",
                text,
            ):
                continue
            return bool(re.search(r"\breturn\b", text))
        return False

    @staticmethod
    def _return_line_after_release(lines: Sequence[ClangCfgLine], line: ClangCfgLine) -> Optional[ClangCfgLine]:
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
    def _release_followed_by_failure_return(lines: Sequence[ClangCfgLine], line: ClangCfgLine) -> bool:
        for item in lines[line.index + 1 : line.index + 5]:
            text = item.text.strip()
            if not text or text in {"}", "};"}:
                continue
            return bool(re.search(r"\breturn\s+(?:NULL|nullptr|-1)\s*;", text))
        return False

    @staticmethod
    def _is_format_forwarding_wrapper(
        func_name: str,
        lines: Sequence[ClangCfgLine],
        fmt_arg: str,
    ) -> bool:
        if "[" in fmt_arg or not re.fullmatch(r"[A-Za-z_]\w*", fmt_arg):
            return False
        text = "\n".join(line.text for line in lines)
        signature = lines[0].text if lines else ""
        name_hint = bool(re.search(r"(?:log|printf|format|trace|debug|warn|error).*wrapper|wrapper", func_name, re.I))
        varargs_signature = "..." in signature or re.search(rf"\bva_start\s*\([^,]+,\s*{re.escape(fmt_arg)}\s*\)", text)
        forwards_to_va_sink = re.search(
            rf"\bv(?:f)?printf\s*\([^;]*\b{re.escape(fmt_arg)}\b[^;]*\)",
            text,
        ) or re.search(
            rf"\bvfprintf\s*\([^;]*\b{re.escape(fmt_arg)}\b[^;]*\)",
            text,
        )
        return bool((name_hint or varargs_signature) and varargs_signature and forwards_to_va_sink)

    def _is_status_failure_return(self, text: str, status_var: str) -> bool:
        return self._is_status_failure_condition(text, status_var) and bool(re.search(r"\breturn\b", text))

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
        return bool(branch_start and self._is_status_failure_condition(branch_start.text, status_var))

    def _is_status_guard_line(self, text: str, status_var: str) -> bool:
        return self._is_status_failure_condition(text, status_var) or self._is_status_success_guard(text, status_var)

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

    def _has_terminating_null_guard(
        self,
        lines: Sequence[ClangCfgLine],
        allocation_line: ClangCfgLine,
        use_line: ClangCfgLine,
        var: str,
    ) -> bool:
        """Return true only for a null branch that exits before this use.

        A null test on its own is not a proof: it might just log or recover.
        For a candidate produced from an allocation result, the false path is
        safe only when the guarded branch terminates before the dereference.
        This also handles compound guards such as ``if (!task || !frame)``.
        """

        escaped = re.escape(var)
        null_condition = re.compile(
            rf"(?:!\s*{escaped}\b|\b{escaped}\s*==\s*(?:NULL|nullptr|0)\b|\b(?:NULL|nullptr|0)\s*==\s*{escaped}\b)"
        )
        start = allocation_line.index + 1
        end = use_line.index
        for index in range(start, end):
            text = lines[index].text
            if not re.search(r"\bif\s*\(", text) or not null_condition.search(text):
                continue
            branch = text
            brace_depth = text.count("{") - text.count("}")
            cursor = index + 1
            if brace_depth > 0:
                while cursor < end and brace_depth > 0:
                    next_text = lines[cursor].text
                    branch += "\n" + next_text
                    brace_depth += next_text.count("{") - next_text.count("}")
                    cursor += 1
            if re.search(r"\b(?:return|goto)\b", branch):
                return True
        return False

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

    def _return_is_error_guard_for_lock(self, text: str, lock_id: str) -> bool:
        if lock_id == "global_lock":
            return False
        escaped = re.escape(lock_id)
        return bool(re.search(rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*return\b", text))

    def _is_transfer(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        transfer_patterns = [
            rf"\breturn\s+{escaped}\s*;",
            rf"\*\s*[A-Za-z_]\w*\s*=\s*{escaped}\s*;",
            rf"\b[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+\s*=\s*{escaped}\s*;",
            rf"\b[A-Za-z_]\w*\s*\[[^\]]+\]\s*=\s*{escaped}\s*;",
        ]
        if any(re.search(pattern, text) for pattern in transfer_patterns):
            return True
        lower = text.lower()
        if var in text and re.search(r"\b(?:append|insert|push|enqueue|register|attach|set|put|add)\w*\s*\(", lower):
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

    def _copy_uses_length(self, text: str, len_var: str) -> bool:
        for api, args in self._calls(text):
            if api not in self._copy_sink_names:
                continue
            if any(re.search(rf"\b{re.escape(len_var)}\b", arg) for arg in self._split_args(args)):
                return True
        return False

    def _find_dependent_count_sink(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        count_var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(count_var)
        for item in lines[line.index + 1 : line.index + 18]:
            text = item.text
            if self._is_var_redefined(text, count_var):
                return None
            if re.search(
                rf"\b(?:memcpy|memmove|strncpy|read|recv|fread|malloc|calloc|_safe_malloc|_safe_calloc)\s*"
                rf"\([^;]*\b{escaped}\b",
                text,
            ):
                return item
            if re.search(rf"\[[^\]]*\b{escaped}\b[^\]]*\]", text):
                return item
            for api, args in self._calls(text):
                if re.search(r"(?:route|dispatch|apply|process|reserve|alloc|copy|decode|parse|policy)", api, re.I) and re.search(
                    rf"\b{escaped}\b",
                    args,
                ):
                    return item
        return None

    @staticmethod
    def _has_overflow_guard(guard_window: str, expr: str) -> bool:
        text = str(guard_window or "")
        identifiers = re.findall(r"\b[A-Za-z_]\w*\b", str(expr or ""))
        size_names = [name for name in identifiers if re.search(r"(?:len|length|size|count|num|total|max)", name, re.I)]
        if re.search(r"\b(?:SIZE_MAX|UINT32_MAX|UINT_MAX|INT_MAX|__builtin_(?:add|mul)_overflow)\b", text):
            return True
        return any(
            re.search(rf"\b{re.escape(name)}\b\s*(?:>|>=|<|<=)\s*[^;]*(?:-\s*|/|MAX|SIZE|UINT|INT)", text)
            for name in size_names
        )

    @staticmethod
    def _is_path_check(text: str) -> bool:
        return bool(
            re.search(r"\b(?:access|stat|lstat|faccessat|fstatat)\s*\(", text)
            or re.search(
                r"\b[A-Za-z_]\w*(?:check|validate|verify)[A-Za-z_0-9]*(?:permission|access|path|file)[A-Za-z_0-9]*\s*\(",
                text,
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _is_file_type_check(text: str) -> bool:
        return bool(
            re.search(r"\bS_IS(?:REG|CHR|BLK|FIFO|SOCK|LNK)\s*\(", text)
            or re.search(r"\b[A-Z_]*IS_(?:REG|CHR|BLK|FIFO|SOCK|LNK)\s*\(", text)
            or re.search(r"\bst_mode\b\s*&\s*S_IF(?:REG|CHR|BLK|FIFO|SOCK|LNK)", text)
            or re.search(r"\b(?:file|fd|descriptor)_[A-Za-z_0-9]*(?:type|mode)\b", text, re.IGNORECASE)
            or re.search(r"\b(?:is|validate|check)[A-Za-z_0-9]*(?:regular|character|device|file_type|fd_type)\b", text, re.IGNORECASE)
        )

    @staticmethod
    def _is_compile_time_size_expr(expr: str) -> bool:
        text = str(expr or "").strip()
        if re.fullmatch(r"\d+", text) or "sizeof" in text:
            return True
        return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*(?:\s*[-+*/]\s*\d+)?", text))

    @staticmethod
    def _is_string_literal(expr: str) -> bool:
        return bool(re.match(r'^\s*(?:L|u8|u|U)?".*"\s*$', str(expr or "")))

    def _macro_guard_names(self, lines: Sequence[ClangCfgLine], *, lock: bool) -> Set[str]:
        configured = self._macro_lock_names if lock else self._macro_unlock_names
        result = set(configured)
        for line in lines:
            for api, _args in self._calls(line.text):
                upper = api.upper()
                if lock and "LOCK" in upper and "UNLOCK" not in upper:
                    result.add(api)
                elif not lock and "UNLOCK" in upper:
                    result.add(api)
        return result

    def _line_between_macro_guards(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        macro_locks: Set[str],
        macro_unlocks: Set[str],
    ) -> bool:
        saw_lock = False
        for item in lines:
            for api, _args in self._calls(item.text):
                if api in macro_locks and item.index < line.index:
                    saw_lock = True
                if api in macro_unlocks and item.index > line.index and saw_lock:
                    return True
            if item.index > line.index and saw_lock and re.search(r"\breturn\b", item.text):
                return False
        return False

    @staticmethod
    def _is_return(text: str) -> bool:
        return bool(re.search(r"\breturn\b", text))

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

    def _calls(self, text: str) -> List[Tuple[str, str]]:
        calls = []
        for match in self._CALL_NAME_RE.finditer(text):
            api = match.group(1)
            args = self._extract_call_args(text, match.end() - 1)
            if args is not None:
                calls.append((api, args))
        return calls

    def _is_call_to(self, text: str, names: Set[str]) -> bool:
        if not names:
            return False
        return any(api in names for api, _ in self._calls(text))

    @staticmethod
    def _resource_var(arg: str) -> str:
        clean = str(arg or "").strip()
        clean = re.sub(r"^\s*\([^)]*\)\s*", "", clean)
        clean = clean.lstrip("*&").strip()
        match = re.match(r"(?P<var>[A-Za-z_]\w*)", clean)
        return match.group("var") if match else ""

    @staticmethod
    def _resource_expr(arg: str) -> str:
        clean = str(arg or "").strip()
        clean = re.sub(r"^\s*\([^)]*\)\s*", "", clean)
        clean = clean.lstrip("*&").strip()
        # A resource identity must retain the complete field/index access path.
        # Retaining only the first member collapsed union/struct siblings (for
        # example ``task->payload.command.command`` and
        # ``task->payload.command.args[i]``) into the same freed object.
        match = re.match(
            r"(?P<expr>[A-Za-z_]\w*(?:(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)|(?:\s*\[[^\]]+\]))*)",
            clean,
        )
        if not match:
            return ""
        return re.sub(r"\s+", "", match.group("expr"))

    @staticmethod
    def _last_line_matching(lines: Sequence[ClangCfgLine], pattern: re.Pattern[str]) -> Optional[ClangCfgLine]:
        for line in reversed(tuple(lines)):
            if pattern.search(line.text):
                return line
        return None

    @staticmethod
    def _first_arg(args: str) -> str:
        items = ClangAstCfgCandidateGenerator._split_args(args)
        return items[0].strip() if items else ""

    @staticmethod
    def _first_line_matching_in(
        lines: Sequence[ClangCfgLine],
        pattern: re.Pattern[str],
    ) -> Optional[ClangCfgLine]:
        for line in lines:
            if pattern.search(line.text):
                return line
        return None

    @staticmethod
    def _signature_param_names(lines: Sequence[ClangCfgLine]) -> List[str]:
        signature = next(
            (
                line.text
                for line in lines[:8]
                if "(" in line.text and not re.match(r"^(?:if|for|while|switch)\b", line.text)
            ),
            "",
        )
        match = re.search(r"\((?P<params>.*)\)", signature)
        if not match:
            return []
        names: List[str] = []
        for raw_param in match.group("params").split(","):
            param = raw_param.strip()
            if not param or param == "void" or "..." in param:
                continue
            param = re.sub(r"\[[^]]*\]", "", param)
            tokens = re.findall(r"\b[A-Za-z_]\w*\b", param)
            if not tokens:
                continue
            candidate = tokens[-1]
            if candidate in {"const", "volatile", "unsigned", "signed", "struct", "enum"}:
                continue
            names.append(candidate)
        return names

    @staticmethod
    def _split_args(args: str) -> List[str]:
        result: List[str] = []
        current: List[str] = []
        depth = 0
        for char in str(args or ""):
            if char in "([{":
                depth += 1
            elif char in ")]}" and depth:
                depth -= 1
            if char == "," and depth == 0:
                result.append("".join(current).strip())
                current = []
                continue
            current.append(char)
        tail = "".join(current).strip()
        if tail:
            result.append(tail)
        return result

    @staticmethod
    def _extract_call_args(text: str, open_paren_index: int) -> Optional[str]:
        depth = 0
        start = open_paren_index + 1
        for idx in range(open_paren_index, len(text)):
            char = text[idx]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return text[start:idx]
        return None

    def _call_re(
        self,
        names: Iterable[str],
        *,
        extra_patterns: Optional[Iterable[str]] = None,
    ) -> re.Pattern[str]:
        parts = [re.escape(name) for name in names if self._is_ident(name)]
        parts.extend(extra_patterns or [])
        if not parts:
            parts = [r"__zscope_no_api_match__"]
        return re.compile(rf"\b(?P<api>{'|'.join(sorted(parts, key=len, reverse=True))})\s*\((?P<args>[^;]*)\)")

    @staticmethod
    def _is_ident(name: str) -> bool:
        return bool(name and ClangAstCfgCandidateGenerator._IDENT_RE.fullmatch(name))

    @staticmethod
    def _semantics_names(semantics: Optional["LocalPatternSemantics"], attr: str) -> Set[str]:
        if semantics is None:
            return set()
        value = getattr(semantics, attr, {})
        if isinstance(value, dict):
            return {str(name) for name in value if str(name).strip()}
        return set()

    @staticmethod
    def _default_semantics() -> "LocalPatternSemantics":
        from ...semantics.defaults import default_local_pattern_semantics

        return default_local_pattern_semantics()

    @staticmethod
    def _checker_defaults(role_name: str) -> Set[str]:
        from ...semantics.defaults import default_checker_api_names

        return set(default_checker_api_names(role_name))

    def _overlay_rows(self, key: str) -> List[Dict[str, Any]]:
        if not isinstance(self.semantic_overlay, dict):
            return []
        rows = self.semantic_overlay.get(key) or []
        return [dict(row) for row in rows if isinstance(row, dict)]

    @staticmethod
    def _mentions_output_argument(text: str) -> bool:
        return any(
            token in text
            for token in (
                "out_param",
                "out param",
                "out parameter",
                "output_arg",
                "output arg",
                "output argument",
                "output parameter",
                "writes output",
                "returns via argument",
                "出参",
                "输出参数",
                "通过参数返回",
                "写入参数",
            )
        )

    @staticmethod
    def _strip_comments(text: str) -> str:
        text = re.sub(r"//.*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text)
        return text

    def _ast_cfg_pack(
        self,
        lines: Sequence[ClangCfgLine],
        events: List[Dict[str, Any]],
        cfg_path: List[int],
    ) -> Dict[str, Any]:
        return {
            "checker_basis": "clangd-indexed function body with synthesized statement/CFG facts",
            "statement_count": len(lines),
            "approx_basic_block_count": len({line.block_id for line in lines}) or 1,
            "declarations": self._declarations(lines),
            "condition_guards": self._condition_guards(lines),
            "scope_summary": self._scope_summary(lines),
            "events": events,
            "cfg_path": cfg_path,
            "path_constraints": self._path_constraints(lines, cfg_path),
        }

    def _collect_tooling_evidence(
        self,
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
    ) -> Dict[str, Any]:
        provider = self.tooling_evidence_provider
        if not callable(provider):
            return {}
        start_line = min((line.number for line in lines), default=0)
        end_line = max((line.number for line in lines), default=0)
        try:
            evidence = provider(
                func_name=func_name,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
            )
        except TypeError:
            try:
                evidence = provider(func_name, file_path, start_line, end_line)
            except Exception:
                return {}
        except Exception:
            return {}
        return evidence if isinstance(evidence, dict) else {}

    @staticmethod
    def _declarations(lines: Sequence[ClangCfgLine]) -> List[Dict[str, Any]]:
        declarations: List[Dict[str, Any]] = []
        decl_re = re.compile(
            r"^(?P<type>(?:(?:const|volatile|unsigned|signed|long|short)\s+)*"
            r"(?:struct\s+\w+|enum\s+\w+|[A-Za-z_]\w+)"
            r"(?:\s+(?:const|volatile|unsigned|signed|long|short|int|char|[A-Za-z_]\w+))*"
            r"\s*\**)\s*(?P<name>[A-Za-z_]\w*)\s*(?P<init>=\s*[^;]+)?;"
        )
        skip = {"return", "if", "for", "while", "switch", "case", "sizeof"}
        for line in lines:
            match = decl_re.match(line.text)
            if not match:
                continue
            type_text = " ".join(match.group("type").split())
            name = match.group("name")
            if type_text in skip or name in skip:
                continue
            declarations.append(
                {
                    "line": line.number,
                    "block": line.block_id,
                    "name": name,
                    "type": type_text,
                    "pointer_depth": type_text.count("*"),
                    "initialized": bool(match.group("init")),
                }
            )
        return declarations[:32]

    @staticmethod
    def _condition_guards(lines: Sequence[ClangCfgLine]) -> List[Dict[str, Any]]:
        guards = []
        for line in lines:
            match = re.search(r"\b(?:if|while|for)\s*\((?P<expr>[^)]*)\)", line.text)
            if match:
                guards.append({"line": line.number, "block": line.block_id, "condition": match.group("expr").strip()})
        return guards[:32]

    @staticmethod
    def _scope_summary(lines: Sequence[ClangCfgLine]) -> Dict[str, Any]:
        return {
            "block_count": len({line.block_id for line in lines}) or 1,
            "return_lines": [line.number for line in lines if re.search(r"\breturn\b", line.text)][:32],
            "branch_lines": [
                line.number
                for line in lines
                if re.search(r"\b(?:if|else|switch|case|for|while)\b", line.text)
            ][:32],
        }

    @staticmethod
    def _event(kind: str, line: ClangCfgLine, variable: str, api: str, expression: str) -> Dict[str, Any]:
        return {
            "kind": kind,
            "line": line.number,
            "block": line.block_id,
            "variable": variable,
            "api": api,
            "expression": expression,
        }

    @staticmethod
    def _path_constraints(lines: Sequence[ClangCfgLine], cfg_path: List[int]) -> List[str]:
        if not cfg_path:
            return []
        low, high = min(cfg_path), max(cfg_path)
        constraints = []
        for line in lines:
            if low <= line.number <= high and re.search(r"\bif\s*\(", line.text):
                constraints.append(f"line {line.number}: {line.text}")
        return constraints[:8]

    def _context(self, lines: Sequence[ClangCfgLine], start: int, end: int) -> str:
        return "\n".join(line.raw for line in lines[max(0, start) : min(len(lines), end)])

    @staticmethod
    def _candidate_id(
        func_name: str,
        file_path: str,
        defect_class: str,
        line: int,
        rule: str,
        sink: str,
    ) -> str:
        digest = hashlib.sha1(
            "|".join([func_name, file_path, defect_class, str(line), rule, sink]).encode("utf-8")
        ).hexdigest()[:10]
        return f"CLANG_CFG_{defect_class.upper()}_{digest}"

    @staticmethod
    def _normalize_key(value: str) -> str:
        return re.sub(r"[^a-z0-9_]+", "_", str(value or "").lower()).strip("_")[:120]

    @staticmethod
    def _line_from_location(location: str) -> int:
        match = re.search(r":(\d+)", location)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _line_from_text(text: str) -> int:
        match = re.search(r"\bline\s+(\d+)\b", text)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _priority_for_issue(issue: Dict[str, Any]) -> float:
        confidence = float(issue.get("rule_confidence") or issue.get("confidence") or 0.5)
        impact = str(issue.get("impact_level") or "medium")
        boost = 0.1 if impact == "high" else 0.0
        group = str(issue.get("candidate_priority_group") or "")
        if group == "exact_sink":
            boost += 0.12
        elif group == "generic_audit":
            boost -= 0.18
        return min(1.0, max(0.0, confidence + boost))

    @staticmethod
    def _readable_reasoning(
        defect_class: str,
        rule: str,
        func_name: str,
        file_path: str,
        line: int,
        description: str,
        source: str,
        sink: str,
        positive: List[str],
        negative: List[str],
    ) -> str:
        parts = [
            f"Clang AST/CFG checker `{rule}` produced an evidence candidate for `{defect_class}`.",
            f"Location: `{func_name}` at `{file_path}:{line}`.",
            f"Observation: {description}",
            f"Source: {source or 'local CFG source'}",
            f"Sink: {sink or 'local CFG sink'}",
        ]
        if positive:
            parts.append("Positive evidence: " + " | ".join(positive[:4]))
        if negative:
            parts.append("Validation notes: " + " | ".join(negative[:3]))
        return "\n".join(parts)

    @staticmethod
    def _dedupe(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = str(issue.get("dedup_key") or issue.get("candidate_id") or issue.get("id"))
            deduped.setdefault(key, issue)
        return list(deduped.values())

