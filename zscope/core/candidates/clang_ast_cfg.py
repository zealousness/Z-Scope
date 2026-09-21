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
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from .cpp_domains.models import ClangCfgLine, ResourceState, LockState
from .cpp_domains.resource_lifecycle import ClangResourceLifecycleRules
from .cpp_domains.memory_bounds_integer import ClangMemoryBoundsIntegerRules
from .cpp_domains.concurrency_shared_state import ClangConcurrencySharedStateRules
from .cpp_domains.protocol_ownership_logic import ClangProtocolOwnershipLogicRules

from .cpp_domains import (
    ClangRuleContext,
    resolve_emitter_descriptor,
    resolve_rule_descriptor,
    run_detector_plan,
)

if TYPE_CHECKING:
    from ...semantics.models import LocalPatternSemantics
    from ...orchestration.subagents import SubAgentTicket


from .cpp_domains.typed_resources import ClangTypedResourceRules


class ClangAstCfgCandidateGenerator(
    ClangResourceLifecycleRules,
    ClangMemoryBoundsIntegerRules,
    ClangConcurrencySharedStateRules,
    ClangProtocolOwnershipLogicRules,
    ClangTypedResourceRules,
):
    """Generate evidence-backed candidates from a Clang-style local CFG view."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
    _CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    _CONTROL_RE = re.compile(r"^\s*(?:if|else|for|while|switch|case|default)\b")

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
        rule_policy: Optional[Any] = None,
        program_facts_provider: Optional[Callable[..., Dict[str, Any]]] = None,
    ):
        self.semantics = self._default_semantics()
        if semantics is not None:
            self.semantics.merge(semantics)
        self.semantic_overlay = semantic_overlay or {}
        self.semantics.merge_overlay(self.semantic_overlay)
        self.tooling_evidence_provider = tooling_evidence_provider
        self.rule_policy = rule_policy
        self.program_facts_provider = program_facts_provider
        self.program_facts: Dict[str, Any] = {}
        self._compile_api_models()

    def generate_issues(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        self._function_name = str(func_name).split("@", 1)[0].rsplit("::", 1)[-1]
        lines = self._parse_lines(code)
        self.last_semantic_events = self.semantics.contracts.trace_calls(
            {"func_name": func_name, "file_path": file_path, "code": code}
        )
        self.program_facts = (
            self.program_facts_provider(func_name, file_path)
            if self.program_facts_provider is not None
            else {}
        )
        if not lines:
            return []
        allowed = set(allowed_skills) if allowed_skills is not None else None
        issues: List[Dict[str, Any]] = []
        from ...semantics.call_context import bind_call_context
        with bind_call_context({"func_name": func_name, "file_path": file_path, "code": code,
                                "program_facts": self.program_facts}, self.semantics.contracts):
            run_detector_plan(
                "clang_ast_cfg",
                "function",
                ClangRuleContext(
                    generator=self,
                    issues=issues,
                    func_name=func_name,
                    file_path=file_path,
                    lines=lines,
                    allowed_skills=allowed,
                ),
            )
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
        rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
        descriptor = resolve_rule_descriptor(
            self.rule_policy,
            rule_id,
            defect_class=defect_class,
        )
        return SubAgentTicket(
            id=str(issue.get("candidate_id") or issue.get("id")),
            skill=str(
                issue.get("skill")
                or (descriptor.skill if descriptor is not None else "resource_lifecycle")
            ),
            task=(
                f"Verify clang AST/CFG {defect_class} candidate. Confirm path "
                "feasibility, ownership or lock state transitions, and guard sufficiency."
            ),
            trigger=str(issue.get("rule") or defect_class),
            line=self._line_from_location(str(issue.get("location") or "")),
            context_slice=str(issue.get("code_snippet") or ""),
            priority_score=int(round(self._priority_for_issue(issue))),
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
        self._allocator_names = self._semantics_names(
            semantics, "allocators"
        ) | self._checker_defaults("extended_allocators")
        self._calloc_names = self._semantics_names(semantics, "calloc_allocators")
        self._reallocator_names = self._semantics_names(semantics, "reallocators")
        self._deallocator_names = self._semantics_names(semantics, "deallocators")
        self._lock_names = self._semantics_names(semantics, "lock_apis") | self._checker_defaults(
            "extended_lock_apis"
        )
        self._unlock_names = self._semantics_names(
            semantics, "unlock_apis"
        ) | self._checker_defaults("extended_unlock_apis")
        self._copy_sink_names = self._semantics_names(
            semantics, "copy_sinks"
        ) | self._checker_defaults("string_copy_sinks")
        # Builtin base sets are kept verbatim so stock projects keep identical
        # candidate behavior; user-defined wrappers join through semantics,
        # checker defaults, and semantic-overlay rows.
        self._send_sink_names = (
            {"send", "write", "sendto", "sendmsg"}
            | self._semantics_names(semantics, "send_sinks")
            | self._checker_defaults("extended_send_sinks")
        )
        self._format_sink_names = (
            {"printf", "fprintf", "syslog", "vprintf", "vfprintf"}
            | self._semantics_names(semantics, "format_sinks")
            | self._checker_defaults("extended_format_sinks")
        )
        self._open_sink_names = (
            {"open", "fopen", "creat"}
            | self._semantics_names(semantics, "io_acquirers")
            | self._checker_defaults("extended_io_acquirers")
        )
        self._recv_source_names = (
            {"recv", "read", "recvfrom"}
            | self._semantics_names(semantics, "recv_sources")
            | self._checker_defaults("extended_recv_sources")
        )
        self._callback_registrar_names = self._semantics_names(
            semantics, "callback_registrars"
        ) | self._checker_defaults("extended_callback_registrars")
        self._io_acquire_names = self._semantics_names(
            semantics, "io_acquirers"
        ) | self._checker_defaults("extended_io_acquirers")
        self._io_release_names = (
            {"close", "closesocket"}
            | self._semantics_names(semantics, "io_releasers")
            | self._checker_defaults("extended_io_releasers")
        )
        self._user_io_acquire_names = semantics.names_from_nondefault_sources("io_acquirers")
        self._user_io_release_names = semantics.names_from_nondefault_sources("io_releasers")
        self._user_send_sink_names = semantics.names_from_nondefault_sources("send_sinks")
        self._user_recv_source_names = semantics.names_from_nondefault_sources("recv_sources")
        self._macro_lock_names: Set[str] = {
            c.symbol.name
            for c in semantics.contracts.contracts
            if c.role == "lock" and c.symbol.symbol_type == "macro"
        }
        self._macro_unlock_names: Set[str] = {
            c.symbol.name
            for c in semantics.contracts.contracts
            if c.role == "unlock" and c.symbol.symbol_type == "macro"
        }

        self._return_acquirers = set(
            self._allocator_names | self._calloc_names | self._reallocator_names
        )
        self._out_param_acquirers: Set[str] = set()
        self._release_names = set(self._deallocator_names)

        _RESOURCE_KIND_RETURN_ACQUIRERS = {
            "allocator",
            "calloc",
            "reallocator",
            "resource",
            "resource_acquire",
        }
        for row in self._overlay_rows("resource_models"):
            name = str(row.get("name") or "").strip()
            if not self._is_ident(name):
                continue
            kind = str(row.get("kind") or "").lower()
            carrier = str(row.get("carrier") or "").lower()
            binding = row.get("object_binding") or {}
            if kind in _RESOURCE_KIND_RETURN_ACQUIRERS:
                if carrier == "return_value":
                    self._return_acquirers.add(name)
                if binding.get("kind") == "output_argument":
                    self._out_param_acquirers.add(name)
                    self._return_acquirers.discard(name)
            if kind in {"deallocator", "resource_release"}:
                self._release_names.add(name)
            if kind == "copy" or carrier == "copy_arguments":
                self._copy_sink_names.add(name)
            if kind == "io_acquire":
                self._io_acquire_names.add(name)
                self._user_io_acquire_names.add(name)
                if binding.get("kind") == "output_argument":
                    self._out_param_acquirers.add(name)
            if kind == "io_release":
                self._io_release_names.add(name)
                self._user_io_release_names.add(name)
            if kind == "send_sink":
                self._send_sink_names.add(name)
                self._user_send_sink_names.add(name)
            if kind == "recv_source":
                self._recv_source_names.add(name)
                self._user_recv_source_names.add(name)
            if kind == "format_sink":
                self._format_sink_names.add(name)
            if kind == "callback_register":
                self._callback_registrar_names.add(name)

        for row in self._overlay_rows("macro_models"):
            name = str(row.get("name") or "").strip()
            if not self._is_ident(name):
                continue
            kind = str(row.get("kind") or "").lower()
            if kind == "lock":
                self._macro_lock_names.add(name)
            if kind == "unlock":
                self._macro_unlock_names.add(name)

        for name in (
            self._allocator_names
            | self._calloc_names
            | self._reallocator_names
            | self._io_acquire_names
        ):
            contracts = [
                c
                for c in semantics.contracts.find(name)
                if c.role in {"allocator", "calloc", "reallocator", "io_acquire"}
            ]
            if not contracts:
                continue
            if any(c.carrier.kind == "return" for c in contracts):
                self._return_acquirers.add(name)
            else:
                self._return_acquirers.discard(name)
            if any(c.carrier.kind == "output_argument" for c in contracts):
                self._out_param_acquirers.add(name)
            else:
                self._out_param_acquirers.discard(name)
        # A project definition shadows a same-spelled standard declaration.
        # Explicitly published project roles remain eligible; bare builtin sets do not.
        for attr, value in vars(self).copy().items():
            if isinstance(value, set) and (attr.endswith("_names") or attr.endswith("_acquirers")):
                for name in semantics.contracts.shadowed_symbols:
                    if not any(c.effects_trusted for c in semantics.contracts.find(name)):
                        value.discard(name)
        self._alloc_call_re = self._call_re(self._return_acquirers)
        self._out_acquire_call_re = self._call_re(self._out_param_acquirers)
        self._realloc_call_re = self._call_re(self._reallocator_names & self._return_acquirers)
        self._release_call_re = self._call_re(self._release_names)
        self._lock_call_re = self._call_re(
            self._lock_names, extra_patterns=[r"pthread_rwlock_(?:rdlock|wrlock)"]
        )
        self._unlock_call_re = self._call_re(self._unlock_names)
        self._send_call_re = self._call_re(self._send_sink_names)
        self._recv_call_re = self._call_re(self._recv_source_names)
        self._format_call_re = self._call_re(self._format_sink_names)
        self._io_acquire_call_re = self._call_re(self._io_acquire_names & self._return_acquirers)
        self._io_release_call_re = self._call_re(self._io_release_names)
        self._callback_registrar_call_re = self._call_re(self._callback_registrar_names)

    def _semantic_api_pattern(self, pattern: str) -> str:
        from ...semantics.contracts import expand_api_pattern

        return expand_api_pattern(pattern, self.semantics)

    _FD_OPEN_EXCLUDED_NAMES = {"fopen", "fdopen", "freopen", "popen"}

    @staticmethod
    def _names_pattern(names: Iterable[str]) -> str:
        """Bare alternation for embedding into larger patterns."""

        escaped = [
            re.escape(str(item))
            for item in sorted({str(name) for name in names if name}, key=len, reverse=True)
        ]
        return "|".join(escaped) or r"__zscope_no_api_match__"

    def _fd_open_names(self) -> Set[str]:
        """Builtin fd-open APIs plus user-defined io_acquire wrappers.

        ``fopen``/``popen``-style FILE* APIs stay excluded exactly as before the
        user-defined extension so stock projects keep identical candidates.
        """

        return (
            {"open", "creat", "socket", "accept", "dup", "eventfd", "memfd_create"}
            | set(self._user_io_acquire_names)
        ) - self._FD_OPEN_EXCLUDED_NAMES

    def _fd_close_names(self) -> Set[str]:
        return {"close", "closesocket"} | set(self._user_io_release_names)

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
        should_emit, descriptor = resolve_emitter_descriptor(
            self.rule_policy,
            rule,
            defect_class=defect_class,
        )
        if not should_emit:
            return
        if (
            allowed_skills is not None
            and descriptor is not None
            and descriptor.skill not in allowed_skills
        ):
            return
        cwe = descriptor.cwe if descriptor is not None else ""
        skill = descriptor.skill if descriptor is not None else ""
        priority_group = self._candidate_priority_group(defect_class, finding_kind)
        validation_budget_class = (
            "generic"
            if defect_class in self._GENERIC_VALIDATION_BUDGET_CLASSES
            else "exact" if priority_group == "exact_sink" else priority_group
        )
        candidate_id = self._candidate_id(
            func_name, file_path, defect_class, line.number, rule, sink
        )
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
            "contract_version": self.semantics.contracts.version,
            "interface_inference_is_proof": False,
            "candidate_id": candidate_id,
            "candidate_source": "clang_ast_cfg",
            "checker": "clang_ast_cfg_checker",
            "defect_class": defect_class,
            "rule": rule,
            "rule_id": descriptor.rule_id if descriptor is not None else rule,
            "cwe": cwe,
            "skill": skill,
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
                "column": line.column,
                "event_ordinal": line.ordinal,
            },
            "path": {
                "function": func_name,
                "complete_in_function": bool(ast_cfg.get("ordering_known", True)),
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
                "rule_id": descriptor.rule_id if descriptor is not None else rule,
                "cwe": cwe,
                "skill": skill,
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
        if defect_class in {
            "race",
            "deadlock",
            "held_lock_callback",
            "lock_protocol_violation",
            "unsynchronized_shared_state",
        }:
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

    def _match_release(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._first_operation_call(self._release_call_re, text)
        if not call:
            return None
        api = call.group("api")
        obj = self.semantics.contracts.resolve_object(
            api, "deallocator", self._split_args(call.group("args"))
        )
        return (api, obj) if obj else None

    def _match_lock(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._first_operation_call(self._lock_call_re, text)
        if not call:
            return None
        api = call.group("api")
        obj = self.semantics.contracts.resolve_object(
            api, "lock", self._split_args(call.group("args"))
        )
        return (api, obj) if obj else None

    def _match_unlock(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._first_operation_call(self._unlock_call_re, text)
        if not call:
            return None
        api = call.group("api")
        obj = self.semantics.contracts.resolve_object(
            api, "unlock", self._split_args(call.group("args"))
        )
        return (api, obj) if obj else None

    def _is_var_redefined(self, text: str, var: str) -> bool:
        return bool(re.search(rf"\b{re.escape(var)}\s*=", text))

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

    def _release_followed_by_return(
        self, lines: Sequence[ClangCfgLine], line: ClangCfgLine
    ) -> bool:
        for item in lines[line.index + 1 : line.index + 5]:
            text = item.text.strip()
            if not text or text in {"}", "};"}:
                continue
            if self._match_unlock(text) and not re.search(r"\breturn\b", text):
                continue
            return bool(re.search(r"\breturn\b", text))
        return False

    def _copy_uses_length(self, text: str, len_var: str) -> bool:
        for api, args in self._calls(text):
            if api not in self._copy_sink_names:
                continue
            if any(re.search(rf"\b{re.escape(len_var)}\b", arg) for arg in self._split_args(args)):
                return True
        return False

    @staticmethod
    def _is_return(text: str) -> bool:
        return bool(re.search(r"\breturn\b", text))

    def _calls(self, text: str) -> List[Tuple[str, str]]:
        calls = []
        for match in self._CALL_NAME_RE.finditer(text):
            api = match.group(1)
            args = self._extract_call_args(text, match.end() - 1)
            if args is not None and not self._is_function_declarator(
                text, api, match.start(), match.end() + len(args) + 1
            ):
                calls.append((api, args))
        return calls

    def _first_operation_call(self, pattern: re.Pattern[str], text: str) -> Optional[re.Match[str]]:
        return next(
            (
                match
                for match in pattern.finditer(text)
                if not self._is_function_declarator(
                    text, match.group("api"), match.start(), match.end()
                )
            ),
            None,
        )

    def _is_function_declarator(self, text: str, api: str, start: int, after: int) -> bool:
        """Exclude the scanned function's declaration, preserving body/recursive calls.

        Interface recognition must not turn its own typed parameter list into an
        allocation or lock event. This uses declaration syntax and the indexed
        function identity, never a naming convention for project interfaces.
        """
        if api != getattr(self, "_function_name", ""):
            return False
        prefix = text[:start].strip()
        if not prefix:
            return text[after:].lstrip().startswith("{")
        if re.search(
            r"\b(?:return|co_return|throw|if|while|for|switch|sizeof|alignof|new|delete)\b", prefix
        ):
            return False
        # A type/qualifier prefix cannot contain a statement, assignment, call,
        # or expression operator. Calls in an initializer remain executable.
        return bool(re.fullmatch(r"[A-Za-z_][\w\s:*&<>,\[\]]*", prefix))

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
    def _last_line_matching(
        lines: Sequence[ClangCfgLine], pattern: re.Pattern[str]
    ) -> Optional[ClangCfgLine]:
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
        return re.compile(
            rf"\b(?P<api>{'|'.join(sorted(parts, key=len, reverse=True))})\s*\((?P<args>[^;]*)\)"
        )

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
        if "api_contracts" in self.semantic_overlay:
            rows = []
            for contract in self.semantics.contracts.contracts:
                if not contract.effects_trusted or contract not in self.semantics.contracts.find(contract.symbol.name):
                    continue
                is_lock = contract.role in {"lock", "unlock", "lock_init", "lock_destroy", "lock_wait", "lock_state"}
                if key == "macro_models" and contract.symbol.symbol_type != "macro":
                    continue
                if key == "resource_models" and is_lock or key == "lock_models" and not is_lock:
                    continue
                rows.append({"name": contract.symbol.name, "kind": contract.role,
                             "symbol_type": contract.symbol.symbol_type,
                             "carrier": "return_value" if contract.carrier.kind == "return" else contract.carrier.kind,
                             "object_binding": contract.to_dict()["carrier"]})
            return rows
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
            "program_fact_version": "zscope.program-events.v1",
            "compiler_cfg_complete": bool(self.program_facts.get("complete")),
            "compiler_cfg_edges": [
                edge
                for function in self.program_facts.get("functions", [])
                for edge in function.get("cfg_edges", [])
            ],
            "compiler_events": [
                event
                for event in self.program_facts.get("events", [])
                if (event.get("location") or {}).get("line") in cfg_path
            ],
            "ordering_known": all(line.ordered for line in lines),
            "shared_accesses": [
                access
                for access in self.program_facts.get("accesses", [])
                if (access.get("location") or {}).get("line") in cfg_path
            ],
            "statement_count": len(lines),
            "approx_basic_block_count": len({line.block_id for line in lines}) or 1,
            "declarations": self._declarations(lines),
            "condition_guards": self._condition_guards(lines),
            "scope_summary": self._scope_summary(lines),
            "events": events,
            "unresolved_interface_effects": [
                event
                for event in getattr(self, "last_semantic_events", [])
                if not event.get("effects_trusted")
                or (
                    event.get("role") in {"deallocator", "unlock", "ownership_transfer"}
                    and event.get("applicability") == "unknown"
                )
            ],
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
                guards.append(
                    {
                        "line": line.number,
                        "block": line.block_id,
                        "condition": match.group("expr").strip(),
                    }
                )
        return guards[:32]

    @staticmethod
    def _scope_summary(lines: Sequence[ClangCfgLine]) -> Dict[str, Any]:
        return {
            "block_count": len({line.block_id for line in lines}) or 1,
            "return_lines": [line.number for line in lines if re.search(r"\breturn\b", line.text)][
                :32
            ],
            "branch_lines": [
                line.number
                for line in lines
                if re.search(r"\b(?:if|else|switch|case|for|while)\b", line.text)
            ][:32],
        }

    @staticmethod
    def _event(
        kind: str, line: ClangCfgLine, variable: str, api: str, expression: str
    ) -> Dict[str, Any]:
        return {
            "kind": kind,
            "line": line.number,
            "column": line.column,
            "event_ordinal": line.ordinal,
            "source_offset": line.offset,
            "offset_basis": line.offset_basis,
            "ordering_known": line.ordered,
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
            f"Clang AST/CFG 检查器 `{rule}` 针对 `{defect_class}` 生成了一个证据候选。",
            f"位置: `{func_name}`，位于 `{file_path}:{line}`。",
            f"观察: {description}",
            f"来源: {source or '本地 CFG 来源'}",
            f"汇点: {sink or '本地 CFG 汇点'}",
        ]
        if positive:
            parts.append("正向证据: " + " | ".join(positive[:4]))
        if negative:
            parts.append("验证说明: " + " | ".join(negative[:3]))
        return "\n".join(parts)

    @staticmethod
    def _dedupe(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = str(issue.get("dedup_key") or issue.get("candidate_id") or issue.get("id"))
            deduped.setdefault(key, issue)
        return list(deduped.values())
