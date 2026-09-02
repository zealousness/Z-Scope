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
    from ...orchestration.candidates import CandidateTicket


class ClangAstCfgCandidateGenerator(
    ClangResourceLifecycleRules,
    ClangMemoryBoundsIntegerRules,
    ClangConcurrencySharedStateRules,
    ClangProtocolOwnershipLogicRules,
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
    ):
        self.semantics = self._default_semantics()
        if semantics is not None:
            self.semantics.merge(semantics)
        self.semantic_overlay = semantic_overlay or {}
        self.tooling_evidence_provider = tooling_evidence_provider
        self.rule_policy = rule_policy
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
    ) -> List["CandidateTicket"]:
        return [
            self.issue_to_ticket(issue)
            for issue in self.generate_issues(
                func_name,
                code,
                file_path,
                allowed_skills=allowed_skills,
            )
        ]

    def issue_to_ticket(self, issue: Dict[str, Any]) -> "CandidateTicket":
        from ...orchestration.candidates import CandidateTicket

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
        return CandidateTicket(
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
        self._send_sink_names = {"send", "write", "sendto", "sendmsg", "_net_send_data"}
        self._format_sink_names = {"printf", "fprintf", "syslog", "vprintf", "vfprintf"}
        self._open_sink_names = {"open", "fopen", "creat"}
        self._macro_lock_names: Set[str] = set()
        self._macro_unlock_names: Set[str] = set()

        self._return_acquirers = set(
            self._allocator_names | self._calloc_names | self._reallocator_names
        )
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
            raw_behavior = row.get("concurrency_behavior")
            behavior: Dict[str, Any] = raw_behavior if isinstance(raw_behavior, dict) else {}
            description = str(row.get("description") or "").lower()
            haystack = " ".join(
                [kind, description, " ".join(str(v).lower() for v in behavior.values())]
            )
            if (
                kind == "lock"
                or behavior.get("acquires_lock")
                or "acquire" in haystack
                and "lock" in haystack
            ):
                self._macro_lock_names.add(name)
            if (
                kind == "unlock"
                or behavior.get("releases_lock")
                or "release" in haystack
                and "lock" in haystack
            ):
                self._macro_unlock_names.add(name)

        self._alloc_call_re = self._call_re(self._return_acquirers)
        self._out_acquire_call_re = self._call_re(self._out_param_acquirers)
        self._realloc_call_re = self._call_re(self._reallocator_names)
        self._release_call_re = self._call_re(self._release_names)
        self._lock_call_re = self._call_re(
            self._lock_names, extra_patterns=[r"pthread_rwlock_[rw]dlock"]
        )
        self._unlock_call_re = self._call_re(self._unlock_names)

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
        bind_unique_resource_acquisition: bool = False,
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
        acquisition = (
            self._unique_resource_acquisition_endpoint(
                ast_cfg,
                func_name=func_name,
                file_path=file_path,
            )
            if bind_unique_resource_acquisition
            else None
        )
        source_endpoint: Dict[str, Any] = {
            "expression": source,
            "file": file_path,
            "line": self._line_from_text(source) or line.number,
        }
        if acquisition is not None:
            # Keep the human-readable ``source`` on the issue for display, but
            # bind the machine identity to the exact producer event.  The
            # endpoint deliberately carries both ``api`` (for audit) and
            # ``operation`` (part of CandidateEnvelope's frozen identity).
            source_endpoint = dict(acquisition["source_endpoint"])
        evidence_pack = {
            "candidate_id": candidate_id,
            "candidate_source": "clang_ast_cfg",
            "checker": "clang_ast_cfg_checker",
            "defect_class": defect_class,
            "rule": rule,
            "rule_id": descriptor.rule_id if descriptor is not None else rule,
            "cwe": cwe,
            "skill": skill,
            "rule_confidence": confidence,
            "source": source_endpoint,
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
        if acquisition is not None:
            evidence_pack.update(
                {
                    "resource_signature": acquisition["resource_signature"],
                    "resource_identity": acquisition["resource_identity"],
                    "source_endpoint": dict(acquisition["source_endpoint"]),
                }
            )
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
        if acquisition is not None:
            issues[-1].update(
                {
                    "resource_signature": acquisition["resource_signature"],
                    "resource_identity": acquisition["resource_identity"],
                    "source_endpoint": dict(acquisition["source_endpoint"]),
                }
            )
        if audit_observation_reason:
            issues[-1]["audit_observation_reason"] = audit_observation_reason

    @classmethod
    def _unique_resource_acquisition_endpoint(
        cls,
        ast_cfg: Dict[str, Any],
        *,
        func_name: str,
        file_path: str,
    ) -> Optional[Dict[str, Any]]:
        """Return one exact producer-owned acquisition identity or fail closed.

        Candidate prose is not an ownership identity.  Only a unique,
        structured ``acquire`` event emitted by this checker may bind a live
        resource obligation.  Missing, duplicate, or partially formed events
        leave the candidate visible but intentionally unbound, so ProofKernel
        cannot promote it from an ambiguous source.
        """

        raw_events = ast_cfg.get("events")
        if not isinstance(raw_events, list):
            return None
        acquisitions = [
            event
            for event in raw_events
            if isinstance(event, dict) and str(event.get("kind") or "").strip().lower() == "acquire"
        ]
        if len(acquisitions) != 1:
            return None
        event = acquisitions[0]
        raw_resource = str(event.get("variable") or "").strip()
        resource = cls._resource_expr(raw_resource)
        # ``_resource_expr`` is also used for tolerant call-argument parsing.
        # Identity binding is stricter: the full producer value must be the
        # parsed access path, never merely start with one.
        if not resource or re.sub(r"\s+", "", raw_resource) != resource:
            return None
        api = str(event.get("api") or "").strip()
        if not cls._IDENT_RE.fullmatch(api):
            return None
        try:
            source_line = int(event.get("line") or 0)
        except (TypeError, ValueError):
            return None
        if source_line <= 0 or not str(func_name or "").strip() or not str(file_path or "").strip():
            return None
        endpoint = {
            "kind": "resource_acquire",
            "function": str(func_name).strip(),
            "file": str(file_path).replace("\\", "/"),
            "line": source_line,
            "api": api,
            "operation": api,
            "resource": resource,
        }
        return {
            "resource_signature": resource,
            "resource_identity": resource,
            "source_endpoint": endpoint,
        }

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
        call = self._release_call_re.search(text)
        if not call:
            return None
        return call.group("api"), self._first_arg(call.group("args"))

    def _match_lock(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._lock_call_re.search(text)
        if not call:
            return None
        return (
            call.group("api"),
            self._resource_var(self._first_arg(call.group("args"))) or "global_lock",
        )

    def _match_unlock(self, text: str) -> Optional[Tuple[str, str]]:
        call = self._unlock_call_re.search(text)
        if not call:
            return None
        return (
            call.group("api"),
            self._resource_var(self._first_arg(call.group("args"))) or "global_lock",
        )

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
            if args is not None:
                calls.append((api, args))
        return calls

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
