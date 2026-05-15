"""Deterministic C memory/concurrency candidate generation.

These rules are intentionally conservative enough to produce evidence-backed
review candidates, not final findings. The validator decides whether a
candidate is verified, rejected, or only an audit observation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

if TYPE_CHECKING:
    from ..orchestration.subagents import SubAgentTicket


@dataclass(frozen=True)
class CodeLine:
    """A source line with its original function-relative context."""

    number: int
    raw: str
    text: str
    index: int


@dataclass
class DeterministicSemantics:
    """Project-specific C aliases and API roles used by deterministic rules."""

    type_aliases: Dict[str, str] = field(default_factory=dict)
    allocators: Dict[str, List[str]] = field(default_factory=dict)
    calloc_allocators: Dict[str, List[str]] = field(default_factory=dict)
    reallocators: Dict[str, List[str]] = field(default_factory=dict)
    deallocators: Dict[str, List[str]] = field(default_factory=dict)
    copy_sinks: Dict[str, List[str]] = field(default_factory=dict)
    lock_apis: Dict[str, List[str]] = field(default_factory=dict)
    unlock_apis: Dict[str, List[str]] = field(default_factory=dict)

    def add_api(self, category: str, name: str, source: str) -> None:
        target = {
            "allocator": self.allocators,
            "calloc": self.calloc_allocators,
            "reallocator": self.reallocators,
            "deallocator": self.deallocators,
            "copy": self.copy_sinks,
            "lock": self.lock_apis,
            "unlock": self.unlock_apis,
        }.get(category)
        if target is None:
            return
        clean = str(name or "").strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", clean):
            return
        sources = target.setdefault(clean, [])
        if source and source not in sources:
            sources.append(source)

    def merge(self, other: "DeterministicSemantics") -> None:
        self.type_aliases.update(other.type_aliases)
        for attr in (
            "allocators",
            "calloc_allocators",
            "reallocators",
            "deallocators",
            "copy_sinks",
            "lock_apis",
            "unlock_apis",
        ):
            for name, sources in getattr(other, attr).items():
                for source in sources:
                    self.add_api(_CATEGORY_BY_ATTR[attr], name, source)


_CATEGORY_BY_ATTR = {
    "allocators": "allocator",
    "calloc_allocators": "calloc",
    "reallocators": "reallocator",
    "deallocators": "deallocator",
    "copy_sinks": "copy",
    "lock_apis": "lock",
    "unlock_apis": "unlock",
}


class DeterministicCandidateGenerator:
    """Generate structured candidates for high-signal C memory/concurrency bugs."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
    _DEFAULT_ALLOCATORS = {"malloc", "_safe_malloc"}
    _DEFAULT_CALLOC_ALLOCATORS = {"calloc", "_safe_calloc"}
    _DEFAULT_REALLOCATORS = {"realloc", "_safe_realloc"}
    _DEFAULT_DEALLOCATORS = {"free", "SAFE_FREE"}
    _DEFAULT_COPY_SINKS = {
        "memcpy",
        "memmove",
        "read",
        "recv",
        "fread",
        "send",
        "write",
        "_net_recv_data",
        "_net_send_data",
    }
    _DEFAULT_LOCK_APIS = {"LOCK", "LOCK_READ", "LOCK_WRITE", "pthread_mutex_lock"}
    _DEFAULT_UNLOCK_APIS = {"UNLOCK", "pthread_mutex_unlock", "pthread_rwlock_unlock"}
    _DEFAULT_SIZE_TYPES = {
        "size_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "unsigned char",
        "unsigned int",
        "unsigned long",
        "int",
        "char",
    }

    def __init__(self, semantics: Optional[DeterministicSemantics] = None):
        self.semantics = semantics or DeterministicSemantics()
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._allocator_names = self._DEFAULT_ALLOCATORS | set(self.semantics.allocators)
        self._calloc_names = self._DEFAULT_CALLOC_ALLOCATORS | set(self.semantics.calloc_allocators)
        self._reallocator_names = self._DEFAULT_REALLOCATORS | set(self.semantics.reallocators)
        self._deallocator_names = self._DEFAULT_DEALLOCATORS | set(self.semantics.deallocators)
        self._copy_sink_names = self._DEFAULT_COPY_SINKS | set(self.semantics.copy_sinks)
        self._lock_names = self._DEFAULT_LOCK_APIS | set(self.semantics.lock_apis)
        self._unlock_names = self._DEFAULT_UNLOCK_APIS | set(self.semantics.unlock_apis)
        self._size_type_names = self._DEFAULT_SIZE_TYPES | set(self.semantics.type_aliases)

        self._alloc_re = self._call_re(self._allocator_names)
        self._calloc_re = self._call_re(self._calloc_names)
        self._realloc_re = self._call_re(self._reallocator_names)
        self._dealloc_re = self._call_re(self._deallocator_names)
        self._copy_or_alloc_re = self._call_re(
            self._allocator_names
            | self._calloc_names
            | self._reallocator_names
            | self._copy_sink_names
        )
        self._copy_sink_re = self._call_re(self._copy_sink_names)
        self._lock_re = self._call_re(self._lock_names, extra_patterns=[r"pthread_rwlock_[rw]dlock"])
        self._unlock_re = self._call_re(self._unlock_names)
        self._size_type_pattern = self._type_pattern(self._size_type_names)
        self._integer_pointer_type_pattern = self._type_pattern(
            name
            for name in self._size_type_names
            if name != "char" and name != "unsigned char"
        )

    _CWE_BY_CLASS = {
        "integer_overflow": "CWE-190",
        "bounds": "CWE-125",
        "format_string": "CWE-134",
        "deadlock": "CWE-833",
        "toctou": "CWE-367",
        "command_injection": "CWE-78",
        "memory_leak": "CWE-401",
        "type_confusion": "CWE-843",
        "realloc_misuse": "CWE-401",
        "double_free": "CWE-415",
        "invalid_free": "CWE-590",
        "stack_escape": "CWE-562",
        "missing_unlock": "CWE-667",
        "held_lock_callback": "CWE-667",
        "lost_wakeup": "CWE-366",
        "signed_unsigned": "CWE-195",
        "off_by_one": "CWE-193",
        "uninitialized_read": "CWE-457",
        "stack_overflow": "CWE-121",
        "alignment": "CWE-704",
        "null_pointer_dereference": "CWE-476",
        "use_after_free": "CWE-416",
        "race": "CWE-362",
        "refcount_race": "CWE-362",
        "object_publication": "CWE-362",
        "double_checked_locking": "CWE-362",
        "stale_fd": "CWE-672",
    }

    _SKILL_BY_CLASS = {
        "integer_overflow": "bounds_and_integer",
        "bounds": "bounds_and_integer",
        "format_string": "string_and_format",
        "deadlock": "concurrency_lock_order",
        "toctou": "shared_state_race",
        "command_injection": "string_and_format",
        "memory_leak": "resource_lifecycle",
        "type_confusion": "ownership_contract",
        "signed_unsigned": "bounds_and_integer",
        "off_by_one": "bounds_and_integer",
        "stack_overflow": "bounds_and_integer",
        "alignment": "bounds_and_integer",
        "uninitialized_read": "bounds_and_integer",
        "realloc_misuse": "resource_lifecycle",
        "double_free": "temporal_memory",
        "invalid_free": "temporal_memory",
        "use_after_free": "temporal_memory",
        "race": "shared_state_race",
        "stack_escape": "stack_escape",
        "missing_unlock": "concurrency_lock_order",
        "held_lock_callback": "concurrency_lock_order",
        "lost_wakeup": "shared_state_race",
        "refcount_race": "shared_state_race",
        "object_publication": "shared_state_race",
        "double_checked_locking": "shared_state_race",
        "stale_fd": "resource_lifecycle",
    }

    _RESOURCE_BY_CLASS = {
        "integer_overflow": "memory",
        "bounds": "memory",
        "format_string": "string",
        "deadlock": "lock",
        "toctou": "file",
        "command_injection": "process",
        "memory_leak": "memory",
        "type_confusion": "memory",
        "signed_unsigned": "memory",
        "off_by_one": "memory",
        "stack_overflow": "memory",
        "alignment": "memory",
        "uninitialized_read": "memory",
        "realloc_misuse": "memory",
        "double_free": "memory",
        "invalid_free": "memory",
        "use_after_free": "memory",
        "race": "shared_state",
        "stack_escape": "stack",
        "missing_unlock": "lock",
        "held_lock_callback": "lock",
        "lost_wakeup": "condition_variable",
        "refcount_race": "shared_state",
        "object_publication": "shared_state",
        "double_checked_locking": "shared_state",
        "stale_fd": "handle",
    }

    def generate_issues(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        self._augment_name_heuristics_from_code(str(code or ""))
        lines = self._parse_lines(code)
        if not lines:
            return []
        allowed = set(allowed_skills) if allowed_skills is not None else None
        issues: List[Dict[str, Any]] = []
        emit = self._make_emit(issues, func_name, file_path, lines, allowed)

        self._rule_allocation_size_overflow(lines, emit)
        self._rule_same_function_resource_leak(lines, emit)
        self._rule_realloc_misuse(lines, emit)
        self._rule_double_and_invalid_free(lines, emit)
        self._rule_stack_escape(lines, emit)
        self._rule_lock_balance_and_callbacks(lines, emit)
        self._rule_condvar_wait(lines, emit)
        self._rule_signed_unsigned(lines, emit)
        self._rule_bounds_and_uninit(lines, emit)
        self._rule_null_pointer(lines, emit)
        self._rule_concurrency_state(lines, emit)
        self._rule_common_c_sinks(lines, emit)
        self._rule_stale_resources(lines, emit)

        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = str(issue.get("dedup_key") or issue["id"])
            deduped.setdefault(key, issue)
        return list(deduped.values())

    def generate_tickets(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List["SubAgentTicket"]:
        return [self.issue_to_ticket(issue) for issue in self.generate_issues(
            func_name,
            code,
            file_path,
            allowed_skills=allowed_skills,
        )]

    def issue_to_ticket(self, issue: Dict[str, Any]) -> "SubAgentTicket":
        from ..orchestration.subagents import SubAgentTicket

        defect_class = str(issue.get("defect_class") or issue.get("subcategory") or "unknown")
        skill = self._SKILL_BY_CLASS.get(defect_class, "resource_lifecycle")
        evidence = dict(issue.get("evidence_pack") or {})
        evidence.setdefault("positive_evidence", issue.get("positive_evidence") or [])
        evidence.setdefault("negative_evidence", issue.get("negative_evidence") or [])
        line = self._line_from_location(str(issue.get("location") or ""))
        return SubAgentTicket(
            id=str(issue.get("candidate_id") or issue.get("id")),
            skill=skill,
            task=(
                f"Verify deterministic {defect_class} candidate. Confirm concrete "
                "source, sink, path feasibility, and guard sufficiency; reject if any "
                "required proof is missing."
            ),
            trigger=str(issue.get("rule") or defect_class),
            line=line,
            context_slice=str(issue.get("code_snippet") or ""),
            priority_score=self._priority_for_issue(issue),
            priority_reasons=[
                "deterministic_candidate",
                defect_class,
                f"rule_confidence={issue.get('rule_confidence', issue.get('confidence', 0.5))}",
            ],
            origin=str(issue.get("source") or issue.get("location") or ""),
            sink=str(issue.get("sink") or issue.get("location") or ""),
            resource_kind=self._RESOURCE_BY_CLASS.get(defect_class, "unknown"),
            source="deterministic_rule",
            evidence=evidence,
        )

    def _make_emit(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: List[CodeLine],
        allowed_skills: Optional[set[str]],
    ):
        def emit(
            *,
            defect_class: str,
            rule: str,
            line: CodeLine,
            description: str,
            root_cause: str,
            suggested_fix: str,
            sink: str,
            source: str = "",
            confidence: float = 0.78,
            impact_level: str = "medium",
            positive: Optional[List[str]] = None,
            negative: Optional[List[str]] = None,
            evidence: Optional[Dict[str, Any]] = None,
            context_start: int = -5,
            context_end: int = 8,
        ) -> None:
            skill = self._SKILL_BY_CLASS.get(defect_class, "resource_lifecycle")
            if allowed_skills is not None and skill not in allowed_skills:
                return

            candidate_id = self._candidate_id(func_name, file_path, defect_class, line.number, sink)
            dedup_key = "|".join(
                [
                    defect_class,
                    file_path.replace("\\", "/").lower(),
                    str(line.number),
                    self._normalize_sink_key(sink),
                ]
            )
            pos = list(positive or [])
            pos.extend(self._api_evidence_for_line(line.text))
            neg = list(negative or [])
            pack = {
                "candidate_id": candidate_id,
                "candidate_source": "deterministic_rule",
                "defect_class": defect_class,
                "rule": rule,
                "rule_confidence": confidence,
                "source": {
                    "expression": source,
                    "line": line.number,
                    "file": file_path,
                },
                "sink": {
                    "operation": sink,
                    "line": line.number,
                    "file": file_path,
                },
                "path": {
                    "function": func_name,
                    "complete_in_function": True,
                    "guard_status": "insufficient_or_absent" if not neg else "needs_validation",
                },
                "object": {
                    "id": source or sink or defect_class,
                    "aliases": [],
                },
                "evidence_refs": [],
                "positive_evidence": pos,
                "negative_evidence": neg,
            }
            if evidence:
                pack.update(evidence)

            reasoning = self._build_readable_reasoning(
                defect_class=defect_class,
                rule=rule,
                func_name=func_name,
                file_path=file_path,
                line=line.number,
                description=description,
                root_cause=root_cause,
                suggested_fix=suggested_fix,
                source=source,
                sink=sink,
                positive_evidence=pos,
                negative_evidence=neg,
                evidence_pack=pack,
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
                    "finding_kind": "deterministic_candidate",
                    "rule": rule,
                    "cwe": self._CWE_BY_CLASS.get(defect_class, ""),
                    "description": description,
                    "root_cause": root_cause,
                    "suggested_fix": suggested_fix,
                    "confidence": confidence,
                    "rule_confidence": confidence,
                    "impact_level": impact_level,
                    "reasoning": reasoning,
                    "code_snippet": self._context(lines, line.index + context_start, line.index + context_end),
                    "source": source,
                    "sink": sink,
                    "dedup_key": dedup_key,
                    "positive_evidence": pos,
                    "negative_evidence": neg,
                    "evidence_pack": pack,
                    "evidence_refs": [],
                }
            )

        return emit

    @staticmethod
    def _build_readable_reasoning(
        *,
        defect_class: str,
        rule: str,
        func_name: str,
        file_path: str,
        line: int,
        description: str,
        root_cause: str,
        suggested_fix: str,
        source: str,
        sink: str,
        positive_evidence: List[str],
        negative_evidence: List[str],
        evidence_pack: Dict[str, Any],
    ) -> str:
        """Build Chinese human-readable reasoning from deterministic evidence."""

        cwe = DeterministicCandidateGenerator._CWE_BY_CLASS.get(defect_class, "")
        path = evidence_pack.get("path") if isinstance(evidence_pack.get("path"), dict) else {}
        guard_status = str(path.get("guard_status") or "")
        if guard_status == "insufficient_or_absent":
            guard_text = "当前函数内未看到足够的边界检查、所有权转移或同步保护。"
        elif guard_status == "needs_validation":
            guard_text = "存在部分保护或反向证据，需要结合上下文继续确认。"
        else:
            guard_text = "规则证据未给出额外保护状态。"

        flow_parts = []
        if source:
            flow_parts.append(f"源/对象 `{source}`")
        if sink:
            flow_parts.append(f"汇点/操作 `{sink}`")
        flow = " -> ".join(flow_parts) if flow_parts else "规则命中的本地代码片段"

        lines = [
            f"确定性规则 `{rule}` 在 `{func_name}` 的 `{file_path}:{line}` 命中了 `{defect_class}`"
            + (f"（{cwe}）" if cwe else "")
            + " 候选。",
            f"问题判断：{description}",
            f"数据/资源路径：{flow}。",
            f"保护状态：{guard_text}",
        ]
        if positive_evidence:
            lines.append("关键证据：")
            lines.extend(f"- {item}" for item in positive_evidence[:6])
            if len(positive_evidence) > 6:
                lines.append(f"- 另有 {len(positive_evidence) - 6} 条结构化证据未展开。")
        if negative_evidence:
            lines.append("需要复核的反向证据：")
            lines.extend(f"- {item}" for item in negative_evidence[:4])
        else:
            lines.append("反向证据：未发现能否定该候选的本地保护或清理证据。")
        lines.append(f"根因：{root_cause}")
        lines.append(f"建议：{suggested_fix}")
        return "\n".join(lines)

    def _rule_allocation_size_overflow(self, lines: List[CodeLine], emit) -> None:
        params = self._function_params(lines)
        arithmetic_defs: Dict[str, Tuple[CodeLine, str, List[str]]] = {}
        for line in lines:
            clean = line.text
            assign = re.search(
                rf"\b(?:{self._size_type_pattern})\s+"
                r"(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]*[+*][^;]*);",
                clean,
            )
            if assign:
                expr = assign.group("expr").strip()
                operands = [item for item in self._IDENT_RE.findall(expr) if item not in {"sizeof", "SIZE_MAX", "UINT_MAX"}]
                arithmetic_defs[assign.group("var")] = (line, expr, operands)
                if (
                    self._next_window_has_sink(lines, line.index, assign.group("var"))
                    and not self._has_pre_overflow_guard(lines, line.index, operands)
                    and not self._has_post_wrap_check(lines, line.index, assign.group("var"), operands)
                    and self._is_high_risk_size_expr(expr, params)
                ):
                    emit(
                        defect_class="integer_overflow",
                        rule="arithmetic_size_before_sink",
                        line=line,
                        description=(
                            f"`{assign.group('var')}` is computed from `{expr}` before it is "
                            "used as a size/length argument; wraparound can shrink the allocation "
                            "or copy bound."
                        ),
                        root_cause="Size arithmetic is performed before proving operands are bounded.",
                        suggested_fix="Check operands before the arithmetic, or use a checked size helper.",
                        source=expr,
                        sink=f"{assign.group('var')} used by allocation/copy",
                        confidence=0.82,
                        positive=[
                            f"line {line.number}: arithmetic size expression `{expr}`",
                            "nearby allocation/copy consumes the computed size",
                        ],
                        negative=self._guard_evidence(lines, line.index, operands),
                    )

            alloc_call = self._match_call(clean, self._allocator_names, "expr")
            if alloc_call:
                expr = alloc_call.group("expr")
                if not re.search(r"[+*]", expr) or not self._is_high_risk_size_expr(expr, params):
                    continue
                identifiers = [
                    item
                    for item in self._IDENT_RE.findall(expr)
                    if item not in {"sizeof"} | self._allocator_names | self._reallocator_names
                ]
                if identifiers and not self._has_pre_overflow_guard(lines, line.index, identifiers):
                    emit(
                        defect_class="integer_overflow",
                        rule="inline_allocation_size_overflow",
                        line=line,
                        description="Allocation size is computed inline with unchecked addition/multiplication.",
                        root_cause="The allocation expression can wrap before the allocator sees it.",
                        suggested_fix="Validate operands before the allocation expression or use checked arithmetic.",
                        source=expr.strip(),
                        sink=clean.strip(),
                        confidence=0.84,
                        positive=[
                            f"line {line.number}: allocator call contains arithmetic `{expr.strip()}`",
                        ],
                        negative=self._guard_evidence(lines, line.index, identifiers),
                    )

        for line in lines:
            clean = line.text
            call = self._match_call(clean, self._calloc_names, "args", until=";")
            if not call:
                continue
            args = call.group("args")
            identifiers = [
                item
                for item in self._IDENT_RE.findall(args)
                if item not in {"calloc", "_safe_calloc", "sizeof", "NULL"}
            ]
            nearby = "\n".join(item.text for item in lines[max(0, line.index - 4) : line.index + 1])
            if (
                len(identifiers) >= 2
                and any(item in params for item in identifiers)
                and "_parse_arguments" not in nearby
                and not self._has_pre_overflow_guard(lines, line.index, identifiers)
            ):
                emit(
                    defect_class="integer_overflow",
                    rule="calloc_product_overflow",
                    line=line,
                    description="calloc-like allocation multiplies two caller-sized operands without a visible precheck.",
                    root_cause="The element count and size product may overflow before allocation.",
                    suggested_fix="Check `count <= SIZE_MAX / elem_size` before calloc or rely on a proven checked wrapper.",
                    source=args.strip(),
                    sink=clean.strip(),
                    confidence=0.67,
                    positive=[f"line {line.number}: calloc-like call `{clean.strip()}`"],
                    negative=self._guard_evidence(lines, line.index, identifiers),
                )

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
                if re.search(rf"\b[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\s*=\s*{re.escape(var)}\b", line.text):
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
                *(f"line {alloc_line.number}: allocation assigned to `{var}`" for var, alloc_line in leaked),
                "no matching release/return/ownership transfer found in the function body",
            ],
        )

    def _rule_double_and_invalid_free(self, lines: List[CodeLine], emit) -> None:
        last_free: Dict[str, CodeLine] = {}
        pointer_owners = self._pointer_owner_vars(lines)
        for line in lines:
            free = self._match_call(line.text, self._deallocator_names, "arg")
            if not free:
                if re.search(r"\breturn\b", line.text):
                    last_free.clear()
                    continue
                for var in list(last_free):
                    if re.search(
                        rf"\b{re.escape(var)}\s*=\s*(?:NULL|0|{self._names_pattern(self._allocator_names | self._calloc_names)})",
                        line.text,
                    ):
                        last_free.pop(var, None)
                continue

            arg = free.group("arg").strip()
            if arg.startswith("&") or re.search(r"[+\-]\s*\d+", arg):
                emit(
                    defect_class="invalid_free",
                    rule="free_non_owner_pointer",
                    line=line,
                    description=f"`{arg}` is freed even though it is not the base owner pointer.",
                    root_cause="A deallocator receives an interior or stack-address expression.",
                    suggested_fix="Free only the owning base pointer returned by the allocator.",
                    source=arg,
                    sink=line.text.strip(),
                    confidence=0.84,
                    positive=[f"line {line.number}: frees non-owner expression `{arg}`"],
                )
                continue

            var_match = re.match(r"([A-Za-z_]\w*)$", arg)
            if not var_match:
                continue
            var = var_match.group(1)
            if var not in pointer_owners:
                continue
            previous = last_free.get(var)
            if previous:
                emit(
                    defect_class="double_free",
                    rule="same_pointer_freed_twice",
                    line=line,
                    description=f"`{var}` is released twice on the same local path.",
                    root_cause="No reassignment or nulling of the owner is visible between releases.",
                    suggested_fix="Remove the duplicate release or set ownership to NULL after the first release.",
                    source=var,
                    sink=line.text.strip(),
                    confidence=0.88,
                    positive=[
                        f"line {previous.number}: first release of `{var}`",
                        f"line {line.number}: second release of `{var}`",
                    ],
                )
            last_free[var] = line

    def _rule_stack_escape(self, lines: List[CodeLine], emit) -> None:
        locals_seen = self._collect_local_vars(lines)
        for line in lines:
            create = re.search(r"\bpthread_create\s*\((?P<args>[^;]+)\)", line.text)
            if create:
                for var, decl in locals_seen.items():
                    if f"&{var}" in create.group("args") and decl.index < line.index:
                        emit(
                            defect_class="stack_escape",
                            rule="stack_address_to_thread",
                            line=line,
                            description=f"Address of stack local `{var}` is passed to a new thread.",
                            root_cause="The thread may outlive the stack frame that owns the argument.",
                            suggested_fix="Allocate a heap-owned argument or join before returning from the frame.",
                            source=f"&{var}",
                            sink=line.text.strip(),
                            confidence=0.87,
                            impact_level="high",
                            positive=[
                                f"line {decl.number}: local `{var}` is stack allocated",
                                f"line {line.number}: `{var}` address escapes through pthread_create",
                            ],
                        )
            ret = re.search(r"\breturn\s+&(?P<var>[A-Za-z_]\w*)\s*;", line.text)
            if ret and ret.group("var") in locals_seen:
                decl = locals_seen[ret.group("var")]
                emit(
                    defect_class="stack_escape",
                    rule="return_stack_address",
                    line=line,
                    description=f"Function returns the address of stack local `{ret.group('var')}`.",
                    root_cause="Returned pointer refers to storage destroyed when the function returns.",
                    suggested_fix="Return owned heap storage or write into caller-provided storage.",
                    source=f"&{ret.group('var')}",
                    sink=line.text.strip(),
                    confidence=0.9,
                    impact_level="high",
                    positive=[
                        f"line {decl.number}: stack local declaration",
                        f"line {line.number}: address returned",
                    ],
                )

    def _rule_lock_balance_and_callbacks(self, lines: List[CodeLine], emit) -> None:
        held: List[CodeLine] = []
        for line in lines:
            if self._lock_re.search(line.text):
                held.append(line)
            if held and re.search(r"\b[A-Za-z_]\w*(?:callback|cb|handler)[A-Za-z_0-9]*\s*\(", line.text, re.IGNORECASE):
                lock_line = held[-1]
                emit(
                    defect_class="held_lock_callback",
                    rule="callback_while_lock_held",
                    line=line,
                    description="Callback/function-pointer style call is made while a lock is held.",
                    root_cause="External callback code can re-enter the same subsystem or acquire conflicting locks.",
                    suggested_fix="Copy required state under the lock, release the lock, then invoke the callback.",
                    source=f"lock at line {lock_line.number}",
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        f"line {lock_line.number}: lock acquired",
                        f"line {line.number}: callback-like call before unlock",
                    ],
                )
            if held and re.search(r"\breturn\b", line.text):
                lock_line = held[-1]
                emit(
                    defect_class="missing_unlock",
                    rule="return_while_lock_held",
                    line=line,
                    description="Function returns while a mutex/rwlock appears to be held.",
                    root_cause="A path exits the function before the matching unlock.",
                    suggested_fix="Release the lock before every return path or use a single cleanup label.",
                    source=f"lock at line {lock_line.number}",
                    sink=line.text.strip(),
                    confidence=0.8,
                    impact_level="high",
                    positive=[
                        f"line {lock_line.number}: lock acquired",
                        f"line {line.number}: return before matching unlock",
                    ],
                )
            if self._unlock_re.search(line.text) and held:
                held.pop()

    def _rule_condvar_wait(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            if "pthread_cond_wait" not in line.text:
                continue
            previous = self._previous_nonempty(lines, line.index, limit=4)
            if any(re.search(r"\bif\s*\(", item.text) for item in previous) and not any(
                re.search(r"\bwhile\s*\(", item.text) for item in previous
            ):
                emit(
                    defect_class="lost_wakeup",
                    rule="cond_wait_guarded_by_if",
                    line=line,
                    description="Condition variable wait is guarded by `if` rather than a predicate loop.",
                    root_cause="Spurious wakeups or missed predicate changes can make the thread continue incorrectly.",
                    suggested_fix="Guard pthread_cond_wait with a while loop that rechecks the shared predicate.",
                    source="condition predicate",
                    sink=line.text.strip(),
                    confidence=0.83,
                    impact_level="high",
                    positive=[
                        "nearby branch uses `if` before pthread_cond_wait",
                        f"line {line.number}: condition variable wait",
                    ],
                )

    def _rule_signed_unsigned(self, lines: List[CodeLine], emit) -> None:
        signed_reads: Dict[str, CodeLine] = {}
        casts: Dict[str, Tuple[CodeLine, str]] = {}
        for line in lines:
            read = re.search(r"\bint\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?:recv|read|_net_recv_data)\s*\(", line.text)
            if read:
                signed_reads[read.group("var")] = line
            cast = re.search(r"\bsize_t\s+(?P<size>[A-Za-z_]\w*)\s*=\s*\(size_t\)\s*(?P<src>[A-Za-z_]\w*)\s*;", line.text)
            if cast and cast.group("src") in signed_reads:
                casts[cast.group("size")] = (line, cast.group("src"))
            for size_var, (cast_line, src_var) in list(casts.items()):
                if re.search(rf"\b(?:memcpy|memmove|_net_send_data|_net_recv_data)\s*\([^;]*\b{re.escape(size_var)}\b", line.text):
                    emit(
                        defect_class="signed_unsigned",
                        rule="negative_length_cast_to_size_t",
                        line=cast_line,
                        description=f"Signed length `{src_var}` is cast to size_t and later used as a copy/IO length.",
                        root_cause="Negative error values can become very large unsigned sizes.",
                        suggested_fix=f"Check `{src_var} >= 0` and upper bounds before casting to size_t.",
                        source=src_var,
                        sink=line.text.strip(),
                        confidence=0.86,
                        impact_level="high",
                        positive=[
                            f"line {signed_reads[src_var].number}: signed result from IO",
                            f"line {cast_line.number}: cast to size_t",
                            f"line {line.number}: unsigned length reaches copy/IO sink",
                        ],
                    )

    def _rule_bounds_and_uninit(self, lines: List[CodeLine], emit) -> None:
        struct_locals: Dict[str, Tuple[CodeLine, int, bool]] = {}
        unaligned_ptrs: Dict[str, CodeLine] = {}
        for line in lines:
            off = re.search(r"\b(?P<array>[A-Za-z_]\w*)\s*\[\s*sizeof\s*\(\s*(?P=array)\s*\)\s*\]\s*=", line.text)
            if off:
                emit(
                    defect_class="off_by_one",
                    rule="sizeof_index_write",
                    line=line,
                    description="Array write indexes `array[sizeof(array)]`, one element past the end.",
                    root_cause="sizeof(array) is the byte count and is outside the zero-based index range.",
                    suggested_fix="Use `sizeof(array) - 1` for the terminator or a length-aware helper.",
                    source=off.group("array"),
                    sink=line.text.strip(),
                    confidence=0.9,
                    impact_level="high",
                    positive=[f"line {line.number}: writes at sizeof(array) index"],
                )

            vla = re.search(
                rf"\b(?:{self._size_type_pattern})\s+(?P<var>[A-Za-z_]\w*)\s*\[\s*(?P<expr>[^]\d][^]]*)\s*\]\s*;",
                line.text,
            )
            if vla and not self._is_macro_size_expr(vla.group("expr")) and re.search(r"[+*]|[A-Za-z_]\w*", vla.group("expr")):
                emit(
                    defect_class="stack_overflow",
                    rule="unbounded_vla_or_stack_array",
                    line=line,
                    description="Stack array size is derived from a runtime expression without a visible cap.",
                    root_cause="Caller-controlled or data-dependent stack allocation can exhaust the stack.",
                    suggested_fix="Cap the size before stack allocation or allocate bounded heap storage.",
                    source=vla.group("expr").strip(),
                    sink=line.text.strip(),
                    confidence=0.76,
                    impact_level="high",
                    positive=[f"line {line.number}: stack allocation size `{vla.group('expr').strip()}`"],
                )

            align = re.search(
                rf"\*\s*\(\s*(?:{self._integer_pointer_type_pattern})\s*\*\s*\)\s*\([^)]*\+\s*1\s*\)",
                line.text,
            )
            if align:
                emit(
                    defect_class="alignment",
                    rule="unaligned_integer_pointer_cast",
                    line=line,
                    description="Potentially unaligned byte pointer is cast to an integer pointer and dereferenced.",
                    root_cause="The cast requires alignment that the byte-offset expression does not guarantee.",
                    suggested_fix="Use memcpy into an aligned local integer or byte-wise decoding.",
                    source=line.text.strip(),
                    sink=line.text.strip(),
                    confidence=0.78,
                    positive=[f"line {line.number}: dereferences integer pointer from byte offset"],
                )
            ptr_cast = re.search(
                rf"\b(?P<var>[A-Za-z_]\w*)\s*=\s*\([^;]*(?:{self._integer_pointer_type_pattern})\s*\*\s*\)"
                r"\s*\([^;]*\+\s*1\s*\)",
                line.text,
            )
            if ptr_cast:
                unaligned_ptrs[ptr_cast.group("var")] = line
            for var, cast_line in list(unaligned_ptrs.items()):
                if line.index > cast_line.index and re.search(rf"\*{re.escape(var)}\b", line.text):
                    emit(
                        defect_class="alignment",
                        rule="unaligned_integer_pointer_cast",
                        line=line,
                        description="Potentially unaligned byte pointer is cast to an integer pointer and later dereferenced.",
                        root_cause="The cast requires alignment that the byte-offset expression does not guarantee.",
                        suggested_fix="Use memcpy into an aligned local integer or byte-wise decoding.",
                        source=cast_line.text.strip(),
                        sink=line.text.strip(),
                        confidence=0.82,
                        positive=[
                            f"line {cast_line.number}: integer pointer is formed from byte offset",
                            f"line {line.number}: pointer is dereferenced",
                        ],
                    )
                    unaligned_ptrs.pop(var, None)

            decl = re.search(r"\b(?:struct\s+)?(?P<type>[A-Z][A-Za-z_0-9]*)\s+(?P<var>[A-Za-z_]\w*)\s*;", line.text)
            if decl and "=" not in line.text and "typedef" not in line.text:
                struct_locals[decl.group("var")] = (line, 0, False)
            for var, (decl_line, field_writes, has_memset) in list(struct_locals.items()):
                if re.search(rf"\bmemset\s*\(\s*&{re.escape(var)}\s*,", line.text):
                    struct_locals[var] = (decl_line, field_writes, True)
                elif re.search(rf"\b{re.escape(var)}\.[A-Za-z_]\w*\s*=", line.text):
                    struct_locals[var] = (decl_line, field_writes + 1, has_memset)
                elif re.search(rf"\b(?:_net_send_data|send|write)\s*\([^;]*&{re.escape(var)}\s*,\s*sizeof\s*\(\s*{re.escape(var)}\s*\)", line.text):
                    if not has_memset and field_writes > 0:
                        emit(
                            defect_class="uninitialized_read",
                            rule="partial_struct_sent",
                            line=line,
                            description=f"`{var}` is partially initialized and then sent/copied with sizeof.",
                            root_cause="Padding or unassigned fields can leak stale stack bytes.",
                            suggested_fix="Zero-initialize the struct before field assignments or serialize fields explicitly.",
                            source=var,
                            sink=line.text.strip(),
                            confidence=0.82,
                            positive=[
                                f"line {decl_line.number}: local aggregate `{var}` declared without initializer",
                                f"line {line.number}: entire aggregate is sent/copied",
                            ],
                        )

    def _rule_null_pointer(self, lines: List[CodeLine], emit) -> None:
        strchr_results: Dict[str, CodeLine] = {}
        guarded: set[str] = set()
        for line in lines:
            assign = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*strchr\s*\(", line.text)
            if assign:
                strchr_results[assign.group("var")] = line
                guarded.discard(assign.group("var"))
                continue
            for var in list(strchr_results):
                if re.search(rf"\bif\s*\([^)]*(?:!\s*{re.escape(var)}|{re.escape(var)}\s*==\s*NULL|NULL\s*==\s*{re.escape(var)})", line.text):
                    guarded.add(var)
                elif var not in guarded and re.search(rf"(\*{re.escape(var)}\b|{re.escape(var)}\s*\[|{re.escape(var)}\s*-)", line.text):
                    src_line = strchr_results[var]
                    emit(
                        defect_class="null_pointer_dereference",
                        rule="unchecked_strchr_result",
                        line=line,
                        description=f"`{var}` from strchr is used without a visible NULL check.",
                        root_cause="strchr can return NULL when the delimiter is absent.",
                        suggested_fix=f"Check `{var}` for NULL before pointer arithmetic or dereference.",
                        source=f"strchr result at line {src_line.number}",
                        sink=line.text.strip(),
                        confidence=0.83,
                        positive=[
                            f"line {src_line.number}: `{var}` receives strchr result",
                            f"line {line.number}: `{var}` is used before NULL check",
                        ],
                    )
                    guarded.add(var)

    def _rule_concurrency_state(self, lines: List[CodeLine], emit) -> None:
        seen_race_globals: set[str] = set()
        for idx, line in enumerate(lines):
            dcl = re.search(r"\bif\s*\(\s*!\s*(?P<obj>g_[A-Za-z_]\w*)\s*\)", line.text)
            if dcl:
                obj = dcl.group("obj")
                window = "\n".join(item.text for item in lines[idx + 1 : idx + 9])
                if self._lock_re.search(window) and re.search(rf"\bif\s*\(\s*!\s*{re.escape(obj)}\s*\)", window):
                    emit(
                        defect_class="double_checked_locking",
                        rule="double_checked_global_without_atomic",
                        line=line,
                        description=f"`{obj}` uses double-checked locking without visible atomic publication.",
                        root_cause="Readers outside the lock can observe a partially initialized object or stale pointer.",
                        suggested_fix="Guard all accesses with the same lock or publish through atomic acquire/release.",
                        source=obj,
                        sink="double checked locking",
                        confidence=0.74,
                        impact_level="high",
                        positive=[f"line {line.number}: first check of `{obj}` occurs outside lock"],
                    )

            publish = re.search(r"\b(?P<global>g_[A-Za-z_0-9.]+)\s*=\s*(?P<obj>[A-Za-z_]\w*)\s*;", line.text)
            if publish:
                obj = publish.group("obj")
                later = lines[idx + 1 : idx + 8]
                if any(re.search(rf"\b{re.escape(obj)}->[A-Za-z_]\w*\s*=", item.text) for item in later):
                    emit(
                        defect_class="object_publication",
                        rule="object_published_before_initialization",
                        line=line,
                        description=f"`{obj}` is published through `{publish.group('global')}` before later field initialization.",
                        root_cause="Concurrent readers can observe the object before all fields are initialized.",
                        suggested_fix="Fully initialize the object before linking/publishing it to shared state.",
                        source=obj,
                        sink=line.text.strip(),
                        confidence=0.81,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: object is assigned to shared/global state",
                            "later lines initialize fields after publication",
                        ],
                    )

            find_locked = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*find[A-Za-z_0-9]*locked\s*\(", line.text)
            if find_locked:
                var = find_locked.group("var")
                later = lines[idx + 1 : idx + 12]
                unlock_idx = next((item.index for item in later if self._unlock_re.search(item.text)), None)
                if unlock_idx is not None:
                    for item in later:
                        if item.index <= unlock_idx:
                            continue
                        if re.search(rf"\b{re.escape(var)}->ref_count\s*(?:\+\+|--|\+=|-=)", item.text):
                            emit(
                                defect_class="refcount_race",
                                rule="refcount_update_after_unlock",
                                line=item,
                                description=f"`{var}->ref_count` is modified after releasing the protecting lock.",
                                root_cause="Reference count update is not atomic or protected by the lock that found the object.",
                                suggested_fix="Increment/decrement the reference count under the same lock or use atomics.",
                                source=var,
                                sink=item.text.strip(),
                                confidence=0.84,
                                impact_level="high",
                                positive=[
                                    f"line {line.number}: object is found under lock",
                                    "unlock occurs before the refcount update",
                                    f"line {item.number}: ref_count is updated",
                                ],
                            )
                            break

            callback_ctx = re.search(
                r"\b(?P<global>g_[A-Za-z_0-9]*(?:callback|cb)[A-Za-z_0-9]*)\s*="
                r"\s*(?P<obj>[A-Za-z_]\w*find[A-Za-z_0-9]*locked\s*\([^;]+)",
                line.text,
                re.IGNORECASE,
            )
            if callback_ctx:
                later = lines[idx + 1 : idx + 8]
                if any(self._unlock_re.search(item.text) for item in later):
                    emit(
                        defect_class="use_after_free",
                        rule="global_callback_context_borrowed_under_lock",
                        line=line,
                        description="A global callback context stores a borrowed cache entry that can be freed later.",
                        root_cause="The entry pointer is saved globally without taking ownership or a protected reference.",
                        suggested_fix="Store an owned reference/copy or unregister/clear the callback before entry removal.",
                        source=callback_ctx.group("obj"),
                        sink=line.text.strip(),
                        confidence=0.8,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: global callback context assigned from locked lookup",
                            "the lock is released after storing the borrowed pointer",
                        ],
                    )

            race = re.search(
                r"\b(?P<global>g_[A-Za-z_0-9]*(?:counter|flag|running|shutdown|state|status|ready|stop|done|active|enabled)[A-Za-z_0-9]*)\b",
                line.text,
                re.IGNORECASE,
            )
            if race and not (self._lock_re.search(line.text) or self._unlock_re.search(line.text)):
                global_name = race.group("global")
                if global_name not in seen_race_globals and re.search(r"\+\+|--|while\s*\(|if\s*\(|=[^=]", line.text):
                    seen_race_globals.add(global_name)
                    emit(
                        defect_class="race",
                        rule="unsynchronized_shared_flag_or_counter",
                        line=line,
                        description=f"`{global_name}` is accessed without an evident lock or atomic operation.",
                        root_cause="Shared flag/counter access is not consistently synchronized across threads.",
                        suggested_fix="Use a mutex or atomic operations for all reads and writes of the shared state.",
                        source=global_name,
                        sink=line.text.strip(),
                        confidence=0.68,
                        positive=[f"line {line.number}: unsynchronized shared global access"],
                    )

            if re.search(r"\breturn\s+[A-Za-z_]\w+\s*;", line.text):
                self._emit_borrowed_after_unlock(lines, line, emit)

    def _rule_common_c_sinks(self, lines: List[CodeLine], emit) -> None:
        permission_check_line: Optional[CodeLine] = None
        length_field_defs: Dict[str, Tuple[CodeLine, str]] = {}
        held_locks: List[CodeLine] = []
        for line in lines:
            length_def = re.search(
                rf"\b(?:{self._size_type_pattern})\s+"
                r"(?P<var>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*=\s*"
                r"(?P<src>[A-Za-z_]\w*(?:->|\.)[A-Za-z_0-9]*(?:len|length|size)[A-Za-z_0-9]*)\s*;",
                line.text,
                re.IGNORECASE,
            )
            if length_def:
                length_field_defs[length_def.group("var")] = (line, length_def.group("src"))
            for len_var, (src_line, src_expr) in list(length_field_defs.items()):
                if line.index <= src_line.index:
                    continue
                if not re.search(
                    rf"\b(?:{self._names_pattern(self._copy_sink_names)})\s*\([^;]*\b{re.escape(len_var)}\b",
                    line.text,
                ):
                    continue
                guard_window = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index])
                if re.search(rf"\b{re.escape(len_var)}\b\s*[<>]=?\s*[^;]*(?:data_len|buf_len|buffer_len|remaining|capacity|sizeof)", guard_window):
                    continue
                emit(
                    defect_class="bounds",
                    rule="external_length_field_reaches_copy",
                    line=line,
                    description=f"Length field `{src_expr}` reaches a copy/IO sink without a visible buffer-bound guard.",
                    root_cause="A serialized or structured length field is trusted without proving the backing buffer contains that many bytes.",
                    suggested_fix="Validate the length against the remaining input buffer or destination capacity before copying.",
                    source=f"{src_expr} at line {src_line.number}",
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        f"line {src_line.number}: length is loaded from an object field",
                        f"line {line.number}: length reaches copy/IO sink",
                    ],
                )
                length_field_defs.pop(len_var, None)

            fmt = re.search(r"\b(?:printf|fprintf|syslog)\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", line.text)
            if fmt:
                emit(
                    defect_class="format_string",
                    rule="nonliteral_format_string",
                    line=line,
                    description=f"`{fmt.group('arg')}` is used as a printf-style format string.",
                    root_cause="Attacker-controlled percent sequences can be interpreted as format directives.",
                    suggested_fix=f"Use `printf(\"%s\", {fmt.group('arg')})` or an equivalent literal format.",
                    source=fmt.group("arg"),
                    sink=line.text.strip(),
                    confidence=0.86,
                    impact_level="high",
                    positive=[f"line {line.number}: non-literal printf-style format"],
                )

            if self._lock_re.search(line.text):
                held_locks.append(line)
            nested_lookup = re.search(
                r"\b(?P<fn>[A-Za-z_]\w*(?:find|lookup|search|get)[A-Za-z_0-9]*)\s*\(",
                line.text,
                re.IGNORECASE,
            )
            if held_locks and nested_lookup:
                lock_line = held_locks[-1]
                nearby = "\n".join(item.text for item in lines[max(0, line.index - 30) : line.index + 30])
                fn_name = nested_lookup.group("fn")
                if re.search(r"(?:_nolock|_locked|locked_)", fn_name, re.IGNORECASE):
                    nested_lookup = None
                elif not re.search(rf"\b{re.escape(fn_name)}\s*\(", lock_line.text):
                    has_local_lock_evidence = (
                        re.search(rf"\b{re.escape(fn_name)}\s*\([^)]*\)\s*{{[^}}]*(?:{self._names_pattern(self._lock_names)})\s*\(", nearby, re.S)
                        or re.search(rf"\b{re.escape(fn_name)}\s*[:=].*(?:requires|takes|locks)", nearby, re.I)
                    )
                    emit(
                        defect_class="deadlock",
                        rule="lookup_like_call_under_held_lock",
                        line=line,
                        description=f"`{fn_name}` is called while a lock is already held; lookup-style helpers often have their own lock contract.",
                        root_cause="A helper can recursively acquire the same lock or invert lock ownership if its locking contract is not no-lock/locked.",
                        suggested_fix="Use a no-lock helper for locked callers, document lock ownership, or release before calling.",
                        source=f"lock at line {lock_line.number}",
                        sink=line.text.strip(),
                        confidence=0.74 if has_local_lock_evidence else 0.62,
                        impact_level="high",
                        positive=[
                            f"line {lock_line.number}: lock acquired before helper call",
                            f"line {line.number}: lookup-like helper called while lock is held",
                        ],
                        negative=[] if has_local_lock_evidence else ["callee locking behavior requires validation"],
                    )
                    nested_lookup = None
            if held_locks and nested_lookup:
                lock_line = held_locks[-1]
                nearby = "\n".join(item.text for item in lines[max(0, line.index - 30) : line.index + 30])
                fn_name = nested_lookup.group("fn")
                if (
                    re.search(rf"\b{re.escape(fn_name)}\s*\([^)]*\)\s*{{[^}}]*(?:{self._names_pattern(self._lock_names)})\s*\(", nearby, re.S)
                    or re.search(rf"\b{re.escape(fn_name)}\s*[:=].*(?:requires|takes|locks)", nearby, re.I)
                ):
                    emit(
                        defect_class="deadlock",
                        rule="lookup_like_call_under_held_lock",
                        line=line,
                        description=f"`{fn_name}` is called while a lock is already held and appears to acquire a lock itself.",
                        root_cause="A lookup/helper routine can recursively acquire the same lock or invert lock ownership.",
                        suggested_fix="Use a no-lock helper for locked callers, document lock ownership, or release before calling.",
                        source=f"lock at line {lock_line.number}",
                        sink=line.text.strip(),
                        confidence=0.74,
                        impact_level="high",
                        positive=[
                            f"line {lock_line.number}: lock acquired before helper call",
                            f"line {line.number}: lookup-like helper called while lock is held",
                        ],
                    )
            if self._unlock_re.search(line.text) and held_locks:
                held_locks.pop()

            if re.search(r"\b(?:access|stat|lstat|faccessat|fstatat)\s*\(", line.text) or re.search(
                r"\b[A-Za-z_]\w*(?:check|validate|verify)[A-Za-z_0-9]*(?:permission|access|path|file)[A-Za-z_0-9]*\s*\(",
                line.text,
                re.IGNORECASE,
            ):
                permission_check_line = line
            if permission_check_line and re.search(r"\b(?:open|fopen|creat)\s*\(", line.text):
                emit(
                    defect_class="toctou",
                    rule="path_check_before_open",
                    line=line,
                    description="A pathname is checked separately from a later open/use operation.",
                    root_cause="The path can change between the check and the open operation.",
                    suggested_fix="Open the file first with secure flags, then validate/use the opened descriptor.",
                    source=f"path check at line {permission_check_line.number}",
                    sink=line.text.strip(),
                    confidence=0.76,
                    positive=[
                        f"line {permission_check_line.number}: pathname check",
                        f"line {line.number}: separate pathname open/use",
                    ],
                )
                permission_check_line = None

            system_call = re.search(r"\bsystem\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", line.text)
            if system_call:
                emit(
                    defect_class="command_injection",
                    rule="system_with_constructed_command",
                    line=line,
                    description=f"`{system_call.group('arg')}` is passed to system.",
                    root_cause="Constructed command text can contain shell metacharacters or environment-derived content.",
                    suggested_fix="Avoid system; pass argv directly to execve/posix_spawn and validate each argument.",
                    source=system_call.group("arg"),
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="critical",
                    positive=[f"line {line.number}: system executes a non-literal command string"],
                )

    def _emit_borrowed_after_unlock(self, lines: List[CodeLine], return_line: CodeLine, emit) -> None:
        match = re.search(r"\breturn\s+(?P<ret>[A-Za-z_]\w+)\s*;", return_line.text)
        if not match:
            return
        ret = match.group("ret")
        previous = list(reversed(lines[max(0, return_line.index - 12) : return_line.index]))
        assigned = None
        saw_unlock = False
        for item in previous:
            if self._unlock_re.search(item.text):
                saw_unlock = True
            if re.search(rf"\b{re.escape(ret)}\s*=\s*[^;]*->[A-Za-z_]\w*", item.text):
                assigned = item
                break
        if assigned and saw_unlock:
            emit(
                defect_class="use_after_free",
                rule="borrowed_pointer_returned_after_unlock",
                line=return_line,
                description=f"Borrowed pointer `{ret}` is returned after the protecting lock is released.",
                root_cause="Concurrent mutation can free or replace the pointee after unlock and before caller use.",
                suggested_fix="Return an owned copy or keep a reference under the lock before unlocking.",
                source=f"borrowed pointer assigned at line {assigned.number}",
                sink=return_line.text.strip(),
                confidence=0.82,
                impact_level="high",
                positive=[
                    f"line {assigned.number}: borrowed pointer is read from shared object",
                    "a matching unlock appears before return",
                    f"line {return_line.number}: borrowed pointer escapes to caller",
                ],
            )

    def _rule_stale_resources(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            close = re.search(r"\bclose\s*\(\s*(?P<fd>[A-Za-z_]\w*)\s*\)\s*;", line.text)
            if close:
                later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 7])
                if (
                    not self._previous_assignment_from_open(lines, line.index, close.group("fd"))
                    and not re.search(r"(?:g_[A-Za-z_]\w*fd|fd)\s*=\s*-1", later)
                ):
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
    def _names_pattern(names: Iterable[str]) -> str:
        escaped = [
            re.escape(name).replace(r"\ ", r"\s+")
            for name in sorted({str(item) for item in names if item}, key=len, reverse=True)
        ]
        return "|".join(escaped) or r"a\bnothing_matches"

    @classmethod
    def _call_re(
        cls,
        names: Iterable[str],
        *,
        extra_patterns: Optional[Iterable[str]] = None,
    ) -> re.Pattern[str]:
        patterns = [cls._names_pattern(names)]
        patterns.extend(str(item) for item in extra_patterns or [] if item)
        return re.compile(rf"\b(?:{'|'.join(patterns)})\s*\(")

    @classmethod
    def _type_pattern(cls, names: Iterable[str]) -> str:
        return cls._names_pattern(names)

    @classmethod
    def _match_call(
        cls,
        text: str,
        names: Iterable[str],
        arg_group: str,
        *,
        until: str = ")",
    ) -> Optional[re.Match[str]]:
        terminator = r";" if until == ";" else r"\)"
        return re.search(
            rf"\b(?:{cls._names_pattern(names)})\s*\(\s*(?P<{arg_group}>[^{terminator}]+)",
            text,
        )

    def _api_evidence_for_line(self, text: str) -> List[str]:
        evidence: List[str] = []
        categories = [
            ("allocator", self.semantics.allocators),
            ("calloc", self.semantics.calloc_allocators),
            ("reallocator", self.semantics.reallocators),
            ("deallocator", self.semantics.deallocators),
            ("copy", self.semantics.copy_sinks),
            ("lock", self.semantics.lock_apis),
            ("unlock", self.semantics.unlock_apis),
        ]
        for category, mapping in categories:
            for name, sources in mapping.items():
                if re.search(rf"\b{re.escape(name)}\s*\(", text):
                    evidence.append(
                        f"`{name}` classified as {category} API via {', '.join(sources)}"
                    )
        return evidence

    def _augment_name_heuristics_from_code(self, code: str) -> None:
        changed = False
        for name in sorted(set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", code))):
            category = self._classify_api_name(name)
            if not category:
                continue
            before = set(getattr(self.semantics, self._attr_for_category(category)))
            self.semantics.add_api(category, name, "name_heuristic")
            after = set(getattr(self.semantics, self._attr_for_category(category)))
            changed = changed or before != after
        if changed:
            self._compile_patterns()

    @staticmethod
    def _classify_api_name(name: str) -> str:
        lower = name.lower()
        tokens = [token for token in re.split(r"_+", lower) if token]
        if tokens:
            last = tokens[-1]
            previous = tokens[-2] if len(tokens) > 1 else ""
            if last == "unlock":
                return "unlock"
            if last == "lock" and previous not in {"under", "with", "while"}:
                return "lock"
            if lower.startswith("unlock") or lower.startswith("lock"):
                return "unlock" if lower.startswith("unlock") else "lock"
        if "realloc" in lower:
            return "reallocator"
        if "calloc" in lower:
            return "calloc"
        if "alloc" in lower or "malloc" in lower:
            return "allocator"
        if re.search(r"(?:^|_)(?:free|dealloc)(?:_|$)", lower) or lower.endswith(("free", "dealloc")):
            return "deallocator"
        if re.search(r"(?:mem)?(?:copy|cpy|move)", lower):
            return "copy"
        return ""

    @staticmethod
    def _attr_for_category(category: str) -> str:
        return {
            "allocator": "allocators",
            "calloc": "calloc_allocators",
            "reallocator": "reallocators",
            "deallocator": "deallocators",
            "copy": "copy_sinks",
            "lock": "lock_apis",
            "unlock": "unlock_apis",
        }[category]

    def _parse_lines(self, code: str) -> List[CodeLine]:
        parsed: List[CodeLine] = []
        for idx, raw in enumerate(str(code or "").splitlines()):
            match = self._LINE_RE.match(raw)
            if match:
                number = int(match.group(1))
                text = match.group(2)
            else:
                number = idx + 1
                text = raw
            parsed.append(CodeLine(number=number, raw=raw, text=self._strip_comment(text).strip(), index=idx))
        return parsed

    @staticmethod
    def _strip_comment(text: str) -> str:
        return re.sub(r"//.*$", "", text)

    def _context(self, lines: List[CodeLine], start: int, end: int) -> str:
        return "\n".join(line.raw for line in lines[max(0, start) : min(len(lines), end)])

    def _collect_local_vars(self, lines: List[CodeLine]) -> Dict[str, CodeLine]:
        locals_seen: Dict[str, CodeLine] = {}
        for line in lines:
            if "(" in line.text and ")" in line.text and "{" in line.text:
                continue
            decl = re.search(
                r"^\s*(?:const\s+)?(?:struct\s+)?[A-Za-z_][A-Za-z_0-9]*(?:\s*\*)?\s+"
                r"(?P<var>[A-Za-z_]\w*)\s*(?:=\s*[^;]+)?;",
                line.text,
            )
            if decl and not line.text.startswith(("return", "if", "for", "while")):
                locals_seen[decl.group("var")] = line
        return locals_seen

    def _next_window_has_sink(self, lines: List[CodeLine], idx: int, var: str) -> bool:
        window = "\n".join(item.text for item in lines[idx + 1 : idx + 9])
        return bool(re.search(rf"\b{re.escape(var)}\b", window) and self._copy_or_alloc_re.search(window))

    def _has_pre_overflow_guard(self, lines: List[CodeLine], idx: int, operands: Iterable[str]) -> bool:
        operand_list = [item for item in operands if item]
        window = "\n".join(item.text for item in lines[max(0, idx - 8) : idx + 1])
        if "SIZE_MAX" not in window and "UINT_MAX" not in window:
            return False
        if "/" in window or "-" in window:
            return any(re.search(rf"\b{re.escape(op)}\b", window) for op in operand_list)
        return False

    def _has_post_wrap_check(self, lines: List[CodeLine], idx: int, var: str, operands: Iterable[str]) -> bool:
        window = "\n".join(item.text for item in lines[idx + 1 : idx + 5])
        if not window:
            return False
        return any(
            re.search(rf"\bif\s*\([^)]*\b{re.escape(var)}\s*<\s*{re.escape(op)}\b", window)
            for op in operands
            if op
        )

    def _is_high_risk_size_expr(self, expr: str, params: Iterable[str]) -> bool:
        identifiers = [item for item in self._IDENT_RE.findall(expr) if item not in {"sizeof", "SIZE_MAX", "UINT_MAX"}]
        if "*" in expr:
            return bool(identifiers)
        param_set = set(params)
        if any(item in param_set for item in identifiers):
            return True
        return any(
            (
                re.search(r"(payload|packet|max|field|count|size|data|cmd|total)", item)
                or (item.endswith("_len") and not item.startswith("key_"))
            )
            for item in identifiers
        )

    def _function_params(self, lines: List[CodeLine]) -> set[str]:
        if not lines:
            return set()
        signature = lines[0].text
        match = re.search(r"\((?P<params>.*)\)", signature)
        if not match:
            return set()
        params: set[str] = set()
        for part in match.group("params").split(","):
            part = part.strip()
            if not part or part == "void":
                continue
            name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?$", part.replace("*", " "))
            if name_match:
                params.add(name_match.group(1))
        return params

    @staticmethod
    def _is_macro_size_expr(expr: str) -> bool:
        text = str(expr or "").strip()
        return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", text))

    @staticmethod
    def _previous_assignment_from_open(lines: List[CodeLine], idx: int, fd: str) -> bool:
        previous = "\n".join(item.text for item in lines[max(0, idx - 12) : idx])
        return bool(re.search(rf"\b{re.escape(fd)}\s*=\s*(?:open|socket|accept|accept4)\s*\(", previous))

    def _pointer_owner_vars(self, lines: List[CodeLine]) -> set[str]:
        owners: set[str] = set()
        alloc_names = self._allocator_names | self._calloc_names | self._reallocator_names
        for line in lines:
            pointer_decl = re.search(
                r"(?:^|[;{]\s*)(?:const\s+)?(?:struct\s+)?[A-Za-z_]\w*(?:\s*\*)+\s*"
                r"(?P<var>[A-Za-z_]\w*)\b",
                line.text,
            )
            if pointer_decl:
                owners.add(pointer_decl.group("var"))
            alloc_assign = re.search(
                rf"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                rf"(?:{self._names_pattern(alloc_names)})\s*\(",
                line.text,
            )
            if alloc_assign:
                owners.add(alloc_assign.group("var"))
        return owners

    def _guard_evidence(self, lines: List[CodeLine], idx: int, operands: Iterable[str]) -> List[str]:
        if self._has_pre_overflow_guard(lines, idx, operands):
            return ["nearby SIZE_MAX/UINT_MAX precondition may guard this arithmetic; validator must prove it"]
        return []

    @staticmethod
    def _previous_nonempty(lines: List[CodeLine], idx: int, limit: int) -> List[CodeLine]:
        result: List[CodeLine] = []
        for item in reversed(lines[max(0, idx - limit) : idx]):
            if item.text:
                result.append(item)
        return result

    @staticmethod
    def _candidate_id(func_name: str, file_path: str, defect_class: str, line: int, sink: str) -> str:
        digest = hashlib.sha1(
            f"{file_path}:{func_name}:{defect_class}:{line}:{sink}".encode("utf-8")
        ).hexdigest()[:10]
        prefix = re.sub(r"[^A-Za-z0-9]+", "_", defect_class).upper()
        return f"RULE_{prefix}_{line}_{digest}"

    @staticmethod
    def _line_from_location(location: str) -> int:
        match = re.search(r":(\d+)(?::|$)", location)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _normalize_sink_key(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip().lower())[:120]

    @staticmethod
    def _priority_for_issue(issue: Dict[str, Any]) -> int:
        confidence = issue.get("rule_confidence", issue.get("confidence", 0.5))
        try:
            score = float(confidence)
        except (TypeError, ValueError):
            score = 0.5
        severity = str(issue.get("impact_level") or "").lower()
        bonus = {"critical": 18, "high": 12, "medium": 6, "low": 0}.get(severity, 3)
        return max(1, min(100, int(score * 80) + bonus))
