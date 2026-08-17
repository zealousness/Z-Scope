"""Regex/local-pattern C memory/concurrency candidate generation.

These rules are intentionally conservative enough to produce evidence-backed
review candidates, not final findings. The validator decides whether a
candidate is verified, rejected, or only an audit observation.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

from ...semantics.models import LocalPatternSemantics, attr_for_category, classify_api_name
from .cpp_domains.models import CodeLine
from .cpp_domains.resource_lifecycle import RegexResourceLifecycleRules
from .cpp_domains.memory_bounds_integer import RegexMemoryBoundsIntegerRules
from .cpp_domains.concurrency_shared_state import RegexConcurrencySharedStateRules
from .cpp_domains.protocol_ownership_logic import RegexProtocolOwnershipLogicRules

from .cpp_domains import (
    RegexRuleContext,
    resolve_emitter_descriptor,
    resolve_rule_descriptor,
    run_detector_plan,
)

if TYPE_CHECKING:
    from ...orchestration.candidates import CandidateTicket


def default_local_semantics() -> LocalPatternSemantics:
    """Load packaged default API roles without creating an import cycle at module load."""

    from ...semantics.defaults import default_local_pattern_semantics

    return default_local_pattern_semantics()


class RegexCandidateGenerator(
    RegexResourceLifecycleRules,
    RegexMemoryBoundsIntegerRules,
    RegexConcurrencySharedStateRules,
    RegexProtocolOwnershipLogicRules,
):
    """Generate structured candidates for high-signal C memory/concurrency bugs."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
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

    def __init__(
        self,
        semantics: Optional[LocalPatternSemantics] = None,
        rule_policy: Optional[Any] = None,
    ):
        self.semantics = default_local_semantics()
        if semantics is not None:
            self.semantics.merge(semantics)
        self.rule_policy = rule_policy
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._allocator_names = set(self.semantics.allocators)
        self._calloc_names = set(self.semantics.calloc_allocators)
        self._reallocator_names = set(self.semantics.reallocators)
        self._deallocator_names = set(self.semantics.deallocators)
        self._copy_sink_names = set(self.semantics.copy_sinks)
        self._lock_names = set(self.semantics.lock_apis)
        self._unlock_names = set(self.semantics.unlock_apis)
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
        self._lock_re = self._call_re(
            self._lock_names, extra_patterns=[r"pthread_rwlock_[rw]dlock"]
        )
        self._unlock_re = self._call_re(self._unlock_names)
        self._size_type_pattern = self._type_pattern(self._size_type_names)
        self._integer_pointer_type_pattern = self._type_pattern(
            name for name in self._size_type_names if name != "char" and name != "unsigned char"
        )

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
        "busy_loop": "cpu",
        "unchecked_return": "error_status",
        "state_inconsistency": "shared_state",
        "key_truncation": "key",
        "size_limit_mismatch": "memory",
        "fd_type_mismatch": "handle",
        "protocol_mixup": "protocol",
        "protocol_validation": "protocol",
        "partial_resource_leak": "memory",
        "dynamic_array_race": "shared_state",
        "version_filtering": "protocol",
        "missing_refcount": "resource_lifecycle",
        "sigpipe_unhandled": "signal",
        "fd_encoding_mismatch": "handle",
        "semantic_mismatch": "protocol",
        "byte_order_logic": "protocol",
        "reader_state_race": "shared_state",
        "uninitialized_output": "memory",
        "file_type_validation": "file",
        "log_level_misuse": "logging",
        "logic_error": "protocol",
        "global_mode_race": "shared_state",
        "slot_race": "shared_state",
        "shared_memory_race": "shared_memory",
        "state_machine": "shared_state",
        "signal_deadlock": "signal",
        "signal_race": "signal",
        "callback_self_destroy_race": "callback_lifetime",
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
        run_detector_plan(
            "regex",
            "function",
            RegexRuleContext(generator=self, lines=lines, emit=emit),
        )

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
        rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
        descriptor = resolve_rule_descriptor(
            self.rule_policy,
            rule_id,
            defect_class=defect_class,
        )
        skill = str(
            issue.get("skill") or (descriptor.skill if descriptor else "resource_lifecycle")
        )
        evidence = dict(issue.get("evidence_pack") or {})
        evidence.setdefault("positive_evidence", issue.get("positive_evidence") or [])
        evidence.setdefault("negative_evidence", issue.get("negative_evidence") or [])
        line = self._line_from_location(str(issue.get("location") or ""))
        return CandidateTicket(
            id=str(issue.get("candidate_id") or issue.get("id")),
            skill=skill,
            task=(
                f"Verify regex/local-pattern {defect_class} candidate. Confirm concrete "
                "source, sink, path feasibility, and guard sufficiency; reject if any "
                "required proof is missing."
            ),
            trigger=str(issue.get("rule") or defect_class),
            line=line,
            context_slice=str(issue.get("code_snippet") or ""),
            priority_score=self._priority_for_issue(issue),
            priority_reasons=[
                str(issue.get("candidate_source") or "regex_local_rule"),
                defect_class,
                f"rule_confidence={issue.get('rule_confidence', issue.get('confidence', 0.5))}",
            ],
            origin=str(issue.get("source") or issue.get("location") or ""),
            sink=str(issue.get("sink") or issue.get("location") or ""),
            resource_kind=self._RESOURCE_BY_CLASS.get(defect_class, "unknown"),
            source=str(issue.get("candidate_source") or "regex_local_rule"),
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
                "candidate_source": "regex_local_rule",
                "defect_class": defect_class,
                "rule": rule,
                "rule_id": descriptor.rule_id if descriptor is not None else rule,
                "cwe": cwe,
                "skill": skill,
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
                cwe=cwe,
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
                    "finding_kind": "regex_candidate",
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
                    "code_snippet": self._context(
                        lines, line.index + context_start, line.index + context_end
                    ),
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
        cwe: str,
    ) -> str:
        """Build Chinese human-readable reasoning from regex/local-pattern evidence."""

        raw_path = evidence_pack.get("path")
        path: Dict[str, Any] = raw_path if isinstance(raw_path, dict) else {}
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
            f"Regex 本地规则 `{rule}` 在 `{func_name}` 的 `{file_path}:{line}` 命中 `{defect_class}`"
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
        return classify_api_name(name)

    @staticmethod
    def _attr_for_category(category: str) -> str:
        return attr_for_category(category)

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
            parsed.append(
                CodeLine(number=number, raw=raw, text=self._strip_comment(text).strip(), index=idx)
            )
        return parsed

    @staticmethod
    def _strip_comment(text: str) -> str:
        return re.sub(r"//.*$", "", text)

    def _context(self, lines: List[CodeLine], start: int, end: int) -> str:
        return "\n".join(line.raw for line in lines[max(0, start) : min(len(lines), end)])

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

    @staticmethod
    def _candidate_id(
        func_name: str, file_path: str, defect_class: str, line: int, sink: str
    ) -> str:
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
