"""Heuristic planning for context-clean focused subagent tickets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..agents.deep_worker.agent import DeepWorkerAgent
from ..framework.llm_client import LLMClient
from .specs import SpecRegistry


@dataclass
class SubAgentTicket:
    id: str
    skill: str
    task: str
    trigger: str
    line: int
    context_slice: str
    priority_score: int = 0
    priority_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "skill": self.skill,
            "task": self.task,
            "trigger": self.trigger,
            "line": self.line,
            "context_slice": self.context_slice,
            "priority_score": self.priority_score,
            "priority_reasons": self.priority_reasons or [],
        }


class SubAgentOrchestrator:
    """Creates and optionally executes narrow deep-worker investigations."""

    RULES = [
        (
            "resource_lifecycle",
            re.compile(r"\b(malloc|calloc|realloc|strdup|open|fopen|socket|shm_open)\s*\("),
            "Trace acquired memory/file/socket/shared-memory resources across normal and error paths. "
            "Check leak, double release, early release, ownership transfer, and UAF.",
        ),
        (
            "temporal_memory",
            re.compile(r"\b(free|realloc|close|fclose|munmap)\s*\("),
            "Trace lifetime around this release operation. Check subsequent uses, duplicate releases, "
            "alias releases, and error-path ordering.",
        ),
        (
            "bounds_and_integer",
            re.compile(r"\b(memcpy|memmove|strcpy|strncpy|strcat|sprintf|snprintf|read|recv|fread)\s*\("),
            "Audit buffer bounds and integer/size conversions feeding this copy or IO operation.",
        ),
        (
            "string_and_format",
            re.compile(
                r"\b(strlen|strcmp|strncmp|strcasecmp|strncasecmp|strchr|strstr|sscanf|"
                r"strcpy|strncpy|strcat|strncat|sprintf|snprintf|printf|fprintf|syslog)\s*\("
            ),
            "Audit string termination, bounded string comparison/copy semantics, parsing, "
            "and format-string control for this string operation.",
        ),
        (
            "null_and_failure",
            re.compile(
                r"\b(if\s*\([^;\n]*(?:NULL|nullptr|!\s*[A-Za-z_][A-Za-z0-9_]*|==\s*-?1|<\s*0)"
                r"[^;\n]*\)|goto\s+(?:err|error|fail|failed|cleanup)\b|return\s+(?:NULL|nullptr|-?1|[A-Z_]*ERR[A-Z0-9_]*))"
            ),
            "Audit failure/null handling at this branch or return. Check whether all acquired "
            "resources and caller-visible outputs stay consistent on the error path.",
        ),
        (
            "ownership_contract",
            re.compile(
                r"\b(return\s+(?:0|-?1|true|false|TRUE|FALSE|[A-Z_][A-Z0-9_]*)\s*;|"
                r"if\s*\([^;\n]*(?:==|!=|&&|\|\|)[^;\n]*\))"
            ),
            "Audit API/ownership contract consistency around this branch or return. Check whether "
            "the callee/caller obligations and success/error semantics are preserved.",
        ),
        (
            "concurrency_lock_order",
            re.compile(r"\b(pthread_mutex_lock|pthread_rwlock_wrlock|pthread_rwlock_rdlock|mtx_lock|spin_lock)\s*\("),
            "Audit lock acquisition and release balance, lock order, and early returns while locked.",
        ),
        (
            "shared_state_race",
            re.compile(r"\b(pthread_create|thrd_create|CreateThread|_beginthreadex|clone)\s*\("),
            "Audit thread entry handoff, stack argument lifetime, shared state protection, and join/detach cleanup.",
        ),
        (
            "stack_escape",
            re.compile(r"\breturn\s+&|pthread_create\s*\([^;]*&\w+"),
            "Audit whether stack addresses escape to callers or asynchronous threads.",
        ),
    ]

    def __init__(self, spec_registry: SpecRegistry, tools: List[Any]):
        self.spec_registry = spec_registry
        self.tools = tools

    def plan(
        self,
        func_name: str,
        code: str,
        max_tickets: int = 4,
        allowed_skills: Optional[List[str]] = None,
    ) -> List[SubAgentTicket]:
        candidates = self.plan_candidates(func_name, code, allowed_skills=allowed_skills)
        return self.select_tickets(candidates, max_tickets)

    def plan_candidates(
        self,
        func_name: str,
        code: str,
        allowed_skills: Optional[List[str]] = None,
    ) -> List[SubAgentTicket]:
        lines = code.splitlines()
        tickets: List[SubAgentTicket] = []
        seen = set()
        allowed = set(allowed_skills) if allowed_skills is not None else None
        for idx, line in enumerate(lines):
            clean = re.sub(r"^\s*(\d+)\s*\|\s*", "", line)
            line_no = self._extract_line_number(line, idx + 1)
            for skill, pattern, task in self.RULES:
                if allowed is not None and skill not in allowed:
                    continue
                match = pattern.search(clean)
                if not match:
                    continue
                key = (skill, line_no, match.group(0))
                if key in seen:
                    continue
                seen.add(key)
                start = max(0, idx - 12)
                end = min(len(lines), idx + 18)
                context_slice = "\n".join(lines[start:end])
                score, reasons = self._score_candidate(skill, clean, context_slice, match.group(0))
                ticket = SubAgentTicket(
                    id=f"{func_name}:{skill}:{line_no}",
                    skill=skill,
                    task=task,
                    trigger=match.group(0),
                    line=line_no,
                    context_slice=context_slice,
                    priority_score=score,
                    priority_reasons=reasons,
                )
                tickets.append(ticket)
        return tickets

    @staticmethod
    def select_tickets(candidates: List[SubAgentTicket], max_tickets: int) -> List[SubAgentTicket]:
        if max_tickets <= 0:
            return []
        return sorted(candidates, key=lambda t: (-t.priority_score, t.line, t.skill))[:max_tickets]

    @staticmethod
    def unassigned_candidates(
        candidates: List[SubAgentTicket],
        selected: List[SubAgentTicket],
    ) -> List[SubAgentTicket]:
        selected_ids = {ticket.id for ticket in selected}
        return [ticket for ticket in candidates if ticket.id not in selected_ids]

    def run_tickets(
        self,
        llm_client: LLMClient,
        tickets: List[SubAgentTicket],
        max_iterations: int = 20,
    ) -> List[Dict[str, Any]]:
        worker = DeepWorkerAgent(llm_client, self.tools)
        reports: List[Dict[str, Any]] = []
        for ticket in tickets:
            skill = self.spec_registry.get_skill(ticket.skill)
            input_data = {
                "ticket": ticket.to_dict(),
                "context_slice": ticket.context_slice,
                "skill_contract": skill.to_prompt_block() if skill else "",
                "max_iterations": max_iterations,
            }
            response = worker.run(input_data)
            status = self._report_status(response)
            reports.append(
                {
                    "ticket": ticket.to_dict(),
                    "status": status,
                    "success": status == "completed",
                    "data": response.data,
                    "error": response.error,
                    "metadata": response.metadata,
                }
            )
        return reports

    @staticmethod
    def summarize_reports(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts = {
            "completed": 0,
            "failed": 0,
            "invalid": 0,
            "partial": 0,
            "killed": 0,
        }
        for report in reports:
            status = str(report.get("status") or "failed")
            if status not in counts:
                status = "failed"
            counts[status] += 1
        return counts

    @staticmethod
    def _report_status(response: Any) -> str:
        if response.success:
            return "completed"
        metadata = response.metadata or {}
        failure_kind = metadata.get("failure_kind")
        if failure_kind == "invalid_report":
            return "invalid"
        if failure_kind == "partial":
            return "partial"
        if failure_kind == "aborted":
            return "killed"
        return "failed"

    @staticmethod
    def _score_candidate(
        skill: str,
        line: str,
        context_slice: str,
        trigger: str,
    ) -> tuple[int, List[str]]:
        text = f"{line}\n{context_slice}".lower()
        score = 10
        reasons: List[str] = []

        risk_patterns = [
            (r"\bgoto\b|\berr(or)?\b|\bfail(ed|ure)?\b|cleanup", 8, "error_or_cleanup_path"),
            (r"\breturn\b", 6, "near_early_return"),
            (r"\bfor\s*\(|\bwhile\s*\(", 5, "loop_context"),
            (r"->|\.", 4, "object_or_struct_state"),
            (r"\bglobal\b|\bstatic\b", 4, "shared_or_static_state"),
            (r"\brealloc\s*\(", 5, "realloc_semantics"),
            (r"\bpthread|\bthread|\block|\bmutex", 5, "concurrency_context"),
            (r"\bmemcpy|\bstrcpy|\bread|\brecv", 4, "copy_or_input_context"),
            (r"\bstrcmp|\bstrncmp|\bstrlen|\bstrstr|\bsscanf|\bprintf", 5, "string_api_context"),
            (r"\bnull\b|!\s*[a-z_][a-z0-9_]*|\bgoto\s+(err|fail|cleanup)", 5, "failure_path_context"),
            (r"\breturn\s+(0|-?1|true|false|[A-Z_][A-Z0-9_]*)\s*;", 3, "contract_return_context"),
        ]
        for pattern, weight, reason in risk_patterns:
            if re.search(pattern, text):
                score += weight
                reasons.append(reason)

        if skill in {"resource_lifecycle", "temporal_memory"}:
            score += 3
            reasons.append("lifetime_sensitive_skill")
        if trigger.startswith("realloc"):
            score += 4
            reasons.append("realloc_trigger")
        if skill == "string_and_format":
            score += 4
            reasons.append("string_semantics_skill")
        if skill == "ownership_contract":
            score += 2
            reasons.append("contract_semantics_skill")

        return score, reasons or ["source_order_tiebreaker"]

    @staticmethod
    def _extract_line_number(line: str, fallback: int) -> int:
        match = re.match(r"^\s*(\d+)\s*\|", line)
        if not match:
            return fallback
        try:
            return int(match.group(1))
        except ValueError:
            return fallback
