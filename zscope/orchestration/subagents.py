"""Heuristic planning for context-clean focused subagent tickets."""

from __future__ import annotations

import re
from dataclasses import dataclass
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "skill": self.skill,
            "task": self.task,
            "trigger": self.trigger,
            "line": self.line,
            "context_slice": self.context_slice,
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
                ticket = SubAgentTicket(
                    id=f"{func_name}:{skill}:{line_no}",
                    skill=skill,
                    task=task,
                    trigger=match.group(0),
                    line=line_no,
                    context_slice="\n".join(lines[start:end]),
                )
                tickets.append(ticket)
                if len(tickets) >= max_tickets:
                    return tickets
        return tickets

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
            reports.append(
                {
                    "ticket": ticket.to_dict(),
                    "success": response.success,
                    "data": response.data,
                    "error": response.error,
                    "metadata": response.metadata,
                }
            )
        return reports

    @staticmethod
    def _extract_line_number(line: str, fallback: int) -> int:
        match = re.match(r"^\s*(\d+)\s*\|", line)
        if not match:
            return fallback
        try:
            return int(match.group(1))
        except ValueError:
            return fallback
