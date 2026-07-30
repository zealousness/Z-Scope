"""Heuristic planning for context-clean focused subagent tickets."""

from __future__ import annotations

import re
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..agents.deep_worker.agent import DeepWorkerAgent
from ..common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from ..tools.policy import ToolPolicy
from ..framework.llm_client import LLMClient
from .scheduler import INVESTIGATOR_ROLE, ScanScheduler
from .specs import SpecRegistry


DEFAULT_SUBAGENT_SPAWN_ALLOWLIST = ("deep_worker",)


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
    origin: str = ""
    sink: str = ""
    resource_kind: str = ""
    source: str = "source_rule"
    sources: List[str] = field(default_factory=list)
    call_paths: List[List[str]] = field(default_factory=list)
    dedup_key: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

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
            "origin": self.origin,
            "sink": self.sink,
            "resource_kind": self.resource_kind,
            "source": self.source,
            "sources": self.sources or ([self.source] if self.source else []),
            "call_paths": self.call_paths or [],
            "dedup_key": self.dedup_key,
            "evidence": self.evidence or {},
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

    def __init__(
        self,
        spec_registry: SpecRegistry,
        tools: List[Any],
        *,
        scheduler: Optional[ScanScheduler] = None,
    ):
        self.spec_registry = spec_registry
        self.tools = tools
        self.scheduler = scheduler

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
                    origin=f"{func_name}:{line_no}:{match.group(0)}",
                    sink=f"{func_name}:{line_no}:{match.group(0)}",
                    resource_kind=self._resource_kind_for_trigger(skill, match.group(0)),
                    source="source_rule",
                    evidence={
                        "function": func_name,
                        "line": line_no,
                        "matched_text": clean.strip(),
                    },
                )
                tickets.append(ticket)
        return tickets

    def plan_snapshot_candidates(
        self,
        func_name: str,
        snapshot: Dict[str, Any],
        allowed_skills: Optional[List[str]] = None,
    ) -> List[SubAgentTicket]:
        """Create focused tickets from semantic snapshot suspicious points."""
        if not isinstance(snapshot, dict):
            return []

        allowed = set(allowed_skills) if allowed_skills is not None else None
        tickets: List[SubAgentTicket] = []
        for idx, point in enumerate(snapshot.get("suspicious_points") or []):
            if not isinstance(point, dict):
                continue
            skill = self._skill_from_suspicious_point(point)
            if allowed is not None and skill not in allowed:
                continue

            line_no = self._extract_snapshot_line(point, fallback=idx + 1)
            trigger = str(point.get("type") or point.get("trigger") or "snapshot_suspicious_point")
            confidence = self._confidence_to_score(point.get("confidence"))
            location = str(point.get("location") or f"{func_name}:{line_no}")
            context_slice = (
                "/* Semantic snapshot candidate. Use tools for concrete source lines if needed. */\n"
                f"Function: {func_name}\n"
                f"Snapshot summary: {snapshot.get('summary', '')}\n"
                f"Suspicious point: {point}\n"
                f"Key semantics: {snapshot.get('semantic_fingerprint') or snapshot.get('key_semantics') or ''}"
            )
            ticket = SubAgentTicket(
                id=f"{func_name}:{skill}:snapshot:{line_no}:{idx}",
                skill=skill,
                task=(
                    "Verify this suspicious point from the semantic snapshot. "
                    "Confirm or reject it with concrete source evidence and path constraints."
                ),
                trigger=trigger,
                line=line_no,
                context_slice=context_slice,
                priority_score=confidence,
                priority_reasons=["semantic_snapshot_suspicious_point"],
                origin=f"{func_name}:{line_no}:{trigger}",
                sink=f"{func_name}:{line_no}:{trigger}",
                resource_kind=self._resource_kind_for_trigger(
                    skill,
                    f"{trigger} {point.get('description', '')} {point.get('reason', '')}",
                ),
                source="semantic_snapshot",
                evidence={
                    "function": func_name,
                    "location": location,
                    "snapshot_summary": snapshot.get("summary", ""),
                    "suspicious_point": point,
                },
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
        tool_policy: Optional[ToolPolicy] = None,
        max_workers: int = 1,
        ticket_timeout: Optional[float] = 300.0,
        budget_exhaustion_policy: str = "observe",
        agent_type: str = "deep_worker",
        spawn_allowlist: Optional[List[str]] = None,
        nested_spawn_allowed: bool = False,
        llm_client_resolver: Optional[Callable[[SubAgentTicket], LLMClient]] = None,
        execution_policy_resolver: Optional[Callable[[SubAgentTicket], Dict[str, Any]]] = None,
        worktree_isolation: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if not tickets:
            return []
        allowed_agents = set(spawn_allowlist or DEFAULT_SUBAGENT_SPAWN_ALLOWLIST)
        if agent_type not in allowed_agents:
            return [
                self._spawn_denied_report(
                    ticket,
                    agent_type=agent_type,
                    spawn_allowlist=sorted(allowed_agents),
                )
                for ticket in tickets
            ]
        workers = max(1, min(int(max_workers or 1), len(tickets)))
        # Budget thresholds are telemetry only.  Parent/user cancellation
        # remains authoritative, but a local ticket budget never kills work.
        budget_policy = "observe"
        parent_token = current_cancellation_token()
        if (
            self.scheduler is None
            and workers == 1
            and not (ticket_timeout and ticket_timeout > 0)
        ):
            return [
                self._run_one_ticket(
                    llm_client,
                    ticket,
                    max_iterations=max_iterations,
                    tool_policy=tool_policy,
                    worker_index=0,
                    agent_type=agent_type,
                    nested_spawn_allowed=nested_spawn_allowed,
                    llm_client_resolver=llm_client_resolver,
                    execution_policy_resolver=execution_policy_resolver,
                    worktree_isolation=worktree_isolation,
                    parent_token=parent_token,
                    ticket_timeout=ticket_timeout,
                    budget_exhaustion_policy=budget_policy,
                )
                for ticket in tickets
            ]

        reports_by_id: Dict[str, Dict[str, Any]] = {}
        futures: Dict[Future[Any], tuple[SubAgentTicket, int]] = {}
        started_at = time.perf_counter()
        detached_futures = False
        executor: Optional[ThreadPoolExecutor] = None
        if self.scheduler is None:
            executor = ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="zscope-deep-worker",
            )
        try:
            for idx, ticket in enumerate(tickets):
                worker_index = idx % workers
                submitter = (
                    self.scheduler.submit
                    if self.scheduler is not None
                    else executor.submit
                )
                submit_args = (
                    (INVESTIGATOR_ROLE, self._run_one_ticket, llm_client, ticket)
                    if self.scheduler is not None
                    else (self._run_one_ticket, llm_client, ticket)
                )
                future = submitter(
                    *submit_args,
                    max_iterations=max_iterations,
                    tool_policy=tool_policy,
                    worker_index=worker_index,
                    agent_type=agent_type,
                    nested_spawn_allowed=nested_spawn_allowed,
                    llm_client_resolver=llm_client_resolver,
                    execution_policy_resolver=execution_policy_resolver,
                    worktree_isolation=worktree_isolation,
                    parent_token=parent_token,
                    ticket_timeout=ticket_timeout,
                    budget_exhaustion_policy=budget_policy,
                    **(
                        {"priority": int(ticket.priority_score or 0)}
                        if self.scheduler is not None
                        else {}
                    ),
                )
                futures[future] = (ticket, worker_index)

            pending = set(futures)
            try:
                while pending:
                    if parent_token is not None:
                        parent_token.raise_if_cancelled()
                    wait_timeout = self._batch_poll_timeout(
                        parent_token=parent_token,
                    )
                    completed, _ = wait(
                        pending,
                        timeout=wait_timeout,
                        return_when=FIRST_COMPLETED,
                    )
                    for future in completed:
                        pending.discard(future)
                        ticket, _worker_index = futures[future]
                        try:
                            reports_by_id[ticket.id] = future.result()
                        except CancellationError:
                            if parent_token is not None and parent_token.is_cancelled():
                                raise
                            reports_by_id[ticket.id] = self._exception_report(
                                ticket,
                                CancellationError("subagent_cancelled"),
                                agent_type=agent_type,
                                worker_index=_worker_index,
                                max_iterations=max_iterations,
                                execution_policy=self._execution_policy_for_ticket(
                                    ticket,
                                    execution_policy_resolver,
                                ),
                                worktree_isolation=worktree_isolation,
                            )
                        except Exception as exc:
                            reports_by_id[ticket.id] = self._exception_report(
                                ticket,
                                exc,
                                agent_type=agent_type,
                                worker_index=_worker_index,
                                max_iterations=max_iterations,
                                execution_policy=self._execution_policy_for_ticket(
                                    ticket,
                                    execution_policy_resolver,
                                ),
                                worktree_isolation=worktree_isolation,
                            )

            except CancellationError:
                detached_futures = True
                for future in pending:
                    future.cancel()
                raise
        finally:
            if executor is not None:
                executor.shutdown(
                    wait=not detached_futures,
                    cancel_futures=detached_futures,
                )

        for ticket in tickets:
            if ticket.id not in reports_by_id:
                reports_by_id[ticket.id] = self._exception_report(
                    ticket,
                    RuntimeError("subagent completed without a result"),
                    elapsed_ms=(time.perf_counter() - started_at) * 1000,
                    agent_type=agent_type,
                    max_iterations=max_iterations,
                    execution_policy=self._execution_policy_for_ticket(
                        ticket,
                        execution_policy_resolver,
                    ),
                    worktree_isolation=worktree_isolation,
                )
        return [reports_by_id[ticket.id] for ticket in tickets]

    def _run_one_ticket(
        self,
        llm_client: LLMClient,
        ticket: SubAgentTicket,
        *,
        max_iterations: int,
        tool_policy: Optional[ToolPolicy],
        worker_index: int,
        agent_type: str = "deep_worker",
        nested_spawn_allowed: bool = False,
        llm_client_resolver: Optional[Callable[[SubAgentTicket], LLMClient]] = None,
        execution_policy_resolver: Optional[Callable[[SubAgentTicket], Dict[str, Any]]] = None,
        worktree_isolation: Optional[Dict[str, Any]] = None,
        parent_token: Optional[CancellationToken] = None,
        ticket_timeout: Optional[float] = 300.0,
        budget_exhaustion_policy: str = "observe",
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        selected_llm_client = (
            llm_client_resolver(ticket) if llm_client_resolver is not None else llm_client
        )
        execution_policy = self._execution_policy_for_ticket(ticket, execution_policy_resolver)
        if "model" not in execution_policy:
            model = getattr(selected_llm_client, "models", []) or []
            if model:
                execution_policy["model"] = str(model[0])
        isolation = dict(worktree_isolation or {"mode": "read_only", "snapshot_writes": False})
        budget_policy = "observe"
        worker = DeepWorkerAgent(selected_llm_client, self.tools, tool_policy=tool_policy)
        skill = self.spec_registry.get_skill(ticket.skill)
        agent = self.spec_registry.get_agent(agent_type)
        visible_tool_names = [
            str(tool.name)
            for tool in self.tools
            if tool_policy is None or tool_policy.is_tool_visible(str(tool.name))
        ]
        input_data = {
            "ticket": ticket.to_dict(),
            "context_slice": ticket.context_slice,
            "agent_contract": agent.to_prompt_block(allowed_tools=visible_tool_names) if agent else "",
            "skill_contract": skill.to_prompt_block(
                allowed_tools=visible_tool_names,
                allowed_mcp_tools=[],
                allowed_mcp_resources=[],
            ) if skill else "",
            "max_iterations": max_iterations,
            "agent_type": agent_type,
            "nested_spawn_allowed": nested_spawn_allowed,
            "execution_policy": execution_policy,
            "worktree_isolation": isolation,
        }
        try:
            ticket_token = (
                parent_token.child(
                    timeout_seconds=None
                )
                if parent_token is not None
                else CancellationToken(
                    timeout_seconds=None
                )
            )
            with bind_cancellation_token(ticket_token):
                ticket_token.raise_if_cancelled()
                response = worker.run(input_data)
                ticket_token.raise_if_cancelled()
            status = self._report_status(response)
            metadata = dict(response.metadata or {})
            duration_seconds = max(0.0, time.perf_counter() - started)
            metadata.update(
                {
                    "ticket_id": ticket.id,
                    "worker_index": worker_index,
                    "duration_ms": duration_seconds * 1000,
                    "max_iterations": max_iterations,
                    "max_turns": max_iterations,
                    "stop_reason": status,
                    "agent_type": agent_type,
                    "spawn_allowed": True,
                    "nested_spawn_allowed": nested_spawn_allowed,
                    "subagent_can_spawn": False,
                    "ticket_skill": ticket.skill,
                    "ticket_priority_score": ticket.priority_score,
                    "ticket_source": ticket.source,
                    "ticket_sources": ticket.sources or ([ticket.source] if ticket.source else []),
                    "execution_policy": execution_policy,
                    "worktree_isolation": isolation,
                    "needs_human_review": self._needs_human_review(response, status),
                }
            )
            metadata.update(
                self._ticket_budget_metadata(
                    duration_seconds,
                    ticket_timeout,
                    budget_policy,
                )
            )
            return {
                "ticket": ticket.to_dict(),
                "status": status,
                "success": status == "completed",
                "data": response.data,
                "error": response.error,
                "metadata": metadata,
            }
        except CancellationError:
            if parent_token is not None and parent_token.is_cancelled():
                raise
            report = self._exception_report(
                ticket,
                CancellationError("subagent_cancelled"),
                elapsed_ms=(time.perf_counter() - started) * 1000,
                agent_type=agent_type,
                worker_index=worker_index,
                max_iterations=max_iterations,
                execution_policy=execution_policy,
                worktree_isolation=isolation,
            )
            report["metadata"].update(
                self._ticket_budget_metadata(
                    max(0.0, time.perf_counter() - started),
                    ticket_timeout,
                    budget_policy,
                )
            )
            return report
        except Exception as exc:
            report = self._exception_report(
                ticket,
                exc,
                worker_index=worker_index,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                agent_type=agent_type,
                max_iterations=max_iterations,
                execution_policy=execution_policy,
                worktree_isolation=isolation,
            )
            report["metadata"].update(
                self._ticket_budget_metadata(
                    max(0.0, time.perf_counter() - started),
                    ticket_timeout,
                    budget_policy,
                )
            )
            return report
        finally:
            self._close_thread_llm_sessions(llm_client, selected_llm_client)

    @staticmethod
    def _batch_poll_timeout(
        *,
        parent_token: Optional[CancellationToken],
    ) -> Optional[float]:
        """Poll only when parent cancellation must remain responsive."""

        if parent_token is None:
            return None

        poll_seconds = 0.05
        parent_remaining = parent_token.remaining_seconds()
        if parent_remaining is not None:
            poll_seconds = min(poll_seconds, max(0.0, parent_remaining))
        return poll_seconds

    @staticmethod
    def _ticket_budget_metadata(
        duration_seconds: float,
        ticket_budget_seconds: Optional[float],
        policy: str,
    ) -> Dict[str, Any]:
        try:
            budget = (
                float(ticket_budget_seconds)
                if ticket_budget_seconds is not None
                else None
            )
        except (TypeError, ValueError):
            budget = None
        if budget is not None and budget <= 0:
            budget = None
        duration = max(0.0, float(duration_seconds or 0.0))
        exceeded = budget is not None and duration > budget
        overrun = max(0.0, duration - budget) if budget is not None else 0.0
        return {
            "ticket_budget_seconds": budget,
            "ticket_budget_exceeded": exceeded,
            "ticket_budget_overrun_seconds": round(overrun, 4),
            "budget_exhaustion_policy": str(policy or "observe"),
        }

    @staticmethod
    def _close_thread_llm_sessions(*clients: LLMClient) -> None:
        seen: set[int] = set()
        for client in clients:
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_thread_session = getattr(client, "close_thread_session", None)
            if callable(close_thread_session):
                close_thread_session()

    @staticmethod
    def _exception_report(
        ticket: SubAgentTicket,
        exc: Exception,
        *,
        agent_type: str = "deep_worker",
        worker_index: int = -1,
        elapsed_ms: float = 0.0,
        max_iterations: int = 0,
        execution_policy: Optional[Dict[str, Any]] = None,
        worktree_isolation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "ticket": ticket.to_dict(),
            "status": "failed",
            "success": False,
            "data": {},
            "error": str(exc),
            "metadata": {
                "ticket_id": ticket.id,
                "worker_index": worker_index,
                "duration_ms": elapsed_ms,
                "failure_kind": "exception",
                "stop_reason": "failed",
                "agent_type": agent_type,
                "max_iterations": max_iterations,
                "max_turns": max_iterations,
                "execution_policy": dict(execution_policy or {}),
                "worktree_isolation": dict(worktree_isolation or {}),
                "needs_human_review": True,
            },
        }

    @staticmethod
    def _spawn_denied_report(
        ticket: SubAgentTicket,
        *,
        agent_type: str,
        spawn_allowlist: List[str],
    ) -> Dict[str, Any]:
        return {
            "ticket": ticket.to_dict(),
            "status": "failed",
            "success": False,
            "data": {},
            "error": f"Subagent type {agent_type!r} is not in spawn allowlist.",
            "metadata": {
                "ticket_id": ticket.id,
                "agent_type": agent_type,
                "spawn_allowlist": spawn_allowlist,
                "failure_kind": "spawn_denied",
                "stop_reason": "spawn_denied",
                "needs_human_review": True,
            },
        }

    @staticmethod
    def _execution_policy_for_ticket(
        ticket: SubAgentTicket,
        execution_policy_resolver: Optional[Callable[[SubAgentTicket], Dict[str, Any]]],
    ) -> Dict[str, Any]:
        if execution_policy_resolver is None:
            return {}
        policy = execution_policy_resolver(ticket)
        return dict(policy or {})

    @staticmethod
    def _needs_human_review(response: Any, status: str) -> bool:
        if status != "completed":
            return True
        data = response.data if hasattr(response, "data") else {}
        if isinstance(data, dict) and data.get("needs_human_review"):
            return True
        metadata = response.metadata if hasattr(response, "metadata") else {}
        return bool(isinstance(metadata, dict) and metadata.get("needs_human_review"))

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
    def _skill_from_suspicious_point(point: Dict[str, Any]) -> str:
        text = " ".join(
            str(point.get(field, ""))
            for field in ("type", "category", "subcategory", "description", "reason")
        ).lower()
        if any(word in text for word in ("overflow", "bounds", "oob", "integer", "copy", "buffer")):
            return "bounds_and_integer"
        if any(word in text for word in ("leak", "resource", "cleanup", "release", "file", "socket")):
            return "resource_lifecycle"
        if any(word in text for word in ("uaf", "use after free", "double free", "invalid free")):
            return "temporal_memory"
        if any(word in text for word in ("null", "failure", "unchecked", "error")):
            return "null_and_failure"
        if any(word in text for word in ("lock", "deadlock", "mutex")):
            return "concurrency_lock_order"
        if any(word in text for word in ("race", "shared", "thread")):
            return "shared_state_race"
        if any(word in text for word in ("stack", "escape", "async")):
            return "stack_escape"
        if any(word in text for word in ("string", "format", "strcmp", "strlen", "termination")):
            return "string_and_format"
        if any(word in text for word in ("ownership", "contract", "logic", "caller", "callee")):
            return "ownership_contract"
        return "ownership_contract"

    @staticmethod
    def _extract_snapshot_line(point: Dict[str, Any], fallback: int) -> int:
        for key in ("line", "start_line", "location"):
            value = point.get(key)
            if value is None:
                continue
            nums = re.findall(r"\d+", str(value))
            if nums:
                try:
                    return int(nums[-1])
                except ValueError:
                    continue
        return fallback

    @staticmethod
    def _confidence_to_score(value: Any) -> int:
        try:
            confidence = float(value)
            if 0 <= confidence <= 1:
                return 10 + int(confidence * 20)
            return int(confidence)
        except (TypeError, ValueError):
            return 18

    @staticmethod
    def _resource_kind_for_trigger(skill: str, trigger: str) -> str:
        text = f"{skill} {trigger}".lower()
        if any(word in text for word in ("malloc", "calloc", "realloc", "free", "memory")):
            return "memory"
        if any(word in text for word in ("open", "close", "fopen", "fclose", "socket", "file")):
            return "handle"
        if any(word in text for word in ("lock", "mutex", "rwlock", "spin")):
            return "lock"
        if any(word in text for word in ("string", "strcmp", "strncmp", "strlen", "format")):
            return "string"
        return "unknown"

    @staticmethod
    def _extract_line_number(line: str, fallback: int) -> int:
        match = re.match(r"^\s*(\d+)\s*\|", line)
        if not match:
            return fallback
        try:
            return int(match.group(1))
        except ValueError:
            return fallback
