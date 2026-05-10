"""
Main analyzer logic for Z-SCOPE.
Orchestrates the analysis process using LLM, CodeIndex, and SnapshotStore.
"""

import json
import logging
import time
import datetime
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, cast

from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..retrieval.code_index import CodeIndex
from .snapshot_store import SnapshotStore
from .tools_runtime import ToolsRuntime
from ..framework.llm_client import LLMClient
from ..agents.semantic_modeler.agent import SemanticModeler
from ..agents.vulnerability_analyzer.agent import VulnerabilityAnalyzer
from ..agents.validator_agent.agent import ValidatorAgent
from .report import FinalReport, Issue, ReportGenerator
from ..common.utils import validate_json_schema
from .._version import __version__
from ..orchestration.specs import SpecRegistry, WorkflowStep
from ..orchestration.subagents import SubAgentOrchestrator
from ..orchestration.skill_selection import SkillSelection, select_vulnerability_skills

logger = logging.getLogger(__name__)


# System Prompt Definitions
SYSTEM_PROMPT = """You are Z-SCOPE, an advanced static analysis engine for C/C++ projects.
Detect REAL defects: functionality bugs, reliability issues, performance bottlenecks, race conditions, resource leaks.
Do NOT report stylistic issues, naming conventions, or readability suggestions.

PROCESS:
1. Analyze the given entry function thoroughly: logic, resource management, error handling.
2. Use 'get_function_impl' or 'get_function_snapshot' tools to understand callees. Do not guess callee behavior.
3. Standard library functions (malloc, printf, etc.) need not be analyzed unless misused.
4. Depth-limited analysis: max depth 3.
5. For every function analyzed, output a 'function_snapshot' JSON (serves as cache).
6. Finally, output a 'final_report' JSON with all found issues.

OUTPUT FORMATS:
Output JSON blocks wrapped in ```json ... ``` for each phase.

[Function Snapshot] - Output after analyzing each function:

```json
{
  "type": "function_snapshot",
  "func_name": "cache_get",
  "location": "src/cache_core.c:140",
  "summary": "从缓存中查找key对应的值，复制到输出缓冲区",
  "inputs": [{"name": "handle", "type": "cache_t*", "role": "缓存句柄"}, {"name": "key", "type": "const char*", "role": "查找键"}],
  "outputs": [{"kind": "return", "type": "int", "meaning": "0成功，-1失败"}],
  "resources": {
    "allocates_memory": false,
    "frees_memory": false,
    "locks": [{"lock": "handle->mutex", "mode": "exclusive", "balanced": true}],
    "file_io": false,
    "network_io": false
  },
  "error_handling": {
    "checks_parameters": true,
    "checks_alloc_failure": false,
    "rollback_on_error": "full"
  },
  "concurrency": {
    "thread_safe": "likely_yes",
    "uses_global_state": false
  },
  "semantic_fingerprint": {
    "normalized_hash_hint": "lookup key in hash table, copy value to output buffer",
    "key_semantics": ["mutex protected", "memcpy without size check"]
  },
  "suspicious_points": [
    {
      "location": "src/cache_core.c:155",
      "type": "buffer_overflow",
      "description": "memcpy未检查目标缓冲区大小",
      "confidence": 0.85,
      "impact_category": "reliability"
    }
  ],
  "callees": ["hash_lookup", "memcpy"]
}
```

[Final Report] - Output after completing the entire analysis:

```json
{
  "type": "final_report",
  "entry_function": "cache_get",
  "overall_verdict": "issues_found",
  "issues": [
    {
      "id": "ISSUE_1",
      "function": "cache_get",
      "location": "cache_get:28",
      "code_snippet": "memcpy(value_out, node->value, node->value_size);",
      "category": "reliability",
      "subcategory": "buffer_overflow",
      "description": "memcpy未检查目标缓冲区大小，可能导致堆溢出",
      "root_cause": "开发者未将buffer_size纳入memcpy的大小限制",
      "suggested_fix": "在memcpy前添加大小检查",
      "confidence": 0.85,
      "impact_level": "high"
    }
  ],
  "notes": ["已分析3个被调用函数"]
}
```

Field rules for final_report:
- overall_verdict: one of no_issue_found, issues_found, insufficient_info
- location: "function_name:LINE_NUMBER" where LINE_NUMBER is a relative line offset within the function (starting from 1). Output ONLY digits, no text.
- code_snippet: copy the exact problematic code lines from the source, do not modify
- category: one of functionality, reliability, performance
- confidence: a decimal number between 0 and 1
- impact_level: one of low, medium, high, critical
- description, root_cause, suggested_fix: 用中文描述

[Refresh Decision] - Output when comparing old snapshot with new code:

```json
{
  "type": "snapshot_refresh_decision",
  "func_name": "cache_get",
  "refresh_needed": true,
  "reason": "memcpy调用新增了size参数检查",
  "what_changed": ["添加了buffer_size边界检查", "修改了错误返回路径"],
  "risk_if_not_refreshed": "high"
}
```

- refresh_needed: true or false
- risk_if_not_refreshed: one of low, medium, high
- reason, what_changed: 用中文描述
"""


class Analyzer:
    """
    Main analyzer class.
    """

    def __init__(self, config: ZScopeConfig, code_index: Optional[CodeIndex] = None,
                 snapshot_store: Optional[SnapshotStore] = None,
                 user_config: Optional[UserConfigStore] = None,
                 force_ignore_history: bool = False,
                 maintain_mode: bool = False):
        self.config = config
        self.code_index = code_index or CodeIndex(
            config.project.project_root,
            config.project.compile_commands_path,
            source_root=config.project.source_root,
            indexing_config=config.indexing,
            priority_functions=[config.project.entry_function] if config.project.entry_function else None,
            include_paths=config.project.include_paths,
            exclude_paths=config.project.exclude_paths,
        )
        self.snapshot_store = snapshot_store or SnapshotStore(Path(config.analysis.snapshot_dir))
        db_dir = Path(config.analysis.user_config_db) if config.analysis.user_config_db else Path(config.analysis.snapshot_dir)
        self.user_config = user_config or UserConfigStore(db_dir)
        self.llm_clients: Dict[str, LLMClient] = {}
        for name, llm_cfg in config.llms.items():
            self.llm_clients[name] = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=llm_cfg.timeout,
                max_retries=llm_cfg.max_retries,
                max_tokens=llm_cfg.max_tokens
            )
        self.report_generator = ReportGenerator(config.project.project_root)
        self.tools_runtime = ToolsRuntime(self.code_index, self.snapshot_store, self.user_config)
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        self.workflow_spec = self.spec_registry.get_workflow(config.analysis.workflow_name)
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        self.workflow_progress: List[Dict[str, Any]] = []
        self.current_workflow_step: Optional[str] = None
        
        self.analyzed_functions: Set[str] = set()
        self.issues: List[Issue] = []

    def run(self) -> Dict[str, Any]:
        """Run the selected workflow as executable orchestration steps."""
        state = self._create_workflow_state()
        if state.get("error"):
            return {"error": state["error"]}

        workflow_name = self.workflow_spec.name if self.workflow_spec else self.config.analysis.workflow_name
        logger.info(
            "Starting workflow '%s' on entry function: %s",
            workflow_name,
            state["entry_func"],
        )

        steps = self._selected_workflow_steps()
        self._execute_workflow_steps(state, steps)

        if state.get("final_report_dict"):
            return self._finalize_returned_report(state)

        if not state.get("final_report"):
            self._build_final_report(state)

        return self._persist_final_report(state)

    def _create_workflow_state(self) -> Dict[str, Any]:
        """Create mutable execution state shared by workflow steps."""
        entry_func = self.config.project.entry_function
        if not entry_func:
            return {"error": "No entry function configured"}
        self.user_config.clear_config_warnings()

        impl_result = self.code_index.get_function_impl(entry_func)
        if not impl_result:
            return {"error": "Entry function not found"}

        agent_context = {
            "func_name": entry_func,
            "code": impl_result["code"],
            "location": f"{impl_result['file']}:{impl_result['start_line']}",
        }

        user_context_parts = []
        paired_ctx = self.user_config.get_paired_functions_context()
        if paired_ctx:
            user_context_parts.append(paired_ctx)
        pointer_ctx = self.user_config.get_pointer_targets_context()
        if pointer_ctx:
            user_context_parts.append(pointer_ctx)
        intent_ctx = self.user_config.get_function_intent_context(entry_func)
        if intent_ctx:
            user_context_parts.append(intent_ctx)
        if user_context_parts:
            agent_context["user_config_context"] = "\n".join(user_context_parts)

        return {
            "entry_func": entry_func,
            "impl_result": impl_result,
            "agent_context": agent_context,
            "notes": [],
            "issues": [],
            "pending_new_issues": [],
            "verified_hist_issues": [],
            "valid_hist_issues": [],
            "user_rejected_hist_issues": [],
            "historical_report": None,
            "needs_refresh": True,
            "refresh_reason": "no_snapshot",
            "is_code_unchanged": False,
            "history_loaded": False,
            "history_reconciled": False,
            "subagent_ticket_plan": [],
            "subagent_reports": [],
            "total_context_tokens": 0,
            "any_failure": False,
            "failure_msg": "",
            "final_report": None,
            "final_report_dict": None,
        }

    def _selected_workflow_steps(self) -> List[WorkflowStep]:
        if self.workflow_spec and self.workflow_spec.steps:
            return self.workflow_spec.steps
        return [
            WorkflowStep(id="premodel_reachable_callees"),
            WorkflowStep(id="model_entry"),
            WorkflowStep(id="focused_subagent_planning"),
            WorkflowStep(id="vulnerability_mining"),
            WorkflowStep(id="validate_findings"),
            WorkflowStep(id="persist_report"),
        ]

    def _execute_workflow_steps(self, state: Dict[str, Any], steps: List[WorkflowStep]) -> None:
        for step in steps:
            self._begin_workflow_step(step)
            try:
                should_stop = self._execute_workflow_step(state, step)
                self._finish_workflow_step(step, "completed")
                if should_stop:
                    return
            except Exception as exc:
                self._finish_workflow_step(step, "failed", str(exc))
                raise

    def _execute_workflow_step(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        step_id = step.id
        if step_id in {"discover_entries", "merge_skipped_reports"}:
            logger.info("[workflow] Step '%s' is handled by the CLI layer.", step_id)
            return False
        if step_id in {"load_snapshot_state", "compare_hashes"}:
            self._load_history_state(state)
            return False
        if step_id == "reuse_unchanged":
            return self._reuse_unchanged_report(state)
        if step_id == "reconcile_changed":
            self._reconcile_changed_issues(state)
            return False
        if step_id in {"analyze_remaining", "rescan_changed"}:
            self._execute_default_scan_subworkflow(state)
            return True
        if step_id == "premodel_reachable_callees":
            self._step_premodel_reachable_callees(state)
            return False
        if step_id == "model_entry":
            self._step_model_entry(state)
            return False
        if step_id == "focused_subagent_planning":
            self._step_focused_subagent_planning(state)
            return False
        if step_id == "vulnerability_mining":
            self._step_vulnerability_mining(state)
            return False
        if step_id == "validate_findings":
            self._step_validate_findings(state)
            return False
        if step_id == "persist_report":
            self._build_final_report(state)
            return False

        logger.warning("[workflow] Unknown workflow step '%s'; skipping.", step_id)
        return False

    def _execute_default_scan_subworkflow(self, state: Dict[str, Any]) -> None:
        if not state.get("history_loaded"):
            self._load_history_state(state)
        if not state.get("history_reconciled"):
            self._reconcile_changed_issues(state)

        substeps = [
            WorkflowStep(id="premodel_reachable_callees"),
            WorkflowStep(id="model_entry"),
            WorkflowStep(id="focused_subagent_planning"),
            WorkflowStep(id="vulnerability_mining"),
            WorkflowStep(id="validate_findings"),
            WorkflowStep(id="persist_report"),
        ]
        self._execute_workflow_steps(state, substeps)

    def _begin_workflow_step(self, step: WorkflowStep) -> None:
        self.current_workflow_step = step.id
        record = {
            "index": len(self.workflow_progress) + 1,
            "id": step.id,
            "agent": step.agent,
            "action": step.action,
            "status": "running",
            "started_at": datetime.datetime.now().isoformat(),
        }
        self.workflow_progress.append(record)
        workflow_name = self.workflow_spec.name if self.workflow_spec else self.config.analysis.workflow_name
        logger.info(
            "[workflow:%s] step %d start: %s%s",
            workflow_name,
            record["index"],
            step.id,
            f" ({step.action})" if step.action else "",
        )

    def _finish_workflow_step(self, step: WorkflowStep, status: str, error: str = "") -> None:
        for record in reversed(self.workflow_progress):
            if record["id"] == step.id and record["status"] == "running":
                record["status"] = status
                record["finished_at"] = datetime.datetime.now().isoformat()
                if error:
                    record["error"] = error
                break
        logger.info("[workflow] step %s %s", step.id, status)
        self.current_workflow_step = None

    def _load_history_state(self, state: Dict[str, Any]) -> None:
        if state.get("history_loaded"):
            return

        entry_func = state["entry_func"]
        impl_result = state["impl_result"]
        historical_report = None
        if self.snapshot_store and not self.force_ignore_history:
            historical_report = self.snapshot_store.load_final_report(entry_func, impl_result["file"])

        hist_issues = historical_report.get("issues", []) if historical_report else []
        valid_hist_issues = [
            iss for iss in hist_issues
            if iss.get("validation_status") in ("validated", "pending")
        ]
        user_rejected_hist_issues = [
            iss for iss in hist_issues
            if iss.get("validation_status") == "rejected"
            and iss.get("rejection_source") == "user"
        ]

        needs_refresh = True
        reason = "no_snapshot"
        if self.snapshot_store and not self.force_ignore_history:
            needs_refresh, reason_value = self.snapshot_store.needs_refresh(
                entry_func,
                impl_result["code"],
                impl_result["file"],
            )
            reason = str(reason_value)

        state.update(
            {
                "historical_report": historical_report,
                "valid_hist_issues": valid_hist_issues,
                "user_rejected_hist_issues": user_rejected_hist_issues,
                "needs_refresh": needs_refresh,
                "refresh_reason": reason,
                "is_code_unchanged": (not needs_refresh and reason != "no_snapshot"),
                "history_loaded": True,
            }
        )

    def _reuse_unchanged_report(self, state: Dict[str, Any]) -> bool:
        if not state.get("history_loaded"):
            self._load_history_state(state)

        historical_report = state.get("historical_report")
        if self.maintain_mode and state.get("is_code_unchanged") and historical_report:
            logger.info(
                "[maintain] '%s' unchanged, reusing historical report (0 LLM tokens).",
                state["entry_func"],
            )
            state["final_report_dict"] = dict(historical_report)
            return True
        return False

    def _reconcile_changed_issues(self, state: Dict[str, Any]) -> None:
        if state.get("history_reconciled"):
            return
        if not state.get("history_loaded"):
            self._load_history_state(state)

        valid_hist_issues = state.get("valid_hist_issues", [])
        if not state.get("is_code_unchanged") and valid_hist_issues:
            entry_func = state["entry_func"]
            logger.info(
                "Code changed for %s. Verifying whether %d historical issue(s) still exist.",
                entry_func,
                len(valid_hist_issues),
            )
            recon_agent_cfg = next(
                (a for a in self.config.project.agents if a.name == "issue_reconciler_agent"),
                None,
            )
            recon_llm_ref = recon_agent_cfg.llm_ref if recon_agent_cfg and recon_agent_cfg.llm_ref else "default"
            recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
            if recon_client is None:
                raise RuntimeError("No LLM client configured for issue reconciliation")

            from ..agents.issue_reconciler.agent import IssueReconcilerAgent

            reconciler_agent = IssueReconcilerAgent(recon_client)
            verified_hist_issues = []
            for hist_issue in valid_hist_issues:
                input_data = {
                    "mode": "verify_fix",
                    "historical_issue": hist_issue,
                    "new_code": state["impl_result"]["code"],
                }
                resp = reconciler_agent.run(input_data)
                if resp.success and resp.data.get("still_exists"):
                    hist_issue["location"] = resp.data.get("new_location", hist_issue.get("location"))
                    verified_hist_issues.append(hist_issue)
                else:
                    logger.info("Historical issue %s fixed in new code. Dropping.", hist_issue.get("id"))
            state["verified_hist_issues"] = verified_hist_issues
        else:
            state["verified_hist_issues"] = list(valid_hist_issues)

        state["history_reconciled"] = True

    def _step_premodel_reachable_callees(self, state: Dict[str, Any]) -> None:
        sm_agent_cfg = next((a for a in self.config.project.agents if a.name == "semantic_modeler"), None)
        sm_llm_ref = sm_agent_cfg.llm_ref if sm_agent_cfg and sm_agent_cfg.llm_ref else "default"
        sm_client = self.llm_clients.get(sm_llm_ref, self.llm_clients["default"])

        modeled, skipped, tokens = self._premodel_callees(
            state["entry_func"],
            sm_client,
            max_depth=self.config.analysis.max_premodel_depth,
            max_callees=self.config.analysis.max_premodel_callees,
        )
        state["total_context_tokens"] += tokens
        state["notes"].append(
            f"Premodeled {modeled} reachable callee(s), reused {skipped} snapshot(s)."
        )

    def _step_model_entry(self, state: Dict[str, Any]) -> None:
        sm_agent_cfg = next((a for a in self.config.project.agents if a.name == "semantic_modeler"), None)
        sm_llm_ref = sm_agent_cfg.llm_ref if sm_agent_cfg and sm_agent_cfg.llm_ref else "default"
        sm_client = self.llm_clients.get(sm_llm_ref, self.llm_clients["default"])
        semantic_agent = SemanticModeler(sm_client, self._get_tools())
        agent_context = state["agent_context"]

        logger.info("Running Semantic Modeler agent with '%s' LLM...", sm_llm_ref)
        self._attach_agent_contract(agent_context, "semantic_modeler")
        response = semantic_agent.run(agent_context)
        sm_tokens = response.metadata.get("context_tokens", 0) if response.metadata else 0
        state["total_context_tokens"] += sm_tokens

        if response.success:
            self.snapshot_store.save_snapshot(
                state["entry_func"],
                response.data,
                agent_context["code"],
                agent_context["location"],
            )
            logger.info(
                "Successfully modeled function: %s (ctx ≈ %s tokens)",
                state["entry_func"],
                f"{sm_tokens:,}",
            )
            state["notes"].append(f"Successfully modeled function: {state['entry_func']}")
        else:
            logger.warning("Semantic modeling failed: %s (ctx ≈ %s tokens)", response.error, f"{sm_tokens:,}")
            state["notes"].append(f"Semantic modeling failed: {response.error}")

    def _step_focused_subagent_planning(self, state: Dict[str, Any]) -> None:
        va_agent_cfg = next(
            (a for a in self.config.project.agents if a.enabled and a.name == "vulnerability_analyzer"),
            None,
        )
        if not va_agent_cfg:
            return

        tools = self._get_tools()
        orchestrator = SubAgentOrchestrator(self.spec_registry, tools)
        selection = self._select_vulnerability_skills_for_config(va_agent_cfg)
        tickets = orchestrator.plan(
            state["entry_func"],
            state["agent_context"]["code"],
            max_tickets=self.config.analysis.max_subagent_tickets,
            allowed_skills=selection.skills,
        )
        if not tickets:
            return

        ticket_plan = [ticket.to_dict() for ticket in tickets]
        state["subagent_ticket_plan"] = ticket_plan
        state["agent_context"]["subagent_plan"] = ticket_plan
        state["agent_context"]["active_skills"] = selection.skills
        state["agent_context"]["skill_selection_restricted"] = selection.restricted
        state["notes"].append(f"Planned {len(tickets)} focused subagent ticket(s).")

        if not self._should_spawn_subagents(va_agent_cfg):
            return

        va_llm_ref = va_agent_cfg.llm_ref if va_agent_cfg.llm_ref else "default"
        va_client = self.llm_clients.get(va_llm_ref, self.llm_clients["default"])
        reports = orchestrator.run_tickets(
            va_client,
            tickets,
            max_iterations=min(self.config.analysis.max_tool_iterations, 20),
        )
        state["subagent_reports"] = reports
        state["agent_context"]["subagent_reports"] = reports
        state["total_context_tokens"] += sum(
            int(report.get("metadata", {}).get("context_tokens", 0) or 0)
            for report in reports
        )
        state["notes"].append(f"Executed {len(reports)} focused subagent ticket(s).")

    def _step_vulnerability_mining(self, state: Dict[str, Any]) -> None:
        agent_context = state["agent_context"]
        for agent_cfg in self.config.project.agents:
            if not agent_cfg.enabled or agent_cfg.name != "vulnerability_analyzer":
                continue

            logger.info("Running Vulnerability Analyzer agent for task: %s", agent_cfg.task)
            va_llm_ref = agent_cfg.llm_ref if agent_cfg.llm_ref else "default"
            va_client = self.llm_clients.get(va_llm_ref, self.llm_clients["default"])
            analyzer_agent = VulnerabilityAnalyzer(va_client, self._get_tools())
            selection = self._select_vulnerability_skills_for_config(agent_cfg)

            agent_context["task"] = agent_cfg.task
            agent_context["active_skills"] = selection.skills
            agent_context["skill_selection_restricted"] = selection.restricted
            self._attach_agent_contract(
                agent_context,
                "vulnerability_analyzer",
                agent_cfg.skills,
                active_skill_names=selection.skills,
            )
            response = analyzer_agent.run(
                agent_context,
                max_iterations=self.config.analysis.max_tool_iterations,
            )

            if response.success:
                raw_new_issues = response.data.get("issues", [])
                va_ctx_tokens = response.metadata.get("context_tokens", 0) if response.metadata else 0
                state["total_context_tokens"] += va_ctx_tokens
                logger.info(
                    "Vulnerability Analyzer found %d issue(s) for task: %s (ctx ≈ %s tokens)",
                    len(raw_new_issues),
                    agent_cfg.task,
                    f"{va_ctx_tokens:,}",
                )

                new_issues = self._deduplicate_against_history(raw_new_issues, state)
                state["pending_new_issues"].extend(new_issues)
                state["notes"].append(f"Analyzed task: {agent_cfg.task}")
            else:
                logger.error("Vulnerability analysis failed: %s", response.error)
                state["notes"].append(f"Vulnerability analysis failed: {response.error}")
                state["any_failure"] = True
                state["failure_msg"] = response.error

    def _deduplicate_against_history(
        self,
        raw_new_issues: List[Dict[str, Any]],
        state: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        dedup_reference_issues = (
            state.get("verified_hist_issues", [])
            + state.get("user_rejected_hist_issues", [])
        )
        if not raw_new_issues or not dedup_reference_issues:
            return raw_new_issues

        logger.info(
            "Deduplicating %d new issue(s) against %d reference issue(s).",
            len(raw_new_issues),
            len(dedup_reference_issues),
        )
        recon_agent_cfg = next(
            (a for a in self.config.project.agents if a.name == "issue_reconciler_agent"),
            None,
        )
        recon_llm_ref = recon_agent_cfg.llm_ref if recon_agent_cfg and recon_agent_cfg.llm_ref else "default"
        recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
        if recon_client is None:
            raise RuntimeError("No LLM client configured for issue reconciliation")

        from ..agents.issue_reconciler.agent import IssueReconcilerAgent

        reconciler_agent = IssueReconcilerAgent(recon_client)
        user_rejected_hist_issues = state.get("user_rejected_hist_issues", [])
        new_issues = []
        for raw_issue in raw_new_issues:
            input_data = {
                "mode": "deduplicate",
                "historical_issues": dedup_reference_issues,
                "new_issue": raw_issue,
            }
            resp = reconciler_agent.run(input_data)
            if resp.success and resp.data.get("is_duplicate"):
                matched_id = resp.data.get("matched_historical_id")
                matched_user_rejected = any(
                    iss.get("id") == matched_id and iss.get("rejection_source") == "user"
                    for iss in user_rejected_hist_issues
                )
                if matched_user_rejected:
                    logger.info("New issue matches user-rejected issue %s. Auto-suppressing.", matched_id)
                else:
                    logger.info("New issue corresponds to historical issue %s. Skipping validation.", matched_id)
            else:
                new_issues.append(raw_issue)
        return new_issues

    def _step_validate_findings(self, state: Dict[str, Any]) -> None:
        new_issues = state.get("pending_new_issues", [])
        if not new_issues:
            return

        validator_enabled = any(
            a.name == "validator_agent" and a.enabled
            for a in self.config.project.agents
        )
        if not validator_enabled:
            logger.info("Validator agent disabled, marking %d issue(s) unvalidated.", len(new_issues))
            for raw_issue in new_issues:
                raw_issue["validation_status"] = "unvalidated"
                state["issues"].append(raw_issue)
            state["pending_new_issues"] = []
            return

        val_agent_cfg = next((a for a in self.config.project.agents if a.name == "validator_agent"), None)
        val_llm_ref = val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
        val_client = self.llm_clients.get(val_llm_ref, self.llm_clients["default"])
        validator_agent = ValidatorAgent(val_client, self._get_tools())

        for raw_issue in new_issues:
            issue_func = raw_issue.get("function", state["agent_context"]["func_name"])
            logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)

            issue_code = state["agent_context"]["code"]
            if issue_func != state["agent_context"]["func_name"]:
                impl = self.code_index.get_function_impl(issue_func)
                if impl:
                    issue_code = impl["code"]

            val_input = {
                "finding": json.dumps(raw_issue, indent=2, ensure_ascii=False),
                "context_code": issue_code,
            }
            self._attach_agent_contract(val_input, "validator_agent")
            val_resp = validator_agent.run(val_input)

            if val_resp.success:
                val_data = val_resp.data
                if val_data.get("is_valid"):
                    raw_issue["validation_status"] = "validated"
                    raw_issue["validation_reasoning"] = val_data.get("reasoning")
                    raw_issue["confidence"] = val_data.get(
                        "confidence_score",
                        raw_issue.get("confidence", 0.5),
                    )
                    logger.info(
                        "Issue %s VALIDATED with confidence %s",
                        raw_issue.get("id"),
                        raw_issue["confidence"],
                    )
                    state["issues"].append(raw_issue)
                else:
                    raw_issue["validation_status"] = "rejected"
                    raw_issue["rejection_source"] = "validator"
                    raw_issue["validation_reasoning"] = val_data.get("reasoning")
                    logger.info("Issue %s REJECTED by Validator, discarding.", raw_issue.get("id"))
            else:
                logger.warning(
                    "Validation failed for issue %s in function %s: %s",
                    raw_issue.get("id"),
                    issue_func,
                    val_resp.error,
                )
                raw_issue["validation_status"] = "pending"
                raw_issue["validation_error"] = val_resp.error
                state["issues"].append(raw_issue)

        state["pending_new_issues"] = []

    def _build_final_report(self, state: Dict[str, Any]) -> None:
        all_issues = state.get("issues", []) + state.get("verified_hist_issues", [])
        self._resolve_issue_locations(all_issues)

        if state.get("any_failure") and not all_issues:
            verdict = "error"
            state["notes"].append(
                f"Analysis incomplete due to agent failure: {state.get('failure_msg', '')}"
            )
        else:
            verdict = "issues_found" if all_issues else "no_issue_found"

        final_report = FinalReport(
            entry_function=state["entry_func"],
            overall_verdict=verdict,
            issues=[
                Issue.from_dict(i, context_function=state["entry_func"], issue_index=idx + 1)
                for idx, i in enumerate(all_issues)
                if isinstance(i, dict)
            ] or [i for i in all_issues if isinstance(i, Issue)],
            notes=state["notes"],
        )
        final_report.metadata = self._build_workflow_metadata(state)
        state["final_report"] = final_report

    def _build_workflow_metadata(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": __version__,
            "context_tokens": state.get("total_context_tokens", 0),
            "workflow": self.workflow_spec.name if self.workflow_spec else self.config.analysis.workflow_name,
            "workflow_mode": self.workflow_spec.mode if self.workflow_spec else self.config.analysis.workflow_name,
            "workflow_progress": list(self.workflow_progress),
            "current_workflow_step": self.current_workflow_step,
            "subagent_ticket_count": len(state.get("subagent_ticket_plan", [])),
            "subagent_reports_count": len(state.get("subagent_reports", [])),
        }

    def _persist_final_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        final_report = state["final_report"]
        final_report.metadata = self._build_workflow_metadata(state)
        self.report_generator.save_json_report(final_report)
        self.report_generator.save_markdown_report(final_report)

        report_dict = cast(Dict[str, Any], final_report.to_dict())
        if self.snapshot_store:
            self.snapshot_store.save_final_report(
                state["entry_func"],
                report_dict,
                state["agent_context"]["location"],
            )
        return report_dict

    def _finalize_returned_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        report_dict = dict(state["final_report_dict"])
        metadata = dict(report_dict.get("metadata") or {})
        metadata.update(self._build_workflow_metadata(state))
        report_dict["metadata"] = metadata
        return report_dict

    def _attach_agent_contract(
        self,
        context: Dict[str, Any],
        agent_name: str,
        extra_skills: Optional[List[str]] = None,
        active_skill_names: Optional[List[str]] = None,
    ) -> None:
        """Attach agent/skill contracts to a single agent invocation."""
        agent_spec = self.spec_registry.get_agent(agent_name)
        if agent_spec:
            context["agent_contract"] = agent_spec.to_prompt_block(active_skills=active_skill_names)
        else:
            context.pop("agent_contract", None)

        skills = self.spec_registry.skills_for_agent(
            agent_name,
            extra=extra_skills,
            only=active_skill_names,
        )
        if skills:
            context["skill_contracts"] = "\n\n".join(skill.to_prompt_block() for skill in skills)
        else:
            context.pop("skill_contracts", None)

    def _select_vulnerability_skills_for_config(self, agent_cfg: Any) -> SkillSelection:
        """Select active vulnerability skills from the configured analyzer task."""
        available = [
            skill.name
            for skill in self.spec_registry.skills_for_agent(
                "vulnerability_analyzer",
                extra=getattr(agent_cfg, "skills", None),
            )
        ]
        selection = select_vulnerability_skills(getattr(agent_cfg, "task", None), available)
        if selection.restricted:
            logger.info(
                "Task-selected vulnerability skills for '%s': %s",
                getattr(agent_cfg, "task", ""),
                ", ".join(selection.skills) or "none",
            )
        return selection

    def _should_spawn_subagents(self, agent_cfg: Any) -> bool:
        """Decide whether focused deep-worker LLM calls are enabled for this run."""
        explicit = getattr(agent_cfg, "can_spawn_subagents", None)
        if explicit is not None:
            return bool(explicit)
        agent_spec = self.spec_registry.get_agent("vulnerability_analyzer")
        if not self.config.analysis.enable_subagent_workers:
            return False
        return bool(agent_spec and agent_spec.can_spawn_subagents)

    def _get_tools(self) -> List[Any]:
        """Initialize and return the set of tools."""
        from ..tools.code_retrieval import GetFunctionImplTool
        from ..tools.snapshot_tool import GetFunctionSnapshotTool
        from ..tools.utils import (
            ListFunctionsTool,
            GetFileSnippetTool,
            GetCallersTool,
            GetTypeInfoTool,
            GetCallGraphTool,
            GetDataFlowTool,
            FindFunctionPointersTool,
            QueryPointerAliasTool,
            VerifyTaintReachabilityTool,
            GetDeepCallContextTool,
        )

        # Base tools universally supported by all backends (including regex/clangd)
        tools = [
            GetFunctionImplTool(self.code_index, self.user_config),
            GetFunctionSnapshotTool(self.snapshot_store),
            ListFunctionsTool(self.code_index),
            GetFileSnippetTool(self.code_index),
            GetCallersTool(self.code_index),
            GetTypeInfoTool(self.code_index),
        ]
        
        # Heavy CPG tools only supported by advanced graph backends
        advanced_backends = ["joern", "svf", "unified"]
        if hasattr(self.code_index, "backend_name") and self.code_index.backend_name in advanced_backends:
            tools.extend([
                GetCallGraphTool(self.code_index),
                GetDataFlowTool(self.code_index),
                FindFunctionPointersTool(self.code_index),
                QueryPointerAliasTool(self.code_index),
                VerifyTaintReachabilityTool(self.code_index),
                GetDeepCallContextTool(self.code_index),
            ])
            
        return tools

    def _premodel_callees(self, entry_func: str, sm_client: 'LLMClient',
                          max_depth: int = 3, max_callees: int = 20) -> tuple[int, int, int]:
        """
        递归预建模入口函数的所有可达 callee（逆拓扑序）。
        Returns:
            (modeled_count, skipped_count, total_context_tokens)
        """
        # 1. BFS 收集可达 callee 图
        callee_graph: Dict[str, List[str]] = {}
        visited: Set[str] = set()
        queue: list = [(entry_func, 0)]
        impl_cache: Dict[str, Any] = {}  # 缓存 get_function_impl 结果

        while queue:
            func, depth = queue.pop(0)
            if func in visited or depth > max_depth:
                continue
            visited.add(func)

            callees_raw = self.code_index.get_callees(func, limit=max_callees)
            callee_names = [c["name"] for c in callees_raw if c.get("name")]

            # 过滤掉无源码的函数（标准库等）
            resolvable = []
            for c in callee_names:
                if c in visited:
                    continue
                impl = self.code_index.get_function_impl(c)
                if impl is not None:
                    impl_cache[c] = impl
                    resolvable.append(c)
                    queue.append((c, depth + 1))

            callee_graph[func] = resolvable

        # 2. 逆拓扑排序：叶子函数优先
        order = self._topo_sort(callee_graph, entry_func)
        # 过滤掉入口函数本身（由主流程建模）
        order = [f for f in order if f != entry_func]

        if not order:
            return 0, 0, 0

        logger.info(f"[premodel] {len(order)} reachable callees to pre-model for '{entry_func}'")

        # 3. 逐个建模
        semantic_agent = SemanticModeler(sm_client, self._get_tools())
        modeled = 0
        skipped = 0
        total_tokens = 0

        for func in order:
            # 快速检查：已有快照则跳过
            existing = self.snapshot_store.load_snapshot(func)
            if existing is not None:
                skipped += 1
                continue

            # 跨线程锁保护
            status = self.snapshot_store.lock_manager.acquire(func, timeout=120.0)
            if status == "done":
                skipped += 1
                continue
            if status == "timeout":
                logger.warning(f"[premodel] Timeout waiting for '{func}', skipping.")
                continue

            # status == "acquired"：由当前 Worker 建模
            try:
                impl = impl_cache.get(func) or self.code_index.get_function_impl(func)
                if not impl:
                    self.snapshot_store.lock_manager.release(func, success=False)
                    continue

                location = f"{impl['file']}:{impl['start_line']}"

                # 高效拦截：平凡函数不需要让大模型看
                if self._is_trivial_function(impl["code"], self.config.analysis.trivial_function_max_lines):
                    logger.info(f"[premodel] Auto-skipping trivial function '{func}'")
                    fake_snapshot = {
                        "type": "function_snapshot",
                        "func_name": func,
                        "location": location,
                        "summary": "[Auto-Skipped] Trivial Function (极简直通结构，未调用 LLM)",
                        "inputs": [],
                        "outputs": [],
                        "resources": {},
                        "error_handling": {},
                        "concurrency": {},
                        "semantic_fingerprint": {"key_semantics": ["trivial representation"]},
                        "suspicious_points": [],
                        "callees": impl.get("callees", []),
                        "is_trivial": True
                    }
                    self.snapshot_store.save_snapshot(func, fake_snapshot, impl["code"], location)
                    self.snapshot_store.lock_manager.release(func, success=True)
                    modeled += 1
                    continue

                context = {
                    "func_name": func,
                    "code": impl["code"],
                    "location": location,
                    "schema": "{}",
                }
                self._attach_agent_contract(context, "semantic_modeler")

                logger.info(f"[premodel] Modeling callee '{func}' ...")
                resp = semantic_agent.run(context)
                call_tokens = resp.metadata.get("context_tokens", 0) if resp.metadata else 0
                total_tokens += call_tokens

                if resp.success:
                    self.snapshot_store.save_snapshot(
                        func, resp.data, impl["code"], location
                    )
                    self.snapshot_store.lock_manager.release(func, success=True)
                    modeled += 1
                else:
                    self.snapshot_store.lock_manager.release(func, success=False)
                    logger.warning(f"[premodel] Failed to model '{func}': {resp.error}")
            except Exception as e:
                self.snapshot_store.lock_manager.release(func, success=False)
                logger.error(f"[premodel] Error modeling '{func}': {e}")

        logger.info(f"[premodel] Done: {modeled} modeled, {skipped} reused from cache (ctx ≈ {total_tokens:,} tokens)")
        return modeled, skipped, total_tokens

    @staticmethod
    def _is_trivial_function(code: str, max_lines_threshold: int) -> bool:
        """
        判断一个函数是否过于简单，不需要经过大模型做深度语义分析。
        1. 去除注释和空行后，行数 <= max_lines_threshold
        2. 代码体内不含有锁、内存分配、IO等高危关键字（无涉安全）
        """
        if max_lines_threshold <= 0:
            return False

        # 1. 粗略清洗注释和左侧行号前缀
        import re
        lines = code.split("\n")
        clean_lines = []
        in_block_comment = False
        for line in lines:
            line = line.strip()
            # Remove line numbers inserted by `get_function_impl`: "123 | int foo() {" -> "int foo() {"
            line = re.sub(r"^\d+\s*\|\s*", "", line)
            if not line:
                continue

            if in_block_comment:
                if "*/" in line:
                    in_block_comment = False
                    line = line[line.find("*/") + 2:].strip()
                else:
                    continue

            if "/*" in line:
                if "*/" in line:
                    line = re.sub(r"/\*.*?\*/", "", line).strip()
                else:
                    in_block_comment = True
                    line = line[:line.find("/*")].strip()

            if "//" in line:
                line = line[:line.find("//")].strip()

            if line:
                clean_lines.append(line)

        # 除了大括号和函数签名之外的有效逻辑行
        logic_lines = [l for l in clean_lines if l not in ("{", "}")]
        # Let's say if signature is 1 line, body is N lines. We just check total clean logic lines.
        # usually 1 line signature + 1 line return + maybe brackets.
        if len(logic_lines) > max_lines_threshold + 1:  # +1 for signature roughly
            return False

        # 2. 验证风险关键字
        # 不区分大小写匹配敏感操作
        clean_code_body = " ".join(clean_lines).lower()
        risky_keywords = [
            r"malloc", r"calloc", r"realloc", r"free", r"alloc", r"new\s", r"delete\s",
            r"lock", r"mutex", r"mtx", r"cond", r"thread", r"spin", r"pthread",
            r"file", r"fopen", r"fclose", r"read", r"write", r"socket", r"send", r"recv", r"connect", r"open", r"close"
        ]
        
        for kw in risky_keywords:
            if re.search(kw, clean_code_body):
                return False

        return True

    @staticmethod
    def _topo_sort(graph: Dict[str, List[str]], root: str) -> list:
        """逆拓扑排序：返回叶子优先的建模顺序。"""
        visited: Set[str] = set()
        order: list = []

        def dfs(node: str):
            if node in visited:
                return
            visited.add(node)
            for child in graph.get(node, []):
                dfs(child)
            order.append(node)

        dfs(root)
        return order  # 天然是逆拓扑序（叶子在前）

    def _tool_executor_wrapper(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper to intercept tool execution for snapshot logic."""
        
        # Intercept get_function_impl to check for snapshot refresh
        if tool_name == "get_function_impl" and self.config.analysis.enable_snapshot_cache:
            func_name = str(args.get("func_name") or "")
            return self._smart_get_implementation(func_name, args)

        return self.tools_runtime.execute_tool(tool_name, args)

    def _smart_get_implementation(self, func_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Smart implementation retrieval:
        1. Get current code.
        2. Check if snapshot exists.
        3. If snapshot exists, check if code changed (hash check).
        4. If code changed, ask LLM if refresh is needed.
        """
        # 1. Get real implementation
        impl_result = self.tools_runtime.execute_tool("get_function_impl", args)
        if not impl_result.get("success"):
            return impl_result
        
        current_code = impl_result["data"]["code"]
        file_path = impl_result["data"]["file"]  # Extract file path
        
        # 2. Check snapshot status with file_path
        needs_refresh, reason = self.snapshot_store.needs_refresh(func_name, current_code, file_path)
        
        if not needs_refresh and reason != "no_snapshot":
            # Snapshot is valid and up to date (or only cosmetic changes)
            logger.info(f"Using cached snapshot for '{func_name}' in '{file_path}' (reason: {reason})")
            snapshot = self.snapshot_store.load_snapshot(func_name, file_path)
            return {
                "success": True, 
                "data": impl_result["data"], 
                "snapshot": snapshot, 
                "note": "Snapshot allows skipping deep analysis if irrelevant."
            }

        if reason == "code_changed":
            # 3. Ask LLM if we really need to refresh (semantic check)
            # This requires a mini-LLM call.
            logger.info(f"Code changed for '{func_name}' in '{file_path}', checking with LLM if refresh needed...")
            snapshot = self.snapshot_store.load_snapshot(func_name, file_path)
            decision = self._ask_refresh_decision(func_name, snapshot or {}, current_code)
            
            if not decision.get("refresh_needed"):
                logger.info(f"LLM decided refresh NOT needed for '{func_name}'")
                return {
                    "success": True,
                    "data": impl_result["data"],
                    "snapshot": snapshot,
                    "note": "Code changed but LLM deemed snapshot still valid."
                }
            
            logger.info(f"Refresh needed for '{func_name}': {decision.get('reason')}")

        # If we are here, we return the code and expect the LLM to analyze it and produce a new snapshot
        return impl_result

    def _default_llm_client(self) -> LLMClient:
        client = self.llm_clients.get("default")
        if client is None:
            try:
                client = next(iter(self.llm_clients.values()))
            except StopIteration as exc:
                raise RuntimeError("No LLM clients configured") from exc
        return client

    def _ask_refresh_decision(self, func_name: str, old_snapshot: Dict[str, Any], new_code: str) -> Dict[str, Any]:
        """Ask LLM if snapshot needs refresh."""
        prompt = f"""
Function '{func_name}' has changed.
Old Snapshot Summary: {old_snapshot.get('summary')}
Old Fingerprint: {old_snapshot.get('semantic_fingerprint')}

New Code:
```c
{new_code}
```

Determine if the semantic contract/behavior relevant to defect attributes (resources, errors, concurrency) has changed.
Output a JSON of type 'snapshot_refresh_decision'.
"""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
        
        # Use a separate simpler call (no tools)
        try:
            response = self._default_llm_client().chat_completion(messages, max_tokens=500)
            content = response["choices"][0]["message"]["content"]
            decision = self._extract_json_block(content, "snapshot_refresh_decision")
            return decision or {"refresh_needed": True, "reason": "Failed to parse decision"}
        except Exception as e:
            logger.error(f"Failed to get refresh decision: {e}")
            return {"refresh_needed": True, "reason": "Error calling LLM"}

    def _extract_final_report(self, text: str) -> Optional[FinalReport]:
        """Parse final report from text."""
        data = self._extract_json_block(text, "final_report")
        if not data:
            return None
            
        try:
            issues = [Issue.from_dict(i, context_function=data.get("entry_function", "unknown"), issue_index=idx+1) for idx, i in enumerate(data.get("issues", []))]
            return FinalReport(
                entry_function=data.get("entry_function", ""),
                overall_verdict=data.get("overall_verdict", "insufficient_info"),
                issues=issues,
                notes=data.get("notes", [])
            )
        except Exception as e:
            logger.error(f"Failed to parse FinalReport object: {e}")
            return None

    def _extract_json_block(self, text: str, type_hint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Extract JSON block from text using robust utility.
        """
        from ..common.utils import extract_json_blocks
        
        candidates = extract_json_blocks(text)
        
        for data in candidates:
            if type_hint:
                if data.get("type") == type_hint:
                    return data
                # Handle nested wrap
                if type_hint in data and isinstance(data[type_hint], dict) and data[type_hint].get("type") == type_hint:
                    return cast(Dict[str, Any], data[type_hint])
            else:
                # If no hint, return the first dictionary found
                return data
                
        return None
            
        return None

    def _save_snapshot_from_llm(self, snapshot_data: Dict[str, Any]) -> None:
        """Save a snapshot emitted by LLM."""
        func_name = snapshot_data.get("func_name")
        if not func_name:
            return
            
        # We need the code implementation to calculate hash for the snapshot
        # Since we might be inside the analysis loop, we can fetch it again from index
        impl = self.code_index.get_function_impl(func_name)
        if impl:
            self.snapshot_store.save_snapshot(
                func_name=func_name,
                snapshot=snapshot_data,
                code=impl["code"],
                location=f"{impl['file']}:{impl['start_line']}"
            )

    def _resolve_issue_locations(self, issues: List[Dict[str, Any]]) -> None:
        """Format absolute line numbers outputted by LLM into standard file:line format."""
        for issue in issues:
            if not isinstance(issue, dict):
                continue

            func_name = issue.get("function")
            if not func_name:
                continue

            # Try to find the file from the function name
            func_info = self.code_index.get_function_impl(func_name)
            raw_location = str(issue.get("location", ""))
            
            # Extract line number/range from LLM output (e.g., "142" or "142-145" or "cache_get:142")
            nums = re.findall(r"\d+", raw_location)
            line_suffix = "unknown"
            if len(nums) >= 2:
                line_suffix = f"{nums[0]}-{nums[1]}"
            elif len(nums) == 1:
                line_suffix = f"{nums[0]}"

            if not func_info:
                issue["location"] = f"unknown_file:{line_suffix}"
                continue

            relative_file = func_info["file"]
            issue["location"] = f"{relative_file}:{line_suffix}"


