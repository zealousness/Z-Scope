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
from typing import Dict, Any, List, Optional, Set

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
            priority_functions=[config.project.entry_function] if config.project.entry_function else None
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
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        
        self.analyzed_functions: Set[str] = set()
        self.issues: List[Issue] = []

    def run(self) -> Dict[str, Any]:
        """Run the multi-agent analysis."""
        entry_func = self.config.project.entry_function
        logger.info(f"Starting multi-agent analysis on entry function: {entry_func}")

        # Clear config warnings from previous run
        self.user_config.clear_config_warnings()

        impl_result = self.code_index.get_function_impl(entry_func)
        if not impl_result:
            return {"error": "Entry function not found"}

        # Initialize common context
        agent_context = {
            "func_name": entry_func,
            "code": impl_result["code"],
            "location": f"{impl_result['file']}:{impl_result['start_line']}"
        }

        # Inject user config context
        user_context_parts = []
        paired_ctx = self.user_config.get_paired_functions_context()
        if paired_ctx:
            user_context_parts.append(paired_ctx)
        intent_ctx = self.user_config.get_function_intent_context(entry_func)
        if intent_ctx:
            user_context_parts.append(intent_ctx)
        if user_context_parts:
            agent_context["user_config_context"] = "\n".join(user_context_parts)

        issues = []
        notes = []

        if self.snapshot_store and not self.force_ignore_history:
            historical_report = self.snapshot_store.load_final_report(entry_func, impl_result['file'])
        else:
            historical_report = None
            
        hist_issues = historical_report.get("issues", []) if historical_report else []
        valid_hist_issues = [iss for iss in hist_issues if iss.get("validation_status") in ("validated", "pending")]
        # Collect user-rejected issues for auto-suppression in dedup
        user_rejected_hist_issues = [iss for iss in hist_issues if iss.get("validation_status") == "rejected" and iss.get("rejection_source") == "user"]
        
        needs_refresh = True
        reason = "no_snapshot"
        if self.snapshot_store and not self.force_ignore_history:
            needs_refresh, reason = self.snapshot_store.needs_refresh(entry_func, impl_result['code'], impl_result['file'])
        
        is_code_unchanged = (not needs_refresh and reason != "no_snapshot")
        
        # --maintain mode: if code is unchanged, reuse historical report entirely (zero LLM cost)
        if self.maintain_mode and is_code_unchanged and historical_report:
            logger.info(f"[maintain] '{entry_func}' unchanged, reusing historical report (0 LLM tokens).")
            return historical_report
        
        verified_hist_issues = []
        if not is_code_unchanged and valid_hist_issues:
            logger.info(f"Code changed for {entry_func}. Verifying if {len(valid_hist_issues)} historical issues still exist...")
            recon_agent_cfg = next((a for a in self.config.project.agents if a.name == "issue_reconciler_agent"), None)
            recon_llm_ref = recon_agent_cfg.llm_ref if recon_agent_cfg and recon_agent_cfg.llm_ref else "default"
            recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
            
            from ..agents.issue_reconciler.agent import IssueReconcilerAgent
            reconciler_agent = IssueReconcilerAgent(recon_client)
            
            for hist_issue in valid_hist_issues:
                input_data = {
                    "mode": "verify_fix",
                    "historical_issue": hist_issue,
                    "new_code": impl_result['code']
                }
                resp = reconciler_agent.run(input_data)
                if resp.success and resp.data.get("still_exists"):
                    hist_issue["location"] = resp.data.get("new_location", hist_issue.get("location"))
                    verified_hist_issues.append(hist_issue)
                else:
                    logger.info(f"Historical issue {hist_issue.get('id')} fixed in new code. Dropping.")
        else:
            verified_hist_issues = valid_hist_issues

        # 1. Run Semantic Modeler (modeling logic)
        sm_agent_cfg = next((a for a in self.config.project.agents if a.name == "semantic_modeler"), None)
        sm_llm_ref = sm_agent_cfg.llm_ref if sm_agent_cfg and sm_agent_cfg.llm_ref else "default"
        sm_client = self.llm_clients.get(sm_llm_ref, self.llm_clients["default"])
        
        semantic_agent = SemanticModeler(sm_client, self._get_tools())
        logger.info(f"Running Semantic Modeler agent with '{sm_llm_ref}' LLM...")
        s_resp = semantic_agent.run(agent_context)
        if s_resp.success:
            # Save snapshot to store
            self.snapshot_store.save_snapshot(
                entry_func, s_resp.data, agent_context["code"], agent_context["location"]
            )
            notes.append(f"Successfully modeled function: {entry_func}")
        else:
            logger.warning(f"Semantic modeling failed: {s_resp.error}")
            notes.append(f"Semantic modeling failed: {s_resp.error}")
        
        # 2. Run Vulnerability Analyzer for each configured task
        any_failure = False
        failure_msg = ""
        
        for agent_cfg in self.config.project.agents:
            if not agent_cfg.enabled or agent_cfg.name != "vulnerability_analyzer":
                continue

            logger.info(f"Running Vulnerability Analyzer agent for task: {agent_cfg.task}")
            va_llm_ref = agent_cfg.llm_ref if agent_cfg.llm_ref else "default"
            va_client = self.llm_clients.get(va_llm_ref, self.llm_clients["default"])
            analyzer_agent = VulnerabilityAnalyzer(va_client, self._get_tools())
            
            agent_context["task"] = agent_cfg.task
            v_resp = analyzer_agent.run(agent_context, max_iterations=self.config.analysis.max_tool_iterations)
            
            if v_resp.success:
                raw_new_issues = v_resp.data.get("issues", [])
                logger.info(f"Vulnerability Analyzer found {len(raw_new_issues)} issues for task: {agent_cfg.task}")
                
                new_issues = []
                # Combine verified historical issues + user-rejected issues for dedup reference
                dedup_reference_issues = verified_hist_issues + user_rejected_hist_issues
                
                if raw_new_issues and dedup_reference_issues:
                    logger.info(f"Deduplicating {len(raw_new_issues)} new issues against {len(dedup_reference_issues)} reference issues ({len(user_rejected_hist_issues)} user-rejected)...")
                    recon_agent_cfg = next((a for a in self.config.project.agents if a.name == "issue_reconciler_agent"), None)
                    recon_llm_ref = recon_agent_cfg.llm_ref if recon_agent_cfg and recon_agent_cfg.llm_ref else "default"
                    recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
                    
                    from ..agents.issue_reconciler.agent import IssueReconcilerAgent
                    reconciler_agent = IssueReconcilerAgent(recon_client)
                    
                    for raw_issue in raw_new_issues:
                        input_data = {
                            "mode": "deduplicate",
                            "historical_issues": dedup_reference_issues,
                            "new_issue": raw_issue
                        }
                        resp = reconciler_agent.run(input_data)
                        if resp.success and resp.data.get("is_duplicate"):
                            matched_id = resp.data.get("matched_historical_id")
                            # Check if matched against a user-rejected issue
                            matched_user_rejected = any(
                                iss.get("id") == matched_id and iss.get("rejection_source") == "user"
                                for iss in user_rejected_hist_issues
                            )
                            if matched_user_rejected:
                                logger.info(f"New issue matches user-rejected issue {matched_id}. Auto-suppressing.")
                            else:
                                logger.info(f"New issue corresponds to historical issue {matched_id}. Skipping validation.")
                        else:
                            new_issues.append(raw_issue)
                else:
                    new_issues = raw_new_issues
                
                # Check if validator agent is enabled
                validator_enabled = any(
                    a.name == "validator_agent" and a.enabled 
                    for a in self.config.project.agents
                )
                
                if validator_enabled and new_issues:
                    val_agent_cfg = next((a for a in self.config.project.agents if a.name == "validator_agent"), None)
                    val_llm_ref = val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
                    val_client = self.llm_clients.get(val_llm_ref, self.llm_clients["default"])
                    validator_agent = ValidatorAgent(val_client, self._get_tools())
                    
                    validated_issues = []
                    for raw_issue in new_issues:
                        issue_func = raw_issue.get("function", agent_context["func_name"])
                        logger.info(f"Validating issue: {raw_issue.get('id', 'unknown')} in {issue_func}")
                        
                        # Try to get the specific code for the function where the issue was found
                        issue_code = agent_context["code"]
                        if issue_func != agent_context["func_name"]:
                             impl = self.code_index.get_function_impl(issue_func)
                             if impl:
                                 issue_code = impl["code"]

                        val_input = {
                            "finding": json.dumps(raw_issue, indent=2, ensure_ascii=False),
                            "context_code": issue_code
                        }
                        val_resp = validator_agent.run(val_input)
                        
                        if val_resp.success:
                            val_data = val_resp.data
                            if val_data.get("is_valid"):
                                # Enrich issue with validation reasoning
                                raw_issue["validation_status"] = "validated"
                                raw_issue["validation_reasoning"] = val_data.get("reasoning")
                                raw_issue["confidence"] = val_data.get("confidence_score", raw_issue.get("confidence", 0.5))
                                logger.info(f"Issue {raw_issue.get('id')} VALIDATED with confidence {raw_issue['confidence']}")
                                validated_issues.append(raw_issue)
                            else:
                                # Validator rejected: discard this issue, do NOT persist
                                raw_issue["validation_status"] = "rejected"
                                raw_issue["rejection_source"] = "validator"
                                raw_issue["validation_reasoning"] = val_data.get("reasoning")
                                logger.info(f"Issue {raw_issue.get('id')} REJECTED by Validator, discarding.")
                                # Do NOT append to validated_issues
                        else:
                            # Fallback if validation fails
                            logger.warning(
                                "Validation failed for issue %s in function %s: %s",
                                raw_issue.get("id"), issue_func, val_resp.error,
                            )
                            raw_issue["validation_status"] = "pending"
                            raw_issue["validation_error"] = val_resp.error
                            validated_issues.append(raw_issue)

                    issues.extend(validated_issues)
                else:
                    # Validator not enabled - pass through issues without validation
                    if not validator_enabled:
                        logger.info("Validator agent disabled, skipping validation step")
                    for raw_issue in new_issues:
                        raw_issue["validation_status"] = "unvalidated"
                        issues.append(raw_issue)
                
                notes.append(f"Analyzed task: {agent_cfg.task}")
            else:
                logger.error(f"Vulnerability analysis failed: {v_resp.error}")
                notes.append(f"Vulnerability analysis failed: {v_resp.error}")
                any_failure = True
                failure_msg = v_resp.error

        # 3. Combine newly found and validated issues with verified historical issues
        all_issues = issues + verified_hist_issues

        # 4. Resolve locations for issues without explicit locations
        self._resolve_issue_locations(all_issues)
        
        issues = all_issues

        # Construct Final Report
        if any_failure and not issues:
             verdict = "error"
             notes.append(f"Analysis incomplete due to agent failure: {failure_msg}")
        else:
             verdict = "issues_found" if issues else "no_issue_found"

        final_report = FinalReport(
            entry_function=entry_func,
            overall_verdict=verdict,
            issues=[Issue.from_dict(i, context_function=entry_func, issue_index=idx+1) for idx, i in enumerate(issues) if isinstance(i, dict)] or [i for i in issues if isinstance(i, Issue)],
            notes=notes
        )

        final_report.metadata = {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "0.2.0"
        }

        # Save results to disk
        self.report_generator.save_json_report(final_report)
        self.report_generator.save_markdown_report(final_report)

        report_dict = final_report.to_dict()
        
        # Finally, persist the actual issues into the Snapshot DB to survive Ctrl+C
        if self.snapshot_store:
            self.snapshot_store.save_final_report(
                entry_func, 
                report_dict, 
                agent_context["location"]
            )

        return report_dict

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
        )

        # Base tools universally supported by all backends (including regex/clangd)
        tools = [
            GetFunctionImplTool(self.code_index),
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
            ])
            
        return tools



    def _tool_executor_wrapper(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper to intercept tool execution for snapshot logic."""
        
        # Intercept get_function_impl to check for snapshot refresh
        if tool_name == "get_function_impl" and self.config.analysis.enable_snapshot_cache:
            func_name = args.get("func_name")
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
            decision = self._ask_refresh_decision(func_name, snapshot, current_code)
            
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
            response = self.llm_client.chat_completion(messages, max_tokens=500)
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

    def _extract_json_block(self, text: str, type_hint: str = None) -> Optional[Dict[str, Any]]:
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
                    return data[type_hint]
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


