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
  "location": "src/cache_core.c:140-165",
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
                 user_config: Optional[UserConfigStore] = None):
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
        self.llm_client = LLMClient(
            api_key=config.llm.api_key,
            base_url=config.llm.base_url,
            models=config.llm.models,
            timeout=config.llm.timeout,
            max_retries=config.llm.max_retries,
            max_tokens=config.llm.max_tokens
        )
        self.report_generator = ReportGenerator(config.project.project_root)
        self.tools_runtime = ToolsRuntime(self.code_index, self.snapshot_store, self.user_config)
        
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

        # 1. Run Semantic Modeler (modeling logic)
        semantic_agent = SemanticModeler(self.llm_client, self._get_tools())
        logger.info("Running Semantic Modeler agent...")
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
        analyzer_agent = VulnerabilityAnalyzer(self.llm_client, self._get_tools())
        any_failure = False
        failure_msg = ""

        for agent_cfg in self.config.project.agents:
            if not agent_cfg.enabled or agent_cfg.name != "vulnerability_analyzer":
                continue
            
            logger.info(f"Running Vulnerability Analyzer agent for task: {agent_cfg.task}")
            agent_context["task"] = agent_cfg.task
            v_resp = analyzer_agent.run(agent_context, max_iterations=self.config.analysis.max_tool_iterations)
            
            if v_resp.success:
                new_issues = v_resp.data.get("issues", [])
                logger.info(f"Vulnerability Analyzer found {len(new_issues)} issues for task: {agent_cfg.task}")
                
                # Check if validator agent is enabled
                validator_enabled = any(
                    a.name == "validator_agent" and a.enabled 
                    for a in self.config.project.agents
                )
                
                if validator_enabled and new_issues:
                    # 3. Run Validator Agent for each found issue
                    validator_agent = ValidatorAgent(self.llm_client, self._get_tools())
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
                            else:
                                raw_issue["validation_status"] = "rejected"
                                raw_issue["validation_reasoning"] = val_data.get("reasoning")
                                logger.info(f"Issue {raw_issue.get('id')} REJECTED by Validator: {val_data.get('reasoning')}")
                            
                            validated_issues.append(raw_issue)
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

        # 3. Resolve locations using snippets
        self._resolve_issue_locations(issues)

        # 4. Filter false positives
        issues = self._filter_false_positives(issues)

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
            "version": "0.1.0"
        }

        # Save results
        self.report_generator.save_json_report(final_report)
        self.report_generator.save_markdown_report(final_report)

        return final_report.to_dict()

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

        return [
            GetFunctionImplTool(self.code_index),
            GetFunctionSnapshotTool(self.snapshot_store),
            ListFunctionsTool(self.code_index),
            GetFileSnippetTool(self.code_index),
            GetCallersTool(self.code_index),
            GetTypeInfoTool(self.code_index),
            GetCallGraphTool(self.code_index),
            GetDataFlowTool(self.code_index),
            FindFunctionPointersTool(self.code_index),
        ]



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
        """Resolve exact line numbers for issues using code snippets."""
        file_cache: Dict[Path, str] = {}
        for issue in issues:
            if not isinstance(issue, dict):
                continue

            func_name = issue.get("function")
            if not func_name:
                continue

            # Try to find the file from the function name
            func_info = self.code_index.get_function_impl(func_name)
            if not func_info:
                # 兜底：即使找不到函数，也清洗 location 中的垃圾字符
                self._sanitize_location(issue)
                continue

            relative_file = func_info["file"]
            abs_file = self.config.project.project_root / relative_file

            if not abs_file.exists():
                self._sanitize_location(issue)
                continue

            location = issue.get("location", "")
            if self._should_resolve_location_from_function(func_name, location, abs_file):
                self._apply_function_offset_location(issue, func_info, relative_file, location)

            snippet = issue.get("code_snippet")
            if not snippet:
                continue
                
            try:
                if abs_file in file_cache:
                    content = file_cache[abs_file]
                else:
                    with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    file_cache[abs_file] = content
                
                # Clean snippet for better matching: strip and ignore common prefix/suffix artifacts
                clean_snippet = snippet.strip().strip('`').strip()
                if not clean_snippet:
                    continue
                    
                # Search for the snippet
                # 1. Exact match
                index = content.find(clean_snippet)
                if index == -1:
                    # 2. Try matching without leading/trailing whitespace lines
                    lines = [line.strip() for line in clean_snippet.split('\n') if line.strip()]
                    if lines:
                        first_line = lines[0]
                        if len(first_line) > 10:
                            index = content.find(first_line)
                
                if index != -1:
                    # Calculate line number
                    line_no = content[:index].count("\n") + 1
                    issue["location"] = f"{relative_file}:{line_no}"
                    logger.info(f"Resolved location for {issue.get('id')} to {issue['location']}")
                else:
                    logger.debug(f"Could not resolve location for {issue.get('id')} using snippet")
                    
            except Exception as e:
                logger.error(f"Error resolving location for {issue.get('id')}: {e}")

    def _should_resolve_location_from_function(self, func_name: str, location: str, abs_file: Path) -> bool:
        if not location or location.startswith("unknown"):
            return True

        file_part = location.split(":")[0]
        # 判断 file_part 是否像源文件路径（有扩展名），而非函数名
        source_extensions = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}
        has_source_ext = any(file_part.endswith(ext) for ext in source_extensions)
        if not has_source_ext:
            return True

        return False

    def _sanitize_location(self, issue: Dict[str, Any]) -> None:
        """清洗 location 中弱模型产生的垃圾 token（如"会社""bubble"等）。"""
        location = issue.get("location", "")
        if not location or ":" not in location:
            return
        func_part, line_part = location.split(":", 1)
        nums = re.findall(r"\d+", line_part)
        if len(nums) >= 2:
            issue["location"] = f"{func_part}:{nums[0]}-{nums[1]}"
        elif len(nums) == 1:
            issue["location"] = f"{func_part}:{nums[0]}"

    def _apply_function_offset_location(
        self, issue: Dict[str, Any], func_info: Dict[str, Any], relative_file: str, location: str
    ) -> None:
        start_line = func_info.get("start_line")
        end_line = func_info.get("end_line")
        if not start_line or not end_line:
            return

        offset_start = None
        offset_end = None

        if location and ":" in location:
            _, line_part = location.split(":", 1)
            # 用正则提取数字，容忍弱模型在偏移后附加的乱码字符
            nums = re.findall(r"\d+", line_part)
            if len(nums) >= 2:
                offset_start = int(nums[0])
                offset_end = int(nums[1])
            elif len(nums) == 1:
                offset_start = int(nums[0])

        max_offset = max(1, end_line - start_line + 1)
        if offset_start and offset_start >= 1:
            # 截断到有效范围，容忍弱模型数行数不准
            clamped_start = min(offset_start, max_offset)
            mapped_start = start_line + clamped_start - 1
            if offset_end is not None and offset_end >= clamped_start:
                clamped_end = min(offset_end, max_offset)
                mapped_end = start_line + clamped_end - 1
                issue["location"] = f"{relative_file}:{mapped_start}-{mapped_end}"
            else:
                issue["location"] = f"{relative_file}:{mapped_start}"
            return

        issue["location"] = f"unresolved:{location}" if location else "unresolved"

    def _filter_false_positives(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out issues that have been marked as false positives."""
        filtered = []
        for issue in issues:
            if not isinstance(issue, dict):
                filtered.append(issue)
                continue
            func = issue.get("function", "")
            loc = issue.get("location", "")
            subcat = issue.get("subcategory", "")
            if self.user_config.is_false_positive(func, loc, subcat):
                logger.info(f"Filtering false positive: {issue.get('id')} in {func}")
                continue
            filtered.append(issue)
        return filtered
