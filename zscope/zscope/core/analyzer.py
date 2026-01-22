"""
Main analyzer logic for Z-SCOPE.
Orchestrates the analysis process using LLM, CodeIndex, and SnapshotStore.
"""

import json
import logging
import time
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from ..config.config import ZScopeConfig
from ..retrieval.code_index import CodeIndex
from .snapshot_store import SnapshotStore
from .tools_runtime import ToolsRuntime
from ..framework.llm_client import LLMClient
from ..agents.semantic_modeler.agent import SemanticModeler
from ..agents.vulnerability_analyzer.agent import VulnerabilityAnalyzer
from .report import FinalReport, Issue, ReportGenerator
from ..common.utils import validate_json_schema

logger = logging.getLogger(__name__)


# System Prompt Definitions
SYSTEM_PROMPT = """
You are Z-SCOPE, an advanced static analysis engine for C/C++ projects.
Your goal is to detect REAL defects (functionality bugs, reliability issues, performance bottlenecks, race conditions, resource leaks).
DO NOT report stylistic issues, naming conventions, or readability suggestions.

PROCESS:
1. You will be given an entry function to analyze.
2. You must analyze it thoroughly, understanding its logic, resource management, and error handling.
3. If the function calls other functions in the project, use the 'get_function_impl' or 'get_function_snapshot' tools to understand them.
   - Do not guess what a callee does if it's critical to the correctness of the caller.
   - You don't need to analyze generic C standard library functions (like malloc, printf) unless misused.
4. Maintain a depth-limited analysis (default max depth 3).
5. For every function you analyze, you MUST produce a 'function_snapshot' JSON summary. This serves as a cache for future analysis.
6. Finally, produce a 'final_report' JSON with all found issues.

OUTPUT FORMATS:
You must strictly output JSON blocks for specific phases.

[Schema: Function Snapshot] - Output this when you have finished analyzing a specific function.
{
  "type": "function_snapshot",
  "func_name": "...",
  "location": "path:line-line",
  "summary": "Brief semantic summary...",
  "inputs": [{"name":"...","type":"...","role":"..."}],
  "outputs": [{"kind":"return","type":"...","meaning":"..."}],
  "resources": {
    "allocates_memory": true/false,
    "frees_memory": true/false,
    "locks": [{"lock":"...","mode":"...","balanced":true/false}],
    "file_io": true/false,
    "network_io": true/false
  },
  "error_handling": {
    "checks_parameters": true/false,
    "checks_alloc_failure": true/false,
    "rollback_on_error": "none|partial|full"
  },
  "concurrency": {
    "thread_safe": "unknown|likely_yes|likely_no",
    "uses_global_state": true/false
  },
  "semantic_fingerprint": {
    "normalized_hash_hint": "string summary of logic for change detection",
    "key_semantics": ["invariant1", "invariant2"]
  },
  "suspicious_points": [
    {
      "location": "path:line",
      "type": "bug_type",
      "description": "...",
      "confidence": 0.0-1.0,
      "impact_category": "functionality|reliability|performance"
    }
  ],
  "callees": ["func1", "func2"]
}

[Schema: Final Report] - Output this when you are done with the entire task.
{
  "type": "final_report",
  "entry_function": "...",
  "overall_verdict": "no_issue_found|issues_found|insufficient_info",
  "issues": [
    {
      "id": "unique_id",
      "function": "...",
      "location": "Optional guess of location",
      "code_snippet": "Exact problematic code snippet from the source (IMPORTANT: This will be used to find the exact line number)",
      "category": "functionality|reliability|performance",
      "subcategory": "e.g. memory_leak",
      "description": "...",
      "root_cause": "...",
      "suggested_fix": "...",
      "confidence": 0.8,
      "impact_level": "low|medium|high|critical"
    }
  ],
  "notes": ["..."]
}

[Schema: Refresh Decision] - Output this when asked to compare old snapshot with new code.
{
  "type": "snapshot_refresh_decision",
  "func_name": "...",
  "refresh_needed": true/false,
  "reason": "...",
  "what_changed": ["..."],
  "risk_if_not_refreshed": "low|medium|high"
}
"""


class Analyzer:
    """
    Main analyzer class.
    """

    def __init__(self, config: ZScopeConfig):
        self.config = config
        self.code_index = CodeIndex(
            config.project.project_root, config.project.compile_commands_path
        )
        self.snapshot_store = SnapshotStore(Path(config.analysis.snapshot_dir))
        self.llm_client = LLMClient(
            api_key=config.llm.api_key,
            base_url=config.llm.base_url,
            models=config.llm.models,
            timeout=config.llm.timeout,
            max_retries=config.llm.max_retries
        )
        self.report_generator = ReportGenerator(config.project.project_root)
        
        self.analyzed_functions: Set[str] = set()
        self.issues: List[Issue] = []

    def run(self) -> Dict[str, Any]:
        """Run the multi-agent analysis."""
        entry_func = self.config.project.entry_function
        logger.info(f"Starting multi-agent analysis on entry function: {entry_func}")

        impl_result = self.code_index.get_function_impl(entry_func)
        if not impl_result:
            return {"error": "Entry function not found"}

        # Initialize common context
        agent_context = {
            "func_name": entry_func,
            "code": impl_result["code"],
            "location": f"{impl_result['file']}:{impl_result['start_line']}"
        }

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
        for agent_cfg in self.config.project.agents:
            if not agent_cfg.enabled or agent_cfg.name != "vulnerability_analyzer":
                continue
            
            logger.info(f"Running Vulnerability Analyzer agent for task: {agent_cfg.task}")
            agent_context["task"] = agent_cfg.task
            v_resp = analyzer_agent.run(agent_context)
            
            if v_resp.success:
                issues.extend(v_resp.data.get("issues", []))
                notes.append(f"Analyzed task: {agent_cfg.task}")
            else:
                logger.error(f"Vulnerability analysis failed: {v_resp.error}")
                notes.append(f"Vulnerability analysis failed: {v_resp.error}")

        # 3. Resolve locations using snippets
        self._resolve_issue_locations(issues)

        # Construct Final Report
        final_report = FinalReport(
            entry_function=entry_func,
            overall_verdict="issues_found" if issues else "no_issue_found",
            issues=[Issue(**i) for i in issues if isinstance(i, dict)] or [i for i in issues if isinstance(i, Issue)],
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
        from ..tools.utils import ListFunctionsTool, GetFileSnippetTool
        
        return [
            GetFunctionImplTool(self.code_index),
            GetFunctionSnapshotTool(self.snapshot_store),
            ListFunctionsTool(self.code_index),
            GetFileSnippetTool(self.code_index)
        ]

        # CRITICAL FIX: Explicitly demand JSON final_report if not provided
        final_content = result["content"]
        
        # Check if LLM already provided final_report
        if '"type": "final_report"' not in final_content and '"type":"final_report"' not in final_content:
            logger.info("LLM did not provide final_report, requesting explicitly...")
            
            # Add explicit request for final report
            conversation = result["conversation"]
            final_report_prompt = """
You have completed your analysis. Now you MUST output the final_report JSON.

Based on your analysis, create a JSON object with this EXACT structure:
```json
{
  "type": "final_report",
  "entry_function": "cache_get",
  "overall_verdict": "issues_found",
  "issues": [
    {
      "id": "ISSUE_1",
      "function": "function_name",
      "location": "filename:line (optional guess)",
      "code_snippet": "Exact code snippet from the source (used to resolve accurate location)",
      "category": "reliability",
      "subcategory": "buffer_overflow|memory_leak|resource_leak|etc",
      "description": "Clear description of the defect",
      "root_cause": "Why this happens",
      "suggested_fix": "How to fix it",
      "confidence": 0.9,
      "impact_level": "critical|high|medium|low"
    }
  ],
  "notes": ["Any additional observations"]
}
```

Output ONLY the JSON, no other text. If you found defects, list them all. If you found no defects, use "overall_verdict": "no_issue_found" with empty issues array.
"""
            conversation.append({"role": "user", "content": final_report_prompt})
            
            # Get final response
            try:
                final_response = self.llm_client.chat_completion(conversation, max_tokens=4096)
                final_content = final_response["choices"][0]["message"]["content"]
                logger.info("Received explicit final_report response")
            except Exception as e:
                logger.error(f"Failed to get final report: {e}")
                # Keep original content

        # Process final result
        final_report = self._extract_final_report(final_content)
        
        if not final_report:
            # If LLM didn't output a JSON report, try to parse what it said or force a report
            logger.warning("No structured final report found in LLM output. Attempting fallback.")
            # In a real system, we might ask LLM to format it again. 
            # For now, we wrap the text content.
            final_report = FinalReport(
                entry_function=entry_func,
                overall_verdict="insufficient_info",
                notes=[f"LLM did not provide structured output. Raw output: {final_content[:500]}..."]
            )

        # Update metadata
        final_report.metadata = {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "0.1.0",
            "iterations": result.get("iterations", 0),
        }

        # Save reports
        json_path = self.report_generator.save_json_report(final_report)
        md_path = self.report_generator.save_markdown_report(final_report)

        logger.info(f"Analysis complete. Report saved to {json_path} and {md_path}")
        return final_report.to_dict()

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
            issues = [Issue(**i) for i in data.get("issues", [])]
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
        Extract JSON block from text. 
        Handles markdown code blocks and raw JSON.
        """
        # Try finding markdown code blocks first
        import re
        matches = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        
        candidates = matches + [text]
        
        for candidate in candidates:
            try:
                # Naive cleanup for non-strict JSON logic if needed, but lets try parse
                data = json.loads(candidate)
                if isinstance(data, dict):
                    if type_hint and data.get("type") != type_hint:
                        continue
                        
                    # Also, if we find a snapshot, save it!
                    if data.get("type") == "function_snapshot":
                        self._save_snapshot_from_llm(data)
                        
                    return data
            except json.JSONDecodeError:
                continue
                
        # Fallback: try finding just the { ... } object if mixed with text and no backticks
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                json_str = text[start : end + 1]
                data = json.loads(json_str)
                if type_hint and data.get("type") == type_hint:
                    return data
                if data.get("type") == "function_snapshot":
                    self._save_snapshot_from_llm(data)
                    if type_hint == "function_snapshot": 
                         return data
        except:
            pass
            
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
        for issue in issues:
            if not isinstance(issue, dict):
                continue
                
            snippet = issue.get("code_snippet")
            if not snippet:
                continue
                
            func_name = issue.get("function")
            if not func_name:
                continue
                
            # Try to find the file from the function name
            func_info = self.code_index.get_function_impl(func_name)
            if not func_info:
                continue
                
            relative_file = func_info["file"]
            abs_file = self.config.project.project_root / relative_file
            
            if not abs_file.exists():
                continue
                
            try:
                with open(abs_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
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
