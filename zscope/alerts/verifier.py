"""
Alert verification orchestrator.
Takes external alerts (SARIF etc.), enriches them with code context from CodeIndex,
then uses the Validator Agent to confirm or reject each alert.
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..retrieval.code_index import CodeIndex
from .adapter import AlertAdapter, ExternalAlert, AlertSeverity
from ..snapshots.store import SnapshotStore
from ..tools.policy import ToolPolicy, deny_sensitive_paths_hook
from ..tools.runtime import ToolsRuntime
from ..framework.llm_client import LLMClient
from ..reporting.report import FinalReport, Issue, ReportGenerator
from ..orchestration.specs import SpecRegistry

logger = logging.getLogger(__name__)


class AlertVerifier:
    """告警验证编排器。"""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: CodeIndex,
        llm_client: LLMClient,
        user_config: Optional[UserConfigStore] = None,
    ):
        self.config = config
        self.code_index = code_index
        self.llm_client = llm_client
        self.user_config = user_config
        self.snapshot_store = SnapshotStore(Path(config.analysis.snapshot_dir))
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        self.tools_runtime = ToolsRuntime(
            code_index=code_index,
            snapshot_store=self.snapshot_store,
            user_config=user_config,
            tool_policy=ToolPolicy.allow_all(
                pre_hooks=[deny_sensitive_paths_hook],
                audit_log_path=self._tool_audit_log_path(),
            ),
        )

    def _tool_audit_log_path(self) -> Optional[Path]:
        configured = str(getattr(self.config.analysis, "tool_audit_log", "") or "").strip()
        if not configured:
            return None
        path = Path(configured)
        if path.is_absolute():
            return path
        return self.config.project.project_root / path

    def verify_alerts(
        self,
        alerts: List[ExternalAlert],
        max_workers: int = 1,
    ) -> List[Dict[str, Any]]:
        """验证一批外部告警，返回验证结果列表。"""
        total = len(alerts)
        logger.info("Starting verification of %d alerts", total)

        worker_count = self._worker_count(total, max_workers)
        if worker_count <= 1:
            results = [
                self._verify_alert_safely(alert, idx, total)
                for idx, alert in enumerate(alerts, 1)
            ]
        else:
            logger.info(
                "Verifying %d alert(s) with %d worker(s).",
                total,
                worker_count,
            )
            results_by_index: Dict[int, Dict[str, Any]] = {}
            with ThreadPoolExecutor(
                max_workers=worker_count,
                thread_name_prefix="zscope-alert-verifier",
            ) as executor:
                future_to_index = {
                    executor.submit(self._verify_alert_safely, alert, idx, total): idx
                    for idx, alert in enumerate(alerts, 1)
                }
                for future in as_completed(future_to_index):
                    idx = future_to_index[future]
                    try:
                        results_by_index[idx] = future.result()
                    except Exception as e:
                        alert = alerts[idx - 1]
                        logger.exception("Alert verification worker crashed for alert %d.", idx)
                        results_by_index[idx] = self._make_error_result(alert, idx, str(e))
            results = [results_by_index[idx] for idx in range(1, total + 1)]

        confirmed = sum(1 for r in results if r.get("verdict") == "confirmed")
        rejected = sum(1 for r in results if r.get("verdict") == "rejected")
        uncertain = sum(1 for r in results if r.get("verdict") == "uncertain")
        logger.info(
            "Verification complete: %d confirmed, %d rejected, %d uncertain",
            confirmed, rejected, uncertain,
        )
        return results

    def _worker_count(self, alert_count: int, max_workers: int) -> int:
        if alert_count <= 1:
            return 1
        try:
            requested = int(max_workers or 1)
        except (TypeError, ValueError):
            requested = 1
        return max(1, min(alert_count, requested))

    def _verify_alert_safely(
        self,
        alert: ExternalAlert,
        idx: int,
        total: int,
    ) -> Dict[str, Any]:
        logger.info(
            "[%d/%d] Verifying %s:%d (%s)",
            idx,
            total,
            alert.file_path,
            alert.line,
            alert.rule_id,
        )
        try:
            return self._verify_single(alert, idx)
        except Exception as e:
            logger.error("Failed to verify alert %d: %s", idx, e)
            return self._make_error_result(alert, idx, str(e))

    def _verify_single(self, alert: ExternalAlert, idx: int) -> Dict[str, Any]:
        """验证单个告警。"""
        alert_id = f"ALERT_{idx}"

        # 1. 收集代码上下文
        context = self._build_context(alert)

        # 2. 构建 prompt
        user_prompt = self._build_prompt(alert, alert_id, context)

        # 3. 调用 LLM 验证
        messages = [
            {"role": "system", "content": self._system_prompt()},
            {"role": "user", "content": user_prompt},
        ]

        response = self.llm_client.run_conversation_with_tools(
            messages=messages,
            tools_schema=self.tools_runtime.get_tools_schema(),
            tool_executor=self.tools_runtime.execute_tool,
            max_iterations=self.config.analysis.max_tool_iterations,
            trace_agent="alert_verifier",
            trace_label=f"alert={alert_id}; rule={alert.rule_id}; file={alert.file_path}:{alert.line}",
        )

        # 4. 解析验证结果
        result = self._parse_verification(response.get("content", ""), alert, alert_id)
        return result

    def _system_prompt(self) -> str:
        agent_spec = self.spec_registry.get_agent("alert_verifier")
        if not agent_spec:
            return "alert_verifier"
        return agent_spec.to_prompt_block()

    def _build_context(self, alert: ExternalAlert) -> Dict[str, Any]:
        """为告警收集代码上下文。"""
        context: Dict[str, Any] = {"code_snippet": "", "callers": [], "callees": []}

        # 获取告警所在位置的代码片段
        snippet = self.code_index.get_file_snippet(
            alert.file_path,
            max(1, alert.line - 10),
            (alert.end_line or alert.line) + 10,
        )
        if snippet:
            context["code_snippet"] = snippet.get("code", "")

        # 如果知道函数名，获取完整实现和调用关系
        if alert.function:
            impl = self.code_index.get_function_impl(alert.function)
            if impl:
                context["function_code"] = impl.get("code", "")
                context["callees"] = impl.get("callees", [])
            context["callers"] = self.code_index.get_callers(alert.function)

        return context

    def _build_prompt(
        self, alert: ExternalAlert, alert_id: str, context: Dict[str, Any]
    ) -> str:
        """构建发送给 LLM 的验证 prompt。"""
        parts = [
            f"## 待验证告警 [{alert_id}]",
            f"- 工具: {alert.tool}",
            f"- 规则: {alert.rule_id}",
            f"- 严重级别: {alert.severity.value}",
            f"- 文件: {alert.file_path}:{alert.line}",
            f"- 描述: {alert.message}",
        ]
        if alert.function:
            parts.append(f"- 函数: {alert.function}")
        if alert.category:
            parts.append(f"- 类别: {alert.category}")

        # 代码上下文
        code = context.get("function_code") or context.get("code_snippet", "")
        if code:
            parts.append(f"\n## 相关代码\n```c\n{code}\n```")

        # codeFlows（SARIF 数据流路径）
        if alert.code_flows:
            parts.append("\n## 数据流路径")
            for i, flow in enumerate(alert.code_flows):
                parts.append(f"### Flow {i + 1}")
                for step in flow.get("steps", []):
                    parts.append(
                        f"  - {step.get('file', '?')}:{step.get('line', '?')} "
                        f"— {step.get('message', '')}"
                    )

        parts.append(
            "\n请使用工具获取更多上下文后，输出验证结果 JSON。"
        )
        return "\n".join(parts)

    def _parse_verification(
        self, response: str, alert: ExternalAlert, alert_id: str
    ) -> Dict[str, Any]:
        """从 LLM 响应中解析验证结果 JSON。"""
        base = {
            "alert_id": alert_id,
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
        }

        from ..common.utils import extract_json_blocks

        candidates = extract_json_blocks(response or "")
        parsed = next(
            (
                item
                for item in candidates
                if isinstance(item, dict)
                and (item.get("type") == "alert_verification" or "verdict" in item)
            ),
            None,
        )

        if not parsed:
            logger.warning("No JSON block found in verification response for %s", alert_id)
            base.update({"verdict": "uncertain", "confidence": 0.0, "reasoning": "无法解析验证结果"})
            return base

        base.update({
            "verdict": parsed.get("verdict", "uncertain"),
            "confidence": parsed.get("confidence", 0.0),
            "reasoning": parsed.get("reasoning", ""),
            "severity_adjustment": parsed.get("severity_adjustment", ""),
            "missing_context": parsed.get("missing_context", []),
        })
        return base

    def _make_error_result(
        self, alert: ExternalAlert, idx: int, error: str
    ) -> Dict[str, Any]:
        return {
            "alert_id": f"ALERT_{idx}",
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
            "verdict": "uncertain",
            "confidence": 0.0,
            "reasoning": f"验证过程出错: {error}",
        }
