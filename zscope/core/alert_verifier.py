"""
Alert verification orchestrator.
Takes external alerts (SARIF etc.), enriches them with code context from CodeIndex,
then uses the Validator Agent to confirm or reject each alert.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..retrieval.code_index import CodeIndex
from .alert_adapter import AlertAdapter, ExternalAlert, AlertSeverity
from .tools_runtime import ToolsRuntime
from ..framework.llm_client import LLMClient
from .report import FinalReport, Issue, ReportGenerator

logger = logging.getLogger(__name__)

# 验证 Agent 的 system prompt
VERIFY_SYSTEM_PROMPT = """你是 Z-SCOPE 的告警验证 Agent。
你的任务是对第三方静态分析工具（如 CodeQL）报告的告警进行交叉验证。

你会收到：
1. 告警信息（工具名、规则ID、描述、位置）
2. 告警所在函数的源码
3. 调用上下文（caller/callee 信息）

你需要：
1. 仔细阅读告警描述和相关代码
2. 使用工具获取更多上下文（callee 实现、类型定义等）
3. 判断告警是否为真实缺陷

【输出格式】
分析完成后输出一个 JSON 代码块：

```json
{
  "type": "alert_verification",
  "alert_id": "ALERT_1",
  "verdict": "confirmed",
  "confidence": 0.85,
  "reasoning": "中文详细理由",
  "severity_adjustment": "",
  "missing_context": []
}
```

verdict 取值: confirmed / rejected / uncertain
severity_adjustment: 为空表示不调整，否则为建议的新严重级别
"""


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
        self.tools_runtime = ToolsRuntime(
            code_index=code_index,
            user_config_store=user_config,
        )

    def verify_alerts(
        self,
        alerts: List[ExternalAlert],
        max_workers: int = 1,
    ) -> List[Dict[str, Any]]:
        """验证一批外部告警，返回验证结果列表。"""
        results = []
        total = len(alerts)
        logger.info("Starting verification of %d alerts", total)

        for idx, alert in enumerate(alerts, 1):
            logger.info(
                "[%d/%d] Verifying %s:%d (%s)",
                idx, total, alert.file_path, alert.line, alert.rule_id,
            )
            try:
                result = self._verify_single(alert, idx)
                results.append(result)
            except Exception as e:
                logger.error("Failed to verify alert %d: %s", idx, e)
                results.append(self._make_error_result(alert, idx, str(e)))

        confirmed = sum(1 for r in results if r.get("verdict") == "confirmed")
        rejected = sum(1 for r in results if r.get("verdict") == "rejected")
        uncertain = sum(1 for r in results if r.get("verdict") == "uncertain")
        logger.info(
            "Verification complete: %d confirmed, %d rejected, %d uncertain",
            confirmed, rejected, uncertain,
        )
        return results

    def _verify_single(self, alert: ExternalAlert, idx: int) -> Dict[str, Any]:
        """验证单个告警。"""
        alert_id = f"ALERT_{idx}"

        # 1. 收集代码上下文
        context = self._build_context(alert)

        # 2. 构建 prompt
        user_prompt = self._build_prompt(alert, alert_id, context)

        # 3. 调用 LLM 验证
        tools_schema = self.tools_runtime.get_tools_schema()
        messages = [{"role": "user", "content": user_prompt}]

        response = self.llm_client.chat_with_tools(
            system_prompt=VERIFY_SYSTEM_PROMPT,
            messages=messages,
            tools=tools_schema,
            tool_executor=self.tools_runtime.execute_tool,
            max_iterations=self.config.analysis.max_tool_iterations,
        )

        # 4. 解析验证结果
        result = self._parse_verification(response, alert, alert_id)
        return result

    def _build_context(self, alert: ExternalAlert) -> Dict[str, Any]:
        """为告警收集代码上下文。"""
        context = {"code_snippet": "", "callers": [], "callees": []}

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
        import re
        json_pattern = re.compile(r"```json\s*\n(.*?)\n\s*```", re.DOTALL)
        match = json_pattern.search(response or "")

        base = {
            "alert_id": alert_id,
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
        }

        if not match:
            logger.warning("No JSON block found in verification response for %s", alert_id)
            base.update({"verdict": "uncertain", "confidence": 0.0, "reasoning": "无法解析验证结果"})
            return base

        try:
            parsed = json.loads(match.group(1))
            base.update({
                "verdict": parsed.get("verdict", "uncertain"),
                "confidence": parsed.get("confidence", 0.0),
                "reasoning": parsed.get("reasoning", ""),
                "severity_adjustment": parsed.get("severity_adjustment", ""),
                "missing_context": parsed.get("missing_context", []),
            })
        except json.JSONDecodeError:
            base.update({"verdict": "uncertain", "confidence": 0.0, "reasoning": "JSON 解析失败"})

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
