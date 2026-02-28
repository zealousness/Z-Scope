"""
CodeQL SARIF adapter - parses SARIF v2.1.0 output into ExternalAlert format.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .alert_adapter import AlertAdapter, AlertSeverity, ExternalAlert

logger = logging.getLogger(__name__)

# SARIF level → AlertSeverity 映射
_LEVEL_MAP = {
    "error": AlertSeverity.HIGH,
    "warning": AlertSeverity.MEDIUM,
    "note": AlertSeverity.LOW,
    "none": AlertSeverity.INFO,
}

# CodeQL rule tag → category 映射
_CATEGORY_MAP = {
    "security": "security",
    "correctness": "correctness",
    "reliability": "reliability",
    "maintainability": "maintainability",
}


class SarifAdapter(AlertAdapter):
    """解析 SARIF v2.1.0 格式（CodeQL / Semgrep 等工具输出）。"""

    def __init__(self, source_root: Optional[str] = None):
        self._source_root = Path(source_root) if source_root else None

    def tool_name(self) -> str:
        return "sarif"

    def parse(self, source: str) -> List[ExternalAlert]:
        """解析 SARIF 文件，返回 ExternalAlert 列表。"""
        path = Path(source)
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="ignore")
        else:
            content = source

        try:
            sarif = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse SARIF JSON: %s", e)
            return []

        alerts = []
        for run in sarif.get("runs", []):
            tool_name = self._extract_tool_name(run)
            rules_map = self._build_rules_map(run)
            for result in run.get("results", []):
                alert = self._convert_result(result, tool_name, rules_map)
                if alert:
                    alerts.append(alert)

        logger.info("Parsed %d alerts from SARIF", len(alerts))
        return alerts

    # ── 内部辅助 ──

    def _extract_tool_name(self, run: Dict) -> str:
        tool = run.get("tool", {}).get("driver", {})
        return tool.get("name", "unknown").lower()

    def _build_rules_map(self, run: Dict) -> Dict[str, Dict]:
        """构建 ruleId → rule metadata 映射。"""
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        return {r.get("id", ""): r for r in rules}

    def _convert_result(
        self, result: Dict, tool_name: str, rules_map: Dict[str, Dict]
    ) -> Optional[ExternalAlert]:
        """将单个 SARIF result 转换为 ExternalAlert。"""
        rule_id = result.get("ruleId", "")
        message = self._extract_message(result)
        level = result.get("level", "warning")
        severity = _LEVEL_MAP.get(level, AlertSeverity.MEDIUM)

        # 从 rule metadata 提取 category
        category = ""
        rule_meta = rules_map.get(rule_id, {})
        for tag in rule_meta.get("properties", {}).get("tags", []):
            tag_lower = tag.lower()
            for key, cat in _CATEGORY_MAP.items():
                if key in tag_lower:
                    category = cat
                    break

        # 提取位置信息
        locations = result.get("locations", [])
        if not locations:
            return None
        loc = locations[0].get("physicalLocation", {})
        file_path = self._resolve_artifact(loc)
        if not file_path:
            return None

        region = loc.get("region", {})
        line = region.get("startLine", 0)
        column = region.get("startColumn", 0)
        end_line = region.get("endLine", line)

        # 提取 codeFlows
        code_flows = self._extract_code_flows(result)

        return ExternalAlert(
            tool=tool_name,
            rule_id=rule_id,
            message=message,
            file_path=file_path,
            line=line,
            severity=severity,
            category=category,
            column=column,
            end_line=end_line,
            code_flows=code_flows,
            raw=result,
        )

    def _extract_message(self, result: Dict) -> str:
        msg = result.get("message", {})
        return msg.get("text", msg.get("markdown", ""))

    def _resolve_artifact(self, physical_loc: Dict) -> str:
        """从 physicalLocation 提取文件路径。"""
        uri = physical_loc.get("artifactLocation", {}).get("uri", "")
        if not uri:
            return ""
        # 去掉 file:// 前缀
        if uri.startswith("file://"):
            uri = uri[7:]
        # 相对路径解析
        if self._source_root and not Path(uri).is_absolute():
            return str(self._source_root / uri)
        return uri

    def _extract_code_flows(self, result: Dict) -> List[Dict]:
        """提取 SARIF codeFlows 为简化格式。"""
        flows = []
        for cf in result.get("codeFlows", []):
            for thread_flow in cf.get("threadFlows", []):
                steps = []
                for loc_obj in thread_flow.get("locations", []):
                    pl = loc_obj.get("location", {}).get("physicalLocation", {})
                    file_path = self._resolve_artifact(pl)
                    region = pl.get("region", {})
                    msg = loc_obj.get("location", {}).get("message", {}).get("text", "")
                    steps.append({
                        "file": file_path,
                        "line": region.get("startLine", 0),
                        "message": msg,
                    })
                if steps:
                    flows.append({"steps": steps})
        return flows
