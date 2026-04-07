"""
Alert adapter base class and data models for third-party tool alert verification.
Standardizes alerts from different tools (CodeQL, Coverity, etc.) into a common format.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ExternalAlert:
    """标准化的外部工具告警。"""

    tool: str                    # 来源工具名 (codeql, coverity, etc.)
    rule_id: str                 # 规则 ID
    message: str                 # 告警描述
    file_path: str               # 告警所在文件
    line: int                    # 告警行号
    severity: AlertSeverity = AlertSeverity.MEDIUM
    category: str = ""           # 缺陷类别 (memory, concurrency, etc.)
    function: str = ""           # 所在函数名
    column: int = 0
    end_line: int = 0
    code_flows: List[Dict] = field(default_factory=list)  # SARIF codeFlows
    raw: Dict[str, Any] = field(default_factory=dict)     # 原始数据


class AlertAdapter(ABC):
    """告警适配器抽象基类。将第三方工具输出转换为 ExternalAlert 列表。"""

    @abstractmethod
    def parse(self, source: str) -> List[ExternalAlert]:
        """解析告警源（文件路径或内容），返回标准化告警列表。"""
        ...

    @abstractmethod
    def tool_name(self) -> str:
        """返回工具名称标识。"""
        ...
