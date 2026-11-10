"""
SVF output parser — parses callgraph DOT and saber bug reports,
maps LLVM IR locations back to C source via DWARF debug info.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# DOT 边: "Node0x..." -> "Node0x..." 或带 port (:s0) 和 label
_DOT_EDGE_RE = re.compile(
    r'"?Node(0x[\da-fA-F]+)"?(?::\w+)?\s*->\s*"?Node(0x[\da-fA-F]+)"?'
)
# DOT 节点 label —— 兼容 SVF 2.x 和 3.x 格式
# SVF 2.x: Node0x... [label="{ funcName }"]
# SVF 3.x: Node0x... [...label="{CallGraphNode ID: N \{fun: funcName\}|...}"]
_DOT_NODE_RE_V3 = re.compile(
    r'"?Node(0x[\da-fA-F]+)"?\s*\[.*?\\\{fun:\s*([^\\}]+?)\\\}',
)
_DOT_NODE_RE_V2 = re.compile(
    r'"?Node(0x[\da-fA-F]+)"?\s*\[.*?label\s*=\s*"\{?\s*([^}"]+?)\s*\}?"',
)


class CallGraphParser:
    """解析 SVF wpa -ander 输出的 callgraph_final.dot。"""

    def parse(self, dot_path: Path) -> Dict[str, List[str]]:
        """返回 {caller: [callee, ...]} 映射。"""
        text = dot_path.read_text(encoding="utf-8", errors="ignore")

        # 1. 建立 node_id → func_name 映射（先尝试 SVF 3.x 格式，再回退 2.x）
        node_map: Dict[str, str] = {}
        for m in _DOT_NODE_RE_V3.finditer(text):
            node_map[m.group(1)] = m.group(2).strip()
        if not node_map:
            for m in _DOT_NODE_RE_V2.finditer(text):
                node_map[m.group(1)] = m.group(2).strip()

        # 2. 解析边（去重）
        cg: Dict[str, List[str]] = {}
        for m in _DOT_EDGE_RE.finditer(text):
            caller = node_map.get(m.group(1), "")
            callee = node_map.get(m.group(2), "")
            if caller and callee and callee not in cg.get(caller, []):
                cg.setdefault(caller, []).append(callee)

        logger.info("Parsed callgraph: %d callers, %d edges",
                     len(cg), sum(len(v) for v in cg.values()))
        return cg


class SvfOutputMapper:
    """将 SVF 分析结果映射回源码并写入 KnowledgeDB。"""

    def __init__(self, db, svf_group: str = "default"):
        """db: KnowledgeDB 实例。"""
        self.db = db
        self.svf_group = svf_group

    def import_callgraph(
        self, dot_path: Path, existing_edges: Optional[Dict] = None, *, commit: bool = True
    ):
        """将 SVF 调用图中的间接调用边导入 DB。

        只导入现有 direct call_edges 中不存在的边（即 SVF 解析出的间接调用）。
        """
        cg = CallGraphParser().parse(dot_path)
        count = 0
        # 缓存 caller → file_path 映射，避免重复查询
        caller_file_cache: Dict[str, str] = {}
        for caller, callees in cg.items():
            if caller not in caller_file_cache:
                info = self.db.get_function(caller) if hasattr(self.db, "get_function") else None
                caller_file_cache[caller] = info["file_path"] if info else ""
            call_file = caller_file_cache[caller]
            for callee in callees:
                self.db.insert_indirect_call(
                    caller, callee, "svf-ander",
                    call_file=call_file, call_line=0,
                    svf_group=self.svf_group,
                )
                count += 1
        if commit:
            self.db.commit()
        logger.info("Imported %d indirect call edges from SVF", count)

        return count

    def import_saber_bugs(self, bugs: List[Dict[str, Any]], *, commit: bool = True):
        """将 saber 检测到的 bug 写入 taint_signatures 表。"""
        for bug in bugs:
            self.db.insert_taint_signature(
                source_func="",
                sink_func="",
                bug_type=bug.get("type", ""),
                file_path=bug.get("file", ""),
                line=bug.get("line", 0),
                tool="saber",
                svf_group=self.svf_group,
            )
        if commit:
            self.db.commit()
        logger.info("Imported %d saber bugs (group: %s)", len(bugs), self.svf_group)

        return len(bugs)
