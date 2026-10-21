"""
SVF output parser — parses callgraph DOT and saber bug reports,
maps LLVM IR locations back to C source via DWARF debug info.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# DOT 边: "Node0x..." -> "Node0x..."，可带 source port 和属性。
_DOT_EDGE_RE = re.compile(
    r'"?Node(?P<caller>0x[\da-fA-F]+)"?(?::(?P<caller_port>\w+))?\s*'
    r'->\s*"?Node(?P<callee>0x[\da-fA-F]+)"?\s*(?P<attributes>\[[^\]]*\])?'
)
_DOT_COLOR_RE = re.compile(r'\bcolor\s*=\s*"?(?P<color>[a-zA-Z]+)"?')
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
        """返回 DOT 中所有边的 {caller: [callee, ...]} 映射，保留旧调用方兼容。"""
        edges = self.parse_edges(dot_path)
        cg: Dict[str, List[str]] = {}
        for edge in edges:
            caller = edge["caller"]
            callee = edge["callee"]
            if callee not in cg.get(caller, []):
                cg.setdefault(caller, []).append(callee)
        logger.info("Parsed callgraph: %d callers, %d edges", len(cg), len(edges))
        return cg

    def parse_edges(self, dot_path: Path) -> List[Dict[str, str]]:
        """Return DOT edges with the SVF color and caller source port preserved."""
        text = dot_path.read_text(encoding="utf-8", errors="ignore")

        # 1. 建立 node_id → func_name 映射（先尝试 SVF 3.x 格式，再回退 2.x）
        node_map: Dict[str, str] = {}
        for m in _DOT_NODE_RE_V3.finditer(text):
            node_map[m.group(1)] = m.group(2).strip()
        if not node_map:
            for m in _DOT_NODE_RE_V2.finditer(text):
                node_map[m.group(1)] = m.group(2).strip()

        # 2. 解析边和 SVF 的间接调用标记（red）。
        edges: List[Dict[str, str]] = []
        seen: set[Tuple[str, str, str, str]] = set()
        for m in _DOT_EDGE_RE.finditer(text):
            caller = node_map.get(m.group("caller"), "")
            callee = node_map.get(m.group("callee"), "")
            if not caller or not callee:
                continue
            attributes = m.group("attributes") or ""
            color_match = _DOT_COLOR_RE.search(attributes)
            edge_color = color_match.group("color").lower() if color_match else ""
            caller_port = m.group("caller_port") or ""
            key = (caller, callee, caller_port, edge_color)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                {
                    "caller": caller,
                    "callee": callee,
                    "edge_color": edge_color,
                    "caller_port": caller_port,
                }
            )
        return edges


class SvfOutputMapper:
    """将 SVF 分析结果映射回源码并写入 KnowledgeDB。"""

    def __init__(
        self,
        db,
        svf_group: str = "default",
        project_root: Optional[Path] = None,
        tu_identities: Optional[Mapping[str, Any]] = None,
    ):
        """db: KnowledgeDB 实例。

        ``tu_identities`` is the group's per-TU compile-command identity
        (``BitcodeBuilder.group_tu_identities``). Attribution is a verdict, never
        a guess: a location is ``exact`` only when it names one translation-unit
        source of this group compiled under exactly one command id. Header
        locations, sources linked under several command ids (the default when a
        group mixes macro variants) and unknown paths stay ``ambiguous`` /
        ``unattributed`` so no instance can inherit them.
        """
        self.db = db
        self.svf_group = svf_group
        self.project_root = Path(project_root) if project_root else None
        self.source_to_command_ids: Dict[str, Set[str]] = {}
        self.tu_sources: Set[str] = set()
        rows = (tu_identities or {}).get("tus") if isinstance(tu_identities, dict) else None
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            source = str(row.get("source") or "")
            command_id = str(row.get("command_id") or "")
            if not source or not command_id:
                continue
            self.tu_sources.add(source)
            self.source_to_command_ids.setdefault(source, set()).add(command_id)

    def attribution(self, raw_path: Any) -> Tuple[str, str]:
        """Return ``(command_id, verdict)`` for one reported location."""

        path = self._normalize_signal_path(raw_path)
        if not path:
            return "", "unattributed"
        if path not in self.tu_sources:
            # A header/inline location belongs to every TU that includes it; a
            # path outside the group's TU set is not evidence for any instance.
            return "", (
                "ambiguous"
                if self.project_root and (self.project_root / path).exists()
                else "unattributed"
            )
        command_ids = self.source_to_command_ids.get(path) or set()
        if len(command_ids) != 1:
            return "", "ambiguous"
        return next(iter(command_ids)), "exact"

    def _normalize_signal_path(self, raw_path: Any) -> str:
        text = str(raw_path or "").strip()
        if not text:
            return ""
        candidate = Path(text)
        if not candidate.is_absolute() and self.project_root:
            candidate = self.project_root / candidate
        if self.project_root:
            for base, label in ((self.project_root, ""), (self.project_root.resolve(), "")):
                try:
                    return candidate.resolve().relative_to(base.resolve()).as_posix()
                except (ValueError, OSError):
                    continue
        return candidate.as_posix()

    def import_callgraph(
        self,
        dot_path: Path,
        existing_edges: Optional[Dict] = None,
        *,
        commit: bool = True,
    ) -> int:
        """将 SVF 调用图中的间接调用边导入 DB。

        只导入现有 direct call_edges 中不存在的边（即 SVF 解析出的间接调用）。
        """
        edges = CallGraphParser().parse_edges(dot_path)
        count = 0
        # 缓存 caller → file_path 映射，避免重复查询
        caller_file_cache: Dict[str, str] = {}
        pointer_contexts: Dict[str, List[Dict[str, str]]] = {}
        for edge in edges:
            if edge["edge_color"] != "red":
                continue
            caller = edge["caller"]
            if caller not in pointer_contexts:
                pointer_contexts[caller] = self._pointer_callsite_contexts(caller)

        for edge in edges:
            if edge["edge_color"] != "red":
                continue
            caller = edge["caller"]
            if caller not in caller_file_cache:
                info = self.db.get_function(caller) if hasattr(self.db, "get_function") else None
                caller_file_cache[caller] = info["file_path"] if info else ""
            call_file = caller_file_cache[caller]
            context = self._unique_compatible_pointer_context(
                edge["callee"],
                pointer_contexts.get(caller, []),
            )
            call_line = int(context.get("call_line") or 0) if context else 0
            callsite_id = (
                f"source:{call_line}:{context['pointer_symbol']}"
                if context
                else (f"svf:{edge['caller_port']}" if edge["caller_port"] else "")
            )
            command_id, attribution = self.attribution(call_file)
            inserted = self.db.insert_indirect_call(
                caller,
                edge["callee"],
                "svf-ander",
                call_file=call_file,
                call_line=call_line,
                svf_group=self.svf_group,
                callsite_id=callsite_id,
                command_id=command_id,
                attribution=attribution,
                pointer_symbol=str(context.get("pointer_symbol") or "") if context else "",
                pointer_kind=(
                    str(context.get("pointer_kind") or "unknown") if context else "unknown"
                ),
                pointer_type=str(context.get("pointer_type") or "") if context else "",
                pointer_signature=str(context.get("pointer_signature") or "") if context else "",
                callsite_expression=(
                    str(context.get("callsite_expression") or "") if context else ""
                ),
            )
            count += int(inserted if inserted is not None else 1)
        if commit:
            self.db.commit()
        logger.info("Imported %d indirect call edges from SVF", count)
        return count

    def _pointer_callsite_contexts(self, caller: str) -> List[Dict[str, str]]:
        if not self.project_root or not hasattr(self.db, "get_call_edge_records"):
            return []
        info = self.db.get_function(caller) if hasattr(self.db, "get_function") else None
        call_file = str(info.get("file_path") or "") if info else ""
        source_path = self.project_root / call_file
        try:
            source_lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        records = self.db.get_call_edge_records(caller, caller_file=call_file)
        contexts: List[Dict[str, str]] = []
        for record in records:
            line = int(record.get("call_line") or 0)
            name = str(record.get("name") or "")
            if line <= 0 or not name or line > len(source_lines):
                continue
            context = self._pointer_context_from_source_line(
                source_lines,
                line,
                name,
                caller,
                str(info.get("signature") or "") if info else "",
            )
            if context:
                contexts.append(context)
        return contexts

    def _pointer_context_from_source_line(
        self,
        source_lines: List[str],
        line: int,
        pointer_name: str,
        caller: str,
        caller_signature: str,
    ) -> Optional[Dict[str, str]]:
        raw_line = source_lines[line - 1]
        escaped = re.escape(pointer_name)
        member = re.search(rf"(?P<expr>[A-Za-z_]\w*\s*(?:->|\.)\s*{escaped})\s*\(", raw_line)
        expression = ""
        pointer_kind = ""
        pointer_type = ""
        pointer_symbol = ""
        prefix = "\n".join(source_lines[:line])
        if member:
            expression = re.sub(r"\s+", "", member.group("expr"))
            base = re.split(r"->|\.", expression, maxsplit=1)[0]
            variable = re.search(rf"\b(?P<type>[A-Za-z_]\w*)\s+\**\s*{re.escape(base)}\b", prefix)
            if not variable or not hasattr(self.db, "get_type_info"):
                return None
            container_type = str(variable.group("type") or "")
            container = self.db.get_type_info(container_type) or {}
            definition = str(container.get("full_definition") or "")
            member_type = re.search(rf"\b(?P<type>[A-Za-z_]\w*)\s+{escaped}\s*;", definition)
            if not member_type:
                return None
            pointer_type = str(member_type.group("type") or "")
            pointer_kind = "field"
            pointer_symbol = f"{container_type}.{pointer_name}"
        else:
            local = re.search(rf"(?P<expr>\(\s*\*\s*{escaped}\s*\)|{escaped})\s*\(", raw_line)
            if not local:
                return None
            expression = re.sub(r"\s+", "", local.group("expr"))
            declaration = re.search(rf"\b(?P<type>[A-Za-z_]\w*)\s+(?:\*\s*)?{escaped}\b", prefix)
            if not declaration:
                return None
            pointer_type = str(declaration.group("type") or "")
            parameter_match = re.search(
                rf"\b{re.escape(pointer_type)}\b\s+(?:\*\s*)?{escaped}\b",
                caller_signature,
            )
            pointer_kind = "parameter" if parameter_match else "local"
            pointer_symbol = f"{caller}.{pointer_name}"
        pointer_info = self.db.get_type_info(pointer_type) or {}
        pointer_signature = self._typedef_pointer_signature(
            str(pointer_info.get("full_definition") or "")
        )
        if not pointer_signature:
            return None
        return {
            "call_line": str(line),
            "pointer_symbol": pointer_symbol,
            "pointer_kind": pointer_kind,
            "pointer_type": pointer_type,
            "pointer_signature": pointer_signature,
            "callsite_expression": expression,
        }

    def _unique_compatible_pointer_context(
        self,
        callee: str,
        contexts: List[Dict[str, str]],
    ) -> Optional[Dict[str, str]]:
        function = self.db.get_function(callee) if hasattr(self.db, "get_function") else None
        signature = str(function.get("signature") or "") if function else ""
        function_shape = self._function_pointer_shape(signature, callee)
        if not function_shape:
            return None
        matches = [
            context
            for context in contexts
            if self._function_pointer_shape(context["pointer_signature"], "") == function_shape
        ]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _typedef_pointer_signature(definition: str) -> str:
        match = re.search(
            r"typedef\s+(?P<return>.+?)\s*\(\s*\*\s*[A-Za-z_]\w*\s*\)\s*\((?P<params>[^)]*)\)",
            definition,
        )
        if not match:
            return ""
        return f"{match.group('return').strip()} (*)({match.group('params').strip()})"

    @staticmethod
    def _function_pointer_shape(signature: str, name: str) -> str:
        text = " ".join(str(signature or "").replace("\n", " ").split())
        if "(*)" in text:
            match = re.match(r"(?P<return>.+?)\s*\(\*\)\s*\((?P<params>.*)\)$", text)
        else:
            match = re.match(
                rf"(?P<return>.+?)\s+{re.escape(name)}\s*\((?P<params>.*)\)$",
                text,
            )
        if not match:
            return ""

        def normalize_params(value: str) -> str:
            parts = []
            for raw in value.split(","):
                part = " ".join(raw.split())
                tokens = part.replace("*", " * ").split()
                if len(tokens) > 1 and tokens[-1] != "*":
                    tokens = tokens[:-1]
                parts.append(" ".join(tokens).replace(" *", "*"))
            return ",".join(parts)

        return_type = re.sub(r"\b(?:static|extern|inline)\b", "", match.group("return"))
        return_type = " ".join(return_type.split())
        return f"{return_type} (*)({normalize_params(match.group('params'))})"

    def import_saber_bugs(
        self,
        bugs: List[Dict[str, Any]],
        *,
        commit: bool = True,
    ) -> int:
        """将 saber 检测到的 bug 写入 taint_signatures 表。"""
        count = 0
        for bug in bugs:
            command_id, attribution = self.attribution(bug.get("file"))
            inserted = self.db.insert_taint_signature(
                source_func="",
                sink_func="",
                bug_type=bug.get("type", ""),
                file_path=bug.get("file", ""),
                line=bug.get("line", 0),
                tool="saber",
                svf_group=self.svf_group,
                command_id=command_id,
                attribution=attribution,
            )
            count += int(inserted if inserted is not None else 1)
        if commit:
            self.db.commit()
        logger.info("Imported %d saber bugs (group: %s)", count, self.svf_group)
        return count
