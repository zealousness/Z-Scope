"""
Joern CPG backend - wraps JoernClient into the CodeBackend interface.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from .backend_base import CodeBackend
from ..common.joern_client import JoernClient

logger = logging.getLogger(__name__)


class JoernBackend(CodeBackend):
    """
    基于 Joern CPG 的代码分析后端。
    封装 JoernClient，实现 CodeBackend 统一接口。
    """

    def __init__(
        self,
        joern_path: str = "joern",
        host: str = "127.0.0.1",
        port: int = 8080,
        heap_size: str = "8g",
        joern_client: Optional[JoernClient] = None,
    ):
        self._joern = joern_client or JoernClient(
            joern_path=joern_path, host=host, port=port, heap_size=heap_size
        )
        self._status = "idle"

    @property
    def joern_client(self) -> JoernClient:
        """供 RuleEngine 等 Joern 专属模块直接访问。"""
        return self._joern

    # ── 生命周期 ──

    def initialize(self, source_path: str, **kwargs) -> bool:
        project_root = kwargs.get("project_root")
        compile_commands_path = kwargs.get("compile_commands_path")
        wait = kwargs.get("wait", True)

        if not self._joern.start_server():
            self._status = "error"
            return False

        cc_path = str(compile_commands_path) if compile_commands_path else None
        pr_path = str(project_root) if project_root else None

        if wait:
            ok = self._joern.import_cpg(source_path, pr_path, cc_path)
            self._status = "ready" if ok else "error"
            return ok
        else:
            self._joern.import_cpg_async(source_path, pr_path, cc_path)
            self._status = "building"
            return True

    def wait_for_ready(self, timeout: Optional[int] = None) -> bool:
        """阻塞等待 CPG 就绪。"""
        ok = self._joern.wait_for_cpg(timeout=timeout)
        self._status = "ready" if ok else "error"
        return ok

    def close(self) -> None:
        self._joern.stop_server()
        self._status = "idle"

    def status(self) -> str:
        # 同步 JoernClient 内部状态
        if self._status == "building":
            js = self._joern.cpg_status
            if js == "ready":
                self._status = "ready"
            elif js == "error":
                self._status = "error"
        return self._status

    # ── 索引构建 ──

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        result = self._joern.query(
            'cpg.method.isExternal(false).map(m => Map('
            '"name" -> m.name, "filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1), '
            '"lineNumberEnd" -> m.lineNumberEnd.getOrElse(-1), '
            '"signature" -> m.signature'
            ')).l.toJson'
        )
        if not isinstance(result, list):
            logger.warning("Joern index query returned unexpected result")
            return {}
        index = {}
        for m in result:
            name = m.get("name", "")
            fname = m.get("filename", "")
            if not name or name.startswith("<") or not fname or fname.startswith("<"):
                continue
            index[name] = {
                "name": name,
                "file": fname,
                "start_line": m.get("lineNumber", -1),
                "end_line": m.get("lineNumberEnd", -1),
                "signature": m.get("signature", f"{name}(...)"),
            }
        return index

    # ── 查询方法 ──

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        return self._joern.get_method(name)

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self._joern.get_method_callees(name, limit=limit)

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        return self._joern.get_method_callers(
            func_name,
            limit=limit,
            callee_file=callee_file,
        )

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self._joern.get_method_callees(func_name, limit=limit)

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        decl = self._joern.get_type_decl(type_name)
        if not decl:
            return None
        members = self._joern.get_type_members(type_name)
        decl["members"] = members
        return decl

    def find_type_infos(
        self,
        type_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        matches = [dict(item) for item in self._joern.get_type_decls(type_name)]
        if file_path:
            normalized_hint = str(file_path).replace("\\", "/").strip().lstrip("./")
            matches = [
                item
                for item in matches
                if self._paths_match_type_file(
                    str(item.get("filename") or ""),
                    normalized_hint,
                )
            ]
        return matches

    @staticmethod
    def _paths_match_type_file(stored_path: str, hint_path: str) -> bool:
        stored = str(stored_path or "").replace("\\", "/").strip().lstrip("./")
        hint = str(hint_path or "").replace("\\", "/").strip().lstrip("./")
        return bool(
            stored
            and hint
            and (
                stored == hint
                or stored.endswith(f"/{hint}")
                or hint.endswith(f"/{stored}")
            )
        )

    def get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        return self._joern.get_data_flow_to_sink(source_func, source_param, sink_pattern)

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        return self._joern.find_function_pointers(func_name)

    def get_header_declared_functions(
        self, header_files: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        filter_clause = '.filter(_.filename.matches(".*\\\\.h$"))'
        if header_files:
            patterns = "|".join(re.escape(h) for h in header_files)
            filter_clause = f'.filter(_.filename.matches(".*({patterns})"))'
        result = self._joern.query(
            f'cpg.method.isExternal(false){filter_clause}'
            '.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1))).l.toJson'
        )
        if isinstance(result, list):
            return [r for r in result if r.get("name") and not r["name"].startswith("<")]
        return []
