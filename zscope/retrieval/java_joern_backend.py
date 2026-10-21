"""Java-specific Joern backend.

The core Z-SCOPE pipeline still talks in terms of "functions" for backward
compatibility. This backend maps Java methods onto that callable abstraction and
uses Joern method.fullName as the stable identity whenever possible.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..semantics.java_frameworks import build_java_framework_semantics
from .joern_backend import JoernBackend

logger = logging.getLogger(__name__)


def _scala_string(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def _java_simple_name(full_name: str) -> str:
    head = str(full_name or "").split(":", 1)[0]
    return head.rsplit(".", 1)[-1] if head else ""


def _java_class_name(full_name: str) -> str:
    head = str(full_name or "").split(":", 1)[0]
    if "." not in head:
        return ""
    owner = head.rsplit(".", 1)[0]
    return owner.rsplit(".", 1)[-1]


def _java_package_name(full_name: str) -> str:
    head = str(full_name or "").split(":", 1)[0]
    parts = [part for part in head.split(".") if part]
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def _annotation_projection(owner: str) -> str:
    return (
        f"{owner}.annotation.map(a => Map("
        '"name" -> a.name, '
        '"fullName" -> a.fullName, '
        '"code" -> a.code, '
        '"lineNumber" -> a.lineNumber.getOrElse(-1)'
        ")).l"
    )


def _method_metadata_projection() -> str:
    return (
        '"name" -> m.name, '
        '"fullName" -> m.fullName, '
        '"filename" -> m.filename, '
        '"lineNumber" -> m.lineNumber.getOrElse(-1), '
        '"lineNumberEnd" -> m.lineNumberEnd.getOrElse(-1), '
        '"signature" -> m.signature, '
        '"code" -> m.code, '
        f'"annotations" -> {_annotation_projection("m")}, '
        '"parameterAnnotations" -> m.parameter.filter(_.order > 0).map(p => Map('
        '"name" -> p.name, '
        '"typeFullName" -> p.typeFullName, '
        '"code" -> p.code, '
        f'"annotations" -> {_annotation_projection("p")}'
        ")).l, "
        f'"classAnnotations" -> {_annotation_projection("m.typeDecl")}'
    )


class JavaJoernBackend(JoernBackend):
    """Joern backend tuned for Java source CPGs."""

    def __init__(
        self,
        joern_path: str = "joern",
        host: str = "127.0.0.1",
        port: int = 8080,
        heap_size: str = "8g",
        joern_client: Optional[Any] = None,
    ):
        super().__init__(
            joern_path=joern_path,
            host=host,
            port=port,
            heap_size=heap_size,
            language="java",
            joern_client=joern_client,
        )
        self.language = "java"

    def _method_selector(self, name: str) -> str:
        escaped = _scala_string(name)
        return (
            "cpg.method.isExternal(false)"
            f'.filter(m => m.fullName == "{escaped}" || '
            f'm.fullName.startsWith("{escaped}:") || '
            f'm.name == "{escaped}")'
        )

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        result = self._joern.query(
            "cpg.method.isExternal(false)"
            '.filter(m => !m.name.startsWith("<operator>") && !m.name.startsWith("<"))'
            ".map(m => Map("
            f"{_method_metadata_projection()}"
            ")).l.toJson"
        )
        if not isinstance(result, list):
            logger.warning("Java Joern index query returned unexpected result")
            return {}

        index: Dict[str, Dict[str, Any]] = {}
        for method in result:
            if not isinstance(method, dict):
                continue
            simple_name = str(method.get("name") or "")
            full_name = str(method.get("fullName") or simple_name)
            filename = str(method.get("filename") or "")
            if not simple_name or not full_name or not filename or filename.startswith("<"):
                continue
            method_head = full_name.split(":", 1)[0]
            aliases = [simple_name, method_head]
            index[full_name] = {
                "name": simple_name,
                "qualified_name": full_name,
                "method_full_name": full_name,
                "class_name": _java_class_name(full_name),
                "package": _java_package_name(full_name),
                "file": filename,
                "start_line": method.get("lineNumber", -1),
                "end_line": method.get("lineNumberEnd", -1),
                "signature": method.get("signature", f"{simple_name}(...)"),
                "declaration_code": method.get("code", ""),
                "annotations": method.get("annotations", []),
                "parameter_annotations": method.get("parameterAnnotations", []),
                "class_annotations": method.get("classAnnotations", []),
                "framework_semantics": build_java_framework_semantics(method),
                "language": "java",
                "aliases": aliases,
            }
        return index

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        result = self._joern.query(
            f"{self._method_selector(name)}"
            ".map(m => Map("
            f"{_method_metadata_projection()}"
            ")).take(1).l.toJson"
        )
        if isinstance(result, list) and result:
            method = dict(result[0])
            full_name = str(method.get("fullName") or method.get("name") or name)
            method["qualified_name"] = full_name
            method["method_full_name"] = full_name
            method["declaration_code"] = method.get("code", "")
            method["parameter_annotations"] = method.get("parameterAnnotations", [])
            method["class_annotations"] = method.get("classAnnotations", [])
            method["framework_semantics"] = build_java_framework_semantics(method)
            method["language"] = "java"
            return method
        return None

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        result = self._joern.query(
            f"{self._method_selector(func_name)}.callIn.method.distinct"
            '.filter(m => !m.name.startsWith("<operator>"))'
            ".map(m => Map("
            '"name" -> m.name, '
            '"fullName" -> m.fullName, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1), '
            '"signature" -> m.signature, '
            '"language" -> "java"'
            f")).take({limit}).l.toJson"
        )
        return result if isinstance(result, list) else []

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        result = self._joern.query(
            f"{self._method_selector(func_name)}.callee.distinct"
            '.filter(m => !m.name.startsWith("<operator>"))'
            ".map(m => Map("
            '"name" -> m.name, '
            '"fullName" -> m.fullName, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1), '
            '"signature" -> m.signature, '
            '"language" -> "java"'
            f")).take({limit}).l.toJson"
        )
        return result if isinstance(result, list) else []

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self.get_callees(name, limit=limit)

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        escaped = _scala_string(type_name)
        result = self._joern.query(
            "cpg.typeDecl"
            f'.filter(t => t.fullName == "{escaped}" || t.name == "{escaped}")'
            ".map(t => Map("
            '"name" -> t.name, '
            '"fullName" -> t.fullName, '
            '"kind" -> "class_or_interface", '
            '"filename" -> t.filename, '
            '"lineNumber" -> t.lineNumber.getOrElse(-1), '
            '"members" -> t.member.map(m => Map('
            '"name" -> m.name, "typeFullName" -> m.typeFullName)).l'
            ")).take(1).l.toJson"
        )
        if isinstance(result, list) and result:
            info = dict(result[0])
            info["language"] = "java"
            return info
        return None

    def list_type_infos(self) -> List[Dict[str, Any]]:
        result = self._joern.query(
            "cpg.typeDecl.isExternal(false)"
            '.filter(t => !t.name.startsWith("<"))'
            ".map(t => Map("
            '"name" -> t.name, '
            '"fullName" -> t.fullName, '
            '"kind" -> "class_or_interface", '
            '"filename" -> t.filename, '
            '"lineNumber" -> t.lineNumber.getOrElse(-1), '
            '"lineNumberEnd" -> t.lineNumberEnd.getOrElse(-1)'
            ")).l.toJson"
        )
        if not isinstance(result, list):
            return []
        infos = [dict(item) for item in result]
        for info in infos:
            info["language"] = "java"
        return infos

    def get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        return self._joern.get_data_flow_to_sink(source_func, source_param, sink_pattern)

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """Java has no C-style function pointers; callbacks are represented in the call graph."""
        return []

    def get_header_declared_functions(
        self, header_files: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        return []
