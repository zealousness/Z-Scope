"""
Abstract base class for code analysis backends.
Defines the pluggable interface that CodeIndex delegates to.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FunctionInfo:
    """Standardized function metadata returned by backends."""

    name: str
    file_path: str
    start_line: int
    end_line: int
    signature: str


@dataclass
class TypeInfo:
    """Standardized type definition returned by backends."""

    name: str
    kind: str  # struct / union / enum / typedef
    file_path: str
    line: int
    members: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class CallerInfo:
    """Standardized caller reference."""

    name: str
    file_path: str
    line: int


class CodeBackend(ABC):
    """
    可插拔的代码分析后端接口。

    CodeIndex 持有一个 CodeBackend 实例，将所有后端相关的查询委托给它。
    不同后端（Joern / Clang-SQLite / SVF / regex）各自实现此接口。
    """

    # ── 生命周期 ──

    @abstractmethod
    def initialize(self, source_path: str, **kwargs) -> bool:
        """初始化后端（启动服务 / 加载数据库 / 构建索引）。"""
        ...

    @abstractmethod
    def close(self) -> None:
        """释放后端资源。"""
        ...

    @abstractmethod
    def status(self) -> str:
        """返回后端状态: idle / building / ready / error。"""
        ...

    # ── 索引构建 ──

    @abstractmethod
    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        """
        构建函数索引。返回 {func_name: {file, start_line, end_line, signature}}。
        """
        ...

    # ── 查询方法 ──

    @abstractmethod
    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        """获取调用指定函数的函数列表。"""
        ...

    @abstractmethod
    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        """获取指定函数调用的函数列表。"""
        ...

    @abstractmethod
    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        """获取结构体/联合体/枚举定义及成员。"""
        ...

    def find_type_infos(
        self,
        type_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Return all available type definitions matching the query."""
        info = self.get_type_info(type_name)
        if not info:
            return []
        if file_path:
            stored = str(info.get("file_path") or info.get("filename") or "")
            stored = stored.replace("\\", "/").strip().lstrip("./")
            hint = str(file_path or "").replace("\\", "/").strip().lstrip("./")
            if not (
                stored == hint
                or stored.endswith(f"/{hint}")
                or hint.endswith(f"/{stored}")
            ):
                return []
        return [dict(info)]

    @abstractmethod
    def get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        """污点数据流追踪。"""
        ...

    @abstractmethod
    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """查找函数指针赋值/回调注册。"""
        ...

    @abstractmethod
    def get_header_declared_functions(
        self, header_files: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """获取头文件中声明的公开函数。"""
        ...

    @abstractmethod
    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        """按名称精确查找单个函数节点。"""
        ...

    def get_macro_definitions(self, name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Return macro definitions by name when the backend has macro facts."""
        return []

    def get_function_symbol_context(
        self,
        func_name: str,
        file_path: str = "",
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Return globals and macros referenced by one function."""
        return {"referenced_globals": [], "referenced_macros": []}

    def get_function_info_callees(
        self,
        func_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Return the complete callee edge set used by get_function_info."""
        return self.get_callees(func_name, limit=1_000_000)

    def get_function_info_callers(
        self,
        func_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Return the complete caller edge set used by structured caller tools."""
        return self.get_callers(
            func_name,
            limit=1_000_000,
            callee_file=file_path,
        )

    @abstractmethod
    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        """获取指定函数的被调用者列表（用于 get_function_impl 中提取 callees）。"""
        ...
