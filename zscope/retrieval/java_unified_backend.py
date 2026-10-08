"""Unified Java backend: source structure plus optional graph/flow providers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .backend_base import CodeBackend
from .java_signal_providers import JavaSignalProvider, make_java_signal_providers
from .java_source_backend import JavaSourceBackend

logger = logging.getLogger(__name__)


class JavaUnifiedBackend(CodeBackend):
    """Facade mirroring C/C++ unified mode for Java projects."""

    def __init__(
        self,
        *,
        structure_frontend: str = "auto",
        structure_extractor_command: Optional[List[str]] = None,
        structure_db_path: str = "",
        signal_backends: Optional[List[str]] = None,
        signal_provider_commands: Optional[Dict[str, List[str]]] = None,
        joern_path: str = "joern",
        joern_host: str = "127.0.0.1",
        joern_port: int = 8080,
        joern_heap_size: str = "8g",
    ) -> None:
        self._structure = JavaSourceBackend(
            frontend=structure_frontend,
            extractor_command=structure_extractor_command,
            structure_db_path=structure_db_path,
        )
        self._signal_backend_names = list(signal_backends or [])
        self._signal_provider_commands = dict(signal_provider_commands or {})
        self._joern_cfg = {
            "joern_path": joern_path,
            "joern_host": joern_host,
            "joern_port": joern_port,
            "joern_heap_size": joern_heap_size,
        }
        self._providers: List[JavaSignalProvider] = []
        self._source_path: Optional[Path] = None
        self._project_root: Optional[Path] = None
        self._status = "idle"

    @property
    def structure_backend(self) -> JavaSourceBackend:
        return self._structure

    @property
    def providers(self) -> List[JavaSignalProvider]:
        return list(self._providers)

    @property
    def joern_client(self) -> Optional[Any]:
        for provider in self._providers:
            client = getattr(provider, "joern_client", None)
            if client is not None:
                return client
        return None

    def initialize(self, source_path: str, **kwargs) -> bool:
        self._status = "building"
        self._source_path = Path(source_path).resolve()
        self._project_root = Path(kwargs.get("project_root", source_path)).resolve()
        if not self._structure.initialize(source_path, **kwargs):
            self._status = "error"
            return False

        self._providers = make_java_signal_providers(
            self._signal_backend_names,
            joern_path=str(self._joern_cfg["joern_path"]),
            joern_host=str(self._joern_cfg["joern_host"]),
            joern_port=int(str(self._joern_cfg["joern_port"])),
            joern_heap_size=str(self._joern_cfg["joern_heap_size"]),
            user_config=kwargs.get("user_config"),
            provider_commands=self._signal_provider_commands,
        )
        ready_count = 0
        wait = bool(kwargs.get("wait", True))
        if wait:
            for provider in self._providers:
                try:
                    if provider.initialize(self._source_path, self._project_root, self._structure):
                        ready_count += 1
                    else:
                        status = provider.status()
                        reason = getattr(status, "degraded_reason", "") or "provider unavailable"
                        logger.info(
                            "Java signal provider %s unavailable: %s", provider.name, reason
                        )
                except Exception as exc:
                    logger.warning("Java signal provider %s failed: %s", provider.name, exc)
            if ready_count != len(self._providers):
                self._status = "error"
                logger.error(
                    "Java unified backend requires every configured signal provider: %d/%d ready",
                    ready_count,
                    len(self._providers),
                )
                return False
        self._status = "ready"
        logger.info(
            "Java unified backend ready: structure=%s signal_providers=%d/%d",
            self._structure.frontend,
            ready_count,
            len(self._providers),
        )
        return True

    def close(self) -> None:
        self._structure.close()
        for provider in self._providers:
            provider.close()
        self._status = "idle"

    def status(self) -> str:
        return self._status

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        return self._structure.build_function_index()

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        return self._structure.get_method(name)

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self._structure.get_method_callees(name, limit=limit)

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        rows = list(self._structure.get_callers(func_name, limit=limit, callee_file=callee_file))
        seen = {self._edge_key(row, caller=True) for row in rows}
        for edge in self._provider_call_edges(entry_func=func_name):
            if not self._names_match(edge.get("callee"), func_name):
                continue
            row = {
                "name": edge.get("caller", ""),
                "caller": edge.get("caller", ""),
                "callee": edge.get("callee", ""),
                "file": edge.get("file", ""),
                "line": edge.get("line", 0),
                "call_type": edge.get("call_type", "java_provider_call_graph"),
                "confidence": edge.get("confidence", 0.7),
                "precision": edge.get("precision", "typed_callgraph_flow"),
                "source": "java_signal_provider",
            }
            key = self._edge_key(row, caller=True)
            if key not in seen:
                rows.append(row)
                seen.add(key)
            if len(rows) >= limit:
                break
        return rows[:limit]

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        rows = list(self._structure.get_callees(func_name, limit=limit))
        seen = {self._edge_key(row, caller=False) for row in rows}
        for edge in self._provider_call_edges(entry_func=func_name):
            if not self._names_match(edge.get("caller"), func_name):
                continue
            row = {
                "name": edge.get("callee", ""),
                "callee": edge.get("callee", ""),
                "caller": edge.get("caller", ""),
                "file": edge.get("file", ""),
                "line": edge.get("line", 0),
                "call_type": edge.get("call_type", "java_provider_call_graph"),
                "confidence": edge.get("confidence", 0.7),
                "precision": edge.get("precision", "typed_callgraph_flow"),
                "source": "java_signal_provider",
            }
            key = self._edge_key(row, caller=False)
            if key not in seen:
                rows.append(row)
                seen.add(key)
            if len(rows) >= limit:
                break
        return rows[:limit]

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        return self._structure.get_type_info(type_name)

    def list_type_infos(self) -> List[Dict[str, Any]]:
        return self._structure.list_type_infos()

    def get_data_flow(
        self,
        source_func: str,
        source_param: str,
        sink_pattern: str,
    ) -> List[Dict[str, Any]]:
        return []

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        return []

    def get_header_declared_functions(
        self,
        header_files: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        return []

    def collect_java_signal_matches(self, entry_func: str = "") -> List[Any]:
        matches: List[Any] = []
        for provider in self._providers:
            try:
                matches.extend(provider.collect_rule_matches(entry_func=entry_func))
                matches.extend(
                    signal.to_dict()
                    for signal in provider.collect_flow_signals(entry_func=entry_func)
                )
                matches.extend(
                    signal.to_dict()
                    for signal in provider.collect_taint_signals(entry_func=entry_func)
                )
            except Exception as exc:
                logger.debug("Java provider %s match collection failed: %s", provider.name, exc)
        return matches

    def java_signal_capabilities(self) -> List[Dict[str, Any]]:
        return [provider.capabilities().to_dict() for provider in self._providers]

    def java_signal_status(self) -> List[Dict[str, Any]]:
        return [provider.status().to_dict() for provider in self._providers]

    def _provider_call_edges(self, entry_func: str = "") -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        for provider in self._providers:
            try:
                edges.extend(
                    edge.to_dict() for edge in provider.collect_call_edges(entry_func=entry_func)
                )
            except Exception as exc:
                logger.debug("Java provider %s call edge collection failed: %s", provider.name, exc)
        return edges

    @staticmethod
    def _edge_key(row: Dict[str, Any], *, caller: bool) -> tuple[str, str, str, int]:
        endpoint = str(row.get("caller" if caller else "callee") or row.get("name") or "")
        return (
            endpoint,
            str(row.get("file") or ""),
            str(row.get("call_type") or ""),
            int(row.get("line") or 0),
        )

    @staticmethod
    def _names_match(left: Any, right: str) -> bool:
        left_text = str(left or "")
        right_text = str(right or "")
        if not left_text or not right_text:
            return False
        if left_text == right_text:
            return True
        return left_text.split(":", 1)[0].endswith(
            "." + right_text.split(":", 1)[0]
        ) or right_text.split(":", 1)[0].endswith("." + left_text.split(":", 1)[0])
