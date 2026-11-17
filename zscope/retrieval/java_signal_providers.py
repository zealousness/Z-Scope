"""Java graph/data-flow signal provider adapters."""

from __future__ import annotations

import logging
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..common.joern_client import JoernClient
from ..rules.engine import RuleEngine, RuleMatch
from .java_models import (
    JavaCallEdge,
    JavaFlowSignal,
    JavaProviderCapability,
    JavaProviderStatus,
)

logger = logging.getLogger(__name__)


class JavaSignalProvider:
    """Base interface for Java analysis signal providers."""

    name = "java_signal"
    precision = "source_level_approx"

    def initialize(self, source_root: Path, project_root: Path, structure_backend: Any) -> bool:
        return True

    def capabilities(self) -> JavaProviderCapability:
        return JavaProviderCapability(provider=self.name, precision=self.precision)

    def status(self) -> JavaProviderStatus:
        return JavaProviderStatus(provider=self.name, available=True, initialized=True)

    def collect_call_edges(self, entry_func: str = "") -> List[JavaCallEdge]:
        return []

    def collect_flow_signals(self, entry_func: str = "") -> List[JavaFlowSignal]:
        return []

    def collect_taint_signals(self, entry_func: str = "") -> List[JavaFlowSignal]:
        return []

    def collect_rule_matches(self, entry_func: str = "") -> List[RuleMatch]:
        return []

    def close(self) -> None:
        return None


class JoernJavaSignalProvider(JavaSignalProvider):
    """Joern Java CPG provider kept as graph/flow signal source only."""

    name = "joern"
    precision = "exact_flow"

    def __init__(
        self,
        *,
        joern_path: str = "joern",
        host: str = "127.0.0.1",
        port: int = 8080,
        heap_size: str = "8g",
        user_config: Optional[Any] = None,
        joern_client: Optional[Any] = None,
    ) -> None:
        self.joern = joern_client or JoernClient(
            joern_path=joern_path,
            host=host,
            port=port,
            heap_size=heap_size,
            language="java",
        )
        self.user_config = user_config
        self._ready = False
        self._degraded_reason = ""
        self._matches_cache: Optional[List[RuleMatch]] = None

    @property
    def joern_client(self) -> Any:
        return self.joern

    def initialize(self, source_root: Path, project_root: Path, structure_backend: Any) -> bool:
        if not self.joern.start_server():
            self._degraded_reason = "joern server failed to start"
            return False
        ok = self.joern.import_cpg(
            str(source_root), project_root=str(project_root), language="java"
        )
        self._ready = bool(ok)
        if not ok:
            self._degraded_reason = "joern CPG import failed"
        return self._ready

    def capabilities(self) -> JavaProviderCapability:
        return JavaProviderCapability(
            provider=self.name,
            call_graph=True,
            data_flow=True,
            taint=True,
            path_problem=True,
            framework_semantics=False,
            precision="exact_flow",
            stage="implemented",
            notes=[
                "Joern contributes CPG rules and reachableByFlows signals; source structure is owned by JavaSourceBackend."
            ],
        )

    def status(self) -> JavaProviderStatus:
        return JavaProviderStatus(
            provider=self.name,
            available=self._ready and not self._degraded_reason,
            initialized=self._ready,
            degraded_reason=self._degraded_reason,
            signals_collected=len(self._matches_cache or []),
            call_edges_collected=0,
        )

    def collect_rule_matches(self, entry_func: str = "") -> List[RuleMatch]:
        if not self._ready:
            raise RuntimeError(self._degraded_reason or "Joern provider is not initialized")
        if self._matches_cache is not None:
            return list(self._matches_cache)
        try:
            engine = RuleEngine(self.joern, self.user_config)
            matches = engine.run_builtin_scan()
            matches.extend(engine.run_semantic_cpg_rule_library())
            matches.extend(engine.run_java_framework_data_flow_checks())
            matches.extend(engine.run_paired_function_checks())
            matches.extend(engine.run_configured_data_flow_checks())
        except Exception as exc:
            logger.debug("Unable to collect Joern Java signal matches: %s", exc)
            self._degraded_reason = str(exc)
            raise RuntimeError(f"Joern signal collection failed: {exc}") from exc
        self._degraded_reason = ""
        self._matches_cache = list(matches)
        return list(matches)

    def close(self) -> None:
        stop = getattr(self.joern, "stop_server", None)
        if callable(stop):
            stop()


class ExternalJavaSignalProvider(JavaSignalProvider):
    """Placeholder adapter for SootUp/WALA/CodeQL command integrations.

    The command is expected to emit a JSON array compatible with RuleMatch's
    dictionary shape.  This keeps the provider protocol stable while concrete
    runners are developed independently.
    """

    def __init__(self, name: str, command: Optional[List[str]] = None) -> None:
        self.name = name
        self.command = list(command or [])
        self._ready = False
        self._source_root: Optional[Path] = None
        self._project_root: Optional[Path] = None
        self._degraded_reason = "runner command is not configured"
        self._payload_cache: Dict[str, Dict[str, Any]] = {}
        self._flow_cache: Dict[str, List[JavaFlowSignal]] = {}
        self._call_edge_cache: Dict[str, List[JavaCallEdge]] = {}

    def initialize(self, source_root: Path, project_root: Path, structure_backend: Any) -> bool:
        self._source_root = Path(source_root).resolve()
        self._project_root = Path(project_root).resolve()
        if not self.command:
            self.command = self._default_command()
        self._ready = bool(self.command)
        self._degraded_reason = "" if self._ready else self._default_missing_reason()
        return self._ready

    def capabilities(self) -> JavaProviderCapability:
        precision = {
            "sootup": "typed_callgraph_flow",
            "wala": "typed_callgraph_flow",
            "codeql": "exact_flow",
        }.get(self.name, "source_level_approx")
        return JavaProviderCapability(
            provider=self.name,
            call_graph=self.name in {"sootup", "wala"},
            data_flow=self.name in {"wala", "codeql"},
            taint=self.name in {"wala", "codeql"},
            path_problem=self.name == "codeql",
            framework_semantics=False,
            precision=precision,
            stage="protocol_ready",
            notes=[
                "Provider contract is implemented; configure a runner command to collect signals."
            ],
        )

    def status(self) -> JavaProviderStatus:
        return JavaProviderStatus(
            provider=self.name,
            available=self._ready and not self._degraded_reason,
            initialized=self._ready,
            degraded_reason=self._degraded_reason,
            signals_collected=sum(len(items) for items in self._flow_cache.values()),
            call_edges_collected=sum(len(items) for items in self._call_edge_cache.values()),
        )

    def collect_call_edges(self, entry_func: str = "") -> List[JavaCallEdge]:
        if not self._ready or not self.command:
            raise RuntimeError(self._degraded_reason or f"{self.name} provider is not initialized")
        cache_key = str(entry_func or "")
        if cache_key in self._call_edge_cache:
            return list(self._call_edge_cache[cache_key])
        payload = self._payload_for_entry(entry_func)
        edges: List[JavaCallEdge] = []
        for item in payload.get("call_edges", []):
            if not isinstance(item, dict):
                continue
            try:
                edges.append(
                    JavaCallEdge(
                        caller=str(item.get("caller") or ""),
                        callee=str(item.get("callee") or ""),
                        call_name=str(
                            item.get("call_name") or item.get("call") or item.get("callee") or ""
                        ),
                        file=str(item.get("file") or item.get("filename") or ""),
                        line=int(item.get("line") or item.get("lineNumber") or 0),
                        call_type=str(item.get("call_type") or f"{self.name}_call_graph"),
                        confidence=float(item.get("confidence") or 0.7),
                        precision=str(item.get("precision") or self.capabilities().precision),
                    )
                )
            except (TypeError, ValueError):
                continue
        self._call_edge_cache[cache_key] = edges
        return list(edges)

    def collect_flow_signals(self, entry_func: str = "") -> List[JavaFlowSignal]:
        if not self._ready or not self.command:
            raise RuntimeError(self._degraded_reason or f"{self.name} provider is not initialized")
        cache_key = str(entry_func or "")
        if cache_key in self._flow_cache:
            return list(self._flow_cache[cache_key])
        payload = self._payload_for_entry(entry_func)
        signals: List[JavaFlowSignal] = []
        for item in payload.get("signals", []):
            if not isinstance(item, dict):
                continue
            signals.append(
                JavaFlowSignal(
                    rule_id=str(item.get("rule_id") or item.get("rule") or f"{self.name}_signal"),
                    category=str(item.get("category") or item.get("defect_class") or "java_signal"),
                    source=dict(item.get("source") or {}),
                    sink=dict(item.get("sink") or {}),
                    path=list(item.get("path") or []),
                    score=float(item.get("score") or item.get("confidence") or 6.0),
                    provider=self.name,
                    limitation=str(item.get("limitation") or item.get("limitations") or ""),
                    precision=str(item.get("precision") or self.capabilities().precision),
                    raw_evidence=dict(item.get("raw_evidence") or item),
                )
            )
        self._flow_cache[cache_key] = signals
        return list(signals)

    def collect_rule_matches(self, entry_func: str = "") -> List[RuleMatch]:
        return []

    def _payload_for_entry(self, entry_func: str) -> Dict[str, Any]:
        cache_key = str(entry_func or "")
        if cache_key not in self._payload_cache:
            self._payload_cache[cache_key] = self._run_json_command(entry_func)
        return dict(self._payload_cache[cache_key])

    def _run_json_command(self, entry_func: str) -> Dict[str, Any]:
        if not self.command:
            raise self._command_error("runner command is not configured")
        cmd = [
            part.replace("{entry}", entry_func)
            .replace("{source_root}", str(self._source_root or ""))
            .replace("{project_root}", str(self._project_root or ""))
            for part in self.command
        ]
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self._project_root or self._source_root or "."),
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        except Exception as exc:
            raise self._command_error(str(exc)) from exc
        if proc.returncode != 0:
            raise self._command_error(
                proc.stderr[-1000:] or f"runner exited with {proc.returncode}"
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise self._command_error(f"runner returned non-JSON output: {exc}") from exc
        if isinstance(data, list):
            payload = {"signals": data, "call_edges": [], "metadata": {"legacy_array": True}}
        elif isinstance(data, dict):
            metadata = data.get("metadata", {})
            if not isinstance(metadata, dict):
                raise self._command_error("runner metadata must be a JSON object")
            degraded = str(metadata.get("degraded_reason") or "")
            if degraded:
                raise self._command_error(degraded)
            payload = {
                "signals": data.get("signals", []),
                "call_edges": data.get("call_edges", []),
                "metadata": metadata,
            }
        else:
            raise self._command_error("runner output must be a JSON object or array")
        for key in ("signals", "call_edges"):
            rows = payload[key]
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise self._command_error(f"runner {key} must be an array of JSON objects")
        self._degraded_reason = ""
        return payload

    def _command_error(self, reason: str) -> RuntimeError:
        self._degraded_reason = reason
        return RuntimeError(f"Java provider {self.name} failed: {reason}")

    def _default_command(self) -> List[str]:
        from ..common.portable import default_tool, java_jar

        repo_root = Path(__file__).resolve().parents[2]
        if self.name in {"sootup", "wala"}:
            jar = java_jar(f"signal-{self.name}") or (
                repo_root
                / "tools"
                / f"java-signal-{self.name}"
                / "target"
                / f"zscope-java-signal-{self.name}-0.1.0.jar"
            )
            if not jar.exists():
                return []
            return [
                default_tool("java"),
                "-jar",
                str(jar),
                "--project-root",
                "{project_root}",
                "--source-root",
                "{source_root}",
                "--entry",
                "{entry}",
                "--provider",
                self.name,
            ]
        if self.name == "codeql":
            codeql = shutil.which("codeql")
            script = repo_root / "tools" / "run_codeql_java.py"
            if not codeql or not script.exists():
                return []
            return [
                sys.executable,
                str(script),
                "--codeql",
                codeql,
                "--project-root",
                "{project_root}",
                "--source-root",
                "{source_root}",
                "--entry",
                "{entry}",
            ]
        return []

    def _default_missing_reason(self) -> str:
        if self.name in {"sootup", "wala"}:
            return (
                f"default {self.name} runner jar not found; build it with "
                f"`mvn -q -f tools/java-signal-{self.name}/pom.xml -DskipTests package` "
                "or configure indexing.java_signal_provider_commands"
            )
        if self.name == "codeql":
            return (
                "CodeQL CLI or tools/run_codeql_java.py not found; install CodeQL and ensure "
                "`codeql` is on PATH, or configure indexing.java_signal_provider_commands.codeql"
            )
        return "runner command is not configured"


def make_java_signal_providers(
    names: List[str],
    *,
    joern_path: str,
    joern_host: str,
    joern_port: int,
    joern_heap_size: str,
    user_config: Optional[Any] = None,
    provider_commands: Optional[Dict[str, List[str]]] = None,
) -> List[JavaSignalProvider]:
    providers: List[JavaSignalProvider] = []
    provider_commands = provider_commands or {}
    for raw_name in names:
        name = str(raw_name or "").strip().lower().replace("-", "_")
        if not name:
            continue
        if name == "joern":
            providers.append(
                JoernJavaSignalProvider(
                    joern_path=joern_path,
                    host=joern_host,
                    port=joern_port,
                    heap_size=joern_heap_size,
                    user_config=user_config,
                )
            )
        elif name in {"sootup", "wala", "codeql"}:
            providers.append(ExternalJavaSignalProvider(name, command=provider_commands.get(name)))
    return providers
