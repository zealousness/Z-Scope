"""Batch-level global semantic modeling for function entries."""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from ..agents.semantic_modeler.agent import SemanticModeler
from ..config.config import ZScopeConfig
from ..config.function_entry import FunctionEntry
from ..config.user_config_store import UserConfigStore
from ..semantics.user_config_context import relevant_user_config_context
from ..snapshots.policy import (
    build_lightweight_snapshot,
    build_trivial_snapshot,
    is_lightweight_snapshot_candidate,
    is_trivial_function,
)
from ..snapshots.store import SnapshotStore
from ..tools.policy import ToolPolicy

logger = logging.getLogger(__name__)


@dataclass(frozen=True, order=True)
class FunctionKey:
    """Disambiguated function identity used by global modeling."""

    name: str
    file_path: str = ""


@dataclass
class GlobalModelStats:
    """Counters emitted by the global modeling stage."""

    reachable_functions: int = 0
    modeled_functions: int = 0
    cache_hit_functions: int = 0
    deterministic_snapshot_count: int = 0
    llm_snapshot_count: int = 0
    unresolved_external_callees: int = 0
    depth_capped_edges: int = 0
    breadth_capped_edges: int = 0
    failed_functions: int = 0
    failed_dependencies: int = 0
    components: int = 0
    cyclic_components: int = 0
    total_context_tokens: int = 0
    duration_seconds: float = 0.0
    modeled_order: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reachable_functions": self.reachable_functions,
            "modeled_functions": self.modeled_functions,
            "cache_hit_functions": self.cache_hit_functions,
            "deterministic_snapshot_count": self.deterministic_snapshot_count,
            "llm_snapshot_count": self.llm_snapshot_count,
            "unresolved_external_callees": self.unresolved_external_callees,
            "depth_capped_edges": self.depth_capped_edges,
            "breadth_capped_edges": self.breadth_capped_edges,
            "failed_functions": self.failed_functions,
            "failed_dependencies": self.failed_dependencies,
            "components": self.components,
            "cyclic_components": self.cyclic_components,
            "total_context_tokens": self.total_context_tokens,
            "duration_seconds": self.duration_seconds,
            "modeled_order": list(self.modeled_order),
        }


@dataclass
class _Graph:
    nodes: Set[FunctionKey] = field(default_factory=set)
    entry_keys: Set[FunctionKey] = field(default_factory=set)
    children: Dict[FunctionKey, Set[FunctionKey]] = field(default_factory=dict)
    impls: Dict[FunctionKey, Dict[str, Any]] = field(default_factory=dict)
    unresolved: Set[FunctionKey] = field(default_factory=set)
    aliases: Dict[FunctionKey, FunctionKey] = field(default_factory=dict)
    depth_capped_edges: int = 0
    breadth_capped_edges: int = 0


SemanticAgentFactory = Callable[[], SemanticModeler]
AttachContract = Callable[[Dict[str, Any], str], None]


class GlobalModeler:
    """Collect and model all entry-reachable functions before entry analysis."""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: Any,
        snapshot_store: SnapshotStore,
        user_config: UserConfigStore,
        *,
        semantic_agent_factory: SemanticAgentFactory,
        attach_contract: Optional[AttachContract] = None,
        max_workers: Optional[int] = None,
    ) -> None:
        self.config = config
        self.code_index = code_index
        self.snapshot_store = snapshot_store
        self.user_config = user_config
        self.semantic_agent_factory = semantic_agent_factory
        self.attach_contract = attach_contract or (lambda context, agent_name: None)
        self.max_workers = max(1, int(max_workers or config.analysis.parallel_workers or 1))
        self._stats_lock = threading.Lock()

    @classmethod
    def from_analyzer_helpers(
        cls,
        config: ZScopeConfig,
        code_index: Any,
        snapshot_store: SnapshotStore,
        user_config: UserConfigStore,
        *,
        llm_clients: Dict[str, Any],
        tools_factory: Callable[..., List[Any]],
        tool_policy_factory: Callable[[str], ToolPolicy],
        attach_contract: AttachContract,
    ) -> "GlobalModeler":
        sm_agent_cfg = next(
            (a for a in config.project.agents if a.name == "semantic_modeler"),
            None,
        )
        sm_llm_ref = sm_agent_cfg.llm_ref if sm_agent_cfg and sm_agent_cfg.llm_ref else "default"
        sm_client = llm_clients.get(sm_llm_ref) or llm_clients.get("default")
        if sm_client is None:
            raise RuntimeError("No LLM client configured for semantic_modeler")

        def make_agent() -> SemanticModeler:
            return SemanticModeler(
                sm_client,
                tools_factory("semantic_modeler", enable_on_demand_snapshots=False),
                tool_policy=tool_policy_factory("semantic_modeler"),
            )

        return cls(
            config,
            code_index,
            snapshot_store,
            user_config,
            semantic_agent_factory=make_agent,
            attach_contract=attach_contract,
            max_workers=config.analysis.parallel_workers,
        )

    def run(self, entries: Sequence[FunctionEntry]) -> GlobalModelStats:
        started = time.time()
        graph = self._collect_graph(entries)
        stats = GlobalModelStats(
            reachable_functions=len(graph.impls),
            unresolved_external_callees=len(graph.unresolved),
            depth_capped_edges=graph.depth_capped_edges,
            breadth_capped_edges=graph.breadth_capped_edges,
        )
        if not graph.impls:
            stats.duration_seconds = time.time() - started
            return stats

        component_for, components = self._strongly_connected_components(graph)
        component_children: Dict[int, Set[int]] = {idx: set() for idx in range(len(components))}
        component_parents: Dict[int, Set[int]] = {idx: set() for idx in range(len(components))}
        for parent, children in graph.children.items():
            if parent not in graph.impls:
                continue
            parent_component = component_for[parent]
            for child in children:
                if child not in graph.impls:
                    continue
                child_component = component_for[child]
                if child_component == parent_component:
                    continue
                component_children[parent_component].add(child_component)
                component_parents[child_component].add(parent_component)

        stats.components = len(components)
        stats.cyclic_components = sum(
            1
            for component in components
            if len(component) > 1 or any(key in graph.children.get(key, set()) for key in component)
        )

        pending_children = {
            idx: len(component_children[idx])
            for idx in range(len(components))
        }
        ready = [idx for idx, count in pending_children.items() if count == 0]
        done_components: Set[int] = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_component: Dict[concurrent.futures.Future[None], int] = {}
            while ready or future_to_component:
                while ready:
                    component_idx = ready.pop()
                    future = executor.submit(
                        self._model_component,
                        components[component_idx],
                        graph,
                        stats,
                    )
                    future_to_component[future] = component_idx

                done, _pending = concurrent.futures.wait(
                    future_to_component,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    component_idx = future_to_component.pop(future)
                    future.result()
                    done_components.add(component_idx)
                    for parent_idx in component_parents[component_idx]:
                        pending_children[parent_idx] -= 1
                        if pending_children[parent_idx] == 0 and parent_idx not in done_components:
                            ready.append(parent_idx)

        stats.duration_seconds = time.time() - started
        return stats

    def _collect_graph(self, entries: Sequence[FunctionEntry]) -> _Graph:
        graph = _Graph()
        max_depth = int(self.config.analysis.max_premodel_depth)
        max_callees = int(self.config.analysis.max_premodel_callees)
        if max_depth == 0 or max_callees == 0:
            return graph
        callee_query_limit = max_callees + 1 if max_callees > 0 else 1_000_000

        queue: List[Tuple[FunctionKey, int]] = [
            (FunctionKey(entry.function_name, str(entry.file_path or "")), 0)
            for entry in entries
        ]
        graph.entry_keys = {key for key, _depth in queue}
        best_depth: Dict[FunctionKey, int] = {}

        while queue:
            key, depth = queue.pop(0)
            previous_depth = best_depth.get(key)
            if previous_depth is not None and previous_depth <= depth:
                continue
            best_depth[key] = depth
            graph.nodes.add(key)

            impl = self._get_impl(key, include_context=False)
            if not impl:
                graph.unresolved.add(key)
                continue
            canonical = self._key_from_impl(key.name, impl)
            if canonical != key:
                graph.aliases[key] = canonical
                best_depth[canonical] = min(depth, best_depth.get(canonical, depth))
                graph.nodes.add(canonical)
            key = canonical
            graph.impls[key] = impl
            graph.children.setdefault(key, set())

            if max_depth >= 0 and depth >= max_depth:
                callees = self._get_callee_records(key, callee_query_limit)
                if callees:
                    graph.depth_capped_edges += len(callees)
                continue

            callee_records = self._get_callee_records(key, callee_query_limit)
            if max_callees > 0 and len(callee_records) > max_callees:
                graph.breadth_capped_edges += len(callee_records) - max_callees
                callee_records = callee_records[:max_callees]

            for record in callee_records:
                callee = self._key_from_callee_record(record)
                if not callee.name:
                    continue
                graph.children[key].add(callee)
                queue.append((callee, depth + 1))

        self._canonicalize_graph_edges(graph)
        return graph

    @staticmethod
    def _canonicalize_graph_edges(graph: _Graph) -> None:
        if not graph.aliases:
            return

        def canonical(key: FunctionKey) -> FunctionKey:
            seen: Set[FunctionKey] = set()
            while key in graph.aliases and key not in seen:
                seen.add(key)
                key = graph.aliases[key]
            return key

        normalized_children: Dict[FunctionKey, Set[FunctionKey]] = {}
        for parent, children in graph.children.items():
            normalized_parent = canonical(parent)
            normalized_children.setdefault(normalized_parent, set())
            for child in children:
                normalized_children[normalized_parent].add(canonical(child))
        graph.children = normalized_children
        graph.nodes = {canonical(key) for key in graph.nodes}
        graph.entry_keys = {canonical(key) for key in graph.entry_keys}
        graph.unresolved = {canonical(key) for key in graph.unresolved}

    def _model_component(
        self,
        component: Sequence[FunctionKey],
        graph: _Graph,
        stats: GlobalModelStats,
    ) -> None:
        for key in sorted(component):
            result, tokens = self._model_function(
                key,
                graph.impls[key],
                force_llm=key in graph.entry_keys,
            )
            with self._stats_lock:
                stats.modeled_order.append(self._format_key(key))
                stats.total_context_tokens += tokens
                if result == "cache_hit":
                    stats.cache_hit_functions += 1
                elif result == "deterministic":
                    stats.modeled_functions += 1
                    stats.deterministic_snapshot_count += 1
                elif result == "llm":
                    stats.modeled_functions += 1
                    stats.llm_snapshot_count += 1
                elif result == "failed":
                    stats.failed_functions += 1

    def _model_function(
        self,
        key: FunctionKey,
        impl: Dict[str, Any],
        *,
        force_llm: bool = False,
    ) -> Tuple[str, int]:
        if self._has_current_snapshot(key, impl):
            return "cache_hit", 0

        lock_file_path = str(impl.get("file") or key.file_path or "")
        lock_status = self.snapshot_store.lock_manager.acquire(
            key.name,
            file_path=lock_file_path or None,
        )
        if lock_status == "done":
            return "cache_hit", 0
        if lock_status == "timeout":
            logger.warning("[global-model] Timeout waiting for '%s'", key.name)
            return "failed", 0

        success = False
        context_tokens = 0
        try:
            if self._has_current_snapshot(key, impl):
                success = True
                return "cache_hit", 0

            location = f"{impl.get('file', key.file_path or 'unknown')}:{impl.get('start_line', 0)}"
            code = str(impl.get("code") or "")

            if not force_llm and is_lightweight_snapshot_candidate(key.name, impl):
                snapshot = build_lightweight_snapshot(key.name, impl, location)
                self.snapshot_store.save_snapshot(key.name, snapshot, code, location)
                success = True
                return "deterministic", 0

            if not force_llm and is_trivial_function(
                code,
                self.config.analysis.trivial_function_max_lines,
            ):
                snapshot = build_trivial_snapshot(key.name, impl, location)
                self.snapshot_store.save_snapshot(key.name, snapshot, code, location)
                success = True
                return "deterministic", 0

            context = {
                "func_name": key.name,
                "code": code,
                "location": location,
            }
            user_context = relevant_user_config_context(
                self.user_config,
                key.name,
                code,
                str(impl.get("file") or key.file_path or ""),
            )
            if user_context:
                context["user_config_context"] = user_context
            self.attach_contract(context, "semantic_modeler")
            response = self.semantic_agent_factory().run(context)
            metadata = response.metadata if response.metadata else {}
            context_tokens = int(
                metadata.get("context_tokens", 0)
                or metadata.get("total_tokens", 0)
                or 0
            )
            if response.success:
                self.snapshot_store.save_snapshot(key.name, response.data, code, location)
                success = True
                return "llm", context_tokens
            logger.warning("[global-model] Failed to model '%s': %s", key.name, response.error)
            return "failed", context_tokens
        except Exception as exc:
            logger.exception("[global-model] Error modeling '%s': %s", key.name, exc)
            return "failed", context_tokens
        finally:
            self.snapshot_store.lock_manager.release(
                key.name,
                success=success,
                file_path=lock_file_path or None,
            )

    def _has_current_snapshot(self, key: FunctionKey, impl: Dict[str, Any]) -> bool:
        file_path = str(impl.get("file") or key.file_path or "")
        snapshot = self.snapshot_store.load_snapshot(key.name, file_path or None)
        if not snapshot:
            return False
        try:
            needs_refresh, _reason = self.snapshot_store.needs_refresh(
                key.name,
                str(impl.get("code") or ""),
                file_path or None,
            )
        except Exception:
            return True
        return not needs_refresh

    def _get_impl(self, key: FunctionKey, *, include_context: bool) -> Optional[Dict[str, Any]]:
        try:
            return self.code_index.get_function_impl(
                key.name,
                max_lines=self.config.analysis.max_function_lines,
                warn_missing=False,
                include_context=include_context,
                file_path=key.file_path,
            )
        except TypeError:
            return self.code_index.get_function_impl(key.name)

    def _get_callee_records(self, key: FunctionKey, limit: int) -> List[Any]:
        try:
            records = self.code_index.get_callees(key.name, limit=limit)
        except Exception:
            records = []
        if records:
            return list(records)
        impl = self._get_impl(key, include_context=True)
        if not impl:
            return []
        return list(impl.get("callees") or [])

    @staticmethod
    def _key_from_impl(func_name: str, impl: Dict[str, Any]) -> FunctionKey:
        return FunctionKey(str(impl.get("func_name") or func_name), str(impl.get("file") or ""))

    @staticmethod
    def _key_from_callee_record(record: Any) -> FunctionKey:
        if isinstance(record, str):
            return FunctionKey(record)
        if not isinstance(record, dict):
            return FunctionKey("")
        name = str(
            record.get("name")
            or record.get("func_name")
            or record.get("callee")
            or record.get("method")
            or ""
        )
        file_path = str(
            record.get("file")
            or record.get("file_path")
            or record.get("filename")
            or record.get("callee_file")
            or ""
        )
        return FunctionKey(name, file_path)

    @staticmethod
    def _format_key(key: FunctionKey) -> str:
        return f"{key.name}@{key.file_path}" if key.file_path else key.name

    def _strongly_connected_components(
        self,
        graph: _Graph,
    ) -> Tuple[Dict[FunctionKey, int], List[List[FunctionKey]]]:
        nodes = sorted(graph.impls)
        index = 0
        stack: List[FunctionKey] = []
        on_stack: Set[FunctionKey] = set()
        indexes: Dict[FunctionKey, int] = {}
        lowlinks: Dict[FunctionKey, int] = {}
        components: List[List[FunctionKey]] = []

        def strongconnect(node: FunctionKey) -> None:
            nonlocal index
            indexes[node] = index
            lowlinks[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)

            for child in sorted(graph.children.get(node, set())):
                if child not in graph.impls:
                    continue
                if child not in indexes:
                    strongconnect(child)
                    lowlinks[node] = min(lowlinks[node], lowlinks[child])
                elif child in on_stack:
                    lowlinks[node] = min(lowlinks[node], indexes[child])

            if lowlinks[node] == indexes[node]:
                component: List[FunctionKey] = []
                while stack:
                    child = stack.pop()
                    on_stack.remove(child)
                    component.append(child)
                    if child == node:
                        break
                components.append(sorted(component))

        for node in nodes:
            if node not in indexes:
                strongconnect(node)

        component_for = {
            key: idx
            for idx, component in enumerate(components)
            for key in component
        }
        return component_for, components
