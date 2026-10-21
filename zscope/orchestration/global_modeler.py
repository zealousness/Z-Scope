"""Batch-level global semantic modeling for function entries."""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING, cast

from ..agents.semantic_modeler.agent import SemanticModeler
from ..agents.semantic_modeler.retry import run_semantic_model_with_retries
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
from ..snapshots.modeling_input import (
    SemanticModelInputError,
    build_semantic_model_input,
    hydrate_project_callee_summaries,
    hydrate_project_callee_summaries_from_map,
    is_header_like_path,
)
from ..tools.policy import ToolPolicy
from .scheduler import ENTRY_ROLE, ScanScheduler

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .semantic_demand import SemanticDemandHint
    from ..semantics.security_map import AuditUnit, SecuritySemanticMap

MAX_FAILED_FUNCTIONS_FOR_STAGE = 0


def modeling_profile(config: ZScopeConfig) -> str:
    profiles = getattr(getattr(config, "scan", None), "llm_profiles", None)
    public = str(getattr(profiles, "modeling", "") or "")
    if public:
        return public
    agent = next((a for a in config.project.agents if a.name == "semantic_modeler"), None)
    return str(getattr(agent, "llm_ref", "") or "default")


@dataclass(frozen=True, order=True)
class FunctionKey:
    """Disambiguated function identity used by global modeling."""

    name: str
    file_path: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        from ..semantics.contracts import code_tokens

        object.__setattr__(self, "file_path", self.file_path.replace("\\", "/"))
        object.__setattr__(self, "signature", " ".join(code_tokens(self.signature)))


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
    unresolved_entry_functions: int = 0
    reconciled_functions: int = 0
    reconciliation_unchanged_functions: int = 0
    reconciliation_failures: int = 0
    unknown_project_callees: int = 0
    components: int = 0
    cyclic_components: int = 0
    recursive_rounds: int = 0
    total_context_tokens: int = 0
    duration_seconds: float = 0.0
    modeled_order: List[str] = field(default_factory=list)
    rebuild_reasons: Dict[str, str] = field(default_factory=dict)
    propagated_functions: int = 0
    peak_concurrency: int = 0
    wait_seconds: float = 0.0
    partial_reasons: List[str] = field(default_factory=list)
    contract_validation_retry_count: int = 0
    contract_validation_failure_count: int = 0
    published_contract_count: int = 0
    derived_pair_count: int = 0
    extracted_contract_count: int = 0
    rejected_contract_count: int = 0
    standard_model_count: int = 0
    external_model_missing: List[str] = field(default_factory=list)
    modeling_tasks: Dict[str, Any] = field(default_factory=dict)
    resource_inference_coverage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict

        return {**asdict(self), "stage_complete": self.stage_complete}

    def _legacy_to_dict(self) -> Dict[str, Any]:
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
            "unresolved_entry_functions": self.unresolved_entry_functions,
            "reconciled_functions": self.reconciled_functions,
            "reconciliation_unchanged_functions": self.reconciliation_unchanged_functions,
            "reconciliation_failures": self.reconciliation_failures,
            "unknown_project_callees": self.unknown_project_callees,
            "stage_complete": self.stage_complete,
            "components": self.components,
            "cyclic_components": self.cyclic_components,
            "total_context_tokens": self.total_context_tokens,
            "duration_seconds": self.duration_seconds,
            "modeled_order": list(self.modeled_order),
        }

    @property
    def stage_complete(self) -> bool:
        return (
            self.failed_functions <= MAX_FAILED_FUNCTIONS_FOR_STAGE
            and self.failed_dependencies == 0
            and self.unresolved_entry_functions == 0
            and self.reconciliation_failures == 0
            and not self.partial_reasons
        )


@dataclass
class _Graph:
    nodes: Set[FunctionKey] = field(default_factory=set)
    entry_keys: Set[FunctionKey] = field(default_factory=set)
    children: Dict[FunctionKey, Set[FunctionKey]] = field(default_factory=dict)
    impls: Dict[FunctionKey, Dict[str, Any]] = field(default_factory=dict)
    unresolved: Set[FunctionKey] = field(default_factory=set)
    aliases: Dict[FunctionKey, FunctionKey] = field(default_factory=dict)
    external_models: Dict[FunctionKey, str] = field(default_factory=dict)
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
        scheduler: Optional[ScanScheduler] = None,
        demand_hints: Sequence["SemanticDemandHint"] = (),
        demand_security_map: Optional["SecuritySemanticMap"] = None,
        demand_audit_units: Sequence["AuditUnit"] = (),
    ) -> None:
        self.config = config
        self.code_index = code_index
        self.snapshot_store = snapshot_store
        self.user_config = user_config
        self.semantic_agent_factory = semantic_agent_factory
        self.attach_contract = attach_contract or (lambda context, agent_name: None)
        self.scheduler = scheduler
        self.demand_hints = demand_hints
        self.demand_security_map = demand_security_map
        self.demand_audit_units = demand_audit_units
        configured_inflight = max(
            1,
            int(getattr(config.concurrency, "llm_max_inflight", 1) or 1),
        )
        self.max_workers = max(
            1,
            min(int(max_workers or configured_inflight), configured_inflight),
        )
        self._stats_lock = threading.Lock()
        self.result: Any = None

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
        scheduler: Optional[ScanScheduler] = None,
    ) -> "GlobalModeler":
        sm_llm_ref = modeling_profile(config)
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
            scheduler=scheduler,
            max_workers=config.concurrency.llm_max_inflight,
        )

    def run(self, entries: Sequence[FunctionEntry]) -> GlobalModelStats:
        from .semantic_modeling import IncrementalSemanticModeling
        from ..retrieval.code_index import semantic_modeling_context

        with semantic_modeling_context():
            self.result = IncrementalSemanticModeling(self).run(entries)
        return cast(GlobalModelStats, self.result.stats)

    def _run_legacy(self, entries: Sequence[FunctionEntry]) -> GlobalModelStats:
        started = time.time()
        graph = self._collect_graph(entries)
        stats = GlobalModelStats(
            reachable_functions=len(graph.impls),
            unresolved_external_callees=len(graph.unresolved),
            depth_capped_edges=graph.depth_capped_edges,
            breadth_capped_edges=graph.breadth_capped_edges,
            unresolved_entry_functions=len(graph.entry_keys & graph.unresolved),
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

        pending_children = {idx: len(component_children[idx]) for idx in range(len(components))}
        ready = [idx for idx, count in pending_children.items() if count == 0]
        done_components: Set[int] = set()

        executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        if self.scheduler is None:
            executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix="zscope-global-model",
            )
        try:
            future_to_component: Dict[concurrent.futures.Future[None], int] = {}
            while ready or future_to_component:
                while ready:
                    component_idx = ready.pop()
                    if self.scheduler is not None:
                        future = self.scheduler.submit(
                            ENTRY_ROLE,
                            self._model_component,
                            components[component_idx],
                            graph,
                            stats,
                            priority=len(components[component_idx]),
                        )
                    else:
                        assert executor is not None
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
        finally:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)

        if stats.failed_functions == 0 and stats.unresolved_entry_functions == 0:
            self._reconcile_project_callee_summaries(graph, stats)

        stats.duration_seconds = time.time() - started
        return stats

    def _collect_graph(self, entries: Sequence[FunctionEntry]) -> _Graph:
        graph = _Graph()
        queue: List[Tuple[FunctionKey, int]] = [
            (
                FunctionKey(
                    entry.function_name,
                    str(entry.file_path or ""),
                    FunctionEntry.normalize_signature(entry.signature),
                ),
                0,
            )
            for entry in entries
        ]
        graph.entry_keys = {key for key, _depth in queue}
        max_depth = -1
        max_callees = -1
        if max_depth == 0 or max_callees == 0:
            graph.unresolved.update(graph.entry_keys)
            return graph
        callee_query_limit = max_callees + 1 if max_callees > 0 else 2_147_483_647
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

            try:
                callee_records = self._get_callee_records(key, callee_query_limit)
            except Exception as exc:
                from ..common.cancellation import CancellationError

                if isinstance(exc, CancellationError):
                    raise
                logger.warning("Callgraph dependencies unavailable for %s: %s", key, exc)
                graph.unresolved.add(key)
                continue
            if max_callees > 0 and len(callee_records) > max_callees:
                graph.breadth_capped_edges += len(callee_records) - max_callees
                callee_records = callee_records[:max_callees]

            for record in callee_records:
                callee = self._key_from_callee_record(record)
                if not callee.name:
                    continue
                classifier = getattr(self.code_index, "call_model_status", None)
                status = classifier(callee.name, key.name, record) if callable(classifier) else ""
                if status in {"standard_model", "external_model_missing"}:
                    graph.external_models[callee] = status
                    continue
                graph.children[key].add(callee)
                queue.append((callee, depth + 1))

        self._canonicalize_graph_edges(graph)
        return graph

    def _reconcile_project_callee_summaries(
        self,
        graph: _Graph,
        stats: GlobalModelStats,
    ) -> None:
        summary_map: Dict[str, str] = {}
        for impl in graph.impls.values():
            index_name = str(impl.get("index_name") or "").strip()
            snapshot = self.snapshot_store.load_snapshot(index_name) if index_name else None
            summary = str(snapshot.get("summary") or "").strip() if snapshot else ""
            if not index_name or not summary:
                stats.reconciliation_failures += 1
                logger.warning(
                    "[snapshot-reconcile] summary map missing index_name=%s "
                    "reason=global_summary_missing",
                    index_name or "unknown",
                )
                continue
            summary_map[index_name] = summary

        if stats.reconciliation_failures:
            return

        for key, impl in sorted(graph.impls.items()):
            try:
                context = build_semantic_model_input(
                    self.code_index,
                    key.name,
                    file_path=str(impl.get("file") or key.file_path or ""),
                    index_name=str(impl.get("index_name") or ""),
                    start_line=int(impl.get("start_line") or 0) or None,
                    include_context=False,
                )
                context = hydrate_project_callee_summaries_from_map(
                    context,
                    summary_map,
                )
                stats.unknown_project_callees += sum(
                    1
                    for item in context.get("project_callees", [])
                    if str(item.get("callee_summary") or "").strip() == "unknown"
                )
                status = self.snapshot_store.reconcile_project_callee_summaries(
                    str(context["index_name"]),
                    context,
                )
            except Exception as exc:
                status = "failed"
                logger.exception(
                    "[snapshot-reconcile] global refresh failed key=%s error=%s",
                    self._format_key(key),
                    exc,
                )
            if status == "refreshed":
                stats.reconciled_functions += 1
            elif status == "unchanged":
                stats.reconciliation_unchanged_functions += 1
            else:
                stats.reconciliation_failures += 1
                logger.warning(
                    "[snapshot-reconcile] global refresh incomplete key=%s status=%s",
                    self._format_key(key),
                    status,
                )

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
        try:
            context = build_semantic_model_input(
                self.code_index,
                key.name,
                file_path=str(impl.get("file") or key.file_path or ""),
                index_name=str(impl.get("index_name") or ""),
                start_line=int(impl.get("start_line") or 0) or None,
                include_context=False,
            )
            context = hydrate_project_callee_summaries(
                context,
                self.code_index,
                self.snapshot_store,
            )
        except SemanticModelInputError as exc:
            logger.warning(
                "[global-model] Skipping LLM snapshot key=%s reason=%s llm_called=false",
                self._format_key(key),
                exc.reason,
            )
            return "failed", 0
        index_name = str(context["index_name"])
        if self._has_current_snapshot(key, context):
            return "cache_hit", 0

        lock_started = time.monotonic()
        logger.info(
            "[snapshot-lock] waiting context=global index_name=%s",
            index_name,
        )
        lock_status = self.snapshot_store.lock_manager.acquire(index_name)
        logger.info(
            "[snapshot-lock] outcome context=global index_name=%s status=%s waited=%.2fs",
            index_name,
            lock_status,
            time.monotonic() - lock_started,
        )
        if lock_status == "done":
            return "cache_hit", 0
        if lock_status == "timeout":
            logger.warning(
                "[global-model] Timeout waiting index_name=%s",
                index_name,
            )
            return "failed", 0

        success = False
        context_tokens = 0
        try:
            if self._has_current_snapshot(key, context):
                success = True
                return "cache_hit", 0

            code = str(context.get("code") or "")

            if not force_llm and is_lightweight_snapshot_candidate(key.name, context):
                snapshot = build_lightweight_snapshot(context["func_name"], context)
                self.snapshot_store.save_snapshot(index_name, snapshot, code)
                success = True
                return "deterministic", 0

            if not force_llm and is_trivial_function(
                code,
                self.config.analysis.trivial_function_max_lines,
            ):
                snapshot = build_trivial_snapshot(context["func_name"], context)
                self.snapshot_store.save_snapshot(index_name, snapshot, code)
                success = True
                return "deterministic", 0

            user_context = relevant_user_config_context(
                self.user_config,
                context["func_name"],
                context["code"],
                context["file_path"],
            )
            if user_context:
                context["user_config_context"] = user_context
            self.attach_contract(context, "semantic_modeler")
            response = run_semantic_model_with_retries(
                self.semantic_agent_factory,
                context,
                log_context="global",
                index_name=index_name,
                snapshot_store=self.snapshot_store,
            )
            metadata = response.metadata if response.metadata else {}
            finalization_mode = str(metadata.get("finalization_mode") or "legacy")
            terminal_tool = str(metadata.get("terminal_tool_name") or "")
            terminal_valid = bool(metadata.get("terminal_tool_valid", False))
            terminal_calls = int(metadata.get("terminal_tool_call_count", 0) or 0)
            context_tokens = int(
                metadata.get("context_tokens", 0) or metadata.get("total_tokens", 0) or 0
            )
            if response.success:
                self.snapshot_store.save_snapshot(
                    index_name,
                    response.data,
                    context["code"],
                    dependency_context=context,
                )
                logger.info(
                    "[snapshot-llm] completed context=global index_name=%s "
                    "success=true context_tokens=%d finalization_mode=%s "
                    "terminal_tool=%s terminal_tool_valid=%s terminal_tool_call_count=%d",
                    index_name,
                    context_tokens,
                    finalization_mode,
                    terminal_tool or "none",
                    terminal_valid,
                    terminal_calls,
                )
                success = True
                return "llm", context_tokens
            failure_reason = str(metadata.get("reason") or "semantic_model_failed")
            logger.warning(
                "[snapshot-llm] completed context=global index_name=%s "
                "success=false context_tokens=%d finalization_mode=%s "
                "terminal_tool=%s terminal_tool_valid=%s terminal_tool_call_count=%d "
                "reason=%s error=%s",
                index_name,
                context_tokens,
                finalization_mode,
                terminal_tool or "none",
                terminal_valid,
                terminal_calls,
                failure_reason,
                response.error,
            )
            return "failed", context_tokens
        except Exception as exc:
            logger.exception(
                "[snapshot-llm] failed context=global index_name=%s "
                "success=false context_tokens=%d reason=semantic_model_exception error=%s",
                index_name,
                context_tokens,
                exc,
            )
            return "failed", context_tokens
        finally:
            self.snapshot_store.lock_manager.release(
                index_name,
                success=success,
            )

    def _has_current_snapshot(self, key: FunctionKey, context: Dict[str, Any]) -> bool:
        del key
        index_name = str(context.get("index_name") or "")
        if not index_name:
            return False
        snapshot = self.snapshot_store.load_snapshot(index_name)
        if not snapshot:
            self.snapshot_store.lock_manager.invalidate(index_name)
            return False
        try:
            needs_refresh, _reason = self.snapshot_store.needs_refresh(
                index_name,
                str(context.get("code") or ""),
                context,
            )
        except Exception as exc:
            logger.warning(
                "[global-model] Snapshot refresh check failed index_name=%s "
                "reason=snapshot_refresh_check_failed error=%s",
                index_name,
                exc,
            )
            return False
        if needs_refresh:
            self.snapshot_store.lock_manager.invalidate(index_name)
        return not needs_refresh

    def _get_impl(self, key: FunctionKey, *, include_context: bool) -> Optional[Dict[str, Any]]:
        result: Optional[Dict[str, Any]] = None
        if key.signature:
            try:
                result = self.code_index.get_function_impl(
                    key.signature,
                    max_lines=None,
                    warn_missing=False,
                    include_context=include_context,
                    file_path=key.file_path,
                )
            except Exception as exc:
                logger.debug(
                    "[global-model] Signature lookup unavailable key=%s error=%s",
                    self._format_key(key),
                    exc,
                )
        if result is not None:
            return result
        try:
            impl = self.code_index.get_function_impl(
                key.name,
                max_lines=None,
                warn_missing=False,
                include_context=include_context,
                file_path=key.file_path,
            )
        except TypeError:
            return cast(
                Optional[Dict[str, Any]],
                self.code_index.get_function_impl(key.name),
            )
        if impl or not key.file_path or not is_header_like_path(key.file_path):
            return cast(Optional[Dict[str, Any]], impl)
        logger.debug(
            "[global-model] retrying header declaration without file constraint key=%s",
            self._format_key(key),
        )
        try:
            return cast(
                Optional[Dict[str, Any]],
                self.code_index.get_function_impl(
                    key.name,
                    max_lines=None,
                    warn_missing=False,
                    include_context=include_context,
                    file_path="",
                ),
            )
        except TypeError:
            return cast(
                Optional[Dict[str, Any]],
                self.code_index.get_function_impl(key.name),
            )

    def _get_callee_records(self, key: FunctionKey, limit: int) -> List[Any]:
        # Prefer canonical per-symbol facts: a name-only callgraph can combine
        # file-local homonyms or overloads from different implementations.
        finder = getattr(self.code_index, "find_function_metadata", None) or getattr(
            self.code_index, "find_function_infos", None
        )
        if callable(finder):
            impl = self._get_impl(key, include_context=False) or {}
            infos = finder(str(impl.get("index_name") or key.name), file_path=key.file_path)
            matches = [
                info
                for info in infos or []
                if isinstance(info, dict)
                and (not impl.get("index_name") or info.get("index_name") == impl["index_name"])
            ]
            if len(matches) == 1 and "project_callees" in matches[0]:
                project = list(matches[0].get("project_callees") or [])
                # Retain external declarations for coverage accounting, while the
                # graph classifier keeps them out of implementation modeling.
                external = [
                    r
                    for r in self.code_index.get_callees(key.name, limit=limit)
                    if isinstance(r, dict)
                    and r.get("callee_kind") in {"system_function", "external_function"}
                ]
                return project + external
        records = self.code_index.get_callees(
            key.signature or key.name,
            limit=limit,
        )
        if not records and key.signature:
            records = self.code_index.get_callees(key.name, limit=limit)
        if records:
            return list(records)
        impl = self._get_impl(key, include_context=True) or {}
        if not impl:
            return []
        return list(impl.get("callees") or [])

    @staticmethod
    def _key_from_impl(func_name: str, impl: Dict[str, Any]) -> FunctionKey:
        return FunctionKey(
            str(impl.get("func_name") or func_name),
            str(impl.get("file") or ""),
            FunctionEntry.normalize_signature(impl.get("signature") or ""),
        )

    @staticmethod
    def _key_from_callee_record(record: Any) -> FunctionKey:
        if isinstance(record, str):
            return FunctionKey(record)
        if not isinstance(record, dict):
            return FunctionKey("")
        if record.get("callee_index_name"):
            return FunctionKey(str(record["callee_index_name"]))
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
        signature = FunctionEntry.normalize_signature(
            record.get("signature") or record.get("callee_signature") or ""
        )
        return FunctionKey(name, file_path, signature)

    @staticmethod
    def _format_key(key: FunctionKey) -> str:
        base = f"{key.name}@{key.file_path}" if key.file_path else key.name
        return f"{base}::{key.signature}" if key.signature else base

    def _strongly_connected_components(
        self,
        graph: _Graph,
    ) -> Tuple[Dict[FunctionKey, int], List[List[FunctionKey]]]:
        # Iterative Kosaraju traversal avoids Python's recursion limit on long
        # entry paths. The scheduler owns dependency ordering between SCCs.
        nodes = sorted(graph.impls)
        adjacency = {
            node: sorted(child for child in graph.children.get(node, set()) if child in graph.impls)
            for node in nodes
        }
        reverse: Dict[FunctionKey, List[FunctionKey]] = {node: [] for node in nodes}
        for node, children in adjacency.items():
            for child in children:
                reverse[child].append(node)
        visited: Set[FunctionKey] = set()
        order: List[FunctionKey] = []
        for root in nodes:
            stack = [(root, False)]
            while stack:
                node, exiting = stack.pop()
                if exiting:
                    order.append(node)
                elif node not in visited:
                    visited.add(node)
                    stack.append((node, True))
                    stack.extend(
                        (child, False)
                        for child in reversed(adjacency[node])
                        if child not in visited
                    )
        visited.clear()
        components: List[List[FunctionKey]] = []
        for root in reversed(order):
            if root in visited:
                continue
            component: List[FunctionKey] = []
            pending = [root]
            while pending:
                node = pending.pop()
                if node in visited:
                    continue
                visited.add(node)
                component.append(node)
                pending.extend(reverse[node])
            components.append(sorted(component))
        component_for = {key: idx for idx, component in enumerate(components) for key in component}
        return component_for, components
