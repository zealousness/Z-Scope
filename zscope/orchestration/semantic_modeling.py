"""Incremental, dependency-driven semantic modeling before candidate generation."""

from __future__ import annotations

import concurrent.futures as futures
from contextlib import contextmanager
import copy
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence, TYPE_CHECKING

from ..agents.semantic_modeler.retry import run_semantic_model_with_retries
from ..agents.semantic_modeler.schema import (
    DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
    PROGRAM_GENERATED_SNAPSHOT_FIELDS,
    PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
)
from ..common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from ..config.function_entry import FunctionEntry
from ..semantics.contracts import (
    ApiContract,
    SymbolIdentity,
    code_tokens,
    contract_rows,
    digest,
    outward_contract,
    parse_pair_targets,
    CONTRACT_COMPILER_VERSION,
)
from ..semantics.contract_compiler import (
    compile_snapshot,
    complete_transparent_pairs,
    derive_contracts,
)
from ..snapshots.policy import SNAPSHOT_CANDIDATE_POLICY_VERSION
from ..snapshots.modeling_input import build_semantic_model_input

if TYPE_CHECKING:
    from .global_modeler import FunctionKey, GlobalModeler, GlobalModelStats, _Graph

logger = logging.getLogger(__name__)
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


@dataclass
class SessionSemanticResult:
    stats: Any
    snapshots: dict[str, dict[str, Any]] = field(default_factory=dict)
    entry_paths: dict[str, list[list[str]]] = field(default_factory=dict)
    contract_version: str = ""
    local_semantics: Any = None
    overlay: dict[str, Any] = field(default_factory=dict)
    suspicious_metrics: dict[str, Any] = field(default_factory=dict)
    entry_symbols: dict[str, list[str]] = field(default_factory=dict)
    symbol_paths: dict[str, list[list[str]]] = field(default_factory=dict)

    @property
    def partial(self) -> bool:
        return not self.stats.stage_complete


@contextmanager
def _propagate_modeling_interrupt(token: CancellationToken):
    """Signal workers before ThreadPoolExecutor waits for their termination."""
    try:
        yield
    except (KeyboardInterrupt, SystemExit):
        root = token
        while root._parent is not None:
            root = root._parent
        root.cancel("semantic_modeling_interrupted")
        raise


class IncrementalSemanticModeling:
    """One function per task; SCC rounds commit only after all members finish.

    The sidecar stores input fingerprints, not a second source of API roles.
    Rules receive only the registry rebuilt from the committed workbook.
    """

    def __init__(self, modeler: "GlobalModeler") -> None:
        self.modeler = modeler
        self.store = modeler.snapshot_store
        self.cache_dir = Path(self.store.snapshot_dir) / ".semantic-modeling"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.contexts: dict[Any, dict[str, Any]] = {}
        self.records: dict[Any, dict[str, Any]] = {}
        self.snapshots: dict[Any, dict[str, Any]] = {}
        self.outputs: dict[Any, str] = {}
        self.completed: set[Any] = set()
        self.token = current_cancellation_token() or CancellationToken()
        self.active = 0
        self.guard = threading.Lock()
        from .global_modeler import GlobalModelStats, modeling_profile
        from ..semantics.defaults import default_local_pattern_semantics

        self.stats = GlobalModelStats()
        prompt = Path(__file__).parents[1] / "agents" / "semantic_modeler" / "AGENT.md"
        cfg = modeler.config
        profile = modeling_profile(cfg)
        llm = cfg.llms.get(profile) or cfg.llms.get("default")
        self.spec = digest(
            {
                "version": 2,
                "contract_compiler": CONTRACT_COMPILER_VERSION,
                "program_facts": "zscope.program-events.v4",
                "schema": DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
                "prompt": prompt.read_text(encoding="utf-8"),
                "model": getattr(llm, "models", None),
                "profile": profile,
                "builtins": default_local_pattern_semantics().contracts.version,
            }
        )
        self.manual_rows: dict[str, Any] = {}

    def _check_cancelled(self) -> None:
        if self.token:
            self.token.raise_if_cancelled()

    def run(self, entries: Sequence[FunctionEntry]) -> SessionSemanticResult:
        lock_key = str(self.cache_dir.resolve())
        with _LOCKS_GUARD:
            lock = _LOCKS.setdefault(lock_key, threading.RLock())
        started = time.monotonic()
        while not lock.acquire(timeout=0.1):
            self._check_cancelled()
        self.stats.wait_seconds += time.monotonic() - started
        try:
            with bind_cancellation_token(self.token):
                return self._run(entries)
        finally:
            lock.release()

    def _run(self, entries: Sequence[FunctionEntry]) -> SessionSemanticResult:
        started = time.monotonic()
        self._check_cancelled()
        if self.token is None:
            from .modeling_coordinator import reset_local_epoch

            reset_local_epoch(str(self.store.snapshot_dir), self.store)
        workbook = self.modeler.user_config.workbook
        workbook.import_confirmed_reviews()
        self.manual_rows = {
            sheet: [r for r in rows if not str(r.get("source") or "").startswith("inferred")]
            for sheet, rows in workbook.read_rows().items()
        }
        try:
            graph = self.modeler._collect_graph(entries)
        except CancellationError:
            raise
        except Exception as exc:
            from .global_modeler import _Graph

            graph = _Graph()
            self.stats.partial_reasons.append(f"call_graph_unavailable:{type(exc).__name__}:{exc}")
        self._prepare_contexts(graph)
        self.stats.unresolved_entry_functions = len(graph.entry_keys & graph.unresolved)
        self.stats.unresolved_external_callees = len(graph.unresolved - graph.entry_keys)
        self.stats.standard_model_count = sum(
            s == "standard_model" for s in graph.external_models.values()
        )
        self.stats.external_model_missing = sorted(
            k.name for k, s in graph.external_models.items() if s == "external_model_missing"
        )
        self._schedule(graph)

        # Model explicitly referenced counterpart definitions even if no entry
        # invokes them. The search only adds symbols named by an actual contract.
        searched: set[SymbolIdentity] = set()
        searched_release_callers: set[str] = set()
        companion_entries: list[FunctionEntry] = []
        while True:
            additions = self._transparent_companions(graph, searched_release_callers)
            companion_entries.extend(additions)
            for snapshot in list(self.snapshots.values()):
                for raw in snapshot.get("interface_contracts", []) or []:
                    for target in parse_pair_targets(
                        [*raw.get("pairs", []), *raw.get("proposed_pairs", [])]
                    ):
                        if target in searched or any(
                            k.name == target.name
                            and (not target.file_path or k.file_path == target.file_path)
                            and (not target.signature or k.signature == target.signature)
                            for k in graph.impls
                        ):
                            continue
                        searched.add(target)
                        from .global_modeler import FunctionKey

                        if self.modeler._get_impl(
                            FunctionKey(target.name, target.file_path, target.signature),
                            include_context=False,
                        ):
                            additions.append(
                                FunctionEntry(
                                    target.name,
                                    file_path=target.file_path,
                                    signature=target.signature,
                                )
                            )
            if not additions:
                break
            extra = self.modeler._collect_graph(additions)
            graph.nodes.update(extra.nodes)
            graph.impls.update(extra.impls)
            graph.children.update(extra.children)
            graph.unresolved.update(extra.unresolved)
            graph.aliases.update(extra.aliases)
            self.modeler._canonicalize_graph_edges(graph)
            self._prepare_contexts(graph)
            self._schedule(graph)

        self.stats.reachable_functions = len(graph.impls)
        self.stats.failed_dependencies = sum(
            1 for key in graph.unresolved if key in graph.impls or key.file_path or "@" in key.name
        )
        index_path = self.cache_dir / "coverage.json"
        previous = self._read_json(index_path)
        coverage = dict(previous.get("entries") or {})
        current_ids = {self._identity(key).key: key for key in graph.impls}
        covered_ids = set(current_ids)
        companion_edges = {key: set(children) for key, children in graph.children.items()}
        for key, snapshot in self.snapshots.items():
            for raw in snapshot.get("interface_contracts", []) or []:
                for target in parse_pair_targets(raw.get("pairs", [])):
                    companion_edges.setdefault(key, set()).update(
                        k
                        for k in graph.impls
                        if k.name == target.name
                        and (not target.file_path or k.file_path == target.file_path)
                        and (not target.signature or k.signature == target.signature)
                    )
        # Only retract previously generated data owned by the entries scanned
        # now; unrelated entry configurations remain available.
        scanned_entries = set()
        for entry in entries:

            def matches_entry(symbol: SymbolIdentity) -> bool:
                return (
                    symbol.name == entry.function_name
                    and (
                        not entry.file_path
                        or symbol.file_path == str(entry.file_path).replace("\\", "/")
                    )
                    and (
                        not entry.signature
                        or symbol.signature == " ".join(code_tokens(entry.signature))
                    )
                )

            # Persist the resolved symbol, independent of whether the caller
            # supplied a file/signature hint in this particular invocation.
            for old_entry_id in list(coverage):
                try:
                    old_symbol = SymbolIdentity.from_value(json.loads(old_entry_id))
                except (ValueError, TypeError):
                    continue
                if matches_entry(old_symbol):
                    covered_ids.update(coverage.pop(old_entry_id))
            roots = [key for key in graph.entry_keys if matches_entry(self._identity(key))]
            for root in roots:
                entry_id = self._identity(root).key
                scanned_entries.add(entry_id)
                visited = set()
                pending = [root]
                while pending:
                    key = pending.pop()
                    if key in visited:
                        continue
                    visited.add(key)
                    pending.extend(companion_edges.get(key, set()) - visited)
                coverage[entry_id] = sorted(
                    self._identity(key).key for key in visited if key in graph.impls
                )
                coverage[entry_id] = sorted(
                    set(coverage[entry_id])
                    | {
                        self._identity(key).key
                        for key in graph.impls
                        if any(
                            key.name == companion.function_name
                            and (not companion.file_path or key.file_path == companion.file_path)
                            for companion in companion_entries
                        )
                    }
                )
        owned_elsewhere = {
            identity
            for entry_id, identities in coverage.items()
            if entry_id not in scanned_entries
            for identity in identities
        }
        covered_ids -= owned_elsewhere - set(current_ids)
        covered = set()
        for identity in covered_ids:
            try:
                symbol = SymbolIdentity.from_value(json.loads(identity))
                covered.add((symbol.name, symbol.file_path, symbol.signature))
            except (ValueError, TypeError):
                continue
        # Pair closure is a publication product. Do not feed generated workbook
        # edges back into per-function LLM inputs or mutate cached snapshots.
        publication = copy.deepcopy(list(self.snapshots.values()))
        from ..semantics.defaults import default_local_pattern_semantics

        pair_registry = default_local_pattern_semantics().contracts
        for sheet in self.manual_rows.values():
            for row in sheet:
                contract = ApiContract.from_row(row)
                if contract:
                    pair_registry.add(contract)
        self.stats.derived_pair_count = complete_transparent_pairs(publication, pair_registry)
        rows = contract_rows(publication)
        from ..semantics.contract_review import review_roots

        review = review_roots(publication, pair_registry)
        rows["contract_review"] = review["rows"]
        self.store._write_json_atomic(self.cache_dir / "contract-review.json", review)
        self.stats.published_contract_count = sum(len(items) for items in rows.values())
        published_config = self.modeler.user_config
        try:
            workbook.merge_generated(rows, covered_symbols=covered)
            self.store._write_json_atomic(index_path, {"entries": coverage})
        except OSError as exc:
            self.stats.partial_reasons.append(f"workbook_publication_failed:{type(exc).__name__}")
            published_config = self._manual_config()
        return self._publish(graph, published_config, started)

    def _transparent_companions(self, graph: "_Graph", searched: set[str]) -> list[FunctionEntry]:
        """Search callers of explicit protocol endpoints, then check their source.

        A caller's spelling does not participate in this search. Business callers
        with internal cleanup or additional release obligations are excluded.
        """
        from .global_modeler import FunctionKey
        from ..semantics.defaults import default_local_pattern_semantics
        from ..semantics.contracts import ACQUIRE_ROLES, RELEASE_ROLES

        getter = getattr(self.modeler.code_index, "get_callers", None)
        if not callable(getter):
            return []
        registry = default_local_pattern_semantics().contracts
        for snapshot in self.snapshots.values():
            for raw in snapshot.get("interface_contracts", []):
                contract = ApiContract.from_row(
                    {"contract": raw, "symbol_name": snapshot.get("func_name")}
                )
                if contract:
                    registry.add(contract)
        endpoints = {
            target.name
            for contract in registry.contracts
            if contract.role in ACQUIRE_ROLES and contract.source.startswith("inferred")
            for target in contract.pairs
        }
        additions = []
        for endpoint in sorted(endpoints - searched):
            searched.add(endpoint)
            try:
                callers = getter(endpoint, limit=2_147_483_647)
                for caller in callers:
                    name = str(
                        caller.get("name")
                        or caller.get("caller_name")
                        or caller.get("function")
                        or ""
                    )
                    file = str(
                        caller.get("file")
                        or caller.get("file_path")
                        or caller.get("caller_file")
                        or ""
                    )
                    if not name or any(
                        k.name == name and (not file or k.file_path == file) for k in graph.impls
                    ):
                        continue
                    impl = self.modeler._get_impl(
                        FunctionKey(name, file, ""), include_context=False
                    )
                    if not impl:
                        continue
                    context = {**impl, "func_name": name, "file_path": impl.get("file", file)}
                    candidates = derive_contracts(context, registry)
                    if any(
                        c["role"] in RELEASE_ROLES
                        and any(d.get("transparent") for d in c["delegates"])
                        for c in candidates
                    ):
                        additions.append(FunctionEntry(name, file_path=file))
            except CancellationError:
                raise
            except Exception as exc:
                self.stats.partial_reasons.append(
                    f"pair_companion_search:{endpoint}:{type(exc).__name__}"
                )
        return additions

    def _manual_config(self) -> Any:
        """Retain only human input when generated data cannot be published."""
        from ..config.user_config_workbook import UserConfigWorkbook

        rows = copy.deepcopy(self.manual_rows)

        class ReadOnlyRows(UserConfigWorkbook):
            def read_rows(self) -> Any:
                return copy.deepcopy(rows)

        config = copy.copy(self.modeler.user_config)
        config.workbook = ReadOnlyRows(self.modeler.user_config.workbook.path)
        return config

    def _publish(
        self, graph: "_Graph", published_config: Any, started: float
    ) -> SessionSemanticResult:

        # This read is the publication barrier. No rule sees model output before
        # manual precedence, generated-row retirement and workbook parsing.
        from ..semantics.inference import LocalPatternSemanticBuilder
        from ..core.candidates.evidence import SemanticOverlayCompiler

        builder = LocalPatternSemanticBuilder(
            self.modeler.code_index,
            published_config,
            self.store,
            (Path(path) for path in self.modeler.config.project.exclude_paths),
        )
        semantics = builder.semantics_from_user_config()
        if hasattr(self.modeler.code_index, "source_root") and hasattr(
            self.modeler.code_index, "project_root"
        ):
            semantics.merge(builder.scan_typedef_aliases())
        from ..semantics.defaults import default_local_pattern_semantics

        effective = default_local_pattern_semantics()
        effective.merge(semantics)
        self.stats.published_contract_count = sum(
            c.source.startswith("inferred") for c in effective.contracts.contracts
        )
        overlay = SemanticOverlayCompiler(published_config).compile()
        overlay["contract_version"] = effective.contracts.version
        overlay["shadowed_symbols"] = sorted(effective.contracts.shadowed_symbols)
        self.stats.duration_seconds = time.monotonic() - started
        from .modeling_coordinator import scan_coordinator

        self.stats.modeling_tasks = scan_coordinator(
            str(self.store.snapshot_dir), self.store
        ).metrics()
        result = SessionSemanticResult(
            self.stats,
            contract_version=effective.contracts.version,
            local_semantics=effective,
            overlay=overlay,
        )
        for key, snapshot in self.snapshots.items():
            identity = self._identity(key).key
            result.snapshots[identity] = snapshot
            paths = self._symbol_paths(key, graph)
            result.entry_paths[identity] = [[node.name for node in path] for path in paths]
            result.entry_symbols[identity] = [self._identity(path[0]).key for path in paths]
            result.symbol_paths[identity] = [
                [self._identity(node).key for node in path] for path in paths
            ]
        result.suspicious_metrics = {
            "enabled": False,
            "policy_version": SNAPSHOT_CANDIDATE_POLICY_VERSION,
            "total": sum(len(s.get("suspicious_points") or []) for s in self.snapshots.values()),
            "registered": 0,
            "merged": 0,
            "unresolved": 0,
            "reason": "snapshot_observations_are_validator_context",
        }
        from ..semantics.contracts import semantic_model_unit_uid

        audit = {
            "schema_version": CONTRACT_COMPILER_VERSION,
            "contract_version": result.contract_version,
            "snapshot_candidate_policy": SNAPSHOT_CANDIDATE_POLICY_VERSION,
            "stats": self.stats.to_dict(),
            "workbook": str(self.modeler.user_config.workbook.path),
            "api_contracts": overlay.get("api_contracts", []),
            "api_pairs": overlay.get("api_pairs", []),
            "failed_models": [
                failure
                for key in graph.impls
                if (
                    failure := self._read_json(
                        self.cache_dir / (digest(self._identity(key).key) + ".failure.json")
                    )
                )
            ],
            "call_sites": [
                event
                for context in self.contexts.values()
                for event in effective.contracts.trace_calls(context)
            ],
            "snapshots": [
                {
                    "symbol": identity,
                    "audit_unit_uid": semantic_model_unit_uid(snapshot),
                    "index_name": snapshot.get("index_name"),
                    "snapshot_hash": digest(snapshot),
                    "raw_interface_contracts": snapshot.get("raw_interface_contracts", []),
                    "normalized_interface_contracts": snapshot.get("interface_contracts", []),
                    "diagnostics": snapshot.get("contract_diagnostics", []),
                }
                for identity, snapshot in result.snapshots.items()
            ],
        }
        audit["call_site_counts"] = {
            status: sum(e["applicability"] == status for e in audit["call_sites"])
            for status in ("applies", "does_not_apply", "unknown")
        }
        try:
            self.store._write_json_atomic(self.cache_dir / "publication.json", audit)
        except OSError as exc:
            self.stats.partial_reasons.append(f"semantic_audit_export:{type(exc).__name__}")
        return result

    def _identity(self, key: Any) -> SymbolIdentity:
        return SymbolIdentity.from_value(
            {
                "name": key.name,
                "file_path": key.file_path,
                "signature": key.signature,
                "symbol_type": (
                    "macro" if self.contexts.get(key, {}).get("is_macro") else "function"
                ),
            }
        )

    def _prepare_contexts(self, graph: "_Graph") -> None:
        from .global_modeler import FunctionKey

        pending = list(graph.impls)
        while pending:
            self._check_cancelled()
            key = pending.pop()
            if key in self.contexts or key in self.completed:
                continue
            impl = graph.impls[key]
            try:
                if impl.get("is_macro") and not re.search(
                    r"(?:#\s*define\s+)?" + re.escape(key.name) + r"\(",
                    str(impl.get("code") or ""),
                ):
                    context = {
                        "func_name": key.name,
                        "index_name": impl["index_name"],
                        "file_path": str(impl.get("file") or key.file_path),
                        "start_line": int(impl.get("start_line") or 1),
                        "end_line": int(impl.get("end_line") or impl.get("start_line") or 1),
                        "signature": str(impl.get("signature") or ""),
                        "is_macro": True,
                        "is_static": False,
                        "code": str(impl.get("code") or ""),
                        **{field: [] for field in PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS},
                    }
                else:
                    context = build_semantic_model_input(
                        self.modeler.code_index,
                        key.name,
                        file_path=str(impl.get("file") or key.file_path),
                        index_name=str(impl.get("index_name") or ""),
                        include_context=False,
                    )
                self.contexts[key] = context
                getter = getattr(self.modeler.code_index, "get_function_program_facts", None)
                if callable(getter) and not context.get("is_macro"):
                    context["program_facts"] = getter(key.name, context["file_path"])
                unresolved = []
                classifier = getattr(self.modeler.code_index, "call_model_status", None)
                for target in context.get("unresolved_callees", []):
                    name = str(target.get("callee_name") or "")
                    status = classifier(name, key.name, target) if callable(classifier) else ""
                    if status in {"standard_model", "external_model_missing"}:
                        context.setdefault("external_model_dependencies", []).append(
                            {**target, "status": status}
                        )
                    else:
                        unresolved.append(target)
                if unresolved:
                    context["unresolved_callees"] = unresolved
                else:
                    context.pop("unresolved_callees", None)
                if impl.get("truncated"):
                    self.stats.partial_reasons.append(f"{key.name}:source_truncated")
                for field_name in ("unresolved_callees", "unresolved_referenced_types"):
                    if context.get(field_name):
                        self.stats.partial_reasons.append(f"{key.name}:{field_name}")
                for field_name, value in context.items():
                    if field_name.endswith("_truncation") and value:
                        self.stats.partial_reasons.append(f"{key.name}:{field_name}")
                for macro in context.get("referenced_macros", []):
                    name = str(macro.get("macro_index_name") or "")
                    match = re.match(r"(.+)@(.+):(\d+)-(\d+)$", name)
                    if not match:
                        self.stats.partial_reasons.append(f"{key.name}:unresolved_macro:{name}")
                        continue
                    macro_key = FunctionKey(match[1], match[2], "")
                    graph.children.setdefault(key, set()).add(macro_key)
                    if macro_key in graph.impls:
                        continue
                    macro_impl = self.modeler._get_impl(macro_key, include_context=False)
                    if macro_impl:
                        extra = self.modeler._collect_graph(
                            [FunctionEntry(macro_key.name, file_path=macro_key.file_path)]
                        )
                        graph.nodes.update(extra.nodes)
                        graph.impls.update(extra.impls)
                        graph.children.update(extra.children)
                        graph.unresolved.update(extra.unresolved)
                        graph.aliases.update(extra.aliases)
                        self.modeler._canonicalize_graph_edges(graph)
                        pending.extend(k for k in extra.impls if k not in self.contexts)
                        continue
                    # Macro facts already contain the authoritative full
                    # definition and identity; a function AST is unnecessary.
                    definition = str(macro.get("definition") or "")
                    macro_context: dict[str, Any] = {
                        "func_name": match[1],
                        "index_name": name,
                        "file_path": match[2],
                        "start_line": int(match[3]),
                        "end_line": int(match[4]),
                        "signature": "",
                        "is_macro": True,
                        "is_static": False,
                        "code": definition,
                        "project_callees": [],
                        "external_callees": [],
                        "referenced_globals": [],
                        "referenced_macros": [],
                        "referenced_types": [],
                    }
                    graph.impls[macro_key] = {**macro_context, "file": match[2]}
                    graph.children.setdefault(macro_key, set())
                    self.contexts[macro_key] = macro_context
                    self._load_record(macro_key)
                self._load_record(key)
            except CancellationError:
                raise
            except Exception as exc:
                logger.warning("Semantic modeling input unavailable for %s: %s", key, exc)
                self.stats.failed_functions += 1
                self.stats.partial_reasons.append(f"{key.name}:input_unavailable")
                self.completed.add(key)
                self.outputs[key] = "unknown"

    @staticmethod
    def _snapshot_content_hash(snapshot: dict[str, Any]) -> str:
        # Callee prose is refreshed by SnapshotStore without changing the model.
        content = dict(snapshot)
        content["project_callees"] = [
            (
                {k: v for k, v in item.items() if k != "callee_summary"}
                if isinstance(item, dict)
                else item
            )
            for item in snapshot.get("project_callees", [])
        ]
        return digest(content)

    def _load_record(self, key: Any) -> None:
        record = self._read_json(self.cache_dir / (digest(self._identity(key).key) + ".json"))
        self.records[key] = record
        snapshot = self.store.load_snapshot(str(record.get("index_name") or "")) if record else None
        if (
            snapshot is not None
            and not record.get("contract_errors")
            and (
                digest(snapshot) == record.get("snapshot_hash")
                or self._snapshot_content_hash(snapshot) == record.get("snapshot_content_hash")
            )
        ):
            record["cached_snapshot"] = snapshot
            self.outputs[key] = str(record.get("output_hash") or "unknown")
        else:
            self.outputs[key] = "unknown"

    def _schedule(self, graph: "_Graph") -> None:
        component_for, components = self.modeler._strongly_connected_components(graph)
        children: dict[int, set[int]] = {i: set() for i in range(len(components))}
        for parent, callees in graph.children.items():
            if parent not in component_for:
                continue
            for callee in callees:
                if callee in component_for and component_for[parent] != component_for[callee]:
                    children[component_for[parent]].add(component_for[callee])
        self.stats.components = len(components)
        cyclic = {
            i
            for i, members in enumerate(components)
            if len(members) > 1 or any(k in graph.children.get(k, set()) for k in members)
        }
        self.stats.cyclic_components = len(cyclic)
        finished = {
            i for i, members in enumerate(components) if all(k in self.completed for k in members)
        }
        rounds: dict[int, int] = {}
        batches: dict[int, dict[str, Any]] = {}
        jobs: dict[futures.Future[Any], tuple[int, Any]] = {}
        max_rounds = max(1, int(self.modeler.config.analysis.semantic_model_max_rounds))
        with (
            futures.ThreadPoolExecutor(
                max_workers=self.modeler.max_workers, thread_name_prefix="zscope-modeling"
            ) as pool,
            _propagate_modeling_interrupt(self.token),
        ):
            while len(finished) < len(components):
                self._check_cancelled()
                ready = [
                    i
                    for i in children
                    if i not in finished and i not in batches and children[i] <= finished
                ]
                for i in ready:
                    members = components[i]
                    frozen = dict(self.outputs)
                    rounds[i] = rounds.get(i, 0) + 1
                    self.stats.recursive_rounds += int(i in cyclic)
                    batches[i] = {
                        "results": {},
                        "before": {k: frozen.get(k, "unknown") for k in members},
                    }
                    for key in members:
                        if key not in self.contexts:
                            batches[i]["results"][key] = None
                            continue
                        future = pool.submit(self._task, key, graph, frozen, time.monotonic())
                        jobs[future] = (i, key)
                if jobs:
                    done, _ = futures.wait(jobs, timeout=0.1, return_when=futures.FIRST_COMPLETED)
                    for future in done:
                        i, key = jobs.pop(future)
                        batches[i]["results"][key] = future.result()
                for i in list(batches):
                    batch = batches[i]
                    if len(batch["results"]) != len(components[i]):
                        continue
                    changed = False
                    failed = False
                    for key, result in batch["results"].items():
                        if result is None:
                            failed = True
                            self.outputs[key] = "unknown"
                            self.snapshots.pop(key, None)
                            continue
                        snapshot, record, status = result
                        output = record["output_hash"]
                        changed |= output != batch["before"][key]
                        try:
                            self._commit(key, snapshot, record, status)
                        except CancellationError:
                            raise
                        except Exception as exc:
                            self.stats.failed_functions += 1
                            self.stats.partial_reasons.append(
                                f"{key.name}:snapshot_commit_failed:{type(exc).__name__}"
                            )
                            self.outputs[key] = "unknown"
                            self.snapshots.pop(key, None)
                            self._invalidate_record(key)
                            failed = True
                            continue
                        self.outputs[key] = output
                        self.snapshots[key] = snapshot
                    del batches[i]
                    if i in cyclic and changed and not failed and rounds[i] < max_rounds:
                        continue
                    if i in cyclic and (failed or changed):
                        self.stats.partial_reasons.append(
                            "recursive_contract_unknown:" + ",".join(k.name for k in components[i])
                        )
                        for key in components[i]:
                            self.outputs[key] = "unknown"
                            self.snapshots.pop(key, None)
                            self._invalidate_record(key)
                    finished.add(i)
                    self.completed.update(components[i])
                if (
                    not jobs
                    and not batches
                    and len(finished) != len(components)
                    and not any(i not in finished and children[i] <= finished for i in children)
                ):
                    raise RuntimeError("Semantic component scheduler stalled")

    def _task(self, key: Any, graph: "_Graph", frozen: dict[Any, str], queued: float) -> Any:
        with bind_cancellation_token(self.token):
            self._check_cancelled()
            with self.guard:
                self.active += 1
                self.stats.peak_concurrency = max(self.stats.peak_concurrency, self.active)
                self.stats.wait_seconds += time.monotonic() - queued
            try:
                return self._model(key, graph, frozen)
            except CancellationError:
                raise
            except Exception as exc:
                logger.warning("Semantic model failed for %s: %s", key, exc)
                with self.guard:
                    self.stats.failed_functions += 1
                    self.stats.partial_reasons.append(
                        f"{key.name}:model_failed:{type(exc).__name__}"
                    )
                self._invalidate_record(key)
                return None
            finally:
                with self.guard:
                    self.active -= 1

    def _model(self, key: Any, graph: "_Graph", frozen: dict[Any, str]) -> Any:
        context = copy.deepcopy(self.contexts[key])
        callees = {
            self._identity(child).key: frozen.get(child, "unknown")
            for child in graph.children.get(key, set())
            if child in graph.impls
        }
        identifiers = set(code_tokens(context["code"]))
        manual = {
            sheet: [
                r
                for r in rows
                if str(r.get("symbol_name") or r.get("func_name") or "") in identifiers
            ]
            for sheet, rows in self.manual_rows.items()
        }
        manual = {sheet: rows for sheet, rows in manual.items() if rows}
        manual_fingerprint = {
            sheet: [
                (
                    contract.structural()
                    if (contract := ApiContract.from_row(row))
                    else {
                        k: v for k, v in row.items() if k not in {"source", "confidence", "notes"}
                    }
                )
                for row in rows
            ]
            for sheet, rows in manual.items()
        }
        dependencies = {}
        for field_name in ("referenced_macros", "referenced_types", "referenced_globals"):
            dependencies[field_name] = sorted(
                (self._dependency_value(item) for item in context.get(field_name, [])), key=digest
            )

        from ..semantics.compiler_fingerprint import compiler_structure

        inputs = {
            "code": digest(code_tokens(context["code"])),
            "compilation": digest(compiler_structure(context.get("program_facts", {}))),
            "dependencies": digest(dependencies),
            "callees": digest(callees),
            "manual": digest(manual_fingerprint),
            "spec": self.spec,
        }
        cached = self.records.get(key) or {}
        cached_snapshot = cached.get("cached_snapshot")
        if cached_snapshot is not None and cached.get("inputs") == inputs:
            from .modeling_coordinator import scan_coordinator

            scan_coordinator(str(self.store.snapshot_dir), self.store).record_cache_hit()
            snapshot = self._relocate(cached_snapshot, context)
            record = {
                **cached,
                "index_name": context["index_name"],
                "snapshot_hash": digest(snapshot),
            }
            return snapshot, record, "cache_hit"
        tokenized = " ".join(code_tokens(context["code"]))
        if (
            context.get("is_macro")
            and not re.search(
                r"(?:#\s*define\s+)?" + re.escape(key.name) + r"\(", str(context.get("code") or "")
            )
        ) or (
            key not in graph.entry_keys
            and re.fullmatch(
                r"[^{}]+\{ return (?:[-+]?\s*\d+|NULL|nullptr|true|false) ; \}", tokenized
            )
        ):
            from ..snapshots.policy import build_trivial_snapshot

            snapshot = build_trivial_snapshot(context["func_name"], context)
            snapshot["interface_contracts"] = []
            snapshot["code"] = context["code"]
            return (
                snapshot,
                {
                    "inputs": inputs,
                    "output_hash": digest(outward_contract(snapshot)),
                    "index_name": context["index_name"],
                    "snapshot_hash": digest(snapshot),
                },
                "deterministic",
            )
        reason = next(
            (
                part
                for part in ("spec", "code", "compilation", "dependencies", "manual", "callees")
                if cached.get("inputs", {}).get(part) != inputs[part]
            ),
            "missing_or_invalid_snapshot",
        )
        with self.guard:
            self.stats.rebuild_reasons[self._identity(key).key] = reason
            self.stats.propagated_functions += int(reason == "callees")
        # Callee contracts are frozen for this round, including recursive peers.
        context["callee_interface_contracts"] = {
            self._identity(child).key: (
                outward_contract(
                    self.snapshots.get(child)
                    or (self.records.get(child) or {}).get("cached_snapshot")
                    or {}
                )
                if frozen.get(child, "unknown") != "unknown"
                else {"status": "unknown"}
            )
            for child in graph.children.get(key, set())
            if child in graph.impls
        }
        for item in context.get("project_callees", []):
            child = next(
                (
                    c
                    for c in graph.children.get(key, set())
                    if self.contexts.get(c, {}).get("index_name") == item.get("callee_index_name")
                ),
                None,
            )
            child_snapshot = (
                self.snapshots.get(child)
                or (self.records.get(child) or {}).get("cached_snapshot")
                or {}
            )
            item["callee_summary"] = (
                str(child_snapshot.get("summary") or "unknown")
                if frozen.get(child, "unknown") != "unknown"
                else "unknown"
            )
        # Execution certificates are not part of the outward semantic hash, but
        # composition must see the committed callee certificate, not a stripped
        # LLM-facing structural summary. Never reconstruct trust from prose.
        for child in graph.children.get(key, set()):
            identity = self._identity(child).key
            if (
                identity in context["callee_interface_contracts"]
                and frozen.get(child, "unknown") != "unknown"
            ):
                child_snapshot = (
                    self.snapshots.get(child)
                    or (self.records.get(child) or {}).get("cached_snapshot")
                    or {}
                )
                context["callee_interface_contracts"][identity]["interface_contracts"] = (
                    copy.deepcopy(child_snapshot.get("interface_contracts", []))
                )
        if manual:
            context["user_config_context"] = manual
        from ..semantics.defaults import default_local_pattern_semantics

        registry = default_local_pattern_semantics().contracts
        registry.shadowed_symbols.update(k.name for k in graph.impls if registry.find(k.name))
        for sheet in self.manual_rows.values():
            for row in sheet:
                contract = ApiContract.from_row(row)
                if contract:
                    registry.add(contract)
        for child in context["callee_interface_contracts"].values():
            for raw in child.get("interface_contracts", []):
                contract = ApiContract.from_row({"contract": raw})
                if contract:
                    registry.add(contract)

        from ..semantics.contract_compiler import deterministic_contract_snapshot

        adapter_snapshot = deterministic_contract_snapshot(context, registry)
        manual_self = [
            c
            for c in registry.find(key.name, file_path=context["file_path"])
            if c.source != "builtin_defaults" and not c.source.startswith("inferred")
        ]
        if manual_self:
            from ..snapshots.policy import build_trivial_snapshot

            adapter_snapshot = build_trivial_snapshot(context["func_name"], context)
            adapter_snapshot.update(
                interface_contracts=[c.to_dict() for c in manual_self],
                summary="Explicit project interface contract; implementation is not assumed proven.",
                code=context["code"],
            )
        if adapter_snapshot is not None:
            return (
                adapter_snapshot,
                {
                    "inputs": inputs,
                    "output_hash": digest(outward_contract(adapter_snapshot)),
                    "index_name": context["index_name"],
                    "snapshot_hash": digest(adapter_snapshot),
                },
                "deterministic",
            )

        def validate_response(response: Any, model_context: dict[str, Any]) -> list[str]:
            errors = compile_snapshot(
                response.data,
                model_context,
                registry,
                terminal_submissions=(response.metadata or {}).get("terminal_submissions", []),
            )
            response.metadata = dict(response.metadata or {}, contract_errors=errors)
            return errors

        context["standard_interface_contracts"] = [
            c.to_dict()
            for c in registry.contracts
            if c.source == "builtin_defaults"
            and c.symbol.name in identifiers
            and c.symbol.name not in registry.shadowed_symbols
        ]
        self.modeler.attach_contract(context, "semantic_modeler")
        response = run_semantic_model_with_retries(
            self.modeler.semantic_agent_factory,
            context,
            log_context="incremental",
            index_name=context["index_name"],
            response_validator=validate_response,
            snapshot_store=self.store,
            input_version=inputs,
        )
        self._check_cancelled()
        metadata = response.metadata or {}
        from ..semantics.contracts import semantic_model_unit_uid

        try:
            self.store._write_json_atomic(
                self.cache_dir / (digest(self._identity(key).key) + ".attempts.json"),
                {
                    "audit_unit_uid": semantic_model_unit_uid(context),
                    "symbol": self._identity(key).key,
                    "source_hash": inputs["code"],
                    "success": response.success,
                    "attempts": metadata.get("semantic_model_attempts", []),
                },
            )
        except OSError as exc:
            with self.guard:
                self.stats.partial_reasons.append(
                    f"{key.name}:attempt_audit_export:{type(exc).__name__}"
                )
        with self.guard:
            self.stats.total_context_tokens += int(
                metadata.get("cumulative_total_tokens")
                or metadata.get("total_tokens")
                or metadata.get("context_tokens")
                or 0
            )
            self.stats.contract_validation_retry_count += int(
                metadata.get("semantic_model_retry_count") or 0
            )
        contract_errors = list(metadata.get("contract_errors") or [])
        if not isinstance(response.data, dict) or (not response.success and not contract_errors):
            self.store._write_json_atomic(
                self.cache_dir / (digest(self._identity(key).key) + ".failure.json"),
                {
                    "symbol": self._identity(key).key,
                    "source_hash": inputs["code"],
                    "error": response.error,
                    "schema_errors": metadata.get("terminal_validation_errors", []),
                    "attempts": metadata.get("semantic_model_attempts", []),
                    "raw_interface_contracts": metadata.get("rejected_interface_contracts"),
                },
            )
            raise RuntimeError(response.error or "semantic_model_failed")
        if contract_errors:
            with self.guard:
                self.stats.contract_validation_failure_count += 1
                self.stats.partial_reasons.append(f"{key.name}:invalid_interface_contract")
        snapshot = copy.deepcopy(response.data)
        with self.guard:
            self.stats.extracted_contract_count += len(snapshot.get("raw_interface_contracts", []))
            self.stats.extracted_contract_count += sum(
                d.get("action") == "source_protocol_recovered"
                for d in snapshot.get("contract_diagnostics", [])
            )
            self.stats.rejected_contract_count += sum(
                d.get("action") == "not_published" for d in snapshot.get("contract_diagnostics", [])
            )
        for field_name in (
            *PROGRAM_GENERATED_SNAPSHOT_FIELDS,
            *PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
        ):
            if field_name in context:
                snapshot[field_name] = context[field_name]
        snapshot["snapshot_kind"] = "llm"
        snapshot["code"] = context["code"]
        record = {
            "inputs": inputs,
            "output_hash": digest(outward_contract(snapshot)),
            "index_name": context["index_name"],
            "snapshot_hash": digest(snapshot),
            "contract_errors": contract_errors,
        }
        return snapshot, record, "llm"

    def _commit(
        self, key: Any, snapshot: dict[str, Any], record: dict[str, Any], status: str
    ) -> None:
        old = self.records.get(key) or {}
        record["snapshot_content_hash"] = self._snapshot_content_hash(snapshot)
        (self.cache_dir / (digest(self._identity(key).key) + ".failure.json")).unlink(
            missing_ok=True
        )
        dependency_context = {
            **self.contexts[key],
            "project_callees": snapshot.get("project_callees", []),
        }
        snapshot_changed = (
            status != "cache_hit"
            or old.get("snapshot_hash") != record["snapshot_hash"]
            or old.get("index_name") != record["index_name"]
        )
        if snapshot_changed:
            self.store.save_snapshot(
                record["index_name"],
                snapshot,
                self.contexts[key]["code"],
                dependency_context=dependency_context,
            )
        if snapshot_changed or old.get("snapshot_content_hash") != record["snapshot_content_hash"]:
            self.store._write_json_atomic(
                self.cache_dir / (digest(self._identity(key).key) + ".json"),
                {k: v for k, v in record.items() if k != "cached_snapshot"},
            )
        self.records[key] = {**record, "cached_snapshot": snapshot}
        if key not in self.completed:
            self.stats.modeled_order.append(self.modeler._format_key(key))
            if status == "cache_hit":
                self.stats.cache_hit_functions += 1
            else:
                self.stats.modeled_functions += 1
                if status == "deterministic":
                    self.stats.deterministic_snapshot_count += 1
                else:
                    self.stats.llm_snapshot_count += 1

    def _invalidate_record(self, key: Any) -> None:
        self.records[key] = {}
        try:
            self.store._write_json_atomic(
                self.cache_dir / (digest(self._identity(key).key) + ".json"), {}
            )
        except OSError:
            logger.warning("Unable to invalidate semantic cache for %s", key)

    @staticmethod
    def _dependency_value(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: IncrementalSemanticModeling._dependency_value(v)
                for k, v in value.items()
                if k
                not in {
                    "reference_lines",
                    "callsite_lines",
                    "start_line",
                    "end_line",
                    "line",
                    "lines",
                }
            }
        if isinstance(value, list):
            return [IncrementalSemanticModeling._dependency_value(v) for v in value]
        if isinstance(value, str):
            # Backend index names include coordinates; symbol identity does not.
            return code_tokens(re.sub(r":\d+-\d+$", "", value))
        return value

    @staticmethod
    def _relocate(snapshot: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        from difflib import SequenceMatcher
        from .snapshot_candidates import _source_lines

        result = copy.deepcopy(snapshot)

        def indexed_tokens(value: dict[str, Any]) -> tuple[list[str], list[int]]:
            tokens, numbers = [], []
            for number, text in _source_lines(value).items():
                line_tokens = code_tokens(text)
                tokens.extend(line_tokens)
                numbers.extend([number] * len(line_tokens))
            return tokens, numbers

        old_tokens, old_lines = indexed_tokens(snapshot)
        new_tokens, new_lines = indexed_tokens(context)
        locations: dict[int, int] = {}
        for block in SequenceMatcher(
            None, old_tokens, new_tokens, autojunk=False
        ).get_matching_blocks():
            for offset in range(block.size):
                locations.setdefault(old_lines[block.a + offset], new_lines[block.b + offset])
        for point in result.get("suspicious_points", []):
            lines = str(point.get("lines") or "")
            if re.fullmatch(r"\s*\d+(?:\s*[-,]\s*\d+)*\s*", lines):
                point["lines"] = re.sub(
                    r"\d+", lambda m: str(locations.get(int(m[0]), int(m[0]))), lines
                )
        for name in (
            *PROGRAM_GENERATED_SNAPSHOT_FIELDS,
            *PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
            "code",
        ):
            if name in context:
                result[name] = context[name]
        summaries = {
            re.sub(r":\d+-\d+$", "", str(item.get("callee_index_name") or "")): item.get(
                "callee_summary", "unknown"
            )
            for item in snapshot.get("project_callees", [])
        }
        result["project_callees"] = [
            dict(
                item,
                callee_summary=summaries.get(
                    re.sub(r":\d+-\d+$", "", str(item.get("callee_index_name") or "")), "unknown"
                ),
            )
            for item in result.get("project_callees", [])
        ]
        return result

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _entry_paths(target: Any, graph: "_Graph") -> list[list[str]]:
        return [
            [key.name for key in path]
            for path in IncrementalSemanticModeling._symbol_paths(target, graph)
        ]

    @staticmethod
    def _symbol_paths(target: Any, graph: "_Graph") -> list[list[Any]]:
        paths = []
        for entry in sorted(graph.entry_keys):
            queue = [(entry, [entry])]
            visited = set()
            while queue:
                node, path = queue.pop(0)
                if node == target:
                    paths.append(path)
                    break
                if node in visited:
                    continue
                visited.add(node)
                queue.extend(
                    (child, path + [child])
                    for child in sorted(graph.children.get(node, set()))
                    if child not in visited
                )
        return paths
