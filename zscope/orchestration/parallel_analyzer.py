"""
Parallel Analyzer for Z-SCOPE.
Supports concurrent analysis of multiple functions using thread pool.
"""

import concurrent.futures
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from copy import copy, deepcopy
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from dataclasses import dataclass, field, replace

if TYPE_CHECKING:
    from .instance_semantics_context import InstanceSemanticsContext
    from ..semantics.instance_semantics import InstanceSemanticsSnapshot
    from .jobs.instance_results import (
        InstanceResultPayload,
        RecoveryAccepted,
        RecoveryIdentity,
        RecoveryMiss,
    )

from ..config.config import ZScopeConfig, minimum_optional_positive_seconds
from ..config.function_entry import FunctionEntry
from ..config.user_config_store import UserConfigStore
from ..core.candidates.evidence import SemanticOverlayCompiler
from ..core.candidates.decision_facts import DecisionFactGraphCache
from ..core.candidates.function_facts import (
    FunctionFactSummary,
    function_source_fragment,
    numbered_source_fragment,
)
from ..core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from ..core.candidates.regex import RegexCandidateGenerator
from ..core.candidates.graph import GraphCandidateGenerator
from ..core.candidates.adapters import (
    clang_native_matcher_candidates_from_program_facts,
    dedupe_rule_candidates,
    merge_unified_evidence_candidates,
)
from ..core.analysis.analyzer import Analyzer, DEFAULT_SCAN_STEP_IDS
from ..core.validation.runner import ValidationResultCache
from ..rules.validation_obligations import builtin_obligation_coverage
from ..framework.llm_client import LLMClient
from ..framework.llm_usage import (
    ensure_scan_token_usage_ledger,
    scan_token_usage_snapshot,
)
from ..semantics.inference import LocalPatternSemanticBuilder
from ..semantics.models import LocalPatternSemantics
from ..semantics.instance_semantics import (
    ORIGIN_SYSTEM_RECEIPT,
    materialize_effect_semantics,
)
from ..semantics.security_map import SQLiteSecurityMapStore, ZeroLLMSecurityMapBuilder
from ..snapshots.store import SnapshotStore
from ..retrieval.code_index import CodeIndex
from ..retrieval.indexing_identity import atomic_json
from ..retrieval.instance_index import (
    GAP_INSTANCE_NOT_ANALYZED,
    InstanceAnalysisOutcome,
    InstanceAnalysisReport,
    InstanceScope,
    ScopedCodeIndex,
    instance_scope_from_entry_instance,
    wrap_scoped_code_index,
)
from ..orchestration.active_discovery import (
    ActiveDiscoveryAgent,
    ActiveDiscoveryCoordinator,
    SemanticEnrichmentAgent,
    SemanticMapEnricher,
    candidate_coverage_keys,
    historical_variant_keys,
    make_agent_report_runner,
    make_semantic_enrichment_runner,
    resolve_discovery_profile,
)
from ..orchestration.candidates import CandidateLedger, CandidateRegistrar
from ..orchestration.bounded_investigation import make_investigation_runner
from ..orchestration.candidate_envelope import annotate_issue_identity
from ..orchestration.global_modeler import GlobalModeler
from ..orchestration.rollout import (
    rollout_active_discovery_mode,
    rollout_runtime_policy,
)
from ..orchestration.scheduler import ENTRY_ROLE, ScanScheduler
from ..common.issue_identity import (
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
    deduplicate_issues,
    flatten_issue_text,
    issue_call_path_signature,
    issue_resource_signature,
    issue_rank,
    issue_sink_signature,
    issues_may_share_root_cause,
    merge_duplicate_issue,
    normalize_issue_category,
    normalize_issue_key_part,
    parse_issue_location,
    semantic_category_family,
    semantic_related_cluster_keys,
    semantic_root_cause_key,
)
from ..common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
)
from ..reporting.views import (
    build_report_views,
    coalesce_review_observations,
    report_view_summary,
)
from ..reporting.schema import apply_report_schema_v2, coalesce_terminal_candidates
from ..reporting.assembler import ReportAssembler
from ..rules.extensions import preflight_rules
from ..rules.catalog import serialize_effective_rules
from ..benchmarking.discovery_ablation import (
    DiscoveryAblationError,
    DiscoveryAblationRuntimeOverride,
)

logger = logging.getLogger(__name__)

_ENTRY_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_ENTRY_CONTROL_RE = re.compile(r"\b(if|for|while|switch|case|goto)\b")
_ENTRY_HEAVY_TEXT_RE = re.compile(
    r"(pthread|thread|callback|worker|recv|send|read|write|open|fopen|mmap|"
    r"malloc|calloc|realloc|free|lock|unlock|shared|global|argv|getenv|protocol|"
    r"message|runtime|dispatch|session)",
    re.IGNORECASE,
)
_ENTRY_EXPOSURE_WEIGHTS = {
    "other_user_input": 420,
    "communication": 380,
    "thread": 360,
    "callback": 360,
    "api": 140,
}

_PROJECT_KNOWLEDGE_UNSET = object()
_FAST_STATIC_CACHE_SCHEMA = "zscope.fast-static-cache.v12"
_FAST_STATIC_CACHE_DIRECTORY = (".zscope_knowledge", "fast-static", "v12")
_FAST_STATIC_CACHE_MAX_BYTES = 16 * 1024 * 1024


def _unwrapped_coverage_source(code_index: Any) -> Any:
    """The index a scan-level coverage consumer must read.

    A scoped instance facade pins ``get_build_contexts`` to one instance; its
    ``coverage_index`` accessor exposes the shared base. Anything else is
    returned unchanged.
    """

    resolver = getattr(code_index, "coverage_index", None)
    if callable(resolver):
        base = resolver()
        if base is not None:
            return base
    return code_index


def _integer_or_zero(value: Any) -> int:
    """Preserve the runtime's permissive metadata coercion with a typed edge."""

    return int(value or 0)


def _llm_client_usage_snapshots(
    clients: Dict[str, LLMClient],
) -> Dict[int, Dict[str, Any]]:
    snapshots: Dict[int, Dict[str, Any]] = {}
    for client in clients.values():
        client_id = id(client)
        if client_id in snapshots:
            continue
        snapshotter = getattr(client, "usage_snapshot", None)
        if callable(snapshotter):
            raw = snapshotter()
            snapshots[client_id] = dict(raw) if isinstance(raw, dict) else {}
    return snapshots


class _ScanLLMClients(dict[str, LLMClient]):
    """Carry the session factory's accounting start through pre-modeling.

    Session may compile Wiki or prepare semantics before constructing Parallel.
    The first analyzer can claim this start once. Reusing the same mapping in
    another analyzer starts from its current counters instead.
    """

    def __init__(self, clients: Dict[str, LLMClient]):
        super().__init__(clients)
        self._initial_usage = _llm_client_usage_snapshots(self)
        self._usage_claimed = False
        self._usage_claim_lock = threading.Lock()

    def claim_initial_usage(self) -> Optional[Dict[int, Dict[str, Any]]]:
        with self._usage_claim_lock:
            if self._usage_claimed:
                return None
            self._usage_claimed = True
            return deepcopy(self._initial_usage)


def _semantic_contract_observation_rows(events: Iterable[Any]) -> List[Dict[str, Any]]:
    """Compact exact call-site contract resolutions for post-score diagnosis."""

    rows: Dict[str, Dict[str, Any]] = {}
    for value in events:
        if not isinstance(value, Mapping):
            continue
        symbol_value = value.get("symbol")
        symbol = symbol_value if isinstance(symbol_value, Mapping) else {}
        verification_value = value.get("verification")
        verification = verification_value if isinstance(verification_value, Mapping) else {}
        row = {
            "name": str(symbol.get("name") or ""),
            "usr": str(symbol.get("usr") or ""),
            "role": str(value.get("role") or ""),
            "applicability": str(value.get("applicability") or "unknown"),
            "effects_trusted": bool(value.get("effects_trusted")),
            "source": str(value.get("source") or ""),
            "project_semantics_id": str(verification.get("project_semantics_id") or ""),
            "build_context_id": str(value.get("build_context_id") or ""),
            "call_ordinal": int(value.get("call_ordinal") or 0),
        }
        identity = json.dumps(row, ensure_ascii=False, sort_keys=True)
        rows[identity] = row
    return [rows[key] for key in sorted(rows)]


def _semantic_contract_reference_rows(
    context: Mapping[str, Any], registry: Any
) -> List[Dict[str, Any]]:
    """Exact contract-bearing callees referenced by one native function body.

    This is deliberately weaker than :func:`trace_calls`: a current native
    CallExpr/macro-reference receipt proves that the interface occurs in the
    function, but it does not prove a path guard or that the effect applies.
    Keeping the two observations separate lets the post-score audit distinguish
    an interface-discovery gap from the conservative source parser stopping at
    a loop or switch without granting execution semantics from a name match.
    """

    from ..semantics.build_scope import context_build_id, context_symbol_usr

    facts_value = context.get("program_facts")
    facts = facts_value if isinstance(facts_value, Mapping) else {}
    if facts.get("complete") is not True or facts.get("reason"):
        return []
    build_context_id = context_build_id(context)
    caller_usr = context_symbol_usr(context)
    if not build_context_id or not caller_usr:
        return []
    scoped = registry.for_context(context)
    references: Dict[tuple[str, str, str], Dict[str, Any]] = {}

    def add(name: str, usr: str, kind: str, line: Any = 0) -> None:
        if not name or not usr:
            return
        for contract in scoped.find_for_call(name, usr=usr):
            role = str(contract.role or "")
            verification = (
                contract.verification if isinstance(contract.verification, Mapping) else {}
            )
            row = {
                "name": name,
                "usr": usr,
                "role": role,
                "effects_trusted": bool(contract.effects_trusted),
                "source": str(contract.source or ""),
                "project_semantics_id": str(verification.get("project_semantics_id") or ""),
                "build_context_id": build_context_id,
                "reference_kind": kind,
                "line": int(line or 0),
            }
            references[(usr, role, kind)] = row

    bodies = [
        body
        for body in facts.get("functions", []) or []
        if isinstance(body, Mapping) and body.get("complete") is True
    ]
    if len(bodies) == 1:
        owner_value = bodies[0].get("owner")
        owner = owner_value if isinstance(owner_value, Mapping) else {}
        if str(owner.get("usr") or "") == caller_usr:
            for event in bodies[0].get("events", []) or []:
                if not isinstance(event, Mapping) or event.get("event_kind") != "call":
                    continue
                callee_value = event.get("callee")
                callee = callee_value if isinstance(callee_value, Mapping) else {}
                location_value = event.get("location")
                location = location_value if isinstance(location_value, Mapping) else {}
                add(
                    str(callee.get("name") or ""),
                    str(callee.get("usr") or ""),
                    "call",
                    location.get("line"),
                )

    for value in facts.get("referenced_macros", []) or []:
        if not isinstance(value, Mapping):
            continue
        identity_value = value.get("function_identity")
        identity = identity_value if isinstance(identity_value, Mapping) else {}
        if (
            str(identity.get("usr") or "") != caller_usr
            or str(identity.get("build_context_id") or "") != build_context_id
        ):
            continue
        add(
            str(value.get("name") or value.get("qualified_name") or ""),
            str(value.get("usr") or ""),
            "macro_reference",
            value.get("line"),
        )
    return [references[key] for key in sorted(references)]


def _semantic_contract_trace_status(context: Mapping[str, Any], registry: Any) -> str:
    """Report whether the path-aware source trace covered the whole body."""

    from ..semantics.contract_compiler import read_source_facts

    facts = read_source_facts(context, registry.for_context(context))
    return "complete" if facts.complete else "source_parser_incomplete"


class _InstanceEntryLookupIndex(ScopedCodeIndex):
    """Translate one verified full entry signature to its native navigation key."""

    def __init__(
        self,
        base: Any,
        scope: InstanceScope,
        entry: FunctionEntry,
        *,
        semantics_context: Optional["InstanceSemanticsContext"] = None,
        batch_guarded: bool = False,
    ):
        from ..snapshots.modeling_input import build_semantic_model_input
        from .instance_semantics_context import InstanceSemanticsContext

        super().__init__(base, scope)
        if semantics_context is not None and not isinstance(
            semantics_context, InstanceSemanticsContext
        ):
            raise ValueError("instance_entry_lookup_context_unverifiable")
        self._lookup_semantics_context = semantics_context
        self._lookup_batch_guarded = bool(batch_guarded)
        self._lookup_signature = ""
        self._lookup_index_name = ""
        self._lookup_function_name = entry.function_name
        self._expected_signature = ""
        self._lookup_definition_line = 0
        self._lookup_source = self._resolved_source(scope.source)
        model = build_semantic_model_input(
            self, entry.function_name, file_path=str(entry.file_path or ""), include_context=False
        )
        signature = FunctionEntry.normalize_signature(model.get("signature"))
        index_name = str(model.get("index_name") or "")
        self._expected_signature = signature
        self._lookup_definition_line = int(model.get("start_line") or 0)
        if (
            not signature
            or signature != FunctionEntry.normalize_signature(entry.signature)
            or not index_name
            or str(model.get("func_name") or "") != entry.function_name
            or not self._lookup_source
            or self._resolved_source(str(model.get("file_path") or "")) != self._lookup_source
            or self._resolved_source(str(entry.file_path or "")) != self._lookup_source
            or not self._native_lookup_identity_current()
        ):
            raise ValueError("instance_entry_lookup_identity_unverifiable")
        self._lookup_signature = signature
        self._lookup_index_name = index_name

    def _native_lookup_identity_current(self) -> bool:
        facts = super().get_function_program_facts(
            self.scope.usr, self.scope.source, build_context_id=self.scope.build_context_id
        )
        identity = facts.get("function_identity")
        if (
            facts.get("complete") is not True
            or not isinstance(identity, dict)
            or identity.get("usr") != self.scope.usr
            or identity.get("build_context_id") != self.scope.build_context_id
        ):
            return False
        bodies = facts.get("functions")
        if not isinstance(bodies, list) or len(bodies) != 1 or not isinstance(bodies[0], dict):
            return False
        body = bodies[0]
        owner = body.get("owner")
        callable_identity = body.get("callable")
        body_location = body.get("location")
        if (
            not isinstance(owner, dict)
            or not isinstance(callable_identity, dict)
            or not isinstance(body_location, dict)
        ):
            return False
        definitions = [
            row
            for row in self._context_rows(("function",), symbol=self._lookup_function_name)
            if row.get("usr") == self.scope.usr and row.get("is_declaration") is False
        ]
        if len(definitions) != 1:
            return False
        definition = definitions[0]
        begin = definition.get("begin")
        end = definition.get("end")
        location = definition.get("location")
        callable_location = callable_identity.get("location")
        if (
            not isinstance(begin, dict)
            or not isinstance(end, dict)
            or not isinstance(location, dict)
            or not isinstance(callable_location, dict)
        ):
            return False
        # The full native declaration, name and byte coordinates bind the
        # navigation signature to this USR even when two bodies share a line.
        if (
            owner.get("usr") != self.scope.usr
            or callable_identity.get("usr") != self.scope.usr
            or owner.get("name") != self._lookup_function_name
            or callable_identity.get("qualified_name") != self._lookup_function_name
            or definition.get("name") != self._lookup_function_name
            or FunctionEntry.normalize_signature(definition.get("signature"))
            != self._expected_signature
            or self._lookup_definition_line <= 0
            or begin.get("line") != self._lookup_definition_line
            or owner.get("line") != self._lookup_definition_line
            or self._resolved_source(str(owner.get("file") or "")) != self._lookup_source
        ):
            return False
        offsets: List[int] = []
        for coordinate in (begin, end, location, callable_location, body_location):
            offset = coordinate.get("offset")
            if (
                self._resolved_source(str(coordinate.get("file") or "")) != self._lookup_source
                or not isinstance(offset, int)
                or isinstance(offset, bool)
                or offset < 0
            ):
                return False
            offsets.append(offset)
        begin_offset, end_offset, location_offset, callable_offset, body_offset = offsets
        return (
            begin_offset <= location_offset <= end_offset
            and location_offset == callable_offset == body_offset
        )

    def _metadata_identity_conflicts(self, info: Dict[str, Any]) -> bool:
        identities = [info]
        if "function_identity" in info:
            identity = info["function_identity"]
            if not isinstance(identity, dict):
                return True
            identities.append(identity)
        return any(
            (identity.get("usr") and identity["usr"] != self.scope.usr)
            or (
                identity.get("build_context_id")
                and identity["build_context_id"] != self.scope.build_context_id
            )
            for identity in identities
        )

    def _scoped_function_infos(
        self, func_name: str, file_path: str, *, include_type_context: bool = True
    ) -> List[Dict[str, Any]]:
        translated = bool(self._lookup_signature) and func_name == self._lookup_signature
        query = self._lookup_index_name if translated else func_name
        infos = super()._scoped_function_infos(
            query, file_path, include_type_context=include_type_context
        )
        if any(self._metadata_identity_conflicts(info) for info in infos):
            return []
        if not translated:
            return infos
        if (
            len(infos) != 1
            or FunctionEntry.normalize_signature(infos[0].get("signature"))
            != self._lookup_signature
            or self._resolved_source(str(infos[0].get("file_path") or "")) != self._lookup_source
            or not self._native_lookup_identity_current()
        ):
            return []
        return infos

    def call_model_status(self, name: str, caller: str = "", record: Any = None) -> str:
        """Exclude only an actually called, currently authorized standard root."""
        from ..semantics.instance_semantics import (
            ORIGIN_SYSTEM_RECEIPT,
            materialize_effect_semantics,
        )

        context = self._lookup_semantics_context
        if context is None or caller not in {
            self._lookup_function_name,
            self._lookup_index_name,
            self._lookup_signature,
            self.scope.usr,
        }:
            return "source_unavailable"
        snapshot = (
            context.snapshot(self.scope)
            if self._lookup_batch_guarded
            else context.require(self.scope)
        )
        targets = []
        if self._native_lookup_identity_current():
            for row in self._context_rows(("call",)):
                owner, target = row.get("owner"), row.get("target")
                if (
                    isinstance(owner, dict)
                    and isinstance(target, dict)
                    and self._owner_is_entry(owner)
                    and owner.get("name") == self._lookup_function_name
                    and self._target_name(target) == name
                    and str(target.get("usr") or target.get("referenced_usr") or "")
                    and row.get("call_type") != "indirect"
                ):
                    targets.append(target)
        status = "source_unavailable"
        if targets and not self._call_record_conflicts(record, name, targets):
            semantics, overlay = materialize_effect_semantics(snapshot)
            origins = overlay.get("symbol_origins")
            if (
                isinstance(origins, dict)
                and origins.get(name) == ORIGIN_SYSTEM_RECEIPT
                and semantics.contracts.find(name)
            ):
                status = "standard_model"
        if self._lookup_batch_guarded:
            context.snapshot(self.scope)
        else:
            context.require(self.scope)
        return status

    def _call_record_conflicts(self, record: Any, name: str, targets: List[Dict[str, Any]]) -> bool:
        """Caller hints may reject current receipts, never authorize a target."""
        if record is None or (isinstance(record, str) and record == name):
            return False
        if not isinstance(record, dict):
            return True
        target_usrs = {target.get("usr") or target.get("referenced_usr") for target in targets}
        target_files = {
            self._resolved_source(str(location.get("file") or ""))
            for target in targets
            for field in ("declaration", "location")
            for location in [target.get(field)]
            if isinstance(location, dict)
        } - {""}
        for field in ("usr", "callee_usr", "target_usr"):
            if record.get(field) and record[field] not in target_usrs:
                return True
        for field in ("owner_usr", "caller_usr"):
            if record.get(field) and record[field] != self.scope.usr:
                return True
        if (
            record.get("build_context_id")
            and record["build_context_id"] != self.scope.build_context_id
        ):
            return True
        for field in ("source", "caller_file", "file", "file_path"):
            if (
                record.get(field)
                and self._resolved_source(str(record[field])) != self._lookup_source
            ):
                return True
        for field in ("callee_file", "filename"):
            if record.get(field) and self._resolved_source(str(record[field])) not in target_files:
                return True
        for field in ("name", "callee_name", "qualified_name"):
            if record.get(field) and record[field] != name:
                return True
        for field, expected_usrs, expected_files in (
            ("owner", {self.scope.usr}, {self._lookup_source}),
            ("target", target_usrs, target_files),
            (
                "function_identity",
                target_usrs | {self.scope.usr},
                target_files | {self._lookup_source},
            ),
        ):
            if field not in record:
                continue
            identity = record[field]
            if not isinstance(identity, dict):
                return True
            if identity.get("usr") and identity["usr"] not in expected_usrs:
                return True
            expected_names = (
                {self._lookup_function_name}
                if field == "owner"
                else ({name} if field == "target" else {name, self._lookup_function_name})
            )
            for name_field in ("name", "qualified_name"):
                if identity.get(name_field) and identity[name_field] not in expected_names:
                    return True
            if (
                identity.get("build_context_id")
                and identity["build_context_id"] != self.scope.build_context_id
            ):
                return True
            for path_field in ("file", "file_path", "source"):
                if (
                    identity.get(path_field)
                    and self._resolved_source(str(identity[path_field])) not in expected_files
                ):
                    return True
            for coordinate_field in ("declaration", "location"):
                if coordinate_field not in identity:
                    continue
                coordinate = identity[coordinate_field]
                if not isinstance(coordinate, dict):
                    return True
                if (
                    coordinate.get("file")
                    and self._resolved_source(str(coordinate["file"])) not in expected_files
                ):
                    return True
        return False


@dataclass
class ParallelAnalysisResult:
    """Result of parallel analysis across multiple functions."""

    function_name: str
    verdict: str
    entry_identity: str = ""
    entry_file_path: str = ""
    entry_signature: str = ""
    issues: List[Dict[str, Any]] = field(default_factory=list)
    audit_observations: List[Dict[str, Any]] = field(default_factory=list)
    candidate_terminal_states: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    entry_budget_seconds: Optional[float] = None
    entry_budget_exceeded: bool = False
    entry_budget_overrun_seconds: float = 0.0
    budget_exhaustion_policy: str = "observe"
    context_tokens: int = 0
    cumulative_prompt_tokens: int = 0
    cumulative_completion_tokens: int = 0
    cumulative_total_tokens: int = 0
    diff_focus: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Instance scope: only set when the entry was dispatched for one exact
    # ``(BuildContext, native USR)`` instance.
    build_context_id: str = ""
    usr: str = ""
    instance_identity: str = ""
    instance_scope_report: Optional[Dict[str, Any]] = None
    instance_collection: Optional[Dict[str, Any]] = None
    execution_completeness: str = "unknown"
    scan_outcome: str = "unknown"


@dataclass
class InstanceWorkBatch:
    """One scan-scope ledger shared across incrementally analyzed instances.

    Created by :meth:`ParallelAnalyzer.open_instance_batch` and finished by
    :meth:`ParallelAnalyzer.finish_instance_batch`; every work item in between
    analyzes into the same ledger, caches and validation queue.
    """

    analyzer: "ParallelAnalyzer"
    plan: Any
    scoped_entries: List[Tuple[FunctionEntry, Optional[InstanceScope]]] = field(
        default_factory=list
    )
    admission_lock: Any = field(default_factory=threading.RLock, repr=False)
    validation_state: str = "NOT_STARTED"
    results: Dict[str, ParallelAnalysisResult] = field(default_factory=dict)
    settled_instances: Set[str] = field(default_factory=set)
    restored_instances: Set[str] = field(default_factory=set)
    executed_instances: Set[str] = field(default_factory=set)

    @property
    def instances(self) -> List[Any]:
        return list(getattr(self.plan, "instances", []) or [])


class ParallelAnalyzer:
    """Analyze multiple entries with shared scheduling and owned resources."""

    _lifecycle_init_lock = threading.Lock()

    def _lifecycle_condition(self) -> threading.Condition:
        # Also initialize safely for lightweight embedded facades.
        with self._lifecycle_init_lock:
            if not hasattr(self, "_lifecycle_cv"):
                self._lifecycle_cv = threading.Condition(threading.RLock())
                self._active_batch_thread: Optional[int] = None
                self._closing = False
                self._close_complete = False
        return self._lifecycle_cv

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: Optional[CodeIndex] = None,
        user_config: Optional[UserConfigStore] = None,
        force_ignore_history: bool = False,
        maintain_mode: bool = False,
        cancellation_token: Optional[CancellationToken] = None,
        benchmark_ablation_override: Optional[DiscoveryAblationRuntimeOverride] = None,
        project_knowledge_service: Any = _PROJECT_KNOWLEDGE_UNSET,
        owns_project_knowledge_service: bool = False,
        llm_clients: Optional[Dict[str, LLMClient]] = None,
        semantic_result: Any = None,
        reproduction_service: Any = None,
    ):
        preflight_rules(config)
        self.base_config = config
        self.semantic_result = semantic_result
        from ..core.validation.reproduction_planner import SessionReproductionPlanner

        self.reproduction_service = reproduction_service or SessionReproductionPlanner(config)
        self.max_workers = config.concurrency.entry_workers
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        self._benchmark_ablation_override = benchmark_ablation_override
        if benchmark_ablation_override is not None:
            benchmark_ablation_override.require_in_process_supported()
            benchmark_ablation_override.validate_runtime_config(config)
            benchmark_ablation_override.require_cold_runtime_attested()
            if not force_ignore_history or maintain_mode:
                raise DiscoveryAblationError(
                    "isolated-cold ablation requires ignored history and forbids maintain mode"
                )
        self._owns_llm_clients = llm_clients is None
        self._shared_llm_clients = (
            llm_clients if llm_clients is not None else self._build_shared_llm_clients(config)
        )
        self._llm_usage_baseline = _llm_client_usage_snapshots(self._shared_llm_clients)
        if isinstance(self._shared_llm_clients, _ScanLLMClients):
            session_start = self._shared_llm_clients.claim_initial_usage()
            if session_start is not None:
                # A changed mapping cannot lend its factory start to a new,
                # already-used client added by a caller afterwards.
                self._llm_usage_baseline.update(
                    {
                        client_id: snapshot
                        for client_id, snapshot in session_start.items()
                        if client_id in self._llm_usage_baseline
                    }
                )
        self._llm_usage_batch_started = False
        if project_knowledge_service is _PROJECT_KNOWLEDGE_UNSET:
            self.project_knowledge_service = Analyzer.build_project_knowledge_service(
                config,
                self._shared_llm_clients,
            )
            self._owns_project_knowledge_service = True
        else:
            self.project_knowledge_service = project_knowledge_service
            self._owns_project_knowledge_service = bool(owns_project_knowledge_service)
        self._validation_result_cache = ValidationResultCache(
            max_entries=getattr(config.analysis, "validation_cache_entries", 4096)
        )
        self._decision_fact_cache = DecisionFactGraphCache()
        self._candidate_ledger = CandidateLedger(
            project_id=str(
                getattr(config.project, "project_id", "") or config.project.project_root.name
            ),
            project_root=str(config.project.project_root),
            revision=Analyzer._git_commit_sha(config.project.project_root),
        )
        self._scheduler: Optional[ScanScheduler] = None

        if code_index:
            self.code_index = code_index
        else:
            self.code_index = CodeIndex(
                config.project.project_root,
                config.project.compile_commands_path,
                source_root=config.project.project_root,
                indexing_config=config.indexing,
                include_paths=config.project.include_paths,
                exclude_paths=config.project.exclude_paths,
                svf_parallel_workers=(
                    config.concurrency.svf_workers or config.concurrency.index_workers
                ),
            )
        self.snapshot_store = SnapshotStore.from_config(config)
        db_dir = (
            Path(config.analysis.user_config_db)
            if config.analysis.user_config_db
            else Path(config.analysis.snapshot_dir)
        )
        self.user_config = user_config or UserConfigStore(db_dir)
        self._interrupted = False
        self._deadline_exceeded = False
        self._parent_cancellation_token = cancellation_token
        self._cancellation_token = CancellationToken(parent=cancellation_token)
        self._shared_local_pattern_semantics: Optional[LocalPatternSemantics] = None
        self._shared_semantic_overlay: Optional[Dict[str, Any]] = None
        self._shared_semantics_lock = threading.Lock()
        # Candidate IR writes use the shared CodeIndex KnowledgeDB.  Serialize
        # the multi-statement write + commit transaction across entry workers.
        self._candidate_ir_persistence_lock = threading.Lock()
        self._last_materialized_entries: List[FunctionEntry] = []
        self._last_batch_wall_seconds = 0.0
        # Instance-scoped batches keep the exact schedule so the post-discovery
        # validation queue can reopen the same precise scope instead of the
        # unwrapped base index.
        self._batch_instance_scoped = False
        self._instance_scopes_by_build: Dict[str, List[InstanceScope]] = {}
        self._instance_semantics_context: Optional["InstanceSemanticsContext"] = None
        self._validation_semantics_snapshots: Dict[str, "InstanceSemanticsSnapshot"] = {}
        self._validation_semantics_receipts: Dict[str, bytes] = {}
        self._validation_semantics_fact_receipts: Dict[str, bytes] = {}
        # Only successful admission registers historical work. Keep the exact
        # result object so a later execution at the same key cannot inherit it.
        # This is process-local accounting, never an authority from metadata.
        self._restored_result_costs: Dict[str, Tuple[ParallelAnalysisResult, Dict[str, Any]]] = {}
        self._last_scan_budget_metadata: Dict[str, Any] = {}
        self._last_global_model_stats: Optional[Dict[str, Any]] = None
        self._global_modeling_succeeded = False
        self._global_validation_state: Dict[str, Any] = {}
        self._global_validation_duration_seconds = 0.0
        self._project_fact_pass_state: Dict[str, Any] = {}
        self._hierarchical_static_inputs: Optional[Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]] = None
        self._hierarchical_supplements: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._hierarchical_discovery_result: Dict[str, Any] = {}
        self._hierarchical_discovery_done = False
        self._fast_static_scan_state: Dict[str, Any] = {
            "schema": "zscope.fast-static-scan.v1",
            "enabled": False,
            "status": "not_run",
        }
        self._active_discovery_state: Dict[str, Any] = {
            "enabled": False,
            "profile": resolve_discovery_profile(config).name,
            "status": "not_run",
        }
        self._semantic_dedup_llm_cache: Dict[str, Dict[str, Any]] = {}
        self.deferred_entry_candidates: List[Dict[str, Any]] = []
        self._last_combined_report: Optional[Dict[str, Any]] = None
        self._last_markdown_results: Dict[str, ParallelAnalysisResult] = {}
        self.run_id = uuid.uuid4().hex

    @staticmethod
    def _normalize_md_text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value)
        return text.replace("\\n", "\n")

    def analyze_function_entries(
        self,
        entries: List[FunctionEntry],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Dict[str, ParallelAnalysisResult]:
        condition = self._lifecycle_condition()
        with condition:
            if getattr(self, "_closed", False):
                raise RuntimeError("ParallelAnalyzer is closed")
            if self._active_batch_thread is not None:
                raise RuntimeError("ParallelAnalyzer already has an active batch")
            self._active_batch_thread = threading.get_ident()
        try:
            return self._analyze_function_entries(entries, progress_callback)
        finally:
            with condition:
                self._active_batch_thread = None
                condition.notify_all()
                close_requested = getattr(self, "_closed", False)
            if close_requested:
                self.close()

    def analyze_entry_instances(
        self,
        plan: Any,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> InstanceAnalysisReport:
        """Analyze every scheduled compile instance with scoped program facts.

        This is the coordinator-callable execution entry point: each scheduled
        ``EntryInstance`` becomes one real ``Analyzer`` run whose program-facts
        queries are pinned to that instance's exact ``(build_context_id, USR)``.
        The shared candidate ledger, validation result cache, decision-fact
        cache and scan-level validation queue are reused, so candidates keep
        their build identity through dedup and terminal projection.
        """

        instances = list(getattr(plan, "instances", []) or [])
        plan_gaps = [
            gap.to_payload() if hasattr(gap, "to_payload") else dict(gap)
            for gap in (getattr(plan, "gaps", []) or [])
        ]
        plan_status = str(getattr(plan, "status", "") or "")
        if self.base_config.project.language == "java":
            return InstanceAnalysisReport(
                status="not_applicable",
                planned_instances=len(instances),
                plan_gaps=plan_gaps,
                reasons=["java_scan_has_no_compilation_instances"],
            )
        if not instances:
            return InstanceAnalysisReport(
                status="unavailable" if plan_status != "planned" else "empty",
                planned_instances=0,
                plan_gaps=plan_gaps,
                reasons=(
                    ["no_scheduled_instances"]
                    if plan_status == "planned"
                    else [f"entry_instance_plan_{plan_status or 'unavailable'}"]
                ),
            )

        scoped_entries: List[Tuple[FunctionEntry, Optional[InstanceScope]]] = []
        for instance in instances:
            scope = instance_scope_from_entry_instance(instance)
            scoped_entries.append((self._instance_entry(instance), scope))

        # Public-entry lifetime: share the exact occupancy/close/interrupt
        # contract of ``analyze_function_entries`` so a concurrent ``close()``
        # defers owned-resource cleanup until instance analysis has drained.
        condition = self._lifecycle_condition()
        with condition:
            if getattr(self, "_closed", False):
                raise RuntimeError("ParallelAnalyzer is closed")
            if self._active_batch_thread is not None:
                raise RuntimeError("ParallelAnalyzer already has an active batch")
            self._active_batch_thread = threading.get_ident()
        try:
            self.freeze_instance_semantics(plan)
            scoped_entries = self._current_instance_entries(plan)
            self._instance_entry_owners = self._current_instance_owner_aliases(
                InstanceWorkBatch(self, plan=plan, scoped_entries=scoped_entries)
            )
            results = self._analyze_function_entries(
                [entry for entry, _scope in scoped_entries],
                progress_callback,
                scoped_entries=scoped_entries,
            )
            self._last_instance_results = results
            snapshot = self._candidate_ledger.lifecycle_snapshot()
            outcomes: List[InstanceAnalysisOutcome] = []
            for instance, (entry, entry_scope) in zip(instances, scoped_entries):
                if entry_scope is None:  # every scheduled instance has an exact scope
                    continue
                outcomes.append(
                    self._instance_outcome(instance, entry, entry_scope, results, snapshot)
                )
            return InstanceAnalysisReport(
                status="analyzed",
                outcomes=outcomes,
                planned_instances=len(instances),
                plan_gaps=plan_gaps,
            )
        finally:
            with condition:
                self._active_batch_thread = None
                condition.notify_all()
                close_requested = getattr(self, "_closed", False)
            if close_requested:
                self.close()

    def last_instance_results(self) -> Dict[str, ParallelAnalysisResult]:
        """Raw results from the last ``analyze_entry_instances`` call.

        Report generation still consumes the per-entry ``results`` mapping, so
        instance dispatch keeps both the raw results and the instance coverage
        report available to the caller.
        """

        return dict(getattr(self, "_last_instance_results", {}))

    @property
    def cancellation_token(self) -> CancellationToken:
        """The scan token every entry and validation run observes."""

        return self._cancellation_token

    # -- continuous instance batch (job-driven incremental analysis) ---------

    def freeze_instance_semantics(self, plan: Any) -> "InstanceSemanticsContext":
        """Freeze the actual workbook and each exact scope before plan identity."""
        from .instance_semantics_context import freeze_instance_context

        if self._uses_scoped_fast_static_pass():
            settle = getattr(self.code_index, "settle_native_facts", None)
            if callable(settle):
                settled = settle()
                logger.info("[fast-static] native fact barrier: %s", settled)
        scopes = [
            instance_scope_from_entry_instance(instance)
            for instance in list(getattr(plan, "instances", ()) or ())
        ]
        if self._uses_scoped_fast_static_pass():
            scopes = self._extend_fast_project_semantic_scopes(scopes)
        condition = self._lifecycle_condition()
        with condition:
            if getattr(self, "_closed", False):
                raise RuntimeError("ParallelAnalyzer is closed")
            if self._active_batch_thread not in (None, threading.get_ident()):
                raise RuntimeError("ParallelAnalyzer already has an active batch")
            existing = self._instance_semantics_context
            if existing is not None:
                if existing.scopes != {scope.identity: scope for scope in scopes}:
                    raise ValueError("instance_semantics_plan_changed_after_freeze")
                return existing
            semantics_path = getattr(self.base_config.project, "semantics_file", None)
            if semantics_path is None:
                raise ValueError("project_semantics_file_missing")
            context = freeze_instance_context(
                config=self.base_config,
                code_index=self.code_index,
                semantics_path=Path(semantics_path),
                scopes=scopes,
            )
            self._instance_semantics_context = context
            return context

    def _extend_fast_project_semantic_scopes(
        self, scopes: Sequence[InstanceScope]
    ) -> List[InstanceScope]:
        """Add one exact native scope for every indexed C/C++ build context.

        Entry planning names only contexts that contain an entry.  Fast static
        discovery is project-wide, so contexts without an entry still need a
        current semantics receipt and an analysis representative.  Candidate
        functions are registered as lightweight scopes by the project pass and
        receive an exact snapshot only if they reach Validator; freezing every
        project function here duplicates a BuildContext-sized payload thousands
        of times.  A context without a complete project-function owner remains
        an explicit planning gap; it is never filled by a navigation/name guess.
        """

        result = list(scopes)
        represented = {scope.build_context_id for scope in result if scope.build_context_id}
        gaps: List[Dict[str, Any]] = []
        context_ids: Set[str] = set(represented)
        contexts_getter = getattr(self.code_index, "get_build_contexts", None)
        facts_getter = getattr(self.code_index, "get_compilation_facts", None)
        try:
            contexts = list(contexts_getter() or []) if callable(contexts_getter) else []
        except Exception as exc:
            contexts = []
            gaps.append(
                {
                    "reason": "build_context_inventory_unavailable",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
        for context in contexts:
            if not isinstance(context, dict):
                continue
            build_id = str(context.get("build_context_id") or "")
            if not build_id:
                gaps.append({"reason": "build_context_identity_missing"})
                continue
            context_ids.add(build_id)
            if build_id in represented:
                continue
            if str(context.get("status") or "") != "indexed" or not bool(
                context.get("dependencies_complete")
            ):
                gaps.append(
                    {
                        "build_context_id": build_id,
                        "reason": "build_context_not_currently_indexed",
                    }
                )
                continue
            try:
                rows = (
                    list(facts_getter(build_id, kinds=("program_function",)) or [])
                    if callable(facts_getter)
                    else []
                )
            except Exception as exc:
                gaps.append(
                    {
                        "build_context_id": build_id,
                        "reason": "function_inventory_unavailable",
                        "detail": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            owners: List[Tuple[str, str, int, str]] = []
            for row in rows:
                owner = row.get("owner") if isinstance(row, dict) else None
                owner = owner if isinstance(owner, dict) else {}
                usr = str(owner.get("usr") or "")
                name = str(owner.get("name") or "")
                source = str(owner.get("file") or context.get("source") or "")
                try:
                    line = int(owner.get("line") or 0)
                except (TypeError, ValueError):
                    line = 0
                if usr and name and source and line > 0 and self._source_is_in_project(source):
                    owners.append((source, usr, line, name))
            if not owners:
                gaps.append(
                    {
                        "build_context_id": build_id,
                        "reason": "project_function_receipt_missing",
                    }
                )
                continue
            source, usr, _line, name = sorted(set(owners))[0]
            result.append(
                InstanceScope(
                    build_context_id=build_id,
                    usr=usr,
                    identity=f"{build_id}:{usr}",
                    source=source,
                    function_names=(name,),
                    selected_by="fast_static_project_context",
                )
            )
            represented.add(build_id)
        self._fast_project_scope_gaps = gaps
        self._fast_project_build_context_ids = sorted(context_ids)
        return result

    def _instance_semantic_snapshot(self, scope: InstanceScope) -> "InstanceSemanticsSnapshot":
        from .instance_semantics_context import InstanceSemanticsContext

        context = getattr(self, "_instance_semantics_context", None)
        if not isinstance(context, InstanceSemanticsContext):
            raise ValueError("instance_semantics_batch_not_frozen")
        return context.require(scope)

    def _frozen_instance_semantic_snapshot(
        self, scope: InstanceScope
    ) -> "InstanceSemanticsSnapshot":
        """Identity-only lookup inside an enclosing ``require_all`` boundary."""

        from .instance_semantics_context import InstanceSemanticsContext

        context = getattr(self, "_instance_semantics_context", None)
        if not isinstance(context, InstanceSemanticsContext):
            raise ValueError("instance_semantics_batch_not_frozen")
        return context.snapshot(scope)

    def _validation_semantic_snapshot(self, scope: InstanceScope) -> "InstanceSemanticsSnapshot":
        """Return an exact snapshot without freezing the whole project eagerly.

        The initial batch manifest freezes entry scopes plus one build
        representative.  Project-wide fast discovery can emit a candidate for
        any other function in that build.  Materialize only those candidate
        scopes from the already-frozen authority and the build representative's
        effect template, after issuing a fresh exact native admission before
        and after construction.  This preserves ``BuildContext + USR`` binding
        without retaining thousands of heavyweight snapshots.
        """

        from .instance_semantics_context import (
            InstanceSemanticsContext,
            _batch_input_admissions,
        )
        from ..config.project_semantics import compiled_project_contracts
        from ..semantics.instance_semantics import (
            SemanticsUnavailable,
            build_instance_semantics,
        )

        context = getattr(self, "_instance_semantics_context", None)
        if not isinstance(context, InstanceSemanticsContext):
            raise ValueError("instance_semantics_batch_not_frozen")
        try:
            return context.snapshot(scope)
        except ValueError as exc:
            if str(exc) != "instance_semantics_missing":
                raise
        cached = self._validation_semantics_snapshots.get(scope.identity)
        if cached is not None:
            if cached.scope != scope:
                raise ValueError("validation_semantics_scope_changed")
            return cached

        template = next(
            (
                snapshot
                for snapshot in context.snapshots.values()
                if snapshot.scope.build_context_id == scope.build_context_id
            ),
            None,
        )
        if template is None:
            raise ValueError("validation_semantics_build_template_missing")
        admissions, failures = _batch_input_admissions(self.code_index, [scope])
        admission = admissions.get(scope.identity)
        if admission is None:
            raise ValueError(
                failures.get(scope.identity, "validation_semantics_exact_input_unavailable")
            )
        document = json.loads(bytes(context.effective_project_document))
        contracts = compiled_project_contracts(
            document,
            build_context_id=scope.build_context_id,
        )
        value = build_instance_semantics(
            scope=scope,
            scoped_index=wrap_scoped_code_index(self.code_index, scope),
            workbook=context.workbook,
            dependencies=context.dependencies,
            project_contracts_override=contracts,
            _input_admission=admission,
            _build_template=template,
        )
        if isinstance(value, SemanticsUnavailable):
            raise ValueError(value.reason)
        post_admissions, post_failures = _batch_input_admissions(self.code_index, [scope])
        post = post_admissions.get(scope.identity)
        if post is None:
            raise ValueError(
                post_failures.get(scope.identity, "validation_semantics_exact_input_changed")
            )
        if bytes(post.context_receipt) != bytes(admission.context_receipt) or bytes(
            post.program_facts
        ) != bytes(admission.program_facts):
            raise ValueError("validation_semantics_exact_input_changed")
        self._validation_semantics_snapshots[scope.identity] = value
        self._validation_semantics_receipts[scope.identity] = bytes(admission.context_receipt)
        self._validation_semantics_fact_receipts[scope.identity] = bytes(admission.program_facts)
        return value

    def _validation_snapshot_is_frozen(self, snapshot: "InstanceSemanticsSnapshot") -> bool:
        context = self._instance_semantics_context
        if context is not None and context.is_frozen(snapshot):
            return True
        return self._validation_semantics_snapshots.get(snapshot.scope.identity) is snapshot

    def _require_validation_snapshot_current(
        self, scope: InstanceScope, snapshot: "InstanceSemanticsSnapshot"
    ) -> None:
        """Recheck the exact candidate scope at each Validator boundary."""

        from .instance_semantics_context import _batch_input_admissions
        from ..semantics.instance_semantics import authorized_standard_headers_current

        context = self._instance_semantics_context
        if context is not None and context.is_frozen(snapshot):
            if snapshot.scope != scope:
                raise ValueError("validation_semantics_scope_changed")
            return
        if self._validation_semantics_snapshots.get(scope.identity) is not snapshot:
            raise ValueError("validation_semantics_snapshot_not_frozen")
        context_receipt = self._validation_semantics_receipts.get(scope.identity)
        fact_receipt = self._validation_semantics_fact_receipts.get(scope.identity)
        admissions, failures = _batch_input_admissions(self.code_index, [scope])
        current = admissions.get(scope.identity)
        if current is None:
            raise ValueError(
                failures.get(scope.identity, "validation_semantics_exact_input_not_current")
            )
        if (
            context_receipt is None
            or fact_receipt is None
            or bytes(current.context_receipt) != context_receipt
            or bytes(current.program_facts) != fact_receipt
        ):
            raise ValueError("validation_semantics_exact_input_not_current")
        if not authorized_standard_headers_current(snapshot):
            raise ValueError("validation_semantics_standard_headers_not_current")

    def require_current_instance_inputs(self, *, require_complete: bool = True) -> None:
        context = getattr(self, "_instance_semantics_context", None)
        if context is None:
            if getattr(self, "_batch_instance_scoped", False):
                raise ValueError("instance_semantics_batch_not_frozen")
            return
        if require_complete and context.unavailable:
            reasons: Dict[str, int] = {}
            for reason in context.unavailable.values():
                reasons[str(reason)] = reasons.get(str(reason), 0) + 1
            logger.error(
                "[instance-semantics] incomplete manifest: unavailable=%d reasons=%s samples=%s "
                "project_rebind_unresolved=%s",
                len(context.unavailable),
                reasons,
                [
                    {"identity": identity, "reason": reason}
                    for identity, reason in list(context.unavailable.items())[:10]
                ],
                list(context.project_semantics_rebind.get("unresolved", []) or [])[:24],
            )
            raise ValueError("instance_semantics_incomplete_manifest")
        context.require_all()

    def open_instance_batch(self, plan: Any) -> "InstanceWorkBatch":
        """Acquire the lifetime once and release it on every setup failure."""
        condition = self._lifecycle_condition()
        with condition:
            if getattr(self, "_closed", False):
                raise RuntimeError("ParallelAnalyzer is closed")
            if self._active_batch_thread is not None:
                raise RuntimeError("ParallelAnalyzer already has an active batch")
            self._active_batch_thread = threading.get_ident()
        try:
            return self._initialize_instance_batch(plan)
        except BaseException:
            self._release_batch_lifetime()
            raise

    def _initialize_instance_batch(self, plan: Any) -> "InstanceWorkBatch":
        """Open one scan-scope ledger for incremental per-instance analysis.

        The candidate ledger, decision-fact cache, validation result cache and
        scan-level scheduler are created once here and reused by every later
        :meth:`run_instance_batch` call, so a job work item never rebuilds the
        batch (which would reset the ledger and lose cross-instance dedup).
        """

        self._begin_llm_usage_batch()
        instances = list(getattr(plan, "instances", []) or [])
        scoped_entries: List[Tuple[FunctionEntry, Optional[InstanceScope]]] = [
            (self._instance_entry(instance), instance_scope_from_entry_instance(instance))
            for instance in instances
        ]
        self.freeze_instance_semantics(plan)
        scoped_entries = self._current_instance_entries(plan)

        self._last_materialized_entries = [entry for entry, _scope in scoped_entries]
        self._restored_result_costs = {}
        self._interrupted = False
        self._deadline_exceeded = False
        self._cancellation_token = CancellationToken(
            parent=self._parent_cancellation_token,
            timeout_seconds=None,
        )
        self._candidate_ledger = CandidateLedger(
            project_id=str(
                getattr(self.base_config.project, "project_id", "")
                or self.base_config.project.project_root.name
            ),
            project_root=str(self.base_config.project.project_root),
            revision=Analyzer._git_commit_sha(self.base_config.project.project_root),
        )
        self._decision_fact_cache = DecisionFactGraphCache()
        self._validation_result_cache = ValidationResultCache(
            max_entries=getattr(self.base_config.analysis, "validation_cache_entries", 4096)
        )
        self._global_validation_state = {}
        self._global_validation_duration_seconds = 0.0
        self._hierarchical_discovery_done = False
        self._hierarchical_static_inputs = None
        self._hierarchical_supplements = {}
        self._hierarchical_discovery_result = {}
        self._fast_static_scan_state = {
            "schema": "zscope.fast-static-scan.v1",
            "enabled": False,
            "status": "not_run",
        }
        self._project_fact_pass_state = {
            "enabled": False,
            "status": "skipped",
            "reason": "instance_scope_isolated",
        }
        self._shared_local_pattern_semantics = None
        self._shared_semantic_overlay = None
        self._active_discovery_state = {
            "enabled": False,
            "profile": resolve_discovery_profile(self.base_config).name,
            "status": "skipped",
            "reason": "instance_scope_isolated",
        }
        self._batch_instance_scoped = True
        self._instance_scopes_by_build = {}
        self._validation_semantics_snapshots = {}
        self._validation_semantics_receipts = {}
        self._validation_semantics_fact_receipts = {}
        for _entry, scope in scoped_entries:
            if scope is None:
                continue
            self._instance_scopes_by_build.setdefault(scope.build_context_id, []).append(scope)
        self._scheduler = ScanScheduler(
            entry_workers=self.max_workers,
            validator_workers=self.base_config.concurrency.validator_workers,
            investigator_workers=self.base_config.concurrency.investigator_workers,
        )
        batch = InstanceWorkBatch(self, plan=plan, scoped_entries=scoped_entries)
        self._instance_entry_owners = self._current_instance_owner_aliases(batch)
        if self._uses_scoped_fast_static_pass():
            self._run_scoped_fast_static_pass(scoped_entries)
        return batch

    def _current_instance_entries(
        self, plan: Any
    ) -> List[Tuple[FunctionEntry, Optional[InstanceScope]]]:
        """Hydrate entries from the exact native owner already admitted.

        Instance planning and the frozen semantics manifest both establish an
        exact ``(BuildContext, USR)`` identity.  Re-resolving that identity via
        the navigation/name index made a verified native instance fail merely
        because clangd omitted a projection (notably some ``extern "C"``
        definitions).  The owner, callable signature and source below all come
        from the same current program-facts receipt; name lookup is never used
        as a second authority boundary.
        """

        entries: List[Tuple[FunctionEntry, Optional[InstanceScope]]] = []
        self.require_current_instance_inputs()
        for instance in list(getattr(plan, "instances", []) or []):
            scope = instance_scope_from_entry_instance(instance)
            entry = self._instance_entry(instance)
            self._frozen_instance_semantic_snapshot(scope)
            scoped = wrap_scoped_code_index(self.code_index, scope)
            facts = scoped.get_function_program_facts(
                scope.usr,
                scope.source,
                build_context_id=scope.build_context_id,
            )
            identity = facts.get("function_identity") if isinstance(facts, dict) else None
            if not (
                isinstance(facts, dict)
                and facts.get("complete") is True
                and isinstance(identity, dict)
                and str(identity.get("build_context_id") or "") == scope.build_context_id
                and str(identity.get("usr") or "") == scope.usr
            ):
                raise ValueError("instance_current_entry_identity_unverifiable")
            owners: List[Dict[str, str]] = []
            for body in facts.get("functions", []) or []:
                if not isinstance(body, dict):
                    continue
                owner = body.get("owner")
                callable_row = body.get("callable")
                owner = owner if isinstance(owner, dict) else {}
                callable_row = callable_row if isinstance(callable_row, dict) else {}
                if str(owner.get("usr") or "") != scope.usr:
                    continue
                record = {
                    "function_name": str(owner.get("name") or ""),
                    "file_path": str(owner.get("file") or scope.source or ""),
                    "signature": str(
                        callable_row.get("canonical_signature")
                        or callable_row.get("signature")
                        or ""
                    ),
                }
                if all(record.values()) and record not in owners:
                    owners.append(record)
            if len(owners) != 1:
                raise ValueError("instance_current_entry_owner_unverifiable")
            model = owners[0]
            hydrated = self._entry_from_identity_record(
                entry,
                {
                    "function_name": model["function_name"],
                    "file_path": model["file_path"],
                    "signature": model["signature"],
                },
                self.base_config.project.project_root,
            )
            absolute_file = scoped._resolved_source(str(model["file_path"]))
            if not absolute_file or not Path(absolute_file).is_absolute():
                raise ValueError("instance_current_entry_source_unverifiable")
            hydrated = replace(hydrated, file_path=absolute_file)
            entries.append((hydrated, scope))
        self.require_current_instance_inputs()
        return entries

    def _current_instance_owner_aliases(
        self, batch: "InstanceWorkBatch"
    ) -> Dict[Tuple[str, str], Any]:
        """No persisted USR, basename or sink may guess an entry's owner."""
        from .jobs.instance_results import InstanceKey

        aliases: Dict[Tuple[str, str], Any] = {}
        for instance, (entry, scope) in zip(batch.instances, batch.scoped_entries):
            if scope is None:
                raise ValueError("instance_owner_scope_missing")
            key = InstanceKey(
                scope.identity, scope.build_context_id, scope.usr, str(instance.source)
            )
            alias = (
                entry.identity_key(self.base_config.project.project_root),
                scope.build_context_id,
            )
            if alias in aliases and aliases[alias] != key:
                raise ValueError("instance_owner_alias_ambiguous")
            aliases[alias] = key
        return aliases

    def run_instance_batch(
        self,
        batch: "InstanceWorkBatch",
        identities: Sequence[str],
    ) -> Dict[str, ParallelAnalysisResult]:
        """Analyze exactly the claimed instances into the open batch ledger.

        A real window/cancel that reaches the analyzer ends the batch with a
        ``CancellationError`` instead of recording a verdict for an instance
        that was never analyzed: the caller keeps that work item unresolved.
        """

        wanted = {str(value) for value in identities if str(value)}
        selected = [
            (entry, scope)
            for entry, scope in batch.scoped_entries
            if scope is not None and scope.identity in wanted
        ]
        scheduler = self._scheduler
        if scheduler is None:
            raise RuntimeError("no open instance batch scheduler")
        futures = {
            scheduler.submit(
                ENTRY_ROLE,
                self._analyze_single_entry,
                entry,
                instance_scope=scope,
                skip_candidate_discovery=bool(self._fast_static_scan_state.get("activated", False)),
                priority=self._entry_scheduling_score(entry),
            ): (entry, scope)
            for entry, scope in selected
        }
        cancelled = False
        try:
            for future in concurrent.futures.as_completed(
                futures, timeout=self._cancellation_token.remaining_seconds()
            ):
                entry, scope = futures[future]
                key = self._scoped_result_key(entry, scope)
                try:
                    batch.results[key] = future.result()
                    self._restored_result_costs.pop(key, None)
                except concurrent.futures.CancelledError:
                    logger.warning("instance analysis cancelled: %s", scope.identity)
                    cancelled = True
                except Exception as exc:  # one instance failure stays local
                    if self._cancellation_token.is_cancelled():
                        # The token stopped this instance; it is not a verdict.
                        cancelled = True
                        continue
                    logger.error("instance analysis error for %s: %s", scope.identity, exc)
                    batch.results[key] = ParallelAnalysisResult(
                        function_name=entry.function_name,
                        verdict="error",
                        error=str(exc),
                        diff_focus=entry.diff_focus,
                    )
                    self._restored_result_costs.pop(key, None)
        except concurrent.futures.TimeoutError:
            cancelled = True
        self._last_instance_results = dict(batch.results)
        if cancelled or self._cancellation_token.is_cancelled():
            raise CancellationError(self._cancellation_token.reason or "cancelled")
        return dict(batch.results)

    def validate_instance_batch(self, batch: "InstanceWorkBatch") -> None:
        """Run the scan-level validation queue once over the frozen ledger."""
        with batch.admission_lock:
            self.require_current_instance_inputs()
            if batch.validation_state == "DONE":
                return
            if batch.validation_state != "NOT_STARTED":
                raise ValueError("instance_validation_generation_not_restartable")
            batch.validation_state = "RUNNING"
            try:
                self._run_scan_validation_queue()
                self.require_current_instance_inputs()
                if self._global_validation_state.get("validation_queue_drained") is not True:
                    raise ValueError("instance_validation_queue_not_drained")
            except BaseException:
                batch.validation_state = "ABORTED"
                raise
            batch.validation_state = "DONE"

    def export_instance_result(
        self,
        batch: "InstanceWorkBatch",
        *,
        identity: str,
        recovery: "RecoveryIdentity",
        producer_run_id: str,
    ) -> "InstanceResultPayload | RecoveryMiss":
        """Freeze complete neutral collection data; this never mints a receipt."""
        from dataclasses import asdict
        from .candidates import PENDING_WIRE_ADAPTER_VERSION
        from .jobs.instance_results import (
            AnalysisCompletion,
            FrozenJSON,
            InstanceKey,
            InstanceResultPayload,
            RecoveryMiss,
        )
        from .instance_semantics_context import canonical_bytes

        instance = next((item for item in batch.instances if item.identity == identity), None)
        if instance is None:
            raise ValueError("instance_export_not_in_current_plan")
        key = InstanceKey(
            instance.identity, instance.build_context_id, instance.usr, instance.source
        )
        try:
            with batch.admission_lock, self._candidate_ledger._lock:
                if batch.analyzer is not self or batch.validation_state != "NOT_STARTED":
                    raise ValueError("instance_export_generation_not_open")
                self.require_current_instance_inputs()
                context = self._instance_semantics_context
                if context is None or recovery.semantics_digest != context.manifest_digest():
                    raise ValueError("instance_export_semantics_manifest_mismatch")
                entry, scope = next(
                    (entry, scope)
                    for entry, scope in batch.scoped_entries
                    if scope is not None and scope.identity == identity
                )
                assert scope is not None
                snapshot = context.snapshot(scope)
                result = batch.results.get(self._scoped_result_key(entry, scope))
                if result is None or result.error or result.verdict == "error":
                    raise ValueError("instance_collection_result_missing_or_error")
                collection = result.instance_collection
                if (
                    not isinstance(collection, dict)
                    or collection.get("schema") != "zscope.instance-collection-closure.v1"
                    or collection.get("supported") is not True
                    or collection.get("collection_closed") is not True
                    or collection.get("input_current") is not True
                    or collection.get("active_stage_errors") != []
                    or collection.get("semantics_digest") != snapshot.digest
                    or collection.get("entry_identity")
                    != entry.identity_key(self.base_config.project.project_root)
                    or collection.get("scope") != scope.to_payload()
                    or result.instance_identity != identity
                    or result.build_context_id != scope.build_context_id
                    or result.usr != scope.usr
                ):
                    raise ValueError("instance_actual_collection_not_closed")
                pending = self._candidate_ledger.pending_instance_snapshot(
                    instance=key, entry_instances=self._instance_entry_owners
                )
                manifest = json.loads(pending.manifest_json)
                # The codec's manifest counts distinct obligation UIDs across
                # records; the locked full manifest separately retains role,
                # build/cluster membership and every occurrence path row.
                completion = AnalysisCompletion(
                    schema="zscope.instance-analysis-completion.v1",
                    state="complete",
                    collection_closed=True,
                    input_current=True,
                    expected_record_count=manifest["record_count"],
                    expected_obligation_count=len(
                        {record.obligation_uid for record in pending.records}
                    ),
                    expected_occurrence_count=manifest["occurrence_count"],
                    active_stage_errors=(),
                )
                gaps = deepcopy((result.instance_scope_report or {}).get("identity_gaps") or [])
                if not isinstance(gaps, list) or any(
                    not isinstance(gap, dict) or not str(gap.get("reason") or "") for gap in gaps
                ):
                    raise ValueError("instance_export_invalid_scope_diagnostics")
                if any(gap.get("severity") == "identity" for gap in gaps):
                    raise ValueError("instance_export_identity_gap_not_reusable")
                gap_strings = [canonical_bytes(gap).decode("utf-8") for gap in gaps]
                gap_strings.extend(
                    canonical_bytes(
                        {"channel": name, "reason": reason, "disposition": "excluded"}
                    ).decode("utf-8")
                    for name, reason in sorted(collection.get("excluded_subchannels", {}).items())
                )
                outcome = {
                    "schema": "zscope.instance-neutral-outcome.v1",
                    "wire_adapter": PENDING_WIRE_ADAPTER_VERSION,
                    "entry_identity": collection["entry_identity"],
                    "result": asdict(result),
                    "manifest": manifest,
                    "record_diagnostics": json.loads(pending.diagnostics_json),
                    "diagnostic_gaps": gap_strings,
                }
                raw = FrozenJSON(canonical_bytes(outcome))
                self.require_current_instance_inputs()
                return InstanceResultPayload(
                    schema="zscope.instance-result.v1",
                    producer_run_id=producer_run_id,
                    identity=recovery,
                    instance=key,
                    instance_semantics_digest=snapshot.digest,
                    completion=completion,
                    outcome_json=raw,
                    records=pending.records,
                )
        except (ValueError, TypeError, KeyError, StopIteration) as exc:
            return RecoveryMiss(instance=key, reason=str(exc) or type(exc).__name__)

    def require_instance_collection_closed(
        self, batch: "InstanceWorkBatch", *, identity: str
    ) -> None:
        """An executed verdict alone cannot settle an analysis work item."""
        with batch.admission_lock:
            if batch.analyzer is not self or batch.validation_state != "NOT_STARTED":
                raise ValueError("instance_collection_generation_not_open")
            self.require_current_instance_inputs()
            entry, scope = next(
                (entry, scope)
                for entry, scope in batch.scoped_entries
                if scope is not None and scope.identity == identity
            )
            assert scope is not None
            snapshot = self._frozen_instance_semantic_snapshot(scope)
            result = batch.results.get(self._scoped_result_key(entry, scope))
            tracker = result.instance_collection if result is not None else None
            if (
                result is None
                or result.error
                or result.verdict == "error"
                or result.instance_identity != scope.identity
                or result.usr != scope.usr
                or result.build_context_id != scope.build_context_id
                or not isinstance(tracker, dict)
                or tracker.get("supported") is not True
                or tracker.get("collection_closed") is not True
                or tracker.get("input_current") is not True
                or tracker.get("active_stage_errors") != []
                or tracker.get("semantics_digest") != snapshot.digest
                or tracker.get("scope") != scope.to_payload()
                or tracker.get("entry_identity")
                != entry.identity_key(self.base_config.project.project_root)
            ):
                raise ValueError("instance_actual_collection_not_closed")

    def restore_instance_result(
        self, batch: "InstanceWorkBatch", *, admitted: "RecoveryAccepted"
    ) -> None:
        """Stage the complete ledger/result projection and commit once under locks."""
        from dataclasses import asdict, fields
        from .candidates import (
            PENDING_MANIFEST_SCHEMA,
            PENDING_WIRE_ADAPTER_VERSION,
            _pending_bytes,
            _pending_merge_key,
        )
        from .jobs.instance_results import (
            ExpectedInstance,
            InstanceKey,
            RecoveryAccepted,
            verify_instance_result,
        )

        with batch.admission_lock, self._candidate_ledger._lock:
            if batch.analyzer is not self or batch.validation_state != "NOT_STARTED":
                raise ValueError("instance_restore_generation_not_open")
            self.require_current_instance_inputs()
            context = self._instance_semantics_context
            if context is None:
                raise ValueError("instance_restore_semantics_missing")
            allowed = {
                item.identity: InstanceKey(
                    item.identity, item.build_context_id, item.usr, item.source
                )
                for item in batch.instances
            }
            payload = admitted.payload
            if allowed.get(payload.instance.identity) != payload.instance:
                raise ValueError("instance_restore_not_in_current_plan")
            scope = context.scopes[payload.instance.identity]
            snapshot = context.snapshot(scope)
            if payload.identity.semantics_digest != context.manifest_digest():
                raise ValueError("instance_restore_semantics_manifest_mismatch")
            verified = verify_instance_result(
                admitted.receipt,
                expected=payload.identity,
                instance=ExpectedInstance(payload.instance, snapshot.digest),
            )
            if not isinstance(verified, RecoveryAccepted) or verified.payload != payload:
                raise ValueError("instance_restore_bytes_no_longer_match")
            outcome = json.loads(payload.outcome_json)
            if not isinstance(outcome, dict) or set(outcome) != {
                "schema",
                "wire_adapter",
                "entry_identity",
                "result",
                "manifest",
                "record_diagnostics",
                "diagnostic_gaps",
            }:
                raise ValueError("instance_restore_outcome_schema_mismatch")
            if (
                outcome["schema"] != "zscope.instance-neutral-outcome.v1"
                or outcome["wire_adapter"] != PENDING_WIRE_ADAPTER_VERSION
            ):
                raise ValueError("instance_restore_outcome_version_mismatch")
            entry, _ = next(
                (entry, own_scope)
                for entry, own_scope in batch.scoped_entries
                if own_scope is not None and own_scope.identity == scope.identity
            )
            alias = entry.identity_key(self.base_config.project.project_root)
            if outcome["entry_identity"] != alias:
                raise ValueError("instance_restore_current_entry_identity_mismatch")
            rows = outcome["record_diagnostics"]
            if not isinstance(rows, list):
                raise ValueError("instance_restore_diagnostics_missing")
            diagnostics: Dict[tuple[str, ...], int] = {}
            for row in rows:
                if not isinstance(row, dict) or set(row) != {"record_key", "duplicate_count"}:
                    raise ValueError("instance_restore_diagnostics_invalid")
                coordinates = row["record_key"]
                count = row["duplicate_count"]
                if (
                    not isinstance(coordinates, list)
                    or len(coordinates) != 6
                    or any(type(value) is not str for value in coordinates)
                    or type(count) is not int
                    or count < 0
                ):
                    raise ValueError("instance_restore_diagnostics_invalid")
                merged = tuple(coordinates)
                if merged in diagnostics:
                    raise ValueError("instance_restore_diagnostics_duplicate")
                diagnostics[merged] = count
            # Recreate the full logical records using only versioned derived
            # aliases and neutral constants; no old decisions are restored.
            projections: List[Dict[str, Any]] = []
            members: List[Dict[str, Any]] = []
            for pending in payload.records:
                wire = json.loads(pending.record_json)
                record_key = _pending_merge_key(wire)
                if record_key not in diagnostics:
                    raise ValueError("instance_restore_diagnostics_missing_member")
                record = self._candidate_ledger._pending_record_from_projection(
                    pending, duplicate_count=diagnostics[record_key]
                )
                projection = record.to_dict(include_context=True)
                projection["terminal_issue"] = {}
                projections.append(projection)
                members.append(
                    {
                        name: projection[name]
                        for name in (
                            "build_context_id",
                            "candidate_uid",
                            "obligation_uid",
                            "validation_cluster_uid",
                            "evidence_hash",
                            "context_signature",
                            "record_role",
                            "occurrence_uids",
                            "occurrences",
                            "duplicate_count",
                        )
                    }
                    | {"owner_instances": [asdict(owner) for owner in pending.owner_instances]}
                )
            manifest = {
                "schema": PENDING_MANIFEST_SCHEMA,
                "wire_adapter": PENDING_WIRE_ADAPTER_VERSION,
                "instance": asdict(payload.instance),
                "record_count": len(payload.records),
                "obligation_count": sum(
                    record.record_role == "validation_obligation" for record in payload.records
                ),
                "occurrence_count": sum(len(row["occurrence_uids"]) for row in projections),
                "occurrence_row_count": sum(len(row["occurrences"]) for row in projections),
                "members": members,
                "membership_sha256": hashlib.sha256(_pending_bytes(members)).hexdigest(),
                "records_sha256": hashlib.sha256(_pending_bytes(projections)).hexdigest(),
                "diagnostics_sha256": hashlib.sha256(_pending_bytes(rows)).hexdigest(),
            }
            if _pending_bytes(outcome["manifest"]) != _pending_bytes(manifest):
                raise ValueError("instance_restore_full_manifest_mismatch")
            raw_result = outcome["result"]
            if not isinstance(raw_result, dict) or set(raw_result) != {
                item.name for item in fields(ParallelAnalysisResult)
            }:
                raise ValueError("instance_restore_result_projection_incomplete")
            restored = ParallelAnalysisResult(**deepcopy(raw_result))
            if (
                restored.instance_identity != scope.identity
                or restored.build_context_id != scope.build_context_id
                or restored.usr != scope.usr
                or restored.entry_identity != alias
                or restored.error
                or restored.verdict == "error"
            ):
                raise ValueError("instance_restore_result_identity_mismatch")
            result_key = self._scoped_result_key(entry, scope)
            if result_key in batch.results and batch.results[result_key] != restored:
                raise ValueError("instance_restore_result_conflict")
            staged = self._candidate_ledger._stage_pending_instance_records(
                records=payload.records,
                allowed_instances=allowed,
                diagnostics=diagnostics,
                entry_instances=self._instance_entry_owners,
            )
            staged_results = dict(batch.results)
            staged_results[result_key] = restored
            staged_costs = dict(self._restored_result_costs)
            staged_costs[result_key] = (
                restored,
                {
                    "accounting_scope": "historical_producer_work",
                    "entry_key": result_key,
                    "entry_identity": alias,
                    "instance_identity": scope.identity,
                    "build_context_id": scope.build_context_id,
                    "usr": scope.usr,
                    "source": payload.instance.source,
                    "producer_job_id": admitted.receipt.identity.job_id,
                    "producer_run_id": admitted.receipt.producer_run_id,
                    "producer_attempt_no": admitted.receipt.producer_attempt_no,
                    "event_seq": admitted.receipt.event_seq,
                    "artifact_path": str(admitted.receipt.artifact_path),
                    "content_sha256": admitted.receipt.content_sha256,
                    "metrics": self._result_cost_metrics(restored),
                    "entry_budget": {
                        "seconds": restored.entry_budget_seconds,
                        "exceeded": restored.entry_budget_exceeded,
                        "overrun_seconds": restored.entry_budget_overrun_seconds,
                        "exhaustion_policy": restored.budget_exhaustion_policy,
                    },
                    "validation_performance": deepcopy(
                        restored.metadata.get("validation_performance", {})
                    ),
                },
            )
            self.require_current_instance_inputs()
            # Commit ledger, results and accounting without fallible work in between.
            self._candidate_ledger._records = staged
            batch.results = staged_results
            self._restored_result_costs = staged_costs

    def finish_instance_batch(self, batch: "InstanceWorkBatch") -> InstanceAnalysisReport:
        """Project outcomes and release the batch lifetime."""

        try:
            snapshot = self._candidate_ledger.lifecycle_snapshot()
            plan_gaps = [
                gap.to_payload() if hasattr(gap, "to_payload") else dict(gap)
                for gap in (getattr(batch.plan, "gaps", []) or [])
            ]
            outcomes: List[InstanceAnalysisOutcome] = []
            for instance, (entry, scope) in zip(batch.instances, batch.scoped_entries):
                if scope is None:
                    continue
                outcomes.append(
                    self._instance_outcome(instance, entry, scope, batch.results, snapshot)
                )
            self._last_instance_results = dict(batch.results)
            return InstanceAnalysisReport(
                status="analyzed",
                outcomes=outcomes,
                planned_instances=len(batch.instances),
                plan_gaps=plan_gaps,
            )
        finally:
            self._release_batch_lifetime()

    def abandon_instance_batch(self, batch: "InstanceWorkBatch") -> None:
        """Release an open batch that stopped before its checkpoint.

        A window/cancel never projects a completion, but the batch still owns
        the scan scheduler and the analyzer's active-batch lifetime; releasing
        it here is what lets ``close()`` actually tear the run down.  Safe to
        call after :meth:`finish_instance_batch` (idempotent).
        """

        del batch
        self._release_batch_lifetime()

    def _release_batch_lifetime(self) -> None:
        condition = self._lifecycle_condition()
        scheduler = self._scheduler
        if scheduler is None and getattr(self, "_active_batch_thread", None) is None:
            return
        self._scheduler = None
        if scheduler is not None:
            try:
                scheduler.shutdown(wait=True, cancel_futures=True)
            except Exception:
                pass
        with condition:
            self._active_batch_thread = None
            condition.notify_all()
            close_requested = getattr(self, "_closed", False)
        if close_requested:
            self.close()

    @staticmethod
    def _symbol_leaf(usr: str) -> str:
        text = str(usr or "")
        if "@" in text:
            text = text.rsplit("@", 1)[-1]
        text = text.split("#", 1)[0]
        return text or str(usr or "")

    def _instance_entry(self, instance: Any) -> FunctionEntry:
        names = [
            str(name)
            for name in (getattr(instance, "function_names", ()) or ())
            if str(name).strip()
        ]
        name = names[0] if names else self._symbol_leaf(str(getattr(instance, "usr", "") or ""))
        source = str(
            getattr(instance, "source", "") or getattr(instance, "definition_file", "") or ""
        )
        return FunctionEntry(name, file_path=source or None)

    def _instance_outcome(
        self,
        instance: Any,
        entry: FunctionEntry,
        scope: InstanceScope,
        results: Dict[str, ParallelAnalysisResult],
        snapshot: Dict[str, Any],
    ) -> InstanceAnalysisOutcome:
        result = results.get(self._scoped_result_key(entry, scope))
        scope_gaps: List[Dict[str, Any]] = []
        blocked: List[str] = []
        semantics = ""
        fact_queries = 0
        context_status = ""
        status = "analyzed"
        verdict = ""
        error = ""
        duration = 0.0
        if result is None:
            status = "gap"
            error = GAP_INSTANCE_NOT_ANALYZED
            scope_gaps.append(
                {
                    "reason": GAP_INSTANCE_NOT_ANALYZED,
                    "detail": "no analysis result returned for the scheduled instance",
                    "build_context_id": scope.build_context_id,
                    "severity": "identity",
                }
            )
        else:
            verdict = str(result.verdict or "")
            error = str(result.error or "")
            duration = float(result.duration_seconds or 0.0)
            if verdict == "error" and error:
                status = "error"
            report = result.instance_scope_report or {}
            scope_gaps = [dict(item) for item in (report.get("identity_gaps") or [])]
            blocked = sorted(str(name) for name in (report.get("blocked_consumers") or []))
            context_status = str(report.get("context_status") or "")
            fact_queries = len(report.get("fact_queries") or [])
            semantics = str(result.metadata.get("instance_semantics") or "")
        candidates = self._candidates_for_instance(snapshot, entry, scope)
        return InstanceAnalysisOutcome(
            identity=scope.identity,
            build_context_id=scope.build_context_id,
            usr=scope.usr,
            source=str(getattr(instance, "source", "") or ""),
            function_name=entry.function_name,
            status=status,
            verdict=verdict,
            entry_identity=entry.identity_key(self.base_config.project.project_root),
            issues=candidates,
            candidate_build_context_ids=sorted(
                {str(item.get("build_context_id") or "") for item in candidates}
            ),
            scope_gaps=scope_gaps,
            blocked_consumers=blocked,
            context_status=context_status,
            semantics=semantics,
            fact_queries=fact_queries,
            duration_seconds=duration,
            error=error,
        )

    def _candidates_for_instance(
        self,
        snapshot: Dict[str, Any],
        entry: FunctionEntry,
        scope: InstanceScope,
    ) -> List[Dict[str, Any]]:
        entry_identity = entry.identity_key(self.base_config.project.project_root)
        candidates: List[Dict[str, Any]] = []
        for outcome in snapshot.get("outcomes") or []:
            if not isinstance(outcome, dict):
                continue
            issue = outcome.get("issue") or {}
            if str(issue.get("build_context_id") or "") != scope.build_context_id:
                continue
            entries = {str(value) for value in (outcome.get("entries") or []) if str(value)}
            if entry_identity and entries and entry_identity not in entries:
                continue
            candidates.append(
                {
                    "candidate_uid": str(issue.get("candidate_uid") or ""),
                    "validation_cluster_uid": str(issue.get("validation_cluster_uid") or ""),
                    "rule_id": str(issue.get("rule_id") or issue.get("rule") or ""),
                    "defect_class": str(issue.get("defect_class") or ""),
                    "build_context_id": str(issue.get("build_context_id") or ""),
                    "location": str(issue.get("location") or ""),
                    "candidate_disposition": str(issue.get("candidate_disposition") or ""),
                }
            )
        candidates.sort(key=lambda item: (item["validation_cluster_uid"], item["candidate_uid"]))
        return candidates

    @staticmethod
    def _instance_scope_metadata(
        instance_scope: Optional[InstanceScope],
        scoped_index: Any,
    ) -> Dict[str, Any]:
        if instance_scope is None:
            return {}
        metadata: Dict[str, Any] = {
            "build_context_id": instance_scope.build_context_id,
            "usr": instance_scope.usr,
            "instance_identity": instance_scope.identity,
            # Declared: instance analysis runs with the generator's standard
            # roots only; the project-wide model is not instance authorization.
            "instance_semantics": "defaults_only",
        }
        getter = getattr(scoped_index, "scope_report", None)
        if callable(getter):
            value = getter()
            if isinstance(value, dict):
                metadata["instance_scope_report"] = value
        return metadata

    def _analyze_function_entries(
        self,
        entries: List[FunctionEntry],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        scoped_entries: Optional[List[Tuple[FunctionEntry, Optional[InstanceScope]]]] = None,
    ) -> Dict[str, ParallelAnalysisResult]:
        """
        Analyze multiple function entries with custom prompts.

        Args:
            entries: List of FunctionEntry objects with function names and custom prompts
            progress_callback: Optional callback(completed, total, func_name) for progress
            scoped_entries: Optional exact ``(entry, instance_scope)`` pairs.  When
                provided, entries are never re-materialized from the navigation
                projection and each entry is analyzed with its own build context.

        Returns:
            Dict mapping function key to analysis result
        """
        self._begin_llm_usage_batch()
        if scoped_entries is None:
            entries = self._materialize_entry_identities(entries)
            scoped_entries = [(entry, None) for entry in entries]
        else:
            entries = [entry for entry, _scope in scoped_entries]
        self._last_materialized_entries = list(entries)
        self._restored_result_costs = {}
        results = {}
        total = len(scoped_entries)
        completed = 0
        batch_started = time.monotonic()
        scan_budget_seconds = getattr(
            self.base_config.analysis,
            "scan_deadline_seconds",
            None,
        )
        budget_exhaustion_policy = "observe"
        self._interrupted = False
        self._deadline_exceeded = False
        self._cancellation_token = CancellationToken(
            parent=self._parent_cancellation_token,
            timeout_seconds=None,
        )
        self._candidate_ledger = CandidateLedger(
            project_id=str(
                getattr(self.base_config.project, "project_id", "")
                or self.base_config.project.project_root.name
            ),
            project_root=str(self.base_config.project.project_root),
            revision=Analyzer._git_commit_sha(self.base_config.project.project_root),
        )
        self._decision_fact_cache = DecisionFactGraphCache()
        self._global_validation_state = {}
        self._global_validation_duration_seconds = 0.0
        self._project_fact_pass_state = {}
        self._hierarchical_discovery_done = False
        self._hierarchical_static_inputs = None
        self._hierarchical_supplements = {}
        self._hierarchical_discovery_result = {}
        self._fast_static_scan_state = {
            "schema": "zscope.fast-static-scan.v1",
            "enabled": False,
            "status": "not_run",
        }
        self._active_discovery_state = {
            "enabled": False,
            "profile": resolve_discovery_profile(self.base_config).name,
            "status": "not_run",
        }
        self._cancellation_token.raise_if_cancelled()
        scheduler = ScanScheduler(
            entry_workers=self.max_workers,
            validator_workers=self.base_config.concurrency.validator_workers,
            investigator_workers=self.base_config.concurrency.investigator_workers,
        )
        self._scheduler = scheduler

        logger.info(
            f"Starting parallel analysis of {total} function entries with {self.max_workers} workers"
        )
        instance_scoped = any(scope is not None for _entry, scope in scoped_entries)
        self._batch_instance_scoped = instance_scoped
        self._instance_scopes_by_build = {}
        self._validation_semantics_snapshots = {}
        self._validation_semantics_receipts = {}
        self._validation_semantics_fact_receipts = {}
        for _entry, scope in scoped_entries:
            if scope is None:
                continue
            self._instance_scopes_by_build.setdefault(scope.build_context_id, []).append(scope)
        try:
            if total:
                if instance_scoped:
                    # Instance-scoped execution never runs the project-wide
                    # semantic model, deterministic fact pass or active
                    # discovery over the unwrapped index.  Those are stopped
                    # here and stay declared gaps; only the scoped entry
                    # analysis and the shared validation chain run.
                    self._shared_local_pattern_semantics = None
                    self._shared_semantic_overlay = None
                    self._last_global_model_stats = None
                    self._global_modeling_succeeded = False
                    self._project_fact_pass_state = {
                        "enabled": False,
                        "status": "skipped",
                        "reason": "instance_scope_isolated",
                    }
                    self._active_discovery_state = {
                        "enabled": False,
                        "profile": resolve_discovery_profile(self.base_config).name,
                        "status": "skipped",
                        "reason": "instance_scope_isolated",
                    }
                    if self._uses_scoped_fast_static_pass():
                        self._run_scoped_fast_static_pass(scoped_entries)
                elif self.base_config.project.language != "java":
                    if self.semantic_result is None:
                        self._global_modeling_succeeded = self._run_global_modeling(entries)
                    if self.semantic_result is not None:
                        self._shared_local_pattern_semantics = self.semantic_result.local_semantics
                        self._shared_semantic_overlay = self.semantic_result.overlay
                        self._last_global_model_stats = self.semantic_result.stats.to_dict()
                if not instance_scoped:
                    semantics_started = time.time()
                    logger.info("[entry-worker] shared-semantics start entries=%d", total)
                    self._prepare_shared_semantics()
                    logger.info(
                        "[entry-worker] shared-semantics end entries=%d duration=%.2fs",
                        total,
                        time.time() - semantics_started,
                    )
                    self._run_project_deterministic_fact_pass(entries)
        except Exception:
            scheduler.shutdown(wait=True, cancel_futures=True)
            self._scheduler = None
            raise

        scheduled_entries = self._prioritize_scoped_entries(scoped_entries)
        try:
            # Submit all analysis tasks
            future_to_entry = {
                scheduler.submit(
                    ENTRY_ROLE,
                    self._analyze_single_entry,
                    entry,
                    instance_scope=scope,
                    skip_candidate_discovery=bool(
                        self._fast_static_scan_state.get("activated", False)
                    ),
                    priority=self._entry_scheduling_score(entry),
                ): (entry, scope)
                for entry, scope in scheduled_entries
            }

            # Collect results as they complete
            try:
                for future in concurrent.futures.as_completed(
                    future_to_entry,
                    timeout=self._cancellation_token.remaining_seconds(),
                ):
                    entry, scope = future_to_entry[future]
                    completed += 1

                    try:
                        result = future.result()
                        results[self._scoped_result_key(entry, scope)] = result
                        logger.info(
                            f"[{completed}/{total}] {entry.function_name}: {result.verdict} ({len(result.issues)} issues, ctx ≈ {result.context_tokens:,} tokens)"
                        )
                    except concurrent.futures.CancelledError:
                        logger.warning(
                            f"[{completed}/{total}] {entry.function_name}: Cancelled due to interrupt"
                        )
                    except Exception as e:
                        logger.error(f"[{completed}/{total}] {entry.function_name}: ERROR - {e}")
                        results[self._scoped_result_key(entry, scope)] = ParallelAnalysisResult(
                            function_name=entry.function_name,
                            verdict="error",
                            error=str(e),
                            diff_focus=entry.diff_focus,
                        )

                    if progress_callback:
                        progress_callback(completed, total, entry.function_name)

            except KeyboardInterrupt:
                self._interrupted = True
                self._cancellation_token.cancel("scan_interrupted")
                logger.warning(
                    "\n[!] Scan interrupted by user (Ctrl+C). Cancelling queued work "
                    "and returning completed results. Running Python worker threads "
                    "cannot be force-killed safely."
                )

                # cancel_futures only affects queued work; already-running threads may
                # continue until the CLI takes the interrupted fast-exit path.
                scheduler.shutdown(wait=False, cancel_futures=True)

                logger.info(f"Returning {len(results)} completed results out of {total} total.")
                return results
            except concurrent.futures.TimeoutError:
                self._deadline_exceeded = True
                self._cancellation_token.cancel("scan_deadline_exceeded")
                logger.error(
                    "Scan deadline exceeded after %.2fs; cancelling queued entry work.",
                    time.monotonic() - batch_started,
                )
                for future, (entry, scope) in future_to_entry.items():
                    entry_key = self._scoped_result_key(entry, scope)
                    if entry_key in results or future.done():
                        continue
                    future.cancel()
                    results[entry_key] = ParallelAnalysisResult(
                        function_name=entry.function_name,
                        verdict="error",
                        error="scan_deadline_exceeded",
                        diff_focus=entry.diff_focus,
                        metadata={"cancellation_reason": "scan_deadline_exceeded"},
                    )
                scheduler.shutdown(wait=False, cancel_futures=True)
                return results

            discovery_profile = resolve_discovery_profile(self.base_config)
            discovery_mode = rollout_active_discovery_mode(self.base_config)
            ablation_override = self._benchmark_ablation_override
            ablation_disables_map = bool(
                ablation_override is not None and not ablation_override.semantic_map_enabled
            )
            if instance_scoped:
                # Active discovery reads the whole navigation projection; it is
                # stopped for instance scope and stays a declared gap.
                self._active_discovery_state = {
                    "enabled": False,
                    "profile": discovery_profile.name,
                    "status": "skipped",
                    "reason": "instance_scope_isolated",
                    "llm_semantic_model_calls": 0,
                    "llm_discovery_call_count": 0,
                }
            elif (
                discovery_profile.name == "fast"
                or (discovery_mode == "disabled" and ablation_override is None)
                or ablation_disables_map
            ):
                # Fast is a true zero-work path: no semantic-map traversal,
                # sidecar writes, or discovery-model invocation.
                self._active_discovery_state = {
                    "enabled": False,
                    "profile": discovery_profile.name,
                    "status": (
                        "disabled_by_profile"
                        if discovery_profile.name == "fast"
                        else (
                            "disabled_by_ablation"
                            if ablation_disables_map
                            else "disabled_by_rollout"
                        )
                    ),
                    "visibility_mode": discovery_mode,
                    "rollout": rollout_runtime_policy(self.base_config),
                    "llm_semantic_model_calls": 0,
                    "llm_discovery_call_count": 0,
                }
                if ablation_override is not None:
                    self._active_discovery_state["benchmark_ablation"] = (
                        ablation_override.report_metadata()
                    )
            elif ablation_override is not None:
                self._run_active_discovery(entries, discovery_profile)
            else:
                self._active_discovery_state = {"enabled": False,
                    "profile": discovery_profile.name, "status": "unavailable",
                    "reason": "hierarchical_discovery_requires_exact_static_inventory"}

            if not instance_scoped:
                self._register_snapshot_shadow_candidates()
            if self._uses_scan_validation_queue():
                self._run_scan_validation_queue()

        finally:
            self._last_batch_wall_seconds = time.monotonic() - batch_started
            self._last_scan_budget_metadata = self._scan_budget_metadata(
                duration_seconds=self._last_batch_wall_seconds,
                budget_seconds=scan_budget_seconds,
                policy=budget_exhaustion_policy,
            )
            if self._last_scan_budget_metadata["scan_budget_exceeded"]:
                logger.warning(
                    "Scan budget exceeded: budget=%.2fs overrun=%.2fs " "policy=%s outcome=%s",
                    float(str(scan_budget_seconds)),
                    self._last_scan_budget_metadata["scan_budget_overrun_seconds"],
                    budget_exhaustion_policy,
                    ("completed"),
                )
            # Under normal successful execution, properly wait and clean up resources
            if scheduler and not (
                getattr(self, "_interrupted", False) or getattr(self, "_deadline_exceeded", False)
            ):
                try:
                    scheduler.shutdown(wait=True)
                except Exception:
                    pass

        return results

    def _register_snapshot_shadow_candidates(self) -> None:
        """Keep modeling observations outside candidate-blind discovery inputs."""
        mode = getattr(self.base_config.analysis, "semantic_snapshot_candidate_mode", "off")
        if mode != "shadow":
            return
        result = getattr(self, "semantic_result", None)
        if result is None:
            return
        self._cancellation_token.raise_if_cancelled()
        from .snapshot_candidates import register_conditional_snapshot_candidates

        registrar = CandidateRegistrar(
            self._candidate_ledger,
            project_id=str(getattr(self.base_config.project, "project_id", "") or ""),
            project_root=str(self.base_config.project.project_root),
            revision=str(self._candidate_ledger.revision or ""),
            run_id=self.run_id,
            decision_fact_cache=getattr(self, "_decision_fact_cache", None),
        )
        register_conditional_snapshot_candidates(
            result, registrar, mode=mode, project_root=self.base_config.project.project_root
        )

    def _uses_scan_validation_queue(self) -> bool:
        # A few embedding and compatibility callers construct this facade with
        # ``object.__new__`` to exercise report projection only.  Those paths
        # have no configuration or batch lifecycle, so retain the pre-v3
        # per-entry behavior instead of assuming scan-level validation.
        return True

    @staticmethod
    def _fast_validation_rank_key(issue: Mapping[str, Any]) -> Tuple[Any, ...]:
        """Deterministic evidence-only ordering for fast Validator admission.

        This is a scheduling policy, never a finding verdict.  It only uses
        facts already present in the candidate envelope and therefore cannot
        see benchmark truth.  Exact sinks and structural graph findings lead;
        broad audit observations trail.  Confidence merely breaks ties inside
        those evidence classes.
        """

        pack = issue.get("evidence_pack")
        evidence = pack if isinstance(pack, Mapping) else {}
        priority_group = str(
            issue.get("candidate_priority_group") or evidence.get("candidate_priority_group") or ""
        )
        group_order = {
            "exact_sink": 0,
            "graph_structural": 1,
            "semantic_suspicious_point": 2,
            "generic_audit": 4,
        }.get(priority_group, 3)
        source = str(issue.get("candidate_source") or evidence.get("candidate_source") or "")
        source_order = {
            "clang_native_fact": 0,
            "svf_value_flow": 0,
            "saber_bug": 0,
            "clang_ast_cfg": 1,
            "clang_ast_matcher": 1,
            "graph": 2,
            "cpp_graph": 2,
            "regex": 3,
        }.get(source, 4)
        path = evidence.get("path")
        path_complete = bool(isinstance(path, Mapping) and path.get("complete_in_function") is True)
        validation_class = str(
            issue.get("validation_budget_class") or evidence.get("validation_budget_class") or ""
        )
        budget_penalty = 1 if validation_class in {"generic", "generic_soft_overrun"} else 0
        impact = str(issue.get("impact_level") or "").lower()
        impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(impact, 2)
        try:
            confidence = float(
                issue.get("rule_confidence")
                or evidence.get("rule_confidence")
                or issue.get("confidence")
                or 0.0
            )
        except (TypeError, ValueError):
            confidence = 0.0
        return (
            group_order,
            budget_penalty,
            source_order,
            0 if path_complete else 1,
            impact_order,
            -confidence,
            str(issue.get("candidate_uid") or issue.get("candidate_id") or issue.get("id") or ""),
        )

    def _partition_fast_validation_queue(
        self,
        pending: Sequence[Dict[str, Any]],
        *,
        max_groups: Optional[int] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        """Admit every canonical decision-ready obligation exactly once.

        ``max_groups`` remains a source-compatible argument for third-party
        callers during this schema revision, but is intentionally ignored.
        A code-size or category budget must never become a validation coverage
        boundary in fast.
        """

        ordered = sorted(list(pending), key=self._fast_validation_rank_key)
        del max_groups
        admitted = ordered
        deferred: List[Dict[str, Any]] = []

        for rank, issue in enumerate(admitted, start=1):
            issue["fast_validation_admitted"] = True
            issue["fast_validation_rank"] = rank
            pack = issue.get("evidence_pack")
            if isinstance(pack, dict):
                pack["fast_validation_admitted"] = True
                pack["fast_validation_rank"] = rank

        admitted_classes: Dict[str, int] = {}
        deferred_classes: Dict[str, int] = {}
        for bucket, target in ((admitted, admitted_classes), (deferred, deferred_classes)):
            for issue in bucket:
                key = str(issue.get("defect_class") or issue.get("category") or "unknown")
                target[key] = target.get(key, 0) + 1
        telemetry = {
            "policy": "zscope.fast-validator-decision-ready.v2",
            "eligible": len(ordered),
            "max_groups": None,
            "admitted": len(admitted),
            "decision_ready": len(admitted),
            "deferred_to_needs_review": len(deferred),
            "admitted_by_defect_class": admitted_classes,
            "deferred_by_defect_class": deferred_classes,
        }
        return admitted, deferred, telemetry

    def _run_scan_validation_queue(self) -> None:
        """Validate each frozen v3 obligation once after all entries discover it.

        Entry workers can discover the same local sink through many wrappers.
        The shared ledger has already merged those occurrences by
        ``validation_cluster_uid``.  Validating inside each entry therefore
        spends LLM calls before that merge can have any effect.  This method
        restores the intended lifecycle: discovery -> ledger -> one global
        validation queue -> final report projection.
        """

        instance_scoped = bool(getattr(self, "_batch_instance_scoped", False))
        if instance_scoped:
            self.require_current_instance_inputs()
            self._run_hierarchical_discovery()
        # Discovery and optional snapshot observations are complete. Seal the ledger before
        # taking the validation snapshot so no late producer can create an
        # obligation after queue construction has begun.
        self._candidate_ledger.freeze()

        pending: List[Dict[str, Any]] = []
        for record in self._candidate_ledger.records():
            if record.record_role != "validation_obligation" or record.disposition:
                continue
            evidence = deepcopy(
                record.ticket.evidence if isinstance(record.ticket.evidence, dict) else {}
            )
            issue = deepcopy(evidence.pop("candidate_payload", {}) or {})
            if not issue:
                # Candidate payloads are persisted with every v3 obligation.
                # Retain a minimally reportable diagnostic rather than
                # silently dropping a malformed legacy producer.
                issue = {
                    "id": record.ticket.id,
                    "category": record.defect_class,
                    "defect_class": record.defect_class,
                    "description": record.ticket.task,
                    "source": record.ticket.origin,
                    "sink": record.ticket.sink,
                }
            issue["evidence_pack"] = evidence
            supplements = getattr(self, "_hierarchical_supplements", {})
            sink = issue.get("sink")
            sink = sink if isinstance(sink, dict) else {}
            build = str(issue.get("build_context_id") or evidence.get("build_context_id") or "")
            usr = str(issue.get("function_usr") or sink.get("usr") or "")
            if not usr:
                exact_scope = str(issue.get("validation_scope_identity") or "")
                for scope in getattr(self, "_instance_scopes_by_build", {}).get(build, []):
                    if scope.identity == exact_scope:
                        usr = scope.usr
                        break
            supplement = supplements.get((build, usr))
            if supplement:
                evidence["hierarchical_supplement"] = deepcopy(supplement)
            issue.setdefault("code_snippet", record.ticket.context_slice)
            issue.update(
                {
                    "candidate_schema_version": record.schema_version,
                    "candidate_uid": record.candidate_uid,
                    "history_key": record.history_key,
                    "obligation_uid": record.obligation_uid,
                    "decision_context_version": record.decision_context_version,
                    "evidence_hash": record.evidence_hash,
                    "decision_evidence_hash": record.decision_evidence_hash,
                    "validation_cluster_uid": record.validation_cluster_uid,
                    "context_signature": record.context_signature,
                    "occurrence_uid": (record.occurrence_uids[0] if record.occurrence_uids else ""),
                    "occurrence_uids": list(record.occurrence_uids),
                    "call_paths": [list(path) for path in record.call_paths],
                    "entry_paths": [list(path) for path in record.call_paths],
                    "entry_identity": (
                        record.occurrences[0].entry_identity
                        if record.occurrences
                        else str(issue.get("entry_identity") or "")
                    ),
                }
            )
            evidence.update(
                {
                    "candidate_uid": record.candidate_uid,
                    "evidence_hash": record.evidence_hash,
                    "decision_evidence_hash": record.decision_evidence_hash,
                    "validation_cluster_uid": record.validation_cluster_uid,
                    "context_signature": record.context_signature,
                }
            )
            pending.append(issue)

        if not pending:
            self._global_validation_state = {
                "pending_new_issues": [],
                "issues": [],
                "observations": [],
                "notes": ["Scan-level validation queue had no open obligations."],
                "validation_queue_drained": True,
                "budget_exhaustion_policy": str(
                    getattr(self.base_config.analysis, "budget_exhaustion_policy", "observe")
                    or "observe"
                ),
            }
            return

        all_pending = list(pending)
        pending, fast_deferred, fast_admission = self._partition_fast_validation_queue(pending)
        for issue in fast_deferred:
            issue["validation_status"] = "needs_review"
            issue["validation_attempted"] = False
            issue["needs_review_sub_state"] = "fast_precision_budget_deferred"
            issue["fast_validation_admitted"] = False
            issue["fast_validation_policy"] = fast_admission["policy"]
            issue["fast_validation_max_groups"] = fast_admission["max_groups"]
            pack = issue.get("evidence_pack")
            if isinstance(pack, dict):
                pack["fast_validation_admitted"] = False
                pack["fast_validation_policy"] = fast_admission["policy"]
                pack["needs_review_sub_state"] = "fast_precision_budget_deferred"
            self._candidate_ledger.mark_issue_terminal(
                issue, disposition="needs_review", status="needs_review"
            )

        if not pending:
            empty_state: Dict[str, Any] = {
                "pending_new_issues": [],
                "issues": [],
                "observations": list(fast_deferred),
                "notes": ["Fast Validator admission deferred every obligation to needs_review."],
                "validation_queue_drained": True,
                "fast_validation_admission": fast_admission,
                "validator_session_count": 0,
                "validator_api_call_count": 0,
            }
            empty_state.update(self._validator_v3_outcome_summary(all_pending))
            self._global_validation_duration_seconds = 0.0
            self._global_validation_state = empty_state
            return

        groups: List[Tuple[InstanceScope, List[Dict[str, Any]]]] = []
        ungrouped: List[Dict[str, Any]] = []
        if instance_scoped:
            groups, ungrouped = self._instance_validation_groups(pending)

        helper = (
            self._instance_validation_helper(groups[0][0])
            if groups
            else (None if instance_scoped else self._base_validation_helper())
        )
        ledger_records = list(self._candidate_ledger.records())
        raw_occurrence_count = sum(len(record.occurrence_uids) for record in ledger_records)
        eligible_records = [
            record
            for record in ledger_records
            if str(record.decision_context_version or "").endswith(("v3.1", "v3.2", "v3.3"))
            and record.record_role == "validation_obligation"
        ]
        eligible_occurrence_count = sum(len(record.occurrence_uids) for record in eligible_records)
        eligible_duplicate_request_count = sum(
            max(0, len(record.occurrence_uids) - 1) for record in eligible_records
        )
        state: Dict[str, Any] = {
            "entry_func": "__batch__",
            "entry_identity": "__batch__",
            "entry_index_name": "",
            "agent_context": {"func_name": "__batch__", "code": ""},
            "pending_new_issues": (groups[0][1] if groups else pending),
            "issues": [],
            "observations": list(fast_deferred),
            "notes": [],
            "candidate_ledger": self._candidate_ledger,
            "scan_level_raw_occurrence_count": raw_occurrence_count,
            "eligible_alias_occurrence_count": eligible_occurrence_count,
            "eligible_validation_group_count": len(eligible_records),
            # Only already-proven structural aliases participate in this
            # denominator.  The ledger creates one record for a shared future,
            # so every alias here avoided a second Validator invocation.
            "eligible_duplicate_request_count": eligible_duplicate_request_count,
            "coalesced_duplicate_request_count": eligible_duplicate_request_count,
            "cluster_fragmentation_by_reason": {},
            "budget_exhaustion_policy": str(
                getattr(self.base_config.analysis, "budget_exhaustion_policy", "observe")
                or "observe"
            ),
            "validation_queue_drained": False,
            "validator_session_count": 0,
            "validator_api_call_count": 0,
            "validator_turn_distribution": {},
            "validator_prompt_tokens_by_stage": {},
            "evidence_slice_token_count": 0,
            "multi_turn_outlier_count": 0,
            "snapshot_model_call_count": 0,
            "fact_query_cache_hit_count": 0,
            "fast_validation_admission": fast_admission,
        }
        started = time.monotonic()
        logger.info(
            "[validation-queue] start unique_groups=%d raw_occurrences=%d",
            len(pending),
            raw_occurrence_count,
        )
        if groups:
            # One adjudication per obligation, in its own exact build scope.
            all_groups_drained = True
            for index, (scope, issues) in enumerate(groups):
                group_helper = helper if index == 0 else self._instance_validation_helper(scope)
                assert group_helper is not None
                group_snapshot = group_helper._instance_semantics_snapshot
                assert group_snapshot is not None
                self._require_validation_snapshot_current(scope, group_snapshot)
                self._bind_ablation_validator_policy(group_helper.validation_runner)
                state["pending_new_issues"] = list(issues)
                state["validation_queue_drained"] = False
                group_helper._require_instance_semantics_current()
                group_helper.validation_runner.run(state)
                group_helper._require_instance_semantics_current()
                self._require_validation_snapshot_current(scope, group_snapshot)
                all_groups_drained = (
                    all_groups_drained and state.get("validation_queue_drained") is True
                )
            for issue in ungrouped:
                issue["validation_status"] = "needs_review"
                issue["validation_attempted"] = False
                issue["needs_review_sub_state"] = "exact_validation_scope_unavailable"
                self._candidate_ledger.mark_issue_terminal(
                    issue, disposition="needs_review", status="needs_review"
                )
            if ungrouped:
                state["notes"].append(
                    "instance validation gap: "
                    f"{len(ungrouped)} obligation(s) had no exact scheduled scope"
                )
            state["validation_queue_drained"] = all_groups_drained
        elif instance_scoped:
            for issue in ungrouped:
                issue["validation_status"] = "needs_review"
                issue["validation_attempted"] = False
                issue["needs_review_sub_state"] = "exact_validation_scope_unavailable"
                self._candidate_ledger.mark_issue_terminal(
                    issue, disposition="needs_review", status="needs_review"
                )
                state["observations"].append(issue)
            state["notes"].append("instance validation gap: no current exact scope for obligations")
            state["pending_new_issues"] = []
            state["validation_queue_drained"] = True
        else:
            assert helper is not None
            self._bind_ablation_validator_policy(helper.validation_runner)
            helper.validation_runner.run(state)
        if instance_scoped:
            self.require_current_instance_inputs()
        if not instance_scoped and self.semantic_result is not None:
            from .snapshot_candidates import update_snapshot_outcomes

            update_snapshot_outcomes(self.semantic_result, self._candidate_ledger)
        state.update(self._validator_v3_outcome_summary(all_pending))
        self._global_validation_duration_seconds = max(0.0, time.monotonic() - started)
        self._global_validation_state = state
        discovery_result = getattr(self, "_hierarchical_discovery_result", {})
        from .hierarchical_discovery import mode_outcomes

        state["mode_outcomes"] = mode_outcomes(all_pending, discovery_result)
        if discovery_result:
            from .hierarchical_discovery import rule_proposals, save_rule_proposals

            proposals = rule_proposals(discovery_result.get("candidates", []), all_pending)
            proposal_path = Path(self.base_config.analysis.snapshot_dir) / "rule_proposals.json"
            proposals = save_rule_proposals(proposal_path, proposals)
            self._active_discovery_state["rule_proposals"] = proposals
            self._active_discovery_state["rule_proposals_path"] = str(proposal_path)
        logger.info(
            "[validation-queue] end unique_groups=%d confirmed=%d review=%d duration=%.2fs",
            len(all_pending),
            len(state["issues"]),
            len(state["observations"]),
            self._global_validation_duration_seconds,
        )

    def _run_hierarchical_discovery(self) -> None:
        """Deep's only default discovery path, before sealing the shared ledger."""
        if resolve_discovery_profile(self.base_config).name != "deep":
            return
        if getattr(self, "_hierarchical_discovery_done", False):
            return
        from .hierarchical_discovery import HierarchicalDiscovery, build_hierarchy, make_function

        inputs = getattr(self, "_hierarchical_static_inputs", None)
        if not inputs or not self._fast_static_scan_state.get("activated"):
            self._active_discovery_state = {"enabled": True, "status": "unavailable",
                "reason": "current_static_inventory_unavailable", "profile": "deep"}
            return
        runtime, links = inputs
        functions, owners = [], {}
        for build, data in runtime.items():
            for scope, impl, _context, _unit_id, facts in data["function_work"]:
                row = make_function(scope, impl, facts)
                functions.append(row)
                owners[(build, scope.usr)] = (scope, data)
        context = self._instance_semantics_context
        document = json.loads(bytes(context.effective_project_document)) if context else {}
        lifecycle = document.get("lifecycle", {"boundaries": [], "lifetimes": []})
        hierarchy = build_hierarchy(functions, links, lifecycle,
            max_members=self.base_config.analysis.max_premodel_callees)
        hierarchy["gaps"].extend(deepcopy(self._fast_static_scan_state.get("planning_gaps", [])))
        client = self._scan_role_llm_client("analysis")
        if client is None:
            self._active_discovery_state = {"enabled": True, "status": "unavailable",
                "reason": "analysis_client_unavailable", "profile": "deep"}
            return
        def current() -> None:
            self._cancellation_token.raise_if_cancelled()
            self.require_current_instance_inputs()
        modeling_client = self._scan_role_llm_client("modeling") or client
        discovery = HierarchicalDiscovery(client=client,
            cache_dir=Path(self.base_config.analysis.snapshot_dir) / "hierarchical_contracts",
            require_current=current,
            max_iterations=self.base_config.analysis.max_tool_iterations,
            timeout=self.base_config.analysis.active_investigation_timeout_seconds,
            model_identity={"analysis": list(getattr(client, "models", []) or []),
                            "modeling": list(getattr(modeling_client, "models", []) or [])},
            cancellation_token=self._cancellation_token, modeling_client=modeling_client)
        result = discovery.run(hierarchy, lifecycle)
        current()
        # Preserve supplements as unverified context. The Validator must read
        # and bind them itself; they cannot close a required native fact kind.
        self._hierarchical_supplements = {}
        for row in functions:
            summary = result["summaries"].get(row["id"])
            if summary:
                self._hierarchical_supplements[(row["build_context_id"], row["usr"])] = {
                    "summary": summary, "input_digest": result["input_digest"],
                    "compositions": [{"unit": unit, "summary": result["summaries"].get(unit["id"])}
                        for unit in hierarchy["units"] if row["id"] in unit["members"]
                        and unit["id"] in result["summaries"]],
                    "authority": "unverified_context"}
        static_clusters = {record.validation_cluster_uid for record in self._candidate_ledger.records()}
        for candidate in result["candidates"]:
            scope, data = owners[(candidate["build_context_id"], candidate["function_usr"])]
            candidate["validation_scope_identity"] = scope.identity
            helper = self._instance_validation_helper(scope)
            helper._register_candidate_issues({"candidate_ledger": self._candidate_ledger,
                "entry_identity": data["representative_identity"], "run_id": self.run_id},
                [candidate], source="hierarchical_discovery")
            candidate["deep_contribution"] = (
                "existing_candidate_evidence" if candidate.get("validation_cluster_uid") in static_clusters
                else "additional_candidate")
        self._hierarchical_discovery_result = result
        from .hierarchical_discovery import write_json

        contract_path = Path(self.base_config.analysis.snapshot_dir) / "hierarchical_contracts.json"
        write_json(contract_path, {"schema_version": result["schema_version"],
            "input_digest": result["input_digest"], "units": hierarchy["units"],
            "functions": [{k: f[k] for k in ("id", "usr", "build_context_id", "function", "file")}
                          for f in functions], "edges": hierarchy["edges"],
            "summaries": result["summaries"], "gaps": result["gaps"],
            "authority": "unverified_context"})
        self._hierarchical_discovery_done = True
        self._hierarchical_static_inputs = None
        self._active_discovery_state = {k: v for k, v in result.items() if k not in {"summaries", "candidates"}}
        self._active_discovery_state.update({"enabled": True, "profile": "deep",
            "path": "hierarchical_contracts", "candidate_count": len(result["candidates"]),
            "summary_count": len(result["summaries"]), "duration_seconds": result["elapsed_seconds"]})
        self._active_discovery_state["contracts_path"] = str(contract_path)

    def _base_validation_helper(self) -> Analyzer:
        """The scan-level validation helper for an unscoped batch."""

        return Analyzer(
            self.base_config,
            semantic_result=self.semantic_result,
            reproduction_service=getattr(self, "reproduction_service", None),
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            user_config=self.user_config,
            force_ignore_history=self.force_ignore_history,
            maintain_mode=self.maintain_mode,
            candidate_ledger=self._candidate_ledger,
            # The queue only validates frozen candidate evidence.  It must not
            # trigger a second semantic-discovery build after all entry
            # workers have already completed one.
            shared_local_pattern_semantics=self._shared_local_pattern_semantics,
            shared_semantic_overlay=self._shared_semantic_overlay,
            llm_clients=self._shared_llm_clients,
            validation_result_cache=self._validation_result_cache,
            cancellation_token=self._cancellation_token,
            scheduler=self._scheduler,
            candidate_ir_persistence_lock=self._candidate_ir_persistence_lock,
            decision_fact_cache=self._decision_fact_cache,
            write_root_reports=False,
            defer_validation_to_scan=False,
            project_knowledge_service=self.project_knowledge_service,
        )

    def _instance_validation_helper(self, scope: InstanceScope) -> Analyzer:
        """A validation helper pinned to one exact instance build scope.

        The post-discovery Validator, tools and rebuttal then run against the
        same precise ``(BuildContext, USR)`` as the entry analysis; the
        unwrapped base index and the project-wide semantic model never
        authorize an instance verdict.
        """

        snapshot = self._validation_semantic_snapshot(scope)
        context = self._instance_semantics_context
        assert context is not None
        return Analyzer(
            self.base_config,
            semantic_result=None,
            reproduction_service=getattr(self, "reproduction_service", None),
            code_index=wrap_scoped_code_index(self.code_index, scope),
            snapshot_store=self.snapshot_store,
            user_config=self.user_config,
            force_ignore_history=self.force_ignore_history,
            maintain_mode=self.maintain_mode,
            candidate_ledger=self._candidate_ledger,
            shared_local_pattern_semantics=LocalPatternSemantics(),
            shared_semantic_overlay={},
            llm_clients=self._shared_llm_clients,
            validation_result_cache=self._validation_result_cache,
            cancellation_token=self._cancellation_token,
            scheduler=self._scheduler,
            candidate_ir_persistence_lock=self._candidate_ir_persistence_lock,
            decision_fact_cache=self._decision_fact_cache,
            write_root_reports=False,
            defer_validation_to_scan=False,
            project_knowledge_service=self.project_knowledge_service,
            instance_scope=scope,
            instance_semantics_snapshot=snapshot,
            # The enclosing project pass and validation queue perform fresh
            # fail-closed batch currentness checks before and after consuming
            # candidates.  Candidate annotation only needs to prove that it
            # still references the exact frozen snapshot; re-reading YAML,
            # link receipts and include namespaces for every candidate would
            # turn the one-pass scanner back into entry/candidate-scaled IO.
            instance_semantics_current=self._validation_snapshot_is_frozen,
        )

    def _scope_for_pending_issue(self, issue: Dict[str, Any]) -> Optional[InstanceScope]:
        """The exact scheduled scope an obligation belongs to, or ``None``."""

        build_id = str(issue.get("build_context_id") or "")
        if not build_id:
            return None
        scopes = self._instance_scopes_by_build.get(build_id) or []
        requested_scope = str(issue.get("validation_scope_identity") or "")
        if requested_scope:
            matches = [scope for scope in scopes if scope.identity == requested_scope]
            # The fast project pass writes this field from the frozen
            # coordinator scope.  A missing or ambiguous identity is never a
            # request to pick the first build member.
            return matches[0] if len(matches) == 1 else None
        aliases = getattr(self, "_instance_entry_owners", {})
        cluster = str(issue.get("validation_cluster_uid") or "")
        if not cluster or not aliases:
            return None
        with self._candidate_ledger._lock:
            record = self._candidate_ledger._records.get(cluster)
            if record is None or not record.occurrences:
                return None
            owners = {aliases.get((row.entry_identity, build_id)) for row in record.occurrences}
            if None in owners or not owners:
                return None
            contexts = {row.context_signature for row in record.occurrences}
            context = str(issue.get("context_signature") or "")
            if not context or context not in contexts or context != record.context_signature:
                return None
        if len(owners) != 1:
            # A shared obligation cannot select the first entry's semantic
            # advisory. Keep it explicitly unvalidated until context splits.
            return None
        owner = next(iter(owners))
        if owner is None:
            return None
        return next((scope for scope in scopes if scope.identity == owner.identity), None)

    def _instance_validation_groups(
        self, pending: List[Dict[str, Any]]
    ) -> Tuple[List[Tuple[InstanceScope, List[Dict[str, Any]]]], List[Dict[str, Any]]]:
        grouped: Dict[str, Tuple[InstanceScope, List[Dict[str, Any]]]] = {}
        ungrouped: List[Dict[str, Any]] = []
        for issue in pending:
            scope = self._scope_for_pending_issue(issue)
            if scope is None:
                ungrouped.append(issue)
                continue
            grouped.setdefault(scope.identity, (scope, []))[1].append(issue)
        return [grouped[key] for key in sorted(grouped)], ungrouped

    def _bind_ablation_validator_policy(self, runner: Any) -> None:
        """Make the frozen winning Validator arm control the live queue."""

        override = self._benchmark_ablation_override
        if override is None or override.validator_selected_arm == "D":
            return
        if override.validator_selected_arm == "C":
            # Arm C keeps V1+V2 but cannot inherit balanced's V3 investigation.
            setattr(runner, "_assign_v3_investigation_budget", lambda prepared: prepared)
            return
        if override.validator_selected_arm == "B":
            # Arm B is the direct structured decision arm: no fact recheck or V3.
            setattr(
                runner,
                "_run_v3_evidence_recheck",
                lambda _item, _agent, val_data, _metadata: val_data,
            )
            setattr(runner, "_assign_v3_investigation_budget", lambda prepared: prepared)
            return
        raise DiscoveryAblationError(
            f"unsupported live ablation Validator arm: {override.validator_selected_arm}"
        )

    @staticmethod
    def _validator_v3_outcome_summary(issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate auditable fact-resolution and verdict transitions."""

        transitions: Dict[str, int] = {}
        fact_completed = 0
        fact_requested = 0
        for issue in issues:
            resolution = issue.get("validator_fact_resolution")
            if isinstance(resolution, dict):
                fact_requested += 1
                if str(resolution.get("status") or "").startswith("completed"):
                    fact_completed += 1
            history = issue.get("validator_pass_history")
            if not isinstance(history, list):
                continue
            normalized = [item for item in history if isinstance(item, dict)]
            for before, after in zip(normalized, normalized[1:]):
                key = "{before_pass}:{before_verdict}->{after_pass}:{after_verdict}".format(
                    before_pass=str(before.get("pass") or "unknown"),
                    before_verdict=str(before.get("verdict") or "unknown"),
                    after_pass=str(after.get("pass") or "unknown"),
                    after_verdict=str(after.get("verdict") or "unknown"),
                )
                transitions[key] = int(transitions.get(key, 0) or 0) + 1
        return {
            "validator_verdict_transitions": dict(sorted(transitions.items())),
            "validator_fact_request_count": fact_requested,
            "validator_fact_resolution_success_count": fact_completed,
            "validator_fact_resolution_success_rate": (
                round(fact_completed / fact_requested, 4) if fact_requested else None
            ),
        }

    @staticmethod
    def _scan_budget_metadata(
        *,
        duration_seconds: float,
        budget_seconds: Optional[float],
        policy: str,
    ) -> Dict[str, Any]:
        try:
            normalized_budget = float(budget_seconds) if budget_seconds is not None else None
        except (TypeError, ValueError):
            normalized_budget = None
        if normalized_budget is not None and normalized_budget <= 0:
            normalized_budget = None
        duration = max(0.0, float(duration_seconds or 0.0))
        exceeded = normalized_budget is not None and duration > normalized_budget
        overrun = max(0.0, duration - normalized_budget) if normalized_budget is not None else 0.0
        return {
            "scan_budget_seconds": normalized_budget,
            "scan_budget_exceeded": exceeded,
            "scan_budget_overrun_seconds": round(overrun, 3),
            "budget_exhaustion_policy": str(policy or "observe"),
        }

    def _run_global_modeling(self, entries: List[FunctionEntry]) -> bool:
        started = time.time()
        logger.info("[global-model] start entries=%d", len(entries))
        try:
            helper = Analyzer(
                self.base_config,
                semantic_result=self.semantic_result,
                reproduction_service=getattr(self, "reproduction_service", None),
                code_index=self.code_index,
                snapshot_store=self.snapshot_store,
                user_config=self.user_config,
                force_ignore_history=self.force_ignore_history,
                maintain_mode=self.maintain_mode,
                candidate_ledger=self._candidate_ledger,
                shared_local_pattern_semantics=self._shared_local_pattern_semantics,
                shared_semantic_overlay=self._shared_semantic_overlay,
                llm_clients=self._shared_llm_clients,
                validation_result_cache=self._validation_result_cache,
                cancellation_token=self._cancellation_token,
                scheduler=self._scheduler,
                decision_fact_cache=self._decision_fact_cache,
                write_root_reports=False,
                project_knowledge_service=self.project_knowledge_service,
            )
            modeler = GlobalModeler.from_analyzer_helpers(
                self.base_config,
                self.code_index,
                self.snapshot_store,
                self.user_config,
                llm_clients=self._shared_llm_clients,
                tools_factory=helper._get_tools,
                tool_policy_factory=helper._tool_policy_for_agent,
                attach_contract=helper._attach_agent_contract,
                scheduler=self._scheduler,
            )
            with bind_cancellation_token(self._cancellation_token):
                self._cancellation_token.raise_if_cancelled()
                stats = modeler.run(entries)
            self._last_global_model_stats = stats.to_dict()
            self.semantic_result = modeler.result
            logger.info(
                "[global-model] end entries=%d reachable=%d modeled=%d cache_hits=%d "
                "deterministic=%d llm=%d failed=%d unresolved_entries=%d "
                "reconciled=%d reconcile_failed=%d duration=%.2fs",
                len(entries),
                stats.reachable_functions,
                stats.modeled_functions,
                stats.cache_hit_functions,
                stats.deterministic_snapshot_count,
                stats.llm_snapshot_count,
                stats.failed_functions,
                stats.unresolved_entry_functions,
                stats.reconciled_functions,
                stats.reconciliation_failures,
                time.time() - started,
            )
            if not stats.stage_complete:
                logger.error(
                    "[global-model] continuing with partial semantics "
                    "failed=%d unresolved_entries=%d reconcile_failed=%d",
                    stats.failed_functions,
                    stats.unresolved_entry_functions,
                    stats.reconciliation_failures,
                )
                return False
            return True
        except CancellationError:
            raise
        except Exception as exc:
            self._last_global_model_stats = {"error": str(exc)}
            logger.exception("[global-model] failed before entry fan-out.")
            return False

    def _uses_scoped_fast_static_pass(self) -> bool:
        """All C/C++ modes share the exact-instance static foundation.

        The historical name/report key is retained for report compatibility;
        depth selects validation and discovery, never static coverage.
        """

        return bool(
            self.base_config.project.language != "java"
            and resolve_discovery_profile(self.base_config).name in {"fast", "balanced", "deep"}
        )

    @staticmethod
    def _fast_analysis_unit_id(*parts: str) -> str:
        material = json.dumps(
            ["zscope.fast-static-scan.v1", *[str(part or "") for part in parts]],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _fast_static_cache_root(self) -> Tuple[Optional[Path], str]:
        """Return a project-contained cache root without following symlinks.

        Cache availability is never evidence authority.  An unwritable or
        redirected cache therefore makes the run cold instead of weakening
        candidate identity or failing the scan.
        """

        try:
            root = Path(self.base_config.project.project_root).resolve()
            cursor = root
            for part in _FAST_STATIC_CACHE_DIRECTORY:
                cursor = cursor / part
                if cursor.exists() and cursor.is_symlink():
                    return None, "cache_path_symlink"
            cursor.mkdir(parents=True, exist_ok=True)
            resolved = cursor.resolve()
            resolved.relative_to(root)
            return resolved, ""
        except (OSError, RuntimeError, ValueError) as exc:
            return None, f"cache_root_unavailable:{type(exc).__name__}"

    def _fast_static_cache_identity(
        self,
        *,
        build_context_id: str,
        function_scope: InstanceScope,
        wrapper_context: Mapping[str, Any],
        build_context: Mapping[str, Any],
        semantic_overlay: Mapping[str, Any],
    ) -> str:
        effective = getattr(self.base_config, "effective_rules", None)
        provenance = getattr(effective, "provenance", None)
        payload = {
            "schema": _FAST_STATIC_CACHE_SCHEMA,
            "build_context_id": build_context_id,
            "usr": function_scope.usr,
            "source": function_scope.source,
            "function": wrapper_context.get("func_name"),
            "signature": wrapper_context.get("signature"),
            "start_line": wrapper_context.get("start_line"),
            "end_line": wrapper_context.get("end_line"),
            "source_text": wrapper_context.get("code"),
            # Program facts carry the current AST/CFG/type/macro/native input
            # receipts.  The context adds compiler, target, dependency and
            # native tool identity, so a different compile variant cannot hit.
            "program_facts": wrapper_context.get("program_facts"),
            "build_context": dict(build_context),
            "effective_rules_sha256": str(getattr(provenance, "effective_sha256", "") or ""),
            "runtime_analysis": vars(self.base_config.analysis),
            # Only the instance materialized overlay is authoritative here;
            # workbook/model proposals are not allowed into this fast path.
            "semantic_overlay": dict(semantic_overlay),
        }
        material = json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    @staticmethod
    def _read_fast_static_cache(
        path: Path,
        *,
        cache_key: str,
        build_context_id: str,
        unit_kind: str,
        unit_identity: str,
    ) -> Optional[List[Dict[str, Any]]]:
        try:
            if path.is_symlink() or not path.is_file():
                return None
            if path.stat().st_size > _FAST_STATIC_CACHE_MAX_BYTES:
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        if (
            payload.get("schema") != _FAST_STATIC_CACHE_SCHEMA
            or payload.get("cache_key") != cache_key
            or payload.get("build_context_id") != build_context_id
            or payload.get("unit_kind") != unit_kind
            or payload.get("unit_identity") != unit_identity
        ):
            return None
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or any(
            not isinstance(candidate, dict) for candidate in candidates
        ):
            return None
        return [deepcopy(candidate) for candidate in candidates]

    @staticmethod
    def _write_fast_static_cache(
        path: Path,
        *,
        cache_key: str,
        build_context_id: str,
        unit_kind: str,
        unit_identity: str,
        candidates: Sequence[Mapping[str, Any]],
    ) -> None:
        atomic_json(
            path,
            {
                "schema": _FAST_STATIC_CACHE_SCHEMA,
                "cache_key": cache_key,
                "build_context_id": build_context_id,
                "unit_kind": unit_kind,
                "unit_identity": unit_identity,
                "candidates": [deepcopy(dict(candidate)) for candidate in candidates],
            },
        )

    def _fast_static_graph_cache_identity(
        self,
        *,
        build_context_id: str,
        build_context: Mapping[str, Any],
        function_cache_keys: Sequence[str],
        semantic_overlay: Mapping[str, Any],
        link_receipts: Sequence[Mapping[str, Any]],
    ) -> str:
        effective = getattr(self.base_config, "effective_rules", None)
        provenance = getattr(effective, "provenance", None)
        payload = {
            "schema": _FAST_STATIC_CACHE_SCHEMA,
            "unit_kind": "graph",
            "build_context_id": build_context_id,
            "build_context": dict(build_context),
            "function_cache_keys": sorted(str(item) for item in function_cache_keys),
            "semantic_overlay": dict(semantic_overlay),
            "link_receipts": [dict(item) for item in link_receipts],
            "effective_rules_sha256": str(getattr(provenance, "effective_sha256", "") or ""),
            "runtime_analysis": vars(self.base_config.analysis),
        }
        material = json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _source_is_in_project(self, source: str) -> bool:
        if not source:
            return False
        try:
            root = Path(self.base_config.project.project_root).resolve()
            path = Path(source)
            if not path.is_absolute():
                path = root / path
            path.resolve().relative_to(root)
            return True
        except (OSError, ValueError, RuntimeError):
            return False

    def _fast_reachability_routes(
        self,
        scoped_entries: Sequence[Tuple[FunctionEntry, Optional[InstanceScope]]],
        function_names: Set[str],
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
        """Compute entry attribution without using it to drive discovery."""

        routes: Dict[str, List[Dict[str, Any]]] = {}
        unclosed_edges: List[Dict[str, Any]] = []
        project_body_cache: Dict[str, bool] = {}

        def has_project_body(function: str, file_hint: str = "") -> bool:
            if function in project_body_cache:
                return project_body_cache[function]
            try:
                query: Dict[str, Any] = {"max_lines": 1, "warn_missing": False}
                if file_hint:
                    query["file_path"] = file_hint
                impl = self.code_index.get_function_impl(function, **query)
            except Exception:
                impl = None
            result = bool(
                isinstance(impl, dict)
                and self._source_is_in_project(str(impl.get("file") or file_hint or ""))
            )
            project_body_cache[function] = result
            return result

        for entry, scope in scoped_entries:
            if scope is None:
                continue
            entry_identity = entry.identity_key(self.base_config.project.project_root)
            pending: List[Tuple[str, List[str]]] = [(entry.function_name, [entry.function_name])]
            seen: Set[str] = set()
            while pending:
                function, call_path = pending.pop(0)
                if function in seen:
                    continue
                seen.add(function)
                if function in function_names or has_project_body(function):
                    routes.setdefault(function, []).append(
                        {
                            "entry_identity": entry_identity,
                            "call_path": list(call_path),
                        }
                    )
                try:
                    # Navigation is project/link-group scoped.  A TU-scoped
                    # facade intentionally hides the very cross-TU edges that
                    # attribution is meant to follow.
                    callees = self.code_index.get_callees(function, limit=1_000_000)
                except Exception as exc:
                    unclosed_edges.append(
                        {
                            "entry_identity": entry_identity,
                            "caller": function,
                            "callee": "",
                            "reason": f"callee_query:{type(exc).__name__}: {exc}",
                        }
                    )
                    continue
                for row in callees or []:
                    if not isinstance(row, dict):
                        continue
                    callee = str(row.get("name") or row.get("callee_name") or "").strip()
                    if not callee or callee in call_path:
                        continue
                    if callee in function_names:
                        pending.append((callee, [*call_path, callee]))
                        continue
                    declared_file = str(row.get("filename") or row.get("file") or "")
                    if has_project_body(callee, declared_file):
                        pending.append((callee, [*call_path, callee]))
                        continue
                    if declared_file and self._source_is_in_project(declared_file):
                        unclosed_edges.append(
                            {
                                "entry_identity": entry_identity,
                                "caller": function,
                                "callee": callee,
                                "file": declared_file,
                                "reason": "project_edge_outside_translation_unit",
                            }
                        )
        for values in routes.values():
            values.sort(key=lambda row: (row["entry_identity"], row["call_path"]))
        unique_edges = {
            json.dumps(row, sort_keys=True, ensure_ascii=False): row for row in unclosed_edges
        }
        return routes, [unique_edges[key] for key in sorted(unique_edges)]

    def _fast_link_group_sccs(self, function_names: Set[str]) -> List[List[str]]:
        """Build the current link-group call graph and return stable SCCs."""

        adjacency: Dict[str, Set[str]] = {name: set() for name in function_names}
        for caller in sorted(function_names):
            try:
                rows = self.code_index.get_callees(caller, limit=1_000_000)
            except Exception:
                rows = []
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                callee = str(row.get("name") or row.get("callee_name") or "").strip()
                if callee in function_names:
                    adjacency[caller].add(callee)

        index = 0
        indices: Dict[str, int] = {}
        lowlinks: Dict[str, int] = {}
        stack: List[str] = []
        on_stack: Set[str] = set()
        components: List[List[str]] = []

        def visit(node: str) -> None:
            nonlocal index
            indices[node] = index
            lowlinks[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)
            for target in sorted(adjacency[node]):
                if target not in indices:
                    visit(target)
                    lowlinks[node] = min(lowlinks[node], lowlinks[target])
                elif target in on_stack:
                    lowlinks[node] = min(lowlinks[node], indices[target])
            if lowlinks[node] != indices[node]:
                return
            component: List[str] = []
            while stack:
                current = stack.pop()
                on_stack.remove(current)
                component.append(current)
                if current == node:
                    break
            components.append(sorted(component))

        for function in sorted(function_names):
            if function not in indices:
                visit(function)
        return sorted(components, key=lambda values: (values[0] if values else "", len(values)))

    @staticmethod
    def _project_link_group_semantics(
        *,
        target_id: str,
        member_build_context_ids: Sequence[str],
        base_semantics: LocalPatternSemantics,
        semantics_by_build: Sequence[LocalPatternSemantics],
    ) -> Tuple[LocalPatternSemantics, List[Dict[str, Any]]]:
        """Compile exact cross-TU effects for one closed native link record.

        A contract's ``build_context_id`` identifies the TU that proved the
        wrapper implementation; it is not the caller TU.  Within a real link
        record, an exact native USR can therefore be consumed by another
        member.  The projection is intentionally local to this graph unit and
        retains the USR, file and signature.  Unknown identities and contracts
        from any other build remain unavailable, so this never becomes a
        name-level or cross-variant grant.
        """

        members = {str(value) for value in member_build_context_ids if str(value)}
        projected = deepcopy(base_semantics)
        source_contracts = [
            contract
            for semantics in semantics_by_build
            for contract in semantics.contracts.contracts
            if str(contract.symbol.build_context_id or "")
        ]
        source_pairs = [
            pair
            for semantics in semantics_by_build
            for pair in semantics.contracts.pairs
            if str(pair.acquire.build_context_id or "") or str(pair.release.build_context_id or "")
        ]
        # Retain the base TU's system/name-level catalog and shadow decisions,
        # but replace every build-scoped contract with its exact-USR link-local
        # projection.  Keeping both forms would make the same symbol appear as
        # two identities while the base BuildContext is bound.
        projected.contracts.contracts = [
            contract
            for contract in projected.contracts.contracts
            if not str(contract.symbol.build_context_id or "")
        ]
        projected.contracts.pairs = [
            pair
            for pair in projected.contracts.pairs
            if not str(pair.acquire.build_context_id or "")
            and not str(pair.release.build_context_id or "")
        ]
        records: List[Dict[str, Any]] = []

        def project_symbol(symbol: Any) -> Any:
            build_id = str(getattr(symbol, "build_context_id", "") or "")
            if not build_id:
                return symbol
            if build_id not in members or not str(getattr(symbol, "usr", "") or ""):
                return None
            return replace(symbol, build_context_id="")

        for contract in source_contracts:
            symbol = project_symbol(contract.symbol)
            if symbol is None:
                continue
            pair_symbols = []
            invalid_pair = False
            for pair_symbol in contract.pairs:
                value = project_symbol(pair_symbol)
                if value is None:
                    invalid_pair = True
                    break
                pair_symbols.append(value)
            if invalid_pair:
                continue
            verification = dict(contract.verification or {})
            original_build = str(contract.symbol.build_context_id or "")
            if original_build:
                verification.update(
                    {
                        "link_group_projection": "closed_exact_usr",
                        "link_group_id": target_id,
                        "definition_build_context_id": original_build,
                    }
                )
            value = replace(
                contract,
                symbol=symbol,
                pairs=tuple(pair_symbols),
                verification=verification,
            )
            projected.contracts.add(value)
            projected.add_api(contract.role, symbol.name, contract.source)
            if original_build:
                records.append(
                    {
                        "link_group_id": target_id,
                        "definition_build_context_id": original_build,
                        "name": symbol.name,
                        "usr": symbol.usr,
                        "role": contract.role,
                    }
                )

        for pair in source_pairs:
            acquire = project_symbol(pair.acquire)
            release = project_symbol(pair.release)
            if acquire is None or release is None:
                continue
            value = replace(pair, acquire=acquire, release=release)
            if value not in projected.contracts.pairs:
                projected.contracts.pairs.append(value)
        return projected, records

    @staticmethod
    def _compile_fast_native_wrapper_contracts(
        *,
        build_context_id: str,
        semantics: LocalPatternSemantics,
        overlay: Dict[str, Any],
        functions: Sequence[
            Tuple[
                InstanceScope,
                Dict[str, Any],
                Dict[str, Any],
                str,
                FunctionFactSummary,
            ]
        ],
    ) -> Dict[str, Any]:
        """Publish only current native-proven wrapper effects for this build.

        The existing native wrapper checker is deliberately narrow (direct C
        heap adapters with complete program facts).  Running it to a fixed
        point lets wrappers call already-proven wrappers without granting any
        authority to a name, workbook inference, or model proposal.
        """

        from ..semantics.contracts import ApiContract, digest
        from ..semantics.native_wrappers import infer_native_wrapper

        accepted: Set[str] = set()
        rejected_identities: Dict[str, Dict[str, Any]] = {}
        authorized_identities: Dict[str, Dict[str, Any]] = {}
        passes = 0
        for _ in range(max(1, len(functions))):
            passes += 1
            changed = False
            for scope, _impl, context, unit_id, _fact_summary in functions:
                try:
                    inference = infer_native_wrapper(context, semantics.contracts)
                except Exception as exc:
                    reason = f"compiler_error:{type(exc).__name__}"
                    identity = f"{build_context_id}:{scope.usr}"
                    rejected_identities[identity] = {
                        "analysis_unit_id": unit_id,
                        "build_context_id": build_context_id,
                        "usr": scope.usr,
                        "function": str(context.get("func_name") or ""),
                        "file": str(context.get("file_path") or scope.source or ""),
                        "reasons": [reason],
                    }
                    continue
                if not inference["attempted"]:
                    continue
                if inference["reasons"]:
                    identity = f"{build_context_id}:{scope.usr}"
                    reasons = sorted({str(value) for value in inference["reasons"] if value})
                    rejected_identities[identity] = {
                        "analysis_unit_id": unit_id,
                        "build_context_id": build_context_id,
                        "usr": scope.usr,
                        "function": str(context.get("func_name") or ""),
                        "file": str(context.get("file_path") or scope.source or ""),
                        "reasons": reasons,
                    }
                native_rows = []
                for row in inference["contracts"]:
                    if not isinstance(row, dict):
                        continue
                    symbol = row.get("symbol")
                    if isinstance(symbol, dict) and not symbol.get("usr"):
                        row = dict(row, symbol={**symbol, "usr": scope.usr})
                    verification = row.get("verification")
                    verification = verification if isinstance(verification, dict) else {}
                    if verification.get("checker") != "native_wrapper_value_flow.v2":
                        continue
                    contract = ApiContract.from_row({"contract": row})
                    if contract is None:
                        identity = f"{build_context_id}:{scope.usr}"
                        rejected_identities[identity] = {
                            "analysis_unit_id": unit_id,
                            "build_context_id": build_context_id,
                            "usr": scope.usr,
                            "function": str(context.get("func_name") or ""),
                            "file": str(context.get("file_path") or scope.source or ""),
                            "reasons": ["contract_decode_failed"],
                        }
                        continue
                    evidence = contract.evidence if isinstance(contract.evidence, list) else []
                    exact_receipt = any(
                        isinstance(item, dict)
                        and str(item.get("function_usr") or "") == scope.usr
                        and str(item.get("build_context_id") or "") == build_context_id
                        and bool(item.get("native_input_hash"))
                        for item in evidence
                    )
                    if (
                        contract.symbol.build_context_id != build_context_id
                        or contract.symbol.usr != scope.usr
                        or not exact_receipt
                        or not contract.effects_trusted
                    ):
                        identity = f"{build_context_id}:{scope.usr}"
                        rejected_identities[identity] = {
                            "analysis_unit_id": unit_id,
                            "build_context_id": build_context_id,
                            "usr": scope.usr,
                            "function": str(context.get("func_name") or ""),
                            "file": str(context.get("file_path") or scope.source or ""),
                            "reasons": ["native_receipt_not_exact"],
                        }
                        continue
                    # Structurally equivalent wrappers remain distinct native
                    # authorities.  For example ``_safe_malloc`` and
                    # ``_str_dup`` are both allocator contracts, but consumers
                    # must be authorized against the exact wrapper USR in the
                    # current BuildContext.
                    native_rows.append((contract, f"{scope.usr}:{digest(contract.structural())}"))
                for contract, identity in native_rows:
                    if identity in accepted:
                        continue
                    semantics.contracts.add(contract)
                    semantics.add_api(contract.role, contract.symbol.name, contract.source)
                    accepted.add(identity)
                    wrapper_identity = f"{build_context_id}:{scope.usr}"
                    authorized_identities[wrapper_identity] = {
                        "analysis_unit_id": unit_id,
                        "build_context_id": build_context_id,
                        "usr": scope.usr,
                        "function": str(context.get("func_name") or ""),
                        "file": str(context.get("file_path") or scope.source or ""),
                        "role": contract.role,
                    }
                    rejected_identities.pop(wrapper_identity, None)
                    changed = True
            if not changed:
                break
        overlay["contract_version"] = semantics.contracts.version
        overlay["api_contracts"] = [
            contract.to_dict() for contract in semantics.contracts.contracts
        ]
        overlay["api_pairs"] = [pair.to_dict() for pair in semantics.contracts.pairs]
        rejected_by_reason: Dict[str, int] = {}
        for record in rejected_identities.values():
            for reason in record.get("reasons") or []:
                rejected_by_reason[str(reason)] = rejected_by_reason.get(str(reason), 0) + 1
        return {
            "authorized": len(authorized_identities),
            "authorized_identities": list(authorized_identities.values()),
            "rejected_by_reason": dict(sorted(rejected_by_reason.items())),
            "rejected_identities": list(rejected_identities.values()),
            "fixed_point_passes": passes,
        }

    def _run_scoped_fast_static_pass(
        self,
        scoped_entries: Sequence[Tuple[FunctionEntry, Optional[InstanceScope]]],
    ) -> None:
        """Collect C/C++ fast candidates once per exact function instance.

        Discovery is buffered and becomes authoritative only after every local
        function and graph unit completes.  A real failure therefore falls
        back atomically to the existing per-entry collectors; successful
        entry workflows are attribution/report-only and cannot repeat the
        static work.
        """

        started = time.monotonic()
        state: Dict[str, Any] = {
            "schema": "zscope.fast-static-scan.v1",
            "cache_schema": _FAST_STATIC_CACHE_SCHEMA,
            "enabled": True,
            "activated": False,
            "status": "running",
            "unique_function_instances": 0,
            "local_analysis_executions": 0,
            "local_engine_executions": {
                "cpp_clang_cfg": 0,
                "cpp_regex": 0,
                "cpp_graph_view": 0,
                "cpp_clang_matcher": 0,
                "extension_provider": 0,
            },
            "duplicate_local_executions": 0,
            "unique_graph_units": 0,
            "graph_analysis_units": 0,
            "backend_analysis_units": 0,
            "link_group_graph_units": 0,
            "link_group_scc_count": 0,
            "analysis_units": [],
            "planned_build_contexts": [],
            "completed_build_contexts": [],
            "link_coverage": {
                "observed_targets": [],
                "covered_build_contexts": [],
                "uncovered_build_contexts": [],
                "unclosed_edges": [],
            },
            "backend_health": {
                "degraded": False,
                "degraded_units": [],
                "by_build_context": {},
            },
            "semantic_authorization": {
                "authorized": 0,
                "authorized_identities": [],
                "rejected_by_reason": {},
                "rejected_identities": [],
                "project_contracts_authorized": 0,
                "project_authorized_identities": [],
                "by_build_context": {},
                "wrapper_contracts_authorized": 0,
                "wrapper_authorized_identities": [],
                "wrapper_rejected_by_reason": {},
                "wrapper_rejected_identities": [],
                "wrapper_fixed_point_passes": 0,
                "link_group_projected_contracts": 0,
                "link_group_projected_identities": [],
            },
            "candidate_funnel": {
                "raw": 0,
                "dedup": 0,
                "v0": 0,
                "llm": 0,
                "confirmed": 0,
                "rejected": 0,
                "needs_review": 0,
            },
            "cache": {
                "status": "initializing",
                "cold_misses": 0,
                "hot_hits": 0,
                "local_cold_misses": 0,
                "local_hot_hits": 0,
                "graph_cold_misses": 0,
                "graph_hot_hits": 0,
                "invalid_entries": 0,
                "write_failures": 0,
                "reused_candidate_count": 0,
            },
            "rule_execution": {
                "executed_functions": 0,
                "executed_by_rule": {},
                "cache_reused_by_rule": {},
                "emitted_by_rule": {},
                "skipped_with_reason": {},
                "declared_fact_prerequisites": {},
            },
            "validation_obligations": builtin_obligation_coverage(),
            "planning_gaps": [
                dict(item)
                for item in (getattr(self, "_fast_project_scope_gaps", []) or [])
                if isinstance(item, dict)
            ],
            "failures": [],
            "unsupported_capabilities": [],
            "semantic_catalog": {},
            "project_semantics": {},
            "timings_seconds": {},
        }
        self._fast_static_scan_state = state
        effective_rules = self.base_config.effective_rules
        state["rule_execution"]["declared_fact_prerequisites"] = {
            rule_state.descriptor.id: list(rule_state.descriptor.required_capabilities)
            for rule_state in effective_rules.rules
            if rule_state.state == "enabled"
        }
        cache_root, cache_reason = self._fast_static_cache_root()
        if cache_root is None:
            state["cache"]["status"] = "unavailable"
            state["cache"]["reason"] = cache_reason
        else:
            state["cache"]["status"] = "enabled"
        self._cancellation_token.raise_if_cancelled()
        by_build: Dict[str, List[Tuple[FunctionEntry, InstanceScope]]] = {}
        for entry, scope in scoped_entries:
            if scope is not None:
                by_build.setdefault(scope.build_context_id, []).append((entry, scope))
        representatives: Dict[str, InstanceScope] = {
            build_id: rows[0][1] for build_id, rows in by_build.items() if rows
        }
        semantics_context = getattr(self, "_instance_semantics_context", None)
        for scope in list(getattr(semantics_context, "scopes", {}).values()):
            if isinstance(scope, InstanceScope) and scope.build_context_id:
                representatives.setdefault(scope.build_context_id, scope)
                existing = self._instance_scopes_by_build.setdefault(scope.build_context_id, [])
                if all(item.identity != scope.identity for item in existing):
                    existing.append(scope)
        buffered: List[Tuple[Analyzer, Dict[str, Any], List[Dict[str, Any]]]] = []
        seen_units: Set[str] = set()
        project_routes: Dict[str, List[Dict[str, Any]]] = {}
        all_builds = set(getattr(self, "_fast_project_build_context_ids", []) or representatives)
        state["planned_build_contexts"] = sorted(all_builds)

        # Freeze the two semantic authorities into the scan report before any
        # candidate is emitted.  The project document is already immutable in
        # InstanceSemanticsContext; parsing these canonical bytes cannot race a
        # reviewer edit.  Catalog completeness is an additive gate and never
        # inferred from the number of call sites seen in this run.
        from ..config.project_semantics import EFFECT_CONSUMERS, semantics_readiness
        from ..semantics.c_linux_catalog import catalog_audit, classified_names

        catalog = catalog_audit()
        state["semantic_catalog"] = {
            key: deepcopy(value) for key, value in catalog.items() if key != "records"
        }
        state["semantic_catalog"].setdefault(
            "classified_interfaces", len(catalog.get("records") or [])
        )
        state["semantic_catalog"]["observed_unclassified_system_interfaces"] = []
        state["semantic_catalog"]["complete"] = not any(
            catalog.get(key)
            for key in (
                "active_missing_abi",
                "active_missing_source",
                "active_missing_consumer",
                "unaudited",
            )
        )
        catalog_classified_names = classified_names()
        observed_system_interfaces: Set[str] = set()
        if semantics_context is not None:
            project_document = json.loads(bytes(semantics_context.effective_project_document))
            readiness = semantics_readiness(
                project_document,
                project_root=Path(self.base_config.project.project_root),
            )
            rebind_audit = dict(semantics_context.project_semantics_rebind)
            reviewed_contracts: List[Dict[str, Any]] = []
            for row in project_document.get("interfaces", []) or []:
                if not isinstance(row, dict) or row.get("status") != "confirmed":
                    continue
                reviewed_contracts.append(
                    {
                        "id": str(row.get("id") or ""),
                        "primitive": bool(row.get("primitive")),
                        "basis": str(row.get("basis") or ""),
                        "selector": deepcopy(row.get("selector") or {}),
                        "effects": [
                            {
                                "role": str(effect.get("role") or ""),
                                "consumer_adapters": list(
                                    EFFECT_CONSUMERS.get(str(effect.get("role") or ""), ())
                                ),
                            }
                            for effect in row.get("effects", []) or []
                            if isinstance(effect, dict)
                        ],
                    }
                )
            state["project_semantics"] = {
                **readiness.to_dict(),
                "ready": readiness.ready and bool(rebind_audit.get("ready")),
                "path": str(semantics_context.workbook_path),
                "sha256": str(semantics_context.workbook.workbook_sha256),
                "current_rebind": rebind_audit,
                "confirmed_contracts": reviewed_contracts,
                "automatic_by_build": {
                    build: {
                        "schema": data.get("schema"),
                        "contracts": len(data.get("contracts", [])),
                        "units": data.get("units", []),
                        "inventory_gaps": data.get("inventory_gaps", []),
                        "linked_imports": data.get("linked_imports", 0),
                        "link_gaps": data.get("link_gaps", []),
                        "derivation_attempts": data.get("derivation_attempts", 0),
                        "llm_calls": 0,
                        "complete_coverage_proven": False,
                    }
                    for build, data in {
                        snapshot.scope.build_context_id: json.loads(
                            bytes(snapshot.effect_payload)
                        ).get("automatic_derivation", {})
                        for snapshot in semantics_context.snapshots.values()
                    }.items()
                },
                "dispatchers": {
                    status: sum(
                        1
                        for row in project_document.get("dispatchers", []) or []
                        if isinstance(row, dict) and row.get("status") == status
                    )
                    for status in ("pending", "confirmed", "rejected", "stale")
                },
                "function_pointer_bindings": {
                    status: sum(
                        1
                        for row in project_document.get("function_pointer_bindings", []) or []
                        if isinstance(row, dict) and row.get("status") == status
                    )
                    for status in ("pending", "confirmed", "rejected", "stale")
                },
            }

        # Link records remain the only cross-TU ownership authority.  Graph
        # view and batch rules are delegated to one real link-group unit when
        # the record closes over every current member.  Unlinked builds retain
        # one exact TU graph unit; they are also reported as a qualification
        # gap rather than being promoted to a fabricated project graph.
        covered_builds: Set[str] = set()
        link_receipts_by_build: Dict[str, List[Dict[str, Any]]] = {}
        link_groups: List[Dict[str, Any]] = []
        try:
            linked_factory = getattr(self.code_index, "linked_targets", None)
            linked = linked_factory() if callable(linked_factory) else None
            for target in list(getattr(linked, "targets", []) or []):
                if not isinstance(target, dict):
                    continue
                raw_receipt = target.get("receipt")
                receipt: Dict[str, Any] = dict(raw_receipt) if isinstance(raw_receipt, dict) else {}
                target_id = str(receipt.get("target_id") or "")
                if target_id:
                    state["link_coverage"]["observed_targets"].append(target_id)
                target_members = {str(item) for item in (target.get("members") or []) if item}
                covered_builds.update(target_members)
                if target_members:
                    link_groups.append(
                        {
                            "target_id": target_id or f"link-target-{len(link_groups) + 1}",
                            "members": sorted(target_members),
                            "receipt": receipt,
                        }
                    )
                for member in target_members:
                    link_receipts_by_build.setdefault(member, []).append(
                        {
                            "receipt": receipt,
                            "members": sorted(target_members),
                        }
                    )
        except Exception as exc:
            state["link_coverage"]["diagnostic"] = f"{type(exc).__name__}: {exc}"
        state["link_coverage"]["covered_build_contexts"] = sorted(all_builds & covered_builds)
        state["link_coverage"]["uncovered_build_contexts"] = sorted(all_builds - covered_builds)
        linked_graph_builds = {
            str(member)
            for group in link_groups
            if len(group.get("members") or []) > 1
            and set(str(value) for value in group.get("members") or []).issubset(representatives)
            for member in group.get("members") or []
        }
        build_runtime: Dict[str, Dict[str, Any]] = {}

        for build_context_id in sorted(representatives):
            self._cancellation_token.raise_if_cancelled()
            build_started = time.monotonic()
            entries_for_build = by_build.get(build_context_id, [])
            representative_scope = representatives[build_context_id]
            if entries_for_build:
                representative_entry = entries_for_build[0][0]
                representative_identity = representative_entry.identity_key(
                    self.base_config.project.project_root
                )
            else:
                representative_entry = FunctionEntry(
                    str((representative_scope.function_names or (representative_scope.usr,))[0]),
                    file_path=representative_scope.source or None,
                )
                representative_identity = f"__project_static__:{build_context_id}"
            try:
                snapshot = self._frozen_instance_semantic_snapshot(representative_scope)
                semantics, overlay = materialize_effect_semantics(snapshot)
                scoped_index = wrap_scoped_code_index(self.code_index, representative_scope)
                build_contexts = list(scoped_index.get_build_contexts() or [])
                if len(build_contexts) != 1:
                    raise RuntimeError("scoped_build_context_missing_or_ambiguous")
                build_context = dict(build_contexts[0])
                inventory_getter = getattr(scoped_index, "list_function_instances", None)
                function_scopes = (
                    list(inventory_getter() or []) if callable(inventory_getter) else []
                )
                # The scheduled entry itself is always a real instance even if
                # an older third-party facade cannot enumerate the whole TU.
                # ``EntryInstance.identity`` is a report/navigation identity
                # and may use a different textual key than the native
                # inventory.  The execution identity is exactly
                # ``(BuildContext, USR)``; keying by the display identity (or
                # source spelling) would execute one function twice.
                inventory = {
                    (scope.build_context_id, scope.usr): scope
                    for scope in function_scopes
                    if scope.build_context_id and scope.usr
                }
                for _entry, scope in entries_for_build:
                    inventory.setdefault((scope.build_context_id, scope.usr), scope)
                project_scopes = [
                    scope
                    for scope in inventory.values()
                    if self._source_is_in_project(scope.source)
                ]
                project_scopes.sort(key=lambda scope: (scope.source, scope.usr, scope.identity))
                if not project_scopes:
                    raise RuntimeError("scoped_function_inventory_empty")
                validation_scopes = self._instance_scopes_by_build.setdefault(build_context_id, [])
                known_validation_scope_ids = {scope.identity for scope in validation_scopes}
                for function_scope in project_scopes:
                    if function_scope.identity not in known_validation_scope_ids:
                        validation_scopes.append(function_scope)
                        known_validation_scope_ids.add(function_scope.identity)

                helper = self._instance_validation_helper(representative_scope)
                origins = overlay.get("symbol_origins") if isinstance(overlay, dict) else {}
                if isinstance(origins, dict):
                    for symbol_identity, reason in origins.items():
                        text_reason = str(reason or "")
                        if text_reason == ORIGIN_SYSTEM_RECEIPT:
                            state["semantic_authorization"]["authorized"] += 1
                            state["semantic_authorization"]["authorized_identities"].append(
                                {
                                    "build_context_id": build_context_id,
                                    "symbol_identity": str(symbol_identity),
                                    "origin": text_reason,
                                }
                            )
                        else:
                            rejected = state["semantic_authorization"]["rejected_by_reason"]
                            rejected[text_reason or "unknown"] = (
                                rejected.get(text_reason or "unknown", 0) + 1
                            )
                            state["semantic_authorization"]["rejected_identities"].append(
                                {
                                    "build_context_id": build_context_id,
                                    "symbol_identity": str(symbol_identity),
                                    "reason": text_reason or "unknown",
                                }
                            )
                raw_project_contract_rows = (
                    overlay.get("project_contracts", []) if isinstance(overlay, dict) else []
                )
                project_contract_rows = (
                    raw_project_contract_rows if isinstance(raw_project_contract_rows, list) else []
                )
                for project_contract in project_contract_rows:
                    if not isinstance(project_contract, dict):
                        continue
                    raw_symbol = project_contract.get("symbol")
                    symbol = raw_symbol if isinstance(raw_symbol, dict) else {}
                    raw_verification = project_contract.get("verification")
                    verification = raw_verification if isinstance(raw_verification, dict) else {}
                    state["semantic_authorization"]["project_authorized_identities"].append(
                        {
                            "build_context_id": build_context_id,
                            "project_semantics_id": str(
                                verification.get("project_semantics_id") or ""
                            ),
                            "name": str(symbol.get("name") or ""),
                            "usr": str(symbol.get("usr") or ""),
                            "role": str(project_contract.get("role") or ""),
                            "authority": str(verification.get("authority") or ""),
                        }
                    )

                function_names = {
                    str(scope.function_names[0])
                    for scope in project_scopes
                    if scope.function_names and str(scope.function_names[0])
                }
                discovered_routes, unclosed = self._fast_reachability_routes(
                    [(entry, scope) for entry, scope in entries_for_build],
                    function_names,
                )
                for function, rows in discovered_routes.items():
                    current = project_routes.setdefault(function, [])
                    known = {json.dumps(row, sort_keys=True, ensure_ascii=False) for row in current}
                    for row in rows:
                        identity = json.dumps(row, sort_keys=True, ensure_ascii=False)
                        if identity not in known:
                            current.append(dict(row))
                            known.add(identity)
                routes = {
                    function: list(project_routes.get(function) or [])
                    for function in function_names
                }
                state["link_coverage"]["unclosed_edges"].extend(unclosed)
                raw_for_build: List[Dict[str, Any]] = []

                local_started = time.monotonic()
                function_work: List[
                    Tuple[
                        InstanceScope,
                        Dict[str, Any],
                        Dict[str, Any],
                        str,
                        FunctionFactSummary,
                    ]
                ] = []
                source_cache: Dict[Path, str] = {}
                for function_scope in project_scopes:
                    unit_id = self._fast_analysis_unit_id(build_context_id, function_scope.usr)
                    if unit_id in seen_units:
                        state["duplicate_local_executions"] += 1
                        continue
                    seen_units.add(unit_id)
                    function = str(
                        (function_scope.function_names or (representative_entry.function_name,))[0]
                    )
                    function_index = wrap_scoped_code_index(self.code_index, function_scope)
                    program_facts = function_index.get_function_program_facts(
                        function_scope.usr,
                        function_scope.source,
                        build_context_id=build_context_id,
                    )
                    bodies = (
                        [
                            value
                            for value in program_facts.get("functions", []) or []
                            if isinstance(value, Mapping)
                        ]
                        if isinstance(program_facts, Mapping)
                        else []
                    )
                    exact_bodies = []
                    for body in bodies:
                        owner_value = body.get("owner")
                        owner = owner_value if isinstance(owner_value, Mapping) else {}
                        if str(owner.get("usr") or "") == function_scope.usr:
                            exact_bodies.append(body)
                    if (
                        not isinstance(program_facts, Mapping)
                        or program_facts.get("complete") is not True
                        or len(exact_bodies) != 1
                        or exact_bodies[0].get("complete") is not True
                    ):
                        reason = str(
                            (
                                program_facts.get("reason")
                                if isinstance(program_facts, Mapping)
                                else ""
                            )
                            or "program_facts_incomplete"
                        )
                        state["analysis_units"].append(
                            {
                                "schema_version": "zscope.function-fact-summary.v1",
                                "analysis_unit_id": unit_id,
                                "build_context_id": build_context_id,
                                "usr": function_scope.usr,
                                "function": function,
                                "file": function_scope.source,
                                "execution_status": "skipped_with_reason",
                                "skip_reason": reason,
                                "candidate_count": 0,
                                "executed_rule_ids": [],
                            }
                        )
                        state["planning_gaps"].append(
                            {
                                "build_context_id": build_context_id,
                                "analysis_unit_id": unit_id,
                                "usr": function_scope.usr,
                                "reason": reason,
                            }
                        )
                        continue
                    body = exact_bodies[0]
                    owner_value = body.get("owner")
                    owner = owner_value if isinstance(owner_value, Mapping) else {}
                    callable_value = body.get("callable")
                    callable_row = callable_value if isinstance(callable_value, Mapping) else {}
                    code, start_line, end_line = function_source_fragment(
                        body, source_cache=source_cache
                    )
                    if not code.strip():
                        state["analysis_units"].append(
                            {
                                "schema_version": "zscope.function-fact-summary.v1",
                                "analysis_unit_id": unit_id,
                                "build_context_id": build_context_id,
                                "usr": function_scope.usr,
                                "function": function,
                                "file": str(owner.get("file") or function_scope.source),
                                "execution_status": "skipped_with_reason",
                                "skip_reason": "function_source_unavailable",
                                "candidate_count": 0,
                                "executed_rule_ids": [],
                            }
                        )
                        state["planning_gaps"].append(
                            {
                                "build_context_id": build_context_id,
                                "analysis_unit_id": unit_id,
                                "usr": function_scope.usr,
                                "reason": "function_source_unavailable",
                            }
                        )
                        continue
                    native_name = str(owner.get("name") or function)
                    source_file = str(owner.get("file") or function_scope.source)
                    numbered_code = numbered_source_fragment(code, start_line=start_line)
                    impl = {
                        "func_name": native_name,
                        "index_name": native_name,
                        "file": source_file,
                        "signature": str(
                            callable_row.get("canonical_signature")
                            or callable_row.get("signature")
                            or ""
                        ),
                        "code": numbered_code,
                        "start_line": start_line,
                        "end_line": end_line,
                        "is_static": not bool(callable_row.get("external_linkage", True)),
                        "is_macro": False,
                        "truncated": False,
                        "source_authority": "native_program_function",
                    }
                    if isinstance(program_facts, Mapping):
                        for native_function in program_facts.get("functions", []) or []:
                            if not isinstance(native_function, Mapping):
                                continue
                            for event in native_function.get("events", []) or []:
                                if not isinstance(event, Mapping):
                                    continue
                                callee = event.get("callee")
                                if (
                                    not isinstance(callee, Mapping)
                                    or callee.get("is_system_header") is not True
                                ):
                                    continue
                                system_name = str(
                                    callee.get("name") or callee.get("qualified_name") or ""
                                ).strip()
                                if system_name:
                                    observed_system_interfaces.add(system_name)
                    fact_summary = FunctionFactSummary.create(
                        analysis_unit_id=unit_id,
                        build_context_id=build_context_id,
                        usr=function_scope.usr,
                        function=function,
                        file_path=str(impl.get("file") or function_scope.source),
                        source=code,
                        program_facts=(program_facts if isinstance(program_facts, Mapping) else {}),
                    )
                    wrapper_context = {
                        "func_name": function,
                        "index_name": str(impl.get("index_name") or function),
                        "file_path": str(impl.get("file") or function_scope.source),
                        "start_line": _integer_or_zero(impl.get("start_line")),
                        "end_line": _integer_or_zero(impl.get("end_line")),
                        "signature": str(impl.get("signature") or ""),
                        "is_static": bool(impl.get("is_static")),
                        "is_macro": False,
                        "code": str(impl.get("code") or ""),
                        "project_root": str(self.base_config.project.project_root),
                        "build_context_id": build_context_id,
                        "program_facts": program_facts,
                    }
                    function_work.append(
                        (function_scope, impl, wrapper_context, unit_id, fact_summary)
                    )
                    state["analysis_units"].append(
                        {
                            **fact_summary.manifest(),
                            "execution_status": "planned",
                            "candidate_count": 0,
                            "executed_rule_ids": [],
                        }
                    )

                wrapper_summary = self._compile_fast_native_wrapper_contracts(
                    build_context_id=build_context_id,
                    semantics=semantics,
                    overlay=overlay,
                    functions=function_work,
                )
                semantic_state = state["semantic_authorization"]
                semantic_state["wrapper_contracts_authorized"] += int(wrapper_summary["authorized"])
                semantic_state["wrapper_authorized_identities"].extend(
                    dict(value)
                    for value in wrapper_summary.get("authorized_identities") or []
                    if isinstance(value, dict)
                )
                semantic_state["wrapper_fixed_point_passes"] += int(
                    wrapper_summary["fixed_point_passes"]
                )
                wrapper_rejected = semantic_state["wrapper_rejected_by_reason"]
                for reason, count in wrapper_summary["rejected_by_reason"].items():
                    wrapper_rejected[reason] = wrapper_rejected.get(reason, 0) + int(count)
                semantic_state["wrapper_rejected_identities"].extend(
                    dict(value)
                    for value in wrapper_summary.get("rejected_identities") or []
                    if isinstance(value, dict)
                )

                graph_view_builder = GraphCandidateGenerator(
                    scoped_index,
                    semantics,
                    semantic_overlay=overlay,
                    rule_policy=self.base_config.effective_rules.policy,
                    restrict_to_semantics=True,
                )
                prepared_graph_views: List[Tuple[Any, Dict[str, Any]]] = []
                for function_scope, impl, _context, _unit_id, fact_summary in function_work:
                    function = str(
                        (function_scope.function_names or (representative_entry.function_name,))[0]
                    )
                    exact_facts = fact_summary.facts_copy()
                    view = graph_view_builder.prepare_function_view(
                        function,
                        impl,
                        program_facts=exact_facts,
                    )
                    if view is None:
                        raise RuntimeError(f"graph_view_unavailable:{function_scope.identity}")
                    prepared_graph_views.append((view, exact_facts))

                build_runtime[build_context_id] = {
                    "function_work": function_work,
                    "helper": helper,
                    "semantics": semantics,
                    "overlay": overlay,
                    "function_names": set(function_names),
                    "function_scopes": {
                        str((scope.function_names or ("",))[0]): scope
                        for scope in project_scopes
                        if str((scope.function_names or ("",))[0])
                    },
                    "representative_scope": representative_scope,
                    "representative_identity": representative_identity,
                    "function_cache_keys": [],
                    "prepared_graph_views": prepared_graph_views,
                }

                function_cache_keys: List[str] = []
                unit_manifest = {
                    str(row.get("analysis_unit_id") or ""): row
                    for row in state["analysis_units"]
                    if isinstance(row, dict)
                }
                local_rule_ids = sorted(
                    rule_state.descriptor.id
                    for rule_state in effective_rules.rules
                    if rule_state.state == "enabled"
                    and rule_state.descriptor.engine
                    in {"cpp_regex", "cpp_clang_cfg", "cpp_clang_matcher"}
                )
                for (
                    function_scope,
                    impl,
                    _wrapper_context,
                    unit_id,
                    fact_summary,
                ) in function_work:
                    self._cancellation_token.raise_if_cancelled()
                    function = str(
                        (function_scope.function_names or (representative_entry.function_name,))[0]
                    )
                    cache_key = self._fast_static_cache_identity(
                        build_context_id=build_context_id,
                        function_scope=function_scope,
                        wrapper_context=_wrapper_context,
                        build_context=build_context,
                        semantic_overlay=overlay,
                    )
                    cache_path = cache_root / f"{cache_key}.json" if cache_root else None
                    function_cache_keys.append(cache_key)
                    build_runtime[build_context_id]["function_cache_keys"].append(cache_key)
                    findings = (
                        self._read_fast_static_cache(
                            cache_path,
                            cache_key=cache_key,
                            build_context_id=build_context_id,
                            unit_kind="function",
                            unit_identity=function_scope.usr,
                        )
                        if cache_path is not None
                        else None
                    )
                    cache_hit = findings is not None
                    semantic_contract_events: List[Dict[str, Any]] = []
                    semantic_contract_references: List[Dict[str, Any]] = []
                    semantic_contract_trace_status = "unavailable"
                    if findings is None:
                        if cache_path is not None and cache_path.exists():
                            state["cache"]["invalid_entries"] += 1
                        generator = ClangAstCfgCandidateGenerator(
                            program_facts_provider=(
                                lambda *_args, _summary=fact_summary, **_kwargs: (
                                    _summary.facts_copy()
                                )
                            ),
                            semantics=semantics,
                            semantic_overlay=overlay,
                            tooling_evidence_provider=helper._clang_tooling_evidence_for,
                            rule_policy=self.base_config.effective_rules.policy,
                            restrict_to_semantics=True,
                        )
                        findings = generator.generate_issues(
                            function,
                            str(impl.get("code") or ""),
                            str(impl.get("file") or function_scope.source),
                            allowed_skills=None,
                        )
                        # Fast owns one project-level function analysis unit,
                        # but that unit must execute every enabled local
                        # deterministic engine.  Historically the telemetry
                        # declared cpp_regex rules as executed while this path
                        # only ran the Clang CFG facade, which silently dropped
                        # several high-signal pre-MR checks (double free,
                        # recursive lookup under a held lock, stale fd, ...).
                        regex_generator = RegexCandidateGenerator(
                            program_facts_provider=(
                                lambda *_args, _summary=fact_summary, **_kwargs: (
                                    _summary.facts_copy()
                                )
                            ),
                            semantics=semantics,
                            rule_policy=self.base_config.effective_rules.policy,
                            restrict_to_semantics=True,
                        )
                        findings.extend(
                            regex_generator.generate_issues(
                                function,
                                str(impl.get("code") or ""),
                                str(impl.get("file") or function_scope.source),
                                allowed_skills=None,
                            )
                        )
                        state["local_engine_executions"]["cpp_clang_cfg"] += 1
                        state["local_engine_executions"]["cpp_regex"] += 1
                        semantic_contract_events = _semantic_contract_observation_rows(
                            generator.last_semantic_events
                        )
                        semantic_contract_references = _semantic_contract_reference_rows(
                            _wrapper_context, semantics.contracts
                        )
                        semantic_contract_trace_status = _semantic_contract_trace_status(
                            _wrapper_context, semantics.contracts
                        )
                        findings.extend(
                            clang_native_matcher_candidates_from_program_facts(
                                function,
                                str(impl.get("file") or function_scope.source),
                                fact_summary.facts_copy(),
                                semantics,
                                rule_policy=self.base_config.effective_rules.policy,
                            )
                        )
                        findings.extend(
                            helper._clang_tooling_matcher_candidates_from_evidence(
                                function,
                                str(impl.get("file") or function_scope.source),
                                helper._clang_tooling_evidence_for(
                                    func_name=function,
                                    file_path=str(impl.get("file") or function_scope.source),
                                    start_line=_integer_or_zero(impl.get("start_line")),
                                    end_line=_integer_or_zero(impl.get("end_line")),
                                ),
                                rule_policy=self.base_config.effective_rules.policy,
                            )
                        )
                        state["local_engine_executions"]["cpp_clang_matcher"] += 1
                        extension_state = {
                            "entry_func": function,
                            "entry_identity": representative_identity,
                            "impl_result": impl,
                            "engine_capabilities": {},
                            "failed_deterministic_work": [],
                        }
                        findings.extend(helper._detect_extension_rule_candidates(extension_state))
                        state["local_engine_executions"]["extension_provider"] += 1
                        findings = helper._apply_candidate_validation_budget(
                            dedupe_rule_candidates(findings)
                        )
                        state["cache"]["cold_misses"] += 1
                        state["cache"]["local_cold_misses"] += 1
                        state["local_analysis_executions"] += 1
                        state["rule_execution"]["executed_functions"] += 1
                        if cache_path is not None:
                            try:
                                self._write_fast_static_cache(
                                    cache_path,
                                    cache_key=cache_key,
                                    build_context_id=build_context_id,
                                    unit_kind="function",
                                    unit_identity=function_scope.usr,
                                    candidates=findings,
                                )
                            except (OSError, TypeError, ValueError):
                                state["cache"]["write_failures"] += 1
                    else:
                        state["cache"]["hot_hits"] += 1
                        state["cache"]["local_hot_hits"] += 1
                        state["cache"]["reused_candidate_count"] += len(findings)
                        try:
                            semantic_contract_events = _semantic_contract_observation_rows(
                                semantics.contracts.trace_calls(_wrapper_context)
                            )
                            semantic_contract_references = _semantic_contract_reference_rows(
                                _wrapper_context, semantics.contracts
                            )
                            semantic_contract_trace_status = _semantic_contract_trace_status(
                                _wrapper_context, semantics.contracts
                            )
                        except (KeyError, TypeError, ValueError) as exc:
                            semantic_contract_trace_status = f"unavailable:{type(exc).__name__}"
                    manifest = unit_manifest.get(unit_id)
                    if manifest is not None:
                        manifest["execution_status"] = "cache_reused" if cache_hit else "executed"
                        manifest["candidate_count"] = len(findings)
                        manifest["executed_rule_ids"] = list(local_rule_ids)
                        manifest["semantic_contract_trace_status"] = semantic_contract_trace_status
                        manifest["semantic_contract_events"] = semantic_contract_events
                        manifest["semantic_contract_references"] = semantic_contract_references
                    if not cache_hit:
                        executed = state["rule_execution"]["executed_by_rule"]
                        for rule_state in effective_rules.rules:
                            if rule_state.state != "enabled":
                                continue
                            if rule_state.descriptor.engine not in {
                                "cpp_regex",
                                "cpp_clang_cfg",
                                "cpp_clang_matcher",
                            }:
                                continue
                            rule_id = rule_state.descriptor.id
                            executed[rule_id] = executed.get(rule_id, 0) + 1
                    else:
                        reused = state["rule_execution"]["cache_reused_by_rule"]
                        for rule_state in effective_rules.rules:
                            if rule_state.state != "enabled":
                                continue
                            if rule_state.descriptor.engine not in {
                                "cpp_regex",
                                "cpp_clang_cfg",
                                "cpp_clang_matcher",
                            }:
                                continue
                            rule_id = rule_state.descriptor.id
                            reused[rule_id] = reused.get(rule_id, 0) + 1
                    attribution = list(routes.get(function) or [])
                    reachability: Dict[str, Any] = {
                        "status": "reachable" if attribution else "unknown",
                        "reachable": True if attribution else None,
                        "entries": sorted({str(row["entry_identity"]) for row in attribution}),
                        "call_paths": [list(row["call_path"]) for row in attribution],
                    }
                    if not attribution:
                        reachability["coverage_gap"] = "entry_path_not_closed_in_current_graph"
                    for issue in findings:
                        issue["build_context_id"] = build_context_id
                        issue["analysis_unit_id"] = unit_id
                        # Validation must reopen the exact function instance
                        # that produced the candidate. Binding every issue to
                        # the build's representative entry made other source
                        # files and anonymous-namespace functions impossible
                        # to resolve despite current native facts.
                        issue["validation_scope_identity"] = function_scope.identity
                        issue["reachability_attribution"] = reachability
                        issue["entry_identity"] = (
                            reachability["entries"][0]
                            if reachability["entries"]
                            else representative_identity
                        )
                        issue["call_path"] = (
                            list(reachability["call_paths"][0])
                            if reachability["call_paths"]
                            else []
                        )
                        issue["fast_static_scan_v1"] = True
                    annotated = helper._annotate_candidate_issues(
                        findings,
                        checker=helper._local_candidate_checker(),
                        path_kind="fast_project_function_static",
                    )
                    raw_for_build.extend(annotated)
                state["timings_seconds"][f"{build_context_id}:local"] = round(
                    time.monotonic() - local_started, 4
                )

                graph_started = time.monotonic()
                graph_unit_id = self._fast_analysis_unit_id(build_context_id, "graph")
                graph_delegated = build_context_id in linked_graph_builds
                graph_cache_key = self._fast_static_graph_cache_identity(
                    build_context_id=build_context_id,
                    build_context=build_context,
                    function_cache_keys=function_cache_keys,
                    semantic_overlay=overlay,
                    link_receipts=link_receipts_by_build.get(build_context_id, ()),
                )
                graph_cache_path = (
                    cache_root / f"graph-{graph_cache_key}.json" if cache_root else None
                )
                graph_findings = (
                    []
                    if graph_delegated
                    else (
                        self._read_fast_static_cache(
                            graph_cache_path,
                            cache_key=graph_cache_key,
                            build_context_id=build_context_id,
                            unit_kind="graph",
                            unit_identity=graph_unit_id,
                        )
                        if graph_cache_path is not None
                        else None
                    )
                )
                graph_cache_hit = not graph_delegated and graph_findings is not None
                if graph_findings is None:
                    if graph_cache_path is not None and graph_cache_path.exists():
                        state["cache"]["invalid_entries"] += 1
                    graph_generator = GraphCandidateGenerator(
                        scoped_index,
                        semantics,
                        semantic_overlay=overlay,
                        rule_policy=self.base_config.effective_rules.policy,
                        restrict_to_semantics=True,
                    )
                    graph_findings = graph_generator.generate_for_prepared_views(
                        build_runtime[build_context_id]["prepared_graph_views"],
                        include_view_rules=True,
                        include_batch_rules=True,
                    )
                    graph_findings = dedupe_rule_candidates(graph_findings)
                    state["graph_analysis_units"] += 1
                    state["cache"]["cold_misses"] += 1
                    state["cache"]["graph_cold_misses"] += 1
                    if graph_cache_path is not None:
                        try:
                            self._write_fast_static_cache(
                                graph_cache_path,
                                cache_key=graph_cache_key,
                                build_context_id=build_context_id,
                                unit_kind="graph",
                                unit_identity=graph_unit_id,
                                candidates=graph_findings,
                            )
                        except (OSError, TypeError, ValueError):
                            state["cache"]["write_failures"] += 1
                else:
                    state["cache"]["hot_hits"] += 1
                    state["cache"]["graph_hot_hits"] += 1
                    state["cache"]["reused_candidate_count"] += len(graph_findings)
                all_routes = [
                    row for function in sorted(routes) for row in routes.get(function, [])
                ]
                graph_reachability: Dict[str, Any] = {
                    "status": "reachable" if all_routes else "unknown",
                    "reachable": True if all_routes else None,
                    "entries": sorted({str(row["entry_identity"]) for row in all_routes}),
                    "call_paths": [list(row["call_path"]) for row in all_routes],
                }
                if not all_routes:
                    graph_reachability["coverage_gap"] = "entry_path_not_closed_in_current_graph"
                if not graph_delegated:
                    state["unique_graph_units"] += 1
                    for issue in graph_findings:
                        issue["build_context_id"] = build_context_id
                        issue["analysis_unit_id"] = graph_unit_id
                        issue["validation_scope_identity"] = representative_scope.identity
                        issue["reachability_attribution"] = graph_reachability
                        issue["entry_identity"] = representative_identity
                        issue["fast_static_scan_v1"] = True
                    raw_for_build.extend(
                        helper._annotate_candidate_issues(
                            graph_findings,
                            checker=helper._graph_candidate_checker(),
                            path_kind="fast_project_graph_static",
                        )
                    )
                    graph_rule_counter = state["rule_execution"][
                        "cache_reused_by_rule" if graph_cache_hit else "executed_by_rule"
                    ]
                    graph_rule_ids: List[str] = []
                    for rule_state in effective_rules.rules:
                        if (
                            rule_state.state == "enabled"
                            and rule_state.descriptor.engine == "cpp_graph"
                        ):
                            rule_id = rule_state.descriptor.id
                            graph_rule_ids.append(rule_id)
                            graph_rule_counter[rule_id] = graph_rule_counter.get(rule_id, 0) + 1
                    state["analysis_units"].append(
                        {
                            "analysis_unit_id": graph_unit_id,
                            "build_context_id": build_context_id,
                            "usr": "",
                            "file": str(representative_scope.source or ""),
                            "function": "__translation_unit_graph__",
                            "execution_status": ("cache_reused" if graph_cache_hit else "executed"),
                            "candidate_count": len(graph_findings),
                            "executed_rule_ids": sorted(graph_rule_ids),
                        }
                    )
                state["timings_seconds"][f"{build_context_id}:graph"] = round(
                    time.monotonic() - graph_started, 4
                )

                backend_started = time.monotonic()
                backend_state = {
                    "entry_func": representative_entry.function_name,
                    "entry_identity": representative_identity,
                    "impl_result": {},
                    "engine_capabilities": {},
                    "failed_deterministic_work": [],
                }
                backend_findings = helper._detect_instance_backend_signals(
                    backend_state,
                    entry_func=representative_entry.function_name,
                    reachable_funcs=set(function_names),
                )
                backend_unit_id = self._fast_analysis_unit_id(build_context_id, "backend")
                for issue in backend_findings:
                    issue["build_context_id"] = build_context_id
                    issue["analysis_unit_id"] = backend_unit_id
                    issue["validation_scope_identity"] = representative_scope.identity
                    issue["reachability_attribution"] = graph_reachability
                    issue["entry_identity"] = representative_identity
                    issue["fast_static_scan_v1"] = True
                raw_for_build.extend(
                    helper._annotate_candidate_issues(
                        dedupe_rule_candidates(backend_findings),
                        checker=helper._backend_signal_checker(),
                        path_kind="fast_project_backend_static",
                    )
                )
                state["backend_analysis_units"] += 1
                state["analysis_units"].append(
                    {
                        "analysis_unit_id": backend_unit_id,
                        "build_context_id": build_context_id,
                        "usr": "",
                        "file": str(representative_scope.source or ""),
                        "function": "__backend_signals__",
                        "execution_status": "executed",
                        "candidate_count": len(backend_findings),
                        "executed_rule_ids": sorted(
                            {
                                str(issue.get("rule_id") or issue.get("rule") or "")
                                for issue in backend_findings
                                if str(issue.get("rule_id") or issue.get("rule") or "")
                            }
                        ),
                    }
                )
                state["timings_seconds"][f"{build_context_id}:backend"] = round(
                    time.monotonic() - backend_started, 4
                )
                capabilities = helper._engine_capabilities()
                degraded_units: List[Dict[str, Any]] = []
                for name, details in capabilities.items():
                    if not isinstance(details, dict):
                        continue
                    capability_status = str(details.get("status") or "").lower()
                    detail = str(details.get("detail") or "").lower()
                    degraded = capability_status in {
                        "partial",
                        "degraded",
                        "failed",
                        "interrupted",
                        "unavailable",
                        "fallback",
                    }
                    # A scoped SVF exclusion is a declared coverage gap when
                    # the producer did not return an exact instance result.
                    if (
                        name == "svf_taint_query"
                        and capability_status == "excluded"
                        and detail
                        and not detail.startswith("complete:")
                    ):
                        degraded = True
                    if degraded:
                        degraded_units.append(
                            {
                                "engine": str(name),
                                "status": capability_status or "unknown",
                                "reason": str(details.get("reason") or ""),
                                "detail": str(details.get("detail") or ""),
                            }
                        )
                state["backend_health"]["by_build_context"][build_context_id] = {
                    "degraded": bool(degraded_units),
                    "units": degraded_units,
                }
                state["backend_health"]["degraded_units"].extend(
                    {"build_context_id": build_context_id, **item} for item in degraded_units
                )
                state["backend_health"]["degraded"] = bool(
                    state["backend_health"]["degraded_units"]
                )

                state["candidate_funnel"]["raw"] += len(raw_for_build)
                merged = merge_unified_evidence_candidates(
                    raw_for_build,
                    enabled=helper._candidate_backend_profile() == "unified",
                )
                merged = dedupe_rule_candidates(merged)
                state["candidate_funnel"]["dedup"] += len(merged)
                emitted = state["rule_execution"]["emitted_by_rule"]
                for issue in merged:
                    rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
                    if rule_id:
                        emitted[rule_id] = emitted.get(rule_id, 0) + 1
                buffered.append(
                    (
                        helper,
                        {
                            "candidate_ledger": self._candidate_ledger,
                            "entry_identity": representative_identity,
                            "run_id": self.run_id,
                        },
                        merged,
                    )
                )
                state["timings_seconds"][f"{build_context_id}:total"] = round(
                    time.monotonic() - build_started, 4
                )
                state["completed_build_contexts"].append(build_context_id)
            except CancellationError:
                raise
            except Exception as exc:
                logger.exception(
                    "[fast-static] build context %s failed; entry discovery will be restored",
                    build_context_id,
                )
                state["failures"].append(
                    {
                        "build_context_id": build_context_id,
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )

        # A final executable link is not always available for pre-MR library
        # scans.  Preserve that formal coverage gap, but still join the one
        # narrow lifecycle shape whose source identities are independently
        # exact: a C++ ``new`` factory feeds a returned aggregate member, a
        # constructor stores the aggregate, and the matching destructor omits
        # that member while cleaning a sibling.  Do not run the general graph
        # suite here; every other cross-TU rule remains link-record gated.
        unlinked_started = time.monotonic()
        prepared_occurrences: Dict[
            Tuple[str, str, str],
            List[Tuple[str, Any, Mapping[str, Any], InstanceScope]],
        ] = {}
        for runtime_build_id, runtime in build_runtime.items():
            if runtime_build_id in linked_graph_builds:
                continue
            scopes_by_name = runtime.get("function_scopes") or {}
            for view, facts in runtime.get("prepared_graph_views") or []:
                scope = scopes_by_name.get(str(view.name))
                if not isinstance(scope, InstanceScope):
                    continue
                occurrence_key = (str(view.name), str(view.file_path), str(view.signature))
                prepared_occurrences.setdefault(occurrence_key, []).append(
                    (runtime_build_id, view, facts, scope)
                )
        # The same source/signature appearing in multiple BuildContexts is a
        # variant ambiguity, not a wildcard.  Exclude it rather than mixing
        # evidence across compiler variants.
        unique_unlinked = [
            rows[0] for rows in prepared_occurrences.values() if len(rows) == 1
        ]
        if unique_unlinked:
            first_build = unique_unlinked[0][0]
            first_runtime = build_runtime[first_build]
            project_graph = GraphCandidateGenerator(
                wrap_scoped_code_index(
                    self.code_index,
                    first_runtime["representative_scope"],
                ),
                first_runtime["semantics"],
                semantic_overlay=first_runtime["overlay"],
                rule_policy=self.base_config.effective_rules.policy,
                restrict_to_semantics=True,
            )
            project_findings = project_graph.generate_unlinked_factory_cleanup_candidates(
                [(view, facts) for _build, view, facts, _scope in unique_unlinked]
            )
            unlinked_owners = {
                (str(view.name), str(view.file_path)): (build, scope)
                for build, view, _facts, scope in unique_unlinked
            }
            project_unit_id = self._fast_analysis_unit_id(
                "project-unlinked", "factory-member-lifecycle"
            )
            annotated_project: List[Dict[str, Any]] = []
            for issue in project_findings:
                sink_owner = unlinked_owners.get(
                    (str(issue.get("function") or ""), str(issue.get("file_path") or ""))
                )
                if sink_owner is None:
                    location_file = str(issue.get("location") or "").rsplit(":", 1)[0]
                    sink_owner = unlinked_owners.get(
                        (str(issue.get("function") or ""), location_file)
                    )
                if sink_owner is None:
                    continue
                sink_build, sink_scope = sink_owner
                runtime = build_runtime[sink_build]
                helper = runtime["helper"]
                evidence_pack = issue.get("evidence_pack")
                if isinstance(evidence_pack, dict):
                    path = evidence_pack.get("path")
                    path = path if isinstance(path, dict) else {}
                    participating = []
                    for key in (
                        "factory_function",
                        "constructor_function",
                        "destructor_function",
                    ):
                        function_name = str(path.get(key) or "")
                        matches = [
                            {
                                "function": function_name,
                                "build_context_id": build,
                                "usr": scope.usr,
                                "file": str(view.file_path),
                            }
                            for build, view, _facts, scope in unique_unlinked
                            if str(view.name) == function_name
                        ]
                        participating.extend(matches)
                    evidence_pack["cross_build_contexts"] = participating
                    evidence_pack["linkage"] = {
                        "status": "unverified",
                        "reason": "final_link_record_missing",
                        "formal_proof": False,
                        "source_identities_exact": True,
                    }
                issue["build_context_id"] = sink_build
                issue["analysis_unit_id"] = project_unit_id
                issue["validation_scope_identity"] = sink_scope.identity
                issue["reachability_attribution"] = {
                    "status": "unknown",
                    "reachable": None,
                    "entries": [],
                    "call_paths": [],
                    "coverage_gap": "final_link_record_missing",
                }
                issue["entry_identity"] = runtime["representative_identity"]
                issue["fast_static_scan_v1"] = True
                issue["unlinked_project_observation"] = True
                annotated_project.extend(
                    helper._annotate_candidate_issues(
                        [issue],
                        checker=helper._graph_candidate_checker(),
                        path_kind="fast_project_unlinked_factory_lifecycle",
                    )
                )
            project_candidates = dedupe_rule_candidates(annotated_project)
            if project_candidates:
                sink_build = str(project_candidates[0].get("build_context_id") or "")
                runtime = build_runtime[sink_build]
                state["candidate_funnel"]["raw"] += len(annotated_project)
                state["candidate_funnel"]["dedup"] += len(project_candidates)
                emitted = state["rule_execution"]["emitted_by_rule"]
                for issue in project_candidates:
                    rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
                    if rule_id:
                        emitted[rule_id] = emitted.get(rule_id, 0) + 1
                buffered.append(
                    (
                        runtime["helper"],
                        {
                            "candidate_ledger": self._candidate_ledger,
                            "entry_identity": runtime["representative_identity"],
                            "run_id": self.run_id,
                        },
                        project_candidates,
                    )
                )
            state["graph_analysis_units"] += 1
            state["unique_graph_units"] += 1
            executed = state["rule_execution"]["executed_by_rule"]
            executed["paired_free_wrapper_omits_dynamic_member"] = (
                executed.get("paired_free_wrapper_omits_dynamic_member", 0) + 1
            )
            state["analysis_units"].append(
                {
                    "analysis_unit_id": project_unit_id,
                    "build_context_id": "project-unlinked",
                    "usr": "",
                    "file": "",
                    "function": "__unlinked_factory_member_lifecycle__",
                    "execution_status": "executed",
                    "candidate_count": len(project_findings),
                    "executed_rule_ids": ["paired_free_wrapper_omits_dynamic_member"],
                    "coverage_gap": "final_link_record_missing",
                }
            )
        state["timings_seconds"]["project-unlinked:factory-member-lifecycle"] = round(
            time.monotonic() - unlinked_started, 4
        )

        # Cross-TU graph rules run once for each real link record.  Function
        # facts remain owned by their exact BuildContext; the link unit only
        # provides the call/SCC neighborhood in which those facts interact.
        for link_group in link_groups:
            members = [
                str(value)
                for value in link_group.get("members") or []
                if str(value) in build_runtime
            ]
            if len(members) <= 1:
                continue
            target_id = str(link_group.get("target_id") or "")
            missing_members = sorted(
                set(str(value) for value in link_group.get("members") or []) - set(members)
            )
            if missing_members:
                state["unsupported_capabilities"].append(
                    {
                        "target_id": target_id,
                        "reason": "link_group_member_runtime_missing",
                        "members": missing_members,
                    }
                )
                continue
            owners: Dict[str, List[str]] = {}
            for member in members:
                for function in build_runtime[member]["function_names"]:
                    owners.setdefault(str(function), []).append(member)
            ambiguous = {
                function: sorted(values) for function, values in owners.items() if len(values) != 1
            }
            if ambiguous:
                state["unsupported_capabilities"].append(
                    {
                        "target_id": target_id,
                        "reason": "link_group_function_identity_ambiguous",
                        "function_count": len(ambiguous),
                        "functions": ambiguous,
                    }
                )
                continue
            function_names = set(owners)
            group_started = time.monotonic()
            sccs = self._fast_link_group_sccs(function_names)
            state["link_group_scc_count"] += len(sccs)
            first_runtime = build_runtime[members[0]]
            graph_unit_id = self._fast_analysis_unit_id("link-group", target_id)
            group_build_id = f"link-group:{target_id}"
            group_cache_key = self._fast_static_graph_cache_identity(
                build_context_id=group_build_id,
                build_context={
                    "target_id": target_id,
                    "members": members,
                    "sccs": sccs,
                },
                function_cache_keys=[
                    str(value)
                    for member in members
                    for value in build_runtime[member]["function_cache_keys"]
                ],
                semantic_overlay=first_runtime["overlay"],
                link_receipts=[
                    {
                        "receipt": dict(link_group.get("receipt") or {}),
                        "members": members,
                    }
                ],
            )
            group_cache_path = (
                cache_root / f"link-graph-{group_cache_key}.json" if cache_root else None
            )
            prepared_group_views: List[Tuple[Any, Dict[str, Any]]] = [
                prepared
                for member in members
                for prepared in build_runtime[member]["prepared_graph_views"]
            ]
            semantics_by_build = [build_runtime[member]["semantics"] for member in members]
            link_semantics_by_member: Dict[str, LocalPatternSemantics] = {}
            projected_contracts: List[Dict[str, Any]] = []
            for member in members:
                member_semantics, member_projections = self._project_link_group_semantics(
                    target_id=target_id,
                    member_build_context_ids=members,
                    base_semantics=build_runtime[member]["semantics"],
                    semantics_by_build=semantics_by_build,
                )
                link_semantics_by_member[member] = member_semantics
                projected_contracts.extend(member_projections)
            state["semantic_authorization"]["link_group_projected_contracts"] += len(
                projected_contracts
            )
            state["semantic_authorization"]["link_group_projected_identities"].extend(
                projected_contracts
            )
            try:
                group_findings = (
                    self._read_fast_static_cache(
                        group_cache_path,
                        cache_key=group_cache_key,
                        build_context_id=group_build_id,
                        unit_kind="link_group_graph",
                        unit_identity=graph_unit_id,
                    )
                    if group_cache_path is not None
                    else None
                )
                cache_hit = group_findings is not None
                if group_findings is None:
                    group_findings = []
                    # Every function view is evaluated once, using its TU's
                    # system-header/shadow decisions plus exact-USR contracts
                    # projected from this closed link group.  All views remain
                    # available in ``by_name`` for cross-TU relationships.
                    for member in members:
                        member_runtime = build_runtime[member]
                        member_generator = GraphCandidateGenerator(
                            self.code_index,
                            link_semantics_by_member[member],
                            semantic_overlay=member_runtime["overlay"],
                            rule_policy=self.base_config.effective_rules.policy,
                            restrict_to_semantics=True,
                        )
                        group_findings.extend(
                            member_generator.generate_for_prepared_views(
                                prepared_group_views,
                                include_view_rules=True,
                                include_batch_rules=False,
                                view_rule_names=member_runtime["function_names"],
                            )
                        )
                    # Batch detectors execute once over the complete link
                    # group.  The first member provides the target's system
                    # catalog; exact project contracts are link-projected.
                    link_generator = GraphCandidateGenerator(
                        self.code_index,
                        link_semantics_by_member[members[0]],
                        semantic_overlay=first_runtime["overlay"],
                        rule_policy=self.base_config.effective_rules.policy,
                        restrict_to_semantics=True,
                    )
                    group_findings.extend(
                        link_generator.generate_for_prepared_views(
                            prepared_group_views,
                            include_view_rules=False,
                            include_batch_rules=True,
                        )
                    )
                    group_findings = dedupe_rule_candidates(group_findings)
                    for issue in group_findings:
                        function = str(
                            issue.get("function")
                            or issue.get("function_name")
                            or issue.get("func_name")
                            or ""
                        )
                        owner_build_id = owners.get(function, [""])[0]
                        runtime = build_runtime.get(owner_build_id) or first_runtime
                        scope = runtime["function_scopes"].get(function)
                        issue["build_context_id"] = owner_build_id
                        issue["analysis_unit_id"] = graph_unit_id
                        issue["link_group_id"] = target_id
                        issue["link_group_scc"] = next(
                            (component for component in sccs if function in component),
                            [function],
                        )
                        issue["validation_scope_identity"] = (
                            scope.identity
                            if isinstance(scope, InstanceScope)
                            else runtime["representative_scope"].identity
                        )
                        attribution = list(project_routes.get(function) or [])
                        issue["reachability_attribution"] = {
                            "status": "reachable" if attribution else "unknown",
                            "reachable": True if attribution else None,
                            "entries": sorted({str(row["entry_identity"]) for row in attribution}),
                            "call_paths": [list(row["call_path"]) for row in attribution],
                        }
                        if not attribution:
                            issue["reachability_attribution"][
                                "coverage_gap"
                            ] = "entry_path_not_closed_in_current_graph"
                        issue["fast_static_scan_v1"] = True
                    if group_cache_path is not None:
                        self._write_fast_static_cache(
                            group_cache_path,
                            cache_key=group_cache_key,
                            build_context_id=group_build_id,
                            unit_kind="link_group_graph",
                            unit_identity=graph_unit_id,
                            candidates=group_findings,
                        )
                    state["cache"]["cold_misses"] += 1
                    state["cache"]["graph_cold_misses"] += 1
                    state["graph_analysis_units"] += 1
                else:
                    state["cache"]["hot_hits"] += 1
                    state["cache"]["graph_hot_hits"] += 1
                    state["cache"]["reused_candidate_count"] += len(group_findings)
                state["unique_graph_units"] += 1
                state["link_group_graph_units"] += 1
                graph_rule_counter = state["rule_execution"][
                    "cache_reused_by_rule" if cache_hit else "executed_by_rule"
                ]
                graph_rule_ids = sorted(
                    rule_state.descriptor.id
                    for rule_state in effective_rules.rules
                    if rule_state.state == "enabled" and rule_state.descriptor.engine == "cpp_graph"
                )
                for rule_id in graph_rule_ids:
                    graph_rule_counter[rule_id] = graph_rule_counter.get(rule_id, 0) + 1
                state["analysis_units"].append(
                    {
                        "analysis_unit_id": graph_unit_id,
                        "build_context_id": group_build_id,
                        "usr": "",
                        "file": "",
                        "function": f"link-group:{target_id}",
                        "execution_status": "cache_reused" if cache_hit else "executed",
                        "candidate_count": len(group_findings),
                        "executed_rule_ids": graph_rule_ids,
                        "member_build_context_ids": members,
                        "scc_count": len(sccs),
                    }
                )
                grouped_findings: Dict[str, List[Dict[str, Any]]] = {}
                for issue in group_findings:
                    grouped_findings.setdefault(
                        str(issue.get("build_context_id") or ""), []
                    ).append(issue)
                state["candidate_funnel"]["raw"] += len(group_findings)
                for owner_build_id, findings in grouped_findings.items():
                    owner_runtime = build_runtime.get(owner_build_id)
                    if owner_runtime is None:
                        continue
                    annotated = owner_runtime["helper"]._annotate_candidate_issues(
                        findings,
                        checker=owner_runtime["helper"]._graph_candidate_checker(),
                        path_kind="fast_link_group_graph_static",
                    )
                    deduped = dedupe_rule_candidates(annotated)
                    state["candidate_funnel"]["dedup"] += len(deduped)
                    buffered.append(
                        (
                            owner_runtime["helper"],
                            {
                                "candidate_ledger": self._candidate_ledger,
                                "entry_identity": owner_runtime["representative_identity"],
                                "run_id": self.run_id,
                            },
                            deduped,
                        )
                    )
                state["timings_seconds"][f"link-group:{target_id}:graph"] = round(
                    time.monotonic() - group_started,
                    4,
                )
            except CancellationError:
                raise
            except Exception as exc:
                state["failures"].append(
                    {
                        "link_group_id": target_id,
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )

        self._cancellation_token.raise_if_cancelled()
        state["link_coverage"]["observed_targets"] = sorted(
            set(state["link_coverage"]["observed_targets"])
        )
        # Earlier per-TU routing cannot know that a callee is owned by another
        # member of the same real link record.  Close those edges only after
        # every exact BuildContext inventory is available.  A symbol absent
        # from all inventories is retained only when the current index can
        # still prove that its definition belongs to this project; ordinary
        # system calls (for example GetLastError) are not project gaps.
        all_project_functions = {
            str(function)
            for runtime in build_runtime.values()
            for function in runtime.get("function_names") or []
            if str(function)
        }
        genuinely_unclosed: List[Dict[str, Any]] = []
        for row in state["link_coverage"]["unclosed_edges"]:
            if not isinstance(row, dict):
                continue
            callee = str(row.get("callee") or "")
            if callee in all_project_functions:
                continue
            try:
                unresolved_impl = (
                    self.code_index.get_function_impl(
                        callee,
                        max_lines=1,
                        warn_missing=False,
                    )
                    if callee
                    else None
                )
            except Exception:
                genuinely_unclosed.append(row)
                continue
            if isinstance(unresolved_impl, dict) and self._source_is_in_project(
                str(unresolved_impl.get("file") or "")
            ):
                genuinely_unclosed.append(row)
        state["link_coverage"]["unclosed_edges"] = [
            json.loads(key)
            for key in sorted(
                {
                    json.dumps(row, sort_keys=True, ensure_ascii=False)
                    for row in genuinely_unclosed
                    if isinstance(row, dict)
                }
            )
        ]
        state["analysis_units"] = sorted(
            state["analysis_units"],
            key=lambda row: (
                str(row.get("build_context_id") or ""),
                str(row.get("analysis_unit_id") or ""),
            ),
        )
        state["unique_function_instances"] = len(seen_units)
        state["semantic_catalog"]["observed_system_interfaces"] = sorted(observed_system_interfaces)
        state["semantic_catalog"]["observed_unclassified_system_interfaces"] = sorted(
            observed_system_interfaces - catalog_classified_names
        )
        state["semantic_catalog"]["complete"] = bool(
            state["semantic_catalog"].get("complete")
            and not state["semantic_catalog"]["observed_unclassified_system_interfaces"]
        )
        authorization = state["semantic_authorization"]
        for key in (
            "authorized_identities",
            "rejected_identities",
            "project_authorized_identities",
            "wrapper_authorized_identities",
            "wrapper_rejected_identities",
            "link_group_projected_identities",
        ):
            identities = {
                json.dumps(value, sort_keys=True, ensure_ascii=False): dict(value)
                for value in authorization.get(key) or []
                if isinstance(value, dict)
            }
            authorization[key] = [identities[value] for value in sorted(identities)]
        authorization["link_group_projected_contracts"] = len(
            authorization["link_group_projected_identities"]
        )
        # Counts are identities, not repeated call sites or fixed-point passes.
        authorization["authorized"] = len(authorization["authorized_identities"])
        authorization["wrapper_contracts_authorized"] = len(
            authorization["wrapper_authorized_identities"]
        )
        authorization["project_contracts_authorized"] = len(
            authorization["project_authorized_identities"]
        )
        build_authorization: Dict[str, Dict[str, int]] = {}
        for kind, rows in (
            ("builtin_authorized", authorization["authorized_identities"]),
            ("builtin_rejected", authorization["rejected_identities"]),
            ("project_authorized", authorization["project_authorized_identities"]),
            ("derived_wrapper_authorized", authorization["wrapper_authorized_identities"]),
            ("derived_wrapper_rejected", authorization["wrapper_rejected_identities"]),
        ):
            for row in rows:
                build = str(row.get("build_context_id") or "unknown")
                bucket = build_authorization.setdefault(build, {})
                bucket[kind] = bucket.get(kind, 0) + 1
        authorization["by_build_context"] = {
            build: dict(sorted(values.items()))
            for build, values in sorted(build_authorization.items())
        }
        if state["cache"]["status"] != "unavailable":
            hits = int(state["cache"]["hot_hits"] or 0)
            misses = int(state["cache"]["cold_misses"] or 0)
            state["cache"]["status"] = (
                "hot" if hits and not misses else "mixed" if hits and misses else "cold"
            )
        executed_rules = state["rule_execution"]["executed_by_rule"]
        reused_rules = state["rule_execution"]["cache_reused_by_rule"]
        skipped_rules = state["rule_execution"]["skipped_with_reason"]
        for rule_state in effective_rules.rules:
            if rule_state.state != "enabled":
                continue
            rule_id = rule_state.descriptor.id
            if rule_id in executed_rules or rule_id in reused_rules:
                continue
            skipped_rules[rule_id] = (
                "analysis_unit_failed" if state["failures"] else "no_applicable_analysis_unit"
            )
        if state["failures"]:
            state["status"] = "fallback_to_entry_discovery"
            state["activated"] = False
            state["candidate_funnel"]["raw"] = 0
            state["candidate_funnel"]["dedup"] = 0
        else:
            for helper, register_state, candidates in buffered:
                for candidate in candidates:
                    function = str(
                        candidate.get("function")
                        or candidate.get("function_name")
                        or candidate.get("func_name")
                        or ""
                    )
                    attribution = list(project_routes.get(function) or [])
                    reachability = {
                        "status": "reachable" if attribution else "unknown",
                        "reachable": True if attribution else None,
                        "entries": sorted({str(row["entry_identity"]) for row in attribution}),
                        "call_paths": [list(row["call_path"]) for row in attribution],
                    }
                    if not attribution:
                        reachability["coverage_gap"] = "entry_path_not_closed_in_current_graph"
                    candidate["reachability_attribution"] = reachability
                    if attribution:
                        candidate["entry_identity"] = reachability["entries"][0]
                        candidate["call_path"] = list(reachability["call_paths"][0])
                helper._register_candidate_issues(
                    register_state,
                    candidates,
                    source="fast_project_static_pass",
                )
            state["status"] = (
                "complete_with_coverage_gaps"
                if state["link_coverage"]["uncovered_build_contexts"]
                or state["link_coverage"]["unclosed_edges"]
                or state["planning_gaps"]
                or state["unsupported_capabilities"]
                or state["backend_health"]["degraded"]
                else "complete"
            )
            state["activated"] = True
            # Publish only the atomically admitted static inventory. A failed
            # build must not leak partial facts into semantic discovery.
            if resolve_discovery_profile(self.base_config).name == "deep":
                self._hierarchical_static_inputs = (build_runtime, link_groups)
        state["formal_qualified"] = bool(
            state["activated"]
            and not state["link_coverage"]["uncovered_build_contexts"]
            and not state["link_coverage"]["unclosed_edges"]
            and not state["planning_gaps"]
            and not state["unsupported_capabilities"]
            and not state["backend_health"]["degraded"]
            and state.get("semantic_catalog", {}).get("complete") is True
            and not state.get("semantic_catalog", {}).get("observed_unclassified_system_interfaces")
            and state.get("project_semantics", {}).get("ready") is True
            and state["completed_build_contexts"] == state["planned_build_contexts"]
        )
        state["timings_seconds"]["static_total"] = round(time.monotonic() - started, 4)
        logger.info(
            "[fast-static] status=%s functions=%d local_exec=%d graph_units=%d "
            "raw=%d dedup=%d duplicate_local=%d duration=%.2fs",
            state["status"],
            state["unique_function_instances"],
            state["local_analysis_executions"],
            state["graph_analysis_units"],
            state["candidate_funnel"]["raw"],
            state["candidate_funnel"]["dedup"],
            state["duplicate_local_executions"],
            state["timings_seconds"]["static_total"],
        )

    def _run_project_deterministic_fact_pass(
        self,
        entries: List[FunctionEntry],
    ) -> None:
        """Collect local deterministic facts once for the union of entry reachability.

        The ordinary entry workers still own caller-specific context and report
        projection.  This pass owns only cheap function-local collection: it
        traverses the complete reachable union without an LLM skill filter or
        a per-entry depth quota, then registers each result against the entry
        path that reached it.  Ledger identity coalesces those paths before a
        Validator can run.
        """

        started = time.monotonic()
        state: Dict[str, Any] = {
            "enabled": True,
            "status": "complete",
            "reachable_functions": 0,
            "analyzed_functions": 0,
            "candidate_count": 0,
            "rule_candidate_counts": {"by_engine": {}, "by_rule": {}, "total": 0},
            "unresolved_internal_functions": 0,
            "failures": [],
        }
        generator = ClangAstCfgCandidateGenerator(
            program_facts_provider=getattr(self.code_index, "get_function_program_facts", None),
            semantics=self._get_shared_local_pattern_semantics(),
            semantic_overlay=self._get_shared_semantic_overlay(),
            tooling_evidence_provider=None,
            rule_policy=self.base_config.effective_rules.policy,
        )
        helper = Analyzer(
            self.base_config,
            semantic_result=self.semantic_result,
            reproduction_service=getattr(self, "reproduction_service", None),
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            user_config=self.user_config,
            force_ignore_history=self.force_ignore_history,
            maintain_mode=self.maintain_mode,
            candidate_ledger=self._candidate_ledger,
            shared_local_pattern_semantics=self._get_shared_local_pattern_semantics(),
            shared_semantic_overlay=self._get_shared_semantic_overlay(),
            llm_clients=self._shared_llm_clients,
            validation_result_cache=self._validation_result_cache,
            cancellation_token=self._cancellation_token,
            scheduler=self._scheduler,
            decision_fact_cache=self._decision_fact_cache,
            write_root_reports=False,
            defer_validation_to_scan=True,
            project_knowledge_service=self.project_knowledge_service,
        )

        # Keep one call path per (entry, function) to avoid exponential path
        # expansion in recursive dispatcher graphs.  The fact collection is
        # function-scoped; all extra paths remain discoverable through normal
        # entry analysis and will attach as aliases to the same obligation.
        pending: List[tuple[str, str, str, List[str]]] = []
        for entry in entries:
            identity = entry.identity_key(self.base_config.project.project_root)
            pending.append(
                (
                    entry.function_name,
                    str(entry.file_path or ""),
                    identity,
                    [entry.function_name],
                )
            )
        seen_routes: Set[tuple[str, str, str]] = set()
        implementations: Dict[str, Dict[str, Any]] = {}
        routes: Dict[str, List[tuple[str, List[str]]]] = {}

        while pending:
            self._cancellation_token.raise_if_cancelled()
            function, file_hint, entry_identity, call_path = pending.pop(0)
            route_key = (entry_identity, function, file_hint)
            if route_key in seen_routes:
                continue
            seen_routes.add(route_key)
            try:
                impl = self.code_index.get_function_impl(
                    function,
                    max_lines=None,
                    warn_missing=False,
                    file_path=file_hint,
                )
            except Exception as exc:
                state["failures"].append(
                    {
                        "function": function,
                        "entry_identity": entry_identity,
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            if not impl:
                # Calls into a system library or unresolved indirect callback
                # are retained as coverage telemetry, not fabricated failures.
                state["unresolved_internal_functions"] += 1
                continue
            if impl.get("truncated") or not str(impl.get("code") or "").strip():
                state["failures"].append(
                    {
                        "function": function,
                        "entry_identity": entry_identity,
                        "reason": (
                            "source_truncated" if impl.get("truncated") else "source_unavailable"
                        ),
                    }
                )
                continue
            index_name = str(
                impl.get("index_name")
                or impl.get("qualified_name")
                or f"{impl.get('file') or file_hint}::{function}"
            )
            implementations.setdefault(index_name, impl)
            route_list = routes.setdefault(index_name, [])
            if (entry_identity, call_path) not in route_list:
                route_list.append((entry_identity, call_path))
            try:
                callees = self.code_index.get_callees(function, limit=1_000_000)
            except Exception as exc:
                state["failures"].append(
                    {
                        "function": function,
                        "entry_identity": entry_identity,
                        "reason": f"callee_query:{type(exc).__name__}: {exc}",
                    }
                )
                continue
            for callee in callees:
                if not isinstance(callee, dict):
                    continue
                callee_name = str(
                    callee.get("name") or callee.get("function") or callee.get("callee") or ""
                ).strip()
                if not callee_name or callee_name in call_path:
                    continue
                pending.append(
                    (
                        callee_name,
                        str(callee.get("file") or callee.get("file_path") or ""),
                        entry_identity,
                        [*call_path, callee_name],
                    )
                )

        state["reachable_functions"] = len(implementations)
        for index_name, impl in sorted(implementations.items()):
            self._cancellation_token.raise_if_cancelled()
            # CodeIndex exposes this as ``func_name``.  Accept legacy test/
            # backend aliases as compatibility fallbacks, but never mark a
            # complete implementation failed merely because its display key
            # differs from the index record schema.
            function = str(
                impl.get("func_name")
                or impl.get("qualified_name")
                or impl.get("name")
                or impl.get("function")
                or ""
            )
            if not function:
                # CodeIndex index names include source coordinates, but an
                # empty source function is not analysable evidence.
                state["failures"].append(
                    {"function": index_name, "reason": "implementation_missing_function_name"}
                )
                continue
            try:
                findings = generator.generate_issues(
                    function,
                    str(impl.get("code") or ""),
                    str(impl.get("file") or ""),
                    # No ``allowed_skills``: deterministic fact collection is
                    # never a lossy task-router filter.
                    allowed_skills=None,
                )
            except Exception as exc:
                state["failures"].append(
                    {
                        "function": function,
                        "reason": f"candidate_generation:{type(exc).__name__}: {exc}",
                    }
                )
                continue
            state["analyzed_functions"] += 1
            for entry_identity, call_path in routes.get(index_name, []):
                emitted = []
                for finding in findings:
                    issue = deepcopy(finding)
                    issue["entry_identity"] = entry_identity
                    issue["call_path"] = list(call_path)
                    issue["internal_sink_lifted"] = len(call_path) > 1
                    issue["project_fact_pass_v1"] = True
                    emitted.append(issue)
                if emitted:
                    emitted = helper._annotate_candidate_issues(
                        emitted,
                        checker=helper._local_candidate_checker(),
                        path_kind="project_deterministic_fact_pass",
                    )
                if emitted:
                    project_rule_counts = state["rule_candidate_counts"]
                    for issue in emitted:
                        if str(issue.get("candidate_kind") or "") != "deterministic_rule":
                            continue
                        rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
                        engine = str(issue.get("rule_engine") or "")
                        if rule_id:
                            by_rule = project_rule_counts["by_rule"]
                            by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
                        if engine:
                            by_engine = project_rule_counts["by_engine"]
                            by_engine[engine] = by_engine.get(engine, 0) + 1
                        project_rule_counts["total"] += 1
                    helper._register_candidate_issues(
                        {
                            "candidate_ledger": self._candidate_ledger,
                            "entry_identity": entry_identity,
                            "run_id": self.run_id,
                        },
                        emitted,
                        source="project_deterministic_fact_pass",
                    )
                    state["candidate_count"] += len(emitted)

        if state["failures"]:
            state["status"] = "failed"
        state["duration_seconds"] = round(time.monotonic() - started, 4)
        self._project_fact_pass_state = state
        logger.info(
            "[project-facts] end reachable=%d analyzed=%d candidates=%d unresolved=%d failures=%d duration=%.2fs",
            state["reachable_functions"],
            state["analyzed_functions"],
            state["candidate_count"],
            state["unresolved_internal_functions"],
            len(state["failures"]),
            state["duration_seconds"],
        )

    def _run_active_discovery(self, entries: List[FunctionEntry], profile: Any) -> None:
        """Build the zero-LLM map and route bounded hypotheses into the ledger.

        This stage is best-effort by design.  A map/backend/model failure is
        reported as explicit coverage telemetry and never prevents already
        discovered obligations from reaching the shared Validator queue.
        """

        started = time.monotonic()
        snapshot_dir = Path(self.base_config.analysis.snapshot_dir)
        sidecar_path = snapshot_dir / "security_map.db"
        export_path = snapshot_dir / "security_semantic_map.json"
        state: Dict[str, Any] = {
            "enabled": True,
            "profile": str(profile.name),
            "status": "running",
            "sidecar_path": str(sidecar_path),
            "json_export_path": str(export_path),
            "llm_semantic_model_calls": 0,
            "llm_discovery_call_count": 0,
        }
        self._active_discovery_state = state
        try:
            ablation_override = self._benchmark_ablation_override
            discovery_enabled = bool(
                ablation_override is None or ablation_override.active_discovery_enabled
            )
            semantic_enrichment_enabled = bool(
                ablation_override is None or ablation_override.semantic_enrichment_enabled
            )
            if ablation_override is not None:
                state["benchmark_ablation"] = ablation_override.report_metadata()
            self._cancellation_token.raise_if_cancelled()
            max_functions_default = 15_000 if profile.name == "deep" else 5_000
            max_functions = int(
                getattr(
                    self.base_config.analysis,
                    "security_map_max_functions",
                    max_functions_default,
                )
                or max_functions_default
            )
            semantic_map = ZeroLLMSecurityMapBuilder(
                self.code_index,
                project_id=str(
                    getattr(self.base_config.project, "project_id", "")
                    or self.base_config.project.project_root.name
                ),
                revision=str(self._candidate_ledger.revision or ""),
                profile=str(profile.name),
                semantic_overlay=self._get_shared_semantic_overlay(),
                project_root=self.base_config.project.project_root,
                max_functions=max_functions,
            ).build(entries)
            self._cancellation_token.raise_if_cancelled()
            store = SQLiteSecurityMapStore(sidecar_path)
            registrar = CandidateRegistrar(
                self._candidate_ledger,
                project_id=str(
                    getattr(self.base_config.project, "project_id", "")
                    or self.base_config.project.project_root.name
                ),
                project_root=str(self.base_config.project.project_root),
                revision=str(self._candidate_ledger.revision or ""),
                run_id=self.run_id,
                decision_fact_cache=self._decision_fact_cache,
            )
            discovery_llm_client = (
                self._scan_role_llm_client("analysis") if discovery_enabled else None
            )
            modeling_llm_client = (
                self._scan_role_llm_client("modeling") if semantic_enrichment_enabled else None
            )
            report_runner = None
            semantic_enricher = None
            if discovery_llm_client is not None:
                agent_runner = make_agent_report_runner(ActiveDiscoveryAgent(discovery_llm_client))

                def report_runner(projection: Any, active_profile: Any) -> Any:
                    self._cancellation_token.raise_if_cancelled()
                    return agent_runner(projection, active_profile)

            if modeling_llm_client is not None:
                enrichment_runner = make_semantic_enrichment_runner(
                    SemanticEnrichmentAgent(modeling_llm_client)
                )

                def semantic_delta_runner(projection: Any, active_profile: Any) -> Any:
                    self._cancellation_token.raise_if_cancelled()
                    return enrichment_runner(projection, active_profile)

                semantic_enricher = SemanticMapEnricher(
                    profile=profile,
                    store=store,
                    model_identity=str(
                        (getattr(modeling_llm_client, "models", None) or ["unknown"])[0]
                    ),
                    user_semantics_fingerprint=str(
                        semantic_map.fingerprints.get("semantic_overlay") or ""
                    ),
                    report_runner=semantic_delta_runner,
                    mode=str(
                        "active"
                        if ablation_override is not None
                        else getattr(
                            self.base_config.analysis,
                            "security_semantic_enrichment_mode",
                            "shadow",
                        )
                        or "shadow"
                    ),
                )

            coordinator = ActiveDiscoveryCoordinator(
                profile=profile,
                store=store,
                registrar=registrar,
                report_runner=report_runner,
                investigation_runner=make_investigation_runner(
                    self.base_config,
                    semantic_map,
                    discovery_llm_client,
                    cancellation=self._cancellation_token,
                ),
                semantic_enricher=semantic_enricher,
                discovery_enabled=discovery_enabled,
                visibility_mode=(
                    "active"
                    if ablation_override is not None
                    else rollout_active_discovery_mode(self.base_config)
                ),
                rollout_stage=str(
                    (
                        f"benchmark_ablation_{ablation_override.arm_id.lower()}"
                        if ablation_override is not None
                        else rollout_runtime_policy(self.base_config).get("stage") or "unmanaged"
                    )
                ),
            )
            planned_map, discovery_state = coordinator.run(
                semantic_map,
                covered_keys=candidate_coverage_keys(
                    self._candidate_ledger, semantic_map=semantic_map
                ),
                known_variant_keys=self._historical_variant_keys_for_map(semantic_map),
                export_path=export_path,
            )
            state.update(discovery_state)
            planned_units = list(planned_map.audit_units)
            missing_modeling = (
                semantic_enrichment_enabled and modeling_llm_client is None and bool(planned_units)
            )
            missing_discovery = (
                discovery_enabled
                and discovery_llm_client is None
                and int(state.get("completed_report_count", 0) or 0) < len(planned_units)
            )
            if missing_modeling or missing_discovery:
                state["status"] = "planned_no_llm_client"
                missing_roles = [
                    role
                    for role, missing in (
                        ("modeling", missing_modeling),
                        ("analysis", missing_discovery),
                    )
                    if missing
                ]
                state.setdefault("failures", []).append(
                    {
                        "reason": (
                            "No LLM client was configured for required scan role(s): "
                            + ", ".join(missing_roles)
                        )
                    }
                )
                state["uncovered_unit_ids"] = list(
                    dict.fromkeys(
                        [
                            *list(state.get("uncovered_unit_ids") or []),
                            *(unit.unit_id for unit in planned_units),
                        ]
                    )
                )
        except CancellationError:
            state["status"] = "interrupted"
            state["failures"] = [{"reason": "active discovery cancelled"}]
        except Exception as exc:
            state["status"] = "failed"
            state["failures"] = [{"reason": f"{type(exc).__name__}: {exc}"}]
            logger.exception("[active-discovery] stage failed")
        finally:
            state["duration_seconds"] = round(time.monotonic() - started, 4)
            self._active_discovery_state = state
            logger.info(
                "[active-discovery] end profile=%s status=%s units=%d hypotheses=%d "
                "new_groups=%d duration=%.2fs",
                state.get("profile"),
                state.get("status"),
                int(state.get("planned_unit_count", 0) or 0),
                int(state.get("hypothesis_count", 0) or 0),
                int(state.get("new_validation_group_count", 0) or 0),
                state["duration_seconds"],
            )

    def _historical_variant_keys_for_map(self, semantic_map: Any) -> Set[str]:
        """Read prior confirmed reports for the functions in this map."""

        if self.force_ignore_history:
            return set()
        issues: List[Dict[str, Any]] = []
        seen_index_names: Set[str] = set()
        for record in getattr(semantic_map, "functions", ()) or ():
            index_name = str(getattr(record, "index_name", "") or "")
            if not index_name or index_name in seen_index_names:
                continue
            seen_index_names.add(index_name)
            try:
                report = self.snapshot_store.load_final_report(index_name)
            except Exception:
                logger.exception(
                    "[active-discovery] failed to load historical variant report index=%s",
                    index_name,
                )
                continue
            if isinstance(report, dict) and isinstance(report.get("issues"), list):
                issues.extend(item for item in report["issues"] if isinstance(item, dict))
        return historical_variant_keys(issues)

    def _scan_role_llm_client(self, role: str) -> Optional[LLMClient]:
        """Resolve the public role mapping before any legacy Agent config."""

        profiles = getattr(getattr(self.base_config, "scan", None), "llm_profiles", None)
        configured_ref = str(getattr(profiles, role, "") or "")
        if not configured_ref:
            legacy_names = (
                ("active_discovery", "vulnerability_analyzer")
                if role == "analysis"
                else ("semantic_modeler",)
            )
            configured_ref = next(
                (
                    str(getattr(item, "llm_ref", "") or "")
                    for item in self.base_config.project.agents
                    if str(getattr(item, "name", "") or "") in legacy_names
                    and bool(getattr(item, "enabled", True))
                    and str(getattr(item, "llm_ref", "") or "")
                ),
                "",
            )
        configured_ref = configured_ref or "default"
        return self._shared_llm_clients.get(
            configured_ref,
            self._shared_llm_clients.get("default"),
        )

    # Compatibility for integrations that called the former private helper.
    def _active_discovery_llm_client(self) -> Optional[LLMClient]:
        return self._scan_role_llm_client("analysis")

    @staticmethod
    def _build_shared_llm_clients(config: ZScopeConfig) -> Dict[str, LLMClient]:
        clients: Dict[str, LLMClient] = {}
        token_usage_ledger = ensure_scan_token_usage_ledger(config)
        for name, llm_cfg in config.llms.items():
            effective_timeout = minimum_optional_positive_seconds(
                llm_cfg.timeout,
                getattr(
                    config.analysis,
                    "request_deadline_seconds",
                    None,
                ),
            )
            clients[name] = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=effective_timeout,
                max_retries=llm_cfg.max_retries,
                retry_until_available=getattr(llm_cfg, "retry_until_available", False),
                max_tokens=llm_cfg.max_tokens,
                context_window=llm_cfg.context_window,
                model_context_windows=llm_cfg.model_context_windows,
                base_url_rate_limit_per_minute=getattr(
                    llm_cfg, "base_url_rate_limit_per_minute", 0
                ),
                base_url_max_concurrent_requests=getattr(
                    llm_cfg, "base_url_max_concurrent_requests", 0
                ),
                global_max_concurrent_requests=config.concurrency.llm_max_inflight,
                supports_structured_output=getattr(llm_cfg, "supports_structured_output", False),
                token_usage_ledger=token_usage_ledger,
                llm_ref=name,
            )
        return _ScanLLMClients(clients)

    def _prioritize_entries_for_execution(
        self, entries: List[FunctionEntry]
    ) -> List[FunctionEntry]:
        """Schedule likely long-running entries first to reduce batch tail idle time."""
        if len(entries) <= 1:
            return list(entries)

        scored = [
            (self._entry_scheduling_score(entry), index, entry)
            for index, entry in enumerate(entries)
        ]
        scored.sort(key=lambda item: (-item[0], item[1]))
        prioritized = [entry for _score, _index, entry in scored]
        if [entry.function_name for entry in prioritized] != [
            entry.function_name for entry in entries
        ]:
            preview = ", ".join(
                f"{entry.function_name}:{score}"
                for score, _index, entry in scored[: min(8, len(scored))]
            )
            logger.info("[entry-worker] prioritized entry schedule top=%s", preview)
        return prioritized

    def _entry_scheduling_score(self, entry: FunctionEntry) -> int:
        score = 0
        exposure = str(getattr(entry, "exposure", "") or "").strip().lower()
        score += _ENTRY_EXPOSURE_WEIGHTS.get(exposure, 0)
        reason_text = " ".join(str(reason) for reason in getattr(entry, "reasons", []) or [])
        metadata_text = " ".join(
            part
            for part in (
                str(entry.custom_prompt or ""),
                exposure,
                reason_text,
            )
            if part
        )
        if _ENTRY_HEAVY_TEXT_RE.search(metadata_text):
            score += 80

        try:
            impl = self.code_index.get_function_impl(
                entry.function_name,
                max_lines=None,
                include_context=False,
                warn_missing=False,
                file_path=str(entry.file_path or ""),
            )
        except Exception as exc:
            logger.debug(
                "Unable to estimate scheduling cost for '%s': %s",
                entry.function_name,
                exc,
            )
            impl = None

        if isinstance(impl, dict):
            code = str(impl.get("code") or "")
            code_without_entry_name = re.sub(
                rf"\b{re.escape(entry.function_name)}\b",
                "",
                code,
            )
            line_count = max(0, len(code.splitlines()))
            score += min(600, line_count * 4)
            call_names = {
                name
                for name in _ENTRY_CALL_RE.findall(code_without_entry_name)
                if name and name not in {"if", "for", "while", "switch", "return", "sizeof"}
            }
            score += min(360, len(call_names) * 18)
            score += min(220, len(_ENTRY_CONTROL_RE.findall(code_without_entry_name)) * 12)
            score += min(260, len(_ENTRY_HEAVY_TEXT_RE.findall(code_without_entry_name)) * 18)
        return int(score)

    @staticmethod
    def _entry_result_key(entry: FunctionEntry) -> str:
        focus = entry.diff_focus if isinstance(entry.diff_focus, dict) else {}
        component = str(focus.get("component") or "").strip()
        file_path = FunctionEntry._portable_path_text(
            entry.file_path or focus.get("entry_file_path") or ""
        )
        signature = FunctionEntry.normalize_signature(entry.signature)
        if component or file_path or signature:
            key = f"{component or 'default'}:{entry.function_name}@{file_path or '<unknown>'}"
            if signature:
                key = f"{key}::{signature}"
            return key
        return entry.function_name

    @staticmethod
    def _scoped_result_key(entry: FunctionEntry, scope: Optional[InstanceScope]) -> str:
        base = ParallelAnalyzer._entry_result_key(entry)
        if scope is None:
            return base
        return f"{scope.identity}::{base}"

    def _prioritize_scoped_entries(
        self,
        scoped_entries: List[Tuple[FunctionEntry, Optional[InstanceScope]]],
    ) -> List[Tuple[FunctionEntry, Optional[InstanceScope]]]:
        """Schedule likely long-running entries first, keeping each scope paired."""

        if len(scoped_entries) <= 1:
            return list(scoped_entries)
        scored = [
            (self._entry_scheduling_score(entry), index, entry, scope)
            for index, (entry, scope) in enumerate(scoped_entries)
        ]
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [(entry, scope) for _score, _index, entry, scope in scored]

    def _materialize_entry_identities(
        self,
        entries: List[FunctionEntry],
    ) -> List[FunctionEntry]:
        """Resolve legacy name-only entries into file+signature identities."""
        project_root = self.base_config.project.project_root
        getter = getattr(self.code_index, "get_function_impl", None)
        identity_finder = getattr(self.code_index, "find_function_identities", None)
        resolved_entries: List[FunctionEntry] = []
        seen_identities: Set[str] = set()
        for entry in entries:
            file_path = entry.normalized_file_path(project_root)
            resolved = replace(entry, file_path=file_path or None)
            impl: Optional[Dict[str, Any]] = None
            if callable(identity_finder):
                try:
                    matches = identity_finder(
                        resolved.lookup_query(),
                        file_path=file_path,
                    )
                except TypeError:
                    matches = identity_finder(resolved.lookup_query())
                except Exception as exc:
                    logger.debug(
                        "Unable to query entry identity for %s: %s",
                        resolved.function_name,
                        exc,
                    )
                    matches = []
                identity_matches = (
                    [match for match in matches if isinstance(match, dict)]
                    if isinstance(matches, list)
                    else []
                )
                if identity_matches:
                    for match in identity_matches:
                        matched_entry = self._entry_from_identity_record(
                            resolved,
                            match,
                            project_root,
                        )
                        identity = matched_entry.identity_key(project_root)
                        if identity in seen_identities:
                            continue
                        seen_identities.add(identity)
                        resolved_entries.append(matched_entry)
                    continue
            if impl is None and callable(getter):
                try:
                    impl = getter(
                        resolved.lookup_query(),
                        max_lines=None,
                        include_context=False,
                        warn_missing=False,
                        file_path=file_path,
                    )
                except TypeError:
                    try:
                        impl = getter(resolved.lookup_query(), include_context=False)
                    except TypeError:
                        impl = getter(resolved.lookup_query())
                except Exception as exc:
                    logger.debug(
                        "Unable to resolve entry identity for %s: %s",
                        resolved.function_name,
                        exc,
                    )
                    impl = None
            if isinstance(impl, dict):
                resolved = self._entry_from_identity_record(
                    resolved,
                    {
                        "function_name": impl.get("func_name"),
                        "file_path": impl.get("file"),
                        "signature": impl.get("signature"),
                    },
                    project_root,
                )
            identity = resolved.identity_key(project_root)
            if identity in seen_identities:
                continue
            seen_identities.add(identity)
            resolved_entries.append(resolved)
        return resolved_entries

    @staticmethod
    def _entry_from_identity_record(
        entry: FunctionEntry,
        record: Dict[str, Any],
        project_root: Path,
    ) -> FunctionEntry:
        file_path = FunctionEntry(
            function_name=entry.function_name,
            file_path=str(record.get("file_path") or entry.file_path or ""),
        ).normalized_file_path(project_root)
        return replace(
            entry,
            function_name=str(record.get("function_name") or entry.function_name),
            file_path=file_path or None,
            signature=str(record.get("signature") or entry.signature or "") or None,
        )

    def analyze_functions(
        self,
        function_names: List[str],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Dict[str, ParallelAnalysisResult]:
        """
        Analyze multiple functions in parallel.

        Args:
            function_names: List of function names to analyze
            progress_callback: Optional callback(completed, total, func_name) for progress

        Returns:
            Dict mapping function name to analysis result
        """
        # Convert to FunctionEntry objects
        entries = [FunctionEntry(function_name=name) for name in function_names]
        return self.analyze_function_entries(entries, progress_callback)

    def _analyze_single_entry(
        self,
        entry: FunctionEntry,
        instance_scope: Optional[InstanceScope] = None,
        skip_candidate_discovery: bool = False,
    ) -> ParallelAnalysisResult:
        """Analyze a single function entry with optional custom prompt."""

        start_time = time.monotonic()
        entry_key = self._entry_result_key(entry)
        scoped_index = (
            wrap_scoped_code_index(self.code_index, instance_scope)
            if instance_scope is not None
            else self.code_index
        )
        if skip_candidate_discovery and instance_scope is not None:
            return self._project_fast_static_entry_result(
                entry,
                instance_scope,
                scoped_index,
                started=start_time,
            )
        if instance_scope is not None:
            # Per-instance contracts come only from the generator's standard
            # roots.  The project-wide semantic model and overlay are never used
            # as instance-fact authorization, and neither is built here.
            shared_semantics: Optional[LocalPatternSemantics] = LocalPatternSemantics()
            shared_overlay: Optional[Dict[str, Any]] = {}
            entry_semantic_result: Any = None
        else:
            shared_semantics = (
                None if self.maintain_mode else self._get_shared_local_pattern_semantics()
            )
            shared_overlay = None if self.maintain_mode else self._get_shared_semantic_overlay()
            entry_semantic_result = self.semantic_result
        entry_budget_seconds = getattr(
            self.base_config.analysis,
            "entry_deadline_seconds",
            1800.0,
        )
        budget_exhaustion_policy = "observe"
        logger.info(
            "[entry-worker] start entry=%s key=%s file=%s",
            entry.function_name,
            entry_key,
            entry.file_path or "",
        )
        entry_token = self._cancellation_token.child(timeout_seconds=None)

        try:
            # Create a config copy with this function as entry point and custom prompt
            phase_started = time.time()
            config_copy = self._create_config_for_entry(entry)
            if instance_scope is not None:
                self._frozen_instance_semantic_snapshot(instance_scope)
                scoped_index = _InstanceEntryLookupIndex(
                    self.code_index,
                    instance_scope,
                    entry,
                    semantics_context=self._instance_semantics_context,
                    batch_guarded=True,
                )
            logger.info(
                "[entry-worker] config-ready entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - phase_started,
            )

            # Create analyzer and run with shared components
            phase_started = time.time()
            instance_snapshot = (
                self._frozen_instance_semantic_snapshot(instance_scope)
                if instance_scope is not None
                else None
            )
            instance_context = getattr(self, "_instance_semantics_context", None)
            analyzer = Analyzer(
                config_copy,
                code_index=scoped_index,
                snapshot_store=self.snapshot_store,
                user_config=self.user_config,
                force_ignore_history=self.force_ignore_history,
                maintain_mode=self.maintain_mode,
                candidate_ledger=self._candidate_ledger,
                shared_local_pattern_semantics=shared_semantics,
                shared_semantic_overlay=shared_overlay,
                llm_clients=self._shared_llm_clients,
                validation_result_cache=self._validation_result_cache,
                cancellation_token=entry_token,
                scheduler=self._scheduler,
                candidate_ir_persistence_lock=self._candidate_ir_persistence_lock,
                decision_fact_cache=self._decision_fact_cache,
                write_root_reports=False,
                defer_validation_to_scan=self._uses_scan_validation_queue(),
                project_knowledge_service=self.project_knowledge_service,
                semantic_result=entry_semantic_result,
                instance_scope=instance_scope,
                reproduction_service=getattr(self, "reproduction_service", None),
                instance_semantics_snapshot=instance_snapshot,
                instance_semantics_current=(
                    instance_context.is_frozen if instance_context is not None else None
                ),
                skip_candidate_discovery=skip_candidate_discovery,
            )
            logger.info(
                "[entry-worker] analyzer-ready entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - phase_started,
            )
            run_started = time.time()
            logger.info(
                "[entry-worker] run-start entry=%s key=%s",
                entry.function_name,
                entry_key,
            )
            report_dict = analyzer.run()
            report_metadata = (
                dict(report_dict.get("metadata", {}))
                if isinstance(report_dict.get("metadata"), dict)
                else {}
            )
            if instance_scope is not None and not report_dict.get("error"):
                if FunctionEntry.normalize_signature(
                    report_metadata.get("entry_signature")
                ) != FunctionEntry.normalize_signature(entry.signature) or report_metadata.get(
                    "entry_identity"
                ) != entry.identity_key(
                    self.base_config.project.project_root
                ):
                    raise ValueError("instance_entry_workflow_identity_changed")
                self._frozen_instance_semantic_snapshot(instance_scope)
            logger.info(
                "[entry-worker] run-end entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - run_started,
            )

            duration = time.monotonic() - start_time
            budget_metadata = self._entry_budget_metadata(
                duration_seconds=duration,
                budget_seconds=entry_budget_seconds,
                policy=budget_exhaustion_policy,
            )
            report_metadata.update(budget_metadata)
            scope_metadata = self._instance_scope_metadata(instance_scope, scoped_index)
            if instance_snapshot is not None:
                scope_metadata.update(
                    instance_semantics=instance_snapshot.authority_policy,
                    instance_semantics_schema=instance_snapshot.schema,
                    instance_semantics_digest=instance_snapshot.digest,
                )
            report_metadata.update(scope_metadata)
            if budget_metadata["entry_budget_exceeded"]:
                logger.warning(
                    "[entry-worker] budget-exceeded entry=%s key=%s "
                    "budget=%.2fs overrun=%.2fs policy=%s outcome=completed",
                    entry.function_name,
                    entry_key,
                    float(entry_budget_seconds),
                    budget_metadata["entry_budget_overrun_seconds"],
                    budget_exhaustion_policy,
                )
            logger.info(
                "[entry-worker] end entry=%s key=%s verdict=%s issues=%d duration=%.2fs",
                entry.function_name,
                entry_key,
                report_dict.get("overall_verdict", "unknown"),
                len(report_dict.get("issues", [])),
                duration,
            )

            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict=report_dict.get("overall_verdict", "unknown"),
                entry_identity=entry.identity_key(self.base_config.project.project_root),
                entry_file_path=entry.normalized_file_path(self.base_config.project.project_root),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                issues=report_dict.get("issues", []),
                audit_observations=report_metadata.get("audit_observations", []),
                candidate_terminal_states=report_dict.get("candidate_terminal_states", []),
                error=(str(report_dict.get("error")) if report_dict.get("error") else None),
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata["entry_budget_overrun_seconds"],
                budget_exhaustion_policy=budget_exhaustion_policy,
                context_tokens=report_metadata.get("context_tokens", 0),
                cumulative_prompt_tokens=report_metadata.get("cumulative_prompt_tokens", 0),
                cumulative_completion_tokens=report_metadata.get("cumulative_completion_tokens", 0),
                cumulative_total_tokens=report_metadata.get("cumulative_total_tokens", 0),
                diff_focus=entry.diff_focus,
                metadata=report_metadata,
                build_context_id=str(scope_metadata.get("build_context_id") or ""),
                usr=str(scope_metadata.get("usr") or ""),
                instance_identity=str(scope_metadata.get("instance_identity") or ""),
                instance_scope_report=scope_metadata.get("instance_scope_report"),
                instance_collection=deepcopy(report_metadata.get("instance_collection")),
                execution_completeness=str(report_dict.get("completeness") or "unknown"),
                scan_outcome=str(report_dict.get("scan_outcome") or "unknown"),
            )

        except CancellationError as e:
            duration = time.monotonic() - start_time
            reason = entry_token.reason or str(e) or "entry_cancelled"
            budget_metadata = self._entry_budget_metadata(
                duration_seconds=duration,
                budget_seconds=entry_budget_seconds,
                policy=budget_exhaustion_policy,
                force_exceeded=False,
            )
            budget_metadata["cancellation_reason"] = reason
            logger.warning(
                "[entry-worker] cancelled entry=%s key=%s reason=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                reason,
                duration,
            )
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict="error",
                entry_identity=entry.identity_key(self.base_config.project.project_root),
                entry_file_path=entry.normalized_file_path(self.base_config.project.project_root),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                error=reason,
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata["entry_budget_overrun_seconds"],
                budget_exhaustion_policy=budget_exhaustion_policy,
                diff_focus=entry.diff_focus,
                metadata=budget_metadata,
            )
        except Exception as e:
            duration = time.monotonic() - start_time
            budget_metadata = self._entry_budget_metadata(
                duration_seconds=duration,
                budget_seconds=entry_budget_seconds,
                policy=budget_exhaustion_policy,
            )
            logger.exception(
                "[entry-worker] error entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                duration,
            )
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict="error",
                entry_identity=entry.identity_key(self.base_config.project.project_root),
                entry_file_path=entry.normalized_file_path(self.base_config.project.project_root),
                entry_signature=FunctionEntry.normalize_signature(entry.signature),
                error=str(e),
                duration_seconds=duration,
                entry_budget_seconds=budget_metadata["entry_budget_seconds"],
                entry_budget_exceeded=budget_metadata["entry_budget_exceeded"],
                entry_budget_overrun_seconds=budget_metadata["entry_budget_overrun_seconds"],
                budget_exhaustion_policy=budget_exhaustion_policy,
                diff_focus=entry.diff_focus,
                metadata=budget_metadata,
            )
        finally:
            self._close_thread_llm_sessions()

    def _project_fast_static_entry_result(
        self,
        entry: FunctionEntry,
        scope: InstanceScope,
        scoped_index: Any,
        *,
        started: float,
    ) -> ParallelAnalysisResult:
        """Attach entry attribution without rerunning an entry workflow.

        The project pass has already executed and atomically registered every
        detector output.  Reconstructing an ``Analyzer`` for each public entry
        would only rewrite empty reports and snapshots; it cannot discover or
        validate another candidate.  This projection retains the exact
        instance collection closure required by recovery while making entry
        work a metadata-only operation.
        """

        context = getattr(self, "_instance_semantics_context", None)
        snapshot = getattr(context, "snapshots", {}).get(scope.identity)
        if snapshot is None or snapshot.scope != scope:
            raise ValueError("instance_semantics_missing_for_fast_entry_projection")
        self._cancellation_token.raise_if_cancelled()
        scope_metadata = self._instance_scope_metadata(scope, scoped_index)
        entry_identity = entry.identity_key(self.base_config.project.project_root)
        selected_stages = ["local", "graph", "backend", "merge", "persist", "registration"]
        collection = {
            "schema": "zscope.instance-collection-closure.v1",
            "supported": True,
            "selected_workflow": list(DEFAULT_SCAN_STEP_IDS),
            "selected_stages": selected_stages,
            "semantics_digest": snapshot.digest,
            "scope": snapshot.scope.to_payload(),
            "stages": {
                stage: {
                    "disposition": "unsupported" if stage == "persist" else "complete",
                    "reason": (
                        "scoped_raw_knowledge_db_unavailable"
                        if stage == "persist"
                        else "fast_project_static_pass_precollected"
                    ),
                }
                for stage in selected_stages
            },
            "collection_closed": True,
            "input_current": True,
            "active_stage_errors": [],
            "unsupported_stages": {"persist": "scoped_raw_knowledge_db_unavailable"},
            "excluded_capabilities": {
                "semantic_modeling": "instance_scoped_builtin_confirmed_project_no_scan_discovery",
                "svf_taint_query": "scoped_raw_knowledge_db_unavailable",
            },
            "excluded_subchannels": (
                {"clang_knowledge_db": "scoped_raw_knowledge_db_unavailable"}
                if hasattr(scoped_index, "get_instance_backend_signals")
                else {
                    "svf_taint_query": "scoped_raw_knowledge_db_unavailable",
                    "clang_knowledge_db": "scoped_raw_knowledge_db_unavailable",
                }
            ),
            "entry_identity": entry_identity,
        }
        self._cancellation_token.raise_if_cancelled()
        duration = time.monotonic() - started
        metadata = {
            **scope_metadata,
            "instance_semantics": snapshot.authority_policy,
            "instance_semantics_schema": snapshot.schema,
            "instance_semantics_digest": snapshot.digest,
            "instance_collection": deepcopy(collection),
            "fast_static_entry_projection": True,
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
        }
        logger.info(
            "[fast-static] entry-attribution entry=%s build=%s duration=%.4fs",
            entry.function_name,
            scope.build_context_id,
            duration,
        )
        return ParallelAnalysisResult(
            function_name=entry.function_name,
            verdict="no_issue_found",
            entry_identity=entry_identity,
            entry_file_path=entry.normalized_file_path(self.base_config.project.project_root),
            entry_signature=FunctionEntry.normalize_signature(entry.signature),
            duration_seconds=duration,
            diff_focus=entry.diff_focus,
            metadata=metadata,
            build_context_id=scope.build_context_id,
            usr=scope.usr,
            instance_identity=scope.identity,
            instance_scope_report=scope_metadata.get("instance_scope_report"),
            instance_collection=deepcopy(collection),
            execution_completeness="complete",
            scan_outcome="clean",
        )

    @staticmethod
    def _entry_budget_metadata(
        *,
        duration_seconds: float,
        budget_seconds: Optional[float],
        policy: str,
        force_exceeded: bool = False,
    ) -> Dict[str, Any]:
        normalized_budget = (
            float(budget_seconds)
            if budget_seconds is not None and float(budget_seconds) > 0
            else None
        )
        overrun_seconds = (
            max(0.0, float(duration_seconds) - normalized_budget)
            if normalized_budget is not None
            else 0.0
        )
        exceeded = bool(normalized_budget is not None and (force_exceeded or overrun_seconds > 0.0))
        return {
            "entry_budget_seconds": normalized_budget,
            "entry_budget_exceeded": exceeded,
            "entry_budget_overrun_seconds": overrun_seconds,
            "budget_exhaustion_policy": str(policy or "observe"),
            "entry_budget": {
                "seconds": normalized_budget,
                "exceeded": exceeded,
                "overrun_seconds": overrun_seconds,
                "policy": str(policy or "observe"),
            },
        }

    def _close_thread_llm_sessions(self) -> None:
        if not getattr(self, "_owns_llm_clients", False):
            return
        seen: Set[int] = set()
        for client in self._shared_llm_clients.values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_thread_session = getattr(client, "close_thread_session", None)
            if callable(close_thread_session):
                close_thread_session()

    def close(self) -> None:
        condition = self._lifecycle_condition()
        with condition:
            self._closed = True
            # A progress callback may request closure from the batch thread.
            # Its finally block will perform cleanup after scheduling drains.
            if self._active_batch_thread == threading.get_ident():
                return
            while self._active_batch_thread is not None or self._closing:
                condition.wait()
            if self._close_complete:
                return
            self._closing = True
        try:
            self._close_owned_resources()
        finally:
            with condition:
                self._closing = False
                self._close_complete = True
                condition.notify_all()

    def _close_owned_resources(self) -> None:
        scheduler = getattr(self, "_scheduler", None)
        if scheduler is not None:
            scheduler.shutdown(wait=True, cancel_futures=True)
        if getattr(self, "_owns_project_knowledge_service", False):
            Analyzer.close_project_knowledge_service(
                getattr(self, "project_knowledge_service", None)
            )
        if not getattr(self, "_owns_llm_clients", False):
            return
        seen: Set[int] = set()
        for client in getattr(self, "_shared_llm_clients", {}).values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_client = getattr(client, "close", None)
            if callable(close_client):
                close_client()

    def _prepare_shared_semantics(self) -> None:
        """Warm shared project semantics before entry-level analyzers fan out."""
        self._get_shared_local_pattern_semantics()
        self._get_shared_semantic_overlay()

    def _get_shared_local_pattern_semantics(self) -> LocalPatternSemantics:
        if self._shared_local_pattern_semantics is None:
            with self._shared_semantics_lock:
                if self._shared_local_pattern_semantics is None:
                    self._shared_local_pattern_semantics = LocalPatternSemanticBuilder(
                        self.code_index,
                        self.user_config,
                        self.snapshot_store,
                        (Path(path) for path in self.base_config.project.exclude_paths),
                    ).build()
        return self._shared_local_pattern_semantics

    def _get_shared_semantic_overlay(self) -> Dict[str, Any]:
        if self._shared_semantic_overlay is None:
            with self._shared_semantics_lock:
                if self._shared_semantic_overlay is None:
                    self._shared_semantic_overlay = SemanticOverlayCompiler(
                        self.user_config
                    ).compile()
        return self._shared_semantic_overlay

    def _create_config_for_entry(self, entry: FunctionEntry) -> ZScopeConfig:
        """Create a ZScopeConfig copy with the specified entry and custom prompt."""

        agents = []
        for agent_cfg in self.base_config.project.agents:
            agent_copy = copy(agent_cfg)
            entry_custom_prompt = agent_cfg.entry_custom_prompt
            if entry.custom_prompt and agent_cfg.name == "vulnerability_analyzer":
                entry_custom_prompt = entry.custom_prompt
            agent_copy.entry_custom_prompt = entry_custom_prompt
            agents.append(agent_copy)

        project = copy(self.base_config.project)
        project.entry_function = entry.function_name
        project.entry_file_path = entry.file_path
        project.entry_signature = entry.signature
        project.entry_diff_focus = entry.diff_focus
        project.agents = agents

        config = copy(self.base_config)
        config.project = project
        # Keep entry-specific focus separate from the configured task so skill
        # routing remains driven by the global vulnerability scope.
        return config

    @staticmethod
    def _result_cost_metrics(result: ParallelAnalysisResult) -> Dict[str, Any]:
        """Preserve the producer's original metric values without rounding."""
        return {
            "duration_seconds": result.duration_seconds,
            "context_tokens": result.context_tokens,
            "cumulative_prompt_tokens": result.cumulative_prompt_tokens,
            "cumulative_completion_tokens": result.cumulative_completion_tokens,
            "cumulative_total_tokens": result.cumulative_total_tokens,
        }

    def _historical_result_cost(
        self, entry_key: str, result: ParallelAnalysisResult
    ) -> Optional[Dict[str, Any]]:
        try:
            registry = self._restored_result_costs
        except AttributeError:
            return None
        registered = registry.get(entry_key)
        if registered is None or registered[0] is not result:
            return None
        return deepcopy(registered[1])

    def generate_combined_report(
        self, results: Dict[str, ParallelAnalysisResult], output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate a combined report from all parallel analysis results.

        Args:
            results: Dict of function name to analysis result
            output_path: Optional path to save combined report

        Returns:
            Combined report dict
        """
        all_issues: List[Dict[str, Any]] = []
        all_observations: List[Dict[str, Any]] = []
        all_terminal_states: List[Dict[str, Any]] = []
        function_summaries: List[Dict[str, Any]] = []
        historical_costs: List[Dict[str, Any]] = []
        current_results: Dict[str, ParallelAnalysisResult] = {}
        total_duration = 0.0
        base_config = getattr(self, "base_config", None)
        project_config = getattr(base_config, "project", None)
        project_root = str(getattr(project_config, "project_root", "") or "")
        project_id = str(
            getattr(project_config, "project_id", "") or Path(project_root).name or "project"
        )
        source_root = str(getattr(project_config, "project_root", "") or "")
        batch_run_id = str(getattr(self, "run_id", "") or "")
        benchmark_ablation_override = getattr(self, "_benchmark_ablation_override", None)
        benchmark_ablation_metadata = (
            benchmark_ablation_override.report_metadata()
            if benchmark_ablation_override is not None
            else None
        )
        rule_candidate_counts: Dict[str, Any] = {
            "by_engine": {},
            "by_rule": {},
            "total": 0,
        }
        all_terminal_states.extend(self._deferred_entry_terminal_states(project_id, project_root))

        for entry_key, result in results.items():
            historical_cost = self._historical_result_cost(entry_key, result)
            if historical_cost is None:
                current_results[entry_key] = result
                total_duration += result.duration_seconds
            else:
                historical_costs.append(historical_cost)
            result_rule_counts = (
                result.metadata.get("rule_candidate_counts", {})
                if isinstance(result.metadata, dict)
                else {}
            )
            if isinstance(result_rule_counts, dict):
                for dimension in ("by_engine", "by_rule"):
                    values = result_rule_counts.get(dimension)
                    if not isinstance(values, dict):
                        continue
                    target = rule_candidate_counts[dimension]
                    for key, value in values.items():
                        target[str(key)] = target.get(str(key), 0) + int(value or 0)
            all_terminal_states.extend(
                item for item in result.candidate_terminal_states if isinstance(item, dict)
            )
            validation_performance = (
                result.metadata.get("validation_performance", {})
                if isinstance(result.metadata, dict)
                else {}
            )

            function_summary = {
                "function": result.function_name,
                "entry_key": entry_key,
                "entry_identity": result.entry_identity or entry_key,
                "entry_file_path": result.entry_file_path,
                "entry_signature": result.entry_signature,
                "verdict": result.verdict,
                "issue_count": len(result.issues),
                "audit_observation_count": len(result.audit_observations),
                "duration_seconds": round(result.duration_seconds, 2),
                "entry_budget_seconds": result.entry_budget_seconds,
                "entry_budget_exceeded": result.entry_budget_exceeded,
                "entry_budget_overrun_seconds": round(result.entry_budget_overrun_seconds, 3),
                "budget_exhaustion_policy": result.budget_exhaustion_policy,
                "context_tokens": result.context_tokens,
                "cumulative_prompt_tokens": result.cumulative_prompt_tokens,
                "cumulative_completion_tokens": result.cumulative_completion_tokens,
                "cumulative_total_tokens": result.cumulative_total_tokens,
                "validation_performance": validation_performance,
                "error": result.error,
                "cost_provenance": "current_run",
            }
            if historical_cost is not None:
                function_summary.update(
                    {
                        "cost_provenance": "historical_producer_work",
                        "historical_cost": historical_cost,
                        "duration_seconds": 0.0,
                        "context_tokens": 0,
                        "cumulative_prompt_tokens": 0,
                        "cumulative_completion_tokens": 0,
                        "cumulative_total_tokens": 0,
                        "entry_budget_seconds": None,
                        "entry_budget_exceeded": False,
                        "entry_budget_overrun_seconds": 0.0,
                        "validation_performance": {},
                    }
                )
            function_summaries.append(function_summary)

            # Add function context to each issue
            for issue in result.issues:
                issue_copy = issue.copy()
                issue_copy.setdefault("analyzed_from", result.function_name)
                issue_copy.setdefault("reported_from_entry", result.entry_identity or entry_key)
                issue_copy.setdefault("entry_identity", result.entry_identity or entry_key)
                if result.entry_file_path:
                    issue_copy["entry_file_path"] = result.entry_file_path
                if result.entry_signature:
                    issue_copy["entry_signature"] = result.entry_signature
                if entry_key != result.function_name:
                    issue_copy["entry_key"] = entry_key
                self._annotate_diff_relevance(issue_copy, result.diff_focus)
                annotate_issue_identity(
                    issue_copy,
                    project_id=project_id,
                    project_root=project_root,
                    revision=str(result.metadata.get("commit_sha") or ""),
                    entry_function=result.entry_identity or entry_key,
                    run_id=batch_run_id,
                    ordinal=len(all_issues),
                    default_disposition="confirmed",
                )
                all_issues.append(issue_copy)
            for observation in result.audit_observations:
                observation_copy = observation.copy()
                observation_copy.setdefault("analyzed_from", result.function_name)
                observation_copy.setdefault(
                    "reported_from_entry",
                    result.entry_identity or entry_key,
                )
                observation_copy.setdefault(
                    "entry_identity",
                    result.entry_identity or entry_key,
                )
                if result.entry_file_path:
                    observation_copy["entry_file_path"] = result.entry_file_path
                if result.entry_signature:
                    observation_copy["entry_signature"] = result.entry_signature
                if entry_key != result.function_name:
                    observation_copy["entry_key"] = entry_key
                self._annotate_diff_relevance(observation_copy, result.diff_focus)
                annotate_issue_identity(
                    observation_copy,
                    project_id=project_id,
                    project_root=project_root,
                    revision=str(result.metadata.get("commit_sha") or ""),
                    entry_function=result.entry_identity or entry_key,
                    run_id=batch_run_id,
                    ordinal=len(all_observations),
                    default_disposition="needs_review",
                )
                all_observations.append(observation_copy)

        # The scan-level ledger is the final lifecycle authority. Entry reports
        # can be assembled while a shared validation is still in flight, so
        # replace their v3 terminal projection with one final atomic snapshot.
        ledger_snapshot: Dict[str, Any] = {}
        snapshot = getattr(
            getattr(self, "_candidate_ledger", None),
            "freeze",
            None,
        )
        if callable(snapshot):
            ledger_snapshot = snapshot()
        final_records = [
            item for item in ledger_snapshot.get("records", []) if isinstance(item, dict)
        ]
        final_by_cluster = {
            str(item.get("validation_cluster_uid") or ""): item
            for item in final_records
            if item.get("validation_cluster_uid")
        }
        canonical_projection_state: Dict[str, Any] = {
            "candidate_lifecycle_snapshot": ledger_snapshot,
            "finding_root_v1_enabled": True,
            "same_site_aggregation_enabled": True,
        }
        canonical_outcomes = (
            ReportAssembler._canonical_outcome_items(canonical_projection_state) or []
        )
        # A missing/empty ledger snapshot is not a canonical outcome set. This
        # still protects report-only helpers while the stable scan path always
        # uses canonical projection.
        canonical_projection = bool(canonical_outcomes)
        if canonical_projection:
            # A scan-level outcome is authoritative.  Per-entry reports may
            # have been assembled before another entry completed the shared
            # validation future, so they are provenance only at this point.
            all_issues = [
                item
                for item in canonical_outcomes
                if str(item.get("candidate_disposition") or "").lower() == "confirmed"
            ]
            all_observations = [
                item
                for item in canonical_outcomes
                if str(item.get("candidate_disposition") or "").lower() == "needs_review"
            ]
            all_terminal_states = [
                {
                    key: value
                    for key, value in item.items()
                    if key != "issue" and value not in (None, "", [], {})
                }
                for item in canonical_outcomes
            ]
        elif final_by_cluster:
            all_observations = [
                item
                for item in all_observations
                if (
                    not item.get("validation_cluster_uid")
                    or str(
                        final_by_cluster.get(
                            str(item.get("validation_cluster_uid") or ""),
                            {},
                        ).get("candidate_disposition")
                        or ""
                    ).lower()
                    == "needs_review"
                )
            ]
            all_terminal_states = [
                item for item in all_terminal_states if not item.get("validation_cluster_uid")
            ]
            all_terminal_states.extend(final_records)
            all_observations.extend(
                ReportAssembler._unresolved_candidate_observations(
                    {"candidate_lifecycle_snapshot": ledger_snapshot},
                    list(all_issues) + list(all_observations),
                )
            )

        # Deduplicate confirmed issues with the same final-report semantics used
        # by single-entry reports. Observations stay programmatic to avoid an
        # extra batch LLM pass over needs_review-only material.
        interrupted = bool(getattr(self, "_interrupted", False))
        if canonical_projection:
            unique_issues = list(all_issues)
            semantic_dedup_summary = {
                "input_count": len(all_issues),
                "after_programmatic_count": len(all_issues),
                "final_count": len(all_issues),
                "llm_enabled": False,
                "canonical_projection": True,
            }
        else:
            unique_issues, semantic_dedup_summary = self._deduplicate_report_issues(
                all_issues,
                allow_llm=not interrupted,
            )
        review_observations = (
            list(all_observations)
            if canonical_projection
            else coalesce_review_observations(all_observations)
        )
        review_fingerprints = {
            str(item.get("validation_cluster_uid") or "") or str(item.get("candidate_uid") or "")
            for item in review_observations
        }
        non_review_observations = [
            item
            for item in all_observations
            if not (
                str(item.get("validation_cluster_uid") or "")
                or str(item.get("candidate_uid") or "")
            )
            in review_fingerprints
        ]
        unique_observations = (
            review_observations
            if canonical_projection
            else self._deduplicate_issues(non_review_observations) + review_observations
        )
        unique_terminal_states = [
            dict(item)
            for item in coalesce_terminal_candidates(all_terminal_states)
            if isinstance(item, dict)
        ]
        report_views = build_report_views(
            unique_issues,
            unique_observations,
            canonical_projection=canonical_projection,
        )
        view_summary = report_view_summary({"report_views": report_views})
        with_review_view = report_views.get("with_needs_review", {})

        diff_relevance_summary = self._diff_relevance_summary(unique_issues, unique_observations)
        diff_coverage = self._diff_coverage_metadata()
        global_validation_state = dict(getattr(self, "_global_validation_state", {}) or {})
        global_validation_duration = float(
            getattr(self, "_global_validation_duration_seconds", 0.0) or 0.0
        )
        fast_static_state = deepcopy(getattr(self, "_fast_static_scan_state", {}) or {})
        fast_funnel = fast_static_state.setdefault("candidate_funnel", {})
        terminal_counts = {
            "confirmed": 0,
            "rejected": 0,
            "needs_review": 0,
        }
        deduplicated_alias_count = 0
        unresolved_terminal_count = 0
        for outcome in canonical_outcomes:
            disposition = str(outcome.get("candidate_disposition") or "").lower()
            if disposition == "confirmed":
                terminal_counts["confirmed"] += 1
            elif disposition in {"rejected_with_proof", "rejected_with_evidence"}:
                terminal_counts["rejected"] += 1
            elif disposition == "needs_review":
                terminal_counts["needs_review"] += 1
            elif disposition == "deduplicated_alias":
                # Alias records preserve the audit trail for an occurrence
                # already represented by another canonical validation group.
                # They are terminal, but are not themselves a group requiring
                # a second confirmed/rejected/review decision.
                deduplicated_alias_count += 1
            elif (
                disposition != "shadow_observation"
                and str(outcome.get("record_role") or "") != "operational_obligation"
            ):
                unresolved_terminal_count += 1
        fast_funnel.update(terminal_counts)
        fast_funnel["deduplicated_aliases"] = deduplicated_alias_count
        terminal_total = sum(terminal_counts.values())
        fast_funnel["terminal"] = terminal_total
        # ``dedup`` counts build-scoped candidate records while terminal
        # outcomes count canonical validation groups.  Several records may
        # intentionally share one group, so subtracting the two units invents
        # unresolved work.  The lifecycle projection itself is authoritative:
        # every canonical group must have one of the three terminal states.
        fast_funnel["unresolved_terminal"] = (
            unresolved_terminal_count
            if canonical_projection
            else int(int(fast_funnel.get("dedup", 0) or 0) > 0)
        )
        fast_funnel["terminal_count_unit"] = "canonical_validation_group"
        fast_funnel["dedup_count_unit"] = "build_scoped_candidate_record"
        validator_telemetry: Dict[str, Any] = {
            "raw_verdicts": {},
            "parsed_verdicts": {},
            "final_verdicts": {},
            "protocol_anomaly_count": 0,
            "fact_payload_count": 0,
            "edge_payload_count": 0,
            "catalog_ref_count": 0,
            "fact_edge_ref_count": 0,
            "readable_ref_count": 0,
            "empty_ref_count": 0,
            "decision_critical_omission_count": 0,
            "noncritical_truncation_downgrade_count": 0,
            "provider_request_count": 0,
            "provider_delta_count": 0,
            "provider_no_evidence_gain_count": 0,
            "provider_resolved_count": 0,
            "provider_proven_absent_count": 0,
            "provider_unsupported_count": 0,
            "provider_failure_count": 0,
            "evidence_gate_accepted_count": 0,
            "evidence_gate_blocked_count": 0,
            "evidence_gate_failure_reasons": {},
            "claim_replay_positive_count": 0,
            "claim_replay_counter_count": 0,
            "provider_payload_normalized_count": 0,
            "length_retry_count": 0,
            "repair_thinking_disabled_count": 0,
            "protocol_exhausted_count": 0,
            "score_role": "ranking_only",
        }
        for outcome in canonical_outcomes:
            final_verdict = str(outcome.get("model_verdict") or "unavailable")
            final_counts = validator_telemetry["final_verdicts"]
            final_counts[final_verdict] = final_counts.get(final_verdict, 0) + 1
            trail = outcome.get("validator_audit_trail")
            for audit in trail if isinstance(trail, list) else []:
                if not isinstance(audit, dict):
                    continue
                raw_verdict = str(audit.get("raw_verdict") or "unavailable")
                raw_counts = validator_telemetry["raw_verdicts"]
                raw_counts[raw_verdict] = raw_counts.get(raw_verdict, 0) + 1
                parsed_verdict = raw_verdict if audit.get("parsed") is True else "unparsed"
                parsed_counts = validator_telemetry["parsed_verdicts"]
                parsed_counts[parsed_verdict] = parsed_counts.get(parsed_verdict, 0) + 1
                if audit.get("protocol_error"):
                    validator_telemetry["protocol_anomaly_count"] += 1
                if audit.get("provider_payload_normalized") is True:
                    validator_telemetry["provider_payload_normalized_count"] += 1
                validator_telemetry["length_retry_count"] += int(
                    audit.get("length_retry_count", 0) or 0
                )
                if audit.get("repair_thinking_disabled") is True:
                    validator_telemetry["repair_thinking_disabled_count"] += 1
                if audit.get("protocol_exhausted") is True:
                    validator_telemetry["protocol_exhausted_count"] += 1
            gate = outcome.get("evidence_gate")
            if isinstance(gate, dict):
                gate_key = (
                    "evidence_gate_accepted_count"
                    if gate.get("accepted") is True
                    else "evidence_gate_blocked_count"
                )
                validator_telemetry[gate_key] += 1
                claim_kind = str(gate.get("claim_kind") or "")
                if claim_kind == "positive":
                    validator_telemetry["claim_replay_positive_count"] += 1
                elif claim_kind == "counter":
                    validator_telemetry["claim_replay_counter_count"] += 1
                failure_counts = validator_telemetry["evidence_gate_failure_reasons"]
                for failure in gate.get("failures") or []:
                    key = str(failure)
                    failure_counts[key] = int(failure_counts.get(key, 0) or 0) + 1
            readability = outcome.get("validator_evidence_readability")
            if isinstance(readability, dict):
                for key in (
                    "fact_payload_count",
                    "edge_payload_count",
                    "catalog_ref_count",
                    "fact_edge_ref_count",
                    "readable_ref_count",
                    "empty_ref_count",
                    "decision_critical_omission_count",
                ):
                    validator_telemetry[key] += int(readability.get(key) or 0)
            if outcome.get("model_verdict_before_context_check") and not outcome.get(
                "validator_decision_critical_omissions"
            ):
                validator_telemetry["noncritical_truncation_downgrade_count"] += 1
            pre_llm = outcome.get("validator_pre_llm_fact_resolution")
            if isinstance(pre_llm, dict):
                statuses = pre_llm.get("statuses")
                for status in statuses if isinstance(statuses, list) else []:
                    if not isinstance(status, dict):
                        continue
                    validator_telemetry["provider_request_count"] += 1
                    value = str(status.get("status") or "")
                    if status.get("evidence_delta_hash"):
                        validator_telemetry["provider_delta_count"] += 1
                    if value == "resolved":
                        validator_telemetry["provider_resolved_count"] += 1
                    elif value == "proven_absent":
                        validator_telemetry["provider_proven_absent_count"] += 1
                    elif value == "unsupported":
                        validator_telemetry["provider_unsupported_count"] += 1
                    elif value == "failed":
                        validator_telemetry["provider_failure_count"] += 1
        refs = int(validator_telemetry["fact_edge_ref_count"] or 0)
        requests = int(validator_telemetry["provider_request_count"] or 0)
        validator_telemetry["fact_edge_readability_rate"] = (
            round(
                int(validator_telemetry["readable_ref_count"] or 0) / refs,
                4,
            )
            if refs
            else 1.0
        )
        validator_telemetry["provider_delta_rate"] = (
            round(
                int(validator_telemetry["provider_delta_count"] or 0) / requests,
                4,
            )
            if requests
            else 1.0
        )
        fast_static_state["validator"] = validator_telemetry
        validator_sessions = int(global_validation_state.get("validator_session_count", 0) or 0)
        fast_admission = global_validation_state.get("fast_validation_admission")
        fast_admission = fast_admission if isinstance(fast_admission, dict) else {}
        validator_admitted = int(fast_admission.get("admitted", validator_sessions) or 0)
        fast_deferred = int(fast_admission.get("deferred_to_needs_review", 0) or 0)
        decision_ready = sum(
            1 for outcome in canonical_outcomes if outcome.get("validator_decision_ready") is True
        )
        validator_validated = sum(
            1 for outcome in canonical_outcomes if outcome.get("validator_validated") is True
        )
        fast_admission["decision_ready"] = decision_ready
        fast_admission["validator_validated"] = validator_validated
        fast_admission["decision_ready_equals_validated"] = decision_ready == validator_validated
        if fast_admission:
            fast_static_state["validator_admission"] = deepcopy(fast_admission)
        dedup_count = int(fast_funnel.get("dedup", 0) or 0)
        fast_funnel["llm"] = validator_sessions
        fast_funnel["validator_admitted"] = validator_admitted
        fast_funnel["decision_ready"] = decision_ready
        fast_funnel["validator_validated"] = validator_validated
        fast_funnel["fast_deferred_needs_review"] = fast_deferred
        # Deferred fast obligations are not deterministic rejections and must
        # not be mislabeled as V0 filtering.  They remain visible in the
        # explicit needs-review view while the default precision view stays
        # confirmed-only.
        fast_funnel["v0"] = max(0, dedup_count - validator_sessions - fast_deferred)
        active_discovery_state = dict(getattr(self, "_active_discovery_state", {}) or {})
        active_discovery_duration = float(
            active_discovery_state.get("duration_seconds", 0.0) or 0.0
        )
        total_duration += global_validation_duration
        total_duration += active_discovery_duration
        total_duration += float(
            (fast_static_state.get("timings_seconds") or {}).get("static_total", 0.0) or 0.0
        )
        batch_wall_seconds = round(float(getattr(self, "_last_batch_wall_seconds", 0.0) or 0.0), 2)
        effective_speedup = (total_duration / batch_wall_seconds) if batch_wall_seconds > 0 else 0.0
        worker_utilization = (
            effective_speedup / max(1, int(self.max_workers or 1))
            if batch_wall_seconds > 0
            else 0.0
        )
        validation_performance_summary = self._validation_performance_summary(current_results)
        va_candidate_coverage_summary = self._va_candidate_coverage_summary(results)
        entry_budget_summary = self._entry_budget_summary(current_results)
        llm_iteration_budget_summary = self._llm_iteration_budget_summary(current_results)
        scan_budget_summary = dict(getattr(self, "_last_scan_budget_metadata", {}) or {})
        llm_usage_summary = self._llm_usage_summary()
        scan_token_usage = scan_token_usage_snapshot(base_config) if base_config is not None else {}
        wiki_service = getattr(self, "project_knowledge_service", None)
        wiki_telemetry_fn = getattr(wiki_service, "telemetry_snapshot", None)
        wiki_telemetry = (
            wiki_telemetry_fn()
            if callable(wiki_telemetry_fn)
            else {
                "effective_mode": "off",
                "active_effective_mode": False,
                "resolution_count": 0,
                "wiki_resolution_count": 0,
                "source_fallback_count": 0,
                "none_count": 0,
                "knowledge_context_tokens": 0,
                "incremental_fact_count": 0,
                "wiki_context_injected": False,
                "selected_constraint_ids": {},
                "selected_source_ref_ids": {},
                "fallback_reasons": {},
            }
        )
        llm_usage_summary["scan_token_usage"] = scan_token_usage
        retained_prompt_tokens = sum(r.cumulative_prompt_tokens for r in current_results.values())
        retained_completion_tokens = sum(
            r.cumulative_completion_tokens for r in current_results.values()
        )
        retained_total_tokens = sum(r.cumulative_total_tokens for r in current_results.values())
        retained_prompt_tokens += int(
            global_validation_state.get("total_cumulative_prompt_tokens", 0) or 0
        )
        retained_completion_tokens += int(
            global_validation_state.get("total_cumulative_completion_tokens", 0) or 0
        )
        retained_total_tokens += int(
            global_validation_state.get("total_cumulative_total_tokens", 0) or 0
        )
        retained_prompt_tokens += int(
            active_discovery_state.get("cumulative_prompt_tokens", 0) or 0
        )
        retained_completion_tokens += int(
            active_discovery_state.get("cumulative_completion_tokens", 0) or 0
        )
        retained_total_tokens += int(active_discovery_state.get("cumulative_total_tokens", 0) or 0)
        total_context_tokens = sum(r.context_tokens for r in current_results.values()) + int(
            global_validation_state.get("total_context_tokens", 0) or 0
        )
        total_context_tokens += int(active_discovery_state.get("context_tokens", 0) or 0)
        response_prompt_tokens = int(llm_usage_summary.get("prompt_tokens") or 0)
        response_completion_tokens = int(llm_usage_summary.get("completion_tokens") or 0)
        response_total_tokens = int(llm_usage_summary.get("total_tokens") or 0)
        # A successful response supplies one authoritative triple, including
        # valid zero values. Retained counters are only a whole-triple fallback
        # when no response was observed, and already exclude historical work.
        has_response_usage = int(llm_usage_summary.get("successful_calls") or 0) > 0
        current_prompt_tokens, current_completion_tokens, current_total_tokens = (
            (response_prompt_tokens, response_completion_tokens, response_total_tokens)
            if has_response_usage
            else (retained_prompt_tokens, retained_completion_tokens, retained_total_tokens)
        )
        historical_cost_summary = {
            "accounting_scope": "historical_producer_work",
            "results": historical_costs,
            "totals": {
                metric: sum(item["metrics"][metric] for item in historical_costs)
                for metric in (
                    "duration_seconds",
                    "context_tokens",
                    "cumulative_prompt_tokens",
                    "cumulative_completion_tokens",
                    "cumulative_total_tokens",
                )
            },
        }
        engine_capabilities = {
            entry_key: (
                result.metadata.get("engine_capabilities")
                if isinstance(result.metadata, dict)
                else {}
            )
            for entry_key, result in results.items()
        }
        project_fact_state = dict(getattr(self, "_project_fact_pass_state", {}) or {})
        project_rule_counts = project_fact_state.get("rule_candidate_counts")
        if isinstance(project_rule_counts, dict):
            for dimension in ("by_engine", "by_rule"):
                values = project_rule_counts.get(dimension)
                if not isinstance(values, dict):
                    continue
                target = rule_candidate_counts[dimension]
                for key, value in values.items():
                    target[str(key)] = target.get(str(key), 0) + int(value or 0)
        if project_fact_state:
            engine_capabilities["__project_deterministic_fact_pass__"] = {
                "project_deterministic_fact_pass": {
                    "status": str(project_fact_state.get("status") or "complete"),
                    "active": bool(project_fact_state.get("enabled", False)),
                    "candidate_count": int(project_fact_state.get("candidate_count", 0) or 0),
                    "reachable_functions": int(
                        project_fact_state.get("reachable_functions", 0) or 0
                    ),
                    "analyzed_functions": int(project_fact_state.get("analyzed_functions", 0) or 0),
                    "unresolved_internal_functions": int(
                        project_fact_state.get("unresolved_internal_functions", 0) or 0
                    ),
                    "failures": list(project_fact_state.get("failures") or []),
                }
            }
        if fast_static_state:
            engine_capabilities["__fast_static_scan__"] = {
                "fast_static_scan": {
                    "schema": str(fast_static_state.get("schema") or "zscope.fast-static-scan.v1"),
                    "status": str(fast_static_state.get("status") or "not_run"),
                    "active": bool(fast_static_state.get("activated", False)),
                    "unique_function_instances": int(
                        fast_static_state.get("unique_function_instances", 0) or 0
                    ),
                    "local_analysis_executions": int(
                        fast_static_state.get("local_analysis_executions", 0) or 0
                    ),
                    "duplicate_local_executions": int(
                        fast_static_state.get("duplicate_local_executions", 0) or 0
                    ),
                    "graph_analysis_units": int(
                        fast_static_state.get("graph_analysis_units", 0) or 0
                    ),
                    "failures": list(fast_static_state.get("failures") or []),
                }
            }
        if active_discovery_state:
            engine_capabilities["__active_discovery__"] = {
                "security_semantic_map": {
                    "status": str(active_discovery_state.get("status") or "not_run"),
                    "active": bool(active_discovery_state.get("enabled", False)),
                    "profile": str(active_discovery_state.get("profile") or "fast"),
                    "planned_unit_count": int(
                        active_discovery_state.get("planned_unit_count", 0) or 0
                    ),
                    "completed_report_count": int(
                        active_discovery_state.get("completed_report_count", 0) or 0
                    ),
                    "hypothesis_count": int(active_discovery_state.get("hypothesis_count", 0) or 0),
                    "new_validation_group_count": int(
                        active_discovery_state.get("new_validation_group_count", 0) or 0
                    ),
                    "failures": list(active_discovery_state.get("failures") or []),
                }
            }
        error_result_count = sum(
            1
            for result in results.values()
            if bool(result.error) or str(result.verdict).lower() == "error"
        )

        rule_candidate_counts["by_engine"] = dict(
            sorted(rule_candidate_counts["by_engine"].items())
        )
        rule_candidate_counts["by_rule"] = dict(sorted(rule_candidate_counts["by_rule"].items()))
        rule_candidate_counts["total"] = sum(rule_candidate_counts["by_rule"].values())
        effective_rules = getattr(base_config, "effective_rules", None)
        global_validation_report = {
            "enabled": self._uses_scan_validation_queue(),
            "duration_seconds": round(global_validation_duration, 4),
            "unique_group_count": int(
                global_validation_state.get("validation_group_count", 0) or 0
            ),
            "raw_occurrence_count": int(
                global_validation_state.get("scan_level_raw_occurrence_count", 0) or 0
            ),
            "drained": bool(global_validation_state.get("validation_queue_drained", False)),
            "validator_session_count": int(
                global_validation_state.get("validator_session_count", 0) or 0
            ),
            "validator_api_call_count": int(
                global_validation_state.get("validator_api_call_count", 0) or 0
            ),
            "validator_turn_distribution": dict(
                global_validation_state.get("validator_turn_distribution") or {}
            ),
            "validator_prompt_tokens_by_stage": dict(
                global_validation_state.get("validator_prompt_tokens_by_stage") or {}
            ),
            "evidence_slice_token_count": int(
                global_validation_state.get("evidence_slice_token_count", 0) or 0
            ),
            "multi_turn_outlier_count": int(
                global_validation_state.get("multi_turn_outlier_count", 0) or 0
            ),
            "fact_request_count": int(
                global_validation_state.get("validator_fact_request_count", 0) or 0
            ),
            "fact_resolution_success_count": int(
                global_validation_state.get("validator_fact_resolution_success_count", 0) or 0
            ),
            "fact_resolution_success_rate": global_validation_state.get(
                "validator_fact_resolution_success_rate"
            ),
            "evidence_recheck_count": int(
                global_validation_state.get("validator_evidence_recheck_count", 0) or 0
            ),
            "targeted_investigation_count": int(
                global_validation_state.get("validator_targeted_investigation_count", 0) or 0
            ),
            "verdict_transitions": dict(
                global_validation_state.get("validator_verdict_transitions") or {}
            ),
        }
        combined_report = {
            "rule_catalog": (
                serialize_effective_rules(effective_rules) if effective_rules is not None else {}
            ),
            "rule_candidate_counts": rule_candidate_counts,
            "type": "parallel_analysis_report",
            "summary": {
                "functions_analyzed": len(results),
                "functions_scheduled": len(results),
                "functions_completed": len(results) - error_result_count,
                "functions_failed": error_result_count,
                "total_issues": len(unique_issues),
                "unique_issues": len(unique_issues),
                "audit_observations": len(unique_observations),
                "deferred_entry_count": len(getattr(self, "deferred_entry_candidates", []) or []),
                "needs_review_issues": int(
                    with_review_view.get("included_needs_review_count") or 0
                ),
                "total_issues_with_needs_review": int(
                    with_review_view.get("issue_count") or len(with_review_view.get("issues", []))
                ),
                "total_duration_seconds": round(total_duration, 2),
                "batch_wall_seconds": batch_wall_seconds,
                "total_context_tokens": total_context_tokens,
                "total_cumulative_prompt_tokens": current_prompt_tokens,
                "total_cumulative_completion_tokens": current_completion_tokens,
                "total_cumulative_total_tokens": current_total_tokens,
                "retained_entry_prompt_tokens": retained_prompt_tokens,
                "retained_entry_completion_tokens": retained_completion_tokens,
                "retained_entry_total_tokens": retained_total_tokens,
                "llm_usage": llm_usage_summary,
                "parallel_speedup": f"{effective_speedup:.2f}x observed (using {self.max_workers} workers)",
                "parallel_worker_utilization": round(worker_utilization, 4),
                "diff_relevance": diff_relevance_summary["issues"],
                "diff_coverage": diff_coverage.get("coverage_summary", {}),
                "validation_performance": validation_performance_summary,
                "global_validation_queue": dict(global_validation_report),
                "project_deterministic_fact_pass": project_fact_state,
                "fast_static_scan": fast_static_state,
                "mode_outcomes": dict(getattr(self, "_global_validation_state", {}).get("mode_outcomes", {})),
                "active_discovery": active_discovery_state,
                "benchmark_ablation": benchmark_ablation_metadata,
                "va_candidate_coverage": va_candidate_coverage_summary,
                "entry_budget": entry_budget_summary,
                "llm_iteration_budget": llm_iteration_budget_summary,
                "scan_budget": scan_budget_summary,
                "semantic_dedup": semantic_dedup_summary,
                "interrupted": interrupted,
            },
            "function_results": function_summaries,
            "issues": unique_issues,
            "issues_by_severity": self._group_by_severity(unique_issues),
            "report_views": report_views,
            "issues_with_needs_review": with_review_view.get("issues", []),
            "issues_by_severity_with_needs_review": with_review_view.get("issues_by_severity", {}),
            "candidate_terminal_states": unique_terminal_states,
            "metadata": {
                "run_id": batch_run_id,
                "repo": project_root,
                "project_id": project_id,
                "source_root": source_root,
                "commit_sha": next(
                    (
                        str(result.metadata.get("commit_sha") or "")
                        for result in results.values()
                        if isinstance(result.metadata, dict) and result.metadata.get("commit_sha")
                    ),
                    "",
                ),
                "config_hash": next(
                    (
                        str(result.metadata.get("config_hash") or "")
                        for result in results.values()
                        if isinstance(result.metadata, dict) and result.metadata.get("config_hash")
                    ),
                    "",
                ),
                "effective_rules_sha256": str(
                    getattr(
                        getattr(base_config, "rule_catalog_provenance", None),
                        "effective_sha256",
                        "",
                    )
                    or ""
                ),
                "rule_catalog": (
                    serialize_effective_rules(effective_rules)
                    if effective_rules is not None
                    else {}
                ),
                "rule_candidate_counts": rule_candidate_counts,
                "runtime_spec": (
                    dict(vars(getattr(base_config, "runtime_provenance", None)))
                    if getattr(base_config, "runtime_provenance", None) is not None
                    else {}
                ),
                "scan_depth": str(getattr(getattr(base_config, "scan", None), "depth", "fast")),
                "effective_scan": {
                    "depth": str(getattr(getattr(base_config, "scan", None), "depth", "fast")),
                    "depth_source": str(
                        getattr(
                            getattr(base_config, "scan", None),
                            "depth_source",
                            "default",
                        )
                        or "default"
                    ),
                    "rollout": rollout_runtime_policy(base_config),
                },
                "rollout": rollout_runtime_policy(base_config),
                "llm_usage": scan_token_usage,
                "audit_observation_count": len(unique_observations),
                "audit_observations": unique_observations,
                "report_view_summary": view_summary,
                "diff_relevance_summary": diff_relevance_summary,
                "diff_impact_coverage": diff_coverage,
                "context_tokens": total_context_tokens,
                "cumulative_prompt_tokens": current_prompt_tokens,
                "cumulative_completion_tokens": current_completion_tokens,
                "cumulative_total_tokens": current_total_tokens,
                "instance_recovery_costs": historical_cost_summary,
                "retained_entry_prompt_tokens": retained_prompt_tokens,
                "retained_entry_completion_tokens": retained_completion_tokens,
                "retained_entry_total_tokens": retained_total_tokens,
                "llm_usage": llm_usage_summary,
                "wiki_telemetry": wiki_telemetry,
                "validation_performance": validation_performance_summary,
                "global_validation_queue": dict(global_validation_report),
                "project_deterministic_fact_pass": project_fact_state,
                "fast_static_scan": fast_static_state,
                "mode_outcomes": dict(getattr(self, "_global_validation_state", {}).get("mode_outcomes", {})),
                "active_discovery": active_discovery_state,
                "benchmark_ablation": benchmark_ablation_metadata,
                "va_candidate_coverage_summary": va_candidate_coverage_summary,
                "entry_budget": entry_budget_summary,
                "llm_iteration_budget": llm_iteration_budget_summary,
                "scan_budget": scan_budget_summary,
                "engine_capabilities": engine_capabilities,
                "semantic_dedup_summary": semantic_dedup_summary,
                "interrupted": interrupted,
            },
        }
        apply_report_schema_v2(
            combined_report,
            state={
                "interrupted": interrupted,
                "any_failure": error_result_count > 0,
                "candidate_terminal_states": unique_terminal_states,
                "engine_capabilities": engine_capabilities,
                "canonical_outcome_projection": canonical_projection,
                "candidate_ledger_summary": ledger_snapshot.get("summary", {}),
                "llm_usage": scan_token_usage,
                "finding_root_v1_enabled": True,
                "same_site_aggregation_enabled": True,
                "finding_root_count": int(
                    canonical_projection_state.get("finding_root_count", 0) or 0
                ),
                "finding_root_alias_count": int(
                    canonical_projection_state.get("finding_root_alias_count", 0) or 0
                ),
                "aggregation_count": int(
                    canonical_projection_state.get("aggregation_count", 0) or 0
                ),
                "aggregation_alias_count": int(
                    canonical_projection_state.get("aggregation_alias_count", 0) or 0
                ),
                "budget_exhaustion_policy": str(
                    global_validation_state.get("budget_exhaustion_policy") or "observe"
                ),
                "validation_queue_drained": bool(
                    global_validation_state.get("validation_queue_drained", False)
                ),
                "validator_session_count": int(
                    global_validation_state.get("validator_session_count", 0) or 0
                ),
                "validator_api_call_count": int(
                    global_validation_state.get("validator_api_call_count", 0) or 0
                ),
                "validator_turn_distribution": dict(
                    global_validation_state.get("validator_turn_distribution") or {}
                ),
                "validator_prompt_tokens_by_stage": dict(
                    global_validation_state.get("validator_prompt_tokens_by_stage") or {}
                ),
                "evidence_slice_token_count": int(
                    global_validation_state.get("evidence_slice_token_count", 0) or 0
                ),
                "multi_turn_outlier_count": int(
                    global_validation_state.get("multi_turn_outlier_count", 0) or 0
                ),
                "snapshot_model_call_count": int(
                    global_validation_state.get("snapshot_model_call_count", 0) or 0
                ),
                "fact_query_cache_hit_count": int(
                    global_validation_state.get("fact_query_cache_hit_count", 0) or 0
                ),
            },
            issues=unique_issues,
            observations=unique_observations,
            metadata=combined_report["metadata"],
            entry_function="__batch__",
        )
        if benchmark_ablation_override is not None:
            combined_report["answer_material_present"] = False
            combined_report["release_eligible"] = False
            combined_report["formal_eligible"] = False
        from ..benchmarking.protocol import candidate_funnel

        combined_report["metadata"]["candidate_funnel"] = candidate_funnel(combined_report)
        from ..retrieval.build_context import scan_build_coverage

        build_coverage = scan_build_coverage(
            # Combined coverage describes the whole stored index: resolve a
            # scoped facade back to its base so a per-entry "instance" view can
            # never become the scan counts of the combined report.
            _unwrapped_coverage_source(getattr(self, "code_index", None))
        )
        if fast_static_state.get("enabled") is True:
            input_status = build_coverage.get("instance_input_status")
            input_status = input_status if isinstance(input_status, dict) else {}
            expected_instances = int(build_coverage.get("instances", 0) or 0)
            inputs_current = bool(expected_instances) and len(input_status) == expected_instances
            inputs_current = inputs_current and all(
                str(value) == "current" for value in input_status.values()
            )
            project_scan_complete = bool(
                fast_static_state.get("activated")
                and fast_static_state.get("completed_build_contexts")
                == fast_static_state.get("planned_build_contexts")
                and build_coverage.get("extraction_complete") is True
                and inputs_current
            )
            build_coverage["scan_complete"] = project_scan_complete
            if not project_scan_complete:
                reasons = list(build_coverage.get("reasons") or [])
                if "fast_project_scan_incomplete" not in reasons:
                    reasons.append("fast_project_scan_incomplete")
                build_coverage["reasons"] = reasons
                build_coverage["status"] = "partial"
            fast_static_state["build_coverage_qualified"] = bool(
                project_scan_complete
                and not fast_static_state.get("link_coverage", {}).get("uncovered_build_contexts")
                and not fast_static_state.get("link_coverage", {}).get("unclosed_edges")
            )
            fast_static_state["formal_qualified"] = bool(
                fast_static_state.get("formal_qualified")
                and fast_static_state["build_coverage_qualified"]
            )
            combined_report["summary"]["fast_static_scan"] = fast_static_state
            combined_report["metadata"]["fast_static_scan"] = fast_static_state
        combined_report["metadata"]["build_coverage"] = build_coverage
        from ..snapshots.policy import SNAPSHOT_CANDIDATE_POLICY_VERSION

        combined_report["metadata"]["snapshot_candidate_policy"] = SNAPSHOT_CANDIDATE_POLICY_VERSION
        semantic_result = getattr(self, "semantic_result", None)
        if semantic_result is not None:
            combined_report["metadata"][
                "semantic_contract_version"
            ] = semantic_result.contract_version
            combined_report["metadata"]["semantic_modeling"] = semantic_result.stats.to_dict()
            combined_report["metadata"][
                "semantic_snapshot_candidates"
            ] = semantic_result.suspicious_metrics
            if getattr(semantic_result, "demand_plan", None):
                combined_report["metadata"]["semantic_model_demand"] = deepcopy(
                    semantic_result.demand_plan
                )
            if semantic_result.partial:
                combined_report["completeness"] = "partial"
                combined_report["scan_outcome"] = "incomplete"
                combined_report.setdefault("run_manifest", {})["completeness"] = "partial"
                combined_report["run_manifest"]["scan_outcome"] = "incomplete"

        # Keep the exact post-validation projection available to the Markdown
        # renderer.  Entry results are deliberately only intermediate
        # provenance: the scan-level ledger may replace them with a canonical
        # confirmed/needs_review outcome after all workers have completed.
        self._last_combined_report = combined_report

        if output_path:
            from ..reporting.json_io import write_report_atomic

            write_report_atomic(output_path, combined_report)
            logger.info(f"Combined report saved to: {output_path}")

        return combined_report

    def _deferred_entry_terminal_states(
        self,
        project_id: str,
        project_root: str,
    ) -> List[Dict[str, Any]]:
        terminal: List[Dict[str, Any]] = []
        for candidate in getattr(self, "deferred_entry_candidates", []) or []:
            if not isinstance(candidate, dict):
                continue
            identity_payload = {
                "project": project_id,
                "function": candidate.get("function_name"),
                "file": FunctionEntry(
                    function_name=str(candidate.get("function_name") or ""),
                    file_path=str(candidate.get("file_path") or "") or None,
                ).normalized_file_path(Path(project_root)),
                "signature": candidate.get("signature"),
            }
            digest = hashlib.sha256(
                json.dumps(
                    identity_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()[:24]
            terminal.append(
                {
                    "candidate_schema_version": "zscope.entry-candidate.v1",
                    "candidate_uid": f"ENTRY_{digest}",
                    "candidate_disposition": "deferred_budget",
                    "status": "deferred_budget",
                    "deferred_reason": candidate.get("deferred_reason") or "entry_discovery_budget",
                    "function": candidate.get("function_name"),
                    "file": candidate.get("file_path"),
                    "signature": candidate.get("signature"),
                    "exposure": candidate.get("exposure"),
                }
            )
        return terminal

    def _validation_performance_summary(
        self,
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, Any]:
        keys = (
            "iterations",
            "tool_call_count",
            "validator_fast_path_attempted",
            "validator_fast_path_accepted",
            "validator_cache_hit",
            "validator_inflight_coalesced",
            "validation_group_count",
            "validation_group_merged_count",
            "prevalidation_decision_count",
            "deterministic_prevalidation_decision_count",
            "deterministic_prevalidation_confirmed_count",
            "deterministic_prevalidation_rejected_count",
            "deterministic_prevalidation_conflict_count",
            "validator_avoided_count",
            "clang_prevalidation_decision_count",
            "static_audit_observation_count",
            "static_suppressed_count",
        )
        summary: Dict[str, Any] = {key: 0 for key in keys}
        for result in results.values():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            raw_perf = metadata.get("validation_performance")
            perf: Dict[str, Any] = raw_perf if isinstance(raw_perf, dict) else {}
            for key in keys:
                try:
                    summary[key] += int(perf.get(key, 0) or 0)
                except (TypeError, ValueError):
                    continue
        raw_global_state = getattr(self, "_global_validation_state", {})
        global_state: Dict[str, Any] = (
            raw_global_state if isinstance(raw_global_state, dict) else {}
        )
        for key in keys:
            try:
                summary[key] += int(global_state.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
        raw_occurrences = int(global_state.get("scan_level_raw_occurrence_count", 0) or 0)
        scan_groups = int(global_state.get("validation_group_count", 0) or 0)
        grouped_aliases = max(0, raw_occurrences - scan_groups)
        if grouped_aliases:
            summary["validation_group_merged_count"] += grouped_aliases
        summary["scan_level_raw_occurrence_count"] = raw_occurrences
        summary["scan_level_grouped_alias_count"] = grouped_aliases
        # The eligibility denominator intentionally includes only occurrences
        # already assigned to a canonical validation cluster.  Legacy records
        # without a structural identity remain visible but cannot be counted as
        # safely coalescible work.
        eligible_occurrences = int(
            global_state.get("eligible_alias_occurrence_count", raw_occurrences) or 0
        )
        eligible_groups = int(global_state.get("eligible_validation_group_count", scan_groups) or 0)
        eligible_aliases = max(0, eligible_occurrences - eligible_groups)
        summary["eligible_alias_occurrence_count"] = eligible_occurrences
        summary["eligible_validation_group_count"] = eligible_groups
        summary["eligible_coalescing_rate"] = (
            round(eligible_aliases / eligible_occurrences, 4) if eligible_occurrences else 1.0
        )
        summary["all_occurrence_reduction_rate"] = (
            round(grouped_aliases / raw_occurrences, 4) if raw_occurrences else 1.0
        )
        eligible_duplicate_requests = int(
            global_state.get("eligible_duplicate_request_count", 0) or 0
        )
        coalesced_duplicate_requests = int(
            global_state.get("coalesced_duplicate_request_count", 0) or 0
        )
        summary["eligible_duplicate_request_count"] = eligible_duplicate_requests
        summary["coalesced_duplicate_request_count"] = coalesced_duplicate_requests
        summary["coalescing_hit_rate"] = (
            round(coalesced_duplicate_requests / eligible_duplicate_requests, 4)
            if eligible_duplicate_requests
            else 1.0
        )
        summary["cluster_fragmentation_by_reason"] = dict(
            global_state.get("cluster_fragmentation_by_reason") or {}
        )
        summary["structural_coalescing_rate"] = (
            round(grouped_aliases / raw_occurrences, 4) if raw_occurrences else 1.0
        )
        eligible = int(summary.get("validation_group_merged_count") or 0)
        reused = int(summary.get("validator_cache_hit") or 0)
        summary["validation_reuse_rate"] = (
            round(min(1.0, reused / eligible), 4) if eligible else 1.0
        )
        return summary

    @staticmethod
    def _entry_budget_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, Any]:
        budgeted = [
            result for result in results.values() if result.entry_budget_seconds is not None
        ]
        exceeded = [result for result in budgeted if result.entry_budget_exceeded]
        policies = sorted(
            {str(result.budget_exhaustion_policy or "observe") for result in results.values()}
        )
        return {
            "policy": policies[0] if len(policies) == 1 else "mixed",
            "measured_entry_count": len(results),
            "budgeted_entry_count": len(budgeted),
            "exceeded_entry_count": len(exceeded),
            "total_overrun_seconds": round(
                sum(result.entry_budget_overrun_seconds for result in exceeded),
                3,
            ),
            "max_overrun_seconds": round(
                max(
                    (result.entry_budget_overrun_seconds for result in exceeded),
                    default=0.0,
                ),
                3,
            ),
        }

    @staticmethod
    def _llm_iteration_budget_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, Any]:
        observations: List[Dict[str, Any]] = []
        exceeded_entries: set[str] = set()
        for entry_key, result in results.items():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            for raw in metadata.get("budget_observations", []) or []:
                if (
                    not isinstance(raw, dict)
                    or raw.get("kind") != "llm_iteration_budget"
                    or not raw.get("budget_reached")
                ):
                    continue
                item = dict(raw)
                item["entry_identity"] = result.entry_identity or entry_key
                observations.append(item)
                exceeded_entries.add(result.entry_identity or entry_key)
        return {
            "budget_reached_count": len(observations),
            "affected_entry_count": len(exceeded_entries),
            "hard_failure_count": sum(1 for item in observations if item.get("hard_failure")),
            "observations": observations,
        }

    def _begin_llm_usage_batch(self) -> None:
        # The constructor/factory start includes this run's earlier modeling
        # and Wiki work. Only a subsequent batch on this analyzer starts anew.
        if getattr(self, "_llm_usage_batch_started", False):
            self._llm_usage_baseline = _llm_client_usage_snapshots(self._shared_llm_clients)
        self._llm_usage_batch_started = True

    def _windowed_llm_usage_snapshot(
        self, client_id: int, lifetime: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            baselines = self._llm_usage_baseline
        except AttributeError:
            # Preserve the standalone projection helper for legacy callers
            # that did not construct an analyzer or open a batch.
            return lifetime
        baseline = baselines.get(client_id)
        counters = (
            "successful_calls",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "estimated_calls",
            "provider_reported_calls",
        )
        if baseline is None:
            # A newly substituted client has no measured start. Its lifetime
            # counters cannot prove how much belongs to the current batch.
            return {
                **{key: 0 for key in counters},
                "accounting_scope": "current_analyzer_batch_response_boundary",
                "accounting_gap": "client_added_after_usage_window_start",
                "lifetime_usage": lifetime,
            }
        snapshot: Dict[str, Any] = {
            key: max(0, int(lifetime.get(key) or 0) - int(baseline.get(key) or 0))
            for key in counters
        }
        calls = snapshot["successful_calls"]
        duration = max(
            0.0,
            float(lifetime.get("successful_call_wall_seconds_total") or 0.0)
            - float(baseline.get("successful_call_wall_seconds_total") or 0.0),
        )
        snapshot.update(
            {
                "accounting_scope": "current_analyzer_batch_response_boundary",
                "lifetime_usage": lifetime,
                "provider_usage_coverage": (
                    snapshot["provider_reported_calls"] / calls if calls else 0.0
                ),
                "successful_call_wall_seconds_total": duration,
                "successful_call_wall_seconds_mean": duration / calls if calls else 0.0,
            }
        )
        for suffix in ("p50", "p95", "max"):
            key = f"successful_call_wall_seconds_{suffix}"
            # Quantiles cannot be subtracted from cumulative summaries. Keep
            # prior lifetime values explicit instead of labeling them current.
            snapshot[key] = (
                0.0
                if not calls
                else (None if int(baseline.get("successful_calls") or 0) else lifetime.get(key))
            )
        return snapshot

    def _llm_usage_summary(self) -> Dict[str, Any]:
        """Aggregate response-boundary usage without losing cancelled entry work."""

        clients = getattr(self, "_shared_llm_clients", {}) or {}
        unique: Dict[int, Dict[str, Any]] = {}
        for ref, client in clients.items():
            client_id = id(client)
            row = unique.setdefault(
                client_id,
                {
                    "refs": [],
                    "client": client,
                },
            )
            row["refs"].append(str(ref))

        totals: Dict[str, Any] = {
            "successful_calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "estimated_calls": 0,
            "provider_reported_calls": 0,
        }
        per_client: List[Dict[str, Any]] = []
        call_wall_seconds_total = 0.0
        call_wall_seconds_p50 = 0.0
        call_wall_seconds_p95 = 0.0
        call_wall_seconds_max = 0.0
        wall_distribution_known = True
        for client_id, row in unique.items():
            snapshotter = getattr(row["client"], "usage_snapshot", None)
            if not callable(snapshotter):
                continue
            raw = snapshotter()
            lifetime = dict(raw) if isinstance(raw, dict) else {}
            snapshot = self._windowed_llm_usage_snapshot(client_id, lifetime)
            if any(
                snapshot.get(f"successful_call_wall_seconds_{suffix}") is None
                for suffix in ("p50", "p95", "max")
            ):
                wall_distribution_known = False
            for key in totals:
                totals[key] += int(snapshot.get(key) or 0)
            call_wall_seconds_total += float(
                snapshot.get("successful_call_wall_seconds_total") or 0.0
            )
            call_wall_seconds_p50 = max(
                call_wall_seconds_p50,
                float(snapshot.get("successful_call_wall_seconds_p50") or 0.0),
            )
            call_wall_seconds_p95 = max(
                call_wall_seconds_p95,
                float(snapshot.get("successful_call_wall_seconds_p95") or 0.0),
            )
            call_wall_seconds_max = max(
                call_wall_seconds_max,
                float(snapshot.get("successful_call_wall_seconds_max") or 0.0),
            )
            per_client.append(
                {
                    "llm_refs": sorted(set(row["refs"])),
                    **snapshot,
                }
            )

        successful_calls = totals["successful_calls"]
        totals["provider_usage_coverage"] = round(
            (totals["provider_reported_calls"] / successful_calls if successful_calls else 0.0),
            4,
        )
        totals["successful_call_wall_seconds_total"] = round(call_wall_seconds_total, 4)
        totals["successful_call_wall_seconds_mean"] = round(
            call_wall_seconds_total / successful_calls if successful_calls else 0.0,
            4,
        )
        # Benchmarks normally use one effective profile. For multiple clients these are
        # conservative maxima; per-client distributions remain available below.
        totals["successful_call_wall_seconds_p50"] = (
            round(call_wall_seconds_p50, 4) if wall_distribution_known else None
        )
        totals["successful_call_wall_seconds_p95"] = (
            round(call_wall_seconds_p95, 4) if wall_distribution_known else None
        )
        totals["successful_call_wall_seconds_max"] = (
            round(call_wall_seconds_max, 4) if wall_distribution_known else None
        )
        return {
            **totals,
            "accounting_scope": "successful_response_boundary",
            "usage_window": "current_analyzer_batch",
            "failed_or_disconnected_request_usage": "unknown",
            "per_client": per_client,
        }

    @staticmethod
    def _va_candidate_coverage_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for result in results.values():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            coverage = metadata.get("va_candidate_coverage_summary")
            if not isinstance(coverage, dict):
                continue
            for key, value in coverage.items():
                try:
                    summary[key] = summary.get(key, 0) + int(value or 0)
                except (TypeError, ValueError):
                    continue
        return summary

    @classmethod
    def _annotate_diff_relevance(
        cls,
        issue: Dict[str, Any],
        diff_focus: Optional[Dict[str, Any]],
    ) -> None:
        if not isinstance(diff_focus, dict) or diff_focus.get("mode") != "diff_impact":
            return
        relevance = cls._classify_diff_relevance(issue, diff_focus)
        label = {
            "incremental": "[增量]",
            "existing": "[存量]",
            "unknown": "[影响待确认]",
        }.get(relevance, "[影响待确认]")
        issue["diff_relevance"] = relevance
        issue["diff_relevance_label"] = label
        issue["diff_focus"] = cls._compact_diff_focus_for_issue(diff_focus)
        cls._prefix_issue_summary(issue, label)

    @classmethod
    def _classify_diff_relevance(
        cls,
        issue: Dict[str, Any],
        diff_focus: Dict[str, Any],
    ) -> str:
        changed_functions = diff_focus.get("changed_functions")
        if not isinstance(changed_functions, list):
            return "unknown"
        changed_names = {
            str(item.get("function_name") or "")
            for item in changed_functions
            if isinstance(item, dict)
        }
        issue_func = str(issue.get("function") or issue.get("func_name") or "")
        issue_file, issue_line = parse_issue_location(str(issue.get("location") or ""))
        if issue_func:
            if issue_file:
                for item in changed_functions:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("function_name") or "") != issue_func:
                        continue
                    if cls._same_report_path(issue_file, str(item.get("file_path") or "")):
                        return "incremental"
            elif issue_func in changed_names:
                return "incremental"

        if issue_file and issue_line is not None:
            for item in changed_functions:
                if not isinstance(item, dict):
                    continue
                changed_file = str(item.get("file_path") or "")
                changed_lines = item.get("changed_lines")
                if not isinstance(changed_lines, list):
                    continue
                if cls._same_report_path(issue_file, changed_file) and issue_line in {
                    int(line) for line in changed_lines if str(line).isdigit()
                }:
                    return "incremental"

        affected_path_nodes: Set[str] = set()
        affected_path_pairs: Set[tuple[str, str]] = set()
        saw_path_refs = False
        for path_item in diff_focus.get("affected_paths") or []:
            if not isinstance(path_item, dict):
                continue
            path = path_item.get("path")
            if isinstance(path, list):
                affected_path_nodes.update(str(node) for node in path if str(node))
            for ref in path_item.get("path_refs") or []:
                if not isinstance(ref, dict):
                    continue
                saw_path_refs = True
                ref_name = str(ref.get("function_name") or "")
                ref_file = str(ref.get("file_path") or "")
                if ref_name and ref_file:
                    affected_path_pairs.add((ref_name, ref_file))
        if issue_func and issue_file and affected_path_pairs:
            if any(
                name == issue_func and cls._same_report_path(issue_file, file_path)
                for name, file_path in affected_path_pairs
            ):
                return "incremental"
        elif (
            issue_func
            and issue_func in affected_path_nodes
            and (not issue_file or not saw_path_refs)
        ):
            return "incremental"
        if diff_focus.get("fallback_reasons"):
            return "unknown"
        return "existing"

    @staticmethod
    def _same_report_path(left: str, right: str) -> bool:
        left_norm = str(left or "").replace("\\", "/").lstrip("./")
        right_norm = str(right or "").replace("\\", "/").lstrip("./")
        return bool(
            left_norm
            and right_norm
            and (
                left_norm == right_norm
                or left_norm.endswith("/" + right_norm)
                or right_norm.endswith("/" + left_norm)
            )
        )

    @staticmethod
    def _compact_diff_focus_for_issue(diff_focus: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "component": diff_focus.get("component", ""),
            "base_ref": diff_focus.get("base_ref", ""),
            "head_ref": diff_focus.get("head_ref", ""),
            "entry_function": diff_focus.get("entry_function", ""),
            "entry_exposure": diff_focus.get("entry_exposure", ""),
            "fallback_reasons": list(diff_focus.get("fallback_reasons") or []),
            "changed_functions": [
                {
                    "function_name": item.get("function_name", ""),
                    "file_path": item.get("file_path", ""),
                    "changed_lines": list(item.get("changed_lines") or []),
                }
                for item in diff_focus.get("changed_functions") or []
                if isinstance(item, dict)
            ],
        }

    @staticmethod
    def _prefix_issue_summary(issue: Dict[str, Any], label: str) -> None:
        for key in ("title", "summary", "description"):
            value = issue.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            if (
                value.startswith("[增量]")
                or value.startswith("[存量]")
                or value.startswith("[影响待确认]")
            ):
                return
            issue[key] = f"{label} {value}"
            return
        issue["summary"] = label

    @staticmethod
    def _diff_relevance_summary(
        issues: List[Dict[str, Any]],
        observations: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, int]]:
        def count(items: List[Dict[str, Any]]) -> Dict[str, int]:
            result = {"incremental": 0, "existing": 0, "unknown": 0, "unscoped": 0}
            for item in items:
                relevance = str(item.get("diff_relevance") or "unscoped")
                if relevance not in result:
                    relevance = "unknown"
                result[relevance] += 1
            return result

        return {"issues": count(issues), "audit_observations": count(observations)}

    def _diff_coverage_metadata(self) -> Dict[str, Any]:
        if not hasattr(self, "base_config"):
            return {}
        project = getattr(self.base_config, "project", None)
        entry_list = getattr(project, "entry_functions_list", None)
        if not entry_list:
            return {}
        path = Path(entry_list)
        if not path.exists() or not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("Unable to read diff coverage metadata from %s: %s", path, exc)
            return {}
        diff_impact = data.get("diff_impact") if isinstance(data, dict) else None
        if not isinstance(diff_impact, dict):
            return {}
        return {
            "coverage_summary": diff_impact.get("coverage_summary") or {},
            "function_coverage": diff_impact.get("function_coverage") or [],
            "analysis_obligations": diff_impact.get("analysis_obligations") or [],
        }

    @staticmethod
    def _markdown_report_status(issue: Dict[str, Any]) -> str:
        """Return one stable display status for final-report issue projections."""
        status = str(issue.get("validation_status") or "").strip().lower()
        if status:
            return status
        disposition = str(issue.get("candidate_disposition") or "").strip().lower()
        if disposition == "confirmed":
            return "validated"
        if disposition == "needs_review":
            return "needs_review"
        finding_kind = str(issue.get("finding_kind") or "").strip().lower()
        return "needs_review" if finding_kind == "needs_review" else ""

    @staticmethod
    def _markdown_issue_entry(issue: Dict[str, Any]) -> str:
        """Choose the human-facing entry label carried by a final issue."""
        for key in ("analyzed_from", "function", "entry_function", "entry_identity"):
            value = str(issue.get(key) or "").strip()
            if value:
                return value
        return "unknown"

    def _generate_markdown_from_combined_report(
        self, report: Dict[str, Any], output_path: Path
    ) -> str:
        """Render Markdown from the same final projection written as JSON.

        The old renderer consumed ``ParallelAnalysisResult`` objects directly.
        Those objects can be assembled before the shared validation queue
        closes, so they are not authoritative for final dispositions.  This
        renderer intentionally consumes only the post-schema combined report.
        """
        summary_value = report.get("summary")
        summary = summary_value if isinstance(summary_value, dict) else {}
        metadata_value = report.get("metadata")
        metadata = metadata_value if isinstance(metadata_value, dict) else {}
        raw_issues = report.get("issues")
        issues = (
            [item for item in raw_issues if isinstance(item, dict)]
            if isinstance(raw_issues, list)
            else []
        )

        raw_review_items = metadata.get("audit_observations")
        review_items = (
            [item for item in raw_review_items if isinstance(item, dict)]
            if isinstance(raw_review_items, list)
            else []
        )
        if not review_items:
            review_view = (
                report.get("report_views", {}).get("with_needs_review", {})
                if isinstance(report.get("report_views"), dict)
                else {}
            )
            raw_view_issues = review_view.get("issues") if isinstance(review_view, dict) else []
            review_items = (
                [
                    item
                    for item in raw_view_issues
                    if isinstance(item, dict)
                    and self._markdown_report_status(item)
                    in {"needs_review", "uncertain", "unvalidated"}
                ]
                if isinstance(raw_view_issues, list)
                else []
            )
        # Keep Markdown aligned with the report's displayed review view while
        # avoiding confirmed findings duplicated into that view.
        review_items = [
            item
            for item in review_items
            if self._markdown_report_status(item) in {"needs_review", "uncertain", "unvalidated"}
        ]

        raw_function_results = report.get("function_results")
        function_results = (
            [item for item in raw_function_results if isinstance(item, dict)]
            if isinstance(raw_function_results, list)
            else []
        )
        if not function_results:
            function_results = [
                {
                    "function": result.function_name,
                    "entry_identity": result.entry_identity,
                    "entry_key": key,
                    "verdict": result.verdict,
                }
                for key, result in sorted(getattr(self, "_last_markdown_results", {}).items())
            ]

        def belongs_to(item: Dict[str, Any], function_result: Dict[str, Any]) -> bool:
            aliases = {
                str(function_result.get(key) or "").strip()
                for key in ("function", "entry_identity", "entry_key", "entry_file_path")
                if str(function_result.get(key) or "").strip()
            }
            values = {
                str(item.get(key) or "").strip()
                for key in (
                    "analyzed_from",
                    "function",
                    "entry_function",
                    "entry_identity",
                    "reported_from_entry",
                    "entry_key",
                    "entry_file_path",
                )
                if str(item.get(key) or "").strip()
            }
            return bool(aliases.intersection(values))

        function_rows: List[Dict[str, Any]] = []
        for item in function_results:
            matched_issues = [issue for issue in issues if belongs_to(issue, item)]
            matched_review = [review for review in review_items if belongs_to(review, item)]
            display_verdict = str(item.get("verdict") or "unknown")
            if matched_issues:
                display_verdict = "issues_found"
            elif matched_review and display_verdict == "no_issue_found":
                display_verdict = "needs_review"
            function_rows.append(
                {
                    "item": item,
                    "issues": matched_issues,
                    "review": matched_review,
                    "verdict": display_verdict,
                }
            )

        functions_analyzed = int(summary.get("functions_analyzed") or len(function_results))
        issues_found = len(issues)
        error_count = int(summary.get("functions_failed") or 0)
        no_issue_count = sum(row["verdict"] == "no_issue_found" for row in function_rows)
        deferred_count = int(summary.get("deferred_entry_count") or 0)
        completeness = str(
            report.get("completeness")
            or ("incomplete" if error_count or deferred_count else "complete")
        )

        md = [
            "# Z-SCOPE Batch Analysis Report",
            "",
            "## Summary",
            f"- **Completeness**: {completeness}",
            f"- **Functions Analyzed**: {functions_analyzed}",
            f"- **Issues Found**: {issues_found}",
            f"- **No Issues Found**: {no_issue_count}",
            f"- **Errors**: {error_count}",
            f"- **Total Issues Detected**: {int(summary.get('total_issues') or issues_found)}",
            f"- **Audit Observations**: {len(review_items)}",
            f"- **Deferred Entry Candidates**: {deferred_count}",
        ]
        funnel = metadata.get("mode_outcomes") or summary.get("mode_outcomes") or {}
        if funnel:
            md.extend(["", "## Mode Outcomes", "",
                "运行裁决数量；TP/FP、误拒和 precision/recall 由独立 benchmark 评分。", "",
                "| 阶段 | 确认 | 排除 | 未决 |", "|---|---:|---:|---:|",
                f"| 静态候选低成本裁决 | {funnel.get('cheap_confirmed', 0)} | {funnel.get('cheap_rejected', 0)} | {funnel.get('cheap_unresolved', 0)} |",
                f"| 自主 Validator 追加裁决 | {funnel.get('autonomous_confirmed', 0)} | {funnel.get('autonomous_rejected', 0)} | {funnel.get('autonomous_unresolved', 0)} |",
                "",
                f"静态候选：{funnel.get('static_candidates', 0)}；deep 额外候选：{funnel.get('deep_additional_candidates', 0)}，其中确认：{funnel.get('deep_additional_confirmed', 0)}。",
                f"自主调查成本：{funnel.get('autonomous_tokens', 0)} tokens / {funnel.get('autonomous_seconds', 0):.2f}s；deep 发现：{funnel.get('discovery_tokens', 0)} tokens。",
            ])

        diff_coverage = metadata.get("diff_impact_coverage")
        coverage_summary = (
            diff_coverage.get("coverage_summary") if isinstance(diff_coverage, dict) else {}
        )
        if isinstance(coverage_summary, dict) and coverage_summary:
            md.extend(
                [
                    "",
                    "## Diff Impact Coverage",
                    f"- **Changed Functions**: {coverage_summary.get('changed_total', 0)}",
                    f"- **Scan Entries**: {coverage_summary.get('scan_entry_count', 0)}",
                    f"- **Covered By Scan**: {coverage_summary.get('covered_by_scan', 0)}",
                    f"- **Context Only**: {coverage_summary.get('context_only', 0)}",
                    f"- **Triage Only**: {coverage_summary.get('triage_only', 0)}",
                    f"- **Unresolved**: {coverage_summary.get('unresolved', 0)}",
                ]
            )

        md.extend(
            [
                "",
                "## Function Details",
                "",
                "| Function | Verdict | Issues | Needs Review / Audit | Duration |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for row in sorted(
            function_rows,
            key=lambda value: str(value["item"].get("function") or ""),
        ):
            item = row["item"]
            function_name = str(item.get("function") or item.get("entry_identity") or "unknown")
            duration = item.get("duration_seconds")
            duration_str = f"{float(duration):.1f}s" if duration not in (None, "") else "N/A"
            md.append(
                f"| {function_name} | {row['verdict']} | "
                f"{len(row['issues'])} | {len(row['review'])} / {len(row['review'])} | {duration_str} |"
            )

        def append_issue(md_lines: List[str], issue: Dict[str, Any], index: int) -> None:
            impact = str(issue.get("impact_level", "UNKNOWN")).upper()
            confidence = issue.get("confidence", "N/A")
            if isinstance(confidence, float):
                confidence = f"{confidence:.2f}"
            md_lines.extend(
                [
                    f"#### {index}. [{impact}] {issue.get('id', f'ISSUE_{index}')}: {issue.get('function', 'N/A')}",
                    f"- **Location**: `{issue.get('location', 'N/A')}`",
                    f"- **Confidence**: `{confidence}`",
                    f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                ]
            )
            snippet = issue.get("code_snippet")
            if snippet:
                md_lines.append(
                    f"- **Relevant Code**:\n```c\n{self._normalize_md_text(snippet)}\n```"
                )
            md_lines.append(
                f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}"
            )
            if issue.get("reasoning"):
                md_lines.append(
                    f"- **Analysis Reasoning**: {self._normalize_md_text(issue.get('reasoning'))}"
                )
            md_lines.append(
                f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}"
            )
            md_lines.append(
                f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}"
            )
            status = self._markdown_report_status(issue)
            if status:
                status_emoji = {
                    "validated": "✅",
                    "needs_review": "🟡",
                    "rejected": "❌",
                    "pending": "⏳",
                    "unvalidated": "⚠️",
                }.get(status, "")
                md_lines.append(f"- **Validation Status**: {status_emoji} {status}")
            if issue.get("validation_reasoning"):
                md_lines.append(
                    f"- **Validation Reasoning**: {self._normalize_md_text(issue.get('validation_reasoning'))}"
                )
            if issue.get("llm_explanation"):
                md_lines.append(
                    f"- **决策解释**: {self._normalize_md_text(issue.get('llm_explanation'))}"
                )
            md_lines.append("")

        md.extend(["", "## Detected Issues", ""])
        if not issues:
            md.append("*No issues detected.*")
        else:
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for issue in issues:
                if self._markdown_report_status(issue) == "rejected":
                    continue
                grouped.setdefault(self._markdown_issue_entry(issue), []).append(issue)
            if not grouped:
                md.append("*No issues detected.*")
            for entry, entry_issues in sorted(grouped.items()):
                md.extend([f"### Entry Function: `{entry}`", ""])
                for index, issue in enumerate(entry_issues, 1):
                    append_issue(md, issue, index)

        md.extend(["", "## Needs Review Findings", ""])
        if not review_items:
            md.append("*No needs_review observations.*")
        else:
            grouped_review: Dict[str, List[Dict[str, Any]]] = {}
            for item in review_items:
                grouped_review.setdefault(self._markdown_issue_entry(item), []).append(item)
            for entry, entry_issues in sorted(grouped_review.items()):
                md.extend([f"### Entry Function: `{entry}`", ""])
                for index, issue in enumerate(entry_issues, 1):
                    append_issue(md, issue, index)

        content = "\n".join(md)
        output_path.write_text(content, encoding="utf-8")
        logger.info("Markdown report saved to: %s", output_path)
        return content

    def generate_combined_markdown_report(
        self, results: Dict[str, ParallelAnalysisResult], output_path: Path
    ) -> str:
        """
        Generate a human-readable Markdown report for batch analysis.

        Args:
            results: Dict of function name to analysis result
            output_path: Path to save combined report

        Returns:
            Markdown report content
        """
        self._last_markdown_results = results
        combined_report = getattr(self, "_last_combined_report", None)
        if isinstance(combined_report, dict):
            return self._generate_markdown_from_combined_report(combined_report, output_path)

        # Preserve the standalone helper behavior for callers that render a
        # Markdown report without first generating the combined JSON report.
        summary = {
            "total": len(results),
            "issues_found": sum(1 for r in results.values() if r.verdict == "issues_found"),
            "no_issue": sum(1 for r in results.values() if r.verdict == "no_issue_found"),
            "error": sum(1 for r in results.values() if r.verdict == "error"),
            "total_issues": sum(len(r.issues) for r in results.values()),
            "audit_observations": sum(len(r.audit_observations) for r in results.values()),
            "deferred_entries": len(getattr(self, "deferred_entry_candidates", []) or []),
        }
        incomplete = bool(summary["error"] or summary["deferred_entries"]) or any(
            str(item.get("candidate_disposition") or "").lower()
            in {"deferred_budget", "engine_failed"}
            for result in results.values()
            for item in result.candidate_terminal_states
            if isinstance(item, dict)
        )

        md = [
            "# Z-SCOPE Batch Analysis Report",
            "",
            "## Summary",
            f"- **Completeness**: {'incomplete' if incomplete else 'complete'}",
            f"- **Functions Analyzed**: {summary['total']}",
            f"- **Issues Found**: {summary['issues_found']}",
            f"- **No Issues Found**: {summary['no_issue']}",
            f"- **Errors**: {summary['error']}",
            f"- **Total Issues Detected**: {summary['total_issues']}",
            f"- **Audit Observations**: {summary['audit_observations']}",
            f"- **Deferred Entry Candidates**: {summary['deferred_entries']}",
        ]

        diff_coverage = self._diff_coverage_metadata()
        coverage_summary = (
            diff_coverage.get("coverage_summary") if isinstance(diff_coverage, dict) else {}
        )
        if isinstance(coverage_summary, dict) and coverage_summary:
            md.extend(
                [
                    "",
                    "## Diff Impact Coverage",
                    f"- **Changed Functions**: {coverage_summary.get('changed_total', 0)}",
                    f"- **Scan Entries**: {coverage_summary.get('scan_entry_count', 0)}",
                    f"- **Covered By Scan**: {coverage_summary.get('covered_by_scan', 0)}",
                    f"- **Context Only**: {coverage_summary.get('context_only', 0)}",
                    f"- **Triage Only**: {coverage_summary.get('triage_only', 0)}",
                    f"- **Unresolved**: {coverage_summary.get('unresolved', 0)}",
                ]
            )
            not_root = [
                item
                for item in diff_coverage.get("function_coverage", [])
                if isinstance(item, dict)
                and str(item.get("coverage_status") or "") != "scanned_as_root"
            ]
            if not_root:
                md.extend(
                    [
                        "",
                        "| Function | Coverage | Scan Entry | Reason |",
                        "| :--- | :--- | :--- | :--- |",
                    ]
                )
                for item in not_root[:20]:
                    md.append(
                        "| "
                        f"`{item.get('function_name', '')}` | "
                        f"{item.get('coverage_status', '')} | "
                        f"`{item.get('scan_entry', '')}` | "
                        f"{item.get('reason', '')} |"
                    )
                if len(not_root) > 20:
                    md.append(f"| ... | ... | ... | +{len(not_root) - 20} more |")

        md.extend(
            [
                "",
                "## Function Details",
                "",
                "| Function | Verdict | Issues | Needs Review / Audit | Duration |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )

        for name, res in sorted(results.items()):
            duration_str = f"{res.duration_seconds:.1f}s" if res.duration_seconds else "N/A"
            display_name = (
                res.function_name if name == res.function_name else f"{res.function_name} ({name})"
            )
            needs_review_count = sum(
                1
                for issue in res.audit_observations
                if str(issue.get("validation_status") or "").lower() == "needs_review"
            )
            md.append(
                f"| {display_name} | {res.verdict} | {len(res.issues)} | "
                f"{needs_review_count} / {len(res.audit_observations)} | {duration_str} |"
            )

        md.append("")
        md.append("## Detected Issues")
        md.append("")

        # Group issues by analyzed_from (entry function)
        issues_by_entry = {}
        for entry_key, r in results.items():
            if r.verdict == "issues_found":
                issues_by_entry[entry_key] = r.issues

        if not issues_by_entry:
            md.append("*No issues detected.*")
        else:
            for entry_func, issues in sorted(issues_by_entry.items()):
                md.append(f"### Entry Function: `{entry_func}`")
                md.append("")

                # Simple deduplication per entry if needed
                seen_in_entry = set()

                for idx, issue in enumerate(issues, 1):
                    # Skip rejected issues in offline markdown report
                    if issue.get("validation_status") == "rejected":
                        continue

                    issue_key = (
                        f"{issue.get('location', 'N/A')}:{issue.get('description', '')[:50]}"
                    )
                    if issue_key in seen_in_entry:
                        continue
                    seen_in_entry.add(issue_key)

                    impact = str(issue.get("impact_level", "UNKNOWN")).upper()
                    conf = issue.get("confidence", "N/A")
                    if isinstance(conf, float):
                        conf = f"{conf:.2f}"

                    snippet = issue.get("code_snippet")
                    md.extend(
                        [
                            f"#### {idx}. [{impact}] {issue.get('id', f'ISSUE_{idx}')}: {issue.get('function', 'N/A')}",
                            f"- **Location**: `{issue.get('location', 'N/A')}`",
                            f"- **Confidence**: `{conf}`",
                            f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                        ]
                    )
                    if snippet:
                        md.append(
                            f"- **Relevant Code**:\n```c\n{self._normalize_md_text(snippet)}\n```"
                        )

                    md.append(
                        f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}"
                    )

                    # Add reasoning if present
                    reasoning = issue.get("reasoning")
                    if reasoning:
                        md.append(f"- **Analysis Reasoning**: {self._normalize_md_text(reasoning)}")

                    md.append(
                        f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}"
                    )
                    md.append(
                        f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}"
                    )

                    # Add validation status and reasoning
                    val_status = issue.get("validation_status")
                    if val_status:
                        status_emoji = {
                            "validated": "✅",
                            "rejected": "❌",
                            "pending": "⏳",
                            "unvalidated": "⚠️",
                        }.get(val_status, "")
                        md.append(f"- **Validation Status**: {status_emoji} {val_status}")

                        val_reasoning = issue.get("validation_reasoning")
                        if val_reasoning:
                            md.append(
                                f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}"
                            )

                    if issue.get("llm_explanation"):
                        md.append(
                            f"- **决策解释**: {self._normalize_md_text(issue.get('llm_explanation'))}"
                        )

                    md.append("")

        needs_review_by_entry = {}
        for entry_key, r in results.items():
            review_items = [
                issue
                for issue in r.audit_observations
                if str(issue.get("validation_status") or "").lower() == "needs_review"
            ]
            if review_items:
                needs_review_by_entry[entry_key] = review_items

        md.append("")
        md.append("## Needs Review Findings")
        md.append("")
        if not needs_review_by_entry:
            md.append("*No needs_review observations.*")
        else:
            for entry_func, issues in sorted(needs_review_by_entry.items()):
                md.append(f"### Entry Function: `{entry_func}`")
                md.append("")
                for idx, issue in enumerate(issues, 1):
                    impact = str(issue.get("impact_level", "UNKNOWN")).upper()
                    conf = issue.get("confidence", "N/A")
                    if isinstance(conf, float):
                        conf = f"{conf:.2f}"
                    md.extend(
                        [
                            f"#### {idx}. [{impact}] {issue.get('id', f'REVIEW_{idx}')}: {issue.get('function', 'N/A')}",
                            f"- **Location**: `{issue.get('location', 'N/A')}`",
                            f"- **Confidence**: `{conf}`",
                            f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                            f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}",
                            f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}",
                            f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}",
                        ]
                    )
                    val_reasoning = issue.get("validation_reasoning")
                    if val_reasoning:
                        md.append(
                            f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}"
                        )
                    if issue.get("llm_explanation"):
                        md.append(
                            f"- **决策解释**: {self._normalize_md_text(issue.get('llm_explanation'))}"
                        )
                    md.append("")

        content = "\n".join(md)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Markdown report saved to: {output_path}")
        return content

    def _deduplicate_issues(self, issues: List[Dict]) -> List[Dict]:
        """Remove duplicate issues based on canonical sink/root-cause evidence."""
        semantic_cfg = getattr(
            getattr(getattr(self, "base_config", None), "reporting", None), "semantic_dedup", None
        )
        if semantic_cfg is not None and getattr(semantic_cfg, "enabled", True):
            deduped, _summary = deduplicate_semantic_issues_programmatic(issues)
            return deduped
        return deduplicate_issues(issues)

    def _deduplicate_report_issues(
        self,
        issues: List[Dict[str, Any]],
        *,
        allow_llm: bool = True,
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Apply batch final-report semantic dedup, including LLM dedup when enabled."""
        semantic_cfg = getattr(
            getattr(getattr(self, "base_config", None), "reporting", None), "semantic_dedup", None
        )
        if semantic_cfg is None or not getattr(semantic_cfg, "enabled", True):
            deduped = deduplicate_issues(issues)
            return deduped, {
                "enabled": False,
                "input_issue_count": len(issues),
                "output_issue_count": len(deduped),
            }

        deduped, summary = deduplicate_semantic_issues_programmatic(issues)
        llm_configured = bool(getattr(semantic_cfg, "llm_enabled", False))
        llm_enabled = bool(llm_configured and allow_llm)
        summary.update(
            {
                "enabled": True,
                "llm_enabled": llm_enabled,
                "llm_configured": llm_configured,
                "input_issue_count": len(issues),
                "after_programmatic_issue_count": len(deduped),
            }
        )
        if llm_configured and not allow_llm:
            summary["llm_disabled_reason"] = "interrupted_fast_shutdown"
        if llm_enabled:
            deduped, llm_summary = self._deduplicate_report_clusters_with_llm(
                deduped,
                semantic_cfg=semantic_cfg,
            )
            summary.update(llm_summary)
        summary["output_issue_count"] = len(deduped)
        return deduped, summary

    def _deduplicate_report_clusters_with_llm(
        self,
        issues: List[Dict[str, Any]],
        *,
        semantic_cfg: Any,
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        max_cluster_size = max(2, int(getattr(semantic_cfg, "max_cluster_size", 8) or 8))
        threshold = float(getattr(semantic_cfg, "llm_confidence_threshold", 0.85) or 0.85)
        clusters: Dict[str, List[Dict[str, Any]]] = {}
        for issue in issues:
            for key in semantic_related_cluster_keys(issue):
                clusters.setdefault(key, []).append(issue)

        candidate_clusters: List[List[Dict[str, Any]]] = []
        seen_cluster_sets: Set[tuple[int, ...]] = set()
        prefilter_skipped = 0
        for group in clusters.values():
            for candidate_group in self._split_semantic_dedup_cluster(group, max_cluster_size):
                if len(candidate_group) < 2:
                    continue
                if not self._semantic_dedup_cluster_needs_llm(candidate_group):
                    prefilter_skipped += 1
                    continue
                cluster_ids = tuple(sorted(id(issue) for issue in candidate_group))
                if cluster_ids in seen_cluster_sets:
                    continue
                seen_cluster_sets.add(cluster_ids)
                candidate_clusters.append(candidate_group)

        summary: Dict[str, Any] = {
            "llm_candidate_cluster_count": len(candidate_clusters),
            "llm_clusters_called": 0,
            "llm_cache_hits": 0,
            "llm_merge_count": 0,
            "llm_suggestion_count": 0,
            "llm_rejected_merge_count": 0,
            "llm_failed_cluster_count": 0,
            "llm_prefilter_skipped_count": prefilter_skipped,
        }
        if not candidate_clusters:
            return issues, summary

        recon_agent = self._make_issue_reconciler_agent()
        if recon_agent is None:
            summary["llm_disabled_reason"] = "no_issue_reconciler_llm_client"
            return issues, summary

        self._assign_semantic_dedup_ids(issues)
        by_issue_id: Dict[str, Dict[str, Any]] = {}
        issue_order: List[str] = []
        issue_indices = {id(issue): index for index, issue in enumerate(issues)}
        for index, issue in enumerate(issues):
            issue_id = self._semantic_dedup_issue_id(issue, index)
            by_issue_id[issue_id] = issue
            issue_order.append(issue_id)

        cache = getattr(self, "_semantic_dedup_llm_cache", None)
        if cache is None:
            cache = {}
            self._semantic_dedup_llm_cache = cache

        removed: Set[str] = set()
        for cluster in candidate_clusters:
            active_cluster = [
                issue
                for issue in cluster
                if self._semantic_dedup_issue_id(issue, issue_indices.get(id(issue), 0))
                not in removed
            ]
            if len(active_cluster) < 2:
                continue
            cluster_payload = self._semantic_dedup_cluster_payload(active_cluster, issue_indices)
            cluster_fingerprint = self._semantic_dedup_cluster_fingerprint(cluster_payload)
            decision = cache.get(cluster_fingerprint)
            if decision is not None:
                summary["llm_cache_hits"] += 1
            else:
                response = recon_agent.run(cluster_payload)
                summary["llm_clusters_called"] += 1
                if not response.success or not isinstance(response.data, dict):
                    summary["llm_failed_cluster_count"] += 1
                    continue
                decision = response.data
                cache[cluster_fingerprint] = decision

            suggested, rejected = self._apply_llm_dedup_decision(
                decision,
                by_issue_id,
                removed,
                threshold=threshold,
            )
            summary["llm_suggestion_count"] += suggested
            summary["llm_rejected_merge_count"] += rejected

        result = [issue for issue_id, issue in zip(issue_order, issues) if issue_id not in removed]
        for issue in issues:
            issue.pop("_semantic_dedup_uid", None)
        return result, summary

    @staticmethod
    def _semantic_dedup_cluster_needs_llm(group: List[Dict[str, Any]]) -> bool:
        for left_index, left in enumerate(group):
            for right in group[left_index + 1 :]:
                if not ParallelAnalyzer._semantic_dedup_pair_needs_llm(left, right):
                    continue
                return True
        return False

    @staticmethod
    def _semantic_dedup_pair_needs_llm(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
        left_file, _ = parse_issue_location(str(left.get("location") or left.get("file") or ""))
        right_file, _ = parse_issue_location(str(right.get("location") or right.get("file") or ""))
        same_file = bool(
            left_file
            and right_file
            and normalize_issue_key_part(left_file) == normalize_issue_key_part(right_file)
        )
        left_funcs = {
            normalize_issue_key_part(str(value or ""))
            for value in (
                left.get("function"),
                left.get("sink_function"),
                left.get("entry_function"),
            )
            if value
        }
        right_funcs = {
            normalize_issue_key_part(str(value or ""))
            for value in (
                right.get("function"),
                right.get("sink_function"),
                right.get("entry_function"),
            )
            if value
        }
        same_function = bool(left_funcs & right_funcs)
        same_family = semantic_category_family(
            normalize_issue_category(
                str(
                    left.get("category")
                    or left.get("defect_class")
                    or left.get("subcategory")
                    or ""
                )
            )
        ) == semantic_category_family(
            normalize_issue_category(
                str(
                    right.get("category")
                    or right.get("defect_class")
                    or right.get("subcategory")
                    or ""
                )
            )
        )
        shared_resource_or_sink = bool(
            issue_resource_signature(left)
            and issue_resource_signature(left) == issue_resource_signature(right)
        ) or bool(
            issue_sink_signature(left) and issue_sink_signature(left) == issue_sink_signature(right)
        )
        return bool(same_family and ((same_file and same_function) or shared_resource_or_sink))

    @staticmethod
    def _split_semantic_dedup_cluster(
        group: List[Dict[str, Any]],
        max_cluster_size: int,
    ) -> List[List[Dict[str, Any]]]:
        if len(group) <= max_cluster_size:
            return [group]

        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for issue in group:
            bucket_key = (
                issue_resource_signature(issue)
                or issue_sink_signature(issue)
                or semantic_root_cause_key(issue)
                or str(issue.get("function") or issue.get("func_name") or "")
                or "fallback"
            )
            buckets.setdefault(bucket_key, []).append(issue)

        split: List[List[Dict[str, Any]]] = []
        for bucket in buckets.values():
            for start in range(0, len(bucket), max_cluster_size):
                chunk = bucket[start : start + max_cluster_size]
                if len(chunk) > 1:
                    split.append(chunk)
        return split

    def _make_issue_reconciler_agent(self) -> Any:
        config = getattr(self, "base_config", None)
        agents = (
            getattr(getattr(config, "project", None), "agents", []) if config is not None else []
        )
        recon_agent_cfg = next(
            (agent for agent in agents if getattr(agent, "name", "") == "issue_reconciler_agent"),
            None,
        )
        recon_llm_ref = getattr(recon_agent_cfg, "llm_ref", "") if recon_agent_cfg else ""
        recon_llm_ref = recon_llm_ref or "default"
        clients = getattr(self, "_shared_llm_clients", {}) or {}
        recon_client = clients.get(recon_llm_ref) or clients.get("default")
        if recon_client is None:
            logger.warning(
                "Batch semantic LLM dedup requested but no issue_reconciler_agent LLM client is configured."
            )
            return None

        from ..agents.issue_reconciler.agent import IssueReconcilerAgent

        return IssueReconcilerAgent(recon_client)

    @staticmethod
    def _semantic_dedup_issue_id(issue: Dict[str, Any], index: int) -> str:
        return str(
            issue.get("_semantic_dedup_uid")
            or issue.get("run_issue_uid")
            or issue.get("occurrence_uid")
            or issue.get("candidate_uid")
            or issue.get("candidate_id")
            or issue.get("dedup_key")
            or f"semantic_issue_{index}"
        )

    @staticmethod
    def _assign_semantic_dedup_ids(issues: List[Dict[str, Any]]) -> None:
        bases = []
        for index, issue in enumerate(issues):
            internal = (
                issue.get("run_issue_uid")
                or issue.get("occurrence_uid")
                or issue.get("candidate_uid")
                or issue.get("candidate_id")
                or issue.get("dedup_key")
            )
            if not internal:
                payload = {
                    "canonical": canonical_issue_key(issue),
                    "evidence_hash": issue.get("evidence_hash"),
                    "index": index,
                }
                internal = (
                    "SEM_"
                    + hashlib.sha256(
                        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
                    ).hexdigest()[:24]
                )
            bases.append(str(internal))
        counts = {base: bases.count(base) for base in set(bases)}
        for index, (issue, base) in enumerate(zip(issues, bases)):
            if counts[base] == 1:
                issue["_semantic_dedup_uid"] = base
                continue
            issue["_semantic_dedup_uid"] = str(
                issue.get("run_issue_uid") or issue.get("occurrence_uid") or f"{base}::{index}"
            )

    def _semantic_dedup_cluster_payload(
        self,
        cluster: List[Dict[str, Any]],
        issue_indices: Dict[int, int],
    ) -> Dict[str, Any]:
        compact_issues = []
        files = set()
        functions = set()
        resources = set()
        families = set()
        for issue in cluster:
            issue_id = self._semantic_dedup_issue_id(issue, issue_indices.get(id(issue), 0))
            compact = self._compact_issue_for_semantic_dedup(issue, issue_id)
            compact_issues.append(compact)
            if compact.get("file"):
                files.add(compact["file"])
            if compact.get("function"):
                functions.add(compact["function"])
            if compact.get("resource_signature"):
                resources.add(compact["resource_signature"])
            if compact.get("category_family"):
                families.add(compact["category_family"])
        cluster_id = self._semantic_dedup_cluster_fingerprint(
            {"issues": compact_issues, "mode": "deduplicate_cluster"}
        )
        return {
            "mode": "deduplicate_cluster",
            "cluster_id": cluster_id,
            "issues": compact_issues,
            "deterministic_hints": {
                "category_families": sorted(families),
                "same_file": len(files) <= 1,
                "same_function": len(functions) <= 1,
                "resource_signatures": sorted(resources),
            },
        }

    @staticmethod
    def _compact_issue_for_semantic_dedup(issue: Dict[str, Any], issue_id: str) -> Dict[str, Any]:
        location = str(issue.get("location") or issue.get("file") or "")
        file_path, _line = parse_issue_location(location)
        category = str(issue.get("category") or issue.get("subcategory") or "")
        return {
            "id": issue_id,
            "category": category,
            "category_family": semantic_category_family(category),
            "function": issue.get("function") or issue.get("func_name"),
            "file": file_path,
            "location": location,
            "root_cause": issue.get("root_cause"),
            "description": issue.get("description"),
            "positive_evidence": issue.get("positive_evidence"),
            "candidate_source": issue.get("candidate_source") or issue.get("finding_kind"),
            "resource_signature": issue_resource_signature(issue),
            "root_cause_key": semantic_root_cause_key(issue),
            "source": issue.get("source"),
            "sink": issue.get("sink") or issue.get("sink_function"),
            "call_path": issue.get("call_path"),
            "call_path_signature": issue_call_path_signature(issue),
            "sink_signature": issue_sink_signature(issue),
        }

    @staticmethod
    def _semantic_dedup_cluster_fingerprint(payload: Dict[str, Any]) -> str:
        stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _apply_llm_dedup_decision(
        decision: Dict[str, Any],
        by_issue_id: Dict[str, Dict[str, Any]],
        removed: Set[str],
        *,
        threshold: float,
    ) -> tuple[int, int]:
        applied = 0
        rejected = 0
        keep_distinct = {
            str(issue_id)
            for issue_id in decision.get("must_keep_distinct_issue_ids", [])
            if issue_id
        }
        groups = decision.get("duplicate_groups")
        if not isinstance(groups, list):
            return 0, 0
        for group in groups:
            if not isinstance(group, dict):
                continue
            primary_id = str(group.get("primary_issue_id") or "")
            primary = by_issue_id.get(primary_id)
            if primary is None or primary_id in removed:
                rejected += 1
                continue
            try:
                confidence = float(group.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                confidence = 0.0
            for duplicate_id in group.get("duplicate_issue_ids", []) or []:
                duplicate_id = str(duplicate_id or "")
                duplicate = by_issue_id.get(duplicate_id)
                if (
                    not duplicate_id
                    or duplicate is None
                    or duplicate_id == primary_id
                    or duplicate_id in removed
                    or duplicate_id in keep_distinct
                    or primary_id in keep_distinct
                ):
                    rejected += 1
                    continue
                structurally_equivalent = issues_may_share_root_cause(
                    primary,
                    duplicate,
                    confidence=confidence,
                    threshold=threshold,
                    allow_cross_function_root=True,
                )
                primary_cluster = str(primary.get("validation_cluster_uid") or "")
                duplicate_cluster = str(duplicate.get("validation_cluster_uid") or "")
                structurally_blocked = bool(
                    primary_cluster and duplicate_cluster and primary_cluster != duplicate_cluster
                )
                if not structurally_equivalent and not structurally_blocked:
                    rejected += 1
                    continue
                root_key = str(group.get("root_cause_key") or "") or semantic_root_cause_key(
                    primary
                )
                suggestion = {
                    "method": "issue_reconciler_agent_suggestion",
                    "root_cause_key": root_key,
                    "confidence": confidence,
                    "reasoning": group.get("reasoning"),
                    # A model may describe a possible relationship, but a
                    # distinct structured decision identity is an explicit
                    # no-merge boundary.  Preserve the suggestion for audit
                    # without allowing it to remove either finding.
                    "structural_merge_blocked": structurally_blocked,
                }
                primary.setdefault("dedup_cluster_suggestions", []).append(
                    {**suggestion, "role": "primary", "peer_issue_uid": duplicate_id}
                )
                duplicate.setdefault("dedup_cluster_suggestions", []).append(
                    {**suggestion, "role": "possible_alias", "peer_issue_uid": primary_id}
                )
                applied += 1
        return applied, rejected

    @staticmethod
    def _issue_rank(issue: Dict[str, Any]) -> tuple[int, int, int, int, float, int]:
        return issue_rank(issue)

    @classmethod
    def _canonical_issue_key(cls, issue: Dict[str, Any]) -> str:
        return canonical_issue_key(issue)

    @staticmethod
    def _normalize_issue_category(value: str) -> str:
        return normalize_issue_category(value)

    @staticmethod
    def _normalize_issue_key_part(value: Any) -> str:
        return normalize_issue_key_part(value)

    @classmethod
    def _flatten_issue_text(cls, value: Any) -> str:
        return flatten_issue_text(value)

    @staticmethod
    def _parse_issue_location(location: str) -> tuple[str, Optional[int]]:
        return parse_issue_location(location)

    def _group_by_severity(self, issues: List[Dict]) -> Dict[str, List[Dict]]:
        """Group issues by impact level."""
        groups: Dict[str, List[Dict[str, Any]]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        for issue in issues:
            level = issue.get("impact_level", "medium").lower()
            if level in groups:
                groups[level].append(issue)
            else:
                groups["medium"].append(issue)

        return groups
