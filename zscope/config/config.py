"""
Configuration management for Z-SCOPE.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

_yaml: Any
try:
    import yaml as _yaml
except ImportError:
    _yaml = None

yaml: Any = _yaml

logger = logging.getLogger(__name__)


SUPPORTED_PROJECT_LANGUAGES = {"auto", "c_cpp", "java"}


def normalize_project_language(value: Any, default: str = "auto") -> str:
    """Normalize public language aliases and reject ambiguous values."""

    text = str(value or default).strip().lower().replace("-", "_")
    aliases = {
        "c": "c_cpp",
        "cc": "c_cpp",
        "cpp": "c_cpp",
        "c++": "c_cpp",
        "javasrc": "java",
        "java_src": "java",
    }
    normalized = aliases.get(text, text)
    if normalized not in SUPPORTED_PROJECT_LANGUAGES:
        raise ValueError(f"Invalid project.language {value!r}; expected auto, c_cpp, or java")
    return normalized


def detect_project_language(source_root: Path) -> str:
    """Detect Java before C/C++, while preferring C/C++ for mixed repositories."""

    root = Path(source_root)
    java_markers = ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle")
    c_markers = ("compile_commands.json", "CMakeLists.txt", "Makefile", "meson.build")
    has_java_marker = any((root / marker).exists() for marker in java_markers)
    has_c_marker = any((root / marker).exists() for marker in c_markers)
    if has_c_marker:
        return "c_cpp"
    if has_java_marker:
        return "java"
    try:
        if next(root.rglob("*.c"), None) or next(root.rglob("*.cpp"), None):
            return "c_cpp"
        if next(root.rglob("*.java"), None):
            return "java"
    except OSError:
        pass
    return "c_cpp"


def _normalize_llm_base_urls(value: Any, default: str = "https://api.openai.com/v1") -> List[str]:
    if value is None:
        raw_items: List[Any] = [default]
    elif isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, list):
        raw_items = value
    else:
        raw_items = [value]

    urls: List[str] = []
    for item in raw_items:
        if isinstance(item, dict):
            item = item.get("url") or item.get("base_url")
        cleaned = str(item or "").strip().rstrip("/")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls or [default.rstrip("/")]


def _optional_positive_seconds(value: Any, default: Optional[float]) -> Optional[float]:
    """Parse a deadline once, preserving one-release legacy sentinel support.

    New configuration should use ``null`` for unlimited.  Legacy ``0``, ``-1``
    and ``"unlimited"`` are accepted here only so individual subsystems never
    assign conflicting meanings to them.
    """
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in {
        "",
        "none",
        "null",
        "unlimited",
    }:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid deadline value: {value!r}") from exc
    return seconds if seconds > 0 else None


def minimum_optional_positive_seconds(*values: Any) -> Optional[float]:
    """Return the strictest configured deadline, or ``None`` if all are unlimited."""

    parsed = [_optional_positive_seconds(value, None) for value in values if value is not None]
    positive = [value for value in parsed if value is not None]
    return min(positive) if positive else None


def _optional_positive_int(value: Any, default: Optional[int]) -> Optional[int]:
    """Parse an optional positive limit at the configuration boundary.

    ``null`` is the canonical unlimited value.  Legacy non-positive numbers
    and the string ``unlimited`` remain accepted for one release, but are
    normalized here so downstream schedulers never assign their own meaning.
    """

    if value is None:
        return default
    if isinstance(value, str) and value.strip().lower() in {
        "",
        "none",
        "null",
        "unlimited",
    }:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid positive integer limit: {value!r}") from exc
    return parsed if parsed > 0 else None


def _bounded_cache_entries(value: Any, default: int = 4096) -> int:
    """Normalize a bounded cache size; ``null`` means the cache is disabled."""

    if value is None:
        return 0
    if isinstance(value, str) and value.strip().lower() in {
        "",
        "none",
        "null",
        "disabled",
        "unlimited",
    }:
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid cache entry limit: {value!r}") from exc
    return parsed if parsed > 0 else 0


def _normalize_budget_exhaustion_policy(value: Any) -> str:
    """Normalize runtime budgets to observability-only semantics.

    Budgets are tuning signals, not cancellation authority.  Legacy
    ``cancel``/``hard`` spellings remain accepted for one release, but are
    deliberately mapped to ``observe`` so an available LLM cannot be turned
    into an entry failure merely by exhausting a local budget.
    """

    normalized = str(value or "observe").strip().lower().replace("-", "_")
    aliases = {
        "observe": "observe",
        "observe_only": "observe",
        "soft": "observe",
        "cancel": "observe",
        "hard": "observe",
        "enforce": "observe",
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise ValueError(
            "Invalid budget_exhaustion_policy "
            f"{value!r}; expected 'observe' (legacy cancel/hard are accepted "
            "as observe-only aliases)."
        ) from exc


@dataclass
class LLMConfig:
    """Configuration for LLM client."""

    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    base_urls: List[str] = field(default_factory=list)
    base_url_rate_limit_per_minute: Optional[int] = None
    base_url_max_concurrent_requests: Optional[int] = None
    models: List[str] = field(default_factory=list)
    max_tokens: int = 4096
    timeout: Optional[float] = 120.0
    max_retries: int = 2
    retry_until_available: bool = False
    supports_structured_output: bool = False

    def __post_init__(self) -> None:
        self.base_urls = _normalize_llm_base_urls(self.base_urls or self.base_url)
        self.base_url = self.base_urls[0]
        self.base_url_rate_limit_per_minute = _optional_positive_int(
            self.base_url_rate_limit_per_minute,
            None,
        )
        self.base_url_max_concurrent_requests = _optional_positive_int(
            self.base_url_max_concurrent_requests,
            None,
        )
        self.timeout = _optional_positive_seconds(self.timeout, 120.0)


@dataclass
class AgentConfig:
    """Configuration for a specific agent."""

    name: str
    task: Optional[str] = None
    enabled: bool = True
    llm_ref: Optional[str] = None
    skills: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    mcp_servers: List[str] = field(default_factory=list)
    can_spawn_subagents: Optional[bool] = None
    entry_custom_prompt: Optional[str] = None


@dataclass
class EntryDiscoveryConfig:
    """Configuration for automatic entry-point discovery."""

    enabled: bool = False
    max_entries: int = 200
    max_functions: int = 10000
    interface_files: List[str] = field(default_factory=list)
    search_root: Optional[Path] = None


@dataclass
class WikiConfig:
    """Public project Wiki controls; off remains the compatibility default."""

    mode: str = "off"  # off | build_only | shadow | active
    auto_maintain: bool = False
    state_dir: str = ".zscope_knowledge/wiki"
    compiler_enabled: bool = True
    document_exclude: List[str] = field(default_factory=list)
    explanatory_overrides: List[str] = field(default_factory=list)
    generated_overrides: List[str] = field(default_factory=list)
    max_file_bytes: int = 10 * 1024 * 1024
    max_files: int = 10_000
    max_total_bytes: int = 100 * 1024 * 1024
    # Wiki-local limits are opt-in. ``None`` means unlimited; the ordinary
    # LLM profile max_tokens remains the physical request ceiling.
    compiler_max_tokens: Optional[int] = None
    max_wall_seconds: Optional[int] = None
    max_constraints: Optional[int] = None

    def __post_init__(self) -> None:
        self.mode = str(self.mode or "off").strip().lower().replace("-", "_")
        if self.mode not in {"off", "build_only", "shadow", "active"}:
            raise ValueError("project.wiki.mode must be off, build_only, shadow, or active")
        self.state_dir = str(self.state_dir or ".zscope_knowledge/wiki").strip()
        if (
            not self.state_dir
            or Path(self.state_dir).is_absolute()
            or ".." in Path(self.state_dir).parts
        ):
            raise ValueError("project.wiki.state_dir must be project-root relative")
        self.max_file_bytes = int(self.max_file_bytes)
        self.max_files = int(self.max_files)
        self.max_total_bytes = int(self.max_total_bytes)
        self.compiler_max_tokens = _optional_positive_int(self.compiler_max_tokens, None)
        self.max_wall_seconds = _optional_positive_int(self.max_wall_seconds, None)
        self.max_constraints = _optional_positive_int(self.max_constraints, None)
        if min(self.max_file_bytes, self.max_files, self.max_total_bytes) <= 0:
            raise ValueError("project.wiki limits must be positive")


@dataclass
class ReviewMemoryConfig:
    mode: str = "off"
    state_dir: str = ".zscope/review-memory"
    project_scope: str = "project"
    extraction: str = "auto_extract"
    llm_enabled: bool = True
    max_patterns_per_finding: int = 3
    max_context_tokens: int = 1200
    stale_on_source_drift: bool = True
    allow_direct_suppression: bool = False

    def __post_init__(self) -> None:
        self.mode = str(self.mode or "off").strip().lower()
        if self.mode not in {"off", "archive", "extract", "active"}:
            raise ValueError("project.review_memory.mode must be off, archive, extract, or active")
        path = Path(str(self.state_dir or ".zscope/review-memory"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("project.review_memory.state_dir must be project-root relative")
        if self.project_scope != "project" or self.extraction not in {"auto_extract", "async_cli"}:
            raise ValueError("review memory requires project scope and auto_extract or async_cli extraction")
        if self.max_patterns_per_finding < 0 or self.max_context_tokens < 0:
            raise ValueError("review memory limits must be non-negative")
        if self.allow_direct_suppression:
            raise ValueError("review memory cannot enable direct suppression")


@dataclass
class ScanLLMProfiles:
    """User-selected LLM profiles for stable runtime roles."""

    modeling: str = "default"
    analysis: str = "default"
    validation: str = "default"


@dataclass
class ScanConfig:
    """Small public scan intent surface."""

    task: str = ""
    llm_profiles: ScanLLMProfiles = field(default_factory=ScanLLMProfiles)
    depth: str = "fast"
    # Runtime audit metadata for the public depth control.
    depth_source: str = "default"
    # Internal, read-only rollout audit state.  These fields are not accepted
    # by public config v2 and are populated only after CLI/YAML precedence has
    # been resolved.
    requested_depth: str = ""
    requested_depth_source: str = ""
    rollout: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConcurrencyConfig:
    """Explicit worker and LLM capacity limits supplied by the user."""

    entry_workers: int = 4
    validator_workers: int = 2
    investigator_workers: int = 1
    evidence_completion_workers: int = 2
    index_workers: int = 4
    wiki_compiler_workers: int = 4
    svf_workers: Optional[int] = None
    llm_max_inflight: int = 4

    def __post_init__(self) -> None:
        values = {
            "entry_workers": self.entry_workers,
            "validator_workers": self.validator_workers,
            "investigator_workers": self.investigator_workers,
            "evidence_completion_workers": self.evidence_completion_workers,
            "index_workers": self.index_workers,
            "wiki_compiler_workers": self.wiki_compiler_workers,
            "llm_max_inflight": self.llm_max_inflight,
        }
        if self.svf_workers is not None:
            values["svf_workers"] = self.svf_workers
        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"concurrency.{name} must be a positive integer")


@dataclass
class RuntimeAgentConfig:
    """Internal mapping from stable agents to public LLM capacity roles."""

    name: str
    llm_role: str
    enabled: bool = True
    can_spawn_subagents: Optional[bool] = None


@dataclass
class RuntimeSpecProvenance:
    """Auditable identity of the effective internal runtime specification."""

    version: int = 1
    source_path: str = ""
    sha256: str = ""
    developer_override: bool = False


@dataclass
class DiffImpactConfig:
    """Configuration for diff-impact entry planning."""

    strategy: str = "semantic_obligation"
    llm_triage: str = "on_demand"
    caller_search_depth_by_intent: Dict[str, int] = field(
        default_factory=lambda: {
            "new_external_api": 3,
            "resource_acquire_change": 4,
            "input_boundary_change": 4,
            "dispatcher_route_change": 3,
            "thread_or_callback_entry_change": 4,
            "resource_release_change": 6,
            "sink_or_check_change": 5,
            "lock_release_change": 5,
            "destroy_or_unregister_change": 6,
            "ownership_transfer_change": 5,
            "container_registration_change": 5,
            "lifecycle_contract_change": 5,
            "local_logic_change": 2,
            "comment_or_trivial_change": 1,
            "declaration_or_contract_change": 3,
        }
    )


@dataclass
class IndexingConfig:
    """Configuration for code indexing."""

    backend: str = "regex"
    # Joern 配置
    joern_path: str = "joern"
    joern_server_host: str = "127.0.0.1"
    joern_server_port: int = 8080
    joern_heap_size: str = "8g"
    # Clang 配置（Phase 1+）
    clangd_path: str = "clangd"
    clang_frontend: str = "auto"
    clang_indexer_path: str = "zscope-clang-indexer"
    knowledge_db_path: str = ".zscope_knowledge/code_knowledge.db"
    batch_size: int = 50
    max_clangd_threads: int = 8
    shared_cache_max_bytes: int = 512 * 1024 * 1024
    # SVF 配置（Phase 4+）
    svf_bin_dir: str = ""  # SVF 工具目录（含 wpa, saber 等）
    gclang_path: str = "gclang"  # gllvm 前端路径
    get_bc_path: str = "get-bc"  # gllvm 提取 bc 路径
    llvm_link_path: str = "llvm-link"
    svf_heap_limit_mb: int = 32768  # SVF 内存上限（默认 32GB）
    svf_timeout: Optional[float] = 1800.0  # null means no subprocess deadline.
    svf_groups_config: str = ""  # JSON file for multi-group bitcode linking
    svf_scope: str = "auto"  # full | auto | entry
    svf_entry_depth: int = 4
    svf_max_selected_tus: int = 200
    svf_fallback: str = "full"  # full | skip
    svf_always_include: List[str] = field(default_factory=list)
    svf_symbol_closure: bool = True
    svf_exclusive_pools: List[Dict[str, Any]] = field(default_factory=list)
    svf_shared_pools: List[Dict[str, Any]] = field(default_factory=list)
    # Java source structure plus optional graph/flow signal providers.
    java_structure_frontend: str = "auto"  # auto | spoon | javaparser | builtin
    java_structure_extractor_command: List[str] = field(default_factory=list)
    java_structure_db_path: str = ""
    java_signal_backends: List[str] = field(default_factory=lambda: ["sootup", "wala", "joern"])
    java_signal_provider_commands: Dict[str, List[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.backend = str(self.backend or "regex").strip().lower().replace("-", "_")
        if self.clang_frontend not in {"auto", "batch", "lsp"}:
            raise ValueError("indexing.clang.frontend must be auto, batch, or lsp")
        self.java_structure_frontend = (
            str(self.java_structure_frontend or "auto").strip().lower().replace("-", "_")
        )
        if self.java_structure_frontend not in {"auto", "spoon", "javaparser", "builtin"}:
            raise ValueError(
                "indexing.java.structure_frontend must be auto, spoon, javaparser, or builtin"
            )
        self.java_signal_backends = _normalized_name_list(self.java_signal_backends)
        self.java_signal_provider_commands = {
            str(key)
            .strip()
            .lower()
            .replace("-", "_"): [str(part) for part in value if str(part).strip()]
            for key, value in self.java_signal_provider_commands.items()
            if str(key).strip() and isinstance(value, list)
        }
        self.svf_timeout = _optional_positive_seconds(self.svf_timeout, 1800.0)


def _normalized_name_list(values: Any) -> List[str]:
    result: List[str] = []
    for value in values or []:
        name = str(value).strip().lower().replace("-", "_")
        if name and name not in result:
            result.append(name)
    return result


@dataclass
class AnalysisConfig:
    """Configuration for analysis behavior."""

    max_recursion_depth: int = 3
    max_function_lines: int = 500
    max_tool_iterations: int = 50
    snapshot_dir: str = ".zscope_snapshots"
    enable_snapshot_cache: bool = True
    validation_cache_entries: int = 4096
    user_config_db: str = (
        ""  # Path to user config workbook or directory, defaults to {snapshot_dir}/
    )
    enable_global_model: bool = False  # Batch-level global premodel/model_entry replacement.
    max_premodel_depth: int = 3  # Callee recursive pre-modeling max depth
    max_premodel_callees: int = 20  # Max callees to expand per level
    trivial_function_max_lines: int = 5  # Skip modeling if function <= this many valid lines
    # Scan-time LLM classification of unknown lightweight wrapper callees
    # (user-defined risk interfaces without name hints).  Enabled by default in
    # every scan depth because the resulting roles feed rule-facing semantics.
    llm_interface_inference: bool = True
    llm_interface_inference_budget: int = 50  # Max LLM interface classifications per scan.
    # Optional LLM supplement that adds a user-facing Chinese explanation on
    # top of LLM-free deterministic validation decisions (confirmed by proof,
    # audit observations, evidence conflicts).  The deterministic verdict and
    # reasoning stay authoritative; the model only rewrites the explanation.
    llm_decision_explanation: bool = True
    llm_decision_explanation_budget: int = 50  # Max explanation calls per scan.
    workflow_name: str = "default"
    enable_subagent_workers: bool = False
    # Internal rollout control.  ``shadow`` records evidence-backed semantic
    # deltas without allowing them to influence coverage-gap planning;
    # ``active`` applies those deltas to the read-only Security Semantic Map.
    security_semantic_enrichment_mode: str = "shadow"
    max_subagent_tickets: int = 4
    subagent_max_turns: int = 20  # Per-ticket tool/LLM turn budget for focused workers.
    request_deadline_seconds: Optional[float] = 120.0
    validation_deadline_seconds: Optional[float] = 600.0
    subagent_ticket_timeout: Optional[float] = 300.0
    entry_deadline_seconds: Optional[float] = 1800.0
    scan_deadline_seconds: Optional[float] = None
    budget_exhaustion_policy: str = "observe"
    subagent_spawn_allowlist: List[str] = field(default_factory=lambda: ["deep_worker"])
    subagent_skill_llm_refs: Dict[str, str] = field(default_factory=dict)
    subagent_skill_efforts: Dict[str, str] = field(default_factory=dict)
    tool_audit_log: str = ""  # Optional JSONL audit sink for tool/MCP policy events.
    # Escalation-ladder rungs (new_docs/balanced_confirmed_tp_plan.md Phase 4).
    # All default to off so the shipped pipeline behavior is unchanged; pilots
    # enable them individually so each rung's TP contribution stays measurable.
    validation_uncertain_confirm_threshold: Optional[float] = None
    # Defaults to True: the balanced pipeline has always run the V3 reattempt;
    # set False only for R1-only reference runs (plan M5 differential rows).
    validation_v3_reattempt: bool = True
    validation_v2b_adjudication: bool = False
    validation_review_protocol: bool = False
    # M4': compiler-checked review claims (deterministic reject proofs minted
    # from the fact store).  Tri-state like the guards above: ``None`` enables
    # it for ``balanced`` scans only.  Even when depth-enabled, the feature
    # auto-disables when the compile_commands driver is not bound to the fact
    # compiler (see CompleteFactStore.driver_bound).
    validation_checked_proofs: Optional[bool] = None
    validation_positive_case: bool = False
    validation_related_findings: bool = False
    validation_review_checkpoint: bool = False
    # FP-suppression guards (M1/M2/M3').  Tri-state: ``None`` resolves by
    # scan depth — enabled for ``balanced`` scans (where the balanced
    # confirmed-TP pilot verified their effect), disabled elsewhere.  An
    # explicit True/False always wins.
    # M1: an R3 replay escalation that starts from ``uncertain`` and ends
    # ``verified`` no longer auto-confirms; it is held in needs_review with
    # review_disposition_reason=uncertain_confirm_hold.
    validation_uncertain_replay_review: Optional[bool] = None
    # M2: the source_lifecycle_acquire_without_release proof loses its
    # confirm authority (measured 0TP/1FP on the frozen balanced run); it
    # becomes diagnostic-only and the item routes through the normal ladder.
    validation_demote_source_lifecycle_confirm: Optional[bool] = None
    # M3': a cfg-obligation confirm whose function body itself releases the
    # obligation object (free/SAFE_FREE of a sink-argument token) is
    # self-contradictory and is not produced; the item routes through the
    # normal ladder (measured on the frozen run: 1 FP removed, 0 TP touched).
    validation_obligation_infunction_release_guard: Optional[bool] = None

    def __post_init__(self) -> None:
        self.validation_cache_entries = _bounded_cache_entries(
            self.validation_cache_entries,
            4096,
        )
        self.request_deadline_seconds = _optional_positive_seconds(
            self.request_deadline_seconds, 120.0
        )
        self.validation_deadline_seconds = _optional_positive_seconds(
            self.validation_deadline_seconds, 600.0
        )
        self.subagent_ticket_timeout = _optional_positive_seconds(
            self.subagent_ticket_timeout, 300.0
        )
        self.entry_deadline_seconds = _optional_positive_seconds(
            self.entry_deadline_seconds, 1800.0
        )
        self.scan_deadline_seconds = _optional_positive_seconds(self.scan_deadline_seconds, None)
        self.budget_exhaustion_policy = _normalize_budget_exhaustion_policy(
            self.budget_exhaustion_policy
        )
        self.security_semantic_enrichment_mode = (
            str(self.security_semantic_enrichment_mode or "shadow").strip().lower()
        )
        if self.security_semantic_enrichment_mode not in {"shadow", "active"}:
            raise ValueError("security_semantic_enrichment_mode must be 'shadow' or 'active'")
        self.llm_decision_explanation = bool(self.llm_decision_explanation)
        try:
            self.llm_decision_explanation_budget = max(0, int(self.llm_decision_explanation_budget))
        except (TypeError, ValueError):
            self.llm_decision_explanation_budget = 50
        if self.validation_uncertain_confirm_threshold is not None:
            threshold = float(self.validation_uncertain_confirm_threshold)
            if not 0.5 < threshold <= 1.0:
                raise ValueError(
                    "validation_uncertain_confirm_threshold must be None or in (0.5, 1.0]"
                )
            self.validation_uncertain_confirm_threshold = threshold
        self.validation_v3_reattempt = bool(self.validation_v3_reattempt)
        self.validation_v2b_adjudication = bool(self.validation_v2b_adjudication)
        self.validation_review_protocol = bool(self.validation_review_protocol)
        self.validation_checked_proofs = bool(self.validation_checked_proofs)
        self.validation_positive_case = bool(self.validation_positive_case)
        self.validation_related_findings = bool(self.validation_related_findings)
        self.validation_review_checkpoint = bool(self.validation_review_checkpoint)


@dataclass
class SemanticDedupConfig:
    """Configuration for final-report semantic duplicate handling."""

    enabled: bool = True
    llm_enabled: bool = False
    llm_confidence_threshold: float = 0.85
    max_cluster_size: int = 8


@dataclass
class ReportingConfig:
    """Configuration for report assembly and presentation."""

    semantic_dedup: SemanticDedupConfig = field(default_factory=SemanticDedupConfig)


@dataclass
class RulesConfig:
    """Versioned external rule-pack configuration."""

    packs: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    enabled_ids: List[str] = field(default_factory=list)
    disabled_ids: List[str] = field(default_factory=list)


@dataclass
class ProjectConfig:
    """Configuration for the C/C++ or Java project being analyzed."""

    project_root: Path
    source_root: Path
    project_id: str = ""
    language: str = "auto"
    entry_function: Optional[str] = None
    entry_file_path: Optional[str] = None
    entry_signature: Optional[str] = None
    agents: List[AgentConfig] = field(default_factory=list)
    compile_commands_path: Optional[Path] = None
    entry_functions_list: Optional[Path] = None  # Path to JSON file for batch mode
    entry_diff_focus: Optional[Dict[str, Any]] = None
    user_config_file: Optional[Path] = None
    include_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    entry_discovery: EntryDiscoveryConfig = field(default_factory=EntryDiscoveryConfig)
    diff_impact: DiffImpactConfig = field(default_factory=DiffImpactConfig)
    wiki: WikiConfig = field(default_factory=WikiConfig)
    review_memory: ReviewMemoryConfig = field(default_factory=ReviewMemoryConfig)

    def __post_init__(self):
        self.project_root = Path(self.project_root).resolve()
        self.project_id = str(self.project_id or self.project_root.name or "project").strip()

        # Resolve source_root: relative to project_root if not absolute
        if not self.source_root:
            self.source_root = self.project_root
        else:
            self.source_root = Path(self.source_root)
            if not self.source_root.is_absolute():
                self.source_root = (self.project_root / self.source_root).resolve()
            else:
                self.source_root = self.source_root.resolve()

        self.language = normalize_project_language(self.language)
        if self.language == "auto":
            self.language = detect_project_language(self.source_root)
        # Resolve include/exclude paths relative to source_root
        resolved_includes = []
        for p in self.include_paths or []:
            path_obj = Path(p)
            if not path_obj.is_absolute():
                resolved_includes.append((self.source_root / path_obj).absolute())
            else:
                resolved_includes.append(path_obj.absolute())
        self.include_paths = resolved_includes

        resolved_excludes = []
        for p in self.exclude_paths or []:
            path_obj = Path(p)
            if not path_obj.is_absolute():
                resolved_excludes.append((self.source_root / path_obj).absolute())
            else:
                resolved_excludes.append(path_obj.absolute())
        self.exclude_paths = resolved_excludes

        # Resolve compile_commands_path:
        #   1. 显式配置 → 相对路径基于 project_root 解析
        #   2. 自动发现 → 依次查找 project_root、source_root
        if self.compile_commands_path:
            self.compile_commands_path = Path(self.compile_commands_path)
            if not self.compile_commands_path.is_absolute():
                self.compile_commands_path = (
                    self.project_root / self.compile_commands_path
                ).resolve()
            else:
                self.compile_commands_path = self.compile_commands_path.resolve()
        else:
            # 自动发现：project_root 优先（compile_commands.json 通常在构建/任务目录）
            for root in [self.project_root, self.source_root]:
                candidate = root / "compile_commands.json"
                if candidate.exists():
                    self.compile_commands_path = candidate
                    break

        # Resolve entry_functions_list path relative to project root
        if self.entry_functions_list:
            if not Path(self.entry_functions_list).is_absolute():
                self.entry_functions_list = (
                    self.project_root / self.entry_functions_list
                ).resolve()
            else:
                self.entry_functions_list = Path(self.entry_functions_list).resolve()

        if self.user_config_file:
            user_config_file = Path(self.user_config_file)
            if not user_config_file.is_absolute():
                user_config_file = self.project_root / user_config_file
            self.user_config_file = user_config_file.resolve()

        if self.entry_discovery.search_root:
            # 相对 search_root 固定基于 source_root 解析（CLI / Web / MCP 共用同一条规则）。
            search_root = Path(self.entry_discovery.search_root)
            if not search_root.is_absolute():
                search_root = self.source_root / search_root
            search_root = search_root.resolve()
            if not search_root.is_dir():
                raise ValueError(
                    f"project.entry_discovery.search_root is not a directory: {search_root}"
                )
            self.entry_discovery.search_root = search_root


@dataclass
class ZScopeConfig:
    """Main configuration container."""

    llm: LLMConfig
    llms: Dict[str, LLMConfig]
    indexing: IndexingConfig
    analysis: AnalysisConfig
    project: ProjectConfig
    scan: ScanConfig = field(default_factory=ScanConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    runtime_provenance: RuntimeSpecProvenance = field(default_factory=RuntimeSpecProvenance)
    user_config_version: int = 2
    # Populated by the shared rule preflight before any indexer, external tool,
    # or LLM is started.  These are internal runtime objects rather than public
    # v2 YAML fields, so they intentionally do not appear on ``UserConfigV2``.
    effective_rules: Any = field(default=None, repr=False, compare=False)
    rule_catalog_provenance: Any = field(default=None, repr=False, compare=False)
    rule_validation_warnings: List[str] = field(default_factory=list, repr=False)
    # One process-local usage ledger is shared by every LLM profile in a scan.
    # It is intentionally excluded from equality/serialization and is created
    # at the effective-config boundary.
    scan_token_usage_ledger: Any = field(default=None, repr=False, compare=False)


# Public names used by the v2 loader and developer documentation.  The
# effective type intentionally keeps the long-lived ``ZScopeConfig`` name for
# Python integrations while exposing the split boundaries explicitly.
@dataclass
class UserConfigV2:
    llms: Dict[str, LLMConfig]
    project: ProjectConfig
    scan: ScanConfig
    indexing: IndexingConfig
    concurrency: ConcurrencyConfig
    rules: RulesConfig = field(default_factory=RulesConfig)


@dataclass
class RuntimeSpec:
    analysis: AnalysisConfig
    reporting: ReportingConfig
    agents: List[RuntimeAgentConfig]
    knowledge_db_path: str
    snapshot_dir: str
    default_user_config_file: str
    provenance: RuntimeSpecProvenance


EffectiveConfig = ZScopeConfig


class ConfigLoader:
    """Load the strict public v2 configuration and bundled runtime specification."""

    DEFAULT_CONFIG_LOCATIONS = ["./zscope.yaml"]

    @staticmethod
    def load(
        config_path: Optional[str] = None,
        *,
        scan_depth: Optional[str] = None,
    ) -> ZScopeConfig:
        from .v2 import apply_scan_overrides, load_user_config_v2
        from ..framework.llm_usage import ScanTokenUsageLedger
        from ..orchestration.rollout import apply_persisted_rollout_policy
        from ..rules.extensions import preflight_rules

        config = load_user_config_v2(config_path)
        apply_scan_overrides(
            config,
            scan_depth=scan_depth,
        )
        apply_persisted_rollout_policy(config)
        usage_event_path = Path(config.analysis.snapshot_dir) / (
            f"llm_usage_events_{uuid.uuid4().hex}.jsonl"
        )
        config.scan_token_usage_ledger = ScanTokenUsageLedger(
            depth=config.scan.depth, event_sink_path=usage_event_path
        )
        # One shared preflight is deliberately part of configuration loading:
        # every CLI, Web, MCP, batch, and doctor entry point must reject an
        # invalid rule universe before constructing CodeIndex or invoking an
        # external tool/LLM.  ``Analyzer`` repeats this defensively for direct
        # third-party construction with an in-memory config.
        preflight_rules(config)
        return config
