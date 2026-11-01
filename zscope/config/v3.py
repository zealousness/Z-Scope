"""Strict public configuration v3: one user configuration entry point.

Implements the ``config_version: 3`` proposal from the agent implementation
plan (``12_SCHEMAS_AND_EXAMPLES.md``).  The public call shape stays
``ConfigLoader.load(path, scan_depth?, read_only?) -> EffectiveConfig``;
``v2.load_user_config_v2`` dispatches here when the document declares
version 3.

Semantics that intentionally differ from public v2:

* Both v2/v3 use the loaded YAML directory as the only project root;
  public root/source_root keys are rejected even when they equal '.'.
* ``project.targets`` keeps an explicit identity for every declared build
  target.  Composing the current single-target execution chain refuses a
  multi-target document instead of silently treating the first target as
  the whole project.
* ``scan.preset`` is the user-facing quality tier.  Its fast/balanced/deep values are identical to execution depth;
  a preset never enables the
  internal shadow experiments.
* ``execution.stop_at`` resolves the next occurrence of the local wall
  clock in the configured IANA timezone and holds one absolute,
  timezone-aware boundary for this load.  It creates no recurring
  schedule; unknown timezones and DST-ambiguous or nonexistent local
  times are rejected conservatively.

:func:`public_json_schema` is generated from the same key tables and value
vocabularies that drive parsing.  The model in this module is the single
source; no second parser is derived from documentation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import (
    ConcurrencyConfig,
    EffectiveConfig,
    LLMConfig,
    ProjectConfig,
    RulesConfig,
    ScanConfig,
)
from .v2 import (
    LLM_PROFILE_KEYS,
    PUBLIC_CONFIG_VERSION_V3,
    SCAN_DEPTHS_BY_LANGUAGE,
    _agents_from_runtime,
    _anchor_runtime_paths,
    _check_keys,
    _expand_env,
    _mapping,
    _parse_indexing,
    _parse_llms,
    _positive_int,
    _resolve_config_path,
    _string,
    _string_list,
    load_runtime_spec,
    load_yaml_unique,
    reject_legacy_project_roots,
)

# --- Single-source field tables -------------------------------------------------
#
# These tuples and vocabularies drive both strict parsing (_check_keys) and
# public_json_schema().  Any new field must be added here once; the schema
# section guard raises if a field table drifts away from its key tuple.

V3_TOP_LEVEL_KEYS = ("config_version", "llms", "project", "scan", "execution")
PROJECT_KEYS = ("language", "platform", "targets", "semantics_file")
TARGET_KEYS = ("id", "compile_commands")
SCAN_KEYS = ("preset", "focus", "reproduction")
EXECUTION_KEYS = ("timezone", "stop_at", "max_workers")

SCAN_PRESETS = ("deep", "balanced", "fast")
FOCUS_AREAS = ("memory", "resources", "async_lifecycle")
REPRODUCTION_MODES = ("auto",)
PROJECT_PLATFORMS = ("linux_user",)
PROJECT_LANGUAGES = ("c_cpp", "java")
LANGUAGE_DISPLAY_NAMES = {"c_cpp": "C/C++", "java": "Java"}
# How each language treats a target's compile database; drives both the
# parser branch and the language-conditional schema branches below.
TARGET_DATABASE_RULE = {"c_cpp": "required", "java": "forbidden"}

# Temporary internal mapping until U01/S08 replace the legacy depth tiers.
PRESET_DEPTH_MAPPING: Dict[str, str] = {"fast": "fast", "balanced": "balanced", "deep": "deep"}

# Public v3 deliberately has no tool-tuning surface.  Its internal SVF cap
# therefore has to be a broadly admissible per-process default rather than the
# legacy v2 expert default of 32 GiB: admission reserves the full cap for each
# worker, and a 32 GiB cap cannot start even one worker on a 32 GiB host after
# the runtime safety margin.  Explicit v2 configurations retain their chosen
# value; v3 uses this conservative cap and still fails closed if the bitcode
# size estimate cannot fit it.
V3_SVF_HEAP_LIMIT_MB = 8192

STOP_AT_PATTERN = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d")

# Loader semantics the generated schema deliberately does not claim to cover.
# JSON Schema expresses document shape; these constraints are enforced by the
# parser/composer at load time.  The list is embedded verbatim in
# ``public_json_schema()["x-loader-enforced-constraints"]`` so schema
# consumers cannot mistake a shape-valid document for a loadable one.
LOADER_ENFORCED_CONSTRAINTS = (
    "execution.timezone must resolve to a real IANA time zone (ZoneInfo lookup)",
    "execution.stop_at must resolve to an unambiguous, existing local wall-clock "
    "time; daylight-saving gaps and folds are rejected at resolution time",
    "project.targets ids must be unique across the list",
    "the configuration directory is the only project root and target "
    "compile_commands anchor to that directory (filesystem semantics)",
    "string values are whitespace-normalized (stripped) before validation",
    "${VAR} environment expansion applies before validation",
    "YAML documents with duplicate mapping keys are rejected by the loader",
    "multi-target documents parse, but composition refuses until target " "selection is wired",
)

WIRED = "wired"
DECLARED_ONLY = "declared_only"
BLOCKED = "blocked"


@dataclass(frozen=True)
class TargetSpec:
    """One declared build target with explicit identity."""

    id: str
    # Absolute resolved database path; None for Java targets (no compile
    # commands database).  Every target keeps its own identity even when the
    # current execution chain can only consume one.
    compile_commands: Optional[Path] = None


@dataclass(frozen=True)
class ProjectModel:
    """Formal project section of a v3 document."""

    root: Path
    language: str
    platform: str
    targets: Tuple[TargetSpec, ...]
    # Optional at document-parse time so an existing v3 file can receive the
    # actionable migration error from prepare/discovery/scan.  New C/C++
    # documents always declare it; Java documents reject it.
    semantics_file: Optional[Path] = None


@dataclass(frozen=True)
class ScanIntent:
    """User-declared scan intent for this round."""

    preset: str
    focus: Tuple[str, ...]
    reproduction: str
    # Legacy depth temporarily produced from the preset.  The mapping is
    # recorded here explicitly instead of silently renaming the tiers.
    mapped_depth: str
    # ``config`` when the user declared scan.preset and ``default`` when the
    # preset fell back to its default; these reuse the existing rollout
    # governance vocabulary so an explicit preset keeps explicit-depth
    # treatment while defaulted traffic stays gateable.
    mapped_depth_source: str
    mapping_note: str


@dataclass(frozen=True)
class StopWindow:
    """One absolute, timezone-aware stop boundary resolved at load time."""

    timezone: str
    stop_at: str
    resolved_stop_time: datetime


@dataclass(frozen=True)
class ExecutionProfile:
    """User-declared execution preferences."""

    timezone: Optional[str] = None
    stop_at: Optional[str] = None
    max_workers: Optional[int] = None
    stop_window: Optional[StopWindow] = None


@dataclass(frozen=True)
class WiringNote:
    """Consumption state of one v3 field in the current product."""

    field: str
    state: str
    detail: str


@dataclass(frozen=True)
class UserConfigV3:
    """Formal model of a parsed v3 document (single public entry)."""

    config_path: Path
    llms: Dict[str, LLMConfig]
    project: ProjectModel
    scan: ScanIntent
    execution: ExecutionProfile
    wiring: Tuple[WiringNote, ...] = field(default=())


# --- Parsing --------------------------------------------------------------------


def parse_user_config_v3(
    config_path: Optional[str] = None, *, now: Optional[datetime] = None
) -> UserConfigV3:
    """Parse one v3 document into the formal model without composing execution."""

    path = _resolve_config_path(config_path)
    raw = _expand_env(load_yaml_unique(path))
    return _parse_v3_model(path, raw, now=now)


def parse_user_config_v3_document(
    path: Path, raw: Mapping[str, Any], *, now: Optional[datetime] = None
) -> UserConfigV3:
    """Parse one already-read v3 document through the same formal model.

    A consumer that must gate on the raw ``config_version`` itself (so the
    gated document and the parsed model share one read) parses here instead
    of re-reading the file; the rules are exactly those of
    :func:`parse_user_config_v3`.
    """

    return _parse_v3_model(Path(path), raw, now=now)


def load_user_config_v3(path: Path, raw: Mapping[str, Any]) -> EffectiveConfig:
    """Parse and compose a v3 document that v2.load_user_config_v2 dispatched."""

    model = _parse_v3_model(path, raw)
    return compose_effective_config(model)


def _parse_v3_model(
    path: Path, raw: Mapping[str, Any], *, now: Optional[datetime] = None
) -> UserConfigV3:
    _check_keys(raw, V3_TOP_LEVEL_KEYS, "config")
    if raw.get("config_version") != PUBLIC_CONFIG_VERSION_V3:
        raise ValueError(f"config.config_version must be {PUBLIC_CONFIG_VERSION_V3}")

    llms = _parse_llms(raw.get("llms"))
    project = _parse_project_v3(path, raw.get("project"))
    scan = _parse_scan_v3(raw.get("scan"), language=project.language)
    execution = _parse_execution_v3(raw.get("execution"), now=now)
    wiring = _wiring_notes(project, scan, execution)
    return UserConfigV3(
        config_path=path,
        llms=llms,
        project=project,
        scan=scan,
        execution=execution,
        wiring=wiring,
    )


def _parse_project_v3(config_path: Path, raw: Any) -> ProjectModel:
    data = _mapping(raw, "project", required=True)
    reject_legacy_project_roots(data)
    _check_keys(data, PROJECT_KEYS, "project")
    language = data.get("language")
    if language not in PROJECT_LANGUAGES:
        raise ValueError("project.language must be exactly 'c_cpp' or 'java'")

    root = config_path.resolve().parent

    raw_semantics = data.get("semantics_file")
    semantics_file: Optional[Path] = None
    if language == "java":
        if raw_semantics is not None:
            raise ValueError("project.semantics_file is not valid for Java")
    elif raw_semantics is not None:
        semantics_value = _string(raw_semantics, "project.semantics_file")
        semantics_candidate = Path(semantics_value)
        if semantics_candidate.is_absolute():
            raise ValueError("project.semantics_file must be relative to the YAML directory")
        semantics_file = (root / semantics_candidate).resolve()
        try:
            semantics_file.relative_to(root)
        except ValueError as exc:
            raise ValueError("project.semantics_file must stay inside the project root") from exc

    platform = _string(data.get("platform", PROJECT_PLATFORMS[0]), "project.platform")
    if platform not in PROJECT_PLATFORMS:
        raise ValueError("project.platform must be one of: " + ", ".join(PROJECT_PLATFORMS))

    targets_raw = data.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        raise ValueError("project.targets must be a non-empty list of target mappings")
    targets: List[TargetSpec] = []
    seen_ids: List[str] = []
    for index, item in enumerate(targets_raw):
        item_path = f"project.targets[{index}]"
        entry = _mapping(item, item_path, required=True)
        _check_keys(entry, TARGET_KEYS, item_path)
        target_id = _string(entry.get("id"), f"{item_path}.id")
        if target_id in seen_ids:
            raise ValueError(f"project.targets contains duplicate target id {target_id!r}")
        seen_ids.append(target_id)
        compile_commands = entry.get("compile_commands")
        resolved: Optional[Path] = None
        rule = TARGET_DATABASE_RULE[language]
        if rule == "forbidden":
            if compile_commands is not None:
                raise ValueError(
                    f"{item_path}.compile_commands is not valid for "
                    f"{LANGUAGE_DISPLAY_NAMES[language]}"
                )
        elif compile_commands is None:
            raise ValueError(
                f"{item_path}.compile_commands is required for "
                f"{LANGUAGE_DISPLAY_NAMES[language]}"
            )
        else:
            database = Path(_string(compile_commands, f"{item_path}.compile_commands"))
            if not database.is_absolute():
                database = root / database
            resolved = database.resolve()
        targets.append(TargetSpec(id=target_id, compile_commands=resolved))
    return ProjectModel(
        root=root,
        language=language,
        platform=platform,
        targets=tuple(targets),
        semantics_file=semantics_file,
    )


def _parse_scan_v3(raw: Any, *, language: str) -> ScanIntent:
    data = _mapping(raw, "scan")
    _check_keys(data, SCAN_KEYS, "scan")
    preset = _string(data.get("preset", SCAN_PRESETS[0]), "scan.preset")
    if preset in {"quick", "overnight"}:
        raise ValueError(
            "scan.preset quick/overnight removed; run zscope-config migrate (quick -> fast, overnight -> deep)"
        )
    if preset not in SCAN_PRESETS:
        raise ValueError("scan.preset must be one of: " + ", ".join(SCAN_PRESETS))

    focus = tuple(
        _string_list(data.get("focus", list(FOCUS_AREAS)), "scan.focus", allow_empty=False)
    )
    unknown = [area for area in focus if area not in FOCUS_AREAS]
    if unknown:
        raise ValueError(
            "scan.focus contains unknown area(s): "
            + ", ".join(unknown)
            + "; valid areas: "
            + ", ".join(FOCUS_AREAS)
        )

    reproduction = _string(data.get("reproduction", REPRODUCTION_MODES[0]), "scan.reproduction")
    if reproduction not in REPRODUCTION_MODES:
        raise ValueError("scan.reproduction must be one of: " + ", ".join(REPRODUCTION_MODES))

    depth = PRESET_DEPTH_MAPPING[preset]
    allowed = SCAN_DEPTHS_BY_LANGUAGE.get(language, frozenset())
    if depth not in allowed:
        raise ValueError(
            f"scan.preset {preset!r} is not currently available for "
            f"project.language={language!r}; use 'fast'"
        )
    note = (
        f"scan.preset {preset!r} uses the same execution depth; experimental rules remain unchanged"
    )
    return ScanIntent(
        preset=preset,
        focus=focus,
        reproduction=reproduction,
        mapped_depth=depth,
        mapped_depth_source="config" if "preset" in data else "default",
        mapping_note=note,
    )


def _parse_execution_v3(raw: Any, *, now: Optional[datetime]) -> ExecutionProfile:
    data = _mapping(raw, "execution")
    _check_keys(data, EXECUTION_KEYS, "execution")

    timezone_name: Optional[str] = None
    zone: Optional[ZoneInfo] = None
    raw_timezone = data.get("timezone")
    if raw_timezone is not None:
        timezone_name = _string(raw_timezone, "execution.timezone")
        zone = _load_timezone(timezone_name)

    stop_at: Optional[str] = None
    window: Optional[StopWindow] = None
    raw_stop_at = data.get("stop_at")
    if raw_stop_at is not None:
        stop_at = _string(raw_stop_at, "execution.stop_at")
        if STOP_AT_PATTERN.fullmatch(stop_at) is None:
            raise ValueError(
                "execution.stop_at must be a local 'HH:MM' wall-clock time " "(00:00-23:59)"
            )
        if timezone_name is None or zone is None:
            raise ValueError(
                "execution.stop_at requires an explicit execution.timezone so the "
                "boundary does not depend on the loading machine"
            )
        window = StopWindow(
            timezone=timezone_name,
            stop_at=stop_at,
            resolved_stop_time=resolve_stop_boundary(stop_at, zone, now=now),
        )

    raw_max_workers = data.get("max_workers")
    max_workers = (
        _positive_int(raw_max_workers, "execution.max_workers")
        if raw_max_workers is not None
        else None
    )
    return ExecutionProfile(
        timezone=timezone_name,
        stop_at=stop_at,
        max_workers=max_workers,
        stop_window=window,
    )


# --- Stop-window resolution -----------------------------------------------------


def _load_timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, KeyError, OSError) as exc:
        raise ValueError(f"execution.timezone is not a known IANA timezone: {name!r}") from exc


def resolve_stop_boundary(
    stop_at: str, zone: ZoneInfo, *, now: Optional[datetime] = None
) -> datetime:
    """Resolve the next occurrence of a local wall-clock time in ``zone``.

    The result is one absolute, timezone-aware boundary for this load.  No
    recurring schedule is created.  A local time that falls into a
    daylight-saving gap (nonexistent) or fold (ambiguous) is rejected
    conservatively instead of guessing an instant.
    """

    if STOP_AT_PATTERN.fullmatch(stop_at) is None:
        raise ValueError("execution.stop_at must be a local 'HH:MM' wall-clock time (00:00-23:59)")
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("stop boundary resolution requires a timezone-aware 'now'")

    parts = stop_at.split(":")
    hour, minute = int(parts[0]), int(parts[1])
    now_local = now.astimezone(zone)
    naive_now = now_local.replace(tzinfo=None)
    candidate = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0, tzinfo=None)
    if candidate <= naive_now:
        candidate += timedelta(days=1)

    status = _local_wall_clock_status(candidate, zone)
    if status == "nonexistent":
        raise ValueError(
            f"execution.stop_at {stop_at!r} does not exist in {zone.key} on "
            f"{candidate.date().isoformat()} (daylight-saving gap); refusing to guess"
        )
    if status == "ambiguous":
        raise ValueError(
            f"execution.stop_at {stop_at!r} occurs twice in {zone.key} on "
            f"{candidate.date().isoformat()} (daylight-saving fold); refusing to guess"
        )
    return candidate.replace(tzinfo=zone)


def _local_wall_clock_status(naive: datetime, zone: ZoneInfo) -> str:
    first = naive.replace(tzinfo=zone, fold=0)
    round_trip = first.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None)
    if round_trip != naive:
        return "nonexistent"
    second = naive.replace(tzinfo=zone, fold=1)
    if first.utcoffset() != second.utcoffset():
        return "ambiguous"
    return "unique"


# --- Composition into the current execution chain -------------------------------


def compose_effective_config(model: UserConfigV3) -> EffectiveConfig:
    """Compose the current single-target execution chain from a v3 model.

    Every target identity stays on the model.  Feeding the existing chain
    requires exactly one target; anything else is an explicit refusal with
    the declared ids, never a silent first-target shortcut.
    """

    targets = model.project.targets
    if len(targets) != 1:
        ids = ", ".join(target.id for target in targets)
        raise ValueError(
            "the current scan execution chain supports exactly one "
            f"project.targets entry; {len(targets)} declared ({ids}). "
            "Multi-target selection is not wired yet: declare a single "
            "target or stay on public config v2 until it lands."
        )
    target = targets[0]

    runtime = load_runtime_spec()
    # Public v3 has one C/C++ semantic authority.  Reuse the existing
    # UserConfigStore injection seam for validation feedback and evidence
    # renderers, but point its semantic reads at the reviewed YAML instead of
    # allowing individual analyzers to fall back to the legacy XLSX workbook.
    if model.project.language == "c_cpp" and model.project.semantics_file is not None:
        runtime.analysis.user_config_db = str(model.project.semantics_file)
    project = ProjectConfig(
        project_root=model.project.root,
        project_id="",
        target_id=target.id,
        language=model.project.language,
        compile_commands_path=target.compile_commands,
        semantics_file=model.project.semantics_file,
    )
    # Public v3 intentionally removed the legacy entry_function and
    # entry_functions_list knobs. A generated v3 document must nevertheless
    # be directly scannable: entry discovery supplies reachability attribution
    # while the C/C++ fast planner still analyzes every current function
    # instance exactly once. Without this composition default, zscope-init
    # produced a document that prepare called startable but an ordinary scan
    # rejected with "No entry function".
    project.entry_discovery.enabled = True
    scan = ScanConfig(
        task="",
        depth=model.scan.mapped_depth,
        depth_source=model.scan.mapped_depth_source,
    )
    backend = "unified" if model.project.language == "c_cpp" else "java_unified"
    indexing = _parse_indexing(
        {"backend": backend}, language=model.project.language, runtime=runtime
    )
    if model.project.language == "c_cpp":
        indexing.svf_heap_limit_mb = V3_SVF_HEAP_LIMIT_MB
    concurrency = ConcurrencyConfig()
    indexing.max_clangd_threads = concurrency.index_workers
    rules = RulesConfig()
    _anchor_runtime_paths(runtime, project, indexing)
    project.agents = _agents_from_runtime(runtime, scan)

    return EffectiveConfig(
        config_path=model.config_path,
        llm=model.llms["default"],
        llms=model.llms,
        indexing=indexing,
        analysis=runtime.analysis,
        project=project,
        scan=scan,
        concurrency=concurrency,
        reporting=runtime.reporting,
        rules=rules,
        runtime_provenance=runtime.provenance,
        user_config_version=PUBLIC_CONFIG_VERSION_V3,
        user_config_v3=model,
    )


def _wiring_notes(
    project: ProjectModel, scan: ScanIntent, execution: ExecutionProfile
) -> Tuple[WiringNote, ...]:
    multi_target = len(project.targets) != 1
    if multi_target:
        target_note = WiringNote(
            "project.targets",
            BLOCKED,
            "the current execution chain supports one target; composition "
            "refuses the document instead of using the first target as the "
            "whole project",
        )
    else:
        target_note = WiringNote(
            "project.targets",
            WIRED,
            "the single declared target composes into the current execution "
            "chain with its resolved compile database path",
        )
    if execution.stop_window is not None:
        timezone_note = WiringNote(
            "execution.timezone",
            WIRED,
            "used to resolve the stop boundary for this load",
        )
        stop_note = WiringNote(
            "execution.stop_at",
            WIRED,
            "one absolute timezone-aware boundary is held for this load and "
            "consumed for real: the CLI scan session arms it as a monotonic "
            "cooperative deadline on the session runner's shared cancellation "
            "token, and persistent job starts persist it as the job's stop "
            "window (an explicit request stop_at wins); no recurring schedule "
            "is created",
        )
    else:
        timezone_note = WiringNote(
            "execution.timezone",
            DECLARED_ONLY,
            "parsed and validated, but nothing consumes a timezone without a "
            "stop window in this slice",
        )
        stop_note = WiringNote(
            "execution.stop_at",
            DECLARED_ONLY,
            "not configured; long-running scans may run without a time window",
        )
    return (
        WiringNote(
            "llms",
            WIRED,
            "profiles compose directly into the effective LLM configuration",
        ),
        WiringNote(
            "config_path",
            WIRED,
            "the configuration file directory is the only project root; every "
            "project-relative path anchors to that directory",
        ),
        WiringNote(
            "project.language",
            WIRED,
            "explicit c_cpp or java; loader-level auto-detection is not part " "of the v3 model",
        ),
        WiringNote(
            "project.platform",
            DECLARED_ONLY,
            "accepted vocabulary is limited to "
            + ", ".join(PROJECT_PLATFORMS)
            + "; platform-specific behavior is not wired",
        ),
        target_note,
        WiringNote("scan.preset", WIRED, scan.mapping_note),
        WiringNote(
            "scan.focus",
            DECLARED_ONLY,
            "validated and retained; focus-driven skill-domain selection is "
            "not wired and the legacy task stays empty (all skills)",
        ),
        WiringNote(
            "scan.reproduction",
            DECLARED_ONLY,
            "declared intent only; the internal dynamic reproduction "
            "experiment stays at its runtime default and is not enabled",
        ),
        timezone_note,
        stop_note,
        WiringNote(
            "execution.max_workers",
            DECLARED_ONLY,
            "scheduler wiring is pending; the effective concurrency uses the " "existing defaults",
        ),
    )


# --- Same-source JSON schema ------------------------------------------------------


def _section_schema(
    keys: Tuple[str, ...],
    schemas: Mapping[str, Dict[str, Any]],
    required: Tuple[str, ...],
    description: str,
    *,
    dependent_required: Optional[Mapping[str, Sequence[str]]] = None,
    all_of: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build one object schema from the same key tuple the parser enforces.

    ``dependent_required`` and ``all_of`` carry cross-field constraints that
    the key tables alone cannot express; they mirror the corresponding parser
    branches and are covered by the same-source tests.
    """

    drift = set(schemas) ^ set(keys)
    if drift:
        raise RuntimeError(
            "v3 schema field tables drifted from the parsing key tables: "
            + ", ".join(sorted(drift))
        )
    missing = [name for name in required if name not in keys]
    if missing:
        raise RuntimeError("v3 schema requires unparsed key(s): " + ", ".join(missing))
    result: Dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "description": description,
        "properties": {name: schemas[name] for name in keys},
    }
    if required:
        result["required"] = list(required)
    if dependent_required:
        result["dependentRequired"] = {
            name: list(value) for name, value in dependent_required.items()
        }
    if all_of:
        result["allOf"] = [dict(branch) for branch in all_of]
    return result


def _enum_schema(values: Tuple[str, ...], description: str) -> Dict[str, Any]:
    return {"type": "string", "enum": list(values), "description": description}


def _language_is(language: str) -> Dict[str, Any]:
    """Schema fragment matching ``project.language == language`` inside project."""

    return {"required": ["language"], "properties": {"language": {"const": language}}}


def _target_database_conditionals() -> List[Dict[str, Any]]:
    """Language-conditional compile database rules, from TARGET_DATABASE_RULE.

    The parser branch in ``_parse_project_v3`` reads the same rule table, so
    the schema and the parser cannot disagree about which language requires
    or forbids ``compile_commands``.
    """

    branches: List[Dict[str, Any]] = []
    for language in PROJECT_LANGUAGES:
        rule = TARGET_DATABASE_RULE[language]
        if rule == "forbidden":
            then: Dict[str, Any] = {
                "properties": {
                    "targets": {"items": {"properties": {"compile_commands": False}}},
                    "semantics_file": False,
                }
            }
        else:
            then = {
                "required": ["semantics_file"],
                "properties": {"targets": {"items": {"required": list(TARGET_KEYS)}}},
            }
        branches.append(
            {
                "if": _language_is(language),
                "then": then,
                "description": (
                    f"{LANGUAGE_DISPLAY_NAMES[language]} targets: " f"compile_commands is {rule}"
                ),
            }
        )
    return branches


def _preset_availability_conditionals() -> List[Dict[str, Any]]:
    """Language-conditional preset availability from the same mapping tables.

    Derived from PRESET_DEPTH_MAPPING and SCAN_DEPTHS_BY_LANGUAGE, the exact
    tables the parser gate reads.  When a language excludes the default
    preset, the document must declare an allowed preset explicitly because
    the parser rejects the defaulted tier for that language.
    """

    branches: List[Dict[str, Any]] = []
    for language in PROJECT_LANGUAGES:
        allowed = [
            preset
            for preset, depth in PRESET_DEPTH_MAPPING.items()
            if depth in SCAN_DEPTHS_BY_LANGUAGE.get(language, frozenset())
        ]
        if set(allowed) == set(SCAN_PRESETS):
            continue
        scan_then: Dict[str, Any] = {"properties": {"preset": {"enum": allowed}}}
        then: Dict[str, Any] = {"properties": {"scan": scan_then}}
        if SCAN_PRESETS[0] not in allowed:
            scan_then["required"] = ["preset"]
            then["required"] = ["scan"]
        branches.append(
            {
                "if": {
                    "required": ["project"],
                    "properties": {"project": _language_is(language)},
                },
                "then": then,
                "description": (
                    f"preset availability for {LANGUAGE_DISPLAY_NAMES[language]}: "
                    + ", ".join(allowed)
                ),
            }
        )
    return branches


def public_json_schema() -> Dict[str, Any]:
    """JSON Schema for the v3 document, generated from the parsing model."""

    project_fields: Dict[str, Dict[str, Any]] = {
        "language": {
            "type": "string",
            "enum": list(PROJECT_LANGUAGES),
            "description": "Project language; explicit, no loader-level auto-detection",
        },
        "platform": _enum_schema(
            PROJECT_PLATFORMS,
            "Target platform; only linux_user is accepted in this slice",
        ),
        "targets": {
            "type": "array",
            "minItems": 1,
            "description": (
                "Declared build targets; every id and path is retained. "
                "'compile_commands' is required for c_cpp and resolves against "
                "the configuration directory; it is forbidden for java (both enforced by the "
                "language-conditional allOf in this section)"
            ),
            "items": _section_schema(
                TARGET_KEYS,
                {
                    "id": {
                        "type": "string",
                        "minLength": 1,
                        "description": (
                            "Explicit target identity; unique within the document "
                            "(uniqueness is enforced by the loader)"
                        ),
                    },
                    "compile_commands": {
                        "type": "string",
                        "minLength": 1,
                        "description": (
                            "Path to the compile commands database, relative to the configuration directory"
                        ),
                    },
                },
                required=("id",),
                description="One build target with explicit identity",
            ),
        },
        "semantics_file": {
            "type": "string",
            "minLength": 1,
            "description": (
                "C/C++ project primitive contracts. The path is relative to the "
                "configuration directory and must stay inside the project root"
            ),
        },
    }
    scan_fields: Dict[str, Dict[str, Any]] = {
        "preset": _enum_schema(
            SCAN_PRESETS,
            "Quality tier replacing the legacy fast/balanced/deep depth",
        ),
        "focus": {
            "type": "array",
            "items": {"type": "string", "enum": list(FOCUS_AREAS)},
            "minItems": 1,
            "default": list(FOCUS_AREAS),
            "description": (
                "Declared focus areas; duplicate entries are accepted and "
                "normalized (order-preserving deduplication), matching the "
                "loader; retained, not yet wired to skill domains"
            ),
        },
        "reproduction": _enum_schema(
            REPRODUCTION_MODES,
            "Declared reproduction intent; does not enable the internal experiment",
        ),
    }
    execution_fields: Dict[str, Dict[str, Any]] = {
        "timezone": {
            "type": "string",
            "minLength": 1,
            "description": (
                "IANA timezone name such as Asia/Taipei; required whenever "
                "stop_at is set (dependentRequired); zone validity is "
                "enforced by the loader"
            ),
        },
        "stop_at": {
            "type": "string",
            # JSON Schema `pattern` is an unanchored search; the anchors make
            # it a full-string match, and the \s* margins mirror the loader's
            # whitespace normalization before its fullmatch check.
            "pattern": f"^\\s*{STOP_AT_PATTERN.pattern}\\s*$",
            "description": (
                "Local wall-clock 'HH:MM' as a full-string match (surrounding "
                "whitespace is normalized); resolved to the next occurrence "
                "as one absolute boundary, never a recurring schedule"
            ),
        },
        "max_workers": {
            "type": "integer",
            "minimum": 1,
            "description": "Declared worker budget; scheduler wiring is pending",
        },
    }
    profile_fields: Dict[str, Dict[str, Any]] = {
        "base_urls": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
            "description": "OpenAI-compatible endpoints; least-busy-first routing",
        },
        "models": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
            "description": "Candidate models in fallback order",
        },
        "api_key": {
            "type": "string",
            "minLength": 1,
            "description": "Credential; ${VAR} expansion applies",
        },
        "base_url_rate_limit_per_minute": {
            "type": "integer",
            "minimum": 1,
            "description": "Optional per-endpoint rate limit",
        },
        "base_url_max_concurrent_requests": {
            "type": "integer",
            "minimum": 1,
            "description": "Optional per-endpoint in-flight cap",
        },
        "max_tokens": {
            "type": "integer",
            "minimum": 1,
            "default": LLMConfig().max_tokens,
            "description": "Per-response token ceiling",
        },
        "context_window": {
            "type": "integer",
            "minimum": 1,
            "default": LLMConfig().context_window,
            "description": "Input plus output capacity; configure for the actual endpoint",
        },
        "model_context_windows": {
            "type": "object",
            "propertyNames": {"minLength": 1},
            "additionalProperties": {"type": "integer", "minimum": 1},
            "description": "Context capacity overrides keyed by exact request model name",
        },
        "timeout": {
            "type": ["number", "null"],
            "exclusiveMinimum": 0,
            "description": "Request timeout in seconds; null disables it",
        },
        "max_retries": {
            "type": "integer",
            "minimum": 0,
            "default": 2,
            "description": "Retry count for failed requests",
        },
        "retry_until_available": {
            "type": "boolean",
            "default": False,
            "description": "Retry indefinitely on transient errors",
        },
        "supports_structured_output": {
            "type": "boolean",
            "default": False,
            "description": "Use response_format for JSON output",
        },
    }
    root_all_of = _preset_availability_conditionals()
    schema: Dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Z-SCOPE public configuration v3",
        "description": (
            "One user configuration entry point generated from the parsing "
            "model in zscope/config/v3.py; the model is the single source. "
            "This schema expresses document shape only: the constraints in "
            "x-loader-enforced-constraints are enforced by the loader at "
            "parse time, so a schema-valid document is not guaranteed to load"
        ),
        "type": "object",
        "additionalProperties": False,
        "required": ["config_version", "llms", "project"],
        "properties": {
            "config_version": {
                "const": PUBLIC_CONFIG_VERSION_V3,
                "description": "Document version; must be 3",
            },
            "llms": {
                "type": "object",
                "minProperties": 1,
                "required": ["default"],
                "propertyNames": {"minLength": 1},
                "description": "LLM profile table; 'default' is required",
                "additionalProperties": _section_schema(
                    tuple(LLM_PROFILE_KEYS),
                    profile_fields,
                    required=("base_urls", "models", "api_key"),
                    description="One LLM profile",
                ),
            },
            "project": _section_schema(
                PROJECT_KEYS,
                project_fields,
                required=("language", "targets"),
                description="Project identity, root, platform, and build targets",
                all_of=_target_database_conditionals(),
            ),
            "scan": _section_schema(
                SCAN_KEYS,
                scan_fields,
                required=(),
                description="Scan quality tier, focus areas, and reproduction intent",
            ),
            "execution": _section_schema(
                EXECUTION_KEYS,
                execution_fields,
                required=(),
                description="Timezone, stop window, and worker budget",
                dependent_required={"stop_at": ["timezone"]},
            ),
        },
        "x-loader-enforced-constraints": list(LOADER_ENFORCED_CONSTRAINTS),
    }
    if root_all_of:
        schema["allOf"] = root_all_of
    return schema
