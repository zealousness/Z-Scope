"""Controlled dynamic reproduction as provider metadata for the shared adjudication.

This module closes the V01 loop: a memory-safety candidate is turned into an
independently replayable *witness* produced by a sanitizer runner, and that
witness is adapted back into the existing unified decision-proof qualification.
It deliberately does not introduce a second disposition system.

Design invariants (see ``docs/handoffs/2026-10-08-zscope/ACCEPTANCE.md``):

* An execution plan and its execution record are bound to the project, source
  revision, dependency content hash, candidate object/site/defect family, build
  configuration, toolchain, harness, inputs and the executed binary digest. A
  record produced for a different plan never proves the original candidate, and
  adjudication re-derives the *complete* binding from the current issue: any
  difference revokes the confirmation instead of degrading into a partial match.
* Serialized output is audit data, never a capability. Three process-local
  registries exist and none of them can be reconstructed from data:
  ``EXECUTION_AUTHORITY`` records that this process really ran a plan (with the
  runner's *trust*), ``REPLAY_AUTHORITY`` records replays that really ran, and
  ``CONFIRMATION_AUTHORITY`` holds the confirmation capability itself, keyed by
  the identity of the exact proof mapping that was minted. A copy - including a
  JSON round-trip inside the same process - is a different object and therefore
  has no authority. Capabilities expire on their own TTL, and
  ``release_dynamic_reproduction_authority()`` is the shutdown hook.
* Authenticity is not qualification. Every real execution is registered, but only
  ``register_dynamic_reproduction`` may mint confirmation authority, only after a
  fully qualified witness, and only for a *production* provider. A fake or
  test-trusted execution may attach a descriptive record (``outcome``
  ``inconclusive``, ``completeness`` ``incomplete``, no confirmation facts); it can
  never reach the shared adjudication.
* Nothing is launched on unverified identity. Before a run the runner re-hashes
  the harness, every declared input and the executed program, requires the
  command to name that program, and requires every path to sit inside an
  explicitly authorized execution root (an empty set authorizes nothing). A plan
  whose identity cannot be verified, or whose requested isolation cannot be
  provided, is refused with ``unsupported`` instead of being executed anyway.
* Provider outcomes are provider metadata. ``witness_observed`` may become a
  confirmation proof only after identity, classification and independent replay
  checks pass; ``not_reproduced``, ``inconclusive``, ``engine_failed``,
  ``unsupported`` and ``cancelled`` stay undecided and are never a safety
  refutation. Truncated output is ``inconclusive``, never a clean non-reproduction.
* Shadow candidates (K01 conditional observations and active-discovery shadow
  rows) can never be confirmed through this channel.
* The whole service is inert unless a policy explicitly enables it, so default
  scan behaviour is unchanged; the check is enforced at the runner boundary, not
  only by callers.

Resource limits and audit trails are recorded truthfully. AddressSanitizer
reserves a very large virtual address space, so ``RLIMIT_AS`` cannot be applied to
a sanitizer run; the limit is enforced through the tool's own per-allocation cap
and the difference (per-allocation cap is not total RSS, ThreadSanitizer applies
no memory limit at all) is stated in the execution record instead of being papered
over. Outside that per-allocation cap the runner keeps a real boundary: captured
output is spooled with a hard total byte budget and stopped at the cap (the digest
covers exactly the bytes that were captured), the resident set of a run is watched
through ``/proc`` and the process group is killed when it exceeds the declared
memory limit, and one wall-clock deadline covers the whole verification
(``build`` plus every run) so an authorization cannot be stretched by per-process
timeouts. Per-run logs, digests and byte counts are kept per replay; when the logs
are not published to an artifact directory the record says so rather than
presenting a digest as a location, and every execution publishes into its own
directory so a later execution of the same plan cannot overwrite it.

Every claim is re-derived from the current filesystem, not from a declaration:
before *each* run (and between a build and the run it was supposed to produce) the
harness, the declared inputs and the executed program are hashed again, and the
witness proof freezes the digests of the source files it was derived from, so a
file that changes after the execution revokes the confirmation instead of being
confirmed under an old identity. The POSIX ``resource`` module is optional: a
platform without it imports and uses this module, records that no rlimit was
applied there, and relies on the spool cap, the RSS watchdog and the deadline.

One execution is one run. ``execute()`` performs exactly one execution of the
plan (its authorized build plus one run), and ``plan.max_replays`` authorizes the
*total* number of plan executions for the whole verification: the scheduler
(``run_dynamic_reproduction``) spends one slot on the primary execution and shares
the rest with the required independent replays, recording a shortfall instead of
refusing before the provider has been dispatched. The shared budget counts real
process starts, so calling a replay from inside an execution cannot multiply the
authorization, and ``replay_witness`` on its own performs exactly the number of
executions it was asked for. A production confirmation requires *every* execution
- primary and each replay - to be production-trusted with verified inputs and a
candidate-matching witness of its own; test-trusted replays may still describe the
same evidence but can never complete a production confirmation. A plan whose own
build produces the executable binds the program's identity to the post-build hash
of that artifact (``binary_identity_source="post_build_output"``) instead of
requiring a digest that could not exist before the build ran.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping, Protocol, Sequence

try:  # POSIX resource limits are an optimization, never a requirement.
    import resource as _resource
except ImportError:  # pragma: no cover - exercised by the platform simulation test
    _resource = None  # type: ignore[assignment]

from ...common.cancellation import CancellationError, current_cancellation_token
from ...common.validator_protocol import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
)

DYNAMIC_EXECUTION_PLAN_VERSION = "zscope.dynamic-execution-plan.v1"
DYNAMIC_EXECUTION_RECORD_VERSION = "zscope.dynamic-execution-record.v2"
DYNAMIC_WITNESS_PROOF_KIND = "dynamic_witness_candidate_match"
DYNAMIC_WITNESS_PROOF_VERSION = "zscope.dynamic-witness-proof.v1"

PROVIDER_KINDS = frozenset({"fake", "asan", "tsan"})
REPRODUCTION_KINDS = {"fake": "test", "asan": "asan", "tsan": "tsan"}
COMPILER_FLAGS = {"asan": "-fsanitize=address", "tsan": "-fsanitize=thread"}

PROVIDER_OUTCOMES = frozenset(
    {
        "witness_observed",
        "not_reproduced",
        "inconclusive",
        "engine_failed",
        "unsupported",
        "cancelled",
    }
)

# Provider-layer outcome -> reserved ``DynamicReproductionResult`` outcome.
# ``unsupported`` and ``cancelled`` are undecided, so they map onto
# ``inconclusive`` instead of pretending an execution failed or that the
# obligation was refuted.
RESULT_OUTCOME_BY_PROVIDER_OUTCOME = {
    "witness_observed": "reproduced",
    "not_reproduced": "not_reproduced",
    "inconclusive": "inconclusive",
    "engine_failed": "failed",
    "unsupported": "inconclusive",
    "cancelled": "inconclusive",
}

# Provider outcomes that must never be promoted into a decision.
UNDECIDED_OUTCOMES = frozenset(
    {"not_reproduced", "inconclusive", "engine_failed", "unsupported", "cancelled"}
)

DYNAMIC_WITNESS_FACTS = (
    "candidate_object_matched",
    "candidate_site_matched",
    "defect_family_matched",
    "binary_identity_bound",
    "source_identity_bound",
    "replay_consistent",
)

# Sanitizer report kind -> accepted candidate defect-family tokens.
SANITIZER_FAMILY_TOKENS: Mapping[str, frozenset[str]] = {
    "heap-buffer-overflow": frozenset(
        {
            "heap_buffer_overflow",
            "buffer_overflow",
            "heap_overflow",
            "out_of_bounds",
            "out_of_bound",
            "buffer_oob",
            "oob_write",
            "oob_read",
            "oob",
            "cwe_787",
            "cwe_122",
        }
    ),
    "stack-buffer-overflow": frozenset(
        {"stack_buffer_overflow", "buffer_overflow", "out_of_bounds", "cwe_121", "cwe_787"}
    ),
    "global-buffer-overflow": frozenset(
        {"global_buffer_overflow", "buffer_overflow", "out_of_bounds", "cwe_787"}
    ),
    "heap-use-after-free": frozenset(
        {"use_after_free", "uaf", "heap_use_after_free", "dangling_pointer", "cwe_416"}
    ),
    "stack-use-after-return": frozenset(
        {"use_after_return", "stack_use_after_return", "dangling_pointer", "cwe_562"}
    ),
    "use-after-poison": frozenset({"use_after_poison", "use_after_free", "cwe_416"}),
    "double-free": frozenset({"double_free", "double_release", "cwe_415"}),
    "invalid-free": frozenset({"invalid_free", "bad_free", "cwe_590"}),
    "allocation-size-too-big": frozenset(
        {
            "allocation_size_too_big",
            "resource_exhaustion",
            "unbounded_allocation",
            "memory_limit_exceeded",
            "cwe_789",
        }
    ),
    "data-race": frozenset(
        {
            "data_race",
            "race_condition",
            "unsynchronized_access",
            "race_without_happens_before",
            "cwe_362",
        }
    ),
    "lock-order-inversion": frozenset({"lock_order_inversion", "deadlock", "cwe_833"}),
}

_ASAN_HEADER = re.compile(r"ERROR: AddressSanitizer: (?P<kind>[A-Za-z0-9\-]+)")
_ASAN_SUMMARY = re.compile(r"SUMMARY: AddressSanitizer")
_FRAME_WITH_PC = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<function>\S+)\s+"
    r"(?P<file>[^\s:][^:]*?):(?P<line>\d+)(?::(?P<column>\d+))?"
)
_TSAN_FRAME = re.compile(
    r"^\s*#(?P<index>\d+)\s+(?P<function>\S+)\s+"
    r"(?P<file>[^\s:][^:]*?):(?P<line>\d+)(?::(?P<column>\d+))?"
)
_ACCESS = re.compile(
    r"^(?P<access>READ|WRITE) of size (?P<size>\d+) at (?P<address>0x[0-9a-fA-F]+)"
)
_TSAN_ACCESS = re.compile(
    r"^\s*(?P<access>Read|Write|Atomic read|Atomic write) of size (?P<size>\d+) at "
    r"(?P<address>0x[0-9a-fA-F]+) by (?P<thread>.+):"
)
_REGION = re.compile(
    r"(?P<address>0x[0-9a-fA-F]+) is located (?P<offset>[^\[]*?)"
    r"(?P<region_size>\d+)-byte region \[(?P<start>0x[0-9a-fA-F]+),(?P<end>0x[0-9a-fA-F]+)\)"
)
_TSAN_LOCATION = re.compile(
    r"^\s*Location is (?P<scope>\w+) '(?P<name>[^']+)' of size (?P<size>\d+)"
)
_RESOURCE_EXHAUSTION = re.compile(
    r"(?i)(out of memory|exceeds maximum supported size|allocation size .{0,40}exceeds)"
)
_BUILD_FAILURE = re.compile(r"(?i)(error:|fatal error|undefined reference|ld returned)")


class DynamicReproductionError(ValueError):
    """Stable, source-free failure for misuse of the reproduction boundary."""


class _PlanViolation(Exception):
    """A plan asked to execute outside its declared scope."""


class _ToolUnavailable(Exception):
    """The requested execution tool is not usable on this host."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, default=str)


def _digest(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def hash_file(path: str | os.PathLike[str], *, limit: int | None = None) -> tuple[str, bytes]:
    """Return the sha256 of a whole file plus up to ``limit`` head bytes."""

    digest = hashlib.sha256()
    kept = bytearray()
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            digest.update(chunk)
            if limit is not None and len(kept) < limit:
                kept.extend(chunk[: limit - len(kept)])
    return digest.hexdigest(), bytes(kept)


def _normalize_site(value: str) -> tuple[str, int]:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return "", 0
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    match = re.match(r"^(?P<file>.+?):(?P<line>\d+)(?::\d+)?$", text)
    if match is None:
        return text, 0
    return match.group("file").strip(), int(match.group("line"))


def _normalize_tokens(value: str) -> frozenset[str]:
    return frozenset(part for part in re.split(r"[^0-9a-z]+", str(value or "").lower()) if part)


def _object_token(value: str) -> str:
    """Comparison token for a reported or declared object name."""

    return re.sub(r"[^0-9a-z_]+", "", str(value or "").strip().lower())


def _path_suffix_match(reported: str, expected: str) -> bool:
    left = str(reported or "").replace("\\", "/").strip()
    right = str(expected or "").replace("\\", "/").strip()
    if not left or not right:
        return False
    if left == right:
        return True
    return left.endswith("/" + right) or right.endswith("/" + left)


def families_match(finding_kind: str, defect_family: str) -> bool:
    """Return whether a sanitizer report kind is the candidate's defect family."""

    kind = str(finding_kind or "").strip().lower()
    if not kind:
        return False
    tokens = _normalize_tokens(defect_family)
    if not tokens:
        return False
    accepted = SANITIZER_FAMILY_TOKENS.get(kind, frozenset())
    if tokens & accepted:
        return True
    if kind.replace("-", "_") in tokens:
        return True
    # A candidate family may spell the same concept with more words
    # (``out_of_bounds_write`` for ``heap-buffer-overflow``): accept an accepted
    # token whose own tokens are a subset of the candidate's.
    for token in accepted:
        parts = frozenset(part for part in token.split("_") if part)
        if parts and parts <= tokens:
            return True
    return False


@dataclass(frozen=True)
class BuildSpec:
    """A program-owned build invocation belonging to a reproduction plan."""

    argv: tuple[str, ...]
    cwd: str
    timeout_seconds: int = 300
    environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.argv or not self.cwd:
            raise DynamicReproductionError("incomplete_build_spec")
        if self.timeout_seconds < 1:
            raise DynamicReproductionError("invalid_build_timeout")

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
            "environment": [[key, value] for key, value in self.environment],
        }


@dataclass(frozen=True)
class CandidateBinding:
    """Program-resolved identity of the candidate a witness must match."""

    project_id: str
    source_revision: str
    candidate_uid: str
    validation_cluster_uid: str
    object_identity: str
    site: str
    defect_family: str
    build_configuration: str
    toolchain_id: str
    # The source/dependency content digest is tracked separately from the
    # revision label: a candidate may keep its revision while the code it was
    # about has already changed.
    dependency_code_hash: str = ""
    rollout_visibility: str = ""
    candidate_kind: str = ""
    candidate_source: str = ""
    discovered_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        missing = [
            name
            for name in (
                "project_id",
                "source_revision",
                "candidate_uid",
                "validation_cluster_uid",
                "site",
                "defect_family",
            )
            if not str(getattr(self, name) or "").strip()
        ]
        if missing:
            raise DynamicReproductionError(
                "incomplete_candidate_binding:" + ",".join(sorted(missing))
            )

    @property
    def site_file(self) -> str:
        return _normalize_site(self.site)[0]

    @property
    def site_line(self) -> int:
        return _normalize_site(self.site)[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "source_revision": self.source_revision,
            "candidate_uid": self.candidate_uid,
            "validation_cluster_uid": self.validation_cluster_uid,
            "object_identity": self.object_identity,
            "site": self.site,
            "defect_family": self.defect_family,
            "build_configuration": self.build_configuration,
            "toolchain_id": self.toolchain_id,
            "dependency_code_hash": self.dependency_code_hash,
            "rollout_visibility": self.rollout_visibility,
            "candidate_kind": self.candidate_kind,
            "candidate_source": self.candidate_source,
            "discovered_by": list(self.discovered_by),
        }

    def digest(self) -> str:
        """Digest of the complete candidate identity.

        Adjudication compares this against a binding re-derived from the *current*
        issue, so a witness authorized for one object, site, defect family, build
        or toolchain can never be re-pointed at a changed candidate.
        """

        return _digest(self.to_dict())

    def mismatched_fields(self, other: CandidateBinding) -> tuple[str, ...]:
        """Field names where ``other`` differs from this binding."""

        mine = self.to_dict()
        theirs = other.to_dict()
        return tuple(sorted(name for name in mine if mine[name] != theirs[name]))


def _conditional_snapshot_shadow(binding: CandidateBinding) -> bool:
    return bool(
        binding.rollout_visibility.strip().lower() == "shadow"
        and binding.candidate_kind == "conditional_snapshot_observation"
        and binding.candidate_source == "semantic_snapshot"
        and {item.strip().lower() for item in binding.discovered_by if item.strip()}
        == {"semantic_modeling"}
    )


def is_shadow_candidate(binding: CandidateBinding) -> bool:
    """Fail-closed mirror of ``ValidationPipeline._is_rollout_shadow_candidate``.

    The mirror avoids an import cycle (the pipeline imports the proof selector).
    A dedicated test asserts both predicates agree on the pipeline's shadow
    samples so the two cannot drift silently.
    """

    if binding.rollout_visibility.strip().lower() != "shadow":
        return False
    if _conditional_snapshot_shadow(binding):
        return True
    sources = {item.strip().lower() for item in binding.discovered_by if item.strip()}
    if sources:
        return sources == {"llm_active_discovery"}
    return binding.candidate_source.strip().lower() == "active_discovery"


def bind_candidate(
    issue: Mapping[str, Any],
    *,
    project_id: str = "",
    source_revision: str = "",
    build_configuration: str = "",
    toolchain_id: str = "",
    object_identity: str = "",
    site: str = "",
    defect_family: str = "",
) -> CandidateBinding:
    """Resolve the candidate identity a witness has to match.

    Explicit overrides win; otherwise values are read from the issue mapping.
    Missing mandatory identity raises instead of silently degrading, because an
    unbound plan can never be evidence for a specific candidate.
    """

    pack = issue.get("evidence_pack")
    evidence_pack: Mapping[str, Any] = pack if isinstance(pack, Mapping) else {}
    attribution = issue.get("attribution")
    discovered = attribution.get("discovered_by") if isinstance(attribution, Mapping) else None

    def first(*keys: str) -> str:
        for key in keys:
            value = issue.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return str(value)
            if isinstance(evidence_pack, Mapping):
                nested = evidence_pack.get(key)
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()
        return ""

    resolved_project = project_id or first("project_id")
    resolved_revision = source_revision or first(
        "source_revision",
        "code_hash",
        "source_fingerprint",
        "revision",
    )
    resolved_uid = first("candidate_uid", "id", "issue_id", "finding_id")
    cluster = first("validation_cluster_uid", "dedup_key", "cluster_uid") or resolved_uid
    resolved_object = object_identity or first(
        "resource_identity",
        "object_identity",
        "object_key",
        "symbol",
        "sink_expression",
        "sink",
        "function",
    )
    resolved_site = site or first("location", "site", "source_location")
    if not resolved_site:
        file_value = first("file", "file_path", "path")
        line_value = first("line", "start_line")
        if file_value:
            resolved_site = f"{file_value}:{line_value}" if line_value else file_value
    resolved_family = defect_family or first(
        "defect_class", "category", "subcategory", "vuln_type", "rule_id", "rule"
    )
    return CandidateBinding(
        project_id=resolved_project,
        source_revision=resolved_revision,
        candidate_uid=resolved_uid,
        validation_cluster_uid=cluster,
        object_identity=resolved_object,
        site=resolved_site,
        defect_family=resolved_family,
        build_configuration=build_configuration
        or first("build_context_id", "build_configuration", "build_context", "compile_context")
        or "default",
        toolchain_id=toolchain_id or first("toolchain_id", "toolchain") or "unspecified",
        dependency_code_hash=first("dependency_code_hash", "code_hash", "source_fingerprint"),
        rollout_visibility=first("rollout_visibility"),
        candidate_kind=first("candidate_kind"),
        candidate_source=first("candidate_source"),
        discovered_by=tuple(
            str(item) for item in (discovered if isinstance(discovered, (list, tuple)) else [])
        ),
    )


@dataclass(frozen=True)
class ExecutionPlan:
    """A fully bound reproduction plan; a record must reference its digest."""

    plan_id: str
    binding: CandidateBinding
    provider_kind: str
    provider_name: str
    provider_version: str
    harness_ref: str
    harness_digest: str
    input_refs: tuple[str, ...]
    input_digests: tuple[str, ...]
    run_argv: tuple[str, ...]
    run_cwd: str
    env_allowlist: tuple[tuple[str, str], ...]
    timeout_seconds: int
    memory_limit_mb: int
    isolation: str
    max_replays: int
    binary_path: str
    binary_digest: str
    toolchain_id: str
    build_configuration: str
    build: BuildSpec | None = None
    allowed_exec_roots: tuple[str, ...] = ()
    site_tolerance_lines: int = 0
    plan_version: str = DYNAMIC_EXECUTION_PLAN_VERSION
    object_witness: Any = None
    require_exact_object: bool = False

    def __post_init__(self) -> None:
        if self.provider_kind not in PROVIDER_KINDS:
            raise DynamicReproductionError("unsupported_provider_kind")
        if not self.run_argv or not self.run_cwd:
            raise DynamicReproductionError("incomplete_execution_plan")
        if self.timeout_seconds < 1 or self.max_replays < 1:
            raise DynamicReproductionError("invalid_execution_limits")
        if self.memory_limit_mb < 0:
            raise DynamicReproductionError("invalid_memory_limit")
        if self.isolation not in {"process", "user_net_namespace"}:
            raise DynamicReproductionError("unsupported_isolation_mode")
        if len(self.input_refs) != len(self.input_digests):
            raise DynamicReproductionError("input_identity_mismatch")

    @property
    def binding_digest(self) -> str:
        return _digest(
            {
                "binding": self.binding.to_dict(),
                "harness": [self.harness_ref, self.harness_digest],
                "inputs": [list(self.input_refs), list(self.input_digests)],
                "binary": [self.binary_path, self.binary_digest],
                "toolchain": self.toolchain_id,
                "build_configuration": self.build_configuration,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.plan_version,
            "plan_id": self.plan_id,
            "binding": self.binding.to_dict(),
            "binding_digest": self.binding_digest,
            "provider_kind": self.provider_kind,
            "provider_name": self.provider_name,
            "provider_version": self.provider_version,
            "harness_ref": self.harness_ref,
            "harness_digest": self.harness_digest,
            "input_refs": list(self.input_refs),
            "input_digests": list(self.input_digests),
            "run_argv": list(self.run_argv),
            "run_cwd": self.run_cwd,
            "env_allowlist": [[key, value] for key, value in self.env_allowlist],
            "timeout_seconds": self.timeout_seconds,
            "memory_limit_mb": self.memory_limit_mb,
            "isolation": self.isolation,
            "max_replays": self.max_replays,
            "binary_path": self.binary_path,
            "binary_digest": self.binary_digest,
            "toolchain_id": self.toolchain_id,
            "build_configuration": self.build_configuration,
            "allowed_exec_roots": list(self.allowed_exec_roots),
            "site_tolerance_lines": self.site_tolerance_lines,
            "build": self.build.to_dict() if self.build is not None else None,
            "object_witness": self.object_witness.to_dict() if self.object_witness else None,
            "require_exact_object": self.require_exact_object,
        }

    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True)
class SanitizerFinding:
    """One classified sanitizer report."""

    kind: str
    access: str
    frames: tuple[str, ...]
    allocation_frames: tuple[str, ...]
    object_ref: str
    site: str
    source_mapping: tuple[str, ...]
    raw_digest: str
    thread: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "access": self.access,
            "frames": list(self.frames),
            "allocation_frames": list(self.allocation_frames),
            "object_ref": self.object_ref,
            "site": self.site,
            "source_mapping": list(self.source_mapping),
            "raw_digest": self.raw_digest,
            "thread": self.thread,
        }


@dataclass(frozen=True)
class RunEvidence:
    """Audit-grade evidence for exactly one replayed execution.

    Every replay keeps its own outcome, classification, findings, log digests and
    published artifacts, so a later reader can see which run observed what
    instead of only the first finding and the last log excerpt.
    """

    index: int
    outcome: str
    detail: str = ""
    exit_code: int | None = None
    signal_number: int | None = None
    timed_out: bool = False
    oom_killed: bool = False
    classifications: tuple[str, ...] = ()
    findings: tuple[SanitizerFinding, ...] = ()
    stdout_digest: str = ""
    stderr_digest: str = ""
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    output_truncated: bool = False
    artifacts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "outcome": self.outcome,
            "detail": self.detail,
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "oom_killed": self.oom_killed,
            "classifications": list(self.classifications),
            "findings": [item.to_dict() for item in self.findings],
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "output_truncated": self.output_truncated,
            "artifacts": list(self.artifacts),
        }


@dataclass(frozen=True)
class ExecutionRecord:
    """Raw execution evidence produced by exactly one runner invocation."""

    record_id: str
    plan_digest: str
    provider_name: str
    provider_version: str
    provider_kind: str
    outcome: str
    run_argv: tuple[str, ...]
    run_cwd: str
    environment: tuple[tuple[str, str], ...]
    isolation: str
    isolation_verified: bool
    isolation_notes: tuple[str, ...]
    build_argv: tuple[str, ...]
    build_exit_code: int | None
    build_stdout_digest: str
    build_stderr_digest: str
    build_stdout_excerpt: str
    build_stderr_excerpt: str
    exit_code: int | None
    signal_number: int | None
    timed_out: bool
    oom_killed: bool
    binary_digest: str
    binary_path: str
    stdout_digest: str
    stderr_digest: str
    stdout_excerpt: str
    stderr_excerpt: str
    findings: tuple[SanitizerFinding, ...]
    replay_classifications: tuple[str, ...]
    replay_count: int
    duration_ms: int
    memory_limit_mode: str
    runs: tuple[RunEvidence, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    artifact_root: str = ""
    inputs_verified: bool = False
    input_verification_digest: str = ""
    # Execution-time snapshot of the accepted source/harness/input files. It is
    # captured when the plan identity is accepted and carried unchanged into the
    # record/receipt, so registration compares these digests instead of re-hashing.
    source_digests: tuple[tuple[str, str], ...] = ()
    # How the executed program's identity was established: ``plan_declared`` when
    # the plan named the digest, ``post_build_output`` when this plan's own
    # authorized build produced the artifact and it was hashed afterwards.
    binary_identity_source: str = ""
    limitations: tuple[str, ...] = ()
    detail: str = ""
    attestation: str = ""
    record_version: str = DYNAMIC_EXECUTION_RECORD_VERSION

    def __post_init__(self) -> None:
        if self.provider_kind not in PROVIDER_KINDS:
            raise DynamicReproductionError("unsupported_provider_kind")
        if self.outcome not in PROVIDER_OUTCOMES:
            raise DynamicReproductionError("unsupported_provider_outcome")
        if not self.plan_digest or not self.record_id:
            raise DynamicReproductionError("incomplete_execution_record")

    @property
    def classification(self) -> str:
        return self.replay_classifications[0] if self.replay_classifications else ""

    @property
    def replay_consistent(self) -> bool:
        return bool(self.replay_classifications) and len(set(self.replay_classifications)) == 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.record_version,
            "record_id": self.record_id,
            "plan_digest": self.plan_digest,
            "provider_name": self.provider_name,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind,
            "outcome": self.outcome,
            "run_argv": list(self.run_argv),
            "run_cwd": self.run_cwd,
            "environment": [[key, value] for key, value in self.environment],
            "isolation": self.isolation,
            "isolation_verified": self.isolation_verified,
            "isolation_notes": list(self.isolation_notes),
            "build_argv": list(self.build_argv),
            "build_exit_code": self.build_exit_code,
            "build_stdout_digest": self.build_stdout_digest,
            "build_stderr_digest": self.build_stderr_digest,
            "build_stdout_excerpt": self.build_stdout_excerpt,
            "build_stderr_excerpt": self.build_stderr_excerpt,
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "oom_killed": self.oom_killed,
            "binary_digest": self.binary_digest,
            "binary_path": self.binary_path,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "stdout_excerpt": self.stdout_excerpt,
            "stderr_excerpt": self.stderr_excerpt,
            "findings": [item.to_dict() for item in self.findings],
            "replay_classifications": list(self.replay_classifications),
            "replay_count": self.replay_count,
            "duration_ms": self.duration_ms,
            "memory_limit_mode": self.memory_limit_mode,
            "runs": [item.to_dict() for item in self.runs],
            "artifact_refs": list(self.artifact_refs),
            "artifact_root": self.artifact_root,
            "inputs_verified": self.inputs_verified,
            "input_verification_digest": self.input_verification_digest,
            "source_digests": [[path, digest] for path, digest in self.source_digests],
            "binary_identity_source": self.binary_identity_source,
            "limitations": list(self.limitations),
            "detail": self.detail,
        }

    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True)
class ReplayRun:
    """One independent re-execution of the plan."""

    index: int
    record_id: str
    outcome: str
    classifications: tuple[str, ...]
    findings: tuple[SanitizerFinding, ...]
    binary_digest: str
    execution_token: str = ""
    # Every run this re-execution performed, so nested runs are auditable and are
    # matched to the candidate individually instead of through an aggregate.
    runs: tuple[RunEvidence, ...] = ()
    binary_identity_source: str = ""
    input_verification_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "record_id": self.record_id,
            "outcome": self.outcome,
            "classifications": list(self.classifications),
            "findings": [item.to_dict() for item in self.findings],
            "binary_digest": self.binary_digest,
            "binary_identity_source": self.binary_identity_source,
            "input_verification_digest": self.input_verification_digest,
            "runs": [item.to_dict() for item in self.runs],
        }


@dataclass(frozen=True)
class ReplayEvidence:
    """Result of independently re-executing the same plan.

    The summary fields are descriptive only. Confirmation additionally requires
    the exact ``ReplayEvidence`` object to be registered in the process-local
    replay authority together with live execution receipts for every run, so a
    hand-built or deserialized replay claim cannot stand in for real execution.
    """

    plan_digest: str
    binary_digest: str
    classifications: tuple[str, ...]
    provider_name: str
    provider_version: str
    runs: tuple[ReplayRun, ...] = ()

    @property
    def consistent(self) -> bool:
        return bool(self.classifications) and len(set(self.classifications)) == 1

    @property
    def observed_outcomes(self) -> tuple[str, ...]:
        return tuple(run.outcome for run in self.runs)

    @property
    def all_witnesses_observed(self) -> bool:
        return bool(self.runs) and all(run.outcome == "witness_observed" for run in self.runs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_digest": self.plan_digest,
            "binary_digest": self.binary_digest,
            "classifications": list(self.classifications),
            "consistent": self.consistent,
            "provider_name": self.provider_name,
            "provider_version": self.provider_version,
            "runs": [run.to_dict() for run in self.runs],
        }


@dataclass(frozen=True)
class ProviderAvailability:
    available: bool
    reason: str = ""
    details: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"available": self.available, "reason": self.reason, "details": dict(self.details)}


@dataclass(frozen=True)
class DynamicReproductionPolicy:
    """Explicit opt-in policy. Every default keeps current scan behaviour."""

    enabled: bool = False
    # ``shadow`` records provider metadata without granting confirmation
    # authority, so a rollout can be measured before it can confirm anything.
    attach_proof: bool = True
    required_replays: int = 2
    max_replays: int = 3
    timeout_seconds: int = 30
    build_timeout_seconds: int = 300
    # One wall-clock deadline for the whole verification (build plus every run).
    # Per-process timeouts are a separate, weaker bound and cannot be used to
    # stretch an authorization.
    deadline_seconds: int = 900
    memory_limit_mb: int = 512
    isolation: str = "process"
    allow_net_namespace: bool = True
    output_excerpt_bytes: int = 8192
    # Hard byte budget for one captured stream. stdout/stderr are spooled to disk
    # and writing stops at this cap, so the on-disk total of one execution is at
    # most twice this value. A capped stream is reported as truncated and never
    # interpreted as a complete absence of a sanitizer report.
    output_capture_limit_bytes: int = 4 * 1024 * 1024
    # How often the resident set of a running process group is sampled while a
    # memory limit applies to a runtime that cannot take RLIMIT_AS.
    rss_poll_seconds: float = 0.05
    site_tolerance_lines: int = 0
    keep_workdir: bool = False
    # When set, per-run logs are published here before the work directory is
    # removed, so the record's artifact refs stay resolvable. Each execution
    # publishes into its own subdirectory and cannot overwrite an earlier one.
    artifact_dir: str = ""
    # Process-local confirmation authority expires on its own instead of
    # relying on a caller remembering to clear a global registry.
    authority_ttl_seconds: int = 900

    def __post_init__(self) -> None:
        if self.required_replays < 1 or self.max_replays < self.required_replays:
            raise DynamicReproductionError("invalid_replay_policy")
        if self.timeout_seconds < 1 or self.build_timeout_seconds < 1:
            raise DynamicReproductionError("invalid_timeout_policy")
        if self.deadline_seconds < 1:
            raise DynamicReproductionError("invalid_deadline_policy")
        if self.isolation not in {"process", "user_net_namespace"}:
            raise DynamicReproductionError("unsupported_isolation_mode")
        if self.output_capture_limit_bytes < 1:
            raise DynamicReproductionError("invalid_output_capture_limit")
        if self.authority_ttl_seconds < 1:
            raise DynamicReproductionError("invalid_authority_ttl")


@dataclass(frozen=True)
class Qualification:
    """Why a witness may or may not become adjudication input."""

    qualified: bool
    facts: Mapping[str, bool]
    reasons: tuple[str, ...]
    finding: SanitizerFinding | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "qualified": self.qualified,
            "facts": dict(self.facts),
            "reasons": list(self.reasons),
            "finding": self.finding.to_dict() if self.finding is not None else None,
        }


@dataclass(frozen=True)
class DynamicReproductionOutcome:
    """Provider metadata adapted onto one candidate; not a disposition."""

    request: DynamicReproductionRequest
    result: DynamicReproductionResult
    record: ExecutionRecord
    qualification: Qualification
    proof_attached: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "result": self.result.to_dict(),
            "record": self.record.to_dict(),
            "qualification": self.qualification.to_dict(),
            "proof_attached": self.proof_attached,
        }


class DynamicReproductionProvider(Protocol):
    """Minimal provider boundary shared by fake and sanitizer runners."""

    name: str
    version: str
    kind: str

    def availability(self) -> ProviderAvailability: ...

    def execute(self, plan: ExecutionPlan) -> ExecutionRecord: ...


TRUST_PRODUCTION = "production"
TRUST_TEST = "test"


@dataclass(frozen=True)
class _ExecutionEntry:
    """One genuinely executed record still held by this process."""

    token: str
    trust: str
    plan_digest: str
    record_digest: str
    binding_digest: str
    candidate_uid: str
    binary_digest: str
    provider_kind: str
    provider_name: str
    provider_version: str
    isolation: str
    isolation_verified: bool
    inputs_verified: bool
    witness_digest: str
    expires_at: float
    binary_path: str = ""
    binary_evidence_digest: str = ""
    binary_bound: bool = False
    binary_required: bool = False

    @property
    def production(self) -> bool:
        return self.trust == TRUST_PRODUCTION


@dataclass(frozen=True)
class _ReplayEntry:
    """One independently re-executed replay, keyed by object identity."""

    evidence: Any
    plan_digest: str
    binding_digest: str
    execution_tokens: tuple[str, ...]
    expires_at: float


@dataclass(frozen=True)
class _ConfirmationEntry:
    """Confirmation capability minted for exactly one proof object."""

    proof: Any
    plan_digest: str
    record_digest: str
    binding_digest: str
    candidate_uid: str
    execution_token: str
    witness_digest: str
    expires_at: float
    source_digests: tuple[tuple[str, str], ...] = ()
    task_scope: str = ""


class _ExecutionAuthority:
    """Process-scoped registry of genuinely executed records.

    Execution authenticity and confirmation qualification are deliberately
    separate: every real run is registered here, but registration alone grants
    nothing. Only ``register_dynamic_reproduction`` may mint confirmation
    authority, and only for a production provider whose evidence qualified.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._live: dict[str, _ExecutionEntry] = {}

    def register(
        self,
        record: ExecutionRecord,
        *,
        trust: str,
        binding_digest: str,
        candidate_uid: str,
        inputs_verified: bool,
        witness_digest: str = "",
        ttl_seconds: int = 900,
    ) -> str:
        token = hashlib.sha256(
            b"zscope-dynamic-execution"
            + os.urandom(16)
            + record.plan_digest.encode("utf-8")
            + record.digest().encode("utf-8")
        ).hexdigest()
        # Freeze the actual binary accepted at execution time. Real production
        # runs must have a still-matching file; test runs may be symbolic, but
        # any real file they used is bound for later drift checks.
        binary_path = str(getattr(record, "binary_path", "") or "")
        recorded_digest = str(getattr(record, "binary_digest", "") or "")
        measured = ""
        if binary_path:
            try:
                if os.path.isfile(binary_path):
                    measured = hash_file(binary_path)[0]
            except OSError:
                measured = ""
        binary_required = trust == TRUST_PRODUCTION
        if binary_required:
            binary_bound = bool(measured) and bool(recorded_digest) and measured == recorded_digest
            binary_evidence = recorded_digest if binary_bound else ""
        else:
            binary_bound = bool(measured)
            binary_evidence = measured
        with self._lock:
            self._prune()
            self._live[token] = _ExecutionEntry(
                token=token,
                trust=trust,
                plan_digest=record.plan_digest,
                record_digest=record.digest(),
                binding_digest=str(binding_digest),
                candidate_uid=str(candidate_uid),
                binary_digest=record.binary_digest,
                provider_kind=record.provider_kind,
                provider_name=record.provider_name,
                provider_version=record.provider_version,
                isolation=record.isolation,
                isolation_verified=bool(record.isolation_verified),
                inputs_verified=bool(inputs_verified),
                witness_digest=str(witness_digest),
                expires_at=time.monotonic() + max(1, int(ttl_seconds)),
                binary_path=binary_path,
                binary_evidence_digest=binary_evidence,
                binary_bound=binary_bound,
                binary_required=binary_required,
            )
        return token

    def entry(self, token: str) -> _ExecutionEntry | None:
        if not token:
            return None
        with self._lock:
            self._prune()
            return self._live.get(token)

    def promote(self, token: str) -> bool:
        """Re-trust one live execution as production (test-injection only).

        The injection states that the caller has independently verified the plan
        identity for this execution, which is exactly what a real provider does
        before launching.
        """

        with self._lock:
            self._prune()
            entry = self._live.get(token)
            if entry is None:
                return False
            self._live[token] = replace(entry, trust=TRUST_PRODUCTION, inputs_verified=True)
            return True

    def is_live(self, token: str) -> bool:
        return self.entry(token) is not None

    def release(self, token: str) -> None:
        with self._lock:
            self._live.pop(token, None)

    def release_scope(self, *, plan_digest: str = "", binding_digest: str = "") -> int:
        released = 0
        with self._lock:
            for token, entry in list(self._live.items()):
                if plan_digest and entry.plan_digest != plan_digest:
                    continue
                if binding_digest and entry.binding_digest != binding_digest:
                    continue
                self._live.pop(token, None)
                released += 1
        return released

    def clear(self) -> None:
        with self._lock:
            self._live.clear()

    def live_count(self) -> int:
        with self._lock:
            self._prune()
            return len(self._live)

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [token for token, entry in self._live.items() if entry.expires_at <= now]
        for token in expired:
            self._live.pop(token, None)


class _ReplayAuthority:
    """Process-scoped registry of replays that really ran, keyed by identity."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._live: dict[int, _ReplayEntry] = {}

    def register(
        self,
        evidence: ReplayEvidence,
        *,
        plan_digest: str,
        binding_digest: str,
        execution_tokens: Sequence[str],
        ttl_seconds: int = 900,
    ) -> None:
        with self._lock:
            self._prune()
            self._live[id(evidence)] = _ReplayEntry(
                evidence=evidence,
                plan_digest=str(plan_digest),
                binding_digest=str(binding_digest),
                execution_tokens=tuple(str(item) for item in execution_tokens),
                expires_at=time.monotonic() + max(1, int(ttl_seconds)),
            )

    def entry(self, evidence: ReplayEvidence) -> _ReplayEntry | None:
        with self._lock:
            self._prune()
            entry = self._live.get(id(evidence))
        # ``is`` guards against id reuse after the original object is collected.
        return entry if entry is not None and entry.evidence is evidence else None

    def release(self, evidence: ReplayEvidence) -> None:
        with self._lock:
            self._live.pop(id(evidence), None)

    def release_scope(self, *, plan_digest: str = "", binding_digest: str = "") -> int:
        released = 0
        with self._lock:
            for key, entry in list(self._live.items()):
                if plan_digest and entry.plan_digest != plan_digest:
                    continue
                if binding_digest and entry.binding_digest != binding_digest:
                    continue
                self._live.pop(key, None)
                released += 1
        return released

    def clear(self) -> None:
        with self._lock:
            self._live.clear()

    def live_count(self) -> int:
        with self._lock:
            self._prune()
            return len(self._live)

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [key for key, entry in self._live.items() if entry.expires_at <= now]
        for key in expired:
            self._live.pop(key, None)


class _ConfirmationAuthority:
    """Process-scoped confirmation capability, keyed by proof object identity.

    A copy of the proof mapping - including a JSON round-trip inside the same
    process - is a different object and therefore has no authority. Nothing here
    can be reconstructed from serialized data: losing this registry loses the
    capability for good.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._live: dict[int, _ConfirmationEntry] = {}

    def mint(
        self,
        proof: Any,
        *,
        plan_digest: str,
        record_digest: str,
        binding_digest: str,
        candidate_uid: str,
        execution_token: str,
        witness_digest: str,
        ttl_seconds: int = 900,
        source_digests: Sequence[tuple[str, str]] = (),
        task_scope: str = "",
    ) -> None:
        with self._lock:
            self._prune()
            self._live[id(proof)] = _ConfirmationEntry(
                proof=proof,
                plan_digest=str(plan_digest),
                record_digest=str(record_digest),
                binding_digest=str(binding_digest),
                candidate_uid=str(candidate_uid),
                execution_token=str(execution_token),
                witness_digest=str(witness_digest),
                expires_at=time.monotonic() + max(1, int(ttl_seconds)),
                source_digests=tuple((str(path), str(digest)) for path, digest in source_digests),
                task_scope=str(task_scope),
            )

    def lookup(self, proof: Mapping[str, Any]) -> _ConfirmationEntry | None:
        with self._lock:
            self._prune()
            entry = self._live.get(id(proof))
        return entry if entry is not None and entry.proof is proof else None

    def retire_for_execution(self, token: str) -> None:
        with self._lock:
            for key, entry in list(self._live.items()):
                if entry.execution_token == token:
                    self._live.pop(key, None)

    def release_scope(self, *, plan_digest: str = "", binding_digest: str = "") -> int:
        """Retire only the capabilities belonging to one task.

        A scan pass releases what its own attempt created instead of clearing the
        process-wide registry, so a concurrent task keeps its own capability.
        """

        released = 0
        with self._lock:
            for key, entry in list(self._live.items()):
                if plan_digest and entry.plan_digest != plan_digest:
                    continue
                if binding_digest and entry.binding_digest != binding_digest:
                    continue
                self._live.pop(key, None)
                released += 1
        return released

    def clear(self) -> None:
        with self._lock:
            self._live.clear()

    def live_count(self) -> int:
        with self._lock:
            self._prune()
            return len(self._live)

    def _prune(self) -> None:
        now = time.monotonic()
        expired = [key for key, entry in self._live.items() if entry.expires_at <= now]
        for key in expired:
            self._live.pop(key, None)


EXECUTION_AUTHORITY = _ExecutionAuthority()
REPLAY_AUTHORITY = _ReplayAuthority()
CONFIRMATION_AUTHORITY = _ConfirmationAuthority()
# Backwards-compatible name: this is the confirmation registry only.
WITNESS_AUTHORITY = CONFIRMATION_AUTHORITY


def witness_authority_clear() -> None:
    """Drop every process-local capability; used on shutdown and by tests."""

    EXECUTION_AUTHORITY.clear()
    REPLAY_AUTHORITY.clear()
    CONFIRMATION_AUTHORITY.clear()


def release_dynamic_reproduction_authority(
    *, plan_digest: str = "", binding_digest: str = ""
) -> int:
    """Release dynamic-reproduction capabilities held by this process.

    With no selector this is the shutdown hook and drops everything. With a plan
    or binding digest it retires only the capabilities of that task, which is what
    a scan pass uses after its own candidate was adjudicated: clearing the whole
    registry would also destroy a concurrent task's capability.
    """

    if not plan_digest and not binding_digest:
        witness_authority_clear()
        return 0
    released = CONFIRMATION_AUTHORITY.release_scope(
        plan_digest=plan_digest, binding_digest=binding_digest
    )
    released += REPLAY_AUTHORITY.release_scope(
        plan_digest=plan_digest, binding_digest=binding_digest
    )
    released += EXECUTION_AUTHORITY.release_scope(
        plan_digest=plan_digest, binding_digest=binding_digest
    )
    return released


def release_issue_dynamic_reproduction_authority(issue: Mapping[str, Any]) -> int:
    """Release the capabilities created for one candidate's verification.

    The scan calls this once the candidate's own adjudication is complete. Only
    the capabilities belonging to that candidate's plan are retired, so a
    concurrent candidate keeps its own authority; the TTL still retires anything a
    caller never releases, and ``release_dynamic_reproduction_authority()``
    without a selector remains the process shutdown hook.
    """

    meta = issue.get("dynamic_reproduction")
    if not isinstance(meta, Mapping):
        return 0
    plan_meta = meta.get("plan")
    declared = plan_meta if isinstance(plan_meta, Mapping) else {}
    # Capabilities are minted against the *candidate* binding digest, which is
    # re-derived from the issue here; the plan's own ``binding_digest`` field is a
    # plan-scoped digest used for evidence references and is not the same value.
    try:
        binding_digest = bind_candidate(issue).digest()
    except DynamicReproductionError:
        binding_digest = str(declared.get("binding_digest") or "")
    if not binding_digest:
        return 0
    return release_dynamic_reproduction_authority(binding_digest=binding_digest)


def inject_test_execution_authority(token: str, *, reason: str) -> None:
    """Promote one live test-trust execution to production trust.

    This exists so the deterministic suite can exercise the confirmation path
    without a sanitizer toolchain. It is the single explicit switch that does so,
    it requires a stated reason, it refuses an unknown token, and no product code
    calls it. Without it a fake or test-trusted execution can never mint a
    confirmation, which is exactly the boundary the production path relies on.
    """

    if not str(reason or "").strip():
        raise DynamicReproductionError("test_authority_requires_reason")
    if not EXECUTION_AUTHORITY.promote(str(token or "")):
        raise DynamicReproductionError("test_authority_token_not_live")


def frozen_source_digests(
    binding: CandidateBinding, plan: ExecutionPlan
) -> tuple[tuple[str, str], ...]:
    """Digests of the real source files a witness was derived from.

    These are the files the confirmation will be re-checked against at the final
    boundary: the candidate's own source file, the harness and every declared
    input. Only files that can actually be hashed are recorded, so a synthetic
    path cannot turn into a claim about a snapshot that was never read.
    """

    seen: dict[str, str] = {}
    for path in (binding.site_file, plan.harness_ref, *plan.input_refs):
        candidate = str(path or "")
        if not candidate or candidate in seen:
            continue
        try:
            if not os.path.isfile(candidate):
                continue
            seen[candidate] = hash_file(candidate)[0]
        except OSError:
            continue
    return tuple(sorted(seen.items()))


def source_digests_hold(source_digests: Sequence[tuple[str, str]]) -> bool:
    """Whether every frozen file still has exactly the recorded content."""

    for path, digest in source_digests:
        try:
            if not os.path.isfile(path):
                return False
            if hash_file(path)[0] != digest:
                return False
        except OSError:
            return False
    return True


def binary_binding_holds(path: str, digest: str) -> bool:
    """Whether the accepted binary still has exactly the recorded content.

    Missing, unreadable and changed files all fail: the check reads the actual
    bytes and never treats an absent file as a reason to stop checking.
    """

    if not path or not digest:
        return False
    try:
        if not os.path.isfile(path):
            return False
        return hash_file(path)[0] == digest
    except OSError:
        return False


def execution_binary_holds(entry: "_ExecutionEntry") -> bool:
    """Whether a live execution's accepted binary still backs confirmation.

    An execution that bound a real binary file must still match the digest
    accepted at execution time. An execution that bound nothing only qualifies
    when it never required binding, i.e. the symbolic test-only fixture; a real
    production execution always requires a bound binary.
    """

    if entry.binary_bound:
        return binary_binding_holds(entry.binary_path, entry.binary_evidence_digest)
    return not entry.binary_required


def dynamic_witness_proof_is_live(
    proof: Mapping[str, Any], issue: Mapping[str, Any] | None = None
) -> bool:
    """Whether a proof record still holds in-process confirmation authority.

    Four independent conditions must hold: the exact proof object must have been
    minted by the registrar in this process, the execution it derives from must
    still be live, the *actual source files* it was derived from must still have
    the content they had when the execution was verified, and - when an issue is
    supplied - the *complete* candidate identity re-derived from that issue must
    equal the authorized binding. A copied, edited, renamed or re-pointed proof
    therefore has no authority, and neither does one whose source file, object,
    site, defect family, build or toolchain changed since the execution. A changed
    file revokes the confirmation even when no upstream pass has refreshed the
    issue mapping yet, because the check reads the filesystem, not the mapping.
    """

    if not isinstance(proof, Mapping):
        return False
    entry = CONFIRMATION_AUTHORITY.lookup(proof)
    if entry is None:
        return False
    execution = EXECUTION_AUTHORITY.entry(entry.execution_token)
    if execution is None:
        return False
    if not execution_binary_holds(execution):
        return False
    if entry.source_digests and not source_digests_hold(entry.source_digests):
        return False
    if issue is not None:
        try:
            current = bind_candidate(issue)
        except DynamicReproductionError:
            return False
        if current.digest() != entry.binding_digest:
            return False
        if str(proof.get("code_hash") or "") != entry.binding_digest:
            return False
    return True


def parse_asan_report(text: str, *, raw_digest: str = "") -> tuple[SanitizerFinding, ...]:
    """Parse AddressSanitizer reports without trusting surrounding log text."""

    findings: list[SanitizerFinding] = []
    lines = str(text or "").splitlines()
    index = 0
    while index < len(lines):
        header = _ASAN_HEADER.search(lines[index])
        if header is None:
            index += 1
            continue
        kind = header.group("kind").strip().lower()
        access = ""
        address = ""
        thread = ""
        frames: list[str] = []
        allocation_frames: list[str] = []
        source_mapping: list[str] = []
        object_ref = ""
        cursor = index + 1
        section = "access"
        while cursor < len(lines):
            line = lines[cursor]
            if _ASAN_SUMMARY.search(line):
                break
            if _ASAN_HEADER.search(line) and frames:
                break
            access_match = _ACCESS.match(line)
            if access_match is not None and not access:
                access = access_match.group("access").strip().lower()
                address = access_match.group("address")
                thread_match = re.search(r"thread (T\d+)", line)
                if thread_match is not None:
                    thread = thread_match.group(1)
            if not object_ref:
                region_match = _REGION.search(line)
                if region_match is not None:
                    object_ref = region_match.group("address")
            if "allocated by thread" in line:
                section = "allocation"
            frame_match = _FRAME_WITH_PC.match(line)
            if frame_match is not None:
                function = frame_match.group("function")
                file_name = frame_match.group("file").strip()
                line_number = frame_match.group("line")
                rendered = f"{function} {file_name}:{line_number}"
                if section == "allocation":
                    allocation_frames.append(rendered)
                else:
                    frames.append(rendered)
                    source_mapping.append(f"{file_name}:{line_number}")
            cursor += 1
        if not frames:
            # A bare ``ERROR: AddressSanitizer: ...`` line carries no location and
            # can never be bound to a candidate, so it is not a witness.
            index = max(cursor, index + 1)
            continue
        findings.append(
            SanitizerFinding(
                kind=kind,
                access=access,
                frames=tuple(frames),
                allocation_frames=tuple(allocation_frames),
                object_ref=address or object_ref,
                site=frames[0].split()[-1] if frames else "",
                source_mapping=tuple(dict.fromkeys(source_mapping)),
                raw_digest=raw_digest,
                thread=thread,
            )
        )
        index = max(cursor, index + 1)
    return tuple(findings)


def parse_tsan_report(text: str, *, raw_digest: str = "") -> tuple[SanitizerFinding, ...]:
    """Parse ThreadSanitizer reports."""

    findings: list[SanitizerFinding] = []
    lines = str(text or "").splitlines()
    index = 0
    while index < len(lines):
        header = re.search(r"WARNING: ThreadSanitizer: (?P<kind>[A-Za-z0-9 \-]+)", lines[index])
        if header is None:
            index += 1
            continue
        kind = header.group("kind").strip().lower().replace(" ", "-")
        access = ""
        thread = ""
        object_ref = ""
        named_location = ""
        frames: list[str] = []
        source_mapping: list[str] = []
        cursor = index + 1
        while cursor < len(lines):
            line = lines[cursor]
            if "WARNING: ThreadSanitizer:" in line and frames:
                break
            access_match = _TSAN_ACCESS.match(line)
            if access_match is not None and not access:
                access = access_match.group("access").strip().lower().replace(" ", "_")
                object_ref = access_match.group("address")
                thread = access_match.group("thread").strip()
            if not named_location:
                location_match = _TSAN_LOCATION.match(line)
                if location_match is not None:
                    named_location = location_match.group("name")
            frame_match = _TSAN_FRAME.match(line)
            if frame_match is not None:
                function = frame_match.group("function")
                file_name = frame_match.group("file").strip()
                line_number = frame_match.group("line")
                frames.append(f"{function} {file_name}:{line_number}")
                source_mapping.append(f"{file_name}:{line_number}")
            cursor += 1
        if not frames:
            index = max(cursor, index + 1)
            continue
        findings.append(
            SanitizerFinding(
                kind=kind,
                access=access,
                frames=tuple(frames),
                allocation_frames=(),
                # A named global/local is far better candidate evidence than the
                # raw address, so prefer it whenever the report supplies one.
                object_ref=named_location or object_ref,
                site=frames[0].split()[-1] if frames else "",
                source_mapping=tuple(dict.fromkeys(source_mapping)),
                raw_digest=raw_digest,
                thread=thread,
            )
        )
        index = max(cursor, index + 1)
    return tuple(findings)


def parse_sanitizer_report(
    text: str, provider_kind: str, *, raw_digest: str = ""
) -> tuple[SanitizerFinding, ...]:
    if provider_kind == "asan":
        return parse_asan_report(text, raw_digest=raw_digest)
    if provider_kind == "tsan":
        return parse_tsan_report(text, raw_digest=raw_digest)
    return ()


def match_witness_to_candidate(
    binding: CandidateBinding,
    finding: SanitizerFinding,
    *,
    site_tolerance_lines: int = 0,
    object_witness: Any = None,
    require_exact_object: bool = False,
) -> tuple[bool, dict[str, bool], tuple[str, ...]]:
    """Return whether a classified report actually describes this candidate."""

    reasons: list[str] = []
    family_ok = families_match(finding.kind, binding.defect_family)
    if not family_ok:
        reasons.append("defect_family_mismatch")

    reported_file, reported_line = _normalize_site(finding.site)
    site_ok = bool(reported_file) and _path_suffix_match(reported_file, binding.site_file)
    if site_ok and binding.site_line > 0 and reported_line > 0:
        site_ok = abs(reported_line - binding.site_line) <= max(0, site_tolerance_lines)
    if not site_ok:
        reasons.append("candidate_site_mismatch")

    # ThreadSanitizer names the raced global in ``object_ref``; ASAN puts the
    # faulting address there. A site hit is *not* object evidence: the same line
    # can touch several objects, and the same object can be reached from several
    # sites. When the candidate names an object, the witness must name the same
    # object (or reference it by identifier); an anonymous faulting address is
    # only accepted when the candidate object appears in the reported frames.
    reported_object = finding.object_ref.strip()
    named_object = bool(reported_object) and not reported_object.startswith("0x")
    frames_text = " ".join(finding.frames + finding.allocation_frames)
    object_ok = False
    object_reason = "candidate_object_unmatched"
    if not binding.object_identity.strip():
        object_reason = "candidate_object_undeclared"
    elif named_object:
        # Object identity is an exact identity: a *named* witness object is the
        # candidate object only when the names are the same. Both substring
        # directions are rejected on purpose - ``buffer`` is not
        # ``other_buffer`` and ``shared_counter_backup`` is not
        # ``shared_counter`` - because a name that merely contains another name
        # says nothing about which allocation is being reported.
        candidate_token = _object_token(binding.object_identity)
        reported_token = _object_token(reported_object)
        object_ok = bool(candidate_token) and reported_token == candidate_token
        if not object_ok:
            object_reason = "candidate_object_name_mismatch"
    else:
        # Capability boundary: an anonymous faulting address carries no object
        # identity, so the candidate identifier is looked for in the reported
        # frames. That is weaker evidence than a named object - a function name
        # appearing in a stack is not an allocation identity - and it is recorded
        # as such in the qualification facts and in the proof assumptions.
        pattern = (
            r"(?<![0-9A-Za-z_])" + re.escape(binding.object_identity.strip()) + r"(?![0-9A-Za-z_])"
        )
        object_ok = not require_exact_object and bool(re.search(pattern, frames_text))
        if object_witness is not None:
            expected_file, expected_line = _normalize_site(object_witness.access_site)
            allocation_file, allocation_line = _normalize_site(
                object_witness.object_ref.allocation_site
            )
            allocation_matches = any(
                _path_suffix_match(_normalize_site(frame.split()[-1])[0], allocation_file)
                and _normalize_site(frame.split()[-1])[1] == allocation_line
                and frame.split()[0] == object_witness.function
                for frame in finding.allocation_frames
                if frame.split()
            )
            object_ok = bool(
                object_witness.expression == binding.object_identity
                and object_witness.object_ref.build_context_id == binding.build_configuration
                and _path_suffix_match(reported_file, expected_file)
                and reported_line == expected_line
                and finding.access == object_witness.access_kind
                and finding.frames
                and finding.frames[0].split()[0] == object_witness.function
                and allocation_matches
            )
        if not object_ok:
            # A report whose frames name no object at all stays unknown rather
            # than borrowing the site's identity.
            object_reason = "candidate_object_absent_from_frames"
    if not object_ok:
        reasons.append(object_reason)

    facts = {
        "candidate_object_matched": bool(object_ok),
        "candidate_site_matched": bool(site_ok),
        "defect_family_matched": bool(family_ok),
    }
    return (all(facts.values()), facts, tuple(dict.fromkeys(reasons)))


def build_execution_plan(
    binding: CandidateBinding,
    *,
    provider_kind: str,
    provider_name: str,
    provider_version: str,
    run_argv: Sequence[str],
    run_cwd: str,
    harness_ref: str,
    harness_digest: str,
    binary_path: str,
    binary_digest: str,
    toolchain_id: str,
    build_configuration: str,
    input_refs: Sequence[str] = (),
    input_digests: Sequence[str] = (),
    env_allowlist: Mapping[str, str] | None = None,
    timeout_seconds: int = 30,
    memory_limit_mb: int = 512,
    isolation: str = "process",
    max_replays: int = 2,
    build: BuildSpec | None = None,
    allowed_exec_roots: Sequence[str] = (),
    site_tolerance_lines: int = 0,
    object_witness: Any = None,
    require_exact_object: bool = False,
) -> ExecutionPlan:
    """Bind every identity a record needs before anything is executed."""

    payload = _digest(
        {
            "binding": binding.to_dict(),
            "run_argv": list(run_argv),
            "run_cwd": run_cwd,
            "harness": [harness_ref, harness_digest],
            "binary": [binary_path, binary_digest],
            "toolchain": toolchain_id,
            "provider": [provider_kind, provider_name, provider_version],
            "build_configuration": build_configuration,
        }
    )
    return ExecutionPlan(
        plan_id=f"dynrepro-{provider_kind}-{payload[:16]}",
        binding=binding,
        provider_kind=provider_kind,
        provider_name=provider_name,
        provider_version=provider_version,
        harness_ref=harness_ref,
        harness_digest=harness_digest,
        input_refs=tuple(str(item) for item in input_refs),
        input_digests=tuple(str(item) for item in input_digests),
        run_argv=tuple(str(item) for item in run_argv),
        run_cwd=str(run_cwd),
        env_allowlist=tuple(sorted((str(k), str(v)) for k, v in (env_allowlist or {}).items())),
        timeout_seconds=int(timeout_seconds),
        memory_limit_mb=int(memory_limit_mb),
        isolation=str(isolation),
        max_replays=int(max_replays),
        binary_path=str(binary_path),
        binary_digest=str(binary_digest),
        toolchain_id=str(toolchain_id),
        build_configuration=str(build_configuration),
        build=build,
        allowed_exec_roots=tuple(str(item) for item in allowed_exec_roots),
        site_tolerance_lines=int(site_tolerance_lines),
        object_witness=object_witness,
        require_exact_object=require_exact_object,
    )


def make_dynamic_reproduction_policy(config: Any) -> DynamicReproductionPolicy:
    """Resolve the RuntimeSpec mode into an explicit execution policy.

    ``off`` (the shipped default) keeps the feature inert, ``shadow`` executes
    and records provider metadata without granting confirmation authority, and
    ``on`` allows a fully qualified witness to reach the shared adjudication.
    Unknown or missing values fail closed to ``off`` rather than guessing.
    """

    analysis = getattr(config, "analysis", config)
    mode = str(getattr(analysis, "dynamic_reproduction_mode", "off") or "off").strip().lower()
    if mode not in {"off", "shadow", "on"}:
        mode = "off"
    return DynamicReproductionPolicy(
        enabled=mode in {"shadow", "on"},
        attach_proof=mode == "on",
        required_replays=int(getattr(analysis, "dynamic_reproduction_required_replays", 2) or 2),
        max_replays=int(getattr(analysis, "dynamic_reproduction_max_replays", 3) or 3),
        timeout_seconds=int(getattr(analysis, "dynamic_reproduction_timeout_seconds", 30) or 30),
        deadline_seconds=int(
            getattr(analysis, "dynamic_reproduction_deadline_seconds", 900) or 900
        ),
        memory_limit_mb=int(getattr(analysis, "dynamic_reproduction_memory_limit_mb", 512) or 512),
        isolation=str(getattr(analysis, "dynamic_reproduction_isolation", "process") or "process"),
    )


def make_request(binding: CandidateBinding, plan: ExecutionPlan) -> DynamicReproductionRequest:
    """Adapt a plan onto the reserved ``DynamicReproductionRequest`` shape."""

    return DynamicReproductionRequest(
        request_id=plan.plan_id,
        candidate_uid=binding.candidate_uid,
        validation_cluster_uid=binding.validation_cluster_uid,
        reproduction_kind=REPRODUCTION_KINDS[plan.provider_kind],
        target=f"{binding.site}#{binding.object_identity or binding.candidate_uid}",
        evidence_refs=(f"plan:{plan.digest()}", f"binding:{plan.binding_digest}"),
        timeout_seconds=plan.timeout_seconds,
        memory_limit_mb=plan.memory_limit_mb,
    )


def _excerpt(raw: bytes, limit: int) -> str:
    return raw.decode("utf-8", errors="replace")[:limit]


def _within(path: str, root: str) -> bool:
    candidate = os.path.realpath(str(path))
    resolved = os.path.realpath(str(root))
    if not candidate or not resolved:
        return False
    if candidate == resolved:
        return True
    return candidate.startswith(resolved.rstrip(os.sep) + os.sep)


def _allowed_root(path: str, roots: Sequence[str]) -> bool:
    """Whether ``path`` is inside an explicitly authorized root.

    An empty authorization set means "nothing is authorized" rather than "any
    path is allowed": an undeclared plan must not be able to execute anything.
    """

    if not roots:
        return False
    return any(_within(path, root) for root in roots)


def _same_program(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return os.path.realpath(left) == os.path.realpath(right)


def _process_children(pid: int) -> tuple[int, ...]:
    """Direct children of ``pid`` as reported by ``/proc`` (best effort)."""

    try:
        raw = Path(f"/proc/{pid}/task/{pid}/children").read_text(encoding="utf-8")
    except OSError:
        return ()
    children: list[int] = []
    for token in raw.split():
        try:
            children.append(int(token))
        except ValueError:
            continue
    return tuple(children)


@dataclass(frozen=True)
class _RunResult:
    exit_code: int | None
    stdout_digest: str
    stdout_excerpt: bytes
    stderr_digest: str
    stderr_excerpt: bytes
    timed_out: bool
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    rss_exceeded: bool = False
    output_capped: bool = False

    @property
    def truncated(self) -> bool:
        return bool(self.stdout_truncated or self.stderr_truncated)


class _ExecutionBudget:
    """Real process-start budget and wall-clock deadline for one verification.

    ``plan.max_replays`` authorizes a *total* number of executions of the plan:
    the primary execution plus every independent replay. The budget counts the
    processes that are actually started (builds and runs separately) and refuses
    to start more, so nesting a replay inside an execution cannot multiply the
    authorization. The deadline is shared by the whole verification instead of
    being reset per process, so per-run timeouts cannot extend it.
    """

    def __init__(self, *, run_limit: int, deadline: float) -> None:
        self.run_limit = max(0, int(run_limit))
        self.deadline = float(deadline)
        self.runs_started = 0
        self.builds_started = 0
        self.lock = RLock()
        self._build_receipts: dict[str, str] = {}

    @property
    def runs_remaining(self) -> int:
        with self.lock:
            return max(0, self.run_limit - self.runs_started)

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def build_receipt(self, plan_digest: str) -> str:
        """The verified post-build binary digest recorded for this plan, or "".

        The receipt only exists after a build this verification really ran and
        fully re-verified; it is process-local and never persisted.
        """

        with self.lock:
            return self._build_receipts.get(plan_digest, "")

    def record_build_receipt(self, plan_digest: str, binary_digest: str) -> None:
        """Bind this plan to the binary this verification built and checked.

        Recording the same digest twice is idempotent; a conflicting digest is
        refused outright, because one plan producing two different binaries
        inside one verification means the inputs were not stable. There is no
        rebind path.
        """

        with self.lock:
            existing = self._build_receipts.get(plan_digest)
            if existing is not None:
                if existing != binary_digest:
                    raise _PlanViolation("build_receipt_conflict")
                return
            self._build_receipts[plan_digest] = binary_digest

    def claim(self, tag: str) -> None:
        """Reserve one process start, or refuse before anything is launched."""

        with self.lock:
            if self.expired():
                raise _PlanViolation("execution_deadline_exceeded")
            if tag == "build":
                if self.builds_started >= 1:
                    raise _PlanViolation("execution_budget_exhausted:build")
                self.builds_started += 1
                return
            if self.runs_started >= self.run_limit:
                raise _PlanViolation("execution_budget_exhausted")
            self.runs_started += 1


class SanitizerReproductionRunner:
    """Controlled local execution under AddressSanitizer or ThreadSanitizer.

    The runner owns exactly one process group per run and kills only that group
    on timeout or cancellation. It never claims container isolation: the record
    states whether a network-namespace wrap was actually applied.
    """

    def __init__(
        self,
        provider_kind: str,
        *,
        policy: DynamicReproductionPolicy | None = None,
        compiler: str = "",
        version: str = "1",
    ) -> None:
        if provider_kind not in COMPILER_FLAGS:
            raise DynamicReproductionError("unsupported_sanitizer_kind")
        self.kind = provider_kind
        self.name = f"{provider_kind}-runner"
        self.version = str(version)
        self.policy = policy or DynamicReproductionPolicy()
        self.compiler = compiler or ("clang" if shutil.which("clang") else "cc")
        self._budget: _ExecutionBudget | None = None

    def use_budget(self, budget: _ExecutionBudget | None) -> None:
        """Bind (or clear) the shared execution budget for this verification."""

        self._budget = budget

    @property
    def sanitizer_flag(self) -> str:
        return COMPILER_FLAGS[self.kind]

    def availability(self) -> ProviderAvailability:
        """Actually compile and run a probe; file existence is not evidence.

        A disabled policy never compiles or runs anything: default-off has to
        hold at the execution boundary, not only in a caller-side check.
        """

        details: dict[str, str] = {}
        if not self.policy.enabled:
            return ProviderAvailability(False, "dynamic_reproduction_disabled", details)
        compiler = shutil.which(self.compiler) or ""
        details["compiler"] = compiler or self.compiler
        if not compiler:
            return ProviderAvailability(False, "compiler_unavailable", details)
        workdir = tempfile.mkdtemp(prefix=f"zscope-{self.kind}-probe-")
        try:
            source = Path(workdir) / "probe.c"
            source.write_text("int main(void){return 0;}\n", encoding="utf-8")
            binary = Path(workdir) / "probe"
            argv = [compiler, self.sanitizer_flag, "-g", "-O0", "-o", str(binary), str(source)]
            if self.kind == "tsan":
                argv.append("-pthread")
            try:
                built = subprocess.run(
                    argv, cwd=workdir, capture_output=True, timeout=180, check=False
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return ProviderAvailability(
                    False, f"compiler_probe_failed:{type(exc).__name__}", details
                )
            if built.returncode != 0:
                details["compile_stderr"] = built.stderr.decode("utf-8", "replace")[-400:]
                return ProviderAvailability(False, "sanitizer_runtime_unavailable", details)
            try:
                ran = subprocess.run(
                    [str(binary)], cwd=workdir, capture_output=True, timeout=180, check=False
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return ProviderAvailability(
                    False, f"probe_run_failed:{type(exc).__name__}", details
                )
            details["probe_exit_code"] = str(ran.returncode)
            if ran.returncode != 0:
                return ProviderAvailability(False, "sanitizer_probe_failed", details)
            return ProviderAvailability(True, "", details)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # -- execution --------------------------------------------------------
    def authorization_problems(
        self,
        plan: ExecutionPlan,
        workdir: str = "",
        *,
        require_binary: bool = True,
        binary_from_this_build: bool = False,
    ) -> list[str]:
        """Everything that must be true before this plan may execute anything.

        The declared identities are re-derived from the filesystem here: the
        harness, every declared input and the executed program are hashed and
        compared with the plan, and every path must sit inside an explicitly
        authorized root. This is re-run before *every* run, not only on entry, so
        a file that changes while a verification is in progress stops the next
        launch instead of being executed under an earlier declaration.

        ``require_binary`` is false only for a plan whose own build produces the
        executable: that artifact cannot exist yet, so its identity is verified
        immediately after the build and before the run starts. In that case
        ``binary_from_this_build`` allows the *plan's* digest to be empty, but the
        artifact must still exist and it is hashed again for the record.
        """

        problems: list[str] = []
        roots = tuple(plan.allowed_exec_roots)
        if not roots:
            problems.append("exec_roots_not_declared")
        build_cwd = plan.build.cwd if plan.build is not None else ""
        candidates: list[tuple[str, str]] = [
            ("run_cwd", plan.run_cwd),
            ("binary", plan.binary_path),
            ("build_cwd", build_cwd),
        ]
        if plan.harness_ref:
            candidates.append(("harness", plan.harness_ref))
        for index, ref in enumerate(plan.input_refs):
            candidates.append((f"input[{index}]", ref))
        for label, path in candidates:
            if path and not _allowed_root(path, roots):
                problems.append(f"{label}_outside_exec_roots")
        if workdir and not _within(workdir, tempfile.gettempdir()):
            problems.append("workdir_outside_temp_root")

        if not plan.harness_ref:
            problems.append("harness_not_declared")
        elif not os.path.isfile(plan.harness_ref):
            problems.append("harness_missing")
        elif not plan.harness_digest:
            problems.append("harness_digest_not_declared")
        elif hash_file(plan.harness_ref)[0] != plan.harness_digest:
            problems.append("harness_digest_mismatch")

        for index, (ref, declared) in enumerate(zip(plan.input_refs, plan.input_digests)):
            if not os.path.isfile(ref):
                problems.append(f"input_missing[{index}]")
            elif not declared:
                problems.append(f"input_digest_not_declared[{index}]")
            elif hash_file(ref)[0] != declared:
                problems.append(f"input_digest_mismatch[{index}]")

        if not plan.binary_path or not _same_program(plan.run_argv[0], plan.binary_path):
            # The command must name the binary the plan binds, whether or not
            # that binary has been produced yet.
            problems.append("run_argv_not_verified_binary")
        if require_binary:
            if not plan.binary_path or not os.path.isfile(plan.binary_path):
                problems.append("binary_missing")
            else:
                actual, _ = hash_file(plan.binary_path)
                if not plan.binary_digest:
                    if not binary_from_this_build:
                        problems.append("binary_digest_not_declared")
                elif actual != plan.binary_digest:
                    problems.append("binary_identity_mismatch")
        return problems

    def execute(self, plan: ExecutionPlan) -> ExecutionRecord:
        if not self.policy.enabled:
            raise DynamicReproductionError("dynamic_reproduction_disabled")
        if plan.provider_kind != self.kind:
            raise DynamicReproductionError("provider_plan_kind_mismatch")
        workdir = tempfile.mkdtemp(prefix=f"zscope-{self.kind}-run-")
        started = time.monotonic()
        # One ``execute`` call performs exactly one run of the plan, preceded by
        # its build unless the shared budget already carries the verified
        # post-build receipt for this exact plan (then the build is not
        # repeated; the binary is re-hashed against the receipt instead).
        # ``plan.max_replays`` is the *total* number of runs
        # authorized for the whole verification, so a caller that wants the
        # primary execution plus the required independent replays must authorize
        # that many; the scheduler that allocates them is
        # ``run_dynamic_reproduction``. A standalone call still cannot start more
        # processes than the plan allows.
        budget = self._budget or _ExecutionBudget(
            run_limit=1,
            deadline=started + max(1, int(self.policy.deadline_seconds)),
        )

        def finish(*_args: Any, **kwargs: Any) -> ExecutionRecord:
            # ``plan`` and ``started`` are already bound here; the positional
            # arguments some call sites still pass are intentionally ignored.
            return self._record(
                plan,
                started,
                workdir=workdir,
                source_digests=accepted_source_digests,
                **kwargs,
            )

        notes: list[str] = []
        limitations: list[str] = []
        build_result: _RunResult | None = None
        build_argv: tuple[str, ...] = ()
        env: dict[str, str] = {}
        # The verified post-build binary identity this verification already
        # produced for this exact plan, if the shared budget carries one.
        build_receipt = ""
        # Freeze the accepted source/harness/input snapshot as soon as the plan
        # identity is accepted, before any build or run: a later re-hash must
        # never become the execution-time baseline.
        accepted_source_digests: tuple[tuple[str, str], ...] = ()
        try:
            problems = self.authorization_problems(plan, workdir, require_binary=plan.build is None)
            if problems:
                return finish(
                    plan,
                    started,
                    outcome="unsupported",
                    detail="plan_identity_unverified",
                    notes=["no_process_was_started"],
                    limitations=list(problems) + ["unverified_plan_never_launched"],
                )
            accepted_source_digests = frozen_source_digests(plan.binding, plan)
            # Isolation is decided once and applied to the build and the run: a
            # requested boundary that cannot be provided stops the plan instead
            # of silently executing without it.
            prefix: tuple[str, ...] = ()
            isolation = "process"
            isolation_verified = True
            if plan.isolation == "user_net_namespace":
                wrapped, allowed, wrap_notes = self._namespace_wrap(plan.run_argv)
                notes.extend(wrap_notes)
                if allowed:
                    prefix = wrapped[: len(wrapped) - len(plan.run_argv)]
                    isolation = "user_net_namespace"
                else:
                    isolation_verified = False
            notes.extend(
                [
                    f"isolation={isolation}",
                    "process_group_isolated",
                    "subprocess_is_not_a_container_sandbox",
                ]
            )
            if not isolation_verified:
                return finish(
                    plan,
                    started,
                    outcome="unsupported",
                    detail="requested_isolation_unavailable",
                    notes=notes,
                    limitations=["requested_isolation_not_applied"],
                )
            if plan.build is not None:
                build_argv = tuple(plan.build.argv)
                # A shared budget carries the verified post-build identity of
                # the binary this verification already produced for this exact
                # plan, so an independent replay re-executes that binary
                # instead of compiling again. The receipt is process-local,
                # never persisted, and re-checked against a fresh hash below;
                # a binary that no longer matches stops the run instead of
                # being rebound.
                build_receipt = budget.build_receipt(plan.digest())
            if plan.build is not None and not build_receipt:
                build_env = dict(plan.build.environment) or self._base_env(plan, workdir)
                build_result = self._run_once(
                    argv=(*prefix, *plan.build.argv),
                    cwd=plan.build.cwd,
                    env=build_env,
                    timeout_seconds=plan.build.timeout_seconds,
                    address_space_limit_mb=0,
                    tag="build",
                    workdir=workdir,
                    rss_limit_mb=max(0, int(plan.memory_limit_mb)),
                )
                if build_result.timed_out:
                    return finish(
                        plan,
                        started,
                        outcome="engine_failed",
                        detail="build_timeout",
                        build_argv=build_argv,
                        build_result=build_result,
                        notes=notes,
                        limitations=limitations + ["build_timeout"],
                    )
                if build_result.rss_exceeded or build_result.output_capped:
                    return finish(
                        plan,
                        started,
                        outcome="engine_failed",
                        detail="build_resource_exhaustion",
                        build_argv=build_argv,
                        build_result=build_result,
                        notes=notes,
                        limitations=limitations
                        + [
                            (
                                "build_memory_limit_enforced_by_rss_watchdog"
                                if build_result.rss_exceeded
                                else "build_output_capture_limit_reached"
                            ),
                            "resource_exhaustion_is_not_a_candidate_decision",
                        ],
                    )
                if build_result.exit_code != 0:
                    build_text = build_result.stderr_excerpt.decode("utf-8", "replace")
                    return finish(
                        plan,
                        started,
                        outcome="engine_failed",
                        detail=(
                            "build_failed"
                            if _BUILD_FAILURE.search(build_text)
                            else "build_nonzero_exit"
                        ),
                        build_argv=build_argv,
                        build_result=build_result,
                        notes=notes,
                        limitations=limitations,
                    )
            actual_binary_digest = ""
            if os.path.isfile(plan.binary_path):
                actual_binary_digest, _ = hash_file(plan.binary_path)
            if not actual_binary_digest:
                return finish(
                    plan,
                    started,
                    outcome="engine_failed",
                    detail="binary_missing",
                    build_argv=build_argv,
                    build_result=build_result,
                    notes=notes,
                    limitations=limitations,
                )
            if plan.binary_digest and actual_binary_digest != plan.binary_digest:
                return finish(
                    plan,
                    started,
                    outcome="unsupported",
                    detail="plan_identity_unverified",
                    build_argv=build_argv,
                    build_result=build_result,
                    notes=notes,
                    limitations=limitations
                    + ["binary_identity_mismatch", "unverified_plan_never_launched"],
                    binary_digest=actual_binary_digest,
                )
            if build_receipt:
                if actual_binary_digest != build_receipt:
                    # The binary this verification built no longer matches the
                    # receipt recorded when it was verified. Rebinding to the
                    # new content is never an option; the whole verification
                    # stops instead of executing a changed program.
                    return finish(
                        plan,
                        started,
                        outcome="unsupported",
                        detail="plan_identity_changed_during_execution",
                        build_argv=build_argv,
                        build_result=build_result,
                        notes=notes + ["no_run_was_started"],
                        limitations=limitations
                        + ["binary_identity_mismatch", "unverified_plan_never_launched"],
                        binary_digest=actual_binary_digest,
                    )
                limitations.append("binary_reused_from_shared_build_receipt")
            # The whole declared identity is re-derived *after* the build and
            # immediately before the run: a build that rewrites the harness, an
            # input or the executable stops here instead of running under
            # identities that were verified before the build.
            binary_from_build = plan.build is not None and not plan.binary_digest
            if plan.build is not None:
                post_problems = [
                    item
                    for item in self.authorization_problems(
                        plan, workdir, binary_from_this_build=True
                    )
                    if item not in {"run_argv_not_verified_binary"}
                ]
                if post_problems:
                    return finish(
                        plan,
                        started,
                        outcome="unsupported",
                        detail="plan_identity_changed_during_execution",
                        build_argv=build_argv,
                        build_result=build_result,
                        notes=notes + ["no_run_was_started"],
                        limitations=limitations
                        + list(post_problems)
                        + ["identity_changed_after_build", "unverified_plan_never_launched"],
                        binary_digest=actual_binary_digest,
                    )
            if binary_from_build:
                # The plan declared that its own build produces the executable;
                # the identity is bound by the post-build digest instead.
                limitations.append("binary_identity_bound_after_build")
            if plan.build is not None and not build_receipt:
                # Publish the receipt only after this execution's build and the
                # complete post-build identity verification succeeded, so a
                # failed or unverified build leaves nothing to reuse.
                budget.record_build_receipt(plan.digest(), actual_binary_digest)
            env, env_notes, env_limits = self._run_env(plan, workdir)
            notes.extend(env_notes)
            limitations.extend(env_limits)
            run_argv = tuple(plan.run_argv)
            exec_argv = (*prefix, *run_argv)
            verifier = self._verification_digest(plan, actual_binary_digest)
            classifications: list[str] = []
            findings: tuple[SanitizerFinding, ...] = ()
            runs: list[RunEvidence] = []
            last = _RunResult(None, "", b"", "", b"", False)
            for index in range(1):
                # Re-verify the current files once more, right before this run.
                run_problems = self.authorization_problems(
                    plan,
                    workdir,
                    binary_from_this_build=binary_from_build,
                )
                if run_problems:
                    return finish(
                        plan,
                        started,
                        outcome="unsupported",
                        detail="plan_identity_changed_during_execution",
                        build_argv=build_argv,
                        build_result=build_result,
                        run_argv=run_argv,
                        notes=notes + ["no_run_was_started"],
                        limitations=limitations
                        + list(run_problems)
                        + ["identity_changed_before_run", "unverified_plan_never_launched"],
                        binary_digest=actual_binary_digest,
                    )
                last = self._run_once(
                    argv=exec_argv,
                    cwd=plan.run_cwd,
                    env=env,
                    timeout_seconds=plan.timeout_seconds,
                    address_space_limit_mb=0,
                    tag=f"run-{index}",
                    workdir=workdir,
                    rss_limit_mb=max(0, int(plan.memory_limit_mb)),
                )
                text = (last.stderr_excerpt + last.stdout_excerpt).decode("utf-8", "replace")
                truncated = bool(
                    last.stdout_truncated or last.stderr_truncated or last.output_capped
                )
                parsed: tuple[SanitizerFinding, ...] = ()
                if last.timed_out:
                    classification = "engine_failed:timeout"
                elif last.rss_exceeded:
                    classification = "engine_failed:resource_exhaustion"
                elif _RESOURCE_EXHAUSTION.search(text):
                    classification = "engine_failed:resource_exhaustion"
                else:
                    parsed = parse_sanitizer_report(text, self.kind, raw_digest=last.stderr_digest)
                    if parsed:
                        classification = parsed[0].kind
                        if not findings:
                            findings = parsed
                    elif truncated:
                        # Missing text is not evidence of absence: a truncated
                        # stream cannot be reported as a clean non-reproduction.
                        classification = "output_truncated"
                    elif last.exit_code not in (0, None):
                        classification = f"engine_failed:exit_{last.exit_code}"
                    else:
                        classification = "none"
                classifications.append(classification)
                if last.rss_exceeded:
                    limitations.append("memory_limit_enforced_by_rss_watchdog")
                runs.append(
                    RunEvidence(
                        index=index,
                        outcome=(
                            "engine_failed"
                            if classification.startswith("engine_failed:")
                            else "observed"
                        ),
                        detail=classification,
                        exit_code=last.exit_code,
                        signal_number=(
                            -last.exit_code
                            if last.exit_code is not None and last.exit_code < 0
                            else None
                        ),
                        timed_out=bool(last.timed_out),
                        oom_killed=classification == "engine_failed:resource_exhaustion",
                        classifications=(classification,),
                        findings=tuple(parsed),
                        stdout_digest=last.stdout_digest,
                        stderr_digest=last.stderr_digest,
                        stdout_bytes=last.stdout_bytes,
                        stderr_bytes=last.stderr_bytes,
                        output_truncated=truncated,
                    )
                )
                if truncated:
                    limitations.append("output_truncated_before_classification")
                if classification.startswith("engine_failed:"):
                    break
            if any(item == "output_truncated" for item in classifications):
                limitations.append("truncated_output_never_counts_as_non_reproduction")
            outcome, detail = _classify_run(classifications, findings, timed_out=last.timed_out)
            return finish(
                plan,
                started,
                outcome=outcome,
                detail=detail,
                build_argv=build_argv,
                build_result=build_result,
                run_argv=run_argv,
                env=env,
                run_result=last,
                findings=findings,
                classifications=tuple(classifications),
                runs=tuple(runs),
                isolation=isolation,
                isolation_verified=isolation_verified,
                inputs_verified=True,
                input_verification_digest=verifier,
                notes=notes,
                limitations=limitations,
                binary_digest=actual_binary_digest,
                binary_identity_source=(
                    "post_build_output" if binary_from_build else "plan_declared"
                ),
            )
        except _ToolUnavailable as exc:
            return finish(
                plan,
                started,
                outcome="unsupported",
                detail=f"tool_unavailable:{exc}",
                build_argv=build_argv,
                build_result=build_result,
                notes=notes,
                limitations=limitations,
            )
        except _PlanViolation as exc:
            return finish(
                plan,
                started,
                outcome="engine_failed",
                detail=str(exc),
                build_argv=build_argv,
                build_result=build_result,
                notes=notes,
                limitations=limitations + [str(exc)],
            )
        except CancellationError as exc:
            return finish(
                plan,
                started,
                outcome="cancelled",
                detail=f"cancelled:{exc}",
                build_argv=build_argv,
                build_result=build_result,
                notes=notes,
                limitations=limitations,
            )
        finally:
            if not self.policy.keep_workdir:
                shutil.rmtree(workdir, ignore_errors=True)

    def _verification_digest(self, plan: ExecutionPlan, binary_digest: str = "") -> str:
        """Digest of the identities actually verified before the launch."""

        entries = [
            ["harness", plan.harness_ref, plan.harness_digest],
            ["binary", plan.binary_path, binary_digest or plan.binary_digest],
            ["inputs", list(plan.input_refs), list(plan.input_digests)],
        ]
        return _digest(entries)

    # -- internals --------------------------------------------------------
    def _base_env(self, plan: ExecutionPlan, workdir: str) -> dict[str, str]:
        env = {key: value for key, value in plan.env_allowlist}
        env.setdefault("PATH", "/usr/bin:/bin")
        env.setdefault("HOME", workdir)
        env.setdefault("TMPDIR", workdir)
        env.setdefault("LANG", "C.UTF-8")
        return env

    def _run_env(
        self, plan: ExecutionPlan, workdir: str
    ) -> tuple[dict[str, str], list[str], list[str]]:
        env = self._base_env(plan, workdir)
        notes: list[str] = []
        limitations: list[str] = []
        if self.kind == "asan":
            options = [
                "abort_on_error=0",
                "halt_on_error=1",
                "detect_leaks=0",
                "symbolize=1",
                "print_summary=1",
                "exitcode=1",
            ]
            if plan.memory_limit_mb > 0:
                options.append(f"max_allocation_size_mb={plan.memory_limit_mb}")
            env["ASAN_OPTIONS"] = ":".join(options)
            limitations.append("rlimit_as_not_applied_to_sanitizer_runtime")
            if plan.memory_limit_mb > 0:
                limitations.append("memory_limit_enforced_by_sanitizer_allocation_cap")
                # The cap applies to one requested allocation, not to the total
                # resident set of the process; the resident set is additionally
                # bounded by the sampled RSS watchdog.
                limitations.append("memory_limit_is_per_allocation_not_total_rss")
                limitations.append("memory_limit_total_rss_watchdog_applied")
        else:
            env["TSAN_OPTIONS"] = "halt_on_error=1:exitcode=1:history_size=2"
            if plan.memory_limit_mb > 0:
                limitations.append("memory_limit_enforced_by_rss_watchdog")
                limitations.append("rss_watchdog_is_sampled_not_a_kernel_limit")
            else:
                limitations.append("memory_limit_not_enforced_for_tsan")
        return env, notes, limitations

    def _namespace_wrap(self, argv: Sequence[str]) -> tuple[tuple[str, ...], bool, list[str]]:
        unshare = shutil.which("unshare")
        if not unshare or not self.policy.allow_net_namespace:
            return tuple(argv), False, ["net_namespace_unavailable"]
        try:
            probe = subprocess.run(
                [unshare, "--user", "--map-root-user", "--net", "--", "true"],
                capture_output=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return tuple(argv), False, ["net_namespace_probe_failed"]
        if probe.returncode != 0:
            return tuple(argv), False, ["net_namespace_probe_failed"]
        return (
            (unshare, "--user", "--map-root-user", "--net", "--", *argv),
            True,
            ["net_namespace_applied"],
        )

    def _run_once(
        self,
        *,
        argv: Sequence[str],
        cwd: str,
        env: Mapping[str, str],
        timeout_seconds: int,
        address_space_limit_mb: int,
        tag: str,
        workdir: str,
        rss_limit_mb: int = 0,
    ) -> _RunResult:
        if not argv:
            raise DynamicReproductionError("empty_exec_argv")
        # Cancellation is checked *before* anything is spawned: an already
        # cancelled task must not create a process, and a short-lived process must
        # not be able to exit before the loop ever sees the cancellation.
        token = current_cancellation_token()
        if token is not None and token.is_cancelled():
            raise CancellationError(token.reason or "cancelled")
        budget = self._budget
        if budget is not None:
            # Raises _PlanViolation before a process exists when the plan's
            # authorized execution count or the shared deadline is exhausted.
            budget.claim(tag)
        out_path = Path(workdir) / f"{tag}.stdout"
        err_path = Path(workdir) / f"{tag}.stderr"
        preexec: Callable[[], None] | None = None
        if address_space_limit_mb > 0:
            limit_bytes = int(address_space_limit_mb) * 1024 * 1024

            def _apply_limits() -> None:
                if _resource is None:  # pragma: no cover - platform dependent
                    return
                _resource.setrlimit(_resource.RLIMIT_AS, (limit_bytes, limit_bytes))

            preexec = _apply_limits
        deadline = time.monotonic() + max(1, int(timeout_seconds))
        if budget is not None:
            deadline = min(deadline, budget.deadline)
        timed_out = False
        rss_exceeded = False
        output_capped = False
        cap = max(1, int(self.policy.output_capture_limit_bytes))
        with out_path.open("wb") as out_stream, err_path.open("wb") as err_stream:
            try:
                process = subprocess.Popen(
                    list(argv),
                    cwd=cwd,
                    env=dict(env),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    preexec_fn=preexec,
                    close_fds=True,
                )
            except FileNotFoundError:
                raise _ToolUnavailable(str(argv[0])) from None
            except PermissionError:
                raise _ToolUnavailable(str(argv[0])) from None
            except OSError as exc:
                raise _PlanViolation(f"exec_failed:{type(exc).__name__}") from None
            # ``start_new_session`` makes the child a process-group leader, so
            # its group id is its pid and stays known after the leader is reaped.
            group_id = process.pid
            import select as _select

            streams: dict[int, tuple[str, Any, Any]] = {}
            if process.stdout is not None:
                streams[process.stdout.fileno()] = (
                    "stdout",
                    process.stdout,
                    out_stream,
                )
            if process.stderr is not None:
                streams[process.stderr.fileno()] = (
                    "stderr",
                    process.stderr,
                    err_stream,
                )
            written = {"stdout": 0, "stderr": 0}
            eof = {"stdout": False, "stderr": False}
            capped = {"stdout": False, "stderr": False}
            chunk_size = 65536

            def _pump(ready: Sequence[int]) -> None:
                """Move at most ``cap`` bytes per stream into the spool files."""

                for fd in ready:
                    name, _pipe, sink = streams[fd]
                    if eof[name] or capped[name]:
                        continue
                    remaining = cap - written[name]
                    if remaining <= 0:
                        # Budget full: a readable byte means the stream was
                        # capped; an immediate EOF means it stopped exactly at
                        # the budget and is still complete.
                        try:
                            probe = os.read(fd, 1)
                        except OSError as exc:
                            raise _PlanViolation("output_capture_failed") from exc
                        if probe:
                            capped[name] = True
                        else:
                            eof[name] = True
                        continue
                    try:
                        chunk = os.read(fd, min(remaining, chunk_size))
                    except OSError as exc:
                        raise _PlanViolation("output_capture_failed") from exc
                    if not chunk:
                        eof[name] = True
                        continue
                    sink.write(chunk)
                    written[name] += len(chunk)

            rss_deadline = 0.0
            try:
                while True:
                    if token is not None and token.is_cancelled():
                        self._kill_group(process, group_id)
                        process.wait(timeout=10)
                        raise CancellationError(token.reason or "cancelled")
                    now = time.monotonic()
                    if now >= deadline:
                        timed_out = True
                        self._kill_group(process, group_id)
                        process.wait(timeout=10)
                        break
                    if rss_limit_mb > 0 and now >= rss_deadline:
                        rss_deadline = now + max(0.01, float(self.policy.rss_poll_seconds))
                        if self._rss_exceeds(process.pid, rss_limit_mb):
                            rss_exceeded = True
                            self._kill_group(process, group_id)
                            process.wait(timeout=10)
                            break
                    # Capture is bounded by the shared deadline, cancellation
                    # and RSS above; it continues until every pipe has actually
                    # reached EOF or its byte budget.  A leader exiting is not
                    # EOF: authorized descendants may still own the pipes.
                    pending = [
                        fd
                        for fd in streams
                        if not eof[streams[fd][0]] and not capped[streams[fd][0]]
                    ]
                    if pending:
                        wait = max(0.0, min(0.05, deadline - time.monotonic()))
                        try:
                            ready, _, _ = _select.select(pending, [], [], wait)
                        except (OSError, ValueError):
                            ready = []
                        if ready:
                            _pump(ready)
                        if any(capped.values()):
                            output_capped = True
                            self._kill_group(process, group_id)
                            process.wait(timeout=10)
                            for name in capped:
                                if capped[name]:
                                    eof[name] = True
                    elif process.poll() is not None:
                        break
                    else:
                        time.sleep(0.01)
                exit_code = process.returncode
            finally:
                # EOF does not imply that every owned descendant has exited:
                # one can close both pipes and keep running after its leader.
                self._kill_group(process, group_id)
                if process.poll() is None:
                    process.wait(timeout=10)
                for _name, pipe, _sink in streams.values():
                    try:
                        pipe.close()
                    except OSError:
                        pass
        stdout_digest, stdout_bytes, stdout_excerpt, stdout_truncated = self._read_output(out_path)
        stderr_digest, stderr_bytes, stderr_excerpt, stderr_truncated = self._read_output(err_path)
        stdout_truncated = bool(stdout_truncated or capped["stdout"])
        stderr_truncated = bool(stderr_truncated or capped["stderr"])
        output_capped = bool(output_capped or capped["stdout"] or capped["stderr"])
        return _RunResult(
            exit_code=exit_code,
            stdout_digest=stdout_digest,
            stdout_excerpt=stdout_excerpt,
            stderr_digest=stderr_digest,
            stderr_excerpt=stderr_excerpt,
            timed_out=timed_out,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            rss_exceeded=rss_exceeded,
            output_capped=output_capped,
        )

    @staticmethod
    def _spool_within_cap(out_path: Path, err_path: Path, cap: int) -> bool:
        """Whether both spooled streams are still inside the declared byte cap."""

        try:
            return out_path.stat().st_size <= cap and err_path.stat().st_size <= cap
        except OSError:
            return True

    @staticmethod
    def _rss_exceeds(pid: int, limit_mb: int) -> bool:
        """Sample the resident set of a process and its known children.

        ``RLIMIT_AS`` cannot be applied to sanitizer runtimes, so a total-RSS
        boundary is enforced by watching the process group: the sum of the
        resident sizes is compared with the declared limit and the group is killed
        when it exceeds it. This is a real, recorded boundary - not a claim that a
        per-allocation sanitizer cap is a total memory limit.
        """

        total_kb = 0
        try:
            with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    if line.startswith("VmRSS:"):
                        total_kb += int(line.split()[1])
                    elif line.startswith("VmHWM:"):
                        continue
            for child in _process_children(pid):
                try:
                    with open(
                        f"/proc/{child}/status", "r", encoding="utf-8", errors="replace"
                    ) as stream:
                        for line in stream:
                            if line.startswith("VmRSS:"):
                                total_kb += int(line.split()[1])
                except OSError:
                    continue
        except OSError:
            # No readable /proc (or the process already exited): fail closed on
            # nothing - the timeout still bounds the run - but never claim the
            # limit was enforced.
            return False
        return total_kb > max(1, int(limit_mb)) * 1024

    def _read_output(self, path: Path) -> tuple[str, int, bytes, bool]:
        """Digest the captured bytes, keep a bounded prefix, report truncation.

        The stream is spooled with a hard byte cap while it is produced, so the
        digest covers exactly the bytes that were captured; ``truncated`` is set
        when the cap stopped the stream (or a larger file was found), and a
        truncated stream is never treated as a complete one.
        """

        limit = max(1, int(self.policy.output_capture_limit_bytes))
        digest, _ = hash_file(path)
        size = path.stat().st_size if path.exists() else 0
        with path.open("rb") as stream:
            excerpt = stream.read(limit)
        return digest, size, excerpt, size > limit

    @staticmethod
    def _kill_group(process: subprocess.Popen[bytes], group_id: int | None = None) -> None:
        """Kill only the group this runner created for this run.

        ``start_new_session`` makes the child a process-group leader, so the
        group id is known at spawn time and remains usable after the leader has
        been reaped, when ``os.getpgid`` can no longer resolve it.
        """

        pgid = group_id
        if pgid is None:
            try:
                pgid = os.getpgid(process.pid)
            except OSError:
                pgid = process.pid
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except OSError:
                pass

    def _record(
        self,
        plan: ExecutionPlan,
        started: float,
        workdir: str = "",
        *,
        outcome: str,
        detail: str = "",
        build_argv: Sequence[str] = (),
        build_result: _RunResult | None = None,
        run_argv: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        run_result: _RunResult | None = None,
        findings: Sequence[SanitizerFinding] = (),
        classifications: Sequence[str] = (),
        runs: Sequence[RunEvidence] = (),
        isolation: str = "process",
        isolation_verified: bool = True,
        inputs_verified: bool = False,
        input_verification_digest: str = "",
        source_digests: Sequence[tuple[str, str]] = (),
        notes: Sequence[str] = (),
        limitations: Sequence[str] = (),
        binary_digest: str = "",
        binary_identity_source: str = "",
        trust: str = TRUST_PRODUCTION,
    ) -> ExecutionRecord:
        artifacts, artifact_root, artifact_notes = self._publish_artifacts(plan, workdir)
        if artifacts:
            published = {Path(ref).name: ref for ref in artifacts}
            runs = tuple(
                replace(
                    run,
                    artifacts=tuple(
                        published[name]
                        for name in (f"run-{run.index}.stdout", f"run-{run.index}.stderr")
                        if name in published
                    ),
                )
                for run in runs
            )
        record = ExecutionRecord(
            record_id=f"{plan.plan_id}-{os.urandom(6).hex()}",
            plan_digest=plan.digest(),
            provider_name=self.name,
            provider_version=self.version,
            provider_kind=self.kind,
            outcome=outcome,
            run_argv=tuple(plan.run_argv if not run_argv else run_argv),
            run_cwd=plan.run_cwd,
            environment=tuple(sorted((env or {}).items())),
            isolation=isolation,
            isolation_verified=isolation_verified,
            isolation_notes=tuple(dict.fromkeys(notes)),
            build_argv=tuple(build_argv),
            build_exit_code=build_result.exit_code if build_result is not None else None,
            build_stdout_digest=build_result.stdout_digest if build_result is not None else "",
            build_stderr_digest=build_result.stderr_digest if build_result is not None else "",
            build_stdout_excerpt=(
                _excerpt(build_result.stdout_excerpt, self.policy.output_excerpt_bytes)
                if build_result is not None
                else ""
            ),
            build_stderr_excerpt=(
                _excerpt(build_result.stderr_excerpt, self.policy.output_excerpt_bytes)
                if build_result is not None
                else ""
            ),
            exit_code=run_result.exit_code if run_result is not None else None,
            signal_number=(
                -run_result.exit_code
                if run_result is not None
                and run_result.exit_code is not None
                and run_result.exit_code < 0
                else None
            ),
            timed_out=bool(run_result.timed_out) if run_result is not None else False,
            oom_killed=bool(detail == "resource_exhaustion" or detail == "out_of_memory"),
            binary_digest=binary_digest or plan.binary_digest,
            binary_path=plan.binary_path,
            stdout_digest=run_result.stdout_digest if run_result is not None else "",
            stderr_digest=run_result.stderr_digest if run_result is not None else "",
            stdout_excerpt=(
                _excerpt(run_result.stdout_excerpt, self.policy.output_excerpt_bytes)
                if run_result is not None
                else ""
            ),
            stderr_excerpt=(
                _excerpt(run_result.stderr_excerpt, self.policy.output_excerpt_bytes)
                if run_result is not None
                else ""
            ),
            findings=tuple(findings),
            replay_classifications=tuple(classifications),
            replay_count=len(classifications),
            duration_ms=int((time.monotonic() - started) * 1000),
            memory_limit_mode=(
                "sanitizer_allocation_cap"
                if plan.memory_limit_mb > 0 and self.kind == "asan"
                else (
                    "rss_watchdog"
                    if plan.memory_limit_mb > 0 and self.kind == "tsan"
                    else ("rlimit_as" if plan.memory_limit_mb > 0 else "none")
                )
            ),
            runs=tuple(runs),
            artifact_refs=artifacts,
            artifact_root=artifact_root,
            inputs_verified=bool(inputs_verified),
            input_verification_digest=str(input_verification_digest),
            source_digests=tuple((str(path), str(digest)) for path, digest in source_digests),
            binary_identity_source=str(binary_identity_source),
            limitations=tuple(dict.fromkeys([*limitations, *artifact_notes])),
            detail=detail,
        )
        return self.register_execution(record, plan=plan, trust=trust)

    def _publish_artifacts(
        self, plan: ExecutionPlan, workdir: str = ""
    ) -> tuple[tuple[str, ...], str, list[str]]:
        """Copy this run's logs out of the work directory before it is removed.

        Every execution publishes into its own directory below the plan directory,
        named after the work directory, so a second execution of the same plan can
        never overwrite the first one's evidence. Existing files are never
        replaced; without a configured artifact directory the record says so
        instead of presenting a digest as a location.
        """

        destination = str(self.policy.artifact_dir or "").strip()
        if not destination:
            return (), "", ["execution_logs_not_published"]
        source_root = Path(workdir) if workdir else Path(plan.run_cwd)
        try:
            root = Path(destination) / plan.plan_id / Path(workdir).name
            root.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            root = (
                Path(destination) / plan.plan_id / (Path(workdir).name + "-" + os.urandom(4).hex())
            )
            try:
                root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                return (), "", [f"artifact_publish_failed:{type(exc).__name__}"]
        except OSError as exc:
            return (), "", [f"artifact_publish_failed:{type(exc).__name__}"]
        refs: list[str] = []
        notes: list[str] = []
        for source in sorted(source_root.glob("*.stdout")) + sorted(source_root.glob("*.stderr")):
            target = root / source.name
            if target.exists():
                notes.append(f"artifact_not_overwritten:{source.name}")
                continue
            try:
                shutil.copyfile(source, target)
            except OSError:
                notes.append(f"artifact_publish_failed:{source.name}")
                continue
            try:
                if hash_file(target)[0] != hash_file(source)[0]:
                    notes.append(f"artifact_digest_mismatch:{source.name}")
                    continue
            except OSError:
                notes.append(f"artifact_unreadable:{source.name}")
                continue
            refs.append(str(target))
        return tuple(refs), str(root), notes

    def register_execution(
        self,
        record: ExecutionRecord,
        *,
        plan: ExecutionPlan | None = None,
        trust: str = TRUST_PRODUCTION,
    ) -> ExecutionRecord:
        """Register a genuinely executed record in the process-local authority.

        Registration records *authenticity*: that this process really ran the
        plan. It grants no confirmation authority by itself.
        """

        witness_digest = ""
        if record.findings:
            witness_digest = hashlib.sha256(
                json.dumps(
                    [item.to_dict() for item in record.findings],
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
        token = EXECUTION_AUTHORITY.register(
            record,
            trust=trust,
            binding_digest=plan.binding.digest() if plan is not None else "",
            candidate_uid=plan.binding.candidate_uid if plan is not None else "",
            inputs_verified=record.inputs_verified,
            witness_digest=witness_digest,
            ttl_seconds=self.policy.authority_ttl_seconds,
        )
        return replace(record, attestation=token)


def _classify_run(
    classifications: Sequence[str],
    findings: Sequence[SanitizerFinding],
    *,
    timed_out: bool,
) -> tuple[str, str]:
    """Map per-replay classifications onto a provider outcome."""

    if timed_out or "engine_failed:timeout" in classifications:
        return "engine_failed", "timeout"
    if "engine_failed:resource_exhaustion" in classifications:
        return "engine_failed", "resource_exhaustion"
    unique = set(classifications)
    if not classifications:
        return "inconclusive", "no_run"
    if unique == {"none"}:
        return "not_reproduced", "no_sanitizer_report"
    if unique == {"output_truncated"}:
        # The stream was cut off before it could be read in full, so a missing
        # report is unknown rather than absent.
        return "inconclusive", "output_truncated_without_report"
    if len(unique) > 1:
        return "inconclusive", "non_deterministic_replay"
    kind = classifications[0]
    if kind.startswith("engine_failed:"):
        return "engine_failed", kind.split(":", 1)[1]
    if findings and len({item.kind for item in findings}) == 1:
        return "witness_observed", "sanitizer_report"
    if findings:
        return "inconclusive", "mixed_report_kinds"
    return "inconclusive", "unclassified_run"


class AsanReproductionRunner(SanitizerReproductionRunner):
    """AddressSanitizer provider (V01)."""

    def __init__(
        self,
        *,
        policy: DynamicReproductionPolicy | None = None,
        compiler: str = "",
        version: str = "1",
    ) -> None:
        super().__init__("asan", policy=policy, compiler=compiler, version=version)


class TsanReproductionRunner(SanitizerReproductionRunner):
    """ThreadSanitizer provider (V02). Separate build, never mixed with ASAN."""

    def __init__(
        self,
        *,
        policy: DynamicReproductionPolicy | None = None,
        compiler: str = "",
        version: str = "1",
    ) -> None:
        super().__init__("tsan", policy=policy, compiler=compiler, version=version)


@dataclass(frozen=True)
class FakeRun:
    """One scripted fake execution."""

    outcome: str
    findings: tuple[SanitizerFinding, ...] = ()
    exit_code: int | None = 0
    signal_number: int | None = None
    timed_out: bool = False
    oom_killed: bool = False
    stdout: str = ""
    stderr: str = ""
    classifications: tuple[str, ...] = ()
    binary_digest_override: str = ""
    duration_ms: int = 5

    def resolved_classifications(self) -> tuple[str, ...]:
        if self.classifications:
            return self.classifications
        if self.findings:
            return (self.findings[0].kind,)
        if self.outcome == "not_reproduced":
            return ("none",)
        return (f"engine_failed:{self.outcome}",)


class FakeDynamicReproductionRunner:
    """Deterministic runner that pins the provider contract without a toolchain.

    It never launches a process and its executions are registered with *test*
    trust, so nothing it produces can ever mint a production confirmation.
    """

    trust = TRUST_TEST

    def __init__(
        self,
        script: Sequence[FakeRun],
        *,
        kind: str = "fake",
        version: str = "1",
        attest: bool = True,
        available: bool = True,
        availability_reason: str = "",
    ) -> None:
        if kind not in PROVIDER_KINDS:
            raise DynamicReproductionError("unsupported_provider_kind")
        self.kind = kind
        self.name = f"fake-{kind}-runner"
        self.version = str(version)
        self._script = list(script)
        self._index = 0
        self._attest = bool(attest)
        self._available = bool(available)
        self._availability_reason = availability_reason
        self.calls: list[ExecutionPlan] = []
        self._budget: _ExecutionBudget | None = None

    def use_budget(self, budget: _ExecutionBudget | None) -> None:
        self._budget = budget

    def availability(self) -> ProviderAvailability:
        return ProviderAvailability(self._available, self._availability_reason, {"runner": "fake"})

    def extend(self, runs: Sequence[FakeRun]) -> None:
        self._script.extend(runs)

    def execute(self, plan: ExecutionPlan) -> ExecutionRecord:
        self.calls.append(plan)
        if not self._script:
            raise DynamicReproductionError("fake_runner_script_exhausted")
        run = self._script[min(self._index, len(self._script) - 1)]
        self._index += 1
        classifications = run.resolved_classifications()
        record = ExecutionRecord(
            record_id=f"{plan.plan_id}-fake-{self._index}",
            plan_digest=plan.digest(),
            provider_name=self.name,
            provider_version=self.version,
            provider_kind=self.kind,
            outcome=run.outcome,
            run_argv=plan.run_argv,
            run_cwd=plan.run_cwd,
            environment=plan.env_allowlist,
            isolation="process",
            isolation_verified=True,
            isolation_notes=("fake_runner", "no_process_started"),
            build_argv=plan.build.argv if plan.build is not None else (),
            build_exit_code=0 if plan.build is not None else None,
            build_stdout_digest="",
            build_stderr_digest="",
            build_stdout_excerpt="",
            build_stderr_excerpt="",
            exit_code=run.exit_code,
            signal_number=run.signal_number,
            timed_out=run.timed_out,
            oom_killed=run.oom_killed,
            binary_digest=run.binary_digest_override or plan.binary_digest,
            binary_path=plan.binary_path,
            stdout_digest=_sha256_bytes(run.stdout.encode("utf-8")),
            stderr_digest=_sha256_bytes(run.stderr.encode("utf-8")),
            stdout_excerpt=run.stdout,
            stderr_excerpt=run.stderr,
            findings=tuple(run.findings),
            replay_classifications=classifications,
            replay_count=len(classifications),
            duration_ms=run.duration_ms,
            memory_limit_mode="simulated",
            runs=(
                RunEvidence(
                    index=0,
                    outcome=run.outcome,
                    detail=run.outcome,
                    exit_code=run.exit_code,
                    signal_number=run.signal_number,
                    timed_out=run.timed_out,
                    oom_killed=run.oom_killed,
                    classifications=classifications,
                    findings=tuple(run.findings),
                    stdout_digest=_sha256_bytes(run.stdout.encode("utf-8")),
                    stderr_digest=_sha256_bytes(run.stderr.encode("utf-8")),
                    stdout_bytes=len(run.stdout.encode("utf-8")),
                    stderr_bytes=len(run.stderr.encode("utf-8")),
                ),
            ),
            inputs_verified=False,
            source_digests=frozen_source_digests(plan.binding, plan),
            binary_identity_source="plan_declared" if plan.binary_digest else "",
            limitations=("fake_runner", "no_process_started"),
            detail=run.outcome,
        )
        if self._attest:
            return self.register_execution(record, plan=plan, trust=TRUST_TEST)
        return record

    def register_execution(
        self,
        record: ExecutionRecord,
        *,
        plan: ExecutionPlan | None = None,
        trust: str = TRUST_TEST,
    ) -> ExecutionRecord:
        witness_digest = ""
        if record.findings:
            witness_digest = hashlib.sha256(
                json.dumps(
                    [item.to_dict() for item in record.findings],
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
        token = EXECUTION_AUTHORITY.register(
            record,
            trust=trust,
            binding_digest=plan.binding.digest() if plan is not None else "",
            candidate_uid=plan.binding.candidate_uid if plan is not None else "",
            inputs_verified=False,
            witness_digest=witness_digest,
        )
        return replace(record, attestation=token)


def replay_witness(
    plan: ExecutionPlan,
    runner: DynamicReproductionProvider,
    *,
    times: int = 2,
    policy: DynamicReproductionPolicy | None = None,
    budget: _ExecutionBudget | None = None,
) -> ReplayEvidence:
    """Re-execute the same plan, ideally with an independent runner instance.

    Every re-execution is recorded with its own outcome, classifications, findings
    and *nested* per-run evidence, and the resulting evidence is registered against
    live execution receipts. A claim that was not produced here - hand-built,
    edited or deserialized - therefore carries no replay authority, and a nested
    run cannot be replaced by the aggregate classification of its execution.
    """

    if times < 1:
        raise DynamicReproductionError("invalid_replay_count")
    binder = getattr(runner, "use_budget", None)
    if callable(binder) and budget is not None:
        binder(budget)
    classifications: list[str] = []
    runs: list[ReplayRun] = []
    tokens: list[str] = []
    binary_digest = plan.binary_digest
    for index in range(times):
        record = runner.execute(plan)
        binary_digest = record.binary_digest or binary_digest
        if record.attestation:
            tokens.append(record.attestation)
        observed = tuple(record.replay_classifications)
        if record.findings:
            primary = record.findings[0].kind
        elif observed:
            primary = observed[0]
        else:
            primary = f"engine_failed:{record.outcome}"
        classifications.append(primary)
        runs.append(
            ReplayRun(
                index=index,
                record_id=record.record_id,
                outcome=record.outcome,
                classifications=observed or (primary,),
                findings=tuple(record.findings),
                binary_digest=record.binary_digest,
                execution_token=record.attestation,
                runs=tuple(record.runs),
                binary_identity_source=record.binary_identity_source,
                input_verification_digest=record.input_verification_digest,
            )
        )
    evidence = ReplayEvidence(
        plan_digest=plan.digest(),
        binary_digest=binary_digest,
        classifications=tuple(classifications),
        provider_name=runner.name,
        provider_version=runner.version,
        runs=tuple(runs),
    )
    ttl = policy.authority_ttl_seconds if policy is not None else 900
    REPLAY_AUTHORITY.register(
        evidence,
        plan_digest=plan.digest(),
        binding_digest=plan.binding.digest(),
        execution_tokens=tokens,
        ttl_seconds=ttl,
    )
    return evidence


def qualify_witness(
    binding: CandidateBinding,
    plan: ExecutionPlan,
    record: ExecutionRecord,
    *,
    replay: ReplayEvidence | None,
    policy: DynamicReproductionPolicy,
) -> Qualification:
    """Decide whether a record may become adjudication input for this candidate."""

    reasons: list[str] = []
    facts = {name: False for name in DYNAMIC_WITNESS_FACTS}

    if plan.digest() != record.plan_digest:
        reasons.append("plan_record_mismatch")
    if record.provider_kind != plan.provider_kind or record.provider_name != plan.provider_name:
        reasons.append("provider_identity_mismatch")
    entry = EXECUTION_AUTHORITY.entry(record.attestation)
    if entry is None:
        reasons.append("no_live_execution_receipt")
    else:
        if entry.record_digest != record.digest():
            reasons.append("execution_receipt_record_mismatch")
        if entry.binding_digest and entry.binding_digest != binding.digest():
            reasons.append("execution_receipt_binding_mismatch")
        if entry.provider_kind != record.provider_kind:
            reasons.append("execution_receipt_provider_mismatch")
    if record.outcome in UNDECIDED_OUTCOMES:
        reasons.append(f"undecided_outcome:{record.outcome}")
    if entry is not None and entry.production and not entry.inputs_verified:
        # A production execution must have verified the declared identity of its
        # actual inputs before launching.
        reasons.append("inputs_not_verified_before_launch")

    source_bound = bool(plan.harness_digest) and bool(binding.source_revision)
    facts["source_identity_bound"] = source_bound
    if not source_bound:
        reasons.append("source_identity_unbound")

    if plan.binary_digest:
        binary_bound = bool(record.binary_digest) and plan.binary_digest == record.binary_digest
        if record.binary_digest and plan.binary_digest != record.binary_digest:
            reasons.append("binary_identity_mismatch")
    else:
        # The plan declares that its own authorized build produces the executable,
        # so the identity that binds is the post-build digest of that artifact.
        binary_bound = bool(
            record.binary_digest
            and plan.build is not None
            and record.binary_identity_source == "post_build_output"
        )
    facts["binary_identity_bound"] = binary_bound
    if not binary_bound:
        reasons.append("binary_identity_unbound")

    shadow = is_shadow_candidate(binding)
    if shadow:
        reasons.append("shadow_candidate_not_confirmable")
    if not record.isolation_verified:
        # A requested boundary that was not actually applied is a real
        # limitation of the evidence, not a detail to be recorded and ignored.
        reasons.append("requested_isolation_not_applied")

    replay_ok = False
    required = max(1, policy.required_replays)
    replay_reasons: list[str] = []
    replay_entry = REPLAY_AUTHORITY.entry(replay) if isinstance(replay, ReplayEvidence) else None
    if replay is None:
        replay_reasons.append("independent_replay_missing")
    elif replay_entry is None:
        # The claim is not backed by re-executions performed in this process.
        replay_reasons.append("no_live_replay_receipt")
    else:
        if replay_entry.plan_digest != plan.digest():
            replay_reasons.append("replay_plan_mismatch")
        if replay_entry.binding_digest != binding.digest():
            replay_reasons.append("replay_binding_mismatch")
        if not replay_entry.execution_tokens or not all(
            EXECUTION_AUTHORITY.is_live(token) for token in replay_entry.execution_tokens
        ):
            replay_reasons.append("replay_execution_receipt_expired")
        if replay.plan_digest != plan.digest():
            replay_reasons.append("replay_plan_mismatch")
        if replay.binary_digest and replay.binary_digest != record.binary_digest:
            replay_reasons.append("replay_binary_mismatch")
        if not replay.consistent:
            replay_reasons.append("replay_inconsistent")
        # Each independent execution must reproduce the *primary execution's own*
        # classification. Comparing aggregate tuples would be wrong now that one
        # execution performs exactly one run, so the per-run classification of
        # every replay is compared with the primary run's classification.
        primary_signature = tuple(record.replay_classifications)
        for run in replay.runs:
            if tuple(run.classifications) != primary_signature:
                replay_reasons.append("replay_classification_mismatch")
        if len(replay.classifications) < required:
            replay_reasons.append("replay_below_required_count")
        if not replay.all_witnesses_observed:
            # A run that did not itself observe the witness (inconclusive,
            # failed or clean) may never be collapsed into a success.
            replay_reasons.append("replay_run_without_witness")
        if any(
            run.binary_digest and run.binary_digest != record.binary_digest for run in replay.runs
        ):
            replay_reasons.append("replay_run_binary_mismatch")
        if any(len(set(run.classifications)) > 1 for run in replay.runs):
            replay_reasons.append("replay_run_non_deterministic")
        for run in replay.runs:
            if not run.findings:
                continue
            if not any(
                match_witness_to_candidate(
                    binding,
                    candidate_finding,
                    object_witness=plan.object_witness,
                    require_exact_object=plan.require_exact_object,
                    site_tolerance_lines=plan.site_tolerance_lines or policy.site_tolerance_lines,
                )[0]
                for candidate_finding in run.findings
            ):
                replay_reasons.append("replay_run_witness_not_matching_candidate")
        # Production trust is required for *every* execution, including each
        # independent replay: a production primary record combined with
        # test-trusted replays must never add up to a production confirmation.
        for run in replay.runs:
            run_entry = EXECUTION_AUTHORITY.entry(run.execution_token)
            if run_entry is None:
                replay_reasons.append("replay_run_receipt_missing")
            elif run_entry.binding_digest and run_entry.binding_digest != binding.digest():
                replay_reasons.append("replay_run_binding_mismatch")
            # Nested runs of one replay are matched to the candidate themselves:
            # an aggregate classification cannot stand in for per-run identity.
            for nested in run.runs:
                if nested.outcome != "observed":
                    continue
                if not nested.findings:
                    replay_reasons.append("replay_nested_run_without_report")
                    continue
                if not any(
                    match_witness_to_candidate(
                        binding,
                        candidate_finding,
                        object_witness=plan.object_witness,
                        require_exact_object=plan.require_exact_object,
                        site_tolerance_lines=plan.site_tolerance_lines
                        or policy.site_tolerance_lines,
                    )[0]
                    for candidate_finding in nested.findings
                ):
                    replay_reasons.append("replay_nested_run_witness_not_matching_candidate")
    replay_ok = not replay_reasons
    reasons.extend(replay_reasons)
    facts["replay_consistent"] = replay_ok

    # Every run of the primary execution must describe *this* candidate. One
    # execution performs exactly one run, and a record that carries several runs
    # (a caller may aggregate) is checked run by run: a matching aggregate finding
    # cannot excuse a run that reported a different site or object.
    if record.outcome == "witness_observed":
        if not record.runs:
            reasons.append("primary_run_evidence_missing")
        for primary_run in record.runs:
            if primary_run.outcome != "observed":
                continue
            if not primary_run.findings:
                reasons.append("primary_run_witness_without_report")
                continue
            if not any(
                match_witness_to_candidate(
                    binding,
                    candidate_finding,
                    object_witness=plan.object_witness,
                    require_exact_object=plan.require_exact_object,
                    site_tolerance_lines=plan.site_tolerance_lines or policy.site_tolerance_lines,
                )[0]
                for candidate_finding in primary_run.findings
            ):
                reasons.append("primary_run_witness_not_matching_candidate")
    if record.replay_count < 1:
        reasons.append("primary_execution_missing")
    if not record.replay_consistent and record.outcome == "witness_observed":
        reasons.append("record_replay_inconsistent")

    matched_finding: SanitizerFinding | None = None
    if record.outcome == "witness_observed" and record.findings:
        diagnostics = False
        for candidate_finding in record.findings:
            ok, match_facts, match_reasons = match_witness_to_candidate(
                binding,
                candidate_finding,
                object_witness=plan.object_witness,
                require_exact_object=plan.require_exact_object,
                site_tolerance_lines=plan.site_tolerance_lines or policy.site_tolerance_lines,
            )
            if ok:
                matched_finding = candidate_finding
                facts.update(match_facts)
                break
            if not diagnostics:
                # Keep the first finding's per-dimension outcome so a rejected
                # witness still shows which binding actually failed.
                facts.update(match_facts)
                diagnostics = True
            reasons.extend(match_reasons)
    elif record.outcome == "witness_observed":
        reasons.append("witness_without_report")

    # A qualified witness must be free of *every* recorded defect: plan/record
    # identity, provider identity, live attestation, source and binary binding,
    # candidate object/site/family match and a consistent independent replay.
    # Anything that added a reason keeps the candidate undecided.
    qualified = bool(
        matched_finding is not None
        and record.outcome == "witness_observed"
        and all(facts[name] for name in DYNAMIC_WITNESS_FACTS)
        and not reasons
    )
    return Qualification(
        qualified=qualified,
        facts=facts,
        reasons=tuple(dict.fromkeys(reasons)),
        finding=matched_finding,
    )


def replay_production_problems(
    binding: CandidateBinding, replay: ReplayEvidence | None
) -> tuple[str, ...]:
    """Why the independent replays cannot support a *production* confirmation.

    Attachment and authority are deliberately separate: a test-trusted replay may
    still describe the same evidence (so the record stays auditable), but it can
    never turn a production primary execution into a production confirmation. Only
    executions that were really run with verified inputs under production trust
    count, which is why this is checked per replay run instead of per process.
    """

    if not isinstance(replay, ReplayEvidence) or not replay.runs:
        return ("no_production_replay_runs",)
    problems: list[str] = []
    for run in replay.runs:
        entry = EXECUTION_AUTHORITY.entry(run.execution_token)
        if entry is None:
            problems.append("replay_run_receipt_missing")
            continue
        if not entry.production:
            problems.append("replay_run_not_production_trusted")
        if not entry.inputs_verified:
            problems.append("replay_run_inputs_not_verified")
        if entry.binding_digest and entry.binding_digest != binding.digest():
            problems.append("replay_run_binding_mismatch")
    return tuple(dict.fromkeys(problems))


def dynamic_witness_proof_record(
    binding: CandidateBinding,
    plan: ExecutionPlan,
    record: ExecutionRecord,
    finding: SanitizerFinding,
    *,
    authorized: bool = False,
    source_digests: Sequence[tuple[str, str]] = (),
) -> dict[str, Any]:
    """Build a dynamic-witness proof record.

    The public default is deliberately *unauthorized*: it describes the evidence
    but claims no confirmation, because a caller outside the registrar cannot
    supply the process-local execution receipt that would make a confirmation
    real. Only ``register_dynamic_reproduction`` asks for an authorized record,
    and even then the shared adjudication re-checks the live capability.
    """

    fact_ids = [
        f"dynrepro:{record.record_id}",
        f"plan:{plan.digest()[:32]}",
        f"binary:{record.binary_digest[:32]}",
        f"witness_ref:{_digest([record.digest(), finding.raw_digest])[:32]}",
    ]
    frozen = tuple((str(path), str(digest)) for path, digest in source_digests)
    return {
        "proof_version": DYNAMIC_WITNESS_PROOF_VERSION,
        "outcome": "confirm" if authorized else "inconclusive",
        "proof_kind": DYNAMIC_WITNESS_PROOF_KIND,
        "producer_engine": f"dynamic-reproduction:{record.provider_name}@{record.provider_version}",
        "facts": sorted(DYNAMIC_WITNESS_FACTS) if authorized else [],
        "fact_ids": fact_ids,
        "code_hash": binding.digest(),
        "completeness": "complete" if authorized else "incomplete",
        "scope": "controlled_local_harness_execution",
        "assumptions": [
            f"harness_digest={plan.harness_digest}",
            f"isolation={record.isolation}",
            f"replay_count={record.replay_count}",
            f"binary_identity_source={record.binary_identity_source or 'undeclared'}",
            "subprocess_is_not_a_container_sandbox",
            "requires_process_local_execution_receipt",
            *(
                [f"source_files_verified={len(frozen)}"]
                if frozen
                else ["source_snapshot_unavailable"]
            ),
        ],
        "contradiction_or_obligation": (
            f"受控复现观察到与候选对象/站点/缺陷族相符的 `{finding.kind}` 报告"
            f"（{finding.site}），二进制与源码身份均已绑定且独立重放一致。"
        ),
        "subject_identity": binding.object_identity or binding.candidate_uid,
        "producer_trust": record.provider_kind if authorized else "unauthorized",
        "witness_record_digest": record.digest(),
        # The actual files this witness was derived from are frozen into the
        # record: the final boundary re-hashes them, so a later edit of any of
        # them revokes the confirmation instead of silently surviving it.
        "source_files": [{"path": path, "sha256": digest} for path, digest in frozen],
    }


def register_dynamic_reproduction(
    issue: dict[str, Any],
    *,
    plan: ExecutionPlan,
    record: ExecutionRecord,
    replay: ReplayEvidence | None = None,
    policy: DynamicReproductionPolicy | None = None,
) -> DynamicReproductionOutcome:
    """Adapt one execution record onto one candidate as provider metadata.

    Mutates ``issue`` only by adding ``dynamic_reproduction*`` metadata and, for a
    fully qualified witness, one appended live proof record. It never changes
    ``validation_status``, ``candidate_disposition`` or any rejection channel:
    undecided outcomes stay undecided. Identity mismatch between the plan and the
    issue raises instead of degrading, so stale evidence cannot be reused.
    """

    policy = policy or DynamicReproductionPolicy()
    if not policy.enabled:
        raise DynamicReproductionError("dynamic_reproduction_disabled")
    bound = bind_candidate(issue)
    mismatched = plan.binding.mismatched_fields(bound)
    if mismatched:
        # Stale evidence cannot be re-pointed at a changed candidate: refuse
        # instead of degrading into a partial match.
        raise DynamicReproductionError("plan_issue_identity_mismatch:" + ",".join(mismatched))
    entry = EXECUTION_AUTHORITY.entry(record.attestation)
    if record.outcome == "witness_observed" and entry is None:
        # Only a witness claim needs a live receipt; undecided metadata grants
        # nothing and stays registrable so the run is still auditable.
        raise DynamicReproductionError("execution_receipt_not_live")

    qualification = qualify_witness(plan.binding, plan, record, replay=replay, policy=policy)
    request = make_request(plan.binding, plan)
    proof_attached = False
    reasons = qualification.reasons
    if qualification.qualified and not policy.attach_proof:
        reasons = tuple(dict.fromkeys(reasons + ("shadow_mode_proof_not_attached",)))
    if reasons != qualification.reasons:
        qualification = Qualification(
            qualified=qualification.qualified,
            facts=qualification.facts,
            reasons=reasons,
            finding=qualification.finding,
        )

    authority_granted = False
    if qualification.qualified and policy.attach_proof and qualification.finding is not None:
        # Confirmation authority needs a *production* execution. A fake or
        # otherwise test-trusted provider may attach a descriptive record, but
        # that record never carries the confirmation facts and never reaches the
        # shared adjudication.
        authority_reasons = replay_production_problems(plan.binding, replay)
        # Use the *execution-time* snapshot carried by the record; a fresh
        # re-hash at registration must never accept a file that changed after the
        # accepted execution, and a missing file must forbid authority.
        frozen = tuple(record.source_digests)
        snapshot_holds = source_digests_hold(frozen)
        # The binary accepted at execution time must still be present and
        # unchanged; a symbolic test execution that bound no real file qualifies
        # only because it never required binding.
        binary_holds = entry is not None and execution_binary_holds(entry)
        authoritative = bool(
            entry is not None
            and entry.production
            and not authority_reasons
            and snapshot_holds
            and binary_holds
        )
        proof = dynamic_witness_proof_record(
            plan.binding,
            plan,
            record,
            qualification.finding,
            authorized=authoritative,
            source_digests=frozen,
        )
        existing = issue.get("deterministic_proofs")
        proofs = list(existing) if isinstance(existing, list) else []
        proofs.append(proof)
        issue["deterministic_proofs"] = proofs
        proof_attached = True
        if authoritative:
            # The capability is bound to this exact mapping object; the record
            # keeps the strong reference so the id cannot be recycled.
            CONFIRMATION_AUTHORITY.mint(
                proof,
                plan_digest=plan.digest(),
                record_digest=record.digest(),
                binding_digest=plan.binding.digest(),
                candidate_uid=plan.binding.candidate_uid,
                execution_token=record.attestation,
                witness_digest=entry.witness_digest if entry is not None else "",
                ttl_seconds=policy.authority_ttl_seconds,
                source_digests=frozen,
                task_scope=plan.plan_id,
            )
            authority_granted = True
        else:
            reasons = tuple(
                dict.fromkeys(
                    reasons + (authority_reasons or ("test_trust_execution_not_confirming",))
                )
            )
            qualification = Qualification(
                qualified=qualification.qualified,
                facts=qualification.facts,
                reasons=reasons,
                finding=qualification.finding,
            )
            # A test-trust execution keeps no capability at all; the registry
            # entry only has to live long enough to describe this decision.
            CONFIRMATION_AUTHORITY.retire_for_execution(record.attestation)
    authority_reasons = replay_production_problems(plan.binding, replay)

    result_outcome = RESULT_OUTCOME_BY_PROVIDER_OUTCOME.get(record.outcome, "inconclusive")
    if record.outcome == "witness_observed" and not qualification.qualified:
        # A report was observed, but not for *this* candidate: the reserved
        # result must not claim the candidate was reproduced.
        result_outcome = "inconclusive"
    result = DynamicReproductionResult(
        request_id=request.request_id,
        outcome=result_outcome,
        reasoning=_result_reasoning(record, qualification),
        evidence_refs=(f"plan:{plan.digest()}", f"record:{record.record_id}"),
        # Resolvable where possible; a digest is not a location, so when the logs
        # were not published the record says so instead of implying one.
        artifact_refs=tuple(record.artifact_refs)
        or tuple(
            ref
            for ref in (
                f"stdout_digest:{record.stdout_digest}" if record.stdout_digest else "",
                f"stderr_digest:{record.stderr_digest}" if record.stderr_digest else "",
                f"binary_digest:{record.binary_digest}" if record.binary_digest else "",
            )
            if ref
        ),
        duration_ms=max(0, record.duration_ms),
    )
    issue["dynamic_reproduction"] = {
        "schema_version": DYNAMIC_EXECUTION_RECORD_VERSION,
        "provider": f"{record.provider_name}@{record.provider_version}",
        "provider_kind": record.provider_kind,
        "provider_outcome": record.outcome,
        "provider_detail": record.detail,
        "request": request.to_dict(),
        "plan": plan.to_dict(),
        "record": record.to_dict(),
        "qualification": qualification.to_dict(),
        "replay": replay.to_dict() if replay is not None else None,
        "proof_attached": proof_attached,
        # Attachment is not authority: a descriptive record may be attached for
        # evidence, while a confirmation capability exists only when every
        # execution (primary and replays) was production-trusted with verified
        # inputs and no authority problem was recorded.
        "confirmation_authority": {
            "granted": authority_granted,
            "reasons": list(authority_reasons),
        },
    }
    issue["dynamic_reproduction_outcome"] = record.outcome
    issue["dynamic_reproduction_provider"] = f"{record.provider_name}@{record.provider_version}"
    issue["dynamic_reproduction_qualified"] = bool(qualification.qualified)
    return DynamicReproductionOutcome(
        request=request,
        result=result,
        record=record,
        qualification=qualification,
        proof_attached=proof_attached,
    )


def _default_provider_runner(
    plan: ExecutionPlan, policy: DynamicReproductionPolicy
) -> DynamicReproductionProvider:
    """Select the product runner that the plan's provider kind asks for.

    The plan is the authorization record and it names the sanitizer it was
    approved for, so the default product entry must dispatch on that name instead
    of always choosing one sanitizer. An unknown kind fails closed.
    """

    if plan.provider_kind == "asan":
        return AsanReproductionRunner(policy=policy)
    if plan.provider_kind == "tsan":
        return TsanReproductionRunner(policy=policy)
    raise DynamicReproductionError(f"unsupported_provider_kind:{plan.provider_kind}")


def run_dynamic_reproduction(
    issue: dict[str, Any],
    plan: ExecutionPlan,
    *,
    policy: DynamicReproductionPolicy,
    runner: DynamicReproductionProvider | None = None,
    plan_digest: str = "",
) -> DynamicReproductionOutcome:
    """Product entry: execute an authorized plan, replay it, then register.

    This is the only supported way for product code to consume a plan. It refuses
    a disabled policy, checks that the plan still describes the current candidate
    before spending any work, executes the plan with the requested provider,
    re-executes it independently for the required number of replays, and hands the
    result to :func:`register_dynamic_reproduction`.

    Cancellation and shutdown propagate: the runner observes the ambient
    cancellation token and returns a ``cancelled`` record, which stays undecided.
    Nothing is launched when the plan does not match the issue.
    """

    if not policy.enabled:
        raise DynamicReproductionError("dynamic_reproduction_disabled")
    if plan_digest and plan_digest != plan.digest():
        raise DynamicReproductionError("stale_execution_plan")
    bound = bind_candidate(issue)
    mismatched = plan.binding.mismatched_fields(bound)
    if mismatched:
        raise DynamicReproductionError("plan_issue_identity_mismatch:" + ",".join(mismatched))
    required = max(1, policy.required_replays)
    # ``plan.max_replays`` authorizes the *total* number of executions: the
    # primary execution plus the independent replays. The primary always gets its
    # slot; the replays share what is left, and a shortfall is recorded instead of
    # refusing before the provider has even been asked to run.
    authorized_runs = int(plan.max_replays) if int(plan.max_replays) > 0 else 1
    replays = min(required, max(0, authorized_runs - 1))
    provider = runner or _default_provider_runner(plan, policy)
    budget = _ExecutionBudget(
        run_limit=authorized_runs,
        deadline=time.monotonic() + max(1, int(policy.deadline_seconds)),
    )
    binder = getattr(provider, "use_budget", None)
    if callable(binder):
        binder(budget)
    try:
        record = provider.execute(plan)
        replay: ReplayEvidence | None = None
        if record.outcome == "witness_observed" and replays > 0:
            replay = replay_witness(
                plan,
                provider,
                times=replays,
                policy=policy,
                budget=budget,
            )
        outcome = register_dynamic_reproduction(
            issue, plan=plan, record=record, replay=replay, policy=policy
        )
        issue["dynamic_reproduction_budget"] = {
            "authorized_runs": authorized_runs,
            "primary_runs": 1,
            "replays_requested": required,
            "replays_run": replays,
            "clamped_to_plan_budget": replays < required,
            "deadline_seconds": int(policy.deadline_seconds),
        }
        return outcome
    except CancellationError as exc:
        record = ExecutionRecord(
            record_id=f"{plan.plan_id}-cancelled",
            plan_digest=plan.digest(),
            provider_name=provider.name,
            provider_version=provider.version,
            provider_kind=plan.provider_kind,
            outcome="cancelled",
            run_argv=plan.run_argv,
            run_cwd=plan.run_cwd,
            environment=plan.env_allowlist,
            isolation="process",
            isolation_verified=False,
            isolation_notes=("cancelled_before_isolation",),
            build_argv=plan.build.argv if plan.build is not None else (),
            build_exit_code=None,
            build_stdout_digest="",
            build_stderr_digest="",
            build_stdout_excerpt="",
            build_stderr_excerpt="",
            exit_code=None,
            signal_number=None,
            timed_out=False,
            oom_killed=False,
            binary_digest=plan.binary_digest,
            binary_path=plan.binary_path,
            stdout_digest="",
            stderr_digest="",
            stdout_excerpt="",
            stderr_excerpt="",
            findings=(),
            replay_classifications=(),
            replay_count=0,
            duration_ms=0,
            memory_limit_mode="none",
            detail=f"cancelled:{exc}",
            limitations=("cancelled_before_registration", "no_process_was_started"),
        )
        return register_dynamic_reproduction(
            issue, plan=plan, record=record, replay=None, policy=policy
        )


# --------------------------------------------------------------------------
# Product seam: approved-plan acquisition
# --------------------------------------------------------------------------

#: Callable that returns the plan approved for one candidate, or ``None`` when no
#: approved plan exists for it. A provider may also return ``(plan, digest)`` so
#: the caller can detect a plan that changed after it was recorded.
PlanProvider = Callable[
    [Mapping[str, Any], DynamicReproductionPolicy],
    "ExecutionPlan | tuple[ExecutionPlan, str] | None",
]

# One process-local slot: an approved-plan source is never restored from disk, so
# a persisted file cannot become an execution authorization.
_PLAN_PROVIDER: PlanProvider | None = None


def register_dynamic_reproduction_plan_provider(provider: PlanProvider | None) -> None:
    """Install (or clear, with ``None``) the process-local approved-plan source."""

    global _PLAN_PROVIDER
    if provider is not None and not callable(provider):
        raise DynamicReproductionError("plan_provider_not_callable")
    _PLAN_PROVIDER = provider


def dynamic_reproduction_plan_provider() -> PlanProvider | None:
    """Return the installed approved-plan source, if any."""

    return _PLAN_PROVIDER


def attempt_dynamic_reproduction(
    issue: dict[str, Any],
    *,
    config: Any = None,
    policy: DynamicReproductionPolicy | None = None,
    runner: DynamicReproductionProvider | None = None,
    provider: PlanProvider | None = None,
) -> DynamicReproductionOutcome | None:
    """Reproduce one candidate from an approved plan; never invent one.

    This is the scan-facing seam. It resolves the policy from the runtime config,
    and then:

    * returns ``None`` without touching the issue when the mode is off (the
      shipped default), so the default scan path is unchanged;
    * refuses shadow candidates outright;
    * asks the installed plan provider for an approved plan. No provider, no
      plan, or a provider that fails leaves the issue undecided and records why
      under ``dynamic_reproduction_attempt``; the caller keeps its normal path;
    * otherwise executes the plan through :func:`run_dynamic_reproduction`, which
      attaches a proof only when the witness is fully qualified, so the existing
      unified adjudication decides as usual.

    A cancellation is re-raised so the caller's shutdown path keeps working.
    """

    resolved = policy if policy is not None else make_dynamic_reproduction_policy(config)
    if not resolved.enabled:
        return None
    # Binding may legitimately be impossible for an ordinary rule candidate that
    # has no executable-plan identity yet. That is a *missing provider input*, not
    # a scan failure, so it is recorded on the issue and the scan keeps going -
    # including when a provider is installed and would otherwise receive an
    # incomplete candidate.
    try:
        binding = bind_candidate(issue)
    except DynamicReproductionError as exc:
        issue["dynamic_reproduction_attempt"] = {
            "status": "candidate_identity_unavailable",
            "reason": str(exc),
        }
        return None
    if is_shadow_candidate(binding):
        issue["dynamic_reproduction_attempt"] = {"status": "shadow_candidate_not_attempted"}
        return None
    source = provider if provider is not None else _PLAN_PROVIDER
    if source is None:
        issue["dynamic_reproduction_attempt"] = {"status": "no_plan_provider"}
        return None
    plan: ExecutionPlan | None = None
    plan_digest = ""
    try:
        produced = source(issue, resolved)
    except CancellationError:
        raise
    except Exception as exc:  # a plan source must never break the scan
        issue["dynamic_reproduction_attempt"] = {
            "status": "plan_provider_failed",
            "reason": type(exc).__name__,
        }
        return None
    if isinstance(produced, tuple):
        plan, plan_digest = produced[0], str(produced[1] or "")
    else:
        plan = produced
    if plan is None:
        issue["dynamic_reproduction_attempt"] = {"status": "no_plan_available"}
        return None
    if not isinstance(plan, ExecutionPlan):
        # A plan source must return a real approved plan; anything else is a
        # configuration bug and is reported instead of being executed.
        issue["dynamic_reproduction_attempt"] = {"status": "plan_provider_invalid"}
        return None
    try:
        outcome = run_dynamic_reproduction(
            issue, plan, policy=resolved, runner=runner, plan_digest=plan_digest
        )
    except CancellationError:
        raise
    except DynamicReproductionError as exc:
        # A stale or mismatched plan is a plan-source bug, not a candidate
        # verdict: record it and let the scan continue unchanged.
        issue["dynamic_reproduction_attempt"] = {
            "status": "plan_rejected",
            "reason": str(exc),
        }
        return None
    except Exception as exc:  # a provider defect must never break the scan
        issue["dynamic_reproduction_attempt"] = {
            "status": "reproduction_failed",
            "reason": type(exc).__name__,
        }
        return None
    issue["dynamic_reproduction_attempt"] = {"status": "attempted"}
    return outcome


def _result_reasoning(record: ExecutionRecord, qualification: Qualification) -> str:
    if record.outcome == "witness_observed" and qualification.qualified:
        return (
            f"受控复现产生与候选相符的 {record.classification} witness，"
            "已通过身份、分类与独立重放资格检查，交由现有统一裁决处理。"
        )
    if record.outcome == "witness_observed":
        return (
            "复现报告未通过候选身份/站点/缺陷族或独立重放资格检查，保留未决"
            f"（原因：{'、'.join(qualification.reasons) or 'unknown'}）。"
        )
    if record.outcome == "not_reproduced":
        return (
            f"在绑定构建下未观察到 sanitizer 报告（{record.detail}）；"
            "未复现不构成安全反证，候选保持未决。"
        )
    if record.outcome == "engine_failed":
        return f"复现执行失败（{record.detail}），保留未决；执行失败不构成安全反证。"
    if record.outcome == "unsupported":
        if record.detail == "plan_identity_unverified":
            return (
                "执行前无法核验计划声明的 harness/输入/可执行文件身份，未启动任何进程，"
                "候选保持未决。"
            )
        if record.detail == "requested_isolation_unavailable":
            return "请求的隔离边界不可用，未启动任何进程，候选保持未决。"
        return f"该 provider 在本机不可用（{record.detail}），保留未决。"
    if record.outcome == "cancelled":
        return "复现执行被取消，保留未决。"
    return f"复现结果不确定（{record.detail}），保留未决。"
