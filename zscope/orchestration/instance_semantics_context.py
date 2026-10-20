"""Freeze and recheck the dependencies of a bounded instance semantic batch.

This owns no inference or persisted authority. The immutable factory output is
admitted only while the current workbook, policies and exact native inputs still
match. A saved snapshot is never itself evidence that those inputs are current.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from contextlib import nullcontext
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

import yaml

from ..config.user_config_workbook import UserConfigWorkbook
from ..retrieval import indexing_identity
from ..retrieval.build_context import context_input_status
from ..retrieval.code_index import CodeIndex, _JobRuntimeOutputs
from ..retrieval.instance_index import InstanceScope, ScopedCodeIndex, wrap_scoped_code_index
from ..semantics.instance_semantics import (
    FrozenJSON,
    FrozenWorkbookRows,
    InstanceSemanticsSnapshot,
    SemanticsDependencies,
    SemanticsUnavailable,
    _HOST_GLIBC_FEATURES,
    _HOST_GLIBC_STDLIB,
    _is_sha256_hex,
    _trusted_host_header,
    builtin_semantics_fingerprint,
    build_instance_semantics,
)


SEMANTICS_POLICY = "builtin_current_manual_advisory_no_inferred.v1"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def semantics_manifest_digest(snapshots: Mapping[str, InstanceSemanticsSnapshot]) -> str:
    return _digest(
        [
            {"scope": snapshot.scope.to_payload(), "digest": snapshot.digest}
            for _identity, snapshot in sorted(snapshots.items())
        ]
    )


def _policy_json(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _policy_json(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _policy_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_policy_json(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_policy_json(item) for item in value), key=canonical_bytes)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("instance_semantics_unverifiable_policy")


def freeze_workbook(path: Path) -> FrozenWorkbookRows:
    """Use a fresh reader and compare bytes around the complete row projection.

    The product workbook reader caches by mtime/size. A fresh object prevents a
    same-size, same-mtime edit from pairing old cached rows with a new digest.
    A missing workbook is legitimate empty input; unreadable input is an error.
    """
    before = path.read_bytes() if path.exists() else None
    reader = UserConfigWorkbook(path)
    external = reader.list_external_functions()
    paired = reader.list_paired_functions()
    all_rows = reader.read_rows()
    other = [
        {"sheet": sheet, **row}
        for sheet, rows in sorted(all_rows.items())
        if sheet not in {"resource", "lock"}
        for row in rows
    ]
    after = path.read_bytes() if path.exists() else None
    if before != after:
        raise ValueError("instance_semantics_workbook_changed_during_freeze")
    return FrozenWorkbookRows(
        workbook_sha256=(
            _digest({"missing": True}) if before is None else hashlib.sha256(before).hexdigest()
        ),
        external_rows=tuple(FrozenJSON(canonical_bytes(row)) for row in external),
        paired_rows=tuple(FrozenJSON(canonical_bytes(row)) for row in paired),
        other_advisory_rows=tuple(FrozenJSON(canonical_bytes(row)) for row in other),
    )


def current_dependencies(config: Any) -> SemanticsDependencies:
    from ..semantics import contracts, defaults, standard_api
    from ..rules.catalog import serialize_effective_rules
    from ..rules.extensions import preflight_rules
    from .jobs.scan_work import _business_answers_digest

    raw_defaults = files("zscope.semantics").joinpath(defaults.DEFAULT_SEMANTICS_FILE).read_bytes()
    fresh_defaults = yaml.safe_load(raw_defaults) or {}
    if fresh_defaults != defaults.load_default_semantics_data():
        raise ValueError("instance_semantics_cached_defaults_not_current")
    answers = _business_answers_digest(config)
    if answers is None:
        raise ValueError("instance_semantics_business_answers_unverifiable")
    compiler = str(contracts.CONTRACT_COMPILER_VERSION)
    api_version = str(standard_api.STANDARD_API_VERSION)
    if not compiler or not api_version:
        raise ValueError("instance_semantics_versions_unverifiable")
    builtin = builtin_semantics_fingerprint()
    if builtin["compiler_version"] != compiler or builtin["standard_api_version"] != api_version:
        raise ValueError("instance_semantics_loaded_compiler_not_current")
    effective = preflight_rules(config)
    extension_inputs: dict[str, str] = {}
    for source in effective.provenance.extension_sources:
        components = (
            (source,)
            if source.get("kind") == "yaml_pack"
            else source.get("implementation_components", ())
        )
        if not components:
            raise ValueError("instance_semantics_extension_inputs_unverifiable")
        for component in components:
            raw_path = component.get("path")
            if not raw_path or component.get("kind") not in {"yaml_pack", "source_file"}:
                raise ValueError("instance_semantics_extension_inputs_unverifiable")
            path = Path(str(raw_path))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != component.get("sha256"):
                raise ValueError("instance_semantics_extension_inputs_not_current")
            extension_inputs[str(path)] = digest
    return SemanticsDependencies(
        compiler_version=compiler,
        standard_api_version=api_version,
        builtin_payload_sha256=builtin["builtin_payload_sha256"],
        business_answers_sha256=answers,
        effective_policy_sha256=_digest(
            {
                "semantics": SEMANTICS_POLICY,
                "defaults_sha256": hashlib.sha256(raw_defaults).hexdigest(),
                "compiler_sources": {
                    name: hashlib.sha256(
                        files("zscope.semantics").joinpath(name).read_bytes()
                    ).hexdigest()
                    for name in (
                        "contracts.py",
                        "standard_api.py",
                        "defaults.py",
                        "instance_semantics.py",
                    )
                },
                "instance_execution_sources": {
                    name: hashlib.sha256(files("zscope").joinpath(name).read_bytes()).hexdigest()
                    for name in (
                        "core/analysis/analyzer.py",
                        "core/validation/runner.py",
                        "core/candidates/pipeline.py",
                        "core/candidates/regex.py",
                        "core/candidates/graph.py",
                        "core/candidates/clang_ast_cfg.py",
                        "core/candidates/cpp_domains/resource_lifecycle.py",
                        "core/candidates/cpp_domains/concurrency_shared_state.py",
                        "core/candidates/cpp_domains/memory_bounds_integer.py",
                        "core/candidates/cpp_domains/protocol_ownership_logic.py",
                        "core/candidates/cpp_domains/typed_resources.py",
                        "core/candidates/cpp_domains/shared_access.py",
                        "orchestration/parallel_analyzer.py",
                        "orchestration/candidates.py",
                        "orchestration/candidate_envelope.py",
                        "orchestration/subagents.py",
                        "orchestration/instance_semantics_context.py",
                        "orchestration/scan_session.py",
                        "orchestration/jobs/scan_work.py",
                        "orchestration/jobs/instance_results.py",
                        "orchestration/jobs/store.py",
                        "orchestration/jobs/session_scheduler.py",
                        "orchestration/jobs/scheduler_hook.py",
                        "retrieval/code_index.py",
                        "retrieval/indexing_identity.py",
                        "retrieval/clang_batch.py",
                        "retrieval/build_context.py",
                        "retrieval/instance_index.py",
                        "semantics/instance_semantics.py",
                        "semantics/models.py",
                        "semantics/contracts.py",
                        "semantics/contract_conditions.py",
                        "semantics/defaults.py",
                        "semantics/standard_api.py",
                        "rules/catalog.py",
                        "rules/implementation.py",
                        "rules/qualification.py",
                        "rules/extensions.py",
                        "rules/engine.py",
                    )
                },
                "analysis": _policy_json(config.analysis),
                "scan": _policy_json(config.scan),
                "agents": _policy_json(config.project.agents),
                "rule_config": _policy_json(config.rules),
                "rules": _policy_json(serialize_effective_rules(effective)),
                "extension_inputs": extension_inputs,
                "rule_sources": {
                    name: hashlib.sha256(
                        files("zscope.rules").joinpath(name).read_bytes()
                    ).hexdigest()
                    for name in ("builtin_catalog.yaml", "qualification_registry.yaml")
                },
            }
        ),
    )


def _native_inputs_current(context: Mapping[str, Any]) -> bool:
    """Recheck emitting bytes and the existing bounded physical-header trust.

    Tool/loader identities are separate from BuildContext.dependencies. Never
    execute a recorded command, query a loader, or cache a previous digest here.
    The accepted S01 verifier remains the sole physical glibc trust policy.
    """
    tool = context.get("tool")
    if not isinstance(tool, Mapping):
        return False
    capability, binary = tool.get("capability"), tool.get("binary")
    if (
        not isinstance(capability, Mapping)
        or capability.get("protocol") != "zscope.clang-facts.v2"
        or capability.get("target_origin_version") != 1
        or not isinstance(binary, Mapping)
        or "unverified_loader_run" in binary
    ):
        return False
    libraries = binary.get("shared_libraries")
    if not isinstance(libraries, dict):
        return False
    # An explicit empty map is the factory's supported static-tool identity;
    # an absent map or an unknown member can never stand in for that receipt.
    identities = [(binary.get("path"), binary.get("sha256")), *libraries.items()]
    for path, digest in identities:
        if (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or not isinstance(digest, str)
            or not _is_sha256_hex(digest)
            or indexing_identity.file_digest(Path(path)) != digest
        ):
            return False
    dependencies = context.get("dependencies")
    if not isinstance(dependencies, Mapping):
        return False
    for header in (_HOST_GLIBC_STDLIB, _HOST_GLIBC_FEATURES):
        if str(header) in dependencies and not _trusted_host_header(header):
            return False
    return True


def exact_inputs_current(
    index: ScopedCodeIndex, scope: InstanceScope, *, expected_receipt: bytes | None = None
) -> bool:
    """Re-read native bytes/trust, CDB, commands, searches and dependencies."""
    try:
        if index.scope != scope:
            return False
        contexts = index.get_build_contexts(scope.source)
        if len(contexts) != 1:
            return False
        if expected_receipt is not None and canonical_bytes(contexts) != expected_receipt:
            return False
        context = contexts[0]
        if (
            context.get("build_context_id") != scope.build_context_id
            or not _native_inputs_current(context)
            or index.dependencies_current_status() != "current"
            or context_input_status(
                context,
                validator=(
                    runtime.validator(context)
                    if isinstance(
                        runtime := getattr(index.base_index(), "_job_runtime_outputs", None),
                        _JobRuntimeOutputs,
                    )
                    and runtime._active
                    else None
                ),
            )
            != "current"
        ):
            return False
        # Read the underlying exact facts again: the facade's navigation probe
        # can be cached and cannot authorize a later consumption by itself.
        facts = index.base_index().get_function_program_facts(
            scope.usr, scope.source, build_context_id=scope.build_context_id
        )
        if not isinstance(facts, dict) or facts.get("complete") is not True:
            return False
        identity = facts.get("function_identity")
        return bool(
            isinstance(identity, dict)
            and facts.get("build_context_id") == scope.build_context_id
            and identity.get("build_context_id") == scope.build_context_id
            and identity.get("usr") == scope.usr
        )
    except Exception:
        # Missing, unreadable or malformed current input is an admission miss,
        # including errors while checking physical paths or namespace probes.
        return False


@dataclass(frozen=True)
class InstanceSemanticsContext:
    config: Any
    code_index: Any
    workbook_path: Path
    workbook: FrozenWorkbookRows
    dependencies: SemanticsDependencies
    native_input_receipts: Mapping[str, bytes]
    scopes: Mapping[str, InstanceScope]
    snapshots: Mapping[str, InstanceSemanticsSnapshot]
    unavailable: Mapping[str, str]

    def is_current(self, snapshot: InstanceSemanticsSnapshot) -> bool:
        """No caller-supplied booleans or old cached dependency success."""
        expected = self.snapshots.get(snapshot.scope.identity)
        if expected is not snapshot:
            return False
        try:
            runtime = (
                self.code_index._job_runtime_outputs
                if isinstance(self.code_index, CodeIndex)
                else None
            )
            fence = (
                runtime.binding()
                if isinstance(runtime, _JobRuntimeOutputs) and runtime._active
                else nullcontext()
            )
            with fence:
                if (
                    isinstance(runtime, _JobRuntimeOutputs)
                    and runtime._active
                    and not runtime.native_current()
                ):
                    return False
                if current_dependencies(self.config) != self.dependencies:
                    return False
                if freeze_workbook(self.workbook_path) != self.workbook:
                    return False
                receipt = self.native_input_receipts.get(snapshot.scope.identity)
                if receipt is None:
                    return False
                scoped = wrap_scoped_code_index(self.code_index, snapshot.scope)
                return exact_inputs_current(scoped, snapshot.scope, expected_receipt=receipt)
        except Exception:
            return False

    def require(self, scope: InstanceScope) -> InstanceSemanticsSnapshot:
        snapshot = self.snapshots.get(scope.identity)
        if snapshot is None:
            raise ValueError(self.unavailable.get(scope.identity, "instance_semantics_missing"))
        if snapshot.scope != scope or not self.is_current(snapshot):
            raise ValueError("instance_semantics_not_current")
        return snapshot

    def manifest_digest(self) -> str:
        return semantics_manifest_digest(self.snapshots)


def freeze_instance_context(
    *, config: Any, code_index: Any, workbook_path: Path, scopes: Sequence[InstanceScope]
) -> InstanceSemanticsContext:
    workbook = freeze_workbook(workbook_path)
    dependencies = current_dependencies(config)
    snapshots: dict[str, InstanceSemanticsSnapshot] = {}
    native_input_receipts: dict[str, bytes] = {}
    unavailable: dict[str, str] = {}
    for scope in scopes:
        if scope.identity in snapshots or scope.identity in unavailable:
            raise ValueError("instance_semantics_duplicate_instance_identity")
        scoped = wrap_scoped_code_index(code_index, scope)
        try:
            # Freeze the complete receipt, including absent/present members and
            # all dependency/tool-library keys. A later same-ID record cannot
            # shed an input that the real factory used to authorize effects.
            receipt = canonical_bytes(scoped.get_build_contexts(scope.source))
            if not exact_inputs_current(scoped, scope, expected_receipt=receipt):
                unavailable[scope.identity] = "instance_semantics_exact_inputs_not_current"
                continue
            value = build_instance_semantics(
                scope=scope, scoped_index=scoped, workbook=workbook, dependencies=dependencies
            )
            if not exact_inputs_current(scoped, scope, expected_receipt=receipt):
                unavailable[scope.identity] = "instance_semantics_exact_inputs_not_current"
                continue
        except Exception:
            unavailable[scope.identity] = "instance_semantics_freeze_unverifiable"
            continue
        if isinstance(value, SemanticsUnavailable):
            unavailable[scope.identity] = value.reason
        else:
            snapshots[scope.identity] = value
            native_input_receipts[scope.identity] = receipt
    context = InstanceSemanticsContext(
        config=config,
        code_index=code_index,
        workbook_path=workbook_path,
        workbook=workbook,
        dependencies=dependencies,
        native_input_receipts=MappingProxyType(native_input_receipts),
        scopes=MappingProxyType({scope.identity: scope for scope in scopes}),
        snapshots=MappingProxyType(snapshots),
        unavailable=MappingProxyType(unavailable),
    )
    # A change during construction is a miss, never a partially frozen batch.
    if freeze_workbook(workbook_path) != workbook or current_dependencies(config) != dependencies:
        raise ValueError("instance_semantics_dependencies_changed_during_freeze")
    if any(
        not exact_inputs_current(
            wrap_scoped_code_index(code_index, snapshot.scope),
            snapshot.scope,
            expected_receipt=native_input_receipts[identity],
        )
        for identity, snapshot in snapshots.items()
    ):
        raise ValueError("instance_semantics_exact_inputs_changed_during_freeze")
    runtime = code_index._job_runtime_outputs if isinstance(code_index, CodeIndex) else None
    if isinstance(runtime, _JobRuntimeOutputs):
        # All original strict raw/S01 checks have finished before the live
        # factory allowance can be activated under the exact owner binding.
        runtime.activate(context)
        if any(not context.is_current(snapshot) for snapshot in snapshots.values()):
            raise ValueError("instance_semantics_runtime_activation_not_current")
    return context
