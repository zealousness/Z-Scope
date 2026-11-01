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
from ..config.project_semantics import (
    ProjectSemanticsStore,
    compiled_project_contracts,
    empty_project_semantics,
    rebind_project_semantics,
)
from ..retrieval import indexing_identity
from ..retrieval.build_context import context_input_status
from ..retrieval.code_index import CodeIndex, _JobRuntimeOutputs
from ..retrieval.instance_index import InstanceScope, ScopedCodeIndex, wrap_scoped_code_index
from ..semantics.instance_semantics import (
    FrozenJSON,
    FrozenWorkbookRows,
    _InstanceInputAdmission,
    _issue_instance_input_admission,
    InstanceSemanticsSnapshot,
    SemanticsDependencies,
    SemanticsUnavailable,
    _HOST_GLIBC_FEATURES,
    _HOST_GLIBC_STDLIB,
    _is_sha256_hex,
    _trusted_host_header,
    authorized_standard_headers_current,
    builtin_semantics_fingerprint,
    build_instance_semantics,
    compose_linked_automatic_templates,
)


SEMANTICS_POLICY = "builtin_current_automatic_native_confirmed_project.v3"


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


def freeze_project_semantics(
    path: Path,
    *,
    allow_unbound_primitive_proposals: bool = False,
) -> FrozenWorkbookRows:
    """Freeze the one YAML authority file without granting pending rows effects."""

    path = Path(path)
    before = path.read_bytes()
    store = ProjectSemanticsStore(path)
    document = store.read(allow_unbound_primitive_proposals=allow_unbound_primitive_proposals)
    after = path.read_bytes()
    if before != after:
        raise ValueError("instance_semantics_project_file_changed_during_freeze")
    confirmed = [dict(row) for row in document["interfaces"] if row.get("status") == "confirmed"]
    pairs = store.list_paired_functions(
        allow_unbound_primitive_proposals=allow_unbound_primitive_proposals
    )
    other = [
        *({"sheet": "dispatcher", **dict(row)} for row in document["dispatchers"]),
        *(
            {"sheet": "pointer_targets", **dict(row)}
            for row in document["function_pointer_bindings"]
        ),
    ]
    return FrozenWorkbookRows(
        workbook_sha256=hashlib.sha256(before).hexdigest(),
        external_rows=tuple(FrozenJSON(canonical_bytes(row)) for row in confirmed),
        paired_rows=tuple(FrozenJSON(canonical_bytes(row)) for row in pairs),
        other_advisory_rows=tuple(FrozenJSON(canonical_bytes(row)) for row in other),
        project_document=FrozenJSON(canonical_bytes(document)),
    )


def _freeze_authority(
    path: Path,
    *,
    allow_unbound_primitive_proposals: bool = False,
) -> FrozenWorkbookRows:
    # Compatibility for historical unit fixtures and the explicit migration
    # reader only.  Product scan callers pass ``semantics_path`` and therefore
    # never execute workbook-backed semantics.
    return (
        freeze_workbook(path)
        if path.suffix.lower() == ".xlsx"
        else freeze_project_semantics(
            path,
            allow_unbound_primitive_proposals=allow_unbound_primitive_proposals,
        )
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
                        "c_linux_catalog.py",
                        "posix_issue8_manifest.py",
                        "standard_api.py",
                        "defaults.py",
                        "instance_semantics.py",
                        "automatic.py",
                        "native_wrappers.py",
                        "contract_compiler.py",
                        "contract_review.py",
                        "contract_conditions.py",
                        "build_scope.py",
                        "call_context.py",
                    )
                },
                "instance_execution_sources": {
                    name: hashlib.sha256(files("zscope").joinpath(name).read_bytes()).hexdigest()
                    for name in (
                        "core/analysis/analyzer.py",
                        "core/validation/runner.py",
                        "core/validation/claims.py",
                        "core/validation/pipeline.py",
                        "agents/validator_agent/agent.py",
                        "rules/validation_obligations.py",
                        "orchestration/hierarchical_discovery.py",
                        "core/candidates/pipeline.py",
                        "core/candidates/regex.py",
                        "core/candidates/graph.py",
                        "core/candidates/clang_ast_cfg.py",
                        "core/candidates/function_facts.py",
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
                        "semantics/c_linux_catalog.py",
                        "semantics/posix_issue8_manifest.py",
                        "semantics/defaults.py",
                        "semantics/standard_api.py",
                        "config/project_semantics.py",
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


def _batch_input_admissions(
    code_index: Any, scopes: Sequence[InstanceScope]
) -> tuple[dict[str, _InstanceInputAdmission], dict[str, str]]:
    runtime = code_index._job_runtime_outputs if isinstance(code_index, CodeIndex) else None
    active = runtime if isinstance(runtime, _JobRuntimeOutputs) and runtime._active else None
    # A fresh validation snapshot must use the same bound output namespace as
    # require_current(). Ordinary directory census would mistake this job's
    # newly registered queue/checkpoint files for changed compiler inputs.
    with active.binding() if active is not None else nullcontext():
        return _batch_input_admissions_bound(code_index, scopes, active)


def _batch_input_admissions_bound(
    code_index: Any, scopes: Sequence[InstanceScope], runtime: _JobRuntimeOutputs | None
) -> tuple[dict[str, _InstanceInputAdmission], dict[str, str]]:
    """Validate shared build inputs once and exact function identities once.

    A fresh invocation is one admission boundary.  Callers run it before and
    after snapshot construction; no result is persisted or reused across
    boundaries.
    """

    admissions: dict[str, _InstanceInputAdmission] = {}
    failures: dict[str, str] = {}
    if runtime is not None and not runtime.native_current():
        return {}, {scope.identity: "native_inputs_not_current" for scope in scopes}
    try:
        contexts = {
            str(row.get("build_context_id") or ""): dict(row)
            for row in code_index.get_build_contexts()
            if isinstance(row, Mapping) and str(row.get("build_context_id") or "")
        }
    except Exception:
        return {}, {scope.identity: "build_context_inventory_unavailable" for scope in scopes}

    validators: dict[str, indexing_identity.InputValidator] = {}
    build_status: dict[str, str] = {}
    native_status: dict[str, bool] = {}
    tool_status: dict[str, bool] = {}
    for build in sorted({scope.build_context_id for scope in scopes if scope.build_context_id}):
        context = contexts.get(build)
        if context is None:
            build_status[build] = "unknown_build_context"
            continue
        excluded = context.get("search_excludes", [])
        validator_key = indexing_identity.digest_json(excluded)
        validator = (
            runtime.validator(context)
            if runtime is not None
            else validators.setdefault(
                validator_key,
                indexing_identity.InputValidator(Path(path) for path in excluded),
            )
        )
        build_status[build] = context_input_status(context, validator=validator)
        tool_key = indexing_identity.digest_json(context.get("tool") or {})
        if tool_key not in tool_status:
            tool_status[tool_key] = _native_inputs_current(context)
        native_status[build] = tool_status[tool_key]

    for scope in scopes:
        context = contexts.get(scope.build_context_id)
        status = build_status.get(scope.build_context_id, "unknown_build_context")
        if context is None or status != "current":
            failures[scope.identity] = f"context_inputs_not_current:{status}"
            continue
        if not native_status.get(scope.build_context_id, False):
            failures[scope.identity] = "native_inputs_not_current"
            continue
        try:
            facts = code_index.get_function_program_facts(
                scope.usr,
                scope.source,
                build_context_id=scope.build_context_id,
            )
        except Exception:
            failures[scope.identity] = "entry_program_facts_unavailable"
            continue
        identity = facts.get("function_identity") if isinstance(facts, Mapping) else None
        if not (
            isinstance(facts, Mapping)
            and facts.get("complete") is True
            and facts.get("build_context_id") == scope.build_context_id
            and isinstance(identity, Mapping)
            and identity.get("build_context_id") == scope.build_context_id
            and identity.get("usr") == scope.usr
        ):
            failures[scope.identity] = "entry_identity_unverified"
            continue
        admissions[scope.identity] = _issue_instance_input_admission(
            scope=scope,
            context=context,
            program_facts=facts,
        )
    return admissions, failures


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
    effective_project_document: FrozenJSON
    project_semantics_rebind: Mapping[str, Any]

    def snapshot(self, scope: InstanceScope) -> InstanceSemanticsSnapshot:
        """Return the frozen value after an enclosing batch currentness gate.

        This performs identity checks only.  Filesystem/native currency is
        deliberately handled by :meth:`require_all` at batch boundaries so a
        300-function project does not re-walk the same include namespace for
        every function and every semantic lookup.
        """

        snapshot = self.snapshots.get(scope.identity)
        if snapshot is None:
            raise ValueError(self.unavailable.get(scope.identity, "instance_semantics_missing"))
        if snapshot.scope != scope:
            raise ValueError("instance_semantics_scope_changed")
        return snapshot

    def is_frozen(self, snapshot: InstanceSemanticsSnapshot) -> bool:
        return self.snapshots.get(snapshot.scope.identity) is snapshot

    def _link_ids(self) -> set[str]:
        return {
            str(link_id)
            for contract in self.project_semantics_rebind.get("contracts", []) or []
            if isinstance(contract, Mapping)
            for link_id in contract.get("link_target_ids", []) or []
            if str(link_id)
        } | {
            str(link_id)
            for snapshot in self.snapshots.values()
            for link_id in json.loads(bytes(snapshot.effect_payload))
            .get("automatic_derivation", {})
            .get("link_target_ids", [])
        }

    def _links_current(self) -> bool:
        link_ids = self._link_ids()
        if not link_ids:
            return True
        linked_factory = getattr(self.code_index, "linked_targets", None)
        linked = linked_factory() if callable(linked_factory) else None
        current_links = getattr(linked, "current_many", None)
        if callable(current_links):
            return bool(current_links(sorted(link_ids)))
        current_link = getattr(linked, "current", None)
        return bool(
            callable(current_link) and all(current_link(link_id) for link_id in sorted(link_ids))
        )

    def is_current(self, snapshot: InstanceSemanticsSnapshot) -> bool:
        """No caller-supplied booleans or old cached dependency success."""
        expected = self.snapshots.get(snapshot.scope.identity)
        if expected is not snapshot:
            return False
        try:
            # Imported effects depend on definition builds as well as the
            # caller. Recheck the whole frozen batch, including native tools
            # and authorized system declarations in those producer builds.
            if self._link_ids():
                self.require_all()
                return True
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
                if _freeze_authority(self.workbook_path) != self.workbook:
                    return False
                if not self._links_current():
                    return False
                receipt = self.native_input_receipts.get(snapshot.scope.identity)
                if receipt is None:
                    return False
                scoped = wrap_scoped_code_index(self.code_index, snapshot.scope)
                return bool(
                    exact_inputs_current(scoped, snapshot.scope, expected_receipt=receipt)
                    and authorized_standard_headers_current(snapshot)
                )
        except Exception:
            return False

    def require_all(self) -> None:
        """Revalidate one frozen manifest with shared per-batch input caches.

        Common policy, YAML and link inputs are checked once.  Build input
        validators are shared for contexts with the same search exclusions;
        each function still re-reads its exact current native fact identity.
        A later publication boundary calls this method again with fresh
        validators, so edits during analysis fail closed.
        """

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
                    raise ValueError("instance_semantics_native_membership_changed")
                if current_dependencies(self.config) != self.dependencies:
                    raise ValueError("instance_semantics_dependencies_changed")
                if _freeze_authority(self.workbook_path) != self.workbook:
                    raise ValueError("instance_semantics_project_file_changed")
                if not self._links_current():
                    raise ValueError("instance_semantics_link_inputs_changed")

                contexts = {
                    str(row.get("build_context_id") or ""): row
                    for row in self.code_index.get_build_contexts()
                    if isinstance(row, Mapping) and str(row.get("build_context_id") or "")
                }
                validators: dict[str, indexing_identity.InputValidator] = {}
                context_statuses: dict[str, str] = {}
                native_statuses: dict[str, bool] = {}
                header_statuses: dict[bytes, bool] = {}
                for snapshot in self.snapshots.values():
                    if not self.is_frozen(snapshot):
                        raise ValueError("instance_semantics_snapshot_replaced")
                    scope = snapshot.scope
                    context = contexts.get(scope.build_context_id)
                    receipt = self.native_input_receipts.get(scope.identity)
                    if context is None or receipt != canonical_bytes([context]):
                        raise ValueError("instance_semantics_native_receipt_changed")

                    build = scope.build_context_id
                    if build not in native_statuses:
                        native_statuses[build] = _native_inputs_current(context)
                    if not native_statuses[build]:
                        raise ValueError("instance_semantics_native_tool_changed")

                    if build not in context_statuses:
                        if isinstance(runtime, _JobRuntimeOutputs) and runtime._active:
                            validator = runtime.validator(context)
                        else:
                            excluded = context.get("search_excludes", [])
                            validator_key = indexing_identity.digest_json(excluded)
                            validator = validators.setdefault(
                                validator_key,
                                indexing_identity.InputValidator(Path(path) for path in excluded),
                            )
                        context_statuses[build] = context_input_status(context, validator=validator)
                    if context_statuses[build] != "current":
                        raise ValueError("instance_semantics_build_context_changed")

                    facts = self.code_index.get_function_program_facts(
                        scope.usr,
                        scope.source,
                        build_context_id=scope.build_context_id,
                    )
                    identity = facts.get("function_identity") if isinstance(facts, dict) else None
                    if not (
                        isinstance(facts, dict)
                        and facts.get("complete") is True
                        and facts.get("build_context_id") == scope.build_context_id
                        and isinstance(identity, dict)
                        and identity.get("build_context_id") == scope.build_context_id
                        and identity.get("usr") == scope.usr
                    ):
                        raise ValueError("instance_semantics_function_identity_changed")

                    header_key = bytes(snapshot.effect_payload)
                    if header_key not in header_statuses:
                        header_statuses[header_key] = authorized_standard_headers_current(snapshot)
                    if not header_statuses[header_key]:
                        raise ValueError("instance_semantics_standard_headers_changed")
        except Exception as exc:
            if isinstance(exc, ValueError) and str(exc) == "instance_semantics_not_current":
                raise
            raise ValueError("instance_semantics_not_current") from exc

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
    *,
    config: Any,
    code_index: Any,
    workbook_path: Path | None = None,
    semantics_path: Path | None = None,
    scopes: Sequence[InstanceScope],
    allow_unbound_primitive_proposals: bool = False,
) -> InstanceSemanticsContext:
    raw_authority_path = semantics_path or workbook_path
    if raw_authority_path is None:
        raise ValueError("instance_semantics_project_file_missing")
    authority_path = Path(raw_authority_path)
    workbook = _freeze_authority(
        authority_path,
        allow_unbound_primitive_proposals=allow_unbound_primitive_proposals,
    )
    dependencies = current_dependencies(config)
    original_project_document = json.loads(bytes(workbook.project_document))
    # Historical unit fixtures still exercise the explicitly non-product XLSX
    # compatibility reader.  They have no project-semantics authority at all,
    # so represent that absence with the strict empty v1 document before the
    # common rebind path.  Product scan callers always pass ``semantics_path``
    # and cannot use this compatibility branch.
    if authority_path.suffix.lower() == ".xlsx" and not original_project_document:
        original_project_document = empty_project_semantics()
    effective_project_document, project_rebind = rebind_project_semantics(
        original_project_document,
        project_root=Path(config.project.project_root),
        target_id=str(getattr(config.project, "target_id", "") or ""),
        code_index=code_index,
        allow_unbound_primitive_proposals=allow_unbound_primitive_proposals,
    )
    # Rebind is deliberately capable of producing a safe partial registry.
    # A missing observed link record revokes contracts for the unclosed caller
    # BuildContexts while retaining exact same-TU/current-link variants.  The
    # audit remains ``ready=false`` (and therefore blocks formal qualification),
    # but it must not invalidate builtin semantics or every local analysis
    # unit in the scan.
    contracts_by_build = {
        build: compiled_project_contracts(
            effective_project_document,
            build_context_id=build,
        )
        for build in {str(scope.build_context_id) for scope in scopes if scope.build_context_id}
    }
    snapshots: dict[str, InstanceSemanticsSnapshot] = {}
    native_input_receipts: dict[str, bytes] = {}
    unavailable: dict[str, str] = {}
    admissions, admission_failures = _batch_input_admissions(code_index, scopes)
    templates_by_build: dict[str, InstanceSemanticsSnapshot] = {}
    for scope in scopes:
        if scope.identity in snapshots or scope.identity in unavailable:
            raise ValueError("instance_semantics_duplicate_instance_identity")
        scoped = wrap_scoped_code_index(code_index, scope)
        admission = admissions.get(scope.identity)
        if admission is None:
            unavailable[scope.identity] = admission_failures.get(
                scope.identity, "instance_semantics_exact_inputs_not_current"
            )
            continue
        try:
            value = build_instance_semantics(
                scope=scope,
                scoped_index=scoped,
                workbook=workbook,
                dependencies=dependencies,
                project_contracts_override=contracts_by_build.get(scope.build_context_id, []),
                _input_admission=admission,
                _build_template=templates_by_build.get(scope.build_context_id),
            )
        except Exception:
            unavailable[scope.identity] = "instance_semantics_freeze_unverifiable"
            continue
        if isinstance(value, SemanticsUnavailable):
            unavailable[scope.identity] = value.reason
        else:
            snapshots[scope.identity] = value
            native_input_receipts[scope.identity] = bytes(admission.context_receipt)
            templates_by_build.setdefault(scope.build_context_id, value)
    snapshots = compose_linked_automatic_templates(snapshots, code_index)
    context = InstanceSemanticsContext(
        config=config,
        code_index=code_index,
        workbook_path=authority_path,
        workbook=workbook,
        dependencies=dependencies,
        native_input_receipts=MappingProxyType(native_input_receipts),
        scopes=MappingProxyType({scope.identity: scope for scope in scopes}),
        snapshots=MappingProxyType(snapshots),
        unavailable=MappingProxyType(unavailable),
        effective_project_document=FrozenJSON(canonical_bytes(effective_project_document)),
        project_semantics_rebind=MappingProxyType(project_rebind),
    )
    # A change during construction is a miss, never a partially frozen batch.
    if (
        _freeze_authority(
            authority_path,
            allow_unbound_primitive_proposals=allow_unbound_primitive_proposals,
        )
        != workbook
        or current_dependencies(config) != dependencies
    ):
        raise ValueError("instance_semantics_dependencies_changed_during_freeze")
    post_admissions, post_failures = _batch_input_admissions(
        code_index, [snapshot.scope for snapshot in snapshots.values()]
    )
    if post_failures or any(
        identity not in post_admissions
        or bytes(post_admissions[identity].context_receipt) != native_input_receipts[identity]
        or bytes(post_admissions[identity].program_facts)
        != bytes(admissions[identity].program_facts)
        for identity in snapshots
    ):
        raise ValueError("instance_semantics_exact_inputs_changed_during_freeze")
    runtime = code_index._job_runtime_outputs if isinstance(code_index, CodeIndex) else None
    if isinstance(runtime, _JobRuntimeOutputs):
        # All original strict raw/S01 checks have finished before the live
        # factory allowance can be activated under the exact owner binding.
        runtime.activate(context)
        try:
            context.require_all()
        except ValueError:
            raise ValueError("instance_semantics_runtime_activation_not_current")
    return context
