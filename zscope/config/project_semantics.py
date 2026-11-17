"""One authoritative, reviewable C/C++ project-semantics document.

The YAML file is deliberately separate from analyzer-written state.  Only a
human-confirmed row can become executable semantics; discovery can add or
refresh pending rows, but it cannot publish them.  Raw native and model
evidence is referenced from the document and lives below the snapshot tree.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

import yaml

from .support import load_yaml_unique
from ..semantics.contract_conditions import predicate_errors
from ..semantics.contracts import CONTRACT_COMPILER_VERSION


SCHEMA_VERSION = "zscope.project-semantics.v1"
DISCOVERY_SCHEMA = "zscope.primitive-discovery.v1"
STATUS_VALUES = frozenset({"pending", "confirmed", "rejected", "stale"})
BASIS_VALUES = frozenset({"external_model", "expected_contract", "derived_wrapper"})
SELECTOR_KINDS = frozenset({"function", "macro", "function_pointer_slot"})
EFFECT_DOMAINS = frozenset(
    {
        "resource",
        "lock",
        "taint",
        "copy",
        "callback",
        "process",
        "handle",
        "protocol",
    }
)
EXECUTABLE_ROLES = frozenset(
    {
        "allocator",
        "calloc",
        "reallocator",
        "deallocator",
        "lock",
        "unlock",
        "copy",
        "io_acquire",
        "io_release",
        "send_sink",
        "recv_source",
        "format_sink",
        "command_sink",
        "callback_register",
        "ownership_transfer",
        "reference_retention",
        "lock_init",
        "lock_destroy",
        "lock_state",
        "lock_wait",
        "condition_init",
        "condition_destroy",
        "condition_signal",
        "thread_create",
        "thread_release",
        "standard_operation",
    }
)
# Every executable role must name the concrete rule-side adapter that consumes
# it.  This table is part of schema validation and reporting: adding a role to
# the YAML format without implementing its static consumer is forbidden.
EFFECT_CONSUMERS: Mapping[str, tuple[str, ...]] = {
    "allocator": ("resource_lifecycle", "lifecycle_paths", "clang_ast_cfg"),
    "calloc": ("resource_lifecycle", "lifecycle_paths", "clang_ast_cfg"),
    "reallocator": ("resource_lifecycle", "lifecycle_paths", "clang_ast_cfg"),
    "deallocator": ("resource_lifecycle", "lifecycle_paths", "clang_ast_cfg"),
    "lock": ("shared_access", "concurrency_shared_state", "clang_ast_cfg"),
    "unlock": ("shared_access", "concurrency_shared_state", "clang_ast_cfg"),
    "copy": ("memory_bounds_integer", "clang_ast_cfg"),
    "io_acquire": ("resource_lifecycle", "typed_resources", "clang_ast_cfg"),
    "io_release": ("resource_lifecycle", "typed_resources", "clang_ast_cfg"),
    "send_sink": ("protocol_ownership_logic", "clang_ast_cfg"),
    "recv_source": ("protocol_ownership_logic", "configured_data_flow"),
    "format_sink": ("protocol_ownership_logic", "clang_ast_cfg"),
    "command_sink": ("protocol_ownership_logic", "semantic_cpg_rules"),
    "callback_register": ("protocol_ownership_logic", "async_paths"),
    "ownership_transfer": ("resource_lifecycle", "protocol_ownership_logic"),
    "reference_retention": ("retained_slots", "protocol_ownership_logic"),
    "lock_init": ("shared_access",),
    "lock_destroy": ("shared_access",),
    "lock_state": ("shared_access",),
    "lock_wait": ("shared_access", "async_wait"),
    "condition_init": ("shared_access", "async_wait"),
    "condition_destroy": ("shared_access", "async_wait"),
    "condition_signal": ("shared_access", "async_wake"),
    "thread_create": ("async_paths",),
    "thread_release": ("async_paths",),
    "standard_operation": ("protocol_ownership_logic",),
}
TOP_LEVEL_KEYS = (
    "schema_version",
    "interfaces",
    "dispatchers",
    "function_pointer_bindings",
    "discovery_receipt",
)
_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


class ProjectSemanticsError(ValueError):
    """The project semantics document is malformed or not ready."""


@dataclass(frozen=True)
class SemanticsReadiness:
    ready: bool
    pending: tuple[str, ...]
    stale: tuple[str, ...]
    unresolved: tuple[str, ...]
    conflicts: tuple[str, ...]
    unsupported: tuple[str, ...]
    source_mismatches: tuple[str, ...]
    confirmed: int
    rejected: int
    primitives: int
    derived: int
    digest: str

    @property
    def reasons(self) -> tuple[str, ...]:
        values: list[str] = []
        for label, members in (
            ("pending", self.pending),
            ("stale", self.stale),
            ("unresolved", self.unresolved),
            ("conflict", self.conflicts),
            ("unsupported", self.unsupported),
            ("source_mismatch", self.source_mismatches),
        ):
            values.extend(f"{label}:{member}" for member in members)
        return tuple(values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "zscope.project-semantics-readiness.v1",
            "ready": self.ready,
            "pending": list(self.pending),
            "stale": list(self.stale),
            "unresolved": list(self.unresolved),
            "conflicts": list(self.conflicts),
            "unsupported": list(self.unsupported),
            "source_mismatches": list(self.source_mismatches),
            "confirmed": self.confirmed,
            "rejected": self.rejected,
            "primitives": self.primitives,
            "derived": self.derived,
            "digest": self.digest,
            "reasons": list(self.reasons),
        }


def empty_project_semantics() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "interfaces": [],
        "dispatchers": [],
        "function_pointer_bindings": [],
        "discovery_receipt": {},
    }


def render_empty_project_semantics() -> str:
    return """# Z-SCOPE project primitives and reviewed derived interfaces.
# 1. Add known project primitives with primitive: true and status: pending.
#    Or explicitly declare none: zscope-config review-semantics --config zscope.yaml --declare-none
# 2. Run: zscope -c zscope.yaml --discover-primitives
# 3. Review every pending/stale row and set it to confirmed or rejected.
# 4. Validate and complete: zscope-config review-semantics --config zscope.yaml --complete
schema_version: zscope.project-semantics.v1
interfaces: []
dispatchers: []
function_pointer_bindings: []
discovery_receipt: {}
"""


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
        ).encode("utf-8")
    ).hexdigest()


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def stable_interface_id(kind: str, name: str, file_path: str = "", usr: str = "") -> str:
    readable = re.sub(r"[^A-Za-z0-9_.:-]+", "-", f"{kind}:{name}").strip("-")
    suffix = canonical_digest([kind, name, file_path.replace("\\", "/"), usr])[:12]
    return f"project:{readable[:120]}:{suffix}"


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProjectSemanticsError(f"{context} must be a mapping")
    return value


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProjectSemanticsError(f"{context} must be a list")
    return value


def _nonempty(value: Any, context: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ProjectSemanticsError(f"{context} must be nonempty")
    return text


def _validate_object_path(value: Any, context: str) -> None:
    path = _mapping(value, context)
    root = str(path.get("root") or "")
    if root not in {"return", "argument", "global"}:
        raise ProjectSemanticsError(f"{context}.root must be return, argument, or global")
    phase = str(path.get("phase") or "post")
    if phase not in {"pre", "post"}:
        raise ProjectSemanticsError(f"{context}.phase must be pre or post")
    dereference = path.get("dereference", 0)
    if type(dereference) is not int or dereference < 0:
        raise ProjectSemanticsError(f"{context}.dereference must be a nonnegative integer")
    members = path.get("members", [])
    if not isinstance(members, list) or not all(isinstance(item, str) and item for item in members):
        raise ProjectSemanticsError(f"{context}.members must be a list of names")
    if root == "argument" and (type(path.get("index")) is not int or path["index"] < 0):
        raise ProjectSemanticsError(f"{context}.index is required for an argument path")
    if root == "global" and not str(path.get("name") or "").strip():
        raise ProjectSemanticsError(f"{context}.name is required for a global path")


def _validate_variants(value: Any, context: str) -> list[Mapping[str, Any]]:
    variants = _list(value, context)
    seen: dict[str, str] = {}
    result: list[Mapping[str, Any]] = []
    for index, raw in enumerate(variants):
        variant = _mapping(raw, f"{context}[{index}]")
        build = _nonempty(variant.get("build_context_id"), f"{context}[{index}].build_context_id")
        usr = _nonempty(variant.get("usr"), f"{context}[{index}].usr")
        if variant.get("identity_status", "exact") != "exact":
            raise ProjectSemanticsError(f"{context}[{index}].identity_status must be exact")
        previous = seen.setdefault(build, usr)
        if previous != usr:
            raise ProjectSemanticsError(f"{context} has conflicting identities for {build}")
        for key in ("source_sha256", "evidence_sha256", "native_input_hash"):
            digest = str(variant.get(key) or "")
            if digest and not _SHA256_RE.fullmatch(digest):
                raise ProjectSemanticsError(f"{context}[{index}].{key} must be SHA-256")
        result.append(variant)
    return result


def _potentially_executable(predicate: Any) -> bool:
    """Unknown/false conditions do not authorize a confirmed applies branch."""
    from ..semantics.contract_conditions import evaluate

    if not isinstance(predicate, Mapping) or predicate.get("op") in {"false", "unknown"}:
        return False
    if predicate.get("op") == "all":
        return all(_potentially_executable(item) for item in predicate.get("items", []))
    if predicate.get("op") == "any":
        return any(_potentially_executable(item) for item in predicate.get("items", []))
    if predicate.get("op") == "not" and predicate.get("item", {}).get("op") == "unknown":
        return False
    return evaluate(dict(predicate)) != "does_not_apply"


def validate_project_semantics(
    document: Any, *, allow_unbound_primitive_proposals: bool = False
) -> dict[str, Any]:
    data = dict(_mapping(document, "project semantics"))
    unknown = sorted(set(data) - set(TOP_LEVEL_KEYS) - {"lifecycle"})
    if unknown:
        raise ProjectSemanticsError("project semantics has unknown keys: " + ", ".join(unknown))
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ProjectSemanticsError(f"schema_version must be {SCHEMA_VERSION}")
    if "lifecycle" in data:
        from ..orchestration.hierarchical_discovery import validate_lifecycle

        try:
            data["lifecycle"] = validate_lifecycle(data["lifecycle"])
        except ValueError as exc:
            raise ProjectSemanticsError(str(exc)) from exc
    for key in TOP_LEVEL_KEYS[1:]:
        if key not in data:
            raise ProjectSemanticsError(f"project semantics is missing {key}")
    interfaces = _list(data["interfaces"], "interfaces")
    known_ids: set[str] = set()
    for index, raw in enumerate(interfaces):
        path = f"interfaces[{index}]"
        row = _mapping(raw, path)
        identifier = _nonempty(row.get("id"), f"{path}.id")
        if not _ID_RE.fullmatch(identifier):
            raise ProjectSemanticsError(f"{path}.id is not a stable identifier")
        if identifier in known_ids:
            raise ProjectSemanticsError(f"duplicate interface id: {identifier}")
        known_ids.add(identifier)
        if type(row.get("primitive")) is not bool:
            raise ProjectSemanticsError(f"{path}.primitive must be boolean")
        status = str(row.get("status") or "")
        if status not in STATUS_VALUES:
            raise ProjectSemanticsError(
                f"{path}.status must be pending, confirmed, rejected, or stale"
            )
        basis = str(row.get("basis") or "")
        if basis not in BASIS_VALUES:
            raise ProjectSemanticsError(f"{path}.basis is invalid")
        selector = _mapping(row.get("selector"), f"{path}.selector")
        if selector.get("kind") not in SELECTOR_KINDS:
            raise ProjectSemanticsError(f"{path}.selector.kind is invalid")
        _nonempty(selector.get("name"), f"{path}.selector.name")
        cases = _list(row.get("cases"), f"{path}.cases")
        effects = _list(row.get("effects"), f"{path}.effects")
        if status == "confirmed" and not effects:
            raise ProjectSemanticsError(f"{path} confirmed interface requires effects")
        if row.get("otherwise") != "unknown":
            raise ProjectSemanticsError(f"{path}.otherwise must be unknown")
        for case_index, case_raw in enumerate(cases):
            case = _mapping(case_raw, f"{path}.cases[{case_index}]")
            if case.get("effect") not in {"applies", "no_effect", "unknown"}:
                raise ProjectSemanticsError(f"{path}.cases[{case_index}].effect is invalid")
            if not isinstance(case.get("when"), Mapping):
                raise ProjectSemanticsError(f"{path}.cases[{case_index}].when must be a predicate")
            errors = predicate_errors(case.get("when"))
            if errors:
                raise ProjectSemanticsError(
                    f"{path}.cases[{case_index}].when is invalid: {', '.join(errors)}"
                )
        if status == "confirmed" and not any(
            isinstance(case, Mapping) and case.get("effect") == "applies"
            and _potentially_executable(case.get("when")) for case in cases
        ):
            raise ProjectSemanticsError(
                f"{path} confirmed interface needs at least one applies case"
            )
        for effect_index, effect_raw in enumerate(effects):
            effect = _mapping(effect_raw, f"{path}.effects[{effect_index}]")
            if effect.get("domain") not in EFFECT_DOMAINS:
                raise ProjectSemanticsError(f"{path}.effects[{effect_index}].domain is invalid")
            role = str(effect.get("role") or "")
            if role not in EXECUTABLE_ROLES:
                raise ProjectSemanticsError(f"{path}.effects[{effect_index}].role is unsupported")
            if not EFFECT_CONSUMERS.get(role):
                raise ProjectSemanticsError(
                    f"{path}.effects[{effect_index}].role has no static rule adapter"
                )
            _validate_object_path(effect.get("carrier"), f"{path}.effects[{effect_index}].carrier")
            if effect.get("strength", "must_under_guard") not in {"must_under_guard", "may"}:
                raise ProjectSemanticsError(f"{path}.effects[{effect_index}].strength is invalid")
            preconditions = effect.get("preconditions")
            if preconditions is not None:
                errors = predicate_errors(preconditions)
                if errors:
                    raise ProjectSemanticsError(
                        f"{path}.effects[{effect_index}].preconditions is invalid: "
                        + ", ".join(errors)
                    )
        pairs = row.get("pairs", [])
        if not isinstance(pairs, list) or not all(isinstance(item, str) and item for item in pairs):
            raise ProjectSemanticsError(f"{path}.pairs must contain stable interface ids")
        variants = _validate_variants(row.get("variants", []), f"{path}.variants")
        if status == "confirmed":
            selector_exact = bool(
                selector.get("usr")
                and selector.get("signature")
                and selector.get("build_context_id")
            )
            discovery_proposal = bool(
                allow_unbound_primitive_proposals
                and row.get("primitive") is True
                and basis == "expected_contract"
                and selector.get("kind") == "function"
                and selector.get("file")
                and selector.get("usr")
                and selector.get("signature")
            )
            if (
                not variants
                and not (basis == "external_model" and selector_exact)
                and not discovery_proposal
            ):
                raise ProjectSemanticsError(
                    f"{path} confirmed interface needs an exact native variant or exact external selector"
                )

    for collection in ("dispatchers", "function_pointer_bindings"):
        rows = _list(data[collection], collection)
        collection_ids: set[str] = set()
        for index, raw in enumerate(rows):
            row = _mapping(raw, f"{collection}[{index}]")
            identifier = _nonempty(row.get("id"), f"{collection}[{index}].id")
            if identifier in collection_ids:
                raise ProjectSemanticsError(f"duplicate {collection} id: {identifier}")
            collection_ids.add(identifier)
            if row.get("status") not in STATUS_VALUES:
                raise ProjectSemanticsError(f"{collection}[{index}].status is invalid")
            if row.get("status") == "confirmed":
                for required in (
                    ("dispatcher", "build_context_id", "usr", "handler_usr", "guard")
                    if collection == "dispatchers"
                    else (
                        "callsite_id",
                        "build_context_id",
                        "slot_usr",
                        "target_usrs",
                        "attribution",
                    )
                ):
                    if required not in row or row.get(required) in (None, "", []):
                        raise ProjectSemanticsError(
                            f"{collection}[{index}] confirmed row is missing {required}"
                        )
                if collection == "function_pointer_bindings" and row.get("attribution") != "exact":
                    raise ProjectSemanticsError(
                        f"{collection}[{index}] confirmed attribution must be exact"
                    )
    for index, row in enumerate(interfaces):
        for pair in row.get("pairs", []) or []:
            if str(pair).startswith("builtin:"):
                continue
            if str(pair) not in known_ids:
                raise ProjectSemanticsError(
                    f"interfaces[{index}].pairs references unknown interface {pair!r}"
                )
    _mapping(data["discovery_receipt"], "discovery_receipt")
    return data


def load_project_semantics(
    path: Path, *, allow_unbound_primitive_proposals: bool = False
) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise ProjectSemanticsError(
            f"project semantics file is missing: {path}; create it or run zscope-config migrate-semantics"
        )
    try:
        raw = load_yaml_unique(path)
    except Exception as exc:
        raise ProjectSemanticsError(str(exc)) from exc
    return validate_project_semantics(
        raw,
        allow_unbound_primitive_proposals=allow_unbound_primitive_proposals,
    )


def _yaml_round_trip_dump(path: Path, document: Mapping[str, Any]) -> None:
    """Write atomically with a comment-preserving YAML implementation.

    ``ruamel.yaml`` is a product dependency rather than an optional best-effort
    path: silently losing a reviewer's comments while refreshing candidates is
    a data-loss bug.  The explicit error also keeps source checkouts that have
    not refreshed their dependencies from rewriting the authority file.
    """

    try:
        from ruamel.yaml import YAML  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - packaging supplies it
        raise ProjectSemanticsError(
            "comment-preserving YAML support is unavailable; reinstall Z-SCOPE dependencies"
        ) from exc
    yaml_rt = YAML()
    yaml_rt.preserve_quotes = True
    yaml_rt.default_flow_style = False
    yaml_rt.width = 110
    existing: MutableMapping[str, Any]
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml_rt.load(handle)
        existing = loaded if isinstance(loaded, MutableMapping) else {}
        existing["schema_version"] = document["schema_version"]
        if "lifecycle" in document:
            existing["lifecycle"] = deepcopy(document["lifecycle"])
        else:
            existing.pop("lifecycle", None)
        for collection in ("interfaces", "dispatchers", "function_pointer_bindings"):
            current_rows = existing.get(collection)
            if not isinstance(current_rows, list):
                existing[collection] = deepcopy(document[collection])
                continue
            by_id = {
                str(row.get("id") or ""): row
                for row in current_rows
                if isinstance(row, MutableMapping) and row.get("id")
            }
            ordered = []
            for raw in document[collection]:
                identifier = str(raw.get("id") or "")
                target = by_id.get(identifier)
                if target is None:
                    ordered.append(deepcopy(raw))
                    continue
                for old_key in list(target):
                    if old_key not in raw:
                        target.pop(old_key, None)
                for new_key, new_value in raw.items():
                    target[new_key] = deepcopy(new_value)
                ordered.append(target)
            current_rows[:] = ordered
        receipt = existing.get("discovery_receipt")
        if isinstance(receipt, MutableMapping):
            receipt.clear()
            receipt.update(deepcopy(document["discovery_receipt"]))
        else:
            existing["discovery_receipt"] = deepcopy(document["discovery_receipt"])
    else:
        existing = deepcopy(dict(document))
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            yaml_rt.dump(existing, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _selected_variants(row: Mapping[str, Any], build_context_id: str) -> list[Mapping[str, Any]]:
    return [
        variant
        for variant in row.get("variants", []) or []
        if isinstance(variant, Mapping)
        and str(variant.get("build_context_id") or "") == build_context_id
    ]


def _source_mismatch(row: Mapping[str, Any], project_root: Path) -> bool:
    if row.get("basis") == "external_model":
        return False
    for variant in row.get("variants", []) or []:
        if not isinstance(variant, Mapping):
            continue
        raw_file = str(variant.get("file") or row.get("selector", {}).get("file") or "")
        expected = str(variant.get("source_sha256") or "")
        if not raw_file or not expected:
            return True
        path = Path(raw_file)
        if not path.is_absolute():
            path = project_root / path
        try:
            if not path.is_file() or file_sha256(path) != expected:
                return True
        except OSError:
            return True
    return False


def _project_relative(project_root: Path, raw: str) -> str:
    path = Path(str(raw or ""))
    if not path.is_absolute():
        path = project_root / path
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except (OSError, ValueError):
        return ""


def _fact_symbol(row: Mapping[str, Any]) -> tuple[str, str, str, str, bool]:
    """Return name, USR, signature, file and external-linkage from native facts."""

    if row.get("kind") == "macro":
        begin = row.get("begin")
        begin = begin if isinstance(begin, Mapping) else {}
        return (
            str(row.get("name") or ""),
            str(row.get("usr") or ""),
            "",
            str(begin.get("file") or ""),
            False,
        )
    owner = row.get("owner")
    owner = owner if isinstance(owner, Mapping) else {}
    callable_row = row.get("callable")
    callable_row = callable_row if isinstance(callable_row, Mapping) else {}
    return (
        str(owner.get("name") or ""),
        str(owner.get("usr") or ""),
        " ".join(str(callable_row.get("canonical_signature") or "").split()),
        str(owner.get("file") or ""),
        callable_row.get("external_linkage") is True,
    )


def _reviewed_name_matches(*, expected: str, actual: str, expected_usr: str, actual_usr: str) -> bool:
    """Accept one legacy short C++ spelling only under an exact native USR.

    Discovery now persists Clang's canonical qualified name.  Existing reviewed
    v1 documents may still contain the source-facing final component (for
    example ``LockFile``) while already carrying the exact current USR, file
    and signature.  That is an identity presentation mismatch, not permission
    to match by name: without the same non-empty USR this helper always fails.
    """

    if actual == expected:
        return True
    return bool(
        expected
        and actual
        and expected_usr
        and actual_usr == expected_usr
        and "::" not in expected
        and actual.rsplit("::", 1)[-1] == expected
    )


def rebind_project_semantics(
    document: Mapping[str, Any],
    *,
    project_root: Path,
    target_id: str,
    code_index: Any,
    allow_unbound_primitive_proposals: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Revalidate reviewed contracts against current exact native identities.

    ``BuildContext`` intentionally includes physical paths, so copying a
    reviewed project into an isolated benchmark directory creates new IDs.
    Blindly treating the old ID as a wildcard would cross compilation
    variants.  Instead this routine requires the same configured target, source
    digest, selector USR/signature, current native definition facts, and (for
    cross-TU consumers) one current observed link record.  It returns an
    in-memory execution document; the reviewer-owned YAML is never rewritten.
    """

    data = deepcopy(
        validate_project_semantics(
            document,
            allow_unbound_primitive_proposals=allow_unbound_primitive_proposals,
        )
    )
    contexts_getter = getattr(code_index, "get_build_contexts", None)
    facts_getter = getattr(code_index, "get_compilation_facts", None)
    if not callable(contexts_getter) or not callable(facts_getter):
        return data, {
            "schema": "zscope.project-semantics-rebind.v1",
            "ready": False,
            "unresolved": ["native_fact_provider_missing"],
            "contracts": [],
        }
    contexts = [row for row in contexts_getter() or [] if isinstance(row, Mapping)]
    build_ids = sorted(
        str(row.get("build_context_id") or "") for row in contexts if row.get("build_context_id")
    )
    facts_by_build: dict[str, list[dict[str, Any]]] = {}
    for build in build_ids:
        facts_by_build[build] = [
            dict(row)
            for row in facts_getter(
                build,
                kinds=("program_function", "macro", "call"),
            )
            or []
            if isinstance(row, Mapping)
        ]

    linked_factory = getattr(code_index, "linked_targets", None)
    linked = linked_factory() if callable(linked_factory) else None
    linked_targets = [
        target
        for target in list(getattr(linked, "targets", []) or [])
        if isinstance(target, Mapping)
    ]
    target_memberships: list[tuple[str, set[str], str]] = []
    for target in linked_targets:
        receipt = target.get("receipt")
        receipt = receipt if isinstance(receipt, Mapping) else {}
        raw_members = target.get("members")
        members = (
            {str(value) for value in raw_members}
            if isinstance(raw_members, Mapping)
            else {str(value) for value in raw_members or []}
        )
        target_memberships.append(
            (
                str(receipt.get("target_id") or ""),
                members,
                canonical_digest(receipt),
            )
        )

    unresolved: list[str] = []
    audit_rows: list[dict[str, Any]] = []
    current_variants: dict[str, list[dict[str, Any]]] = {}
    interface_names = {
        str(candidate.get("id") or ""): str((candidate.get("selector") or {}).get("name") or "")
        for candidate in data["interfaces"]
        if isinstance(candidate, Mapping) and isinstance(candidate.get("selector"), Mapping)
    }
    for row in data["interfaces"]:
        if row["status"] != "confirmed" or row["basis"] == "external_model":
            continue
        identifier = str(row["id"])
        selector = row["selector"]
        kind = str(selector.get("kind") or "")
        reviewed_target_ids = {
            str(variant.get("target_id") or "")
            for variant in row.get("variants", []) or []
            if isinstance(variant, Mapping) and variant.get("target_id")
        }
        if reviewed_target_ids and target_id not in reviewed_target_ids:
            unresolved.append(f"{identifier}:target_mismatch")
            continue
        expected_file = str(selector.get("file") or "").replace("\\", "/")
        source_path = project_root / expected_file
        reviewed_hashes = {
            str(variant.get("source_sha256") or "")
            for variant in row.get("variants", []) or []
            if isinstance(variant, Mapping) and variant.get("source_sha256")
        }
        unbound_primitive_proposal = bool(
            allow_unbound_primitive_proposals
            and row.get("primitive") is True
            and row.get("basis") == "expected_contract"
            and kind == "function"
            and not row.get("variants")
        )
        try:
            current_source_hash = file_sha256(source_path)
        except OSError:
            unresolved.append(f"{identifier}:source_missing")
            continue
        if (
            not unbound_primitive_proposal
            and (not reviewed_hashes or current_source_hash not in reviewed_hashes)
        ):
            unresolved.append(f"{identifier}:source_digest_changed")
            continue

        expected_name = str(selector.get("name") or "")
        expected_usr = str(selector.get("usr") or "")
        expected_signature = " ".join(str(selector.get("signature") or "").split())
        definitions: list[tuple[str, dict[str, Any], bool]] = []
        for build, facts in facts_by_build.items():
            for fact in facts:
                if (kind == "macro") != (fact.get("kind") == "macro"):
                    continue
                if kind != "macro" and fact.get("kind") != "program_function":
                    continue
                name, usr, signature, raw_file, external = _fact_symbol(fact)
                if (
                    _reviewed_name_matches(
                        expected=expected_name,
                        actual=name,
                        expected_usr=expected_usr,
                        actual_usr=usr,
                    )
                    and usr == expected_usr
                    and _project_relative(project_root, raw_file) == expected_file
                    and (kind == "macro" or signature == expected_signature)
                ):
                    definitions.append((build, fact, external))
        if not definitions:
            unresolved.append(f"{identifier}:exact_definition_missing")
            continue

        roots: set[str] = set()
        for value in row.get("derived_from", []) or []:
            reference = str(value)
            root = interface_names.get(reference)
            if not root and reference.startswith("builtin:"):
                root = reference.split(":", 1)[1]
            if not root:
                root = reference
            if root:
                roots.add(root)
        # A reviewer-confirmed ``primitive: true`` row is itself one of the
        # roots from which discovery is allowed to propagate.  Its
        # ``derived_from`` entries describe the reviewed semantic lineage; they
        # are not a promise that the public primitive still contains one
        # direct call to that builtin.  Real projects commonly insert private
        # helpers (for example ``zmalloc -> ztrymalloc_* -> malloc``).  Applying
        # the derived-wrapper direct-call check to those rows revoked valid
        # user roots after every such indirection.  Derived wrappers and macros
        # still have to replay their immediate reviewed root below.
        if roots and row["primitive"] is not True:
            observed_roots: set[str] = set()
            for _build, fact, _external in definitions:
                if kind == "macro":
                    definition = str(fact.get("definition") or "")
                    observed_roots.update(
                        root
                        for root in roots
                        if re.search(rf"\b{re.escape(root)}\s*\(", definition)
                    )
                    continue
                for event in fact.get("events", []) or []:
                    if not isinstance(event, Mapping):
                        continue
                    if (
                        event.get("event_kind") == "acquire"
                        and event.get("ast_kind") in {"CXXNewExpr", "CXXNewArrayExpr"}
                    ):
                        observed_roots.add("cxx_new")
                        continue
                    if event.get("event_kind") != "call":
                        continue
                    callee = event.get("callee")
                    callee = callee if isinstance(callee, Mapping) else {}
                    observed_roots.add(
                        str(callee.get("qualified_name") or callee.get("name") or "")
                    )
                    callee_usr = str(
                        callee.get("usr") or callee.get("referenced_usr") or ""
                    )
                    if callee_usr:
                        observed_roots.add(f"project-cxx-new:{callee_usr}")
            if not roots.issubset(observed_roots):
                unresolved.append(f"{identifier}:reviewed_root_call_changed")
                continue

        definition_builds = {build for build, _fact, _external in definitions}
        consumers = set(definition_builds)
        link_ids: set[str] = set()
        unclosed_caller_builds: set[str] = set()
        if kind == "function" and any(external for _build, _fact, external in definitions):
            matching_targets = [
                (link_id, members, digest)
                for link_id, members, digest in target_memberships
                if members & definition_builds
            ]
            for link_id, members, _digest in matching_targets:
                consumers.update(members)
                if link_id:
                    link_ids.add(link_id)
            caller_builds: set[str] = set()
            for build, facts in facts_by_build.items():
                for fact in facts:
                    if fact.get("kind") != "call":
                        continue
                    raw_call_target = fact.get("target")
                    call_target: Mapping[str, Any] = (
                        raw_call_target if isinstance(raw_call_target, Mapping) else {}
                    )
                    if (
                        str(call_target.get("usr") or call_target.get("referenced_usr") or "")
                        == expected_usr
                    ):
                        caller_builds.add(build)
            unclosed_caller_builds = caller_builds - consumers
            if unclosed_caller_builds:
                unresolved.append(f"{identifier}:caller_outside_observed_link")
                # Keep only the subset whose identity is independently safe:
                # the definition TU and members of current observed link
                # records.  Callers outside that set receive no executable
                # contract.  Missing link closure remains a readiness/formal
                # gap, but must not suppress unrelated local static analysis.

        variants: list[dict[str, Any]] = []
        definition_build = sorted(definition_builds)[0]
        definition_fact = next(
            fact for build, fact, _external in definitions if build == definition_build
        )
        receipt_digest = canonical_digest(
            sorted(
                digest
                for _link_id, members, digest in target_memberships
                if definition_build in members
            )
        )
        for consumer_build in sorted(consumers):
            native_hash = canonical_digest(
                {
                    "definition": definition_fact,
                    "definition_build_context_id": definition_build,
                    "consumer_build_context_id": consumer_build,
                    "observed_link_receipts": receipt_digest,
                }
            )
            variants.append(
                {
                    "target_id": target_id,
                    "build_context_id": consumer_build,
                    "definition_build_context_id": definition_build,
                    "link_target_ids": sorted(link_ids),
                    "usr": expected_usr,
                    "signature": expected_signature,
                    "file": expected_file,
                    "source_sha256": current_source_hash,
                    "evidence_sha256": str(row.get("evidence_digest") or native_hash),
                    "native_input_hash": native_hash,
                    "identity_status": "exact",
                    "revalidated_current": True,
                }
            )
        current_variants[identifier] = variants
        audit_rows.append(
            {
                "id": identifier,
                "kind": kind,
                "definition_build_context_ids": sorted(definition_builds),
                "consumer_build_context_ids": sorted(consumers),
                "link_target_ids": sorted(link_ids),
                "status": "partial" if unclosed_caller_builds else "authorized",
                "unclosed_consumer_build_context_ids": sorted(unclosed_caller_builds),
            }
        )

    for row in data["interfaces"]:
        if row["status"] == "confirmed" and row["basis"] != "external_model":
            row["variants"] = current_variants.get(str(row["id"]), [])
    ready = not unresolved
    audit = {
        "schema": "zscope.project-semantics-rebind.v1",
        "ready": ready,
        "target_id": target_id,
        "build_context_ids": build_ids,
        "unresolved": sorted(set(unresolved)),
        "contracts": sorted(audit_rows, key=lambda value: str(value["id"])),
        "linked_target_count": len(target_memberships),
    }
    return data, audit


def semantics_readiness(
    document: Mapping[str, Any],
    *,
    project_root: Path,
    build_context_ids: Iterable[str] = (),
) -> SemanticsReadiness:
    data = validate_project_semantics(document)
    builds = {str(value) for value in build_context_ids if str(value)}
    pending: list[str] = []
    stale: list[str] = []
    unresolved: list[str] = []
    conflicts: list[str] = []
    unsupported: list[str] = []
    source_mismatches: list[str] = []
    confirmed = rejected = primitives = derived = 0
    for row in data["interfaces"]:
        identifier = str(row["id"])
        status = str(row["status"])
        primitives += int(row["primitive"] is True)
        derived += int(row["primitive"] is False)
        confirmed += int(status == "confirmed")
        rejected += int(status == "rejected")
        if status == "pending":
            pending.append(identifier)
        elif status == "stale":
            stale.append(identifier)
        if status == "confirmed":
            if any(
                str(effect.get("role") or "") not in EXECUTABLE_ROLES for effect in row["effects"]
            ):
                unsupported.append(identifier)
            if _source_mismatch(row, Path(project_root)):
                source_mismatches.append(identifier)
            if builds and row.get("basis") != "external_model":
                covered = {
                    str(variant.get("build_context_id") or "")
                    for variant in row.get("variants", [])
                    if isinstance(variant, Mapping)
                }
                if builds - covered:
                    unresolved.append(identifier)
            variants: dict[str, set[str]] = {}
            for variant in row.get("variants", []) or []:
                if isinstance(variant, Mapping):
                    variants.setdefault(str(variant.get("build_context_id") or ""), set()).add(
                        str(variant.get("usr") or "")
                    )
            if any(len(values) != 1 or "" in values for values in variants.values()):
                conflicts.append(identifier)
    for collection in ("dispatchers", "function_pointer_bindings"):
        for row in data[collection]:
            identifier = f"{collection}:{row['id']}"
            if row["status"] == "pending":
                pending.append(identifier)
            elif row["status"] == "stale":
                stale.append(identifier)
            elif row["status"] == "confirmed" and builds:
                row_build = str(row.get("build_context_id") or "")
                if row_build not in builds:
                    unresolved.append(identifier)
    receipt = data.get("discovery_receipt") or {}
    if isinstance(receipt, Mapping):
        unresolved.extend(
            f"discovery:{gap}"
            for gap in receipt.get("blocking_coverage_gaps", []) or []
            if str(gap)
        )
    digest = canonical_digest(data)
    ready = not any((pending, stale, unresolved, conflicts, unsupported, source_mismatches))
    return SemanticsReadiness(
        ready=ready,
        pending=tuple(sorted(pending)),
        stale=tuple(sorted(stale)),
        unresolved=tuple(sorted(set(unresolved))),
        conflicts=tuple(sorted(set(conflicts))),
        unsupported=tuple(sorted(set(unsupported))),
        source_mismatches=tuple(sorted(set(source_mismatches))),
        confirmed=confirmed,
        rejected=rejected,
        primitives=primitives,
        derived=derived,
        digest=digest,
    )


def require_project_semantics_ready(
    config: Any,
    *,
    build_context_ids: Iterable[str] = (),
) -> SemanticsReadiness:
    project = getattr(config, "project", None)
    if project is None:
        raise ProjectSemanticsError("configuration has no project section")
    if str(getattr(project, "language", "")) == "java":
        return SemanticsReadiness(True, (), (), (), (), (), (), 0, 0, 0, 0, "")
    from .semantics_workflow import require_workflow

    require_workflow(config)
    path = getattr(project, "semantics_file", None)
    if not path:
        raise ProjectSemanticsError(
            "C/C++ scan requires project.semantics_file; run zscope-init or zscope-config migrate-semantics"
        )
    document = load_project_semantics(Path(path))
    result = semantics_readiness(
        document,
        project_root=Path(project.project_root),
        build_context_ids=build_context_ids,
    )
    if not result.ready:
        raise ProjectSemanticsError(
            "project semantics is not ready: " + ", ".join(result.reasons[:24])
        )
    return result


def _binding_from_object_path(value: Mapping[str, Any]) -> dict[str, Any]:
    root = str(value.get("root") or "")
    members = [str(item) for item in value.get("members", []) or []]
    member_path = "".join("->" + member for member in members)
    if root == "return":
        return {"kind": "return", "member_path": member_path}
    if root == "global":
        return {
            "kind": "global",
            "global_name": str(value.get("name") or ""),
            "member_path": member_path,
            "address_of": bool(value.get("address_of", True)),
        }
    return {
        "kind": "output_argument" if int(value.get("dereference", 0)) else "argument",
        "argument_index": int(value["index"]),
        "member_path": member_path,
        "address_of": bool(value.get("address_of", False)),
    }


_RELEASE_EFFECT_ROLES = frozenset(
    {
        "deallocator",
        "resource_release",
        "io_release",
        "unlock",
        "thread_release",
    }
)


def enrich_derived_interface_pairs(
    interfaces: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Close pair edges through reviewed wrapper/macro abstraction layers.

    Discovery initially learns a wrapper from its primitive root, so an
    acquire wrapper naturally names (for example) ``builtin:pthread_mutex_unlock``.
    A caller, however, invokes the reviewed project unlock wrapper or macro.
    Preserve the primitive edge and add exact, same-layer release interfaces
    reached through ``derived_from``.  This is structural composition of
    already-described interfaces, never a name-based role inference.
    """

    rows = [deepcopy(dict(value)) for value in interfaces]
    by_id = {str(row.get("id") or ""): row for row in rows}
    children: dict[str, set[str]] = {}
    for row in rows:
        identifier = str(row.get("id") or "")
        for parent in row.get("derived_from", []) or []:
            parent_id = str(parent or "")
            if parent_id and identifier:
                children.setdefault(parent_id, set()).add(identifier)

    def release_families(row: Mapping[str, Any]) -> set[str]:
        return {
            str(effect.get("resource_family") or "")
            for effect in row.get("effects", []) or []
            if isinstance(effect, Mapping)
            and str(effect.get("role") or "") in _RELEASE_EFFECT_ROLES
        }

    def acquire_families(row: Mapping[str, Any]) -> set[str]:
        return {
            str(effect.get("resource_family") or "")
            for effect in row.get("effects", []) or []
            if isinstance(effect, Mapping)
            and str(effect.get("role") or "") not in _RELEASE_EFFECT_ROLES
        }

    for row in rows:
        selector = row.get("selector")
        selector = selector if isinstance(selector, Mapping) else {}
        kind = str(selector.get("kind") or "")
        families = acquire_families(row)
        pairs = {str(value) for value in row.get("pairs", []) or [] if str(value)}
        pending = list(pairs)
        seen = set(pending)
        while pending:
            parent = pending.pop()
            for child_id in sorted(children.get(parent, ())):
                if child_id in seen:
                    continue
                seen.add(child_id)
                pending.append(child_id)
                child = by_id.get(child_id)
                if not isinstance(child, Mapping):
                    continue
                child_selector = child.get("selector")
                child_selector = child_selector if isinstance(child_selector, Mapping) else {}
                child_families = release_families(child)
                if str(child_selector.get("kind") or "") != kind or not child_families:
                    continue
                if (
                    families
                    and child_families
                    and not (families & child_families or "" in families or "" in child_families)
                ):
                    continue
                pairs.add(child_id)
        row["pairs"] = sorted(pairs)
    return rows


def compiled_project_contracts(
    document: Mapping[str, Any],
    *,
    build_context_id: str,
) -> list[dict[str, Any]]:
    """Compile confirmed rows into exact instance-scoped ApiContract payloads."""

    data = validate_project_semantics(document)
    data["interfaces"] = enrich_derived_interface_pairs(data["interfaces"])
    identifiers = {str(row["id"]): row for row in data["interfaces"]}
    result: list[dict[str, Any]] = []
    for row in data["interfaces"]:
        if row["status"] != "confirmed":
            continue
        variants = _selected_variants(row, build_context_id)
        if not variants and row["basis"] == "external_model":
            selector = row["selector"]
            selector_build = str(selector.get("build_context_id") or "")
            if selector_build and selector_build != build_context_id:
                continue
            variants = [selector]
        for variant in variants:
            selector = {**dict(row["selector"]), **dict(variant)}
            pair_symbols: list[dict[str, Any]] = []
            for pair_id in row.get("pairs", []) or []:
                if pair_id.startswith("builtin:"):
                    pair_symbols.append({"name": pair_id.split(":", 1)[1]})
                elif pair_id in identifiers:
                    pair_row = identifiers[pair_id]
                    if pair_row.get("status") != "confirmed":
                        continue
                    pair_variants = _selected_variants(pair_row, build_context_id)
                    if not pair_variants and pair_row.get("basis") == "external_model":
                        pair_selector = pair_row["selector"]
                        if str(pair_selector.get("build_context_id") or "") != build_context_id:
                            continue
                    elif pair_variants:
                        pair_selector = {
                            **dict(pair_row["selector"]),
                            **dict(pair_variants[0]),
                        }
                    else:
                        continue
                    pair_symbols.append(
                        {
                            "name": str(pair_selector.get("name") or ""),
                            "file_path": str(pair_selector.get("file") or ""),
                            "signature": str(pair_selector.get("signature") or ""),
                            "usr": str(pair_selector.get("usr") or ""),
                            "build_context_id": build_context_id,
                        }
                    )
            for effect in row["effects"]:
                strength = str(effect.get("strength") or "must_under_guard")
                native = row["basis"] != "external_model"
                delegates: list[dict[str, Any]] = []
                for reference_value in row.get("derived_from", []) or []:
                    reference = str(reference_value or "")
                    if reference.startswith("builtin:"):
                        delegate_symbol = {"name": reference.split(":", 1)[1]}
                    elif reference in identifiers:
                        parent = identifiers[reference]
                        if parent.get("status") != "confirmed":
                            continue
                        parent_variants = _selected_variants(parent, build_context_id)
                        if parent_variants:
                            parent_selector = {
                                **dict(parent["selector"]),
                                **dict(parent_variants[0]),
                            }
                        elif parent.get("basis") == "external_model":
                            parent_selector = dict(parent["selector"])
                            parent_build = str(parent_selector.get("build_context_id") or "")
                            if parent_build and parent_build != build_context_id:
                                continue
                        else:
                            continue
                        delegate_symbol = {
                            "name": str(parent_selector.get("name") or ""),
                            "file_path": str(parent_selector.get("file") or "").replace("\\", "/"),
                            "signature": str(parent_selector.get("signature") or ""),
                            "usr": str(parent_selector.get("usr") or ""),
                            "build_context_id": build_context_id,
                        }
                    else:
                        continue
                    if delegate_symbol.get("name"):
                        delegates.append(
                            {
                                "symbol": delegate_symbol,
                                "role": str(effect["role"]),
                                "transparent": strength != "may",
                            }
                        )
                verification = {
                    "method": "source_composition" if native else "project_external_model",
                    "compiler_version": CONTRACT_COMPILER_VERSION,
                    "effect_strength": strength,
                    "source_hash": str(variant.get("source_sha256") or "explicit_external_model"),
                    "identity_verified": True,
                    "project_semantics_id": row["id"],
                    "authority": "native_current" if native else "explicit_user_assumption",
                    "revalidated_current": bool(variant.get("revalidated_current", False)),
                    "definition_build_context_id": str(
                        variant.get("definition_build_context_id") or build_context_id
                    ),
                    "link_target_ids": [
                        str(value) for value in variant.get("link_target_ids", []) or []
                    ],
                }
                result.append(
                    {
                        "symbol": {
                            "name": str(selector.get("name") or ""),
                            "file_path": str(selector.get("file") or "").replace("\\", "/"),
                            "signature": str(selector.get("signature") or ""),
                            "symbol_type": str(selector.get("kind") or "function"),
                            "build_context_id": build_context_id,
                            "usr": str(selector.get("usr") or ""),
                        },
                        "role": str(effect["role"]),
                        "carrier": _binding_from_object_path(effect["carrier"]),
                        "pairs": pair_symbols,
                        "resource_family": str(effect.get("resource_family") or ""),
                        "source": (
                            f"inferred:project_semantics:{row['id']}"
                            if native
                            else f"project_semantics:external_model:{row['id']}"
                        ),
                        "status": "confirmed",
                        "preconditions": effect.get("preconditions") or {"op": "true"},
                        "effect_cases": deepcopy(row["cases"]),
                        "delegates": delegates,
                        "protocol": deepcopy(effect.get("protocol") or {}),
                        "evidence": [
                            {
                                "evidence_ref": row.get("evidence_ref", ""),
                                "evidence_sha256": variant.get("evidence_sha256", ""),
                                "native_input_hash": variant.get("native_input_hash", ""),
                                "basis": row["basis"],
                            }
                        ],
                        "verification": verification,
                    }
                )
    return result


class ProjectSemanticsStore:
    """Round-trip store and compatibility projection for project semantics."""

    def __init__(self, path: Path):
        self.path = Path(path).resolve()

    def read(self, *, allow_unbound_primitive_proposals: bool = False) -> dict[str, Any]:
        return load_project_semantics(
            self.path,
            allow_unbound_primitive_proposals=allow_unbound_primitive_proposals,
        )

    def write(self, document: Mapping[str, Any]) -> None:
        validated = validate_project_semantics(document)
        _yaml_round_trip_dump(self.path, validated)

    def merge_discovery(
        self,
        *,
        interfaces: Sequence[Mapping[str, Any]],
        dispatchers: Sequence[Mapping[str, Any]] = (),
        pointer_bindings: Sequence[Mapping[str, Any]] = (),
        receipt: Mapping[str, Any],
        allow_unbound_primitive_proposals: bool = False,
        expected_revision: str | None = None,
    ) -> dict[str, int]:
        from .semantics_workflow import revision, SemanticsConflict

        if expected_revision is not None and revision(self.path) != expected_revision:
            raise SemanticsConflict("语义文档已变化，发现结果未发布。")
        current = self.read(
            allow_unbound_primitive_proposals=allow_unbound_primitive_proposals
        )
        stats = {"added": 0, "refreshed": 0, "preserved": 0, "stale": 0}

        def merge_rows(key: str, generated: Sequence[Mapping[str, Any]]) -> None:
            existing = {str(row.get("id") or ""): row for row in current[key]}
            generated_ids: set[str] = set()
            for incoming_raw in generated:
                incoming = deepcopy(dict(incoming_raw))
                identifier = str(incoming.get("id") or "")
                generated_ids.add(identifier)
                old = existing.get(identifier)
                if old is None:
                    current[key].append(incoming)
                    stats["added"] += 1
                    continue
                old_status = str(old.get("status") or "")
                old_evidence = str(old.get("evidence_digest") or "")
                new_evidence = str(incoming.get("evidence_digest") or "")
                if old_status in {"confirmed", "rejected"} and old_evidence == new_evidence:
                    stats["preserved"] += 1
                    continue
                if old_status in {"confirmed", "rejected"} and old_evidence != new_evidence:
                    incoming["status"] = "stale"
                    stats["stale"] += 1
                old.clear()
                old.update(incoming)
                stats["refreshed"] += 1
            for identifier, old in existing.items():
                # User-declared primitive roots are discovery inputs, not
                # outputs.  A discovery refresh must never invalidate one
                # merely because it was not re-derived from itself.
                if old.get("primitive") is True:
                    continue
                if (
                    identifier
                    and identifier not in generated_ids
                    and old.get("status") != "rejected"
                ):
                    old["status"] = "stale"
                    old["stale_reason"] = "candidate_not_reproduced_by_current_discovery"
                    stats["stale"] += 1

        merge_rows("interfaces", interfaces)
        merge_rows("dispatchers", dispatchers)
        merge_rows("function_pointer_bindings", pointer_bindings)
        current["discovery_receipt"] = deepcopy(dict(receipt))
        if expected_revision is not None and revision(self.path) != expected_revision:
            raise SemanticsConflict("语义文档已变化，发现结果未发布。")
        self.write(current)
        return stats

    # Compatibility projections used by existing evidence renderers.  They
    # deliberately expose only reviewed YAML data and never reintroduce
    # function-intent or module-lifecycle execution.
    def list_external_functions(self) -> list[dict[str, Any]]:
        rows = []
        for item in self.read()["interfaces"]:
            if item["status"] != "confirmed":
                continue
            for effect in item.get("effects", []) or []:
                rows.append(
                    {
                        "func_name": item["selector"]["name"],
                        "kind": effect.get("role", ""),
                        "description": item.get("evidence_summary", ""),
                        "source": f"project_semantics:{item['basis']}",
                        "contract": item,
                        "status": "confirmed",
                    }
                )
        return rows

    def list_paired_functions(
        self,
        category: str | None = None,
        *,
        allow_unbound_primitive_proposals: bool = False,
    ) -> list[dict[str, Any]]:
        document = self.read(
            allow_unbound_primitive_proposals=allow_unbound_primitive_proposals
        )
        by_id = {row["id"]: row for row in document["interfaces"]}
        rows = []
        for item in document["interfaces"]:
            for target in item.get("pairs", []) or []:
                release = (
                    target.split(":", 1)[1]
                    if target.startswith("builtin:")
                    else str((by_id.get(target) or {}).get("selector", {}).get("name") or "")
                )
                role = str((item.get("effects") or [{}])[0].get("role") or "")
                if release and (not category or category == role):
                    rows.append(
                        {
                            "category": role,
                            "acquire_func": item["selector"]["name"],
                            "release_func": release,
                            "description": item.get("evidence_summary", ""),
                        }
                    )
        return rows

    def list_dispatchers(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for raw in self.read()["dispatchers"]:
            if raw["status"] != "confirmed":
                continue
            row = dict(raw)
            # The execution overlay predates the public v1 YAML names.  Keep
            # the stored schema precise while projecting the compatibility
            # field names consumed by graph expansion and evidence renderers.
            row["dispatcher_name"] = str(row.get("dispatcher") or "")
            row["file_path"] = str(row.get("file") or "")
            row["message_type"] = str(row.get("guard") or "")
            row.setdefault("handler_kind", "configured_dispatcher")
            rows.append(row)
        return rows

    def get_pointer_targets(
        self, pointer_location: str | None = None, context: str | None = None
    ) -> list[dict[str, Any]]:
        del context
        rows = [
            {
                **dict(row),
                "pointer_location": row.get("slot_usr", ""),
                "target_functions": row.get("target_names", []),
                "scope": row.get("file", ""),
            }
            for row in self.read()["function_pointer_bindings"]
            if row["status"] == "confirmed"
        ]
        if pointer_location:
            rows = [row for row in rows if row["pointer_location"] == pointer_location]
        return rows

    def list_module_lifecycle(self) -> list[dict[str, Any]]:
        return []

    def list_function_intents(self) -> list[dict[str, Any]]:
        return []

    def get_function_intent(self, func_name: str, file_path: str | None = None) -> None:
        del func_name, file_path
        return None
