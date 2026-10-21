"""Exact-instance C/C++ semantics: builtin effects only, manual rows advisory.

This is the S01 first slice (``S01-INSTANCE-SEMANTICS-MIN-R23``, inheriting
``S01-INSTANCE-MODELING-DESIGN-R21``), repaired under the R24 and R25 source
reviews (``S01-R24-P1-01``..``S01-R24-P2-04``, ``S01-R25-P1-01``/``-02``).
One analysis instance is one exact ``(BuildContext, native USR)``; for that
instance a snapshot carries two strictly separated kinds of information:

* **Builtin execution effects**, minted only by the packaged factory
  (:func:`zscope.semantics.defaults.default_local_pattern_semantics` and
  ``standard_contracts``), and only for roots whose standard declaration is
  positively evidenced **inside the pinned build**: every exact-context
  native call receipt for the root must classify it as a system-header
  declaration with external linkage, no TU definition, the root's exact C
  native USR, the supported platform's canonical signature (Linux glibc
  LP64 table in this module). Positive source evidence additionally binds
  the physical host glibc installation's stdlib/features headers, their
  current exact-build content digests, the actual native include resolution,
  compiler search/target receipts and the current native tool identity.
  Only the root-owned, non-writable host installation at /usr/include is
  supported; custom sysroots and other layouts remain an explicit gap.
  Excluding user-controlled include paths alone grants nothing. A missing
  function body, an empty answer, a non-system or user-controlled
  declaration, a wrong signature or native identity, a project definition
  or macro, a foreign or stale build, a command whose include surface
  cannot be enumerated, an ABI this slice cannot verify, or any
  unverifiable origin denies the builtin authority for that root — unknown
  is never a wildcard and never falls back to the name table, a basename or
  a bare boolean.  The deny universe spans contracts, role buckets, pair
  endpoints, checker models and the checker-only packaged roots, so raw
  bucket checkers see the same denial.  Cross-TU composition stays
  deferred.
* **Manual advisory context**, name/file/signature-level descriptions from
  non-inferred workbook rows, filtered through each sheet's real selector
  (pointer ``scope`` glob, dispatcher/lifecycle ``file_path`` glob, function
  intent name/file equality).  They render with
  ``authority=name_only_advisory`` and never enter ``LocalPatternSemantics``
  role maps, ``ContractRegistry``, api pairs or any executable overlay.
  Self-reported builtin source, USR, ``confirmed`` status, ``effect_strength``
  or saved verification in those rows remain workbook content and grant
  nothing.

Every workbook row whose source is inferred is excluded, with the row bytes
and an explicit exclusion reason preserved in ``excluded_rows`` — including
rows whose build/USR look exact or whose saved verification looks valid.  No
inferred execution effect is authorized in this slice.

Snapshots are **factory-issued objects**: :func:`build_instance_semantics`
derives every effect byte from the packaged catalog plus the pinned build's
own receipts and registers the issued object in a process-local issuer
registry.  :func:`materialize_effect_semantics` and :func:`advisory_context`
accept only objects the factory actually issued in this process — a
reconstructed, ``dataclasses.replace``d or otherwise forged snapshot with a
self-consistently recomputed digest is rejected, not merely re-validated
structurally.  Denial travels with the data: the effect payload carries the
per-root origin map and deny set, the materialized ``LocalPatternSemantics``
excludes denied roots from contracts, pairs and role buckets, and the
returned overlay carries ``shadowed_symbols``/``symbol_origins`` while
omitting denied executable content.  Together with the coordinator-owned
``merge_overlay`` shadow pruning (R25 shared dependency), overlay-only
consumers that merge this overlay into an empty or default registry keep
the denial in role buckets and at every guarded query; preseeded raw pairs
staying visible through ``releases``/``acquires`` on such a registry remain
guarded by ``allows`` at the effect-consuming call sites.

:func:`build_instance_semantics` binds the exact ``InstanceScope`` through a
real :class:`~zscope.retrieval.instance_index.ScopedCodeIndex` and never falls
back to name navigation.  Currency is not ``dependencies_current_status()``
alone: the pinned build record must also pass the full
:func:`zscope.retrieval.build_context.context_input_status` verification
(compilation database, command identity, include-search directories, include
probes) and the pinned entry must hold a complete exact native program-facts
receipt.  Unknown or stale dependencies return ``SemanticsUnavailable``.

This module wires no consumer; the coordinator owns all Analyzer/Validator
integration, plan/checkpoint identity and settlement boundaries, the shared
``merge_overlay``/raw-consumer seam and the rebinding of default checker
names into raw consumers.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
import threading
import weakref
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Mapping, NewType, Optional, Tuple, Union

from ..retrieval.build_context import context_input_status
from ..retrieval.instance_index import InstanceScope, ScopedCodeIndex
from ..retrieval.indexing_identity import dependencies_current, file_digest
from .contracts import (
    CONTRACT_COMPILER_VERSION,
    ApiContract,
    ApiPair,
    SymbolIdentity,
)
from .defaults import (
    default_local_pattern_semantics,
    default_overlay_models,
    load_default_semantics_data,
)
from .models import (
    CATEGORY_BY_ATTR,
    DEFAULT_SEMANTICS_SOURCE,
    MERGE_ATTRS,
    LocalPatternSemantics,
)
from .standard_api import STANDARD_API_VERSION
from .user_config_context import parse_user_config_list, user_config_scope_matches

INSTANCE_SEMANTICS_SCHEMA: Literal["zscope.instance-semantics.v1"] = "zscope.instance-semantics.v1"
AUTHORITY_POLICY: Literal["builtin_current_manual_advisory_no_inferred.v1"] = (
    "builtin_current_manual_advisory_no_inferred.v1"
)
#: Manual rows never carry more than name/file/signature-level authority.
ADVISORY_AUTHORITY = "name_only_advisory"
#: Uniform exclusion reason recorded with every excluded inferred row.
INFERRED_EXCLUSION_REASON = "inferred_row_excluded_by_authority_policy"

# Per-root origin statuses.  Only a native system-header call receipt inside
# the pinned build — whose exact native identity, canonical signature and
# declaration source all match the supported platform ABI — authorizes the
# packaged builtin for that root; every other status is a denial that must
# survive into payloads, local semantics, the overlay and diagnostics.
ORIGIN_SYSTEM_RECEIPT = "system_header_call_receipt"
ORIGIN_PROJECT_DEFINED = "project_defined_in_build"
ORIGIN_AMBIGUOUS_IDENTITY = "ambiguous_or_unverifiable_identity"
ORIGIN_NON_SYSTEM_RECEIPT = "non_system_origin_receipt"
ORIGIN_NO_RECEIPT = "no_origin_receipt"
ORIGIN_QUERY_FAILED = "origin_query_failed"
ORIGIN_ABI_UNPROVEN = "no_verifiable_standard_abi"
ORIGIN_SIGNATURE_MISMATCH = "standard_signature_mismatch"
ORIGIN_IDENTITY_MISMATCH = "native_identity_mismatch"
ORIGIN_USER_INCLUDE_DECLARATION = "user_include_declaration"
ORIGIN_UNVERIFIABLE_COMMAND = "unverifiable_command_include_paths"
ORIGIN_STANDARD_SOURCE_UNPROVEN = "no_verified_standard_declaration_source"
_ALLOWED_ORIGINS = frozenset({ORIGIN_SYSTEM_RECEIPT})

# Verified standard-root ABI table for the supported platform (Linux glibc
# LP64): the exact canonical signature each packaged root's declaration must
# carry in the current compilation for its effects to be authorized.  The
# native receipt supplies the actual declaration facts; this table supplies
# the platform expectation the receipt is compared against.  Roots outside
# this table have no receipt-backed ABI verifier in this slice and stay
# denied with an explicit ``no_verifiable_standard_abi`` gap — they are never
# authorized by name, system-header classification or basename alone.
_VERIFIED_STANDARD_ABI: Dict[str, str] = {
    "malloc": "void *(unsigned long)",
    "calloc": "void *(unsigned long, unsigned long)",
    "realloc": "void *(void *, unsigned long)",
    "free": "void (void *)",
}
#: C external-linkage USR form of a standard root (clang ``c:@F@<name>``).
_C_USR_PREFIX = "c:@F@"
#: Command flags that add user-controlled include/sysroot search paths.
_USER_INCLUDE_FLAGS = (
    "-isystem-after",
    "-isystem",
    "-iquote",
    "-idirafter",
    "-isysroot",
    "-I",
    "--sysroot",
)
# These surfaces need a different origin verifier, not an optimistic parse.
_UNSUPPORTED_INCLUDE_SURFACES = (
    "-Xclang",
    "-Xpreprocessor",
    "-Wp,",
    "-cc1",
    "--config",
    "-config",
    "-ivfsoverlay",
    "-vfsoverlay",
    "-fmodule",
    "-fprebuilt-module-path",
    "-fimplicit-module",
    "-stdlib++-isystem",
    "-include",
    "--include",
    "-imacros",
    "-iprefix",
    "-iwith",
    "-internal-",
    "-cxx-isystem",
    "-iframework",
    "-F",
    "-resource-dir",
    "--resource-dir",
    "--gcc-",
    "-gcc-",
    "-B",
    "-working-directory",
    "--working-directory",
)
_HOST_GLIBC_STDLIB = Path("/usr/include/stdlib.h")
_HOST_GLIBC_FEATURES = Path("/usr/include/features.h")

FrozenJSON = NewType("FrozenJSON", bytes)

JSONValue = Union[None, bool, int, float, str, List["JSONValue"], Dict[str, "JSONValue"]]

_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")


# ── Frozen input and snapshot shapes (frozen R23 typed contract) ──


@dataclass(frozen=True)
class FrozenWorkbookRows:
    """Workbook rows frozen as canonical immutable bytes.

    ``external_rows`` mirror ``list_external_functions`` rows, ``paired_rows``
    mirror ``list_paired_functions`` rows and ``other_advisory_rows`` hold the
    remaining advisory sheets (pointer targets, dispatchers, module lifecycle,
    function intents).  ``workbook_sha256`` binds the workbook file the rows
    were read from; the rows themselves are the frozen content.
    """

    workbook_sha256: str
    external_rows: Tuple[FrozenJSON, ...]
    paired_rows: Tuple[FrozenJSON, ...]
    other_advisory_rows: Tuple[FrozenJSON, ...]


@dataclass(frozen=True)
class SemanticsDependencies:
    """Dependency fingerprint the snapshot is only valid for.

    ``compiler_version``, ``standard_api_version`` and
    ``builtin_payload_sha256`` are verified against the current packaged
    factory by :func:`build_instance_semantics`; a mismatched value is stale
    and returns unavailable.  ``business_answers_sha256`` and
    ``effective_policy_sha256`` are bound into the snapshot digest — the
    caller computes them from the current business answers and effective
    policy and re-verifies them at analysis/validation/persistence
    boundaries; this module cannot re-derive them.
    """

    compiler_version: str
    standard_api_version: str
    builtin_payload_sha256: str
    business_answers_sha256: str
    effective_policy_sha256: str


@dataclass(frozen=True)
class InstanceSemanticsSnapshot:
    """Immutable per-instance semantics: builtin effects plus manual advisory.

    ``effect_payload`` and ``advisory_payload`` are canonical UTF-8 bytes;
    ``excluded_rows`` preserves each excluded inferred row together with its
    exclusion reason.  ``digest`` covers the scope, the dependency
    fingerprint, the workbook digest and every payload digest, so any change
    to inputs, builtin defaults, manual rows or excluded rows invalidates the
    snapshot identity (and with it plan checkpoints and per-instance results).

    Only :func:`build_instance_semantics` issues usable snapshot objects;
    consumers must treat any other construction as untrusted data.
    """

    schema: Literal["zscope.instance-semantics.v1"]
    authority_policy: Literal["builtin_current_manual_advisory_no_inferred.v1"]
    scope: InstanceScope
    dependencies: SemanticsDependencies
    workbook_sha256: str
    effect_payload: FrozenJSON
    advisory_payload: FrozenJSON
    excluded_rows: Tuple[FrozenJSON, ...]
    digest: str


@dataclass(frozen=True)
class SemanticsUnavailable:
    """Why no instance semantics could be frozen; never a silent fallback."""

    reason: str


# ── Canonical JSON bytes ──


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return bool(_SHA256_HEX.match(value))


def _validate_json_value(value: Any, *, where: str = "value") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{where}: non-finite float is not JSON data")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, where=f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{where}: JSON object keys must be strings")
            _validate_json_value(item, where=f"{where}.{key}")
        return
    raise ValueError(f"{where}: unsupported JSON value type {type(value).__name__}")


def _canonical_bytes(value: JSONValue) -> FrozenJSON:
    _validate_json_value(value)
    return FrozenJSON(
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _strict_json_loads(data: bytes) -> Any:
    """Decode canonical bytes strictly: duplicate keys and NaN are errors."""

    def object_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key {key!r}")
            result[key] = value
        return result

    def parse_constant(name: str) -> Any:
        raise ValueError(f"non-finite JSON constant {name!r}")

    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=object_pairs,
        parse_constant=parse_constant,
    )


def freeze_workbook_rows(
    *,
    workbook_sha256: str,
    external_rows: Iterable[Mapping[str, Any]] = (),
    paired_rows: Iterable[Mapping[str, Any]] = (),
    other_advisory_rows: Iterable[Mapping[str, Any]] = (),
) -> FrozenWorkbookRows:
    """Freeze live workbook row lists into canonical immutable bytes.

    Rows must be plain JSON values; non-finite floats, non-string keys or
    other non-JSON values raise ``ValueError`` instead of being silently
    coerced.  Classification into manual/inferred happens later, at snapshot
    build time, from the frozen bytes.
    """

    def freeze(rows: Iterable[Mapping[str, Any]]) -> Tuple[FrozenJSON, ...]:
        return tuple(_canonical_bytes(dict(row)) for row in rows)

    return FrozenWorkbookRows(
        workbook_sha256=str(workbook_sha256),
        external_rows=freeze(external_rows),
        paired_rows=freeze(paired_rows),
        other_advisory_rows=freeze(other_advisory_rows),
    )


# ── Factory issuance boundary (R24 S01-R24-P1-01) ──

# Snapshots are authority-bearing objects, and a frozen dataclass plus a
# recomputable digest only proves integrity, never provenance.  The factory
# registers every object it actually issues, keyed by identity; consumers
# reject anything else — including value-identical reconstructions — instead
# of trusting caller-supplied labels or digests.
_ISSUED_SNAPSHOTS: "weakref.WeakValueDictionary[int, InstanceSemanticsSnapshot]" = (
    weakref.WeakValueDictionary()
)
_ISSUER_LOCK = threading.Lock()


def _register_issued(snapshot: InstanceSemanticsSnapshot) -> InstanceSemanticsSnapshot:
    with _ISSUER_LOCK:
        _ISSUED_SNAPSHOTS[id(snapshot)] = snapshot
    return snapshot


def _verify_factory_issued(snapshot: InstanceSemanticsSnapshot) -> None:
    with _ISSUER_LOCK:
        issued = _ISSUED_SNAPSHOTS.get(id(snapshot)) is snapshot
    if not issued:
        raise ValueError(
            "instance semantics snapshot was not issued by build_instance_semantics "
            "in this process; reconstructed or forged snapshots grant nothing"
        )


# ── Packaged builtin payload (the only effect authority) ──


def _sorted_canonical(rows: Iterable[Any]) -> List[Any]:
    def key(row: Any) -> str:
        return json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        )

    return [row for _, row in sorted(((key(row), row) for row in rows), key=lambda item: item[0])]


@lru_cache(maxsize=1)
def _builtin_effect_data() -> Dict[str, Any]:
    """The packaged builtin payload data; the returned value is read-only."""

    semantics = default_local_pattern_semantics()
    overlay = default_overlay_models()
    roles: Dict[str, Dict[str, List[str]]] = {}
    for attr in MERGE_ATTRS:
        bucket = getattr(semantics, attr)
        roles[attr] = {
            str(name): [str(source) for source in sources] for name, sources in bucket.items()
        }
    contracts = _sorted_canonical(contract.to_dict() for contract in semantics.contracts.contracts)
    pairs = _sorted_canonical(pair.to_dict() for pair in semantics.contracts.pairs)
    checker_models = {
        "resource_models": [dict(row) for row in overlay.get("resource_models") or []],
        "lock_models": [dict(row) for row in overlay.get("lock_models") or []],
    }
    described = {str((row.get("symbol") or {}).get("name") or "") for row in contracts}
    for names_by_attr in roles.values():
        described.update(str(name) for name in names_by_attr)
    for row in pairs:
        for endpoint in ("acquire", "release"):
            described.add(str((row.get(endpoint) or {}).get("name") or ""))
    for rows in checker_models.values():
        described.update(str(row.get("name") or "") for row in rows if isinstance(row, dict))
    # Checker-only packaged roots (defaults.yaml ``checker_roles``) never
    # appear in contracts/roles/pairs/models, but they are executable names
    # for raw-bucket checkers, so they belong to the deny universe too.
    checker_only: set = set()
    checker_roles = load_default_semantics_data().get("checker_roles")
    for names in (checker_roles or {}).values():
        checker_only.update(str(name) for name in (names or []) if str(name))
    checker_only -= described
    checker_only.discard("")
    return {
        "type_aliases": dict(semantics.type_aliases),
        "roles": roles,
        "contracts": contracts,
        "pairs": pairs,
        "checker_models": checker_models,
        "checker_only_roots": sorted(checker_only),
    }


def builtin_semantics_fingerprint() -> Dict[str, str]:
    """Current packaged builtin identity for building ``SemanticsDependencies``.

    ``builtin_payload_sha256`` digests the exact packaged builtin payload
    data (aliases, roles, contracts, pairs, checker models and the
    checker-only deny-universe roots) that :func:`build_instance_semantics`
    embeds into every snapshot, so a caller can construct the dependency
    fingerprint the factory will accept.
    """

    data = _builtin_effect_data()
    payload = _canonical_bytes(
        {
            "type_aliases": data["type_aliases"],
            "roles": data["roles"],
            "contracts": data["contracts"],
            "pairs": data["pairs"],
            "checker_models": data["checker_models"],
            "checker_only_roots": data["checker_only_roots"],
        }
    )
    return {
        "compiler_version": CONTRACT_COMPILER_VERSION,
        "standard_api_version": STANDARD_API_VERSION,
        "builtin_payload_sha256": _sha256_hex(payload),
    }


def _effect_payload(denied: Iterable[str], origins: Mapping[str, str]) -> FrozenJSON:
    hidden = set(denied)
    data = _builtin_effect_data()
    models = {
        key: [
            dict(row)
            for row in rows
            if isinstance(row, dict) and str(row.get("name") or "") not in hidden
        ]
        for key, rows in data["checker_models"].items()
    }
    payload: Dict[str, Any] = {
        "schema": INSTANCE_SEMANTICS_SCHEMA,
        "authority_policy": AUTHORITY_POLICY,
        "builtin_source": DEFAULT_SEMANTICS_SOURCE,
        "compiler_version": CONTRACT_COMPILER_VERSION,
        "standard_api_version": STANDARD_API_VERSION,
        "type_aliases": data["type_aliases"],
        "roles": data["roles"],
        "contracts": data["contracts"],
        "pairs": data["pairs"],
        "checker_models": models,
        "checker_only_roots": data["checker_only_roots"],
        "shadowed_symbols": sorted(hidden),
        "symbol_origins": {str(name): str(status) for name, status in origins.items()},
    }
    return _canonical_bytes(payload)


def _builtin_root_universe() -> List[str]:
    """Every packaged executable root name that must carry an origin status.

    The universe spans contract symbols, role buckets, pair endpoints,
    checker model names and the checker-only packaged roots (``delete``,
    ``bcopy`` style): a root without proven origin is denied, so the deny set
    reaches raw-bucket checkers exactly as far as the executable catalog.
    """

    data = _builtin_effect_data()
    names = {str((row.get("symbol") or {}).get("name") or "") for row in data["contracts"]}
    for names_by_attr in data["roles"].values():
        names.update(str(name) for name in names_by_attr)
    for row in data["pairs"]:
        for endpoint in ("acquire", "release"):
            names.add(str((row.get(endpoint) or {}).get("name") or ""))
    for rows in data["checker_models"].values():
        names.update(str(row.get("name") or "") for row in rows if isinstance(row, dict))
    names.update(str(name) for name in data["checker_only_roots"])
    names.discard("")
    return sorted(names)


# ── Exact-scope currency (scoped queries only) ──


def _pinned_context_record(
    scoped_index: ScopedCodeIndex, scope: InstanceScope
) -> Optional[Dict[str, Any]]:
    try:
        contexts = scoped_index.get_build_contexts()
    except Exception:
        return None
    for context in contexts if isinstance(contexts, list) else []:
        if not isinstance(context, dict):
            continue
        if str(context.get("build_context_id") or "") == scope.build_context_id:
            return dict(context)
    return None


def _entry_receipt_problem(scoped_index: ScopedCodeIndex, scope: InstanceScope) -> str:
    """Whether the pinned entry holds a complete exact native receipt."""

    if not scope.usr:
        return "unknown_entry_usr"
    try:
        facts = scoped_index.get_function_program_facts(scope.usr, scope.source)
    except Exception:
        return "entry_program_facts_unavailable"
    if not isinstance(facts, Mapping) or not facts.get("complete"):
        reason = str(facts.get("reason") or "") if isinstance(facts, Mapping) else ""
        return reason or "instance_facts_incomplete"
    identity = facts.get("function_identity")
    identity = identity if isinstance(identity, Mapping) else {}
    if str(identity.get("usr") or "") != scope.usr:
        return "entry_identity_unverified"
    return ""


# ── Per-root builtin origin (R24 S01-R24-P1-03) ──


def _call_origin_receipts(
    scoped_index: ScopedCodeIndex, scope: InstanceScope
) -> List[Tuple[str, Dict[str, Any]]]:
    """Exact-context native call receipts of the pinned build, by target name.

    The receipts come from the content-bound exact-context store — the same
    store the scoped facade serves its per-instance member facts from — keyed
    by the pinned build context id.  No navigation projection, project-wide
    traversal or unscoped classification is involved.  Each target carries
    the native ``is_system_header`` origin flag recorded by the actual
    compilation; a missing or falsy flag is never treated as system.
    """

    base = scoped_index.base_index()
    getter = getattr(base, "get_compilation_facts", None)
    if not callable(getter) or not scope.build_context_id:
        return []
    rows: Any
    try:
        rows = getter(scope.build_context_id, kinds=("call",))
    except TypeError:
        try:
            rows = [
                row
                for row in (getter(scope.build_context_id) or [])
                if isinstance(row, dict) and row.get("kind") == "call"
            ]
        except Exception:
            return []
    except Exception:
        return []
    receipts: List[Tuple[str, Dict[str, Any]]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        target = row.get("target")
        if not isinstance(target, dict):
            continue
        name = str(target.get("qualified_name") or target.get("name") or "")
        if name:
            receipts.append((name, target))
    return receipts


def _user_include_roots(command: Mapping[str, Any]) -> Tuple[List[Path], bool]:
    """Resolve the supported command grammar; retain unknown surfaces as gaps.

    Short include flags accept split and bare-joined values, including
    ``-isystem/path``. Existing equals spellings are conservatively denied
    too. Source-local/quoted lookup and environment include paths also count
    as user roots. Responses, forwarding, overlays, toolchain overrides,
    custom sysroots, malformed paths and unsupported include grammars cannot
    supply an origin witness in this host-installation slice.
    """

    arguments = command.get("arguments")
    directory = Path(str(command.get("directory") or ""))
    if not isinstance(arguments, list) or not arguments or not directory.is_absolute():
        return [], True
    roots: List[Path] = []
    unverifiable = False

    def add_root(value: str) -> None:
        nonlocal unverifiable
        if not value or value.startswith("-") or "\x00" in value:
            unverifiable = True
            return
        path = Path(value)
        try:
            roots.append((path if path.is_absolute() else directory / path).resolve(strict=True))
        except (OSError, ValueError, RuntimeError):
            unverifiable = True

    add_root(str(directory))
    source = Path(str(command.get("source") or ""))
    if source.is_absolute():
        add_root(str(source.parent))
    else:
        unverifiable = True
    environment = command.get("environment") or {}
    if not isinstance(environment, Mapping):
        return roots, True
    for key in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH"):
        if environment.get(key):
            for value in str(environment[key]).split(os.pathsep):
                add_root(value or str(directory))
    if any(
        environment.get(key) for key in ("SDKROOT", "INCLUDE", "GCC_EXEC_PREFIX", "COMPILER_PATH")
    ):
        unverifiable = True
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if not isinstance(argument, str):
            unverifiable = True
            index += 1
            continue
        if argument.startswith("@") or argument.startswith(_UNSUPPORTED_INCLUDE_SURFACES):
            unverifiable = True
            index += 1
            continue
        value = ""
        matched = False
        for flag in _USER_INCLUDE_FLAGS:
            if argument == flag:
                index += 1
                if index < len(arguments) and isinstance(arguments[index], str):
                    value = arguments[index]
                    index += 1
                matched = True
            elif argument.startswith(flag + "="):
                value = argument[len(flag) + 1 :]
                index += 1
                matched = True
            elif flag != "--sysroot" and argument.startswith(flag) and len(argument) > len(flag):
                value = argument[len(flag) :]
                index += 1
                matched = True
            if matched:
                if flag in {"--sysroot", "-isysroot"}:
                    unverifiable = True
                break
        if matched:
            add_root(value)
            continue
        if argument.startswith(("-i", "--sysroot")):
            unverifiable = True
        index += 1
    return roots, unverifiable


def _trusted_host_header(path: Path) -> bool:
    """The explicit host installation is the trust root, not a basename.

    Do not follow a project-controlled symlink into or out of this root, or
    accept a writable installation. Other platform layouts need their own
    verifier; they cannot inherit this one by spelling a header stdlib.h.
    """

    if sys.platform != "linux":
        return False
    try:
        if path.resolve(strict=True) != path or not path.is_file():
            return False
        for component in (path, *path.parents):
            info = component.lstat()
            if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _standard_declaration_files(
    scoped_index: ScopedCodeIndex, scope: InstanceScope, pinned: Mapping[str, Any]
) -> frozenset[Path]:
    """Positive current exact-build source witness for the bounded glibc roots.

    Read only the pinned native store and on-disk identities. Never execute a
    command from a saved manifest. A target flag, ABI, USR, header name/path
    or absent user-root match alone cannot mint this witness. The actual
    include resolution must name the trusted physical installation, both
    glibc headers must have been read by this build with current digests,
    the native target/search receipts must agree, and the emitting binary
    and recorded shared libraries must still match their identities.
    """

    target = pinned.get("target")
    if not isinstance(target, Mapping):
        return frozenset()
    if (
        target.get("target.libc") != "glibc"
        or type(target.get("target.pointer_bits")) is not int
        or target["target.pointer_bits"] != 64
        or not re.fullmatch(
            r"(?:x86_64|aarch64)-[A-Za-z0-9_-]*linux-gnu", str(target.get("target.triple") or "")
        )
    ):
        return frozenset()
    probes = pinned.get("include_probes")
    if not isinstance(probes, Mapping) or probes.get("version") != "zscope.include-probes.v1":
        return frozenset()
    searches = probes.get("search_directories")
    if not isinstance(searches, list) or "/usr/include" not in searches:
        return frozenset()
    tool = pinned.get("tool")
    if not isinstance(tool, Mapping):
        return frozenset()
    capability, binary = tool.get("capability"), tool.get("binary")
    if (
        not isinstance(capability, Mapping)
        or capability.get("protocol") != "zscope.clang-facts.v2"
        or capability.get("target_origin_version") != 1
        or not isinstance(binary, Mapping)
        or not Path(str(binary.get("path") or "")).is_absolute()
        or not isinstance(binary.get("sha256"), str)
        or not _is_sha256_hex(binary["sha256"])
        or file_digest(Path(binary["path"])) != binary["sha256"]
    ):
        return frozenset()
    libraries = binary.get("shared_libraries")
    if (
        binary.get("unverified_loader_run")
        or not isinstance(libraries, dict)
        or (libraries and not dependencies_current(libraries))
    ):
        return frozenset()
    dependencies = pinned.get("dependencies")
    if not isinstance(dependencies, Mapping):
        return frozenset()
    for header in (_HOST_GLIBC_STDLIB, _HOST_GLIBC_FEATURES):
        digest = dependencies.get(str(header))
        if (
            not _trusted_host_header(header)
            or not isinstance(digest, str)
            or not _is_sha256_hex(digest)
            or file_digest(header) != digest
        ):
            return frozenset()
    getter = getattr(scoped_index.base_index(), "get_compilation_facts", None)
    if not callable(getter):
        return frozenset()
    try:
        includes = getter(scope.build_context_id, kinds=("include",))
        for row in includes or []:
            if not isinstance(row, Mapping) or row.get("kind") != "include":
                continue
            resolved = Path(str(row.get("target_file") or ""))
            location = row.get("location")
            if not isinstance(location, Mapping):
                continue
            including = str(location.get("file") or "")
            if (
                resolved.is_absolute()
                and resolved.resolve(strict=True) == _HOST_GLIBC_STDLIB
                and Path(including).is_absolute()
                and isinstance(dependencies.get(including), str)
                and _is_sha256_hex(dependencies[including])
            ):
                return frozenset({_HOST_GLIBC_STDLIB})
    except Exception:
        return frozenset()
    return frozenset()


def _builtin_origin_status(
    scoped_index: ScopedCodeIndex,
    name: str,
    receipts: List[Tuple[str, Dict[str, Any]]],
    include_roots: List[Path],
    has_response_file: bool,
    standard_files: frozenset[Path],
) -> str:
    """Origin status of one packaged builtin root inside the pinned build.

    Project definitions win first: any recorded ``program_function`` body,
    or any non-miss program-facts answer, denies the builtin for this build.
    Otherwise the root is authorized only when every pinned-build call
    receipt for it proves the exact standard declaration: a system-header
    classification, external linkage, no TU definition, the C native USR of
    the root, the platform's canonical signature and a declaration file the
    build command does not reach through user-controlled include paths, and
    an independent positive source witness for that exact physical standard
    declaration file. A
    missing receipt, a non-system or user-controlled declaration, a
    mismatched signature or identity, an unprovable ABI, a response file or
    a failed query all deny it — never a name, basename or bare boolean.
    """

    try:
        facts = scoped_index.get_function_program_facts(name, "")
    except Exception:
        return ORIGIN_QUERY_FAILED
    if not isinstance(facts, Mapping):
        return ORIGIN_QUERY_FAILED
    bodies = [row for row in (facts.get("functions") or []) if isinstance(row, dict)]
    if bodies:
        return ORIGIN_PROJECT_DEFINED
    reason = str(facts.get("reason") or "")
    if reason not in {"", "function_identity_not_found"}:
        return ORIGIN_AMBIGUOUS_IDENTITY
    matching = [target for receipt_name, target in receipts if receipt_name == name]
    if not matching:
        return ORIGIN_NO_RECEIPT
    if any(target.get("is_system_header") is not True for target in matching):
        return ORIGIN_NON_SYSTEM_RECEIPT
    expected_signature = _VERIFIED_STANDARD_ABI.get(name)
    if expected_signature is None:
        return ORIGIN_ABI_UNPROVEN
    if has_response_file:
        return ORIGIN_UNVERIFIABLE_COMMAND
    for target in matching:
        if target.get("has_definition") is True:
            return ORIGIN_PROJECT_DEFINED
        if target.get("external_linkage") is not True:
            return ORIGIN_IDENTITY_MISMATCH
        if str(target.get("usr") or target.get("referenced_usr") or "") != (_C_USR_PREFIX + name):
            return ORIGIN_IDENTITY_MISMATCH
        if str(target.get("canonical_signature") or target.get("signature") or "") != (
            expected_signature
        ):
            return ORIGIN_SIGNATURE_MISMATCH
        declaration = target.get("declaration")
        declaration = declaration if isinstance(declaration, Mapping) else {}
        declared = str(declaration.get("file") or "")
        if not declared or not Path(declared).is_absolute():
            return ORIGIN_IDENTITY_MISMATCH
        try:
            # Classification of a user-root denial does not require the
            # claimed file to exist. Positive authority still requires exact
            # membership in standard_files, whose physical files/digests were
            # independently verified above; this is not an existence fallback.
            resolved = Path(declared).resolve()
        except (OSError, ValueError, RuntimeError):
            return ORIGIN_IDENTITY_MISMATCH
        if any(resolved == root or root in resolved.parents for root in include_roots):
            return ORIGIN_USER_INCLUDE_DECLARATION
        if resolved not in standard_files:
            return ORIGIN_STANDARD_SOURCE_UNPROVEN
    return ORIGIN_SYSTEM_RECEIPT


# ── Snapshot assembly and verification ──


def _row_is_inferred(row: Mapping[str, Any]) -> bool:
    """Workbook inference marker, mirroring the workbook's own classification."""

    if str(row.get("source") or "").startswith("inferred"):
        return True
    intents = str(row.get("intents") or "")
    return intents.lstrip().startswith("[inferred:")


def _snapshot_digest(
    *,
    scope: InstanceScope,
    dependencies: SemanticsDependencies,
    workbook_sha256: str,
    effect_payload: FrozenJSON,
    advisory_payload: FrozenJSON,
    excluded_rows: Tuple[FrozenJSON, ...],
) -> str:
    value = _canonical_bytes(
        {
            "schema": INSTANCE_SEMANTICS_SCHEMA,
            "authority_policy": AUTHORITY_POLICY,
            "scope": scope.to_payload(),
            "dependencies": {
                "compiler_version": dependencies.compiler_version,
                "standard_api_version": dependencies.standard_api_version,
                "builtin_payload_sha256": dependencies.builtin_payload_sha256,
                "business_answers_sha256": dependencies.business_answers_sha256,
                "effective_policy_sha256": dependencies.effective_policy_sha256,
            },
            "workbook_sha256": workbook_sha256,
            "effect_sha256": _sha256_hex(effect_payload),
            "advisory_sha256": _sha256_hex(advisory_payload),
            "excluded_row_sha256": [_sha256_hex(row) for row in excluded_rows],
        }
    )
    return _sha256_hex(value)


def _verify_snapshot(snapshot: InstanceSemanticsSnapshot) -> None:
    """Fail closed unless the factory issued exactly this snapshot object.

    Provenance comes first: only objects minted by
    :func:`build_instance_semantics` in this process carry authority, so a
    reconstructed snapshot with forged content — even with a self-consistently
    recomputed digest and genuine labels — is rejected before any payload is
    parsed.  The digest and label checks remain as integrity boundaries.
    """

    if snapshot.schema != INSTANCE_SEMANTICS_SCHEMA:
        raise ValueError("instance semantics schema mismatch")
    if snapshot.authority_policy != AUTHORITY_POLICY:
        raise ValueError("instance semantics authority policy mismatch")
    _verify_factory_issued(snapshot)
    expected = _snapshot_digest(
        scope=snapshot.scope,
        dependencies=snapshot.dependencies,
        workbook_sha256=snapshot.workbook_sha256,
        effect_payload=snapshot.effect_payload,
        advisory_payload=snapshot.advisory_payload,
        excluded_rows=snapshot.excluded_rows,
    )
    if expected != snapshot.digest:
        raise ValueError("instance semantics digest mismatch")


def build_instance_semantics(
    *,
    scope: InstanceScope,
    scoped_index: ScopedCodeIndex,
    workbook: FrozenWorkbookRows,
    dependencies: SemanticsDependencies,
) -> Union[InstanceSemanticsSnapshot, SemanticsUnavailable]:
    """Freeze builtin effects and manual advisory for one exact instance.

    Returns ``SemanticsUnavailable`` — never a name-navigation fallback — when
    the scope is not exact, the scoped index does not bind this exact scope,
    the pinned build is not current under the full context-input verification,
    the entry lacks a complete exact native receipt, or the dependency
    fingerprint does not match the current packaged builtin factory.  Builtin
    roots without positive in-build system-origin evidence are denied inside
    the snapshot (not turned into an unavailable) so the denial and its
    diagnostics travel with the instance.
    """

    if not isinstance(scoped_index, ScopedCodeIndex):
        return SemanticsUnavailable("scoped_index_required")
    if not isinstance(workbook, FrozenWorkbookRows):
        return SemanticsUnavailable("frozen_workbook_rows_required")
    if not isinstance(dependencies, SemanticsDependencies):
        return SemanticsUnavailable("semantics_dependencies_required")
    if not scope.build_context_id or not scope.usr or not scope.identity:
        return SemanticsUnavailable("inexact_instance_scope")
    if scoped_index.scope != scope:
        return SemanticsUnavailable("scope_mismatch")

    # -- currency: dependency digests plus the full context-input check ----
    status = scoped_index.dependencies_current_status()
    if status != "current":
        return SemanticsUnavailable(f"dependencies_not_current:{status}")
    pinned = _pinned_context_record(scoped_index, scope)
    if pinned is None:
        return SemanticsUnavailable("unknown_build_context")
    input_status = context_input_status(pinned)
    if input_status != "current":
        return SemanticsUnavailable(f"context_inputs_not_current:{input_status}")

    # -- exact native entry receipt ---------------------------------------
    problem = _entry_receipt_problem(scoped_index, scope)
    if problem:
        return SemanticsUnavailable(f"entry_receipt_unavailable:{problem}")

    # -- dependency fingerprint must name the current packaged builtin ----
    for label, value in (
        ("builtin_payload_sha256", dependencies.builtin_payload_sha256),
        ("business_answers_sha256", dependencies.business_answers_sha256),
        ("effective_policy_sha256", dependencies.effective_policy_sha256),
    ):
        if not _is_sha256_hex(value):
            return SemanticsUnavailable(f"invalid_dependency_digest:{label}")
    if not _is_sha256_hex(workbook.workbook_sha256):
        return SemanticsUnavailable("invalid_workbook_digest")
    fingerprint = builtin_semantics_fingerprint()
    if dependencies.compiler_version != fingerprint["compiler_version"]:
        return SemanticsUnavailable("stale_compiler_version")
    if dependencies.standard_api_version != fingerprint["standard_api_version"]:
        return SemanticsUnavailable("stale_standard_api_version")
    if dependencies.builtin_payload_sha256 != fingerprint["builtin_payload_sha256"]:
        return SemanticsUnavailable("stale_builtin_payload")

    # -- workbook rows: strict decode, then manual advisory vs excluded ---
    try:
        external = [_strict_json_loads(row) for row in workbook.external_rows]
        paired = [_strict_json_loads(row) for row in workbook.paired_rows]
        other = [_strict_json_loads(row) for row in workbook.other_advisory_rows]
    except ValueError:
        return SemanticsUnavailable("workbook_row_not_canonical_json")
    for row in (*external, *paired, *other):
        if not isinstance(row, dict):
            return SemanticsUnavailable("workbook_row_not_an_object")

    manual_external: List[JSONValue] = []
    manual_paired: List[JSONValue] = []
    manual_other: List[JSONValue] = []
    excluded_rows: List[FrozenJSON] = []
    for group, manual_target in (
        (external, manual_external),
        (paired, manual_paired),
        (other, manual_other),
    ):
        for row in group:
            if _row_is_inferred(row):
                excluded_rows.append(
                    _canonical_bytes(
                        {
                            "reason": INFERRED_EXCLUSION_REASON,
                            "authority_policy": AUTHORITY_POLICY,
                            "row": row,
                        }
                    )
                )
            else:
                manual_target.append(row)

    advisory_payload = _canonical_bytes(
        {
            "schema": INSTANCE_SEMANTICS_SCHEMA,
            "authority_policy": AUTHORITY_POLICY,
            "advisory_authority": ADVISORY_AUTHORITY,
            "native_instance_verified": False,
            "builtin_source_authority": "packaged_factory_only",
            "external_functions": manual_external,
            "paired_functions": manual_paired,
            "other_advisory": manual_other,
            "excluded_inferred_count": len(excluded_rows),
            "exclusion_reason": INFERRED_EXCLUSION_REASON,
        }
    )

    # -- builtin authority: per-root origin inside this exact build -------
    receipts = _call_origin_receipts(scoped_index, scope)
    include_roots, has_response_file = _user_include_roots(pinned.get("command") or {})
    standard_files = (
        _standard_declaration_files(scoped_index, scope, pinned)
        if any(name in _VERIFIED_STANDARD_ABI for name, _target in receipts)
        else frozenset()
    )
    origins = {
        name: _builtin_origin_status(
            scoped_index, name, receipts, include_roots, has_response_file, standard_files
        )
        for name in _builtin_root_universe()
    }
    denied = sorted(name for name, status in origins.items() if status not in _ALLOWED_ORIGINS)
    effect_payload = _effect_payload(denied, origins)

    return _register_issued(
        InstanceSemanticsSnapshot(
            schema=INSTANCE_SEMANTICS_SCHEMA,
            authority_policy=AUTHORITY_POLICY,
            scope=scope,
            dependencies=dependencies,
            workbook_sha256=workbook.workbook_sha256,
            effect_payload=effect_payload,
            advisory_payload=advisory_payload,
            excluded_rows=tuple(excluded_rows),
            digest=_snapshot_digest(
                scope=scope,
                dependencies=dependencies,
                workbook_sha256=workbook.workbook_sha256,
                effect_payload=effect_payload,
                advisory_payload=advisory_payload,
                excluded_rows=tuple(excluded_rows),
            ),
        )
    )


# ── Consumer-side materialization ──


def _pair_from_row(row: Mapping[str, Any]) -> Optional[ApiPair]:
    acquire = row.get("acquire")
    release = row.get("release")
    if not isinstance(acquire, Mapping) or not isinstance(release, Mapping):
        return None
    return ApiPair(
        SymbolIdentity.from_value(acquire),
        SymbolIdentity.from_value(release),
        row.get("conditions") or [],
        str(row.get("source") or ""),
        row.get("evidence") or [],
    )


def _validate_effect_payload(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("effect payload is not a JSON object")
    if payload.get("schema") != INSTANCE_SEMANTICS_SCHEMA:
        raise ValueError("effect payload schema mismatch")
    if payload.get("authority_policy") != AUTHORITY_POLICY:
        raise ValueError("effect payload authority policy mismatch")
    if payload.get("builtin_source") != DEFAULT_SEMANTICS_SOURCE:
        raise ValueError("effect payload builtin source mismatch")
    aliases = payload.get("type_aliases")
    if not isinstance(aliases, dict) or not all(
        isinstance(alias, str) and isinstance(base, str) for alias, base in aliases.items()
    ):
        raise ValueError("effect payload type aliases malformed")
    roles = payload.get("roles")
    if not isinstance(roles, dict):
        raise ValueError("effect payload roles malformed")
    for attr, names in roles.items():
        if attr not in CATEGORY_BY_ATTR or not isinstance(names, dict):
            raise ValueError(f"effect payload role bucket {attr!r} malformed")
        for name, sources in names.items():
            if not isinstance(name, str) or not isinstance(sources, list) or not sources:
                raise ValueError(f"effect payload role {attr}:{name!r} malformed")
            if any(source != DEFAULT_SEMANTICS_SOURCE for source in sources):
                raise ValueError("effect payload role source is not packaged builtin")
    contracts = payload.get("contracts")
    if not isinstance(contracts, list) or not contracts:
        raise ValueError("effect payload contracts malformed")
    for row in contracts:
        if not isinstance(row, dict) or str(row.get("source") or "") != DEFAULT_SEMANTICS_SOURCE:
            raise ValueError("effect payload contract is not packaged builtin")
    pairs = payload.get("pairs")
    if not isinstance(pairs, list):
        raise ValueError("effect payload pairs malformed")
    for row in pairs:
        if not isinstance(row, dict) or str(row.get("source") or "") != DEFAULT_SEMANTICS_SOURCE:
            raise ValueError("effect payload pair is not packaged builtin")
    shadowed = payload.get("shadowed_symbols")
    if not isinstance(shadowed, list) or not all(isinstance(name, str) for name in shadowed):
        raise ValueError("effect payload shadowed symbols malformed")
    origins = payload.get("symbol_origins")
    if not isinstance(origins, dict) or not all(
        isinstance(name, str) and isinstance(status, str) for name, status in origins.items()
    ):
        raise ValueError("effect payload symbol origins malformed")
    checker_only = payload.get("checker_only_roots")
    if not isinstance(checker_only, list) or not all(
        isinstance(name, str) for name in checker_only
    ):
        raise ValueError("effect payload checker-only roots malformed")
    models = payload.get("checker_models")
    if not isinstance(models, dict) or not all(
        key in models and isinstance(models[key], list)
        for key in ("resource_models", "lock_models")
    ):
        raise ValueError("effect payload checker models malformed")


def _payload_catalog_names(payload: Mapping[str, Any]) -> set:
    """The full packaged root universe a payload must carry origins for."""

    names = {str((row.get("symbol") or {}).get("name") or "") for row in payload["contracts"]}
    for names_by_attr in payload["roles"].values():
        names.update(str(name) for name in names_by_attr)
    for row in payload["pairs"]:
        for endpoint in ("acquire", "release"):
            names.add(str((row.get(endpoint) or {}).get("name") or ""))
    for rows in payload["checker_models"].values():
        names.update(str(row.get("name") or "") for row in rows if isinstance(row, dict))
    names.update(str(name) for name in payload["checker_only_roots"])
    names.discard("")
    return names


def materialize_effect_semantics(
    snapshot: InstanceSemanticsSnapshot,
) -> Tuple[LocalPatternSemantics, Dict[str, JSONValue]]:
    """Rebuild independent effect semantics from the factory-issued payload.

    Every call constructs a fresh ``LocalPatternSemantics`` with its own
    ``ContractRegistry`` from the snapshot's canonical bytes — consumers never
    share mutable registries, role maps or pair lists.  Denied roots are
    excluded from the local contracts, pairs and role buckets entirely, and
    the shadow set is installed so the existing ``add_api`` and
    ``ContractRegistry.find`` guards keep denying them at every query.  The
    returned overlay carries ``shadowed_symbols``/``symbol_origins`` and omits
    denied executable contracts, pairs and checker models, so overlay-only
    consumers that merge it into an empty or default registry keep the
    denial at every guarded query.  A snapshot that the factory did not
    issue in this process — or whose digest or labels do not verify — raises
    ``ValueError``; it never materializes a partial guess.
    """

    _verify_snapshot(snapshot)
    payload = _strict_json_loads(snapshot.effect_payload)
    _validate_effect_payload(payload)

    shadowed = {str(name) for name in payload["shadowed_symbols"]}
    origins = {str(name): str(status) for name, status in payload["symbol_origins"].items()}
    catalog = _payload_catalog_names(payload)
    if set(origins) != catalog:
        raise ValueError("effect payload origin map does not cover the packaged catalog")
    derived_denied = {name for name, status in origins.items() if status not in _ALLOWED_ORIGINS}
    if shadowed != derived_denied:
        raise ValueError("effect payload deny set is inconsistent with its origin receipts")

    semantics = LocalPatternSemantics()
    semantics.type_aliases.update(
        {str(alias): str(base) for alias, base in payload["type_aliases"].items()}
    )
    # The shadow set is installed first: the replayed add_api below keeps the
    # existing guard that a denied builtin name never enters a role bucket,
    # and denied contracts/pairs/models are excluded outright so no consumer
    # query — guarded or raw — can regain them from this object.
    semantics.contracts.shadowed_symbols = shadowed
    for row in payload["contracts"]:
        contract = ApiContract.from_row(
            {"contract": row, "kind": row.get("role"), "source": row.get("source")}
        )
        if contract is None or contract.source != DEFAULT_SEMANTICS_SOURCE:
            raise ValueError("effect payload contract is not packaged builtin")
        if contract.symbol.name in shadowed:
            continue
        semantics.contracts.add(contract)
    for attr, names in payload["roles"].items():
        for name, sources in names.items():
            if name in shadowed:
                continue
            for source in sources:
                semantics.add_api(CATEGORY_BY_ATTR[attr], str(name), source)
    for row in payload["pairs"]:
        pair = _pair_from_row(row)
        if pair is None or pair.source != DEFAULT_SEMANTICS_SOURCE:
            raise ValueError("effect payload pair is not packaged builtin")
        if pair.acquire.name in shadowed or pair.release.name in shadowed:
            continue
        if pair not in semantics.contracts.pairs:
            semantics.contracts.pairs.append(pair)

    overlay: Dict[str, Any] = {
        "builtin_source": DEFAULT_SEMANTICS_SOURCE,
        "contract_version": semantics.contracts.version,
        "shadowed_symbols": sorted(shadowed),
        "symbol_origins": dict(origins),
        "api_contracts": [contract.to_dict() for contract in semantics.contracts.contracts],
        "api_pairs": [pair.to_dict() for pair in semantics.contracts.pairs],
        "macro_models": [],
        "resource_models": [dict(row) for row in payload["checker_models"]["resource_models"]],
        "lock_models": [dict(row) for row in payload["checker_models"]["lock_models"]],
    }
    return semantics, overlay


# ── Scoped manual advisory rendering ──


def _advisory_row_kind(row: Mapping[str, Any]) -> str:
    """The workbook sheet a frozen advisory row belongs to.

    An explicit ``sheet`` tag wins when it names a known sheet; otherwise the
    row's own field shapes decide.  An unrecognized shape renders only under
    the conservative generic selector.
    """

    sheet = str(row.get("sheet") or "").strip().lower()
    if sheet in {"pointer_targets", "dispatcher", "module_lifecycle", "function_intents"}:
        return sheet
    if "pointer_location" in row:
        return "pointer_targets"
    if "dispatcher_name" in row:
        return "dispatcher"
    if "intents" in row or "caller_constraints" in row or "concurrency_group" in row:
        return "function_intents"
    if "symbol_name" in row and (
        "needs_finit" in row or "error_path_cleanup_required" in row or "kind" in row
    ):
        return "module_lifecycle"
    return ""


def _other_advisory_row_applies(
    kind: str,
    row: Mapping[str, Any],
    *,
    function_name: str,
    identifiers: set,
    source_text: str,
    file_path: str,
) -> bool:
    """Each sheet keeps its own real selector; foreign files never render.

    Pointer targets select on their ``scope`` glob plus pointer/target
    relevance, dispatchers and module-lifecycle rows on their ``file_path``
    glob plus their name/pair relevance, and function intents on exact
    symbol-name and file equality — mirroring the selectors the legacy
    user-config context already applies per sheet.
    """

    if kind == "pointer_targets":
        scope = str(row.get("scope") or "*")
        if not user_config_scope_matches(scope, file_path):
            return False
        location = str(row.get("pointer_location") or "")
        targets = set(parse_user_config_list(row.get("target_functions")))
        return (
            bool(location)
            and (location in source_text or location in identifiers)
            or bool(targets & identifiers)
        )
    if kind == "dispatcher":
        selector = str(row.get("file_path") or "*")
        if not user_config_scope_matches(selector, file_path):
            return False
        names = (
            str(row.get("dispatcher_name") or ""),
            str(row.get("handler_name") or ""),
            str(row.get("pair") or ""),
        )
        return any(name and name in identifiers for name in names)
    if kind == "module_lifecycle":
        selector = str(row.get("file_path") or "*")
        if not user_config_scope_matches(selector, file_path):
            return False
        members = (str(row.get("symbol_name") or ""), str(row.get("pair") or ""))
        return any(name and name in identifiers for name in members)
    if kind == "function_intents":
        if str(row.get("symbol_name") or "") != str(function_name or ""):
            return False
        row_file = str(row.get("file_path") or "")
        return not row_file or row_file == file_path
    # Unknown shape: every explicit file selector must match and some
    # identifier must intersect; ambiguous rows stay out of the context.
    for key in ("scope", "file_path"):
        selector = str(row.get(key) or "")
        if selector and not user_config_scope_matches(selector, file_path):
            return False
    tokens = {
        token
        for value in row.values()
        if isinstance(value, str)
        for token in _IDENTIFIER.findall(value)
    }
    return bool(tokens & identifiers)


def advisory_context(
    snapshot: InstanceSemanticsSnapshot,
    *,
    function_name: str,
    source_text: str,
    file_path: str,
) -> str:
    """Render the manual advisory context for one scoped entry.

    Only manual (non-inferred) workbook rows that the current function
    actually references — and whose sheet selector matches this entry's file —
    are rendered, and every section is labeled
    ``authority=name_only_advisory``: these are human descriptions, not
    native instance verification, and self-reported builtin source, USR,
    verification, ``confirmed`` status or ``effect_strength`` grant no
    executable contract, pair role or obligation discharge.  Excluded
    inferred rows appear only as an exclusion diagnostic, never as advisory
    or executable content.
    """

    _verify_snapshot(snapshot)
    payload = _strict_json_loads(snapshot.advisory_payload)
    if not isinstance(payload, dict) or payload.get("advisory_authority") != ADVISORY_AUTHORITY:
        raise ValueError("advisory payload authority mismatch")

    identifiers = set(_IDENTIFIER.findall(str(source_text or "")))
    identifiers.add(str(function_name or ""))
    text = str(source_text or "")
    parts: List[str] = []

    external_lines: List[str] = []
    for row in payload.get("external_functions") or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("func_name") or row.get("symbol_name") or "")
        if not name or name not in identifiers:
            continue
        fields = [
            str(row.get(field) or "").strip()
            for field in ("description", "memory_behavior", "concurrency_behavior", "contract")
        ]
        details = ", ".join(field for field in fields if field)
        origin = str(row.get("source") or "").strip()
        suffix = f" (workbook source: {origin})" if origin else ""
        external_lines.append(f"  {name}: {details}{suffix}" if details else f"  {name}{suffix}")
    if external_lines:
        parts.append(
            "[Instance manual advisory - authority=name_only_advisory]\n"
            "Workbook manual descriptions only; not native instance verification; "
            "self-reported source/USR/verification/confirmed/effect_strength grant no "
            "executable contract, pair role or obligation discharge.\n" + "\n".join(external_lines)
        )

    pair_lines: List[str] = []
    for row in payload.get("paired_functions") or []:
        if not isinstance(row, dict):
            continue
        acquire = str(row.get("acquire_func") or "")
        release = str(row.get("release_func") or "")
        if acquire not in identifiers and release not in identifiers:
            continue
        description = str(row.get("description") or "").strip()
        suffix = f" ({description})" if description else ""
        pair_lines.append(f"  {row.get('category', 'pair')}: {acquire} -> {release}{suffix}")
    if pair_lines:
        parts.append(
            "[Instance manual advisory pairs - authority=name_only_advisory]\n"
            "Manual pair descriptions only; no executable pair, role or release "
            "authorization is manufactured from them.\n" + "\n".join(pair_lines)
        )

    other_lines: List[str] = []
    for row in payload.get("other_advisory") or []:
        if not isinstance(row, dict):
            continue
        kind = _advisory_row_kind(row)
        if not _other_advisory_row_applies(
            kind,
            row,
            function_name=function_name,
            identifiers=identifiers,
            source_text=text,
            file_path=file_path,
        ):
            continue
        rendered = ", ".join(
            f"{key}={row[key]}"
            for key in sorted(row)
            if key != "source" and str(row.get(key) or "").strip()
        )
        if rendered:
            prefix = f"[{kind}] " if kind else ""
            other_lines.append(f"  {prefix}{rendered}")
    if other_lines:
        parts.append(
            "[Instance manual advisory rows - authority=name_only_advisory]\n"
            "Manual per-sheet rows only, filtered by their own file/scope/name "
            "selectors; never native instance verification.\n" + "\n".join(other_lines)
        )

    excluded_count = 0
    raw_count = payload.get("excluded_inferred_count")
    if isinstance(raw_count, int) and raw_count > 0:
        excluded_count = raw_count
    if excluded_count:
        parts.append(
            f"[Excluded inferred workbook rows: {excluded_count}]\n"
            f"  All inferred rows are excluded by authority policy {AUTHORITY_POLICY}; "
            "exact-looking build/USR equality or saved verification does not authorize "
            "inferred effects in this slice."
        )
    return "\n".join(parts)
