"""Project-wide deterministic primitive-wrapper discovery.

Discovery is intentionally a separate command.  It writes review candidates to
the project semantics document but never grants authority; normal scans only
consume rows that a human changed to ``confirmed``.
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Iterable, Mapping, Sequence

from ..common.utils import extract_json_blocks
from ..config.project_semantics import (
    DISCOVERY_SCHEMA,
    ProjectSemanticsStore,
    canonical_digest,
    compiled_project_contracts,
    file_sha256,
    stable_interface_id,
)
from ..core.candidates.function_facts import FunctionFactSummary, function_source_fragment
from ..retrieval.build_context import program_facts_result
from ..retrieval.instance_index import InstanceScope
from ..semantics.contracts import ApiContract, ContractRegistry
from ..semantics.instance_semantics import materialize_effect_semantics
from ..semantics.native_wrappers import (
    DISCOVERABLE_STANDARD_OPERATION_ROOTS,
    infer_native_wrapper,
)
from .instance_semantics_context import freeze_instance_context


_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
_CALL_TOKEN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_DEFINE = re.compile(
    r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]*(\(([^)]*)\))?[ \t]*"
    r"([^\n]*(?:\\\n[^\n]*)*)"
)
_SWITCH_CASE = re.compile(
    r"\bcase\s+(?P<guard>[A-Za-z_]\w*|[-+]?\d+)\s*:\s*(?P<body>.*?)(?=\bcase\b|\bdefault\b|\})",
    re.S,
)


def _project_file(root: Path, raw: str) -> Path:
    path = Path(str(raw or ""))
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _inside(root: Path, raw: str) -> bool:
    try:
        _project_file(root, raw).relative_to(root)
        return True
    except (OSError, ValueError):
        return False


def _inventory(
    code_index: Any, project_root: Path
) -> tuple[list[InstanceScope], list[str], dict[str, dict[str, Any]]]:
    contexts = list(code_index.get_build_contexts() or [])
    get_facts = getattr(code_index, "get_compilation_facts", None)
    if not callable(get_facts):
        return [], ["function_inventory_unavailable:native_fact_provider_missing"], {}
    scopes: dict[tuple[str, str], InstanceScope] = {}
    gaps: list[str] = []
    batches: dict[str, dict[str, Any]] = {}
    for context in contexts:
        if not isinstance(context, Mapping):
            continue
        build = str(context.get("build_context_id") or "")
        if not build:
            gaps.append("build_context_identity_missing")
            continue
        if str(context.get("status") or "") != "indexed" or not context.get(
            "dependencies_complete"
        ):
            gaps.append(f"build_context_not_current:{build}")
            continue
        try:
            rows = list(get_facts(build, kinds=("program_function", "program_access")) or [])
        except Exception as exc:
            gaps.append(f"function_inventory_unavailable:{build}:{type(exc).__name__}")
            continue
        batches[build] = {"context": dict(context), "rows": rows}
        for row in rows:
            owner = row.get("owner") if isinstance(row, Mapping) else None
            owner = owner if isinstance(owner, Mapping) else {}
            usr = str(owner.get("usr") or "")
            name = str(owner.get("name") or "")
            source = str(owner.get("file") or context.get("source") or "")
            if not usr or not name or not source or not _inside(project_root, source):
                continue
            scopes[(build, usr)] = InstanceScope(
                build_context_id=build,
                usr=usr,
                identity=f"{build}:{usr}",
                source=source,
                function_names=(name,),
                selected_by="project_primitive_discovery",
            )
    if not scopes:
        raise ValueError("primitive discovery found no exact project function instances")
    return (
        sorted(scopes.values(), key=lambda item: (item.build_context_id, item.source, item.usr)),
        gaps,
        batches,
    )


def _batch_function_work(
    scopes: Sequence[InstanceScope], batches: Mapping[str, Mapping[str, Any]]
) -> tuple[
    dict[str, list[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]],
    list[dict[str, Any]],
    list[str],
]:
    """Create every function summary from one native query per BuildContext."""

    by_identity = {(scope.build_context_id, scope.usr): scope for scope in scopes}
    work: dict[str, list[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]] = (
        defaultdict(list)
    )
    manifests: list[dict[str, Any]] = []
    gaps: list[str] = []
    source_cache: dict[Path, str] = {}
    for build, batch in batches.items():
        rows = [row for row in batch.get("rows", []) or [] if isinstance(row, Mapping)]
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            owner = row.get("owner")
            owner = owner if isinstance(owner, Mapping) else {}
            usr = str(owner.get("usr") or "")
            if usr:
                grouped[usr].append(dict(row))
        for usr, function_rows in grouped.items():
            scope = by_identity.get((build, usr))
            if scope is None:
                continue
            bodies = [row for row in function_rows if row.get("kind") == "program_function"]
            if len(bodies) != 1 or bodies[0].get("complete") is not True:
                gaps.append(f"program_facts_incomplete:{scope.identity}")
                continue
            body = bodies[0]
            owner = body.get("owner")
            owner = owner if isinstance(owner, Mapping) else {}
            callable_row = body.get("callable")
            callable_row = callable_row if isinstance(callable_row, Mapping) else {}
            name = str(owner.get("name") or (scope.function_names or (scope.usr,))[0])
            signature = str(
                callable_row.get("canonical_signature") or callable_row.get("signature") or ""
            )
            code, start_line, end_line = function_source_fragment(body, source_cache=source_cache)
            if not code:
                gaps.append(f"function_body_unavailable:{scope.identity}")
                continue
            # The full BuildContext contains dependency, header-search and tool
            # receipts shared by every function in the translation unit. It is
            # already checked by `_inventory` and retained by the scoped index;
            # copying it into every FunctionFactSummary made large-project
            # discovery quadratic in receipt size (Redis exceeded 12 GiB).
            # Function analyzers need the exact identity and completeness flag,
            # not another copy of the authenticated receipt.
            facts = program_facts_result([dict(row) for row in function_rows])
            facts["build_context_id"] = build
            facts["cross_tu_complete"] = False
            if facts.get("complete") is not True:
                gaps.append(f"program_facts_incomplete:{scope.identity}")
                continue
            impl = {
                "func_name": name,
                "index_name": name,
                "file": scope.source,
                "signature": signature,
                "code": code,
                "start_line": start_line,
                "end_line": end_line,
                "is_static": not bool(callable_row.get("external_linkage", True)),
                "truncated": False,
            }
            summary = FunctionFactSummary.create(
                analysis_unit_id=(
                    "primitive:" + canonical_digest([scope.build_context_id, scope.usr])[:24]
                ),
                build_context_id=scope.build_context_id,
                usr=scope.usr,
                function=name,
                file_path=scope.source,
                source=code,
                program_facts=facts,
            )
            manifests.append(summary.manifest())
            work[build].append((scope, impl, summary.facts_copy(), name, signature))
    for build_work in work.values():
        build_work.sort(key=lambda item: (item[0].source, item[0].usr))
    return dict(work), manifests, gaps


def _stream_function_work(code_index: Any, project_root: Path) -> tuple[
    list[InstanceScope],
    list[str],
    dict[str, list[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]],
    list[dict[str, Any]],
]:
    """Inventory and summarize one BuildContext at a time.

    Compilation facts can be several gigabytes on real projects.  Retaining
    every context's raw rows before building summaries multiplied peak memory
    by the number of intermediate projections.  This streaming path preserves
    the one-query-per-BuildContext contract while releasing raw rows after the
    corresponding summaries have been created.
    """

    contexts = list(code_index.get_build_contexts() or [])
    get_facts = getattr(code_index, "get_compilation_facts", None)
    if not callable(get_facts):
        return [], ["function_inventory_unavailable:native_fact_provider_missing"], {}, []
    scopes: dict[tuple[str, str], InstanceScope] = {}
    work: dict[str, list[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]] = (
        defaultdict(list)
    )
    manifests: list[dict[str, Any]] = []
    gaps: list[str] = []
    for context in contexts:
        if not isinstance(context, Mapping):
            continue
        build = str(context.get("build_context_id") or "")
        if not build:
            gaps.append("build_context_identity_missing")
            continue
        if str(context.get("status") or "") != "indexed" or not context.get(
            "dependencies_complete"
        ):
            gaps.append(f"build_context_not_current:{build}")
            continue
        try:
            rows = list(get_facts(build, kinds=("program_function", "program_access")) or [])
        except Exception as exc:
            gaps.append(f"function_inventory_unavailable:{build}:{type(exc).__name__}")
            continue
        build_scopes: dict[tuple[str, str], InstanceScope] = {}
        for row in rows:
            owner = row.get("owner") if isinstance(row, Mapping) else None
            owner = owner if isinstance(owner, Mapping) else {}
            usr = str(owner.get("usr") or "")
            name = str(owner.get("name") or "")
            source = str(owner.get("file") or context.get("source") or "")
            if not usr or not name or not source or not _inside(project_root, source):
                continue
            scope = InstanceScope(
                build_context_id=build,
                usr=usr,
                identity=f"{build}:{usr}",
                source=source,
                function_names=(name,),
                selected_by="project_primitive_discovery",
            )
            build_scopes[(build, usr)] = scope
            scopes[(build, usr)] = scope
        batch_work, batch_manifests, batch_gaps = _batch_function_work(
            sorted(
                build_scopes.values(),
                key=lambda item: (item.build_context_id, item.source, item.usr),
            ),
            {build: {"context": dict(context), "rows": rows}},
        )
        work[build].extend(batch_work.get(build, []))
        manifests.extend(batch_manifests)
        gaps.extend(batch_gaps)
    if not scopes:
        raise ValueError("primitive discovery found no exact project function instances")
    for build_work in work.values():
        build_work.sort(key=lambda item: (item[0].source, item[0].usr))
    return (
        sorted(scopes.values(), key=lambda item: (item.build_context_id, item.source, item.usr)),
        gaps,
        dict(work),
        manifests,
    )


def _semantics_relevant_scopes(
    work: Mapping[
        str, Sequence[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]
    ],
    configured_roots: Sequence[Mapping[str, Any]],
    *,
    link_groups: Sequence[Sequence[str]] = (),
) -> tuple[list[InstanceScope], set[str]]:
    """Select candidate identities and one semantic authority scope per build.

    Builtin origin receipts are translation-unit/BuildContext properties:
    ``build_instance_semantics`` reads every native call receipt in that exact
    context.  Freezing every function in the same TU therefore repeated the
    same header/tool/dependency proof hundreds of times.  One exact function
    receipt per BuildContext establishes that shared authority; candidate
    identities remain separate and retain their own facts/USR.
    """

    from ..semantics.c_linux_catalog import active_contracts

    discovery_roles = {
        "allocator",
        "calloc",
        "reallocator",
        "deallocator",
        "lock",
        "unlock",
        "send_sink",
        "recv_source",
        "format_sink",
        "command_sink",
        "callback_register",
        "copy",
        "io_acquire",
        "io_release",
    }
    discovery_root_names = {
        str((row.get("symbol") or {}).get("name") or "")
        for row in active_contracts()
        if str(row.get("role") or "") in discovery_roles
        or (
            str(row.get("role") or "") == "standard_operation"
            and str((row.get("symbol") or {}).get("name") or "")
            in DISCOVERABLE_STANDARD_OPERATION_ROOTS
        )
    }

    configured_by_build: dict[str, set[str]] = defaultdict(set)
    for row in configured_roots:
        for variant in row.get("variants", []) or []:
            if isinstance(variant, Mapping):
                configured_by_build[str(variant.get("build_context_id") or "")].add(
                    str(variant.get("usr") or "")
                )
    selected: dict[tuple[str, str], InstanceScope] = {}
    callers_by_build: dict[str, dict[str, set[str]]] = {}
    plausible_by_build: dict[str, set[str]] = {}
    scopes_by_build: dict[str, dict[str, InstanceScope]] = {}
    direct_cxx_new_usrs = {
        scope.usr
        for functions in work.values()
        for scope, _impl, facts, _name, _signature in functions
        if any(
            isinstance(event, Mapping)
            and event.get("event_kind") == "acquire"
            and event.get("ast_kind") in {"CXXNewExpr", "CXXNewArrayExpr"}
            for body in facts.get("functions", []) or []
            if isinstance(body, Mapping)
            for event in body.get("events", []) or []
        )
        and any(
            isinstance(event, Mapping)
            and event.get("event_kind") == "return"
            and str(event.get("return_value") or "").strip().startswith("new ")
            for body in facts.get("functions", []) or []
            if isinstance(body, Mapping)
            for event in body.get("events", []) or []
        )
    }
    for build, functions in work.items():
        callers: dict[str, set[str]] = defaultdict(set)
        seeds = set(configured_by_build.get(build, set()))
        by_usr = {scope.usr: scope for scope, *_rest in functions}
        plausible_wrappers: set[str] = set(configured_by_build.get(build, set()))
        for scope, _impl, facts, _name, _signature in functions:
            body = next((row for row in facts.get("functions", []) if isinstance(row, Mapping)), {})
            events = [event for event in body.get("events", []) or [] if isinstance(event, Mapping)]
            calls = [event for event in events if event.get("event_kind") == "call"]
            if scope.usr in direct_cxx_new_usrs:
                seeds.add(scope.usr)
                plausible_wrappers.add(scope.usr)
            # Native wrapper inference is intentionally bounded for transitive
            # callers.  A direct call to a trusted root is different: the
            # later value-flow check still has to map the root's carrier to an
            # exact public parameter before it can emit a candidate.  Do not
            # discard such wrappers merely because their retry/error handling
            # makes the CFG larger than this scheduling heuristic (for
            # example a recv/send wrapper with an EINTR/EAGAIN loop).
            if len(events) <= 64 and len(calls) <= 8:
                plausible_wrappers.add(scope.usr)
            for event in calls:
                if not isinstance(event, Mapping) or event.get("event_kind") != "call":
                    continue
                raw_callee = event.get("callee")
                callee = raw_callee if isinstance(raw_callee, Mapping) else {}
                callee_usr = str(callee.get("usr") or callee.get("referenced_usr") or "")
                callee_name = str(callee.get("qualified_name") or callee.get("name") or "")
                if callee_usr:
                    callers[callee_usr].add(scope.usr)
                if callee_name in discovery_root_names:
                    seeds.add(scope.usr)
                # C++ ``new`` is a language primitive.  Its exact factory
                # definition may live in another compile command even when a
                # final link target has not yet been recorded.  Selecting the
                # direct caller here only creates a pending review candidate;
                # it does not authorize cross-TU execution semantics.
                if callee_usr in direct_cxx_new_usrs:
                    seeds.add(scope.usr)
                    plausible_wrappers.add(scope.usr)
        queue = list(seeds)
        while queue:
            callee_usr = queue.pop()
            if callee_usr in by_usr:
                selected[(build, callee_usr)] = by_usr[callee_usr]
            for caller_usr in callers.get(callee_usr, set()):
                key = (build, caller_usr)
                if (
                    key not in selected
                    and caller_usr in by_usr
                    and caller_usr in plausible_wrappers
                ):
                    selected[key] = by_usr[caller_usr]
                    queue.append(caller_usr)
        callers_by_build[build] = callers
        plausible_by_build[build] = plausible_wrappers
        scopes_by_build[build] = by_usr

    # Exact external USRs can cross compilation commands only through an
    # actual link record.  Propagate selected roots/candidates within each
    # closed group until stable; without such a record the per-BuildContext
    # result above is intentionally retained.
    for raw_group in link_groups:
        group = {str(value) for value in raw_group if str(value) in scopes_by_build}
        if len(group) <= 1:
            continue
        link_queue: list[tuple[str, str]] = [key for key in selected if key[0] in group]
        visited: set[tuple[str, str]] = set()
        while link_queue:
            callee_build, callee_usr = link_queue.pop()
            callee_key = (callee_build, callee_usr)
            if callee_key in visited:
                continue
            visited.add(callee_key)
            for caller_build in group:
                for caller_usr in callers_by_build.get(caller_build, {}).get(callee_usr, set()):
                    key = (caller_build, caller_usr)
                    if (
                        key not in selected
                        and caller_usr in scopes_by_build.get(caller_build, {})
                        and caller_usr in plausible_by_build.get(caller_build, set())
                    ):
                        selected[key] = scopes_by_build[caller_build][caller_usr]
                        link_queue.append(key)
    representatives: dict[str, InstanceScope] = {}
    for (build, _usr), scope in sorted(
        selected.items(), key=lambda item: (item[0][0], item[1].source, item[0][1])
    ):
        representatives.setdefault(build, scope)
    return (
        sorted(
            representatives.values(),
            key=lambda scope: (scope.build_context_id, scope.source, scope.usr),
        ),
        {scope.identity for scope in selected.values()},
    )


def _discovery_link_groups(
    code_index: Any, *, build_ids: Iterable[str]
) -> tuple[list[list[str]], list[str]]:
    """Return only closed, real link-record groups for discovery propagation."""

    known = {str(value) for value in build_ids if str(value)}
    groups: list[list[str]] = []
    gaps: list[str] = []
    linked_factory = getattr(code_index, "linked_targets", None)
    if not callable(linked_factory):
        return groups, ["primitive_discovery_link_records_unavailable"]
    try:
        linked = linked_factory()
    except Exception as exc:
        return groups, [f"primitive_discovery_link_records_unavailable:{type(exc).__name__}"]
    for index, target in enumerate(list(getattr(linked, "targets", []) or []), start=1):
        if not isinstance(target, Mapping):
            continue
        receipt = target.get("receipt")
        receipt = receipt if isinstance(receipt, Mapping) else {}
        target_id = str(receipt.get("target_id") or f"target-{index}")
        members = {str(value) for value in target.get("members", []) or [] if str(value)}
        missing = sorted(members - known)
        if missing:
            gaps.append(f"primitive_discovery_link_group_unclosed:{target_id}:" + ",".join(missing))
            continue
        if len(members) > 1:
            groups.append(sorted(members))
    return groups, gaps


def _object_path(binding: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(binding.get("kind") or "unknown")
    member_path = str(binding.get("member_path") or "")
    members = [member for member in re.split(r"(?:->|\.)", member_path) if member]
    if kind == "return":
        return {"root": "return", "phase": "post", "dereference": 0, "members": members}
    if kind == "global":
        return {
            "root": "global",
            "name": str(binding.get("global_name") or ""),
            "phase": "pre",
            "dereference": 0,
            "members": members,
        }
    return {
        "root": "argument",
        "index": int(binding.get("argument_index") or 0),
        "phase": "post" if kind == "output_argument" else "pre",
        "dereference": 1 if kind == "output_argument" else 0,
        "members": members,
    }


def _domain_for_role(role: str) -> str:
    if role in {
        "lock",
        "unlock",
        "lock_init",
        "lock_destroy",
        "lock_state",
        "lock_wait",
        "condition_init",
        "condition_destroy",
        "condition_signal",
    }:
        return "lock"
    if role in {"send_sink", "recv_source", "format_sink"}:
        return "taint"
    if role == "command_sink":
        return "process"
    if role == "copy":
        return "copy"
    if role in {"callback_register", "thread_create", "thread_release"}:
        return "callback"
    if role == "standard_operation":
        return "resource"
    return "resource"


def _interface_from_contract(
    contract: Mapping[str, Any],
    *,
    root: Path,
    source: str,
    code: str,
    build_context_id: str,
    usr: str,
    signature: str,
) -> dict[str, Any]:
    raw_symbol = contract.get("symbol")
    symbol: Mapping[str, Any] = raw_symbol if isinstance(raw_symbol, Mapping) else {}
    name = str(symbol.get("name") or "")
    normalized_file = _project_file(root, source)
    try:
        relative = normalized_file.relative_to(root).as_posix()
    except ValueError:
        relative = str(normalized_file).replace("\\", "/")
    contract_role = str(contract.get("role") or "")
    identifier = stable_interface_id("function", name, relative, usr)
    evidence_digest = canonical_digest(
        {
            "contract": contract,
            "source_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            "build_context_id": build_context_id,
            "usr": usr,
        }
    )
    pairs = []
    for target in contract.get("pairs", []) or []:
        target_name = str(target.get("name") if isinstance(target, Mapping) else target)
        if target_name:
            pairs.append(f"builtin:{target_name}")
    raw_verification = contract.get("verification")
    verification: Mapping[str, Any] = (
        raw_verification if isinstance(raw_verification, Mapping) else {}
    )
    return {
        "id": identifier,
        "primitive": False,
        "selector": {
            "kind": "function",
            "name": name,
            "file": relative,
            "signature": signature,
            "usr": usr,
        },
        "basis": "derived_wrapper",
        "status": "pending",
        "cases": deepcopy(contract.get("effect_cases") or []),
        "effects": [
            {
                "domain": _domain_for_role(contract_role),
                "role": contract_role,
                "operation": contract_role,
                "carrier": _object_path(contract.get("carrier") or {}),
                "resource_family": str(contract.get("resource_family") or ""),
                "strength": str(verification.get("effect_strength") or "must_under_guard"),
                "preconditions": deepcopy(contract.get("preconditions") or {"op": "true"}),
                "protocol": deepcopy(contract.get("protocol") or {}),
            }
        ],
        "otherwise": "unknown",
        "pairs": sorted(set(pairs)),
        "derived_from": sorted(
            {
                f"builtin:{str((delegate.get('symbol') or {}).get('name') or '')}"
                for delegate in contract.get("delegates", []) or []
                if isinstance(delegate, Mapping) and (delegate.get("symbol") or {}).get("name")
            }
        ),
        "evidence_summary": (
            f"Native CFG/value-flow composes {contract_role} through current exact calls."
        ),
        "evidence_ref": "",
        "evidence_digest": evidence_digest,
        "variants": [
            {
                "target_id": "",
                "build_context_id": build_context_id,
                "usr": usr,
                "signature": signature,
                "file": relative,
                "source_sha256": file_sha256(normalized_file),
                "evidence_sha256": evidence_digest,
                "native_input_hash": str(verification.get("native_input_hash") or evidence_digest),
                "identity_status": "exact",
            }
        ],
    }


def _merge_variants(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    meanings: dict[str, set[str]] = defaultdict(set)
    def meaning(row: Mapping[str, Any]) -> str:
        return canonical_digest({key: row.get(key) for key in
                                 ("cases", "effects", "pairs", "primitive", "basis")})
    for input_row in rows:
        meanings[str(input_row["id"])].add(meaning(input_row))
    merged: dict[str, dict[str, Any]] = {}
    for raw in rows:
        row = deepcopy(dict(raw))
        identifier = str(row["id"])
        if len(meanings[identifier]) > 1:
            # Two compiled variants of one symbol may have different effects.
            # Sharing a name/USR does not authorize the first variant's contract
            # for every other variant.
            identifier += ":" + meaning(row)[:12]
            row["id"] = identifier
        current = merged.get(identifier)
        if current is None:
            merged[identifier] = row
            continue
        variants = {
            (str(item.get("build_context_id") or ""), str(item.get("usr") or "")): item
            for item in current.get("variants", [])
            if isinstance(item, Mapping)
        }
        for variant in row.get("variants", []) or []:
            if isinstance(variant, Mapping):
                variants[
                    (str(variant.get("build_context_id") or ""), str(variant.get("usr") or ""))
                ] = deepcopy(dict(variant))
        current["variants"] = [variants[key] for key in sorted(variants)]
        current["evidence_digest"] = canonical_digest(
            [item.get("evidence_sha256") for item in current["variants"]]
        )
    return [merged[key] for key in sorted(merged)]


def _selector_matches_instance(
    selector: Mapping[str, Any],
    *,
    root: Path,
    scope: InstanceScope,
    name: str,
    signature: str,
) -> bool:
    if selector.get("kind") != "function":
        return False
    if selector.get("usr") and selector["usr"] != scope.usr:
        return False
    if selector.get("build_context_id") and selector["build_context_id"] != scope.build_context_id:
        return False
    expected_name = str(selector.get("name") or "")
    if expected_name != name:
        # A source-level user declaration normally names ``LockFile`` rather
        # than Clang's fully-qualified
        # ``leveldb::(anonymous namespace)::PosixEnv::LockFile``.  Permit that
        # spelling only as a selector match; _bind_configured_primitives still
        # requires the file/signature filters to collapse the result to one
        # exact native identity, so this never turns a short name into wildcard
        # execution authority.
        if "::" in expected_name or name.rsplit("::", 1)[-1] != expected_name:
            return False
    expected_file = str(selector.get("file") or "").replace("\\", "/")
    if expected_file:
        actual = _project_file(root, scope.source)
        try:
            actual_file = actual.relative_to(root).as_posix()
        except ValueError:
            actual_file = str(actual).replace("\\", "/")
        if actual_file != expected_file:
            return False
    expected_signature = " ".join(str(selector.get("signature") or "").split())
    return not expected_signature or expected_signature == " ".join(signature.split())


def _bind_configured_primitives(
    document: Mapping[str, Any],
    *,
    root: Path,
    work: Mapping[
        str, Sequence[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]
    ],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Bind user-declared primitive proposals to exact native instances."""

    result: list[dict[str, Any]] = []
    gaps: list[str] = []
    for raw in document.get("interfaces", []) or []:
        if not isinstance(raw, Mapping) or raw.get("primitive") is not True:
            continue
        if raw.get("status") == "rejected" or raw.get("basis") == "derived_wrapper":
            continue
        raw_selector = raw.get("selector")
        selector: Mapping[str, Any] = raw_selector if isinstance(raw_selector, Mapping) else {}
        if raw.get("basis") == "external_model":
            if (
                raw.get("status") == "confirmed"
                and selector.get("usr")
                and selector.get("signature")
                and selector.get("build_context_id")
            ):
                # Closed-source authority is an explicit user assumption.  It
                # cannot be rebound to a body that the project does not own,
                # but it still needs an exact per-build selector and remains
                # visibly external in the compiled registry/report.
                result.append(deepcopy(dict(raw)))
            else:
                gaps.append(f"external_model_identity_incomplete:{raw.get('id')}")
            continue
        matches = [
            (build, scope, name, signature)
            for build, functions in work.items()
            for scope, _impl, _facts, name, signature in functions
            if _selector_matches_instance(
                selector,
                root=root,
                scope=scope,
                name=name,
                signature=signature,
            )
        ]
        if not matches:
            gaps.append(f"configured_primitive_not_resolved:{raw.get('id')}")
            continue
        identities = {
            (_project_file(root, scope.source), scope.usr, name, signature)
            for _build, scope, name, signature in matches
        }
        if len(identities) != 1:
            gaps.append(f"configured_primitive_identity_ambiguous:{raw.get('id')}")
            continue
        item = deepcopy(dict(raw))
        variants = []
        for build, scope, _name, signature in matches:
            source = _project_file(root, scope.source)
            relative = source.relative_to(root).as_posix()
            source_sha = file_sha256(source)
            evidence_sha = canonical_digest(
                {
                    "project_semantics_id": item["id"],
                    "build_context_id": build,
                    "usr": scope.usr,
                    "signature": signature,
                    "source_sha256": source_sha,
                }
            )
            variants.append(
                {
                    "target_id": "",
                    "build_context_id": build,
                    "usr": scope.usr,
                    "signature": signature,
                    "file": relative,
                    "source_sha256": source_sha,
                    "evidence_sha256": evidence_sha,
                    "native_input_hash": evidence_sha,
                    "identity_status": "exact",
                }
            )
        item["selector"] = {
            **dict(selector),
            # Persist the canonical native spelling after a short configured
            # name has collapsed to one exact file/signature/USR identity.
            # Runtime rebind must not have to reinterpret the reviewer's
            # selector on every scan.
            "name": matches[0][2],
            "file": variants[0]["file"],
            "signature": variants[0]["signature"],
            "usr": variants[0]["usr"],
        }
        item["variants"] = variants
        item["status"] = "pending" if raw.get("status") != "confirmed" else "confirmed"
        item["evidence_summary"] = (
            "Configured project primitive rebound to current exact native function instances."
        )
        item["evidence_digest"] = canonical_digest(
            {"selector": item["selector"], "variants": variants}
        )
        result.append(item)
    return result, gaps


def _configured_discovery_contracts(
    document: Mapping[str, Any], candidates: Sequence[Mapping[str, Any]], build: str
) -> list[ApiContract]:
    """Compile exact user roots for discovery only; normal scan authority is unchanged."""

    by_id = {str(row.get("id") or ""): deepcopy(dict(row)) for row in document["interfaces"]}
    candidate_ids: set[str] = set()
    for candidate in candidates:
        item = deepcopy(dict(candidate))
        item["status"] = "confirmed"
        item["basis"] = "external_model"
        if not any(
            isinstance(case, Mapping) and case.get("effect") == "applies"
            for case in item.get("cases", []) or []
        ):
            # Discovery candidates deliberately begin with unknown effects so
            # a human must review them.  The recursive discovery closure still
            # needs a temporary executable view of the exact native edge.  It
            # exists only in this probe document; it is never written back and
            # does not grant scan authority.
            item["cases"] = [{"when": {"op": "true"}, "effect": "applies"}]
        identifier = str(item["id"])
        by_id[identifier] = item
        candidate_ids.add(identifier)
    probe = deepcopy(dict(document))
    probe["interfaces"] = list(by_id.values())
    contracts: list[ApiContract] = []
    for payload in compiled_project_contracts(probe, build_context_id=build):
        raw_verification = payload.get("verification")
        verification: Mapping[str, Any] = (
            raw_verification if isinstance(raw_verification, Mapping) else {}
        )
        if str(verification.get("project_semantics_id") or "") not in candidate_ids:
            continue
        contract = ApiContract.from_row(
            {"contract": payload, "kind": payload.get("role"), "source": payload.get("source")}
        )
        if contract is not None:
            contracts.append(contract)
    return contracts


def _reviewed_interface_definition_scopes(
    document: Mapping[str, Any],
    *,
    root: Path,
    work: Mapping[
        str, Sequence[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]
    ],
) -> tuple[list[InstanceScope], list[str]]:
    """Select exact definition scopes needed to rebind reviewed contracts."""

    by_usr: dict[str, list[InstanceScope]] = defaultdict(list)
    for functions in work.values():
        for scope, _impl, _facts, _name, _signature in functions:
            by_usr[scope.usr].append(scope)
    selected: dict[tuple[str, str], InstanceScope] = {}
    gaps: list[str] = []
    for row in document.get("interfaces", []) or []:
        if not isinstance(row, Mapping) or row.get("status") != "confirmed":
            continue
        selector = row.get("selector")
        selector = selector if isinstance(selector, Mapping) else {}
        if selector.get("kind") != "function":
            continue
        identifier = str(row.get("id") or "")
        usr = str(selector.get("usr") or "")
        name = str(selector.get("name") or "")
        raw_file = str(selector.get("file") or "")
        expected_file = _project_file(root, raw_file) if raw_file else None
        matches = [
            scope
            for scope in by_usr.get(usr, [])
            if (
                not name
                or name in scope.function_names
                or (
                    "::" not in name
                    and any(
                        candidate.rsplit("::", 1)[-1] == name for candidate in scope.function_names
                    )
                )
            )
            and (expected_file is None or _project_file(root, scope.source) == expected_file)
        ]
        if not matches:
            gaps.append(f"confirmed_interface_definition_unresolved:{identifier}")
            continue
        for scope in matches:
            selected[(scope.build_context_id, scope.usr)] = scope
    return (
        sorted(
            selected.values(),
            key=lambda scope: (scope.build_context_id, scope.source, scope.usr),
        ),
        gaps,
    )


def _exact_pointer_bindings(
    work: Mapping[
        str, Sequence[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]
    ],
) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for build, functions in work.items():
        for scope, impl, facts, _name, _signature in functions:
            body = next((row for row in facts.get("functions", []) if isinstance(row, Mapping)), {})
            for event in body.get("events", []) or []:
                if not isinstance(event, Mapping) or event.get("event_kind") != "call":
                    continue
                raw_callee = event.get("callee")
                callee: Mapping[str, Any] = raw_callee if isinstance(raw_callee, Mapping) else {}
                closed = (
                    callee.get("closed_targets")
                    if isinstance(callee.get("closed_targets"), Mapping)
                    else None
                )
                slot_usr = str(callee.get("usr") or "")
                if closed is None:
                    # A value-identity callee without a declaration-backed
                    # target is indirect but not statically closed.  This is
                    # a machine coverage gap, not a reviewable contract: the
                    # schema intentionally permits confirmation only for an
                    # exact non-empty target set.  Materialising one pending
                    # row per unresolved callsite made real projects ask a
                    # human to reject tens of thousands of propositions that
                    # could never be confirmed.
                    if slot_usr and str(callee.get("value_kind") or "") in {
                        "field",
                        "local",
                        "parameter",
                        "global",
                    }:
                        callsite = f"{build}:{scope.usr}:{event.get('event_id')}"
                        reason = f"indirect_call_target_set_unclosed:{callsite}"
                        gaps.append(reason)
                    continue
                targets = [
                    target for target in closed.get("targets", []) if isinstance(target, Mapping)
                ]
                target_usrs = sorted(
                    {str(target.get("usr") or "") for target in targets if target.get("usr")}
                )
                target_names = sorted(
                    {
                        str(target.get("qualified_name") or target.get("name") or "")
                        for target in targets
                        if target.get("qualified_name") or target.get("name")
                    }
                )
                if not slot_usr or not targets or len(target_usrs) != len(targets):
                    gaps.append(
                        f"indirect_call_identity_incomplete:{build}:{scope.usr}:{event.get('event_id')}"
                    )
                    continue
                callsite = f"{build}:{scope.usr}:{event.get('event_id')}"
                digest = canonical_digest([closed, event.get("location"), event.get("operation")])
                rows.append(
                    {
                        "id": stable_interface_id(
                            "function_pointer_slot",
                            callsite,
                            str(impl.get("file") or ""),
                            slot_usr,
                        ),
                        "status": "pending",
                        "file": str(impl.get("file") or "").replace("\\", "/"),
                        "callsite_id": callsite,
                        "build_context_id": build,
                        "caller_usr": scope.usr,
                        "slot_usr": slot_usr,
                        "slot_expression": str(closed.get("expression") or ""),
                        "target_names": target_names,
                        "target_usrs": target_usrs,
                        "attribution": "exact",
                        "source": "native_closed_const_target_set",
                        "evidence_summary": (
                            "Native AST proves a closed immutable function-pointer target set."
                        ),
                        "evidence_digest": digest,
                    }
                )
    return rows, gaps


def _dispatcher_candidates(
    work: Mapping[
        str, Sequence[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]
    ],
    *,
    eligible_handler_instances: set[tuple[str, str]] | None = None,
    root: Path | None = None,
) -> list[dict[str, Any]]:
    # The native/project fact stream can contain the same function instance
    # more than once (for example a base fact plus a completed type projection).
    # A dispatcher contract is identified by its exact BuildContext,
    # dispatcher USR, guard, and handler USR; repeated observations of that
    # identity are corroborating evidence, not distinct reviewer decisions.
    result_by_id: dict[str, dict[str, Any]] = {}
    evidence_by_id: dict[str, set[str]] = {}
    for build, functions in work.items():
        identities = {name: scope for scope, _impl, _facts, name, _signature in functions if name}
        for scope, impl, _facts, name, _signature in functions:
            code = str(impl.get("code") or "")
            for match in _SWITCH_CASE.finditer(code):
                guard = match.group("guard")
                calls = [
                    value
                    for value in _CALL_TOKEN.findall(match.group("body"))
                    if value in identities
                ]
                for handler_name in sorted(set(calls)):
                    handler = identities[handler_name]
                    if handler.usr == scope.usr:
                        continue
                    # Discovery is rooted in current built-in primitives and
                    # reviewer-declared project primitives. An arbitrary
                    # switch branch elsewhere in the project is not a
                    # semantic-interface candidate merely because it calls a
                    # function. Keep only dispatch edges whose exact handler
                    # instance was itself derived into the rooted interface
                    # set. ``None`` remains useful for focused extractor tests,
                    # while production always supplies the set.
                    if (
                        eligible_handler_instances is not None
                        and (build, handler.usr) not in eligible_handler_instances
                    ):
                        continue
                    digest = canonical_digest(
                        [build, scope.usr, guard, handler.usr, match.group(0)]
                    )
                    raw_file = str(impl.get("file") or scope.source)
                    candidate_file = raw_file.replace("\\", "/")
                    if root is not None:
                        resolved_file = _project_file(root, raw_file)
                        try:
                            candidate_file = resolved_file.relative_to(root).as_posix()
                        except ValueError:
                            candidate_file = resolved_file.as_posix()
                    identifier = stable_interface_id(
                        "dispatcher",
                        # Dispatcher rows are executable only for one
                        # exact BuildContext.  The same USR/source can
                        # legitimately appear in several compile
                        # variants, so the stable row identity must be
                        # variant-scoped just like its evidence.
                        f"{build}:{name}:{guard}:{handler_name}",
                        candidate_file,
                        scope.usr,
                    )
                    row = {
                        "id": identifier,
                        "status": "pending",
                        "dispatcher": name,
                        "file": candidate_file,
                        "build_context_id": build,
                        "usr": scope.usr,
                        "handler_name": handler_name,
                        "handler_usr": handler.usr,
                        "guard": guard,
                        "evidence_summary": (
                            "Current switch branch directly calls the exact native handler identity."
                        ),
                        "evidence_digest": digest,
                    }
                    result_by_id.setdefault(identifier, row)
                    evidence_by_id.setdefault(identifier, set()).add(digest)

    for identifier, digests in evidence_by_id.items():
        ordered = sorted(digests)
        row = result_by_id[identifier]
        if len(ordered) > 1:
            row["evidence_digest"] = canonical_digest(["dispatcher-evidence-set", *ordered])
            row["evidence_occurrences"] = len(ordered)
    return sorted(result_by_id.values(), key=lambda row: str(row.get("id") or ""))


def _write_discovery_evidence(
    root: Path,
    *,
    receipt: Mapping[str, Any],
    interfaces: Sequence[dict[str, Any]],
    dispatchers: Sequence[dict[str, Any]],
    pointer_bindings: Sequence[dict[str, Any]],
    llm_audit: Mapping[str, Any] | None = None,
) -> str:
    directory = root / ".zscope_snapshots" / "semantics"
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "zscope.primitive-discovery-evidence.v1",
        "receipt": receipt,
        "interfaces": interfaces,
        "dispatchers": dispatchers,
        "function_pointer_bindings": pointer_bindings,
        # Raw model output belongs in the machine evidence tree, never in the
        # human-maintained YAML authority document.
        "llm_audit": deepcopy(dict(llm_audit or {})),
    }
    digest = canonical_digest(payload)
    path = directory / f"discovery-{digest}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
    return path.relative_to(root).as_posix()


def _human_discovery_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Project the full machine receipt into a bounded YAML summary.

    Per-function manifests and every individual coverage gap live in the
    immutable discovery evidence JSON.  Repeating them in the reviewer-owned
    YAML made large projects produce multi-megabyte configuration files and
    obscured the rows a human actually needs to decide.
    """

    projected = deepcopy(dict(receipt))
    diagnostics = projected.pop("native_discovery_diagnostics", [])
    projected["native_discovery_diagnostic_count"] = len(diagnostics)
    proposal_audit = projected.pop("contract_proposals", {})
    if proposal_audit:
        projected["contract_proposals"] = {
            key: proposal_audit[key] for key in ("schema", "eligible", "reviewed", "requests", "policy")
            if key in proposal_audit
        }
        projected["contract_proposals"]["errors"] = len(proposal_audit.get("errors", []))
    workflow = projected.pop("workflow", None)
    if workflow is not None:
        projected["workflow_digest"] = canonical_digest(workflow)
    facts = list(projected.pop("function_fact_summaries", []) or [])
    gaps = sorted({str(value) for value in projected.get("coverage_gaps", []) or [] if str(value)})
    projected["function_fact_summary_count"] = len(facts)
    projected["function_fact_summary_digest"] = canonical_digest(facts)
    projected["coverage_gap_count"] = len(gaps)
    projected["coverage_gap_digest"] = canonical_digest(gaps)
    projected["coverage_gaps"] = gaps[:50]
    projected["coverage_gaps_truncated"] = len(gaps) > 50
    return projected


_NATIVE_FACT_NOISE = frozenset(
    {
        "declaration",
        "definition_hash",
        "record_layouts",
        "type_definition",
        "target_values",
    }
)


def _compact_native_value(value: Any, *, depth: int = 0) -> Any:
    """Keep decision facts readable without serialising the whole native AST.

    Discovery is advisory and should never send record layouts and repeated
    declaration payloads for every argument of every call.  The full receipt
    remains in the local evidence snapshot through its digest; this projection
    carries only the values needed to judge the proposed effect.
    """

    if depth >= 7:
        return "<depth-limited>"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:64]:
            if str(key) in _NATIVE_FACT_NOISE:
                continue
            result[str(key)] = _compact_native_value(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_compact_native_value(item, depth=depth + 1) for item in value[:32]]
    if isinstance(value, str):
        return value[:600]
    return deepcopy(value)


def _compact_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"expression": str(value)[:240]}
    keys = (
        "name",
        "qualified_name",
        "usr",
        "referenced_usr",
        "expression",
        "value_kind",
        "canonical_signature",
        "signature",
        "integer_bits",
        "integer_unsigned",
        "pointee_record_usr",
        "external_linkage",
        "is_system_header",
    )
    result = {
        key: _compact_native_value(value[key], depth=1)
        for key in keys
        if value.get(key) not in (None, "", [], {})
    }
    location = value.get("location")
    if isinstance(location, Mapping):
        result["location"] = {
            key: location[key]
            for key in ("file", "line", "column")
            if location.get(key) not in (None, "")
        }
    return result


def _compact_event(event: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        key: _compact_native_value(event[key], depth=1)
        for key in (
            "event_id",
            "event_kind",
            "block",
            "expression",
            "operation",
            "assignment_target",
            "assignment_value",
            "reference_kind",
        )
        if event.get(key) not in (None, "", [], {})
    }
    if isinstance(event.get("callee"), Mapping):
        result["callee"] = _compact_identity(event["callee"])
    if isinstance(event.get("object"), Mapping) and event.get("object"):
        result["object"] = _compact_identity(event["object"])
    result["arguments"] = [str(value)[:240] for value in (event.get("arguments") or [])[:16]]
    result["argument_uses"] = [
        [_compact_identity(value) for value in values[:8] if isinstance(value, Mapping)]
        for values in (event.get("argument_uses") or [])[:16]
        if isinstance(values, list)
    ]
    for key in ("defs", "uses"):
        values = event.get(key) or []
        if isinstance(values, list) and values:
            result[key] = [
                _compact_identity(value) for value in values[:12] if isinstance(value, Mapping)
            ]
    location = event.get("location")
    if isinstance(location, Mapping):
        result["location"] = {
            key: location[key]
            for key in ("file", "line", "column")
            if location.get(key) not in (None, "")
        }
    return result


def _decision_fact_excerpt(
    facts: Mapping[str, Any], *, derived_from: Sequence[str]
) -> dict[str, Any]:
    bodies = [item for item in facts.get("functions", []) or [] if isinstance(item, Mapping)]
    body: Mapping[str, Any] = bodies[0] if len(bodies) == 1 else facts
    root_names = {
        str(value).split(":", 1)[-1] for value in derived_from if str(value).split(":", 1)[-1]
    }
    raw_events = [item for item in body.get("events", []) or [] if isinstance(item, Mapping)]
    relevant_events = []
    for event in raw_events:
        callee = event.get("callee")
        callee = callee if isinstance(callee, Mapping) else {}
        callee_name = str(callee.get("qualified_name") or callee.get("name") or "")
        if not root_names or callee_name in root_names:
            relevant_events.append(event)

    def bounded(value: Any, limit: int) -> list[Any]:
        return list(value[:limit]) if isinstance(value, (list, tuple)) else []

    parameters = bounded(body.get("parameters") or facts.get("parameters"), 16)
    selected = {
        "parameters": [
            _compact_identity(value) for value in parameters[:16] if isinstance(value, Mapping)
        ],
        "events": [_compact_event(value) for value in relevant_events[:12]],
        "returns": _compact_native_value(bounded(body.get("returns") or facts.get("returns"), 12)),
        "conditions": _compact_native_value(
            bounded(body.get("conditions") or facts.get("conditions"), 16)
        ),
        "def_use": _compact_native_value(bounded(body.get("def_use") or facts.get("def_use"), 24)),
        "resource_events": _compact_native_value(
            bounded(body.get("resource_events") or facts.get("resource_events"), 16)
        ),
        "lock_events": _compact_native_value(
            bounded(body.get("lock_events") or facts.get("lock_events"), 16)
        ),
    }
    return {key: value for key, value in selected.items() if value not in (None, [], {})}


def _payload_batches(
    payloads: Sequence[Mapping[str, Any]], *, max_chars: int = 16_000, max_items: int = 2
) -> list[list[dict[str, Any]]]:
    """Partition candidates so each one receives exactly one bounded review."""

    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_chars = 0
    for raw in payloads:
        payload = deepcopy(dict(raw))
        payload_chars = len(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        if current and (len(current) >= max_items or current_chars + payload_chars > max_chars):
            batches.append(current)
            current = []
            current_chars = 0
        current.append(payload)
        current_chars += payload_chars
    if current:
        batches.append(current)
    return batches


def _group_review_excerpts(
    excerpts: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Collapse compile variants with identical decision evidence.

    Header-defined C++ functions can appear in hundreds of BuildContexts.  The
    prior payload repeated the same code and decision facts once per context,
    producing 300k-token advisory prompts.  Keep every context identity in the
    coverage record while sending each distinct evidence shape only once.
    """

    grouped: dict[str, dict[str, Any]] = {}
    fact_digests: dict[str, set[str]] = defaultdict(set)
    total_variants = 0
    for raw in excerpts:
        excerpt = deepcopy(dict(raw))
        build = str(excerpt.pop("build_context_id", "") or "")
        digest = str(excerpt.pop("program_fact_digest", "") or "")
        total_variants += 1
        key = canonical_digest(excerpt)
        bucket = grouped.setdefault(key, excerpt)
        builds = bucket.setdefault("build_context_ids", [])
        if build and build not in builds:
            builds.append(build)
        if digest:
            fact_digests[key].add(digest)
    rows: list[dict[str, Any]] = []
    for key in sorted(grouped):
        row = grouped[key]
        row["build_context_ids"] = sorted(row.get("build_context_ids") or [])
        row["program_fact_digest_set"] = canonical_digest(sorted(fact_digests[key]))
        rows.append(row)
    # LLM review is advisory, so bound the number of distinct shapes while the
    # full native evidence remains in the referenced discovery snapshot for the
    # human reviewer.  The omission is explicit and digest-bound.
    included = rows[:4]
    omitted = rows[4:]
    coverage = {
        "total_variants": total_variants,
        "unique_evidence_shapes": len(rows),
        "included_evidence_shapes": len(included),
        "omitted_evidence_shapes": len(omitted),
        "omitted_evidence_digest": canonical_digest(omitted) if omitted else "",
    }
    return included, coverage


def _candidate_review_payloads(
    interfaces: Sequence[dict[str, Any]],
    *,
    document: Mapping[str, Any],
    work: Mapping[
        str, Sequence[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]
    ],
) -> list[dict[str, Any]]:
    """Build bounded, self-contained payloads only for new/changed ambiguity."""

    existing = {
        str(row.get("id") or ""): row
        for row in document.get("interfaces", []) or []
        if isinstance(row, Mapping)
    }
    native_by_identity = {
        (build, scope.usr): (impl, facts)
        for build, functions in work.items()
        for scope, impl, facts, _name, _signature in functions
    }
    payloads: list[dict[str, Any]] = []
    for row in interfaces:
        if row.get("basis") != "derived_wrapper":
            continue
        if row.get("proposal_origin") == "llm_source_composition":
            # Its typed generation/repair is already recorded separately. The
            # legacy advisory-only round cannot revise a contract and should
            # not double model cost or masquerade as an independent proof.
            continue
        before = existing.get(str(row.get("id") or ""))
        changed = before is None or str(before.get("evidence_digest") or "") != str(
            row.get("evidence_digest") or ""
        )
        ambiguity_requires_review = any(
            isinstance(effect, Mapping) and effect.get("strength") == "may"
            for effect in row.get("effects", []) or []
        ) and not (
            isinstance(before, Mapping)
            and isinstance(before.get("llm_review"), Mapping)
            and str(before.get("evidence_digest") or "") == str(row.get("evidence_digest") or "")
        )
        if (
            isinstance(before, Mapping)
            and isinstance(before.get("llm_review"), Mapping)
            and str(before.get("evidence_digest") or "") == str(row.get("evidence_digest") or "")
        ):
            row["llm_review"] = deepcopy(before["llm_review"])
        if not (changed or ambiguity_requires_review):
            continue
        excerpts: list[dict[str, Any]] = []
        for variant in row.get("variants", []) or []:
            if not isinstance(variant, Mapping):
                continue
            identity = (
                str(variant.get("build_context_id") or ""),
                str(variant.get("usr") or ""),
            )
            native = native_by_identity.get(identity)
            if native is None:
                continue
            impl, facts = native
            decision_facts = _decision_fact_excerpt(
                facts,
                derived_from=[str(value) for value in row.get("derived_from", []) or []],
            )
            excerpts.append(
                {
                    "build_context_id": identity[0],
                    "usr": identity[1],
                    "source": str(impl.get("file") or ""),
                    "signature": str(impl.get("signature") or ""),
                    "code": str(impl.get("code") or "")[:2500],
                    "program_fact_digest": canonical_digest(facts),
                    "decision_facts": decision_facts,
                }
            )
        excerpts, excerpt_coverage = _group_review_excerpts(excerpts)
        raw_macro_evidence = row.get("native_evidence")
        if row.get("selector", {}).get("kind") == "macro" and isinstance(
            raw_macro_evidence, Mapping
        ):
            excerpts.append(
                {
                    "build_context_ids": sorted(
                        {
                            str(variant.get("build_context_id") or "")
                            for variant in row.get("variants", []) or []
                            if isinstance(variant, Mapping) and variant.get("build_context_id")
                        }
                    ),
                    "usr": str(row.get("selector", {}).get("usr") or ""),
                    "source": str(row.get("selector", {}).get("file") or ""),
                    "signature": str(row.get("selector", {}).get("signature") or ""),
                    "macro_evidence": _compact_native_value(raw_macro_evidence),
                    "program_fact_digest": canonical_digest(raw_macro_evidence),
                }
            )
        allowed_missing_fact_kinds = {
            "source",
            "path",
            "call_identity",
            "effects",
            "conditions",
        }
        for excerpt in excerpts:
            if not isinstance(excerpt, Mapping):
                continue
            raw_decision_facts = excerpt.get("decision_facts")
            if isinstance(raw_decision_facts, Mapping):
                allowed_missing_fact_kinds.update(str(key) for key in raw_decision_facts)
            macro_evidence = excerpt.get("macro_evidence")
            if isinstance(macro_evidence, Mapping):
                allowed_missing_fact_kinds.update(str(key) for key in macro_evidence)
        payloads.append(
            {
                "id": str(row.get("id") or ""),
                "selector": deepcopy(row.get("selector") or {}),
                "effects": deepcopy(row.get("effects") or []),
                "cases": deepcopy(row.get("cases") or []),
                "derived_from": deepcopy(row.get("derived_from") or []),
                "deterministic_evidence": str(row.get("evidence_summary") or ""),
                "reason": ("first_or_evidence_changed" if changed else "ambiguous_may_effect"),
                "allowed_missing_fact_kinds": sorted(allowed_missing_fact_kinds),
                "native_excerpts": excerpts,
                "native_excerpt_coverage": excerpt_coverage,
            }
        )
    return payloads


def _parse_llm_reviews(response: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str]:
    content = str(response.get("choices", [{}])[0].get("message", {}).get("content", ""))
    for block in extract_json_blocks(content):
        values = block.get("reviews") if isinstance(block, Mapping) else None
        if not isinstance(values, list):
            continue
        reviews = [dict(value) for value in values if isinstance(value, Mapping)]
        return reviews, content
    return [], content


def _llm_review_protocol_error(
    response: Mapping[str, Any], reviews: Sequence[Mapping[str, Any]], raw: str
) -> str:
    if reviews:
        return ""
    choices = response.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices else {}
    finish = (
        str(choice.get("finish_reason") or "unknown") if isinstance(choice, Mapping) else "unknown"
    )
    return (
        f"empty_response:finish_reason={finish}"
        if not raw.strip()
        else f"invalid_review_protocol:finish_reason={finish}"
    )


def _review_discovery_candidates(
    llm_client: Any,
    interfaces: Sequence[dict[str, Any]],
    *,
    document: Mapping[str, Any],
    work: Mapping[
        str, Sequence[tuple[InstanceScope, Mapping[str, Any], Mapping[str, Any], str, str]]
    ],
) -> dict[str, Any]:
    """Run one advisory review and at most one deterministic fact-completion round.

    Model output is deliberately non-authoritative: it may explain or suggest
    refinements to a pending row, but this function never changes its effects
    or status.  Only a human edit to ``confirmed`` can publish a contract.
    """

    payloads = _candidate_review_payloads(interfaces, document=document, work=work)
    payload_ids = {str(item.get("id") or "") for item in payloads}
    reused_reviews = sum(
        1
        for row in interfaces
        if row.get("basis") == "derived_wrapper"
        and isinstance(row.get("llm_review"), Mapping)
        and str(row.get("id") or "") not in payload_ids
    )
    audit: dict[str, Any] = {
        "schema": "zscope.primitive-discovery-llm-audit.v1",
        "eligible": len(payloads),
        "reused_reviews": reused_reviews,
        "reviewed": 0,
        "evidence_completion_rounds": 0,
        "initial_requests": 0,
        "completion_requests": 0,
        "max_prompt_chars": 0,
        "initial_batches": [],
        "completion_batches": [],
        "initial_raw_response": "",
        "completion_raw_response": "",
        "invalid_fact_requests": [],
        "errors": [],
    }
    if llm_client is None or not payloads:
        audit["policy"] = "not_required" if not payloads else "client_unavailable"
        return audit

    by_id = {str(row.get("id") or ""): row for row in interfaces}
    system = (
        "You audit deterministic C/C++ project-interface discoveries. Use only the supplied "
        "current native evidence. Return JSON {reviews:[...]}. Each review needs id, verdict "
        "(agree|refine|disagree|insufficient), rationale, evidence_refs, and optional "
        "missing_fact_kinds/refined_effects. Never claim an interface is confirmed; a human "
        "owns that decision. If facts are missing, use insufficient. Return exactly one compact "
        "review per candidate, keep rationale under 120 characters, and never repeat source or "
        "evidence payloads in the response. missing_fact_kinds may contain only names listed in "
        "that candidate's allowed_missing_fact_kinds."
    )
    valid = {"agree", "refine", "disagree", "insufficient"}
    normalized: dict[str, dict[str, Any]] = {}
    initial_raw: list[str] = []
    initial_batches = list(enumerate(_payload_batches(payloads)))

    def initial_request(item: tuple[int, list[dict[str, Any]]]) -> tuple[Any, ...]:
        batch_index, batch = item
        candidate_ids = {str(payload.get("id") or "") for payload in batch}
        content = json.dumps({"candidates": batch}, ensure_ascii=False, sort_keys=True)
        try:
            initial = llm_client.chat_completion(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": content},
                ],
                temperature=0.0,
                # Discovery review is advisory and the response schema is
                # deliberately compact.  Reasoning-capable providers were
                # otherwise spending thousands of hidden/output tokens per
                # two-row batch (and often hitting the output limit before
                # emitting JSON), which made a first project registration
                # take longer than the scan it prepares.  Deterministic
                # native facts remain the evidence; this switch only asks the
                # model to encode its bounded review directly.
                max_tokens=1536,
                thinking={"type": "disabled"},
                trace_agent="primitive_discovery",
                trace_label=f"advisory_review_{batch_index + 1}",
            )
            reviews, raw = _parse_llm_reviews(initial)
            return (
                batch_index,
                candidate_ids,
                len(content),
                reviews,
                raw,
                _llm_review_protocol_error(initial, reviews, raw),
            )
        except Exception as exc:  # pending rows remain safely reviewable
            return (
                batch_index,
                candidate_ids,
                len(content),
                [],
                "",
                f"{type(exc).__name__}:{exc}",
            )

    with ThreadPoolExecutor(max_workers=min(4, max(1, len(initial_batches)))) as executor:
        initial_results = list(executor.map(initial_request, initial_batches))
    for batch_index, candidate_ids, prompt_chars, reviews, raw, error in initial_results:
        audit["max_prompt_chars"] = max(int(audit["max_prompt_chars"]), prompt_chars)
        if error:
            audit["errors"].append(f"initial_review_batch_{batch_index + 1}:{error}")
            continue
        audit["initial_requests"] = int(audit["initial_requests"]) + 1
        initial_raw.append(raw)
        audit["initial_batches"].append(
            {
                "candidate_ids": sorted(candidate_ids),
                "prompt_chars": prompt_chars,
                "parsed_reviews": len(reviews),
            }
        )
        for review in reviews:
            identifier = str(review.get("id") or "")
            verdict = str(review.get("verdict") or "").lower()
            # A response cannot review a candidate from another batch.
            if identifier not in candidate_ids or identifier not in by_id or verdict not in valid:
                continue
            normalized[identifier] = review
    audit["initial_raw_response"] = "\n".join(initial_raw)

    raw_requests = {
        identifier: [str(kind) for kind in review.get("missing_fact_kinds", []) if str(kind)]
        for identifier, review in normalized.items()
        if review.get("verdict") == "insufficient"
    }
    payload_by_id = {str(payload.get("id") or ""): payload for payload in payloads}
    requests: dict[str, list[str]] = {}
    for identifier, kinds in raw_requests.items():
        allowed = {
            str(value)
            for value in payload_by_id.get(identifier, {}).get("allowed_missing_fact_kinds", [])
            or []
        }
        invalid = sorted(set(kinds) - allowed)
        if invalid:
            audit["invalid_fact_requests"].append({"id": identifier, "fact_kinds": invalid})
        supported = [kind for kind in kinds if kind in allowed]
        if supported:
            requests[identifier] = supported
    if requests:
        completion: dict[str, dict[str, Any]] = {}
        for payload in payloads:
            identifier = payload["id"]
            if identifier not in requests:
                continue
            excerpts = list(payload.get("native_excerpts") or [])
            facts_by_kind: dict[str, list[Any]] = defaultdict(list)
            for excerpt in excerpts:
                if not isinstance(excerpt, Mapping):
                    continue
                decision_facts = excerpt.get("decision_facts")
                if isinstance(decision_facts, Mapping):
                    for kind, value in decision_facts.items():
                        if value not in (None, [], {}):
                            facts_by_kind[str(kind)].append(deepcopy(value))
                macro_evidence = excerpt.get("macro_evidence")
                if isinstance(macro_evidence, Mapping):
                    for kind, value in macro_evidence.items():
                        if value not in (None, [], {}):
                            facts_by_kind[str(kind)].append(deepcopy(value))
            providers: dict[str, Any] = {
                "source": excerpts,
                "path": deepcopy(payload.get("derived_from") or []),
                "call_identity": [
                    {
                        key: deepcopy(excerpt.get(key))
                        for key in ("build_context_id", "usr", "source", "signature")
                    }
                    for excerpt in excerpts
                    if isinstance(excerpt, Mapping)
                ],
                "effects": deepcopy(payload.get("effects") or []),
                "conditions": deepcopy(payload.get("cases") or []),
            }
            providers.update(facts_by_kind)
            provided: dict[str, Any] = {}
            unsupported_or_empty: list[str] = []
            for kind in requests[identifier]:
                value = providers.get(kind)
                if value in (None, [], {}):
                    unsupported_or_empty.append(kind)
                else:
                    provided[kind] = value
            completion[identifier] = {
                "requested_fact_kinds": requests[identifier],
                "provided": provided,
                "unsupported_or_empty": sorted(set(unsupported_or_empty)),
                "evidence_delta": bool(provided),
            }
        audit["provider_results"] = deepcopy(completion)
        completion_payloads = [
            {"id": identifier, **payload} for identifier, payload in sorted(completion.items())
        ]
        completion_raw: list[str] = []
        completion_batches = list(enumerate(_payload_batches(completion_payloads)))

        def completion_request(item: tuple[int, list[dict[str, Any]]]) -> tuple[Any, ...]:
            batch_index, batch = item
            candidate_ids = {str(payload.get("id") or "") for payload in batch}
            fact_completion = {
                str(payload["id"]): {
                    key: deepcopy(value) for key, value in payload.items() if key != "id"
                }
                for payload in batch
            }
            content = json.dumps(
                {"fact_completion": fact_completion}, ensure_ascii=False, sort_keys=True
            )
            try:
                second = llm_client.chat_completion(
                    [
                        {"role": "system", "content": system},
                        {"role": "user", "content": content},
                    ],
                    temperature=0.0,
                    max_tokens=1536,
                    thinking={"type": "disabled"},
                    trace_agent="primitive_discovery",
                    trace_label=f"advisory_fact_completion_{batch_index + 1}",
                )
                second_reviews, second_raw = _parse_llm_reviews(second)
                return (
                    batch_index,
                    candidate_ids,
                    len(content),
                    second_reviews,
                    second_raw,
                    _llm_review_protocol_error(second, second_reviews, second_raw),
                )
            except Exception as exc:
                return (
                    batch_index,
                    candidate_ids,
                    len(content),
                    [],
                    "",
                    f"{type(exc).__name__}:{exc}",
                )

        with ThreadPoolExecutor(max_workers=min(4, max(1, len(completion_batches)))) as executor:
            completion_results = list(executor.map(completion_request, completion_batches))
        for (
            batch_index,
            candidate_ids,
            prompt_chars,
            second_reviews,
            second_raw,
            error,
        ) in completion_results:
            audit["max_prompt_chars"] = max(int(audit["max_prompt_chars"]), prompt_chars)
            if error:
                audit["errors"].append(f"fact_completion_batch_{batch_index + 1}:{error}")
                continue
            audit["completion_requests"] = int(audit["completion_requests"]) + 1
            completion_raw.append(second_raw)
            audit["completion_batches"].append(
                {
                    "candidate_ids": sorted(candidate_ids),
                    "prompt_chars": prompt_chars,
                    "parsed_reviews": len(second_reviews),
                }
            )
            audit["evidence_completion_rounds"] = 1
            for review in second_reviews:
                identifier = str(review.get("id") or "")
                verdict = str(review.get("verdict") or "").lower()
                if identifier in candidate_ids and identifier in requests and verdict in valid:
                    normalized[identifier] = review
        audit["completion_raw_response"] = "\n".join(completion_raw)

    for identifier, review in normalized.items():
        row = by_id[identifier]
        row["llm_review"] = {
            "verdict": str(review.get("verdict") or ""),
            "rationale": str(review.get("rationale") or ""),
            "evidence_refs": [
                str(value) for value in review.get("evidence_refs", []) if str(value)
            ],
            "missing_fact_kinds": [
                str(value) for value in review.get("missing_fact_kinds", []) if str(value)
            ],
            "suggested_refinement": deepcopy(review.get("refined_effects") or []),
            "authority": "advisory_human_confirmation_required",
        }
    audit["reviewed"] = len(normalized)
    audit["verdict_counts"] = dict(
        sorted(
            {
                verdict: sum(
                    1
                    for review in normalized.values()
                    if str(review.get("verdict") or "") == verdict
                )
                for verdict in valid
            }.items()
        )
    )
    audit["policy"] = "advisory_only_human_final"
    return audit


def _direct_parameter_expression(expression: str, parameter: str) -> bool:
    """Return whether a sink argument is the public parameter (or its member).

    This intentionally accepts casts, dereferences, addresses, member access,
    and subscripts, while rejecting calls, arithmetic, and conditional
    expressions. Those richer transformations need a dedicated executable
    contract instead of the one-carrier wrapper projection used here.
    """

    if not expression or not parameter:
        return False
    value = expression.strip()
    while value.startswith("("):
        match = re.match(r"^\([^()]+\)\s*(.+)$", value, re.S)
        if match is None:
            break
        value = match.group(1).strip()
    return bool(
        re.fullmatch(
            rf"[*&\s]*{re.escape(parameter)}"
            rf"(?:(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)|(?:\s*\[[^\]]+\]))*\s*",
            value,
        )
    )


def _lock_wrapper_candidate(
    *,
    facts: Mapping[str, Any],
    semantics: Any,
    root: Path,
    source: str,
    code: str,
    build: str,
    usr: str,
    name: str,
    signature: str,
) -> dict[str, Any] | None:
    bodies = [row for row in facts.get("functions", []) if isinstance(row, Mapping)]
    if len(bodies) != 1:
        return None
    body = bodies[0]
    parameters = [row for row in body.get("parameters", []) if isinstance(row, Mapping)]
    parameter_by_usr = {
        str(row.get("usr") or ""): index for index, row in enumerate(parameters) if row.get("usr")
    }
    root_contracts: dict[str, ApiContract] = {}
    supported_roles = {
        "lock",
        "unlock",
        "send_sink",
        "recv_source",
        "format_sink",
        "command_sink",
        "callback_register",
    }
    for contract in semantics.contracts.contracts:
        if (
            contract.role in supported_roles
            or (
                contract.role == "standard_operation"
                and contract.symbol.name in DISCOVERABLE_STANDARD_OPERATION_ROOTS
            )
        ) and contract.effects_trusted:
            root_contracts[contract.symbol.name] = contract
    matches: list[tuple[ApiContract, int, Mapping[str, Any]]] = []
    for event in body.get("events", []) or []:
        if not isinstance(event, Mapping) or event.get("event_kind") != "call":
            continue
        raw_callee = event.get("callee")
        callee: Mapping[str, Any] = raw_callee if isinstance(raw_callee, Mapping) else {}
        callee_name = str(callee.get("name") or event.get("callee_name") or "")
        contract = root_contracts.get(callee_name)
        if contract is None:
            continue
        uses = event.get("argument_uses") or []
        carrier = contract.carrier.argument_index
        if carrier is None or carrier >= len(uses):
            continue
        referenced = {
            str(value.get("usr") or "")
            for value in uses[carrier]
            if isinstance(value, Mapping) and value.get("usr")
        }
        indices = {parameter_by_usr[value] for value in referenced if value in parameter_by_usr}
        if len(indices) == 1:
            argument_index = next(iter(indices))
            if contract.role in {"format_sink", "command_sink"}:
                arguments = event.get("arguments") or []
                if carrier < len(arguments) and not _direct_parameter_expression(
                    str(arguments[carrier] or ""),
                    str(parameters[argument_index].get("name") or ""),
                ):
                    # Native argument_uses includes values used only to select
                    # an expression. For a security sink that is not the same
                    # as the parameter being the sink payload. For example,
                    # snprintf(..., flag ? "a" : "b", ...) must not become a
                    # user-controlled format wrapper merely because ``flag``
                    # participates in the selection.
                    continue
            matches.append((contract, argument_index, event))
    # Clang can expose the same source call more than once when the value is
    # represented both by the assignment and the CFG expression.  Those are
    # not two runtime effects.  Deduplicate by the resolved semantic effect
    # and carrier, while retaining genuinely distinct multi-effect wrappers.
    unique_matches: dict[
        tuple[str, int, str, str, str], tuple[ApiContract, int, Mapping[str, Any]]
    ] = {}
    for contract, argument_index, event in matches:
        identity = (
            contract.role,
            argument_index,
            contract.symbol.name,
            contract.resource_family,
            canonical_digest(contract.protocol),
        )
        unique_matches.setdefault(identity, (contract, argument_index, event))
    matches = list(unique_matches.values())
    if not matches:
        return None
    normalized_file = _project_file(root, source)
    relative = normalized_file.relative_to(root).as_posix()
    evidence_digest = canonical_digest(
        [
            "zscope.project-wrapper-effects.v2",
            facts,
            [
                [contract.to_dict(), argument_index, event]
                for contract, argument_index, event in matches
            ],
        ]
    )
    effects = []
    pairs: set[str] = set()
    derived_from: set[str] = set()
    for contract, argument_index, _event in matches:
        protocol = deepcopy(contract.protocol)
        if signature.lstrip().startswith("void ") and isinstance(protocol, dict):
            # The public wrapper does not expose the pthread return code.  A
            # caller therefore sees a possible transition, not a transition
            # guarded by the wrapper's nonexistent return value.
            for transition in protocol.get("transitions", []) or []:
                if isinstance(transition, dict):
                    transition["when"] = {"op": "true"}
            protocol["outcome_visibility"] = "hidden_by_void_wrapper"
        effects.append(
            {
                "domain": _domain_for_role(contract.role),
                "role": contract.role,
                "operation": contract.role,
                "carrier": {
                    "root": "argument",
                    "index": argument_index,
                    "phase": "pre",
                    "dereference": 0,
                    "members": [],
                },
                "resource_family": contract.resource_family,
                "strength": "may",
                "protocol": protocol,
            }
        )
        pairs.update(f"builtin:{target.name}" for target in contract.pairs)
        derived_from.add(f"builtin:{contract.symbol.name}")
    return {
        "id": stable_interface_id("function", name, relative, usr),
        "primitive": False,
        "selector": {
            "kind": "function",
            "name": name,
            "file": relative,
            "signature": signature,
            "usr": usr,
        },
        "basis": "derived_wrapper",
        "status": "pending",
        # Applicability of a possible effect is different from certainty of
        # that effect. Status=pending prevents publication; strength=may
        # prevents a human-confirmed proposal from becoming a must proof.
        "cases": [{"when": {"op": "true"}, "effect": "applies"}],
        "effects": effects,
        "otherwise": "unknown",
        "pairs": sorted(pairs),
        "derived_from": sorted(derived_from),
        "evidence_summary": (
            "Exact native calls reach reviewed primitives through mapped public arguments; "
            "duplicate AST/CFG projections were collapsed. The wrapper hides one or more "
            "callee outcomes, so propagated effects remain may."
        ),
        "evidence_ref": "",
        "evidence_digest": evidence_digest,
        "variants": [
            {
                "target_id": "",
                "build_context_id": build,
                "usr": usr,
                "signature": signature,
                "file": relative,
                "source_sha256": file_sha256(normalized_file),
                "evidence_sha256": evidence_digest,
                "native_input_hash": canonical_digest(facts),
                "identity_status": "exact",
            }
        ],
    }


def _cxx_new_factory_candidate(
    *,
    facts: Mapping[str, Any],
    root: Path,
    source: str,
    code: str,
    build: str,
    usr: str,
    name: str,
    signature: str,
) -> dict[str, Any] | None:
    """Discover an exact C++ function that returns one direct ``new`` object."""

    bodies = [row for row in facts.get("functions", []) if isinstance(row, Mapping)]
    if len(bodies) != 1 or "*" not in signature:
        return None
    events = [row for row in bodies[0].get("events", []) or [] if isinstance(row, Mapping)]
    acquisitions = [
        row
        for row in events
        if row.get("event_kind") == "acquire"
        and row.get("ast_kind") in {"CXXNewExpr", "CXXNewArrayExpr"}
        and str(row.get("expression") or "").strip().startswith("new ")
    ]
    returns = [
        row
        for row in events
        if row.get("event_kind") == "return"
        and str(row.get("return_value") or "").strip().startswith("new ")
    ]
    if len(acquisitions) != 1 or len(returns) != 1:
        return None
    acquire_expression = str(acquisitions[0].get("expression") or "").strip()
    return_expression = str(returns[0].get("return_value") or "").strip()
    if acquire_expression != return_expression:
        return None
    if len(re.findall(r"\breturn\b", code)) != 1 or not re.search(
        r"\breturn\s+new\s+[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*", code
    ):
        return None

    normalized_file = _project_file(root, source)
    relative = normalized_file.relative_to(root).as_posix()
    evidence_digest = canonical_digest(
        {
            "schema": "zscope.project-cxx-new-factory.v1",
            "function_facts": facts,
            "source": code,
            "acquire": acquisitions[0],
            "return": returns[0],
        }
    )
    return {
        "id": stable_interface_id("function", name, relative, usr),
        "primitive": False,
        "selector": {
            "kind": "function",
            "name": name,
            "file": relative,
            "signature": signature,
            "usr": usr,
        },
        "basis": "derived_wrapper",
        "status": "pending",
        "cases": [{"when": {"op": "true"}, "effect": "unknown"}],
        "effects": [
            {
                "domain": "resource",
                "role": "allocator",
                "operation": "allocator",
                "carrier": {
                    "root": "return",
                    "phase": "post",
                    "dereference": 0,
                    "members": [],
                },
                "resource_family": "cxx_object",
                "strength": "must_under_guard",
                "protocol": {"acquire": "cxx_new"},
            }
        ],
        "otherwise": "unknown",
        "pairs": [],
        "derived_from": ["builtin:cxx_new"],
        "evidence_summary": (
            f"Current native CXXNewExpr and return facts prove `{name}` returns the exact "
            f"new object `{return_expression}` on normal completion."
        ),
        "evidence_ref": "",
        "evidence_digest": evidence_digest,
        "variants": [
            {
                "target_id": "",
                "build_context_id": build,
                "usr": usr,
                "signature": signature,
                "file": relative,
                "source_sha256": file_sha256(normalized_file),
                "evidence_sha256": evidence_digest,
                "native_input_hash": canonical_digest(facts),
                "identity_status": "exact",
            }
        ],
    }


def _returned_aggregate_member_factory_candidate(
    *,
    facts: Mapping[str, Any],
    semantics: Any,
    direct_cxx_new_factories: set[str],
    root: Path,
    source: str,
    code: str,
    build: str,
    usr: str,
    name: str,
    signature: str,
) -> dict[str, Any] | None:
    """Discover ownership carried by a member of a returned value aggregate."""

    bodies = [row for row in facts.get("functions", []) if isinstance(row, Mapping)]
    if len(bodies) != 1 or "*" in signature.split("(", 1)[0]:
        return None
    events = [row for row in bodies[0].get("events", []) or [] if isinstance(row, Mapping)]
    returned = {
        str(row.get("return_value") or "").strip()
        for row in events
        if row.get("event_kind") == "return"
        and re.fullmatch(r"[A-Za-z_]\w*", str(row.get("return_value") or "").strip())
    }
    if len(returned) != 1:
        return None
    returned_local = next(iter(returned))
    effects: list[dict[str, Any]] = []
    derived_from: set[str] = set()
    evidence_events: list[Mapping[str, Any]] = []
    for event in events:
        if event.get("event_kind") != "call":
            continue
        callee = event.get("callee")
        callee = callee if isinstance(callee, Mapping) else {}
        callee_name = str(callee.get("qualified_name") or callee.get("name") or "")
        callee_usr = str(callee.get("usr") or callee.get("referenced_usr") or "")
        trusted = callee_usr in direct_cxx_new_factories
        contract_source = f"project-cxx-new:{callee_usr}" if trusted else ""
        if not trusted:
            for contract in semantics.contracts.find(
                callee_name,
                build_context_id=build,
                usr=callee_usr,
            ):
                if (
                    contract.role in {"allocator", "calloc", "reallocator"}
                    and contract.carrier.kind == "return"
                    and contract.effects_trusted
                ):
                    trusted = True
                    contract_source = (
                        str(contract.verification.get("project_semantics_id") or "")
                        if isinstance(contract.verification, Mapping)
                        else ""
                    ) or f"builtin:{contract.symbol.name}"
                    break
        if not trusted:
            continue
        targets = [event.get("object"), *(event.get("defs") or [])]
        for raw_target in targets:
            target = raw_target if isinstance(raw_target, Mapping) else {}
            expression = str(target.get("expression") or "").replace(" ", "")
            base = str(target.get("base_expression") or "").strip()
            member = str(target.get("name") or "").strip()
            if (
                base != returned_local
                or str(target.get("value_kind") or "") != "field"
                or not re.fullmatch(r"[A-Za-z_]\w*", member)
                or expression not in {f"{returned_local}.{member}", f"{returned_local}->{member}"}
            ):
                continue
            if not re.search(
                rf"\bif\s*\(\s*{re.escape(returned_local)}\s*(?:\.|->)\s*"
                rf"{re.escape(member)}\s*==\s*(?:NULL|nullptr|0|__null)\s*\)",
                code,
            ):
                continue
            effects.append(
                {
                    "domain": "resource",
                    "role": "allocator",
                    "operation": "allocator",
                    "carrier": {
                        "root": "return",
                        "phase": "post",
                        "dereference": 0,
                        "members": [member],
                    },
                    "resource_family": "cxx_object",
                    "strength": "may",
                    "protocol": {"ownership": "conditional_member"},
                }
            )
            derived_from.add(contract_source)
            evidence_events.append(event)
    unique_effects = {
        str(effect["carrier"]["members"][0]): effect for effect in effects
    }
    if not unique_effects:
        return None
    effects = [unique_effects[key] for key in sorted(unique_effects)]

    normalized_file = _project_file(root, source)
    relative = normalized_file.relative_to(root).as_posix()
    evidence_digest = canonical_digest(
        {
            "schema": "zscope.project-returned-aggregate-members.v1",
            "function_facts": facts,
            "returned_local": returned_local,
            "effects": effects,
            "events": evidence_events,
            "source": code,
        }
    )
    return {
        "id": stable_interface_id("function", name, relative, usr),
        "primitive": False,
        "selector": {
            "kind": "function",
            "name": name,
            "file": relative,
            "signature": signature,
            "usr": usr,
        },
        "basis": "derived_wrapper",
        "status": "pending",
        "cases": [{"when": {"op": "true"}, "effect": "unknown"}],
        "effects": effects,
        "otherwise": "unknown",
        "pairs": [],
        "derived_from": sorted(derived_from),
        "evidence_summary": (
            f"Current native def-use and guarded source facts show `{name}` returns "
            f"`{returned_local}` with conditionally acquired member(s): "
            + ", ".join(effect["carrier"]["members"][0] for effect in effects)
            + "."
        ),
        "evidence_ref": "",
        "evidence_digest": evidence_digest,
        "variants": [
            {
                "target_id": "",
                "build_context_id": build,
                "usr": usr,
                "signature": signature,
                "file": relative,
                "source_sha256": file_sha256(normalized_file),
                "evidence_sha256": evidence_digest,
                "native_input_hash": canonical_digest(facts),
                "identity_status": "exact",
            }
        ],
    }


def _owned_object_factory_candidate(
    *,
    facts: Mapping[str, Any],
    semantics: Any,
    root: Path,
    source: str,
    code: str,
    build: str,
    usr: str,
    name: str,
    signature: str,
) -> dict[str, Any] | None:
    """Discover a returned heap object together with directly owned members.

    This is deliberately narrower than general escape/points-to inference.  A
    candidate requires current native events that bind one trusted return
    allocator to a local, return that exact local, and bind at least one other
    trusted return allocator to a direct field of the same local.  The result
    remains pending human review and all effects are ``may`` because failure
    paths can return a partially initialized object or NULL.
    """

    bodies = [row for row in facts.get("functions", []) if isinstance(row, Mapping)]
    if len(bodies) != 1 or "*" not in signature:
        return None
    body = bodies[0]
    events = [row for row in body.get("events", []) or [] if isinstance(row, Mapping)]
    returned = {
        str(row.get("return_value") or "").strip()
        for row in events
        if row.get("event_kind") == "return"
        and re.fullmatch(r"[A-Za-z_]\w*", str(row.get("return_value") or "").strip())
    }
    if len(returned) != 1:
        return None
    returned_local = next(iter(returned))

    acquisition_roles = {"allocator", "calloc", "reallocator", "io_acquire"}

    def trusted_contract(event: Mapping[str, Any]) -> ApiContract | None:
        raw_callee = event.get("callee")
        callee: Mapping[str, Any] = raw_callee if isinstance(raw_callee, Mapping) else {}
        callee_name = str(callee.get("qualified_name") or callee.get("name") or "")
        callee_usr = str(callee.get("usr") or callee.get("referenced_usr") or "")
        if not callee_name:
            return None
        for contract in semantics.contracts.find(
            callee_name,
            build_context_id=build,
            usr=callee_usr,
        ):
            if not isinstance(contract, ApiContract):
                continue
            if (
                contract.role not in acquisition_roles
                or contract.carrier.kind != "return"
                or contract.carrier.member_path
                or not contract.effects_trusted
            ):
                continue
            if contract.symbol.build_context_id and contract.symbol.build_context_id != build:
                continue
            if contract.symbol.usr:
                if not callee_usr or contract.symbol.usr != callee_usr:
                    continue
            elif not bool(callee.get("is_system_header")):
                # A name-level contract is safe only for the native-verified
                # system declaration that caused it to enter this snapshot.
                continue
            return contract
        return None

    matches: dict[tuple[str, str, str], tuple[ApiContract, str, Mapping[str, Any]]] = {}
    for event in events:
        if event.get("event_kind") != "call":
            continue
        contract = trusted_contract(event)
        if contract is None:
            continue
        raw_object = event.get("object")
        obj: Mapping[str, Any] = raw_object if isinstance(raw_object, Mapping) else {}
        definitions = [row for row in event.get("defs", []) or [] if isinstance(row, Mapping)]
        candidates = [obj, *definitions]
        for target in candidates:
            expression = str(target.get("expression") or "").strip()
            value_kind = str(target.get("value_kind") or "")
            base = str(target.get("base_expression") or "").strip()
            member = str(target.get("name") or "").strip()
            if expression == returned_local and value_kind == "local":
                key = (contract.symbol.name, "", contract.role)
                matches.setdefault(key, (contract, "", event))
            elif (
                base == returned_local
                and value_kind == "field"
                and re.fullmatch(r"[A-Za-z_]\w*", member)
                and expression.replace(" ", "") == f"{returned_local}->{member}".replace(" ", "")
            ):
                key = (contract.symbol.name, member, contract.role)
                matches.setdefault(key, (contract, member, event))

    parent = [value for value in matches.values() if not value[1]]
    members = [value for value in matches.values() if value[1]]
    if len(parent) != 1 or not members:
        return None

    normalized_file = _project_file(root, source)
    relative = normalized_file.relative_to(root).as_posix()
    ordered = [parent[0], *sorted(members, key=lambda value: value[1])]
    effects: list[dict[str, Any]] = []
    pairs: set[str] = set()
    derived_from: set[str] = set()
    for contract, member, _event in ordered:
        # The callee's size/extent protocol is expressed in terms of the
        # callee's parameters.  It cannot be copied onto a higher-level
        # factory whose public parameters have unrelated meanings (for
        # example ``make(name, payload)`` wrapping ``calloc(1, sizeof T)``).
        # Publish the returned allocation as the common allocator effect;
        # the exact callee identity remains in ``derived_from`` and the
        # member ownership carriers stay explicit below.
        role = contract.role if member else "allocator"
        effects.append(
            {
                "domain": _domain_for_role(role),
                "role": role,
                "operation": role,
                "carrier": {
                    "root": "return",
                    "phase": "post",
                    "dereference": 0,
                    "members": [member] if member else [],
                },
                "resource_family": contract.resource_family,
                "strength": "may",
                "protocol": deepcopy(contract.protocol) if member else {},
            }
        )
        pairs.update(f"builtin:{target.name}" for target in contract.pairs)
        project_id = (
            str(contract.verification.get("project_semantics_id") or "")
            if isinstance(contract.verification, Mapping)
            else ""
        )
        derived_from.add(project_id or f"builtin:{contract.symbol.name}")

    evidence_digest = canonical_digest(
        {
            "schema": "zscope.project-owned-object-factory.v1",
            "function_facts": facts,
            "returned_local": returned_local,
            "effects": effects,
            "events": [event for _contract, _member, event in ordered],
            "source": code,
        }
    )
    return {
        "id": stable_interface_id("function", name, relative, usr),
        "primitive": False,
        "selector": {
            "kind": "function",
            "name": name,
            "file": relative,
            "signature": signature,
            "usr": usr,
        },
        "basis": "derived_wrapper",
        "status": "pending",
        "cases": [{"when": {"op": "true"}, "effect": "unknown"}],
        "effects": effects,
        "otherwise": "unknown",
        "pairs": sorted(pairs),
        "derived_from": sorted(derived_from),
        "evidence_summary": (
            f"Current native def-use facts bind trusted allocation roots to returned object "
            f"`{returned_local}` and directly owned member(s) "
            + ", ".join(f"`{returned_local}->{member}`" for _c, member, _e in members)
            + "; all effects remain may pending human review."
        ),
        "evidence_ref": "",
        "evidence_digest": evidence_digest,
        "variants": [
            {
                "target_id": "",
                "build_context_id": build,
                "usr": usr,
                "signature": signature,
                "file": relative,
                "source_sha256": file_sha256(normalized_file),
                "evidence_sha256": evidence_digest,
                "native_input_hash": canonical_digest(facts),
                "identity_status": "exact",
            }
        ],
    }


def _macro_candidates(
    *,
    root: Path,
    bindings: Mapping[tuple[str, str, int], Sequence[Mapping[str, Any]]],
    interfaces: Sequence[Mapping[str, Any]],
    roots: Mapping[str, Mapping[str, Any]],
    work: Mapping[str, Sequence[Any]] | None = None,
    link_groups: Sequence[Sequence[str]] = (),
) -> list[dict[str, Any]]:
    # A function implementation and a macro caller normally have DIFFERENT TU
    # identities. Cross-TU propagation needs both a real link group and the
    # current caller's exact callee USR; an equal name or project is insufficient.
    function_definitions: dict[str, set[str]] = defaultdict(set)
    references: dict[tuple[str, str], set[str]] = defaultdict(set)
    for build, items in (work or {}).items():
        for scope, _impl, facts, _name, _signature in items:
            function_definitions[scope.usr].add(build)
            for body in facts.get("functions", []):
                for event in body.get("events", []):
                    if event.get("event_kind") != "call":
                        continue
                    called = event.get("callee") or {}
                    called_usr = str(called.get("usr") or called.get("referenced_usr") or "")
                    if called_usr:
                        references[(build, str(called.get("name") or ""))].add(called_usr)

    def available(build: str, callee: Mapping[str, Any]) -> bool:
        builds = {v.get("build_context_id") for v in callee.get("variants", [])}
        selector = callee.get("selector") or {}
        if selector.get("kind") == "function" and (not builds or not all(builds)):
            return False
        if not builds or build in builds:
            return True
        usr, name = str(selector.get("usr") or ""), str(selector.get("name") or "")
        if selector.get("kind") != "function" or references.get((build, name)) != {usr}:
            return False
        peers = {member for group in link_groups if build in group for member in group}
        targets = function_definitions.get(usr, set()) & peers
        return len(targets) == 1 and bool(targets & builds)
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for interface in interfaces:
        grouped[str(interface.get("selector", {}).get("name") or "")].append(interface)
    known: dict[str, Mapping[str, Any]] = {}
    for name, candidates in grouped.items():
        meanings = {canonical_digest({key: row.get(key) for key in
                                      ("selector", "cases", "effects", "pairs")})
                    for row in candidates}
        if len(meanings) == 1:
            known[name] = candidates[0]
        elif len({canonical_digest(row.get("selector")) for row in candidates}) == 1:
            # Distinct effects of the same exact function are not ambiguous
            # callees. A macro may expose one while binding another to an
            # internal constant that has no caller-visible object path.
            known[name] = {"alternatives": candidates}
    known.update({str(name): row for name, row in roots.items()})
    result: list[dict[str, Any]] = []
    definitions: list[tuple[Path, str, int, str, list[str], str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _DEFINE.finditer(source):
            name, _raw_params, params_raw, body = match.groups()
            params = [part.strip() for part in str(params_raw or "").split(",") if part.strip()]
            relative = path.relative_to(root).as_posix()
            line = source.count("\n", 0, match.start()) + 1
            definitions.append((path, relative, line, name, params, body))

    constants: dict[str, int] = {}
    for _path, relative, line, name, params, body in definitions:
        # Only current native-bound object macros with literal values; never
        # infer an inactive configuration's value from arbitrary source text.
        if not params and bindings.get((name, relative, line)) and re.fullmatch(r"\s*[-+]?\d+\s*", body):
            constants[name] = int(body.strip())

    unresolved = list(definitions)
    while unresolved:
        next_unresolved: list[tuple[Path, str, int, str, list[str], str]] = []
        progressed = False
        for path, relative, line, name, params, body in unresolved:
            calls = [token for token in _CALL_TOKEN.findall(body) if token in known]
            if len(set(calls)) != 1:
                next_unresolved.append((path, relative, line, name, params, body))
                continue
            callee = known[calls[0]]
            if "alternatives" in callee:
                applicable = [
                    row for row in callee["alternatives"]
                    if _remap_macro_effects(row.get("effects") or [], body=body,
                                           callee_name=calls[0], parameters=params) is not None
                    and _remap_macro_value(row.get("cases") or [], body=body,
                                           callee_name=calls[0], parameters=params,
                                           constants=constants) is not None
                ]
                # General multi-clause composition still needs separate rows;
                # never collapse different guards/pairs into one contract.
                if len(applicable) != 1:
                    continue
                callee = applicable[0]
            source_effects = deepcopy(callee.get("effects") or [])
            source_cases = deepcopy(callee.get("cases") or [])
            if not source_effects:
                next_unresolved.append((path, relative, line, name, params, body))
                continue
            exact_bindings = list(bindings.get((name, relative, line), ()))
            exact_bindings = [b for b in exact_bindings if available(str(b.get("build_context_id") or ""), callee)]
            if not exact_bindings:
                # Source text alone is not a build identity.  A macro becomes
                # a candidate only when the current native TU receipts name
                # its exact definition and BuildContext.
                continue
            macro_usr = str(exact_bindings[0].get("usr") or "")
            if not macro_usr or any(
                str(binding.get("usr") or "") != macro_usr for binding in exact_bindings
            ):
                continue
            source_effects = _remap_macro_effects(
                source_effects,
                body=body,
                callee_name=calls[0],
                parameters=params,
            )
            if source_effects is None:
                continue
            source_cases = _remap_macro_value(
                source_cases, body=body, callee_name=calls[0], parameters=params,
                constants=constants,
            )
            if source_cases is None:
                continue
            definition = f"#define {name}({', '.join(params)}) {body}".rstrip()
            evidence_digest = canonical_digest(
                [
                    "zscope.project-macro-evidence.v3",
                    relative,
                    line,
                    definition,
                    calls[0],
                    source_effects,
                ]
            )
            row = {
                "id": stable_interface_id("macro", name, relative, macro_usr),
                "primitive": False,
                "selector": {
                    "kind": "macro",
                    "name": name,
                    "file": relative,
                    "signature": f"#define {name}({', '.join(params)})",
                    "usr": macro_usr,
                },
                "basis": "derived_wrapper",
                "status": "pending",
                "cases": source_cases or [{"when": {"op": "true"}, "effect": "unknown"}],
                "effects": source_effects,
                "otherwise": "unknown",
                "pairs": deepcopy(callee.get("pairs") or []),
                "derived_from": [str(callee.get("id") or f"builtin:{calls[0]}")],
                "evidence_summary": f"Current macro expansion delegates to {calls[0]}.",
                "native_evidence": {
                    "macro_definition": definition,
                    "parameters": params,
                    "parameter_map": {
                        str(index): parameter for index, parameter in enumerate(params)
                    },
                    "delegated_interface": str(callee.get("id") or f"builtin:{calls[0]}"),
                    "delegated_effects": deepcopy(source_effects),
                },
                "evidence_ref": "",
                "evidence_digest": evidence_digest,
                "variants": [
                    {
                        "target_id": str(binding.get("target_id") or ""),
                        "build_context_id": str(binding.get("build_context_id") or ""),
                        "usr": str(binding.get("usr") or ""),
                        "signature": f"#define {name}",
                        "file": relative,
                        "source_sha256": file_sha256(path),
                        "evidence_sha256": evidence_digest,
                        "native_input_hash": str(
                            binding.get("native_input_hash") or evidence_digest
                        ),
                        "identity_status": "exact",
                    }
                    for binding in exact_bindings
                ],
            }
            result.append(row)
            known[name] = row
            progressed = True
        if not progressed:
            break
        unresolved = next_unresolved
    return result


def _remap_macro_effects(
    effects: Sequence[Mapping[str, Any]],
    *,
    body: str,
    callee_name: str,
    parameters: Sequence[str],
) -> list[dict[str, Any]] | None:
    """Map a delegated macro carrier to the outer macro's exact object path."""

    arguments = _macro_arguments(body, callee_name)
    if arguments is None:
        return None
    remapped = [deepcopy(dict(effect)) for effect in effects]

    def mapped_argument(index: int) -> tuple[str, int | str] | None:
        if index >= len(arguments):
            return None
        actual = arguments[index].strip()
        if actual in parameters:
            return "argument", list(parameters).index(actual)
        global_match = re.fullmatch(r"&?\s*(?P<name>g_[A-Za-z_]\w*)", actual)
        if global_match is not None:
            return "global", global_match.group("name")
        return None

    for effect in remapped:
        carrier = effect.get("carrier") if isinstance(effect, Mapping) else None
        if isinstance(carrier, dict) and carrier.get("root") == "argument":
            mapped = mapped_argument(int(carrier.get("index") or 0))
            if mapped is None:
                return None
            if mapped[0] == "argument":
                carrier["index"] = int(mapped[1])
            else:
                phase = carrier.get("phase", "pre")
                carrier.clear()
                carrier.update(
                    {
                        "root": "global",
                        "name": str(mapped[1]),
                        "phase": phase,
                        "dereference": 0,
                        "members": [],
                    }
                )
        protocol = effect.get("protocol") if isinstance(effect, Mapping) else None
        if not isinstance(protocol, Mapping):
            continue
        for transition in protocol.get("transitions", []) or []:
            if not isinstance(transition, Mapping):
                continue
            for action in transition.get("actions", []) or []:
                if not isinstance(action, dict):
                    continue
                for key in ("object", "old", "new", "callback", "context"):
                    binding = action.get(key)
                    if not isinstance(binding, dict) or binding.get("kind") != "argument":
                        continue
                    mapped = mapped_argument(int(binding.get("argument_index") or 0))
                    if mapped is None:
                        return None
                    if mapped[0] == "argument":
                        binding["argument_index"] = int(mapped[1])
                    else:
                        action[key] = {
                            "kind": "global",
                            "global_name": str(mapped[1]),
                            "address_of": True,
                        }
    return remapped


def _macro_arguments(body: str, callee: str) -> list[str] | None:
    from ..semantics.contracts import code_tokens

    tokens = code_tokens(body)
    starts = [i + 2 for i in range(len(tokens) - 1) if tokens[i] == callee and tokens[i + 1] == "("]
    if len(starts) != 1:
        return None
    depth = 0
    current: list[str] = []
    arguments: list[str] = []
    for token in tokens[starts[0]:]:
        if token == ")" and depth == 0:
            return [*arguments, "".join(current)] if current or arguments else []
        if token == "," and depth == 0:
            arguments.append("".join(current))
            current = []
            continue
        depth += int(token in {"(", "[", "{"}) - int(token in {")", "]", "}"})
        current.append(token)
    return None


def _remap_macro_value(value: Any, *, body: str, callee_name: str,
                       parameters: Sequence[str], constants: Mapping[str, int]) -> Any:
    """Substitute predicates too, not only the effect's carrier argument."""
    args = _macro_arguments(body, callee_name)
    if args is None:
        return None

    def rewrite(item: Any) -> Any:
        if isinstance(item, list):
            return [rewrite(x) for x in item]
        if not isinstance(item, Mapping):
            return item
        if item.get("kind") == "argument":
            index = int(item.get("index", item.get("argument_index", -1)))
            if not 0 <= index < len(args):
                raise ValueError("macro argument unavailable")
            actual = args[index]
            if actual in parameters:
                mapped = {**item, "index": list(parameters).index(actual)}
                mapped.pop("argument_index", None)
                return mapped
            if actual in constants:
                return {"kind": "literal", "value": constants[actual]}
            if re.fullmatch(r"[-+]?\d+", actual):
                return {"kind": "literal", "value": int(actual)}
            if actual in {"NULL", "nullptr"}:
                return {"kind": "literal", "value": None}
            if re.fullmatch(r"&?[A-Za-z_]\w*", actual):
                name = actual.removeprefix("&")
                return {"kind": "global", "name": name, "global_name": name,
                        **({"address_of": True} if actual.startswith("&") else {})}
            raise ValueError("macro predicate substitution unsupported")
        return {key: rewrite(child) for key, child in item.items()}

    try:
        return rewrite(value)
    except ValueError:
        return None


def _macro_reference_bindings(
    code_index: Any,
    *,
    root: Path,
    build_ids: Sequence[str],
) -> tuple[dict[tuple[str, str, int], list[dict[str, Any]]], list[str]]:
    """Bind macro definitions to exact native compilation receipts.

    The batch indexer emits a ``macro`` row for every definition visible in a
    translation unit, including definitions that are not invoked in that TU.
    That is the correct authority for discovery: ``macro_reference`` alone
    would omit review-worthy wrappers such as an unused LOCK_READ macro, while
    source text alone would have no BuildContext identity.
    """

    getter = getattr(code_index, "get_compilation_facts", None)
    if not callable(getter):
        return {}, ["macro_native_facts_unavailable"]
    result: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    gaps: list[str] = []
    for build in build_ids:
        try:
            rows = list(getter(build, kinds=("macro",)) or [])
        except Exception as exc:
            gaps.append(f"macro_native_facts_unavailable:{build}:{type(exc).__name__}")
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            location = row.get("begin")
            location = location if isinstance(location, Mapping) else {}
            name = str(row.get("name") or "")
            usr = str(row.get("usr") or "")
            raw_file = str(location.get("file") or "")
            line = int(location.get("line") or 0)
            if not name or not usr or not raw_file or line <= 0 or not _inside(root, raw_file):
                continue
            relative = _project_file(root, raw_file).relative_to(root).as_posix()
            binding = {
                "build_context_id": build,
                "usr": usr,
                "native_input_hash": canonical_digest(row),
            }
            bucket = result[(name, relative, line)]
            if not any(
                str(item.get("build_context_id") or "") == build
                and str(item.get("usr") or "") == usr
                for item in bucket
            ):
                bucket.append(binding)
    return dict(result), gaps


def discover_project_primitives(
    config: Any, code_index: Any, *, llm_client: Any = None, progress: Any = None
) -> dict[str, Any]:
    from ..config.semantics_workflow import project_activity

    with project_activity(Path(config.project.project_root)):
        return _discover_locked(config, code_index, llm_client=llm_client, progress=progress)


def _discover_locked(
    config: Any, code_index: Any, *, llm_client: Any = None, progress: Any = None
) -> dict[str, Any]:
    from ..config.semantics_workflow import (
        discovery_snapshot, project_inputs, revision, roots_digest, SemanticsConflict,
    )

    def emit(stage: str, **details: Any) -> None:
        if progress is not None:
            progress(stage, details)

    project = config.project
    if str(project.language) == "java":
        raise ValueError("primitive discovery is available only for C/C++ projects")
    semantics_path = getattr(project, "semantics_file", None)
    if semantics_path is None:
        raise ValueError("project.semantics_file is required before primitive discovery")
    root = Path(project.project_root).resolve()
    store = ProjectSemanticsStore(Path(semantics_path))
    # A user may declare a confirmed project primitive before discovery with
    # an exact source selector but without knowing the generated
    # BuildContext id.  Only discovery may read that proposal in this relaxed
    # form; the binder must replace it with current native variants before the
    # store can pass the ordinary scan/prepare validation gate.
    document = store.read(allow_unbound_primitive_proposals=True)
    base_revision = revision(store.path)
    if not (document.get("discovery_receipt", {}).get("declaration") or any(
        row.get("primitive") for row in document["interfaces"]
    )):
        raise ValueError("请先声明项目原语；若没有已知自定义原语，使用项目原语页或 review-semantics --declare-none 明确声明。")
    emit("native_inventory")
    scopes, gaps, work, fact_manifests = _stream_function_work(code_index, root)
    snapshot = discovery_snapshot(config, code_index, document)

    native_failures = [
        gap
        for gap in gaps
        if gap.startswith(
            (
                "build_context_",
                "function_inventory_",
                "function_body_",
                "program_facts_",
            )
        )
    ]
    if native_failures:
        raise ValueError(
            "primitive discovery refused to update YAML because native coverage is incomplete: "
            + ", ".join(sorted(set(native_failures))[:24])
        )

    emit("binding_primitives", functions=len(scopes))
    configured_roots, root_gaps = _bind_configured_primitives(
        document,
        root=root,
        work=work,
    )
    gaps.extend(root_gaps)
    rebound = deepcopy(document)
    rebound_by_id = {row["id"]: row for row in configured_roots}
    rebound["interfaces"] = [rebound_by_id.get(row["id"], row) for row in document["interfaces"]]
    snapshot["roots_digest"] = roots_digest(rebound)
    emit("discovering_wrappers", functions=len(scopes))
    discovery_link_groups, link_group_gaps = _discovery_link_groups(
        code_index,
        build_ids=work,
    )
    gaps.extend(link_group_gaps)
    semantic_scopes, discovery_candidate_identities = _semantics_relevant_scopes(
        work,
        configured_roots,
        link_groups=discovery_link_groups,
    )
    reviewed_scopes, reviewed_scope_gaps = _reviewed_interface_definition_scopes(
        document,
        root=root,
        work=work,
    )
    gaps.extend(reviewed_scope_gaps)
    semantic_scopes = sorted(
        {
            (scope.build_context_id, scope.usr): scope
            for scope in [
                *semantic_scopes, *reviewed_scopes,
                # The model planner also examines units outside the native
                # wrapper checker's restricted root set. Establish current
                # builtin authority in every compiled TU without widening the
                # deterministic wrapper detector's claims.
                *(values[0][0] for values in work.values() if values),
            ]
        }.values(),
        key=lambda scope: (scope.build_context_id, scope.source, scope.usr),
    )
    context = freeze_instance_context(
        config=config,
        code_index=code_index,
        semantics_path=Path(semantics_path),
        scopes=semantic_scopes,
        # Discovery is the only workflow allowed to bind a user's exact,
        # confirmed primitive proposal before native variants have been
        # written back.  Normal scan callers keep the strict default.
        allow_unbound_primitive_proposals=True,
    )
    if context.unavailable:
        details = ", ".join(
            f"{identity}:{reason}" for identity, reason in sorted(context.unavailable.items())[:20]
        )
        raise ValueError("primitive discovery requires current exact native facts: " + details)

    found: list[dict[str, Any]] = list(configured_roots)
    proposal_roots: dict[str, list[Any]] = {}
    native_diagnostics: dict[tuple[str, str], dict[str, Any]] = {}
    roots_for_macros: dict[str, Mapping[str, Any]] = {}
    attempted = rejected = 0
    direct_cxx_new_factories = {
        scope.usr
        for functions in work.values()
        for scope, _impl, facts, _name, _signature in functions
        if any(
            isinstance(event, Mapping)
            and event.get("event_kind") == "acquire"
            and event.get("ast_kind") in {"CXXNewExpr", "CXXNewArrayExpr"}
            for body in facts.get("functions", []) or []
            if isinstance(body, Mapping)
            for event in body.get("events", []) or []
        )
        and any(
            isinstance(event, Mapping)
            and event.get("event_kind") == "return"
            and str(event.get("return_value") or "").strip().startswith("new ")
            for body in facts.get("functions", []) or []
            if isinstance(body, Mapping)
            for event in body.get("events", []) or []
        )
    }
    semantic_snapshots = {
        snapshot.scope.build_context_id: snapshot for snapshot in context.snapshots.values()
    }
    for build, functions in sorted(work.items()):
        emit("discovering_wrappers", build_context_id=build, processed=attempted)
        build_snapshot = semantic_snapshots.get(build)
        if build_snapshot is None:
            continue
        base_semantics, _base_overlay = materialize_effect_semantics(build_snapshot)
        raw_automatic = _base_overlay.get("automatic_contracts")
        automatic_contracts = (
            [dict(row) for row in raw_automatic if isinstance(row, dict)]
            if isinstance(raw_automatic, list)
            else []
        )
        proposal_roots[build] = list(base_semantics.contracts.contracts)
        configured_contracts = _configured_discovery_contracts(document, configured_roots, build)
        derived_contracts: list[ApiContract] = []
        # Configured primitive roots are inputs to the fixed point, not
        # candidates to derive from themselves.  Reprocessing them produced a
        # second project:function row for the same exact lock wrapper, forcing
        # a reviewer to decide two contracts for one symbol and allowing their
        # effects to diverge.
        accepted: set[tuple[str, str]] = {
            (build, str(variant.get("usr") or ""))
            for row in configured_roots
            for variant in row.get("variants", []) or []
            if isinstance(variant, Mapping)
            and str(variant.get("build_context_id") or "") == build
            and variant.get("usr")
        }
        for _pass in range(max(1, len(functions))):
            changed = False
            for scope, impl, facts, name, signature in functions:
                emit("discovering_wrappers", processed=attempted, function=name)
                key = (build, scope.usr)
                if key in accepted or scope.identity not in discovery_candidate_identities:
                    continue
                semantics = deepcopy(base_semantics)
                registry: ContractRegistry = semantics.contracts
                from ..semantics.automatic import align_project_identities

                # New discovery rows use relative selectors, whereas the
                # factory's automatic closure uses native absolute paths.
                # Their exact USR/build identity must remain one callee for
                # subsequent layers of wrapper composition.
                aligned = align_project_identities(
                    automatic_contracts,
                    [c.to_dict() for c in [*configured_contracts, *derived_contracts]],
                )
                for raw_contract in aligned:
                    derived_contract = ApiContract.from_row({"contract": raw_contract})
                    if derived_contract is None:
                        continue
                    registry.add(derived_contract)
                    semantics.add_api(
                        derived_contract.role,
                        derived_contract.symbol.name,
                        derived_contract.source,
                    )
                for root_contract in registry.contracts:
                    # Reviewer-owned configuration is reserved for effects
                    # that cross a function boundary with a rule-consumable
                    # carrier.  Generic copies and standard operations are
                    # still present in native facts, but a one-argument
                    # projection cannot faithfully describe their complete
                    # operand contract.  The narrow path-query subset is
                    # compiled by ``infer_native_wrapper`` above, not by this
                    # macro/wrapper projection.
                    if root_contract.role == "copy" or (
                        root_contract.role == "standard_operation"
                        and root_contract.symbol.name not in DISCOVERABLE_STANDARD_OPERATION_ROOTS
                    ):
                        continue
                    roots_for_macros.setdefault(
                        root_contract.symbol.name,
                        {
                            "id": f"builtin:{root_contract.symbol.name}",
                            "cases": deepcopy(root_contract.effect_cases),
                            "effects": [
                                {
                                    "domain": _domain_for_role(root_contract.role),
                                    "role": root_contract.role,
                                    "operation": root_contract.role,
                                    "carrier": _object_path(asdict(root_contract.carrier)),
                                    "resource_family": root_contract.resource_family,
                                    "strength": "must_under_guard",
                                    "protocol": deepcopy(root_contract.protocol),
                                }
                            ],
                            "pairs": [f"builtin:{target.name}" for target in root_contract.pairs],
                        },
                    )
                wrapper_context = {
                    "func_name": name,
                    "index_name": str(impl.get("index_name") or name),
                    "file_path": str(impl.get("file") or scope.source),
                    "start_line": int(impl.get("start_line") or 0),
                    "end_line": int(impl.get("end_line") or 0),
                    "signature": signature,
                    "is_static": bool(impl.get("is_static")),
                    "is_macro": False,
                    "code": str(impl.get("code") or ""),
                    "project_root": str(root),
                    "build_context_id": build,
                    "program_facts": facts,
                }
                cxx_factory_candidate = _cxx_new_factory_candidate(
                    facts=facts,
                    root=root,
                    source=str(impl.get("file") or scope.source),
                    code=str(impl.get("code") or ""),
                    build=build,
                    usr=scope.usr,
                    name=name,
                    signature=signature,
                )
                if cxx_factory_candidate is not None:
                    found.append(cxx_factory_candidate)
                    derived_contracts.extend(
                        _configured_discovery_contracts(
                            document,
                            [cxx_factory_candidate],
                            build,
                        )
                    )
                    accepted.add(key)
                    changed = True
                    continue
                aggregate_candidate = _returned_aggregate_member_factory_candidate(
                    facts=facts,
                    semantics=semantics,
                    direct_cxx_new_factories=direct_cxx_new_factories,
                    root=root,
                    source=str(impl.get("file") or scope.source),
                    code=str(impl.get("code") or ""),
                    build=build,
                    usr=scope.usr,
                    name=name,
                    signature=signature,
                )
                if aggregate_candidate is not None:
                    found.append(aggregate_candidate)
                    derived_contracts.extend(
                        _configured_discovery_contracts(
                            document,
                            [aggregate_candidate],
                            build,
                        )
                    )
                    accepted.add(key)
                    changed = True
                    continue
                # Composite object factories need their direct field def-use
                # interpreted before the generic one-carrier wrapper compiler.
                # Otherwise a successful root-level projection can consume
                # the function and silently discard its owned-member effects.
                factory_candidate = _owned_object_factory_candidate(
                    facts=facts,
                    semantics=semantics,
                    root=root,
                    source=str(impl.get("file") or scope.source),
                    code=str(impl.get("code") or ""),
                    build=build,
                    usr=scope.usr,
                    name=name,
                    signature=signature,
                )
                if factory_candidate is not None:
                    found.append(factory_candidate)
                    derived_contracts.extend(
                        _configured_discovery_contracts(
                            document,
                            [factory_candidate],
                            build,
                        )
                    )
                    accepted.add(key)
                    changed = True
                    continue
                inference = infer_native_wrapper(wrapper_context, registry)
                native_diagnostics[key] = {
                    "build_context_id": build, "usr": scope.usr, "name": name,
                    "attempted": inference["attempted"],
                    "reasons": inference["reasons"],
                    "native_contracts": len(inference["contracts"]),
                }
                if inference["attempted"]:
                    attempted += 1
                if inference["contracts"]:
                    for contract_row in inference["contracts"]:
                        candidate = _interface_from_contract(
                            contract_row,
                            root=root,
                            source=str(impl.get("file") or scope.source),
                            code=str(impl.get("code") or ""),
                            build_context_id=build,
                            usr=scope.usr,
                            signature=signature,
                        )
                        found.append(candidate)
                        # Propagation must use the candidate's exact current
                        # BuildContext/USR binding.  The native wrapper row is
                        # intentionally portable and can omit that identity;
                        # reusing it directly made the next fixed-point pass
                        # either name-only or unable to authorize composite
                        # factories.
                        derived_contracts.extend(
                            _configured_discovery_contracts(
                                document,
                                [candidate],
                                build,
                            )
                        )
                    accepted.add(key)
                    changed = True
                    continue
                lock_candidate = _lock_wrapper_candidate(
                    facts=facts,
                    semantics=semantics,
                    root=root,
                    source=str(impl.get("file") or scope.source),
                    code=str(impl.get("code") or ""),
                    build=build,
                    usr=scope.usr,
                    name=name,
                    signature=signature,
                )
                if lock_candidate is not None:
                    found.append(lock_candidate)
                    accepted.add(key)
                elif inference["reasons"]:
                    rejected += 1
            if not changed:
                break

    interfaces = _merge_variants(found)
    from .primitive_contract_proposals import propose_contracts

    build_ids = sorted(work)
    macro_bindings, macro_gaps = _macro_reference_bindings(
        code_index, root=root, build_ids=build_ids
    )
    gaps.extend(macro_gaps)
    interfaces, proposal_audit = propose_contracts(
        llm_client, work=work, roots=proposal_roots, link_groups=discovery_link_groups,
        existing=interfaces, root=root, progress=progress, macro_bindings=macro_bindings,
    )
    interfaces = _merge_variants(interfaces)
    macros = _macro_candidates(
        root=root,
        bindings=macro_bindings,
        interfaces=interfaces,
        roots=roots_for_macros,
        work=work,
        link_groups=discovery_link_groups,
    )
    interfaces = _merge_variants([*interfaces, *macros])
    from ..config.project_semantics import enrich_derived_interface_pairs

    # Unconfirmed model propositions cannot establish a new compatible
    # release relation for every allocator mentioning the same standard root.
    paired_interfaces = [
        *enrich_derived_interface_pairs([
            row for row in interfaces if row.get("proposal_origin") != "llm_source_composition"
        ]),
        *(row for row in interfaces if row.get("proposal_origin") == "llm_source_composition"),
    ]
    before_pairs = {
        str(row.get("id") or ""): sorted(str(value) for value in row.get("pairs", []) or [])
        for row in interfaces
    }
    for row in paired_interfaces:
        identifier = str(row.get("id") or "")
        if sorted(str(value) for value in row.get("pairs", []) or []) != before_pairs.get(
            identifier, []
        ):
            # Pair closure changes the reviewed semantic proposition.  Include
            # it in evidence identity so discovery never silently rewrites a
            # prior confirmed/rejected decision.
            row["evidence_digest"] = canonical_digest(
                {
                    "base_evidence_digest": row.get("evidence_digest"),
                    "derived_interface_pairs": row.get("pairs", []),
                }
            )
            for variant in row.get("variants", []) or []:
                if isinstance(variant, dict):
                    variant["evidence_sha256"] = row["evidence_digest"]
    interfaces = paired_interfaces

    pointer_bindings, pointer_gaps = _exact_pointer_bindings(work)
    gaps.extend(pointer_gaps)
    rooted_interface_instances = {
        (
            str(variant.get("build_context_id") or ""),
            str(variant.get("usr") or ""),
        )
        for interface in interfaces
        if interface.get("proposal_origin") != "llm_source_composition"
        for variant in interface.get("variants", []) or []
        if isinstance(variant, Mapping) and variant.get("build_context_id") and variant.get("usr")
    }
    emit("macros_pointers_dispatchers", interfaces=len(interfaces))
    dispatchers = _dispatcher_candidates(
        work,
        eligible_handler_instances=rooted_interface_instances,
        root=root,
    )
    target_id = str(getattr(project, "target_id", "") or "")
    for row in interfaces:
        for variant in row.get("variants", []) or []:
            if isinstance(variant, dict) and not variant.get("target_id"):
                variant["target_id"] = target_id
    for row in (*dispatchers, *pointer_bindings):
        row.setdefault("target_id", target_id)
    emit("model_review", candidates=len(interfaces))
    llm_audit = _review_discovery_candidates(
        llm_client,
        interfaces,
        document=document,
        work=work,
    )

    # Existing exact dispatcher and pointer rows are refreshed separately by
    # their dedicated extractors.  Weak legacy/name-only rows remain pending
    # and therefore cannot pass the scan gate.
    receipt = {
        "workflow": snapshot,
        "declaration": document.get("discovery_receipt", {}).get("declaration") or "custom",
        "schema": DISCOVERY_SCHEMA,
        "completed_at_epoch": int(time.time()),
        "catalog_version": "zscope.c-linux-catalog.v1",
        "project_semantics_schema": "zscope.project-semantics.v1",
        "input_digest": canonical_digest(
            {
                "document_roots": [
                    row
                    for row in document["interfaces"]
                    if row.get("primitive") is True and row.get("status") == "confirmed"
                ],
                "build_contexts": build_ids,
                "function_instances": [scope.identity for scope in scopes],
            }
        ),
        "build_context_ids": build_ids,
        "unique_function_instances": len(scopes),
        "analyzed_function_instances": sum(len(values) for values in work.values()),
        "function_fact_summaries": sorted(
            fact_manifests,
            key=lambda item: (
                str(item.get("build_context_id") or ""),
                str(item.get("usr") or ""),
            ),
        ),
        "wrapper_attempts": attempted,
        "wrapper_rejections": rejected,
        "native_discovery_diagnostics": list(native_diagnostics.values()),
        "contract_proposals": proposal_audit,
        "interface_candidates": len(interfaces),
        "macro_candidates": len(macros),
        "configured_primitive_candidates": len(configured_roots),
        "dispatchers": len(dispatchers),
        "function_pointer_bindings": len(pointer_bindings),
        "llm": {
            "policy": llm_audit.get("policy", "ambiguous_only_human_final"),
            "eligible": int(llm_audit.get("eligible") or 0),
            "reused_reviews": int(llm_audit.get("reused_reviews") or 0),
            "reviewed": int(llm_audit.get("reviewed") or 0),
            "evidence_completion_rounds": int(llm_audit.get("evidence_completion_rounds") or 0),
            "initial_requests": int(llm_audit.get("initial_requests") or 0),
            "completion_requests": int(llm_audit.get("completion_requests") or 0),
            "max_prompt_chars": int(llm_audit.get("max_prompt_chars") or 0),
            "invalid_fact_requests": len(llm_audit.get("invalid_fact_requests") or []),
            "errors": len(llm_audit.get("errors") or []),
        },
        "coverage_gaps": sorted(set(gaps)),
        # Unclosed pointer calls remain machine coverage gaps.  Only exact,
        # non-empty closed target sets are reviewable YAML bindings.
        "blocking_coverage_gaps": sorted(set(root_gaps + macro_gaps)),
    }
    emit("merging", candidates=len(interfaces), model_errors=len(llm_audit.get("errors") or []))
    if (revision(store.path) != base_revision
        or snapshot["inputs"] != project_inputs(root, getattr(config, "config_path", None))
        or discovery_snapshot(config, code_index, rebound)["native_tool"] != snapshot["native_tool"]):
        raise SemanticsConflict("发现期间输入或语义文档发生变化，未发布结果；请检查后重新执行。")
    evidence_ref = _write_discovery_evidence(
        root,
        receipt=receipt,
        interfaces=interfaces,
        dispatchers=dispatchers,
        pointer_bindings=pointer_bindings,
        llm_audit=llm_audit,
    )
    receipt["evidence_ref"] = evidence_ref
    for collection in (interfaces, dispatchers, pointer_bindings):
        for row in collection:
            if not row.get("evidence_ref"):
                row["evidence_ref"] = evidence_ref + f"#{row['id']}"
    human_receipt = _human_discovery_receipt(receipt)
    stats = store.merge_discovery(
        interfaces=interfaces,
        dispatchers=dispatchers,
        pointer_bindings=pointer_bindings,
        receipt=human_receipt,
        allow_unbound_primitive_proposals=True,
        expected_revision=base_revision,
    )
    return {"receipt": receipt, "merge": stats, "path": str(store.path)}
