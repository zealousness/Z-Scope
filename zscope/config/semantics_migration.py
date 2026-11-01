"""One-way migration from the legacy XLSX workbook to project semantics YAML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .project_semantics import (
    ProjectSemanticsStore,
    canonical_digest,
    empty_project_semantics,
    stable_interface_id,
)
from .user_config_workbook import SYMBOL_SHEETS, UserConfigWorkbook
from ..semantics.contracts import ApiContract, ObjectBinding


def _object_path(binding: ObjectBinding) -> dict[str, Any]:
    members = [part for part in binding.member_path.replace(".", "->").split("->") if part]
    if binding.kind == "return":
        return {"root": "return", "phase": "post", "dereference": 0, "members": members}
    if binding.kind == "global":
        return {
            "root": "global",
            "name": binding.global_name,
            "phase": "post",
            "dereference": 0,
            "members": members,
        }
    return {
        "root": "argument",
        "index": int(binding.argument_index or 0),
        "phase": "post",
        "dereference": 1 if binding.kind == "output_argument" else 0,
        "members": members,
    }


def _effect_domain(role: str) -> str:
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
    return "resource"


def _row_contract(row: Mapping[str, Any]) -> ApiContract | None:
    candidate = dict(row)
    # A pending legacy contract is still useful as a proposed specification;
    # ApiContract deliberately refuses it as executable input, so parse a
    # copy with a non-authorizing status solely for migration.
    if str(candidate.get("status") or "").lower() not in {"rejected"}:
        candidate["status"] = "active"
    return ApiContract.from_row(candidate)


def migrate_workbook_document(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a strict semantics document and a complete migration report.

    Nothing migrated from XLSX is immediately executable.  Resource/lock
    specifications become primitive proposals and must be rebound to current
    native identities by discovery before a reviewer can confirm them.
    """

    workbook = UserConfigWorkbook(Path(path))
    rows = workbook.read_rows()
    document = empty_project_semantics()
    interfaces: list[dict[str, Any]] = []
    name_to_id: dict[str, str] = {}
    skipped: list[dict[str, str]] = []

    symbol_rows: list[tuple[str, Mapping[str, Any]]] = []
    for sheet in (*SYMBOL_SHEETS, "contract_review"):
        symbol_rows.extend((sheet, row) for row in rows.get(sheet, []))
    for sheet, row in symbol_rows:
        contract = _row_contract(row)
        name = str(row.get("symbol_name") or "")
        if contract is None or not name:
            skipped.append(
                {
                    "sheet": sheet,
                    "identity": name or str(row.get("review_id") or ""),
                    "reason": "invalid_or_non_contract_row",
                }
            )
            continue
        file_path = str(contract.symbol.file_path or row.get("file_path") or "").replace("\\", "/")
        signature = str(contract.symbol.signature or row.get("signature") or "")
        identifier = stable_interface_id("function", name, file_path, "")
        # Prefer the reviewed contract when the same symbol also appears in a
        # materialized resource/lock row.
        existing_index = next(
            (index for index, item in enumerate(interfaces) if item["id"] == identifier), None
        )
        pairs = [target.name for target in contract.pairs if target.name]
        legacy_status = str(row.get("status") or contract.status or "").lower()
        migrated_status = "rejected" if legacy_status == "rejected" else "pending"
        item = {
            "id": identifier,
            "primitive": True,
            "selector": {
                "kind": "function",
                "name": name,
                "file": file_path,
                "signature": signature,
                "usr": "",
            },
            "basis": "expected_contract",
            "status": migrated_status,
            "cases": contract.effect_cases
            or [{"when": contract.preconditions or {"op": "true"}, "effect": "applies"}],
            "effects": [
                {
                    "domain": _effect_domain(contract.role),
                    "role": contract.role,
                    "operation": contract.role,
                    "carrier": _object_path(contract.carrier),
                    "resource_family": contract.resource_family,
                    "strength": "must_under_guard",
                    "preconditions": contract.preconditions or {"op": "true"},
                    "protocol": contract.protocol or {},
                }
            ],
            "otherwise": "unknown",
            "pairs": pairs,
            "derived_from": [],
            "evidence_summary": (
                f"Migrated from XLSX {sheet}; native identity must be resolved and reviewed."
            ),
            "evidence_ref": "",
            "evidence_digest": canonical_digest(
                {"sheet": sheet, "row": dict(row), "contract": contract.to_dict()}
            ),
            "variants": [],
            "migration": {
                "legacy_sheet": sheet,
                "legacy_status": legacy_status,
                "legacy_source": str(row.get("source") or contract.source or ""),
            },
        }
        if existing_index is None:
            interfaces.append(item)
        elif sheet == "contract_review":
            interfaces[existing_index] = item
        name_to_id[name] = identifier

    for item in interfaces:
        item["pairs"] = sorted(
            {name_to_id.get(name, f"builtin:{name}") for name in item["pairs"] if name}
        )
    document["interfaces"] = sorted(interfaces, key=lambda item: item["id"])

    dispatchers: list[dict[str, Any]] = []
    for row in rows.get("dispatcher", []):
        name = str(row.get("dispatcher_name") or "")
        handler = str(row.get("handler_name") or "")
        if not name:
            continue
        dispatchers.append(
            {
                "id": stable_interface_id("dispatcher", name, str(row.get("file_path") or "")),
                "status": "pending",
                "dispatcher": name,
                "file": str(row.get("file_path") or "").replace("\\", "/"),
                "build_context_id": "",
                "usr": "",
                "handler_name": handler,
                "handler_usr": "",
                "guard": str(row.get("message_type") or ""),
                "evidence_summary": "Migrated name-level dispatcher; exact CFG identity is unresolved.",
                "evidence_digest": canonical_digest(dict(row)),
            }
        )
    document["dispatchers"] = dispatchers

    pointer_bindings: list[dict[str, Any]] = []
    for row in rows.get("pointer_targets", []):
        raw_targets: Any = row.get("target_functions") or []
        if isinstance(raw_targets, str):
            try:
                raw_targets = json.loads(raw_targets)
            except ValueError:
                raw_targets = [item.strip() for item in raw_targets.split(",") if item.strip()]
        targets = [str(value) for value in raw_targets] if isinstance(raw_targets, list) else []
        location = str(row.get("pointer_location") or "")
        if not location:
            continue
        pointer_bindings.append(
            {
                "id": stable_interface_id(
                    "function_pointer_slot", location, str(row.get("scope") or "")
                ),
                "status": "pending",
                "file": str(row.get("scope") or "").replace("\\", "/"),
                "callsite_id": "",
                "build_context_id": "",
                "slot_usr": "",
                "target_names": targets,
                "target_usrs": [],
                "attribution": "unresolved",
                "evidence_summary": "Migrated name-level pointer binding; exact slot/callsite is unresolved.",
                "evidence_digest": canonical_digest(dict(row)),
            }
        )
    document["function_pointer_bindings"] = pointer_bindings

    removed = {
        "module_lifecycle": [dict(row) for row in rows.get("module_lifecycle", [])],
        "function_intents": [dict(row) for row in rows.get("function_intents", [])],
    }
    report = {
        "schema": "zscope.semantics-migration-report.v1",
        "source": str(Path(path).resolve()),
        "source_preserved": True,
        "interfaces": len(document["interfaces"]),
        "dispatchers_pending_rebind": len(dispatchers),
        "pointer_bindings_pending_rebind": len(pointer_bindings),
        "removed": removed,
        "skipped": skipped,
        "notes": [
            "No migrated XLSX row is executable until discovery resolves current native identity and a reviewer confirms it.",
            "module_lifecycle and function_intents are not project semantics; function intent belongs to LLM Wiki.",
        ],
    }
    document["discovery_receipt"] = {
        "schema": "zscope.semantics-migration.v1",
        "source_sha256": canonical_digest(rows),
        "report_digest": canonical_digest(report),
    }
    return document, report


def write_migrated_semantics(xlsx_path: Path, output_path: Path) -> dict[str, Any]:
    document, report = migrate_workbook_document(xlsx_path)
    ProjectSemanticsStore(output_path).write(document)
    return report
