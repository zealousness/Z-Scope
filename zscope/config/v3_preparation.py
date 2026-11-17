"""Read-only preparation of the single public configuration model.

No model, indexer, native tool, provider or usage state is started here.
Every target is checked and the projection contains no credentials.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .preparation import prepare_project
from .support import _resolve_config_path
from .v3 import DECLARED_ONLY, WIRED, compose_effective_config, parse_user_config_v3
from .project_semantics import load_project_semantics, semantics_readiness

V3_PREPARATION_SCHEMA = "zscope.config-v3-preparation.v1"
MULTI_TARGET_REASON = "multi_target_execution_unwired"

# Message codes from the shared preparation that describe one target's
# compile database rather than the document as a whole.
DATABASE_MESSAGE_CODES = frozenset(
    {
        "compile_commands_missing",
        "compile_commands_invalid",
        "compile_commands_incomplete",
        "multiple_compile_variants",
    }
)
# Document-level conditions that block starting a scan.
BLOCKING_DOCUMENT_CODES = frozenset({"project_missing"})
# Single-target compile database conditions that block starting a scan.
BLOCKING_DATABASE_CODES = frozenset({"compile_commands_missing", "compile_commands_invalid"})
# prepare_project sections that must stay identical across targets; if one
# ever becomes target-dependent the multi-target projection must be redone.
SHARED_SECTION_NAMES = ("project", "tools", "tool_check", "models", "scan")


def prepare_saved_config(
    config_path: Optional[str] = None, *, now: Optional[datetime] = None
) -> Dict[str, Any]:
    """Project one saved configuration into read-only preparation data.

    ``config_path`` follows the existing loader conventions (explicit path;
    ``None`` means ``./zscope.yaml``).  ``now`` is only used to resolve a v3
    ``execution.stop_at`` boundary deterministically; the default resolves
    against the real current time.  The result is JSON-serializable and
    contains no credentials, LLM profile details, raw YAML, environment
    values, or compile command contents.
    """

    path = _resolve_config_path(config_path)
    return _prepare_v3(path, now=now)


def _prepare_v3(path: Path, *, now: Optional[datetime]) -> Dict[str, Any]:
    model = parse_user_config_v3(str(path), now=now)
    # Compose one single-target execution chain per target so every target
    # gets its own read-only diagnostics; no target is dropped and the first
    # one is never presented as the whole project.
    outputs = [
        prepare_project(
            compose_effective_config(
                replace(model, project=replace(model.project, targets=(target,)))
            ),
            path,
        )
        for target in model.project.targets
    ]
    _assert_shared_sections_stay_shared(outputs)

    multi = len(model.project.targets) != 1
    envelope = dict(outputs[0])
    if multi:
        envelope["build"] = {"status": "multi_target", "link_targets": "unverified"}
        envelope["messages"] = _document_messages(outputs)
    envelope["version3"] = _version3_block(model, outputs, multi=multi)
    return envelope


def _assert_shared_sections_stay_shared(outputs: List[Dict[str, Any]]) -> None:
    if len(outputs) <= 1:
        return
    for name in SHARED_SECTION_NAMES:
        for output in outputs[1:]:
            if output[name] != outputs[0][name]:
                raise RuntimeError(
                    f"preparation section {name!r} became target-dependent; the "
                    "v3 multi-target projection can no longer share it"
                )


def _document_messages(outputs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    seen: set = set()
    messages: List[Dict[str, str]] = []
    for output in outputs:
        for message in output["messages"]:
            if message["code"] in DATABASE_MESSAGE_CODES:
                continue
            key = (message["code"], message["message"])
            if key not in seen:
                seen.add(key)
                messages.append(message)
    return messages


def _version3_block(model: Any, outputs: List[Dict[str, Any]], *, multi: bool) -> Dict[str, Any]:
    states = {note.field: note.state for note in model.wiring}
    window = model.execution.stop_window

    targets: List[Dict[str, Any]] = []
    for target, output in zip(model.project.targets, outputs):
        database = target.compile_commands
        targets.append(
            {
                "id": target.id,
                "compile_commands": str(database) if database is not None else None,
                # Null (not false) for targets without a database concept:
                # untested, not "failed".
                "database_exists": database.is_file() if database is not None else None,
                "build": output["build"],
                "messages": [
                    message
                    for message in output["messages"]
                    if message["code"] in DATABASE_MESSAGE_CODES
                ],
            }
        )

    semantics_payload: Dict[str, Any]
    semantics_reasons: List[Dict[str, str]] = []
    semantics_path = model.project.semantics_file
    if model.project.language == "java":
        semantics_payload = {"applicable": False, "ready": True, "path": None, "reasons": []}
    elif semantics_path is None:
        semantics_reasons.append(
            {
                "code": "project_semantics_not_configured",
                "message": "C/C++ requires project.semantics_file before discovery or scanning.",
            }
        )
        semantics_payload = {
            "applicable": True,
            "ready": False,
            "path": None,
            "reasons": list(semantics_reasons),
        }
    else:
        try:
            readiness = semantics_readiness(
                load_project_semantics(semantics_path), project_root=model.project.root
            )
        except (OSError, ValueError) as exc:
            semantics_reasons.append(
                {"code": "project_semantics_invalid", "message": str(exc)}
            )
            semantics_payload = {
                "applicable": True,
                "ready": False,
                "path": str(semantics_path),
                "reasons": list(semantics_reasons),
            }
        else:
            from .semantics_workflow import workflow_status

            workflow = workflow_status(
                load_project_semantics(semantics_path), model.project.root, model.config_path
            )
            semantics_payload = {
                "applicable": True,
                "path": str(semantics_path),
                **readiness.to_dict(),
                "workflow": workflow,
                "ready": workflow["ready"],
            }
            semantics_reasons.extend(
                {"code": "project_semantics_not_ready", "message": reason}
                for reason in (workflow["reasons"] or ([] if workflow["ready"] else ["请完成项目原语发现与人工审阅。"]))
            )

    return {
        "schema": V3_PREPARATION_SCHEMA,
        "project_root": str(model.project.root),
        "platform": model.project.platform,
        "targets": targets,
        "project_semantics": semantics_payload,
        "preset": {
            "preset": model.scan.preset,
            "mapped_depth": model.scan.mapped_depth,
            "depth_source": model.scan.mapped_depth_source,
            "mapping_note": model.scan.mapping_note,
        },
        "focus": list(model.scan.focus),
        "reproduction": model.scan.reproduction,
        "max_workers": model.execution.max_workers,
        "execution": {
            "timezone": model.execution.timezone,
            "stop_at_local": model.execution.stop_at,
            "resolved_stop_time": (
                window.resolved_stop_time.isoformat() if window is not None else None
            ),
            # The boundary is parsed and held once per load and consumed for
            # real: CLI scan sessions arm it as a cooperative monotonic
            # deadline, and persistent job starts persist it as the job's
            # stop window when the request carries no explicit stop_at (the
            # owner/scheduler chain enforces the persisted epoch).  The
            # scanner-internal session-scheduler cooperation is tracked
            # separately as checkpoint work.
            "scheduler_consumer_wired": True,
        },
        "wiring": [
            {"field": note.field, "state": note.state, "detail": note.detail}
            for note in model.wiring
        ],
        "declared_not_consumed": [
            note.field for note in model.wiring if note.state == DECLARED_ONLY
        ],
        # Accurate machine disclosure: parsing a field is not enabling it.
        "machine_flags": {
            "focus_wired": states.get("scan.focus") == WIRED,
            "reproduction_wired": states.get("scan.reproduction") == WIRED,
            "max_workers_wired": states.get("execution.max_workers") == WIRED,
            "platform_wired": states.get("project.platform") == WIRED,
            # The stop window is consumed by the CLI session deadline and by
            # persistent job starts (request stop_at overrides); see the
            # execution block above for the exact scope.
            "stop_window_scheduler_wired": True,
        },
        "start_capability": _start_capability(
            outputs, multi=multi, semantic_reasons=semantics_reasons
        ),
    }


def _start_capability(
    outputs: List[Dict[str, Any]],
    *,
    multi: bool,
    semantic_reasons: Sequence[Dict[str, str]] = (),
) -> Dict[str, Any]:
    reasons: List[Dict[str, str]] = [dict(reason) for reason in semantic_reasons]
    if multi:
        reasons.append(
            {
                "code": MULTI_TARGET_REASON,
                "message": (
                    "Multi-target execution is not wired; declare a single "
                    "project.targets entry or stay on public config v2."
                ),
            }
        )
    messages = _document_messages(outputs) if multi else outputs[0]["messages"]
    blocking = BLOCKING_DOCUMENT_CODES | (set() if multi else BLOCKING_DATABASE_CODES)
    for message in messages:
        if message["code"] in blocking:
            reasons.append({"code": message["code"], "message": message["message"]})
    return {"startable": not reasons, "reasons": reasons}
