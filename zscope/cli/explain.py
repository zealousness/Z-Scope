"""Read, replay, and locally reverify one frozen issue-decision trace."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, cast

from ..core.validation.authority import (
    LEGACY_TERMINAL_AUTHORITY_DECISION_V3,
    TERMINAL_AUTHORITY_DECISION_V4,
    TerminalAuthorityEvaluator,
)
from ..core.validation.fact_capabilities import verify_certificate_v2
from ..core.validation.proof_kernel import (
    PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
    ProofKernelEngine,
)
from ..core.validation.proof_kernel.checker import ProofChecker
from ..orchestration.decision_trace import (
    DecisionTraceError,
    load_decision_trace,
    verify_evidence_object,
    verify_model_event,
)


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DecisionTraceError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DecisionTraceError(f"{path} must contain one JSON object")
    return cast(Dict[str, Any], value)


def _items(report: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    for key in ("issues", "observations", "candidate_terminal_states"):
        values = report.get(key)
        if isinstance(values, list):
            yield from (value for value in values if isinstance(value, Mapping))
    views = report.get("report_views")
    if isinstance(views, Mapping):
        for value in views.values():
            if isinstance(value, list):
                yield from (item for item in value if isinstance(item, Mapping))
            elif isinstance(value, Mapping) and isinstance(value.get("issues"), list):
                yield from (item for item in value["issues"] if isinstance(item, Mapping))


def _matches(item: Mapping[str, Any], *, cluster: str, candidate: str, root: str) -> bool:
    if cluster and str(item.get("validation_cluster_uid") or "") == cluster:
        return True
    if candidate and candidate in {
        str(item.get("candidate_uid") or ""),
        *[str(value) for value in item.get("member_candidate_uids") or []],
    }:
        return True
    return bool(root and str(item.get("finding_root_uid") or "") == root)


def _safe_child(root: Path, relative: str) -> Path:
    path = Path(relative)
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise DecisionTraceError("trace reference escapes the snapshot directory")
    current = candidate
    while current != resolved_root:
        if current.is_symlink():
            raise DecisionTraceError("trace reference traverses a symbolic link")
        current = current.parent
    return candidate


def _manifest(report: Mapping[str, Any], report_path: Path) -> tuple[Dict[str, Any], Path]:
    run_manifest = report.get("run_manifest")
    run_manifest = run_manifest if isinstance(run_manifest, Mapping) else {}
    summary = run_manifest.get("decision_trace")
    summary = summary if isinstance(summary, Mapping) else {}
    raw_path = str(summary.get("manifest_path") or "")
    if not raw_path:
        raise DecisionTraceError("report has no decision-trace manifest reference")
    manifest_path = Path(raw_path)
    if not manifest_path.is_absolute():
        manifest_path = (report_path.parent / manifest_path).resolve()
    manifest = _load_json(manifest_path)
    supplied = str(manifest.get("manifest_sha256") or "")
    body = dict(manifest)
    body.pop("manifest_sha256", None)
    actual = hashlib.sha256(
        json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if supplied != actual:
        raise DecisionTraceError("decision-trace manifest hash mismatch")
    usage = manifest.get("llm_usage_events")
    if isinstance(usage, Mapping) and usage.get("available"):
        if usage.get("conservation_valid") is not True:
            raise DecisionTraceError(
                "decision trace and LLM usage ledger do not conserve calls/tokens"
            )
        usage_ref = str(usage.get("path") or "")
        expected_usage_sha = str(usage.get("file_sha256") or "")
        if not usage_ref or not expected_usage_sha:
            raise DecisionTraceError("LLM usage sidecar binding is incomplete")
        usage_path = _safe_child(manifest_path.parent, usage_ref)
        actual_usage_sha = hashlib.sha256(usage_path.read_bytes()).hexdigest()
        if actual_usage_sha != expected_usage_sha:
            raise DecisionTraceError("LLM usage sidecar hash mismatch")
    return manifest, manifest_path.parent


def _resolve_trace(
    report: Mapping[str, Any],
    report_path: Path,
    *,
    cluster: str,
    candidate: str,
    root: str,
) -> tuple[Dict[str, Any], Mapping[str, Any], Path]:
    selected = next(
        (
            item
            for item in _items(report)
            if _matches(item, cluster=cluster, candidate=candidate, root=root)
        ),
        None,
    )
    manifest, snapshot_root = _manifest(report, report_path)
    trace_ref = str(selected.get("decision_trace_ref") or "") if selected is not None else ""
    if not trace_ref and cluster:
        traces = manifest.get("traces")
        record = traces.get(cluster) if isinstance(traces, Mapping) else None
        trace_ref = str(record.get("path") or "") if isinstance(record, Mapping) else ""
    if not trace_ref:
        raise DecisionTraceError("no matching finding or cluster trace was found")
    trace_path = _safe_child(snapshot_root, trace_ref)
    trace = load_decision_trace(trace_path)
    trace_root = str(trace.get("trace_root_sha256") or "")
    traces = manifest.get("traces")
    manifest_record = (
        traces.get(str(trace.get("validation_cluster_uid") or ""))
        if isinstance(traces, Mapping)
        else None
    )
    if (
        isinstance(manifest_record, Mapping)
        and str(manifest_record.get("trace_root_sha256") or "") != trace_root
    ):
        raise DecisionTraceError("manifest trace root does not match the trace")
    trace_document_hash = str(trace.get("document_sha256") or "")
    if selected is not None:
        selected_hash = str(selected.get("decision_trace_sha256") or "")
        if selected_hash and selected_hash != trace_document_hash:
            raise DecisionTraceError("finding decision_trace_sha256 does not match the document")
    if (
        isinstance(manifest_record, Mapping)
        and str(manifest_record.get("document_sha256") or "") != trace_document_hash
    ):
        raise DecisionTraceError("manifest trace document hash does not match the trace")
    for event in trace.get("events") or []:
        if not isinstance(event, Mapping):
            continue
        for reference in (
            *tuple(event.get("input_refs") or []),
            *tuple(event.get("output_refs") or []),
        ):
            ref = str(reference)
            if ref.startswith("evidence_objects/"):
                valid, reason = verify_evidence_object(_safe_child(snapshot_root, ref))
            elif ref.startswith("model_events/"):
                valid, reason = verify_model_event(_safe_child(snapshot_root, ref))
            else:
                raise DecisionTraceError(f"unsupported content-addressed reference: {ref}")
            if not valid:
                raise DecisionTraceError(f"invalid referenced object {ref}: {reason}")
    if selected is None:
        selected = {}
    return trace, selected, snapshot_root


def _load_evidence(snapshot_root: Path, reference: str) -> Dict[str, Any]:
    path = _safe_child(snapshot_root, reference)
    valid, reason = verify_evidence_object(path)
    if not valid:
        raise DecisionTraceError(f"invalid evidence object {reference}: {reason}")
    return _load_json(path)


def _explanation(trace: Mapping[str, Any], item: Mapping[str, Any]) -> Dict[str, Any]:
    events = [dict(value) for value in trace.get("events") or [] if isinstance(value, Mapping)]
    usage = {
        "call_ids": sorted(
            {
                str(call_id)
                for event in events
                for call_id in event.get("call_ids") or []
                if str(call_id)
            }
        ),
        "tool_call_ids": sorted(
            {
                str(call_id)
                for event in events
                for call_id in event.get("tool_call_ids") or []
                if str(call_id)
            }
        ),
        "total_tokens": sum(int(event.get("token_delta") or 0) for event in events),
    }
    return {
        "schema_version": "zscope.issue-explanation.v1",
        "validation_cluster_uid": trace.get("validation_cluster_uid"),
        "candidate_uids": trace.get("candidate_uids") or [],
        "occurrence_uids": trace.get("occurrence_uids") or [],
        "terminal_disposition": trace.get("terminal_disposition"),
        "terminal_event_uid": trace.get("terminal_event_uid"),
        "terminal_authority": trace.get("terminal_authority"),
        "terminal_reason_codes": trace.get("terminal_reason_codes") or [],
        "view_memberships": trace.get("view_memberships") or [],
        "finding_root": trace.get("finding_root") or {},
        "open_clause_ids": item.get("open_clause_ids") or [],
        "usage": usage,
        "timeline": [
            {
                key: event.get(key)
                for key in (
                    "sequence",
                    "event_uid",
                    "stage",
                    "actor",
                    "reason_code",
                    "disposition_before",
                    "disposition_after",
                    "closed_clause_ids",
                    "open_clause_ids",
                    "call_ids",
                    "tool_call_ids",
                    "token_delta",
                    "details",
                )
            }
            for event in events
        ],
    }


def _policy_input(trace: Mapping[str, Any], snapshot_root: Path) -> Dict[str, Any]:
    terminal = next(
        (
            event
            for event in reversed(list(trace.get("events") or []))
            if isinstance(event, Mapping) and event.get("stage") == "policy"
        ),
        None,
    )
    if terminal is None:
        raise DecisionTraceError("trace has no terminal policy event")
    policy_ref = next(
        (
            str(value)
            for value in terminal.get("input_refs") or []
            if "evidence_objects/" in str(value)
        ),
        "",
    )
    if not policy_ref:
        raise DecisionTraceError("terminal policy input was not retained")
    record = _load_evidence(snapshot_root, policy_ref)
    payload = record.get("payload")
    payload = payload if isinstance(payload, Mapping) else {}
    issue = dict(payload.get("issue") or {})
    for key in (
        "decision_proof",
        "evidence_closure_state",
        "v3_evidence_closure",
        "proof_kernel_input",
        "proof_kernel_frozen_state",
        "proof_kernel_closure_evaluation",
        "proof_kernel_promotion_certificate",
        "terminal_authority_decision",
    ):
        if isinstance(payload.get(key), Mapping):
            issue[key] = dict(payload[key])
    proof_decision = payload.get("proof_kernel_terminal_authority_decision")
    if isinstance(proof_decision, Mapping):
        issue["proof_kernel_terminal_authority_decision"] = dict(proof_decision)
    issue["proof_kernel_artifact_refs"] = list(payload.get("proof_kernel_artifact_refs") or [])
    issue["proof_kernel_checker_results"] = list(payload.get("proof_kernel_checker_results") or [])
    issue["proof_kernel_checker_result_refs"] = list(
        payload.get("proof_kernel_checker_result_refs") or []
    )
    issue["proof_kernel_live_selected_action_uids"] = list(
        payload.get("proof_kernel_live_selected_action_uids") or []
    )
    issue["proof_kernel_root_manifest_sha256"] = str(
        payload.get("proof_kernel_root_manifest_sha256") or ""
    )
    return issue


def _failed_policy_replay(expected: str, policy_issue: str) -> Dict[str, Any]:
    replay = (
        TerminalAuthorityEvaluator()
        .evaluate({}, protocol_or_engine_failure=True, operation="audit")
        .to_dict()
    )
    replay.update(
        {
            "matches_frozen_terminal": False,
            "expected_terminal_disposition": expected,
            "policy_issue": policy_issue,
        }
    )
    return replay


def _json_equal(left: Any, right: Any) -> bool:
    return json.dumps(
        left,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) == json.dumps(
        right,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _policy_replay(trace: Mapping[str, Any], snapshot_root: Path) -> Dict[str, Any]:
    expected = str(trace.get("terminal_disposition") or "")
    issue = _policy_input(trace, snapshot_root)
    recorded_authority = issue.get("terminal_authority_decision")
    recorded_engine_authority = issue.get("proof_kernel_terminal_authority_decision")
    schemas = {
        str(value.get("schema_version") or "")
        for value in (recorded_authority, recorded_engine_authority)
        if isinstance(value, Mapping)
    }
    if LEGACY_TERMINAL_AUTHORITY_DECISION_V3 in schemas:
        return _failed_policy_replay(expected, "legacy_v3_audit_only")
    if not (
        isinstance(recorded_authority, Mapping)
        and recorded_authority.get("schema_version") == TERMINAL_AUTHORITY_DECISION_V4
        and isinstance(recorded_engine_authority, Mapping)
        and recorded_engine_authority.get("schema_version") == TERMINAL_AUTHORITY_DECISION_V4
    ):
        return _failed_policy_replay(expected, "terminal_authority_v4_unavailable")

    raw = issue.get("proof_kernel_input")
    if (
        not isinstance(raw, Mapping)
        or set(raw)
        != {
            "schema_version",
            "proof_ir",
            "proof_obligation",
            "selected_action_uids",
        }
        or raw.get("schema_version") != PROOF_KERNEL_AUTHORITY_INPUT_VERSION
    ):
        return _failed_policy_replay(expected, "proof_kernel_input_unavailable")
    selected = raw.get("selected_action_uids")
    live_selected = issue.get("proof_kernel_live_selected_action_uids")
    if not (
        isinstance(raw.get("proof_ir"), Mapping)
        and isinstance(raw.get("proof_obligation"), Mapping)
        and isinstance(selected, list)
        and all(isinstance(value, str) and value for value in selected)
        and len(selected) == len(set(selected))
        and isinstance(live_selected, list)
        and all(isinstance(value, str) and value for value in live_selected)
        and len(live_selected) == len(set(live_selected))
    ):
        return _failed_policy_replay(expected, "proof_kernel_input_invalid")
    try:
        engine = ProofKernelEngine()
        evaluation = (
            engine.evaluate_selected_actions(
                proof_ir=raw["proof_ir"],
                obligation=raw["proof_obligation"],
                selected_action_uids=tuple(live_selected),
            )
            if live_selected
            else engine.evaluate(
                proof_ir=raw["proof_ir"],
                obligation=raw["proof_obligation"],
            )
        )
    except (KeyError, TypeError, ValueError):
        return _failed_policy_replay(expected, "proof_kernel_reduction_failed")

    promotion = (
        evaluation.promotion_certificate.to_dict()
        if evaluation.promotion_certificate is not None
        else None
    )
    stored_promotion = issue.get("proof_kernel_promotion_certificate")
    if stored_promotion == {}:
        stored_promotion = None
    exact_projection = bool(
        issue.get("proof_kernel_frozen_state") == evaluation.frozen_state.to_dict()
        and issue.get("proof_kernel_closure_evaluation") == evaluation.closure_evaluation.to_dict()
        and stored_promotion == promotion
        and issue.get("proof_kernel_checker_results")
        == [dict(value) for value in evaluation.check_results]
        and issue.get("proof_kernel_artifact_refs") == list(evaluation.artifact_refs)
        and issue.get("proof_kernel_checker_result_refs") == list(evaluation.checker_result_refs)
        and issue.get("proof_kernel_root_manifest_sha256") == evaluation.root_manifest_sha256
    )
    if not exact_projection:
        return _failed_policy_replay(expected, "proof_kernel_replay_binding_mismatch")

    carrier: Dict[str, Any] = {}
    evaluation.apply_to_issue(carrier)
    replay = TerminalAuthorityEvaluator().evaluate(carrier, operation="audit").to_dict()
    exact_terminal = bool(
        _json_equal(recorded_authority, replay)
        and _json_equal(recorded_engine_authority, replay)
        and str(replay.get("disposition") or "") == expected
    )
    replay["matches_frozen_terminal"] = exact_terminal
    replay["expected_terminal_disposition"] = expected
    replay["policy_issue"] = "none" if exact_terminal else "terminal_authority_replay_mismatch"
    return replay


def _current_revision(project_root: Path) -> str:
    git_dir = project_root / ".git"
    try:
        if git_dir.is_file():
            marker = git_dir.read_text(encoding="utf-8").strip()
            if marker.lower().startswith("gitdir:"):
                value = Path(marker.split(":", 1)[1].strip())
                git_dir = value if value.is_absolute() else (project_root / value).resolve()
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            return (git_dir / head.split(":", 1)[1].strip()).read_text(encoding="utf-8").strip()
        return head
    except OSError:
        return ""


def _reverify(
    trace: Mapping[str, Any],
    snapshot_root: Path,
    *,
    allow_incomplete_trace: bool = False,
) -> Dict[str, Any]:
    identity = trace.get("identity")
    identity = identity if isinstance(identity, Mapping) else {}
    project_root = Path(str(identity.get("project_root") or ""))
    expected_revision = str(identity.get("project_revision") or "")
    if expected_revision and project_root.exists():
        current = _current_revision(project_root)
        if current and current != expected_revision:
            raise DecisionTraceError("project revision changed; frozen claim comparison is refused")
    try:
        policy = _policy_replay(trace, snapshot_root)
        policy_issue = _policy_input(trace, snapshot_root)
    except DecisionTraceError:
        if not allow_incomplete_trace:
            raise
        policy = {
            "available": False,
            "reason": "interrupted_trace_has_no_terminal_policy_event",
        }
        policy_issue = {}
    results: list[Dict[str, Any]] = []
    for event in trace.get("events") or []:
        if not isinstance(event, Mapping) or event.get("stage") != "verifier":
            continue
        inputs = [_load_evidence(snapshot_root, str(ref)) for ref in event.get("input_refs") or []]
        outputs = [
            _load_evidence(snapshot_root, str(ref)) for ref in event.get("output_refs") or []
        ]
        action_certificate = next(
            (value for value in outputs if value.get("kind") == "evidence_certificate"),
            None,
        ) or next(
            (value for value in outputs if value.get("kind") == "evidence_certificate_v2"),
            None,
        )
        if isinstance(action_certificate, Mapping):
            payload = action_certificate.get("payload")
            payload = payload if isinstance(payload, Mapping) else {}
            if payload.get("protocol_revision") == 2:
                artifacts = {
                    str(value.get("kind") or ""): value.get("payload")
                    for value in outputs
                    if isinstance(value, Mapping) and isinstance(value.get("payload"), Mapping)
                }
                proof_ir = artifacts.get("program_proof_ir")
                obligation = artifacts.get("proof_obligation")
                action = artifacts.get("action")
                frozen_check = artifacts.get("proof_check_result")
                strict_certificate = artifacts.get("evidence_certificate") or payload
                if not all(
                    isinstance(value, Mapping)
                    for value in (proof_ir, obligation, action, strict_certificate, frozen_check)
                ):
                    raise DecisionTraceError(
                        "strict proof certificate has no complete frozen replay artifact set"
                    )
                recomputed = ProofChecker().check(
                    proof_ir=cast(Mapping[str, Any], proof_ir),
                    obligation=cast(Mapping[str, Any], obligation),
                    action=cast(Mapping[str, Any], action),
                    certificate=cast(Mapping[str, Any], strict_certificate),
                )
                matches = recomputed == frozen_check
                accepted = recomputed.get("status") == "accepted"
                results.append(
                    {
                        "claim_uid": "",
                        "fact_kind": str(payload.get("fact_kind") or ""),
                        "status": str(payload.get("status") or "unknown"),
                        "classification": (
                            "valid_certificate" if accepted and matches else "proof_replay_mismatch"
                        ),
                        "matches_frozen_status": matches,
                        "certificate_valid": accepted,
                        "certificate_reason": (
                            "ok" if accepted and matches else "checker_replay_mismatch"
                        ),
                    }
                )
                continue
            valid = verify_certificate_v2(payload)
            results.append(
                {
                    "claim_uid": "",
                    "fact_kind": str(payload.get("fact_kind") or ""),
                    "status": str(payload.get("status") or "unknown"),
                    "classification": ("legacy_preview" if valid else "certificate_invalid"),
                    "matches_frozen_status": False,
                    "certificate_valid": False,
                    "certificate_reason": (
                        "legacy_preview_not_replay_authoritative"
                        if valid
                        else "certificate_v2_invalid"
                    ),
                }
            )
            continue
        results.append(
            {
                "claim_uid": "",
                "fact_kind": "",
                "status": "unknown",
                "classification": "legacy_claim_preview_not_replayed",
                "matches_frozen_status": False,
                "certificate_valid": False,
                "certificate_reason": "p5_checker_artifacts_unavailable",
            }
        )
    return {
        "schema_version": "zscope.cluster-reverify.v1",
        "validation_cluster_uid": trace.get("validation_cluster_uid"),
        "claim_results": results,
        "all_claims_match": all(
            value["matches_frozen_status"] and value["certificate_valid"] for value in results
        ),
        "policy_replay": policy,
    }


def _render_text(value: Mapping[str, Any]) -> str:
    lines = [
        f"Cluster: {value.get('validation_cluster_uid', '')}",
        f"Terminal: {value.get('terminal_disposition', '')}",
        f"Authority: {value.get('terminal_authority', '')}",
        "Reasons: " + ", ".join(str(item) for item in value.get("terminal_reason_codes") or []),
        "Views: " + ", ".join(str(item) for item in value.get("view_memberships") or []),
    ]
    for event in value.get("timeline") or []:
        lines.append(
            f"{int(event.get('sequence') or 0):02d} "
            f"[{event.get('stage')}] {event.get('reason_code')} "
            f"({event.get('actor')})"
        )
    return "\n".join(lines)


def _render_mermaid(value: Mapping[str, Any]) -> str:
    lines = ["flowchart TD"]
    timeline = value.get("timeline") or []
    for index, event in enumerate(timeline):
        label = f"{event.get('stage')}: {event.get('reason_code')}".replace('"', "'")
        lines.append(f'    E{index}["{label}"]')
        if index:
            lines.append(f"    E{index - 1} --> E{index}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Explain one frozen Z-Scope issue decision")
    parser.add_argument("--report", type=Path, required=True)
    selectors = parser.add_mutually_exclusive_group(required=True)
    selectors.add_argument("--cluster", default="")
    selectors.add_argument("--candidate", default="")
    selectors.add_argument("--finding-root", dest="finding_root", default="")
    parser.add_argument(
        "--mode", choices=("explain", "policy-replay", "reverify"), default="explain"
    )
    parser.add_argument("--format", choices=("text", "json", "mermaid"), default="text")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = _load_json(args.report)
        trace, item, snapshot_root = _resolve_trace(
            report,
            args.report,
            cluster=args.cluster,
            candidate=args.candidate,
            root=args.finding_root,
        )
        if args.mode == "policy-replay":
            output: Mapping[str, Any] = _policy_replay(trace, snapshot_root)
        elif args.mode == "reverify":
            output = _reverify(trace, snapshot_root)
        else:
            output = _explanation(trace, item)
        if args.format == "json" or args.mode != "explain":
            print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
        elif args.format == "mermaid":
            print(_render_mermaid(output))
        else:
            print(_render_text(output))
        return 0
    except (DecisionTraceError, KeyError, TypeError, ValueError) as exc:
        print(f"zscope-explain: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
