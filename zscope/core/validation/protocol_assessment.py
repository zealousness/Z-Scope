"""Current-source replay and acceptance questions for bounded object paths.

Source effects are descriptive. Business obligations require scoped user
declarations, combined with current technical evidence by the dedicated checker.
This refines the existing validation pipeline; it is not another verdict store.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from ..candidates.cpp_domains.lifecycle_paths import LifecyclePaths, PATH_VERSION
from ..candidates.cpp_domains.async_paths import (
    AsyncLifecyclePaths,
    ASYNC_VERSION,
    native_inputs_current,
)
from ...semantics.contracts import ContractRegistry, code_tokens, digest
from ...semantics.business_assumptions import assumption_key
from .evidence import normalize_missing_fact_kinds

RULE = "zscope.c_cpp.cpp_clang_cfg.object_protocol_path"
SCHEMA = "zscope.protocol-assessment.v12"
BUSINESS = "event:business_release_requirement"
ENDPOINT = "event:responsibility_endpoint"
NONCONCURRENT = "event:nonconcurrent_reference_count"
SERIAL_HANDLES = "event:serial_handle_namespace"
REQUIREMENTS = {
    "callback_after_release": "此入口及其直接 pthread 回调和 cleanup 属于实际使用的业务路径，允许工作者按记录的解锁、通知、调用方条件等待、无通知唤醒/超时、延迟取消或 join 顺序暂停/恢复并访问该获取代次；记录的时钟和截止时间前提可成立，没有本模型范围外的生命周期协调使记录的调度不可达。",
    "repeat_return": "该接口约定：同一获取代次完成归还后，不允许再次归还（并非允许重复调用的幂等接口）。",
    "wrong_pool_return": "该接口约定：资源必须归还给实际获取它的池实例，不允许跨池归还。",
    "stale_generation_return": "该接口约定：归还者必须持有当前获取代次，旧代次指针不得结束重新获取对象的生命周期。",
    "failed_retention_unreleased": "留存失败时调用方仍承担已获取资源的归还责任，且不存在获准的永久持有或责任豁免。",
    "released_reference_retained": "接收方保留的引用必须指向尚未归还的获取代次。",
    "release_with_live_references": "该对象的正引用计数代表仍有有效持有者，业务协议禁止此时提前归还。",
    "zero_count_unreleased": "该引用计数协议要求最后一次 drop 在返回前实际归还对象，不允许缓存、延迟销毁或责任转交。",
    "refcount_after_return": "引用计数接口要求持有尚未归还的对象，不允许对已归还代次执行此操作。",
    "stale_generation_refcount": "引用计数操作必须对应所持有的获取代次，旧指针不能修改同地址新代次的计数。",
    "handle_left_live": "此句柄仍由调用方承担关闭责任，不存在获准的永久持有、责任转交或豁免。",
    "closed_handle_operation": "此接口要求持有仍有效的描述符代次，不允许在已消费该代次后再次 close/dup。",
    "stale_handle_generation": "此接口要求操作所持有的描述符代次，旧句柄数值不得操作同值重新获取的新代次。",
    "wrong_handle_namespace": "此句柄必须用于其获取时的命名空间，不允许仅凭相同整数跨命名空间操作。",
}


class _CheckedAssessment(dict[str, Any]):
    """Process-local receipt; JSON/model fields cannot impersonate a replay."""

    def __init__(self, payload: dict[str, Any]):
        super().__init__(payload)
        self.receipt = digest(payload)
        self.feedback_guard: Callable[[], bool] | None = None
        self.dependency_guard: Callable[[], bool] | None = None


def is_protocol_candidate(issue: dict[str, Any]) -> bool:
    return (issue.get("rule_id") or issue.get("rule")) == RULE


def _path(issue: dict[str, Any]) -> dict[str, Any]:
    pack = issue.get("evidence_pack")
    value = pack.get("object_protocol_path") if isinstance(pack, dict) else None
    return value if isinstance(value, dict) else {}


def _identity(issue: dict[str, Any]) -> str:
    return digest(
        [issue.get("candidate_id") or issue.get("id"), issue.get("resource_identity"), _path(issue)]
    )


def _missing(issue: dict[str, Any]) -> set[str]:
    fact_slice = issue.get("decision_fact_slice")
    return set(normalize_missing_fact_kinds(issue.get("missing_fact_kinds"))) | set(
        normalize_missing_fact_kinds(fact_slice.get("missing_fact_kinds"))
        if isinstance(fact_slice, dict)
        else []
    )


def checked_assessment(issue: Mapping[str, Any]) -> _CheckedAssessment | None:
    assessment = issue.get("protocol_assessment")
    if (
        not isinstance(assessment, _CheckedAssessment)
        or assessment.receipt != digest(assessment)
        or assessment.get("candidate_binding") != _identity(dict(issue))
        or issue.get("evidence_conflict")
        or issue.get("blocking_negative_evidence") is True
    ):
        return None
    if assessment.feedback_guard is not None:
        try:
            if not assessment.feedback_guard():
                return None
        except Exception:
            return None
    if assessment.dependency_guard is not None:
        try:
            if not assessment.dependency_guard():
                return None
        except Exception:
            return None
    return assessment


def feedback_changed(issue: Mapping[str, Any]) -> bool:
    assessment = issue.get("protocol_assessment")
    if isinstance(assessment, _CheckedAssessment) and assessment.feedback_guard is not None:
        try:
            return not assessment.feedback_guard()
        except Exception:
            return True
    return False


def protocol_review_state(issue: dict[str, Any]) -> str:
    """Only a current process receipt can distinguish conditional from pending."""
    if not is_protocol_candidate(issue):
        return ""
    assessment = checked_assessment(issue)
    if assessment is None:
        return "protocol_pending"
    assumptions = {a["fact_kind"] for a in assessment.get("assumptions", [])}
    if assessment.get("state") == "conditional" and not (_missing(issue) - assumptions):
        return "business_conditional"
    return "protocol_pending"


def assess_protocol_candidate(
    issue: dict[str, Any],
    code_index: Any,
    registry: ContractRegistry | None,
    answer_store: Any = None,
) -> dict[str, Any] | None:
    """Re-execute from current native facts and the runtime contract registry.

    No contract or checker claims supplied inside a candidate/model response are
    loaded into the registry. Source receipts, complete paths and the selected
    observation must all match. Failure is pending, never a safe/defect result.
    """
    if not is_protocol_candidate(issue):
        return None
    recorded = _path(issue)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "state": "pending",
        "candidate_binding": _identity(issue),
        "scope": "concrete_same_tu_entry_path",
        "proof_authority": False,
        "technical_witness_current": False,
        "assumptions": [],
        "technical_gaps": [],
    }

    def finish(reason: str = "") -> dict[str, Any]:
        if reason:
            payload["technical_gaps"].append(reason)
        return _CheckedAssessment(payload)

    provider = getattr(code_index, "get_function_program_facts", None)
    engines = {PATH_VERSION: LifecyclePaths, ASYNC_VERSION: AsyncLifecyclePaths}
    engine = engines.get(str(recorded.get("schema") or ""))
    if engine is None or not recorded.get("complete"):
        return finish("missing_or_obsolete_path_receipt")
    if not isinstance(registry, ContractRegistry) or not callable(provider):
        return finish("current_protocol_provider_unavailable")
    build = str(recorded.get("build_context_id") or "")
    file_path = str(issue.get("file_path") or "")
    entry = str(recorded.get("entry_usr") or "")
    if not (build and file_path and entry and recorded.get("contract_inputs")):
        return finish("missing_protocol_source_binding")
    try:
        registry_version = registry.version
        facts = provider(entry, file_path, build_context_id=build)
        current = engine(facts, registry, provider).run()
        if registry.version != registry_version:
            return finish("protocol_registry_changed_during_replay")
        if not current["complete"]:
            payload["technical_gaps"].extend(current["gaps"])
            return finish("current_path_incomplete")
        if digest(current) != digest(
            {k: v for k, v in recorded.items() if k != "selected_observation"}
        ):
            return finish("path_or_contract_changed")
        selected = recorded.get("selected_observation")
        if (
            not isinstance(selected, dict)
            or selected not in current["observations"]
            or selected.get("kind") not in REQUIREMENTS
        ):
            return finish("observation_not_reproduced")
        resource = next(r for r in current["resources"] if r["id"] == selected["resource_id"])
        if issue.get("resource_identity") != resource["id"]:
            return finish("object_identity_mismatch")
        # Current build receipts bind native bodies. Independently check the
        # source tokens used to compile the registered descriptive effects.
        refs = []
        for usr, contract in current["contract_inputs"].items():
            if contract.get("standard_root"):
                # Already resolved again against the live registry and current
                # native system declaration by the async interpreter.
                refs.append({"standard_api": usr, **contract})
                continue
            symbol = contract["symbol"]
            implementation = code_index.get_function_impl(
                symbol["name"], file_path=symbol["file_path"], include_context=False
            )
            source_hash = digest(code_tokens(implementation.get("code") or ""))
            if source_hash != contract["verification"]["source_hash"]:
                return finish("protocol_source_changed")
            refs.append({"function_usr": contract.get("function_usr", usr), **contract})
    except (AttributeError, KeyError, TypeError, ValueError, IndexError, StopIteration, OSError):
        return finish("protocol_replay_unavailable")

    payload.update(
        {
            "technical_witness_current": True,
            "scope": current["scope"],
            "link_target": current.get("link_target", {}),
            "build_context_id": build,
            "entry_usr": entry,
            "object_ref": resource["object_ref"],
            "observation": selected,
            "source_refs": refs,
            "dependency_hash": digest([current["inputs"], current["contract_inputs"]]),
        }
    )
    required = {BUSINESS}
    if any(e["kind"].startswith("refcount_") for e in current["trace"]):
        required.add(NONCONCURRENT)
    if any(e["kind"].startswith("handle_") for e in current["trace"]):
        required.add(SERIAL_HANDLES)
    if selected["kind"] in {"failed_retention_unreleased", "handle_left_live"}:
        required.add(ENDPOINT)
    for kind in sorted(required):
        statement = (
            "此对象路径处于非并发执行上下文，没有未建模的并发或重入计数修改/释放；顺序计数本身不证明线程安全。"
            if kind == NONCONCURRENT
            else (
                "本入口退出是该对象的业务责任终点；此后不存在仍获准的持有者或后续清理阶段。"
                if kind == ENDPOINT
                else REQUIREMENTS[selected["kind"]]
            )
        )
        if kind == SERIAL_HANDLES:
            statement = "此句柄命名空间在本路径期间按顺序独占操作，没有未建模的并发、重入或外部关闭/重开；整数相等本身不证明身份。"
        payload["assumptions"].append(
            {
                "id": "ASSUMPTION_" + digest([payload["candidate_binding"], kind])[:24],
                "fact_kind": kind,
                "statement": statement,
                "status": "unconfirmed",
                "source_kind": "analysis_requirement",
                "scope": {
                    "build_context_id": build,
                    "entry_usr": entry,
                    "object_ref": resource["object_ref"],
                },
                "basis": {
                    "dependency_hash": payload["dependency_hash"],
                    "observation_kind": selected["kind"],
                },
                "question": "请在验收时核实该前提是否成立，并提供适用范围及业务约定来源。",
            }
        )
    technical = _missing(issue) - required
    if selected["kind"] == "released_reference_retained":
        technical.add("event:later_slot_access")
    keys = [assumption_key(a) for a in payload["assumptions"]]
    reader = getattr(answer_store, "get_protocol_answers", None)
    rows = reader(keys) if callable(reader) else {}
    revisions = {key: int(rows.get(key, {}).get("revision", 0)) for key in keys}
    for assumption, key in zip(payload["assumptions"], keys):
        assumption["subject_key"] = key
        row = rows.get(key)
        if row:
            if row.get("origin") != "user_acceptance" or row.get("answer") not in {
                "yes",
                "no",
                "unknown",
            }:
                technical.add("business_feedback_invalid")
                continue
            assumption["answer"] = {
                field: row[field]
                for field in ("answer", "revision", "source_note", "origin", "created_at")
            }
            assumption["status"] = {"yes": "accepted", "no": "denied", "unknown": "unconfirmed"}[
                row["answer"]
            ]
            if row["answer"] == "no":
                # A denied premise calls for revised analysis, not a global
                # safety verdict or an automatically persisted suppression.
                technical.add("business_premise_denied")
    payload["feedback_revisions"] = revisions
    payload["technical_gaps"] = sorted(technical)
    payload["state"] = (
        "pending"
        if technical
        else (
            "established"
            if all(a["status"] == "accepted" for a in payload["assumptions"])
            else "conditional"
        )
    )
    result = _CheckedAssessment(payload)
    if engine is AsyncLifecyclePaths:
        from copy import deepcopy

        context = deepcopy(facts.get("build_context") or {})
        result.dependency_guard = lambda: (
            registry.version == registry_version and native_inputs_current(context)
        )
    revision_reader = getattr(answer_store, "protocol_answer_revisions", None)
    if callable(revision_reader):
        result.feedback_guard = lambda: revision_reader(keys) == revisions
    return result


def protocol_confirmation(issue: Mapping[str, Any]) -> Any:
    """Complete current path plus explicit, scoped user declarations only."""
    assessment = checked_assessment(issue)
    if (
        assessment is None
        or assessment.get("state") != "established"
        or assessment.feedback_guard is None
    ):
        return None
    assumptions = assessment["assumptions"]
    if (
        not assumptions
        or assessment.get("technical_gaps")
        or any(a.get("status") != "accepted" for a in assumptions)
        or _missing(dict(issue)) - {a["fact_kind"] for a in assumptions}
    ):
        return None
    from .proofs import DecisionProof

    return DecisionProof(
        outcome="confirm",
        proof_kind="checked_object_protocol_with_business_declarations",
        producer_engine=SCHEMA,
        fact_ids=tuple(
            [
                assessment["dependency_hash"],
                *[a["subject_key"] + ":" + str(a["answer"]["revision"]) for a in assumptions],
            ]
        ),
        code_hash=assessment["dependency_hash"],
        assumptions=tuple(a["statement"] for a in assumptions),
        contradiction_or_obligation=str(assessment["observation"]["kind"]),
        scope="concrete_c_path_under_scoped_user_declarations",
        completeness="complete",
        subject_identity=str(issue.get("resource_identity") or ""),
    )


def reset_business_facts(issue: dict[str, Any]) -> None:
    """Retract old answer-derived facts before reading the current revision."""
    fact_slice = dict(issue.get("decision_fact_slice") or {})
    facts = list(fact_slice.get("facts") or [])
    removed = {
        f.get("fact_uid") for f in facts if f.get("provider") == "protocol_business_feedback"
    }
    fact_slice["facts"] = [f for f in facts if f.get("fact_uid") not in removed]
    fact_slice["fact_uids"] = [u for u in fact_slice.get("fact_uids", []) if u not in removed]
    required = {BUSINESS}
    if any(str(e.get("kind", "")).startswith("refcount_") for e in _path(issue).get("trace", [])):
        required.add(NONCONCURRENT)
    if any(str(e.get("kind", "")).startswith("handle_") for e in _path(issue).get("trace", [])):
        required.add(SERIAL_HANDLES)
    if (_path(issue).get("selected_observation") or {}).get("kind") in {
        "failed_retention_unreleased",
        "handle_left_live",
    }:
        required.add(ENDPOINT)
    missing = sorted(_missing(issue) | required)
    fact_slice.update(missing_fact_kinds=missing, coverage="partial")
    issue.update(
        decision_fact_slice=fact_slice,
        missing_fact_kinds=missing,
        decision_fact_coverage="partial",
        candidate_promotion_eligible=False,
        candidate_promotion_reason="business_requirements_unconfirmed",
    )
    if isinstance(issue.get("security_obligation"), dict):
        issue["security_obligation"]["decision_fact_slice"] = dict(fact_slice)


def publish_business_facts(issue: dict[str, Any]) -> None:
    assessment = checked_assessment(issue)
    if assessment is None:
        return
    from .evidence_completion import EvidenceCompletionQueue

    facts = [
        {
            "fact_uid": "FACT_" + digest([a["subject_key"], a["answer"]]),
            "fact_kind": a["fact_kind"],
            "provider": "protocol_business_feedback",
            "dependency_code_hash": assessment["dependency_hash"],
            "scope": a["scope"],
            "declaration": a["answer"],
            "proof_authority": False,
        }
        for a in assessment["assumptions"]
        if a["status"] == "accepted"
    ]
    EvidenceCompletionQueue._apply_fact_delta_to_decision_context(issue, facts)
    if isinstance(issue.get("security_obligation"), dict):
        issue["security_obligation"]["decision_fact_slice"] = dict(issue["decision_fact_slice"])
