#!/usr/bin/env python3
"""Qualify P4 contracts over a neutral, answer-isolated structural corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import (
    PREDICATE_REGISTRY,
    ProofKernelEngine,
    build_evidence_action,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
)
from zscope.core.validation.proof_kernel.canonical import content_sha256
from zscope.orchestration.hypothesis_hunter.models import (
    build_attack_surface_audit_unit,
    build_hypothesis_offer,
    build_localized_coverage_key,
    materialize_security_hypothesis,
    validate_hypothesis_offer,
    validate_security_hypothesis,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/p4_hypothesis_hunter"


def _load(name: str) -> dict[str, Any]:
    value = json.loads((FIXTURE / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain one object")
    return value


def _graph(case_uid: str, family: str, features: Mapping[str, Any]) -> FunctionIRGraph:
    complete = features.get("coverage_complete") is True
    if family == "concurrency":
        statements = (
            ["pthread_mutex_lock(&gate)", "consume(shared)"]
            if features.get("lock_before_access")
            else ["consume(shared)"]
        )
        calls = [
            *(
                [{"callee": "pthread_mutex_lock", "line": 3}]
                if features.get("lock_before_access")
                else []
            ),
            {"callee": "consume", "line": 4},
        ]
        successors = ["B0"]
    elif family == "resource":
        statements = [
            "p = malloc(8)",
            *(["free(p)"] if features.get("cleanup_on_exit") else []),
        ]
        calls = [
            {"callee": "malloc", "line": 3},
            *([{"callee": "free", "line": 4}] if features.get("cleanup_on_exit") else []),
        ]
        successors = ["B0"]
    elif family == "path_guard":
        statements = ["source_value = read_input()"]
        calls = [{"callee": "read_input", "line": 3}, {"callee": "consume", "line": 5}]
        successors = ["B2"] if features.get("source_sink_edge") else ["B0"]
    else:
        statements = ["use_layout(value)"]
        calls = [{"callee": "use_layout", "line": 3}]
        successors = ["B0"]
    blocks = [
        {
            "id": "B3",
            "label": "ENTRY",
            "successors": successors,
            "predecessors": [],
            "statements": statements,
        }
    ]
    if family == "path_guard":
        blocks.append(
            {
                "id": "B2",
                "label": "",
                "successors": ["B0"],
                "predecessors": (["B3"] if features.get("source_sink_edge") else []),
                "statements": ["consume(source_value)"],
            }
        )
    blocks.append(
        {
            "id": "B0",
            "label": "EXIT",
            "successors": [],
            "predecessors": [
                *(["B3"] if successors == ["B0"] else []),
                *(["B2"] if family == "path_guard" else []),
            ],
            "statements": [],
        }
    )
    evidence = {
        "clang_path": "clang-21.1.8",
        "code_snapshot_sha256": content_sha256({"case_uid": case_uid, "features": features}),
        "unresolved_dynamic_edges": not complete,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": case_uid,
                "function_section_unique": True,
                "entry_blocks": ["B3"],
                "exit_blocks": ["B0"],
                "blocks": blocks,
            }
        },
        "ast_dump": {"summary": {"target_function": {"call_exprs": calls}}},
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function=case_uid,
        file=f"src/{case_uid}.c",
    )
    if graph is None:
        raise ValueError(f"failed to freeze FunctionIRGraph for {case_uid}")
    return graph


def _artifacts(
    *,
    project_uid: str,
    case_uid: str,
    family: str,
    features: Mapping[str, Any],
) -> dict[str, Any]:
    graph = _graph(case_uid, family, features)
    type_layouts: list[dict[str, Any]] = []
    if family == "contract_type" and features.get("layout_present"):
        layout_body = {
            "type_uid": "TYPE_NEUTRAL_RECORD",
            "size_bytes": 8 if features.get("layout_matches") else 16,
            "alignment_bytes": 4,
            "fields": [],
            "backend_sha256": graph.backend_sha256,
        }
        type_layouts.append({**layout_body, "layout_sha256": content_sha256(layout_body)})
    proof_ir = program_proof_ir_from_graph(
        graph,
        project_uid=project_uid,
        revision_uid="REV_" + graph.code_snapshot_sha256[:32],
        type_layouts=type_layouts,
    )
    if family == "concurrency":
        predicate_id = "lock_must_hold_at_access"
        access = next(value for value in graph.events if value.callee == "consume")
        parameters = {"access_statement_uid": access.statement_uid, "lock_uid": "gate"}
        expected_value: Any = {"must_hold": False}
        target = access
    elif family == "resource":
        predicate_id = "cleanup_covers_all_exits"
        acquire = next(value for value in graph.events if value.kind == "resource_acquire")
        parameters = {"resource_uid": acquire.subject_symbols[0]}
        expected_value = {"cleanup_complete": False}
        target = acquire
    elif family == "path_guard":
        predicate_id = "source_sink_path_exists"
        target = next(value for value in graph.events if value.callee == "consume")
        parameters = {"source_node_uid": graph.entry_block_uid, "sink_node_uid": target.block_uid}
        expected_value = {"path_exists": True}
    else:
        predicate_id = "record_layout_matches"
        target = next(iter(graph.events))
        parameters = {"type_uid": "TYPE_NEUTRAL_RECORD"}
        expected_layout_body = {
            "type_uid": "TYPE_NEUTRAL_RECORD",
            "size_bytes": 8,
            "alignment_bytes": 4,
            "fields": [],
            "backend_sha256": graph.backend_sha256,
        }
        expected_value = {
            "layout": {
                **expected_layout_body,
                "layout_sha256": content_sha256(expected_layout_body),
            }
        }
    spec = PREDICATE_REGISTRY[predicate_id]
    subject_uid = "HSUBJ_" + content_sha256([project_uid, case_uid, family])[:32]
    region_uid = "HREGION_" + content_sha256([case_uid, target.statement_uid])[:32]
    clause = build_proof_clause(
        role="confirmation",
        provider_family=spec.provider_family,
        predicate_id=predicate_id,
        fact_kind=spec.fact_kind,
        quantifier=spec.quantifier,
        expected_value=expected_value,
        parameters=parameters,
    )
    obligation = build_proof_obligation(
        validation_cluster_uid="HCLUSTER_" + content_sha256(case_uid)[:32],
        defect_family=family,
        subject_uid=subject_uid,
        decision_region_uid=region_uid,
        confirmation_clauses=(clause,),
        counterproof_clauses=(),
        open_clauses=(),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    action = build_evidence_action(
        obligation=obligation,
        clause=clause,
        proof_ir=proof_ir,
        provider_id=spec.provider_id,
        verifier_id=spec.verifier_id,
    )
    localized = build_localized_coverage_key(
        project_uid=project_uid,
        revision_uid="REV_QUALIFICATION",
        function_uid=case_uid,
        defect_family=family,
        subject_uid=subject_uid,
        decision_region_uid=region_uid,
        structural_fingerprint_sha256=content_sha256({"family": family, "features": features}),
    )
    audit_unit = build_attack_surface_audit_unit(
        project_uid=project_uid,
        revision_uid="REV_QUALIFICATION",
        risk_score=75,
        trigger_kinds=("external_reachable_sensitive", "localized_candidate_desert"),
        localized_coverage_key=localized,
        root_entry_uids=("ENTRY_EXTERNAL",),
        member_function_uids=(case_uid,),
        event_refs=(f"evidence:{case_uid}",),
        security_spec_refs=(),
        unknown_refs=(),
        dependency_hashes=proof_ir["dependency_hashes"],
        backend_coverage={"cfg": "complete" if features.get("coverage_complete") else "partial"},
    )
    resource_ref = f"evidence:{case_uid}" if family == "resource" else None
    offer = build_hypothesis_offer(
        audit_unit_uid=audit_unit["audit_unit_uid"],
        defect_family=family,
        subject_uid=subject_uid,
        decision_region_uid=region_uid,
        location={
            "file": graph.file,
            "function_uid": case_uid,
            "start_line": max(1, int(target.source_line or 1)),
            "end_line": max(1, int(target.source_line or 1)),
            "statement_uid": target.statement_uid,
        },
        source_ref=None if resource_ref else f"evidence:{case_uid}:source",
        sink_ref=None if resource_ref else f"evidence:{case_uid}:sink",
        resource_ref=resource_ref,
        proof_ir=proof_ir,
        proof_obligation=obligation,
        evidence_actions=(action,),
        evidence_refs=(f"evidence:{case_uid}",),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    selection = {
        "offer_uid": offer["offer_uid"],
        "evidence_action_uids": [action["action_uid"]],
        "supporting_fact_refs": [],
        "opposing_fact_refs": [],
        "unknown_fact_refs": [],
        "evidence_refs": [f"evidence:{case_uid}"],
    }
    hypothesis = materialize_security_hypothesis(offer=offer, selection=selection)
    valid_offer, offer_reason = validate_hypothesis_offer(offer)
    valid_hypothesis, hypothesis_reason = validate_security_hypothesis(
        hypothesis,
        offer=offer,
    )
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=proof_ir,
        obligation=obligation,
        selected_action_uids=(action["action_uid"],),
    )
    return {
        "program_proof_ir": proof_ir,
        "proof_obligation": obligation,
        "evidence_action": action,
        "security_hypothesis": hypothesis,
        "proof_shadow_decision": evaluation.shadow_decision,
        "proof_reason_code": evaluation.reason_code,
        "checker_results": list(evaluation.check_results),
        "registered_in_shadow_ledger": evaluation.shadow_decision == "confirmed",
        "contracts_resolvable": valid_offer and valid_hypothesis,
        "contract_validation": {
            "offer": offer_reason,
            "hypothesis": hypothesis_reason,
        },
    }


def qualify() -> dict[str, Any]:
    source = _load("source-corpus.json")
    expected = _load("expected-results.json")
    classifications = expected["classification_by_variant_index"]
    expected_registration = expected["expected_registration"]
    cases: list[dict[str, Any]] = []
    frozen_replays: dict[str, dict[str, Any]] = {}
    safe_false_acceptance = 0
    near_false_acceptance = 0
    positive_registered = 0
    project_with_replayable_proof: set[str] = set()
    for project in source["projects"]:
        project_uid = str(project["project_uid"])
        for family in source["families"]:
            features_by_variant = source["source_features"][family]
            for index, variant in enumerate(source["variants"]):
                case_uid = f"{project_uid}_{family}_{variant}".lower()
                features = dict(features_by_variant[index])
                artifacts = _artifacts(
                    project_uid=project_uid,
                    case_uid=case_uid,
                    family=family,
                    features=features,
                )
                classification = str(classifications[str(index)])
                registered = bool(artifacts["registered_in_shadow_ledger"])
                expected_value = bool(expected_registration[classification])
                if registered != expected_value:
                    raise ValueError(
                        f"qualification mismatch for {case_uid}: "
                        f"registered={registered} expected={expected_value}"
                    )
                if classification == "positive" and registered:
                    positive_registered += 1
                    project_with_replayable_proof.add(project_uid)
                elif classification == "safe" and registered:
                    safe_false_acceptance += 1
                elif classification == "near_miss" and registered:
                    near_false_acceptance += 1
                source_payload = {
                    "project_uid": project_uid,
                    "api_style": project["api_style"],
                    "family": family,
                    "variant": variant,
                    "features": features,
                    "source_template": source["source_templates"][family],
                }
                replay_key = f"{family}:{classification}"
                replay_payload = {
                    "program_proof_ir": artifacts["program_proof_ir"],
                    "proof_obligation": artifacts["proof_obligation"],
                    "evidence_action": artifacts["evidence_action"],
                    "security_hypothesis": artifacts["security_hypothesis"],
                    "checker_results": artifacts["checker_results"],
                    "expected_shadow_decision": artifacts["proof_shadow_decision"],
                }
                frozen_replays.setdefault(
                    replay_key,
                    {
                        "replay_uid": replay_key,
                        "content_sha256": content_sha256(replay_payload),
                        **replay_payload,
                    },
                )
                cases.append(
                    {
                        "case_uid": case_uid,
                        "source_sha256": content_sha256(source_payload),
                        "classification": classification,
                        "provider_family": family,
                        "variant": variant,
                        "frozen_replay_uid": replay_key,
                        "program_proof_ir_sha256": artifacts["program_proof_ir"]["content_sha256"],
                        "proof_obligation_sha256": artifacts["proof_obligation"]["content_sha256"],
                        "evidence_action_sha256": artifacts["evidence_action"]["content_sha256"],
                        "predicate_id": artifacts["evidence_action"]["predicate_id"],
                        "proof_shadow_decision": artifacts["proof_shadow_decision"],
                        "proof_reason_code": artifacts["proof_reason_code"],
                        "registered_in_shadow_ledger": registered,
                        "contracts_resolvable": artifacts["contracts_resolvable"],
                    }
                )
    metamorphic_groups: dict[str, set[tuple[str, str]]] = {}
    for value in cases:
        if value["variant"] not in {"base", "rename", "wrapper_extract"}:
            continue
        predicate = value["predicate_id"]
        key = f"{value['provider_family']}:{value['case_uid'].split('_')[1]}"
        metamorphic_groups.setdefault(key, set()).add((predicate, value["proof_shadow_decision"]))
    metamorphic_consistent = all(len(values) == 1 for values in metamorphic_groups.values())
    body = {
        "schema_version": "zscope.p4-hypothesis-qualification.v1",
        "source_corpus_sha256": content_sha256(source),
        "expected_results_sha256": content_sha256(expected),
        "case_count": len(cases),
        "project_count": len(source["projects"]),
        "provider_family_count": len(source["families"]),
        "positive_registered_count": positive_registered,
        "safe_case_count": sum(value["classification"] == "safe" for value in cases),
        "safe_false_acceptance_count": safe_false_acceptance,
        "near_miss_false_acceptance_count": near_false_acceptance,
        "contract_resolution_percent": round(
            100.0 * sum(value["contracts_resolvable"] for value in cases) / len(cases),
            2,
        ),
        "projects_with_replayable_proof": sorted(project_with_replayable_proof),
        "metamorphic_consistent": metamorphic_consistent,
        "answer_isolation": {
            "product_runtime_reads_expected_results": False,
            "source_and_expected_are_separate": True,
        },
        "frozen_replays": [frozen_replays[key] for key in sorted(frozen_replays)],
        "cases": cases,
    }
    minimums = expected["minimums"]
    if (
        body["case_count"] < int(minimums["audit_units"])
        or body["safe_case_count"] < int(minimums["safe_units"])
        or len(project_with_replayable_proof) < int(minimums["project_count"])
        or body["provider_family_count"] < int(minimums["provider_family_count"])
        or safe_false_acceptance
        or near_false_acceptance
        or body["contract_resolution_percent"] != 100.0
        or not metamorphic_consistent
    ):
        raise ValueError("P4 qualification acceptance threshold failed")
    return {**body, "content_sha256": content_sha256(body)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the replay result with the packaged frozen qualification artifact",
    )
    args = parser.parse_args(argv)
    result = qualify()
    if args.check:
        frozen_path = (
            ROOT
            / "zscope/orchestration/hypothesis_hunter/qualification/qualification-artifact.json"
        )
        frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
        if frozen != result:
            print("P4 qualification artifact differs from deterministic replay")
            return 1
        print(
            "P4 hypothesis qualification passed: "
            f"cases={result['case_count']} "
            f"safe={result['safe_case_count']} "
            f"near_miss_false={result['near_miss_false_acceptance_count']} "
            f"safe_false={result['safe_false_acceptance_count']}"
        )
        return 0
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
