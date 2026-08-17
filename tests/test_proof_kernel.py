import json
from pathlib import Path

import pytest

from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import (
    PREDICATE_REGISTRY,
    NON_EXECUTABLE_PREDICATES,
    POLARITY_ROLE_TERMINAL_MATRIX,
    ProofArtifactStore,
    ProofChecker,
    ProofKernelEngine,
    ProofProvider,
    build_evidence_action,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
)
from zscope.core.validation.proof_kernel.canonical import seal_mapping
from zscope.core.validation.proof_kernel.models import validate_certificate_envelope


def _graph(*, complete: bool = True) -> FunctionIRGraph:
    evidence = {
        "clang_path": "clang-21.1.8",
        "code_snapshot_sha256": "a" * 64,
        "unresolved_dynamic_edges": not complete,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "neutral_worker",
                "function_section_unique": True,
                "entry_blocks": ["B3"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B3",
                        "label": "ENTRY",
                        "successors": ["B2"],
                        "predecessors": [],
                        "statements": ["p = malloc(8)", "pthread_mutex_lock(&gate)"],
                    },
                    {
                        "id": "B2",
                        "label": "",
                        "successors": ["B1"],
                        "predecessors": ["B3"],
                        "statements": ["consume(p)", "free(p)"],
                    },
                    {
                        "id": "B1",
                        "label": "",
                        "successors": ["B0"],
                        "predecessors": ["B2"],
                        "statements": ["pthread_mutex_unlock(&gate)"],
                    },
                    {
                        "id": "B0",
                        "label": "EXIT",
                        "successors": [],
                        "predecessors": ["B1"],
                        "statements": [],
                    },
                ],
            }
        },
        "ast_dump": {
            "summary": {
                "target_function": {
                    "call_exprs": [
                        {"callee": "malloc", "line": 3},
                        {"callee": "pthread_mutex_lock", "line": 4},
                        {"callee": "consume", "line": 5},
                        {"callee": "free", "line": 6},
                        {"callee": "pthread_mutex_unlock", "line": 7},
                    ]
                }
            }
        },
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence, function="neutral_worker", file="src/neutral_worker.c"
    )
    assert graph is not None
    return graph


def _artifacts(predicate_id, parameters, expected, *, complete=True, roles=("confirmation",)):
    graph = _graph(complete=complete)
    proof_ir = program_proof_ir_from_graph(
        graph, project_uid="PROJECT_NEUTRAL", revision_uid="REV_NEUTRAL"
    )
    spec = PREDICATE_REGISTRY[predicate_id]
    clauses = [
        build_proof_clause(
            role=role,
            provider_family=spec.provider_family,
            predicate_id=predicate_id,
            fact_kind=spec.fact_kind,
            quantifier=spec.quantifier,
            expected_value=expected,
            parameters=parameters,
        )
        for role in roles
    ]
    obligation = build_proof_obligation(
        validation_cluster_uid="VAL_NEUTRAL",
        defect_family="neutral_family",
        subject_uid="SUBJECT_NEUTRAL",
        decision_region_uid="REGION_NEUTRAL",
        confirmation_clauses=[value for value in clauses if value["role"] == "confirmation"],
        counterproof_clauses=[value for value in clauses if value["role"] == "counterproof"],
        open_clauses=[value for value in clauses if value["role"] == "open"],
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    actions = [
        build_evidence_action(
            obligation=obligation,
            clause=clause,
            proof_ir=proof_ir,
            provider_id=spec.provider_id,
            verifier_id=spec.verifier_id,
        )
        for clause in clauses
    ]
    return proof_ir, obligation, actions


def test_provider_proposes_and_independent_checker_accepts_recomputed_fact() -> None:
    graph = _graph()
    access = next(event.statement_uid for event in graph.events if event.callee == "consume")
    proof_ir, obligation, actions = _artifacts(
        "lock_must_hold_at_access",
        {"access_statement_uid": access, "lock_uid": "gate"},
        {"must_hold": True},
    )
    certificate = ProofProvider().produce(
        proof_ir=proof_ir, obligation=obligation, action=actions[0]
    )
    result = ProofChecker().check(
        proof_ir=proof_ir,
        obligation=obligation,
        action=actions[0],
        certificate=certificate,
    )

    assert result["status"] == "accepted"
    assert result["terminal_contribution"] == "confirmation"
    assert result["accepted_fact"]["origin"] == "proof_checker_v2"


def test_derived_required_fact_cannot_become_terminal_proof() -> None:
    proof_ir, obligation, actions = _artifacts(
        "source_sink_path_exists",
        {"source_node_uid": "B3", "sink_node_uid": "B1"},
        {"$derived": True},
    )
    certificate = ProofProvider().produce(
        proof_ir=proof_ir, obligation=obligation, action=actions[0]
    )

    result = ProofChecker().check(
        proof_ir=proof_ir,
        obligation=obligation,
        action=actions[0],
        certificate=certificate,
    )

    assert result["status"] == "accepted"
    assert result["accepted_fact"]["value"] == {"path_exists": True}
    assert result["terminal_contribution"] == "none"


def test_obligation_dependency_hash_cannot_be_rebound() -> None:
    proof_ir, obligation, _ = _artifacts(
        "source_sink_path_exists",
        {"source_node_uid": "B3", "sink_node_uid": "B1"},
        {"path_exists": True},
    )
    forged_body = dict(obligation)
    forged_body.pop("obligation_uid")
    forged_body.pop("content_sha256")
    forged_body["dependency_hashes"] = ["f" * 64]
    forged_obligation = seal_mapping(forged_body, uid_field="obligation_uid", prefix="POBL_")
    clause = forged_obligation["confirmation_clauses"][0]
    spec = PREDICATE_REGISTRY[clause["predicate_id"]]
    action = build_evidence_action(
        obligation=forged_obligation,
        clause=clause,
        proof_ir=proof_ir,
        provider_id=spec.provider_id,
        verifier_id=spec.verifier_id,
    )
    certificate = ProofProvider().produce(
        proof_ir=proof_ir,
        obligation=forged_obligation,
        action=action,
    )

    result = ProofChecker().check(
        proof_ir=proof_ir,
        obligation=forged_obligation,
        action=action,
        certificate=certificate,
    )

    assert result["status"] == "rejected"
    assert result["reason_codes"] == ["obligation_dependency_hash_mismatch"]


def test_registry_freezes_non_executable_facts_and_role_polarity_matrix() -> None:
    assert set(NON_EXECUTABLE_PREDICATES) >= {
        "happens_before",
        "ownership_transfer",
        "caller_contract",
        "object_identity",
        "value_range",
    }
    assert POLARITY_ROLE_TERMINAL_MATRIX[("confirmation", "supports")] == "confirmation"
    assert POLARITY_ROLE_TERMINAL_MATRIX[("counterproof", "refutes")] == "counterproof"


def test_checker_rejects_rehashed_forged_certificate() -> None:
    proof_ir, obligation, actions = _artifacts(
        "source_sink_path_exists",
        {"source_node_uid": "B3", "sink_node_uid": "B1"},
        {"path_exists": True},
    )
    certificate = ProofProvider().produce(
        proof_ir=proof_ir, obligation=obligation, action=actions[0]
    )
    forged_body = dict(certificate)
    forged_body.pop("certificate_uid")
    forged_body.pop("content_sha256")
    forged_body["witness"] = {
        "cfg_nodes": ["B3", "B1"],
        "cfg_edges": [["B3", "B1"]],
        "path_node_uids": ["B3", "B1"],
        "exit_node_uids": [],
        "values": {"path_exists": True},
    }
    forged = seal_mapping(forged_body, uid_field="certificate_uid", prefix="CERT_")

    result = ProofChecker().check(
        proof_ir=proof_ir, obligation=obligation, action=actions[0], certificate=forged
    )

    assert result["status"] == "rejected"
    assert "certificate_witness_recompute_mismatch" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("code_sha256", "1" * 64),
        ("backend_sha256", "2" * 64),
        ("ir_sha256", "3" * 64),
        ("subject_uid", "SUBJECT_FORGED"),
        ("decision_region_uid", "REGION_FORGED"),
        ("quantifier", "for_all_paths"),
        ("assumption_ids", ["unapproved.assumption"]),
        ("action_uid", "EVACTION_" + "4" * 32),
        ("predicate_polarity", "refutes"),
        ("provider_version", "v999"),
    ],
)
def test_checker_rejects_rehashed_identity_scope_and_assumption_tampering(
    field, replacement
) -> None:
    proof_ir, obligation, actions = _artifacts(
        "source_sink_path_exists",
        {"source_node_uid": "B3", "sink_node_uid": "B1"},
        {"path_exists": True},
    )
    certificate = ProofProvider().produce(
        proof_ir=proof_ir, obligation=obligation, action=actions[0]
    )
    forged_body = dict(certificate)
    forged_body.pop("certificate_uid")
    forged_body.pop("content_sha256")
    forged_body[field] = replacement
    forged = seal_mapping(forged_body, uid_field="certificate_uid", prefix="CERT_")

    checked = ProofChecker().check(
        proof_ir=proof_ir, obligation=obligation, action=actions[0], certificate=forged
    )

    assert checked["status"] != "accepted"
    assert checked["accepted_fact"] is None


def test_action_parameters_cannot_escape_frozen_clause() -> None:
    proof_ir, obligation, actions = _artifacts(
        "source_sink_path_exists",
        {"source_node_uid": "B3", "sink_node_uid": "B1"},
        {"path_exists": True},
    )
    action_body = dict(actions[0])
    action_body.pop("action_uid")
    action_body.pop("content_sha256")
    action_body["fixed_parameters"] = {"source_node_uid": "B2", "sink_node_uid": "B1"}
    forged_action = seal_mapping(action_body, uid_field="action_uid", prefix="EVACTION_")
    certificate = ProofProvider().produce(
        proof_ir=proof_ir, obligation=obligation, action=forged_action
    )

    checked = ProofChecker().check(
        proof_ir=proof_ir,
        obligation=obligation,
        action=forged_action,
        certificate=certificate,
    )

    assert checked["status"] == "rejected"
    assert checked["reason_codes"] == ["fixed_parameter_clause_mismatch"]


def test_incomplete_universal_predicate_is_unknown_with_empty_witness() -> None:
    graph = _graph(complete=False)
    access = next(event.statement_uid for event in graph.events if event.callee == "consume")
    proof_ir, obligation, actions = _artifacts(
        "lock_must_hold_at_access",
        {"access_statement_uid": access, "lock_uid": "gate"},
        {"must_hold": True},
        complete=False,
    )
    certificate = ProofProvider().produce(
        proof_ir=proof_ir, obligation=obligation, action=actions[0]
    )
    result = ProofChecker().check(
        proof_ir=proof_ir,
        obligation=obligation,
        action=actions[0],
        certificate=certificate,
    )

    assert certificate["status"] == "unknown"
    assert all(not value for value in certificate["witness"].values())
    assert result["status"] == "unknown"
    assert result["accepted_fact"] is None


def test_entry_parameter_binding_requires_frozen_signature_domain() -> None:
    proof_ir, obligation, actions = _artifacts(
        "external_entry_parameter_binding",
        {"parameter_uid": "arg0", "parameter_slot": "0"},
        {"$derived": True},
    )

    certificate = ProofProvider().produce(
        proof_ir=proof_ir, obligation=obligation, action=actions[0]
    )
    result = ProofChecker().check(
        proof_ir=proof_ir,
        obligation=obligation,
        action=actions[0],
        certificate=certificate,
    )

    assert certificate["status"] == "unknown"
    assert certificate["coverage"]["unresolved_reasons"] == ["entry_signature_not_frozen"]
    assert all(not value for value in certificate["witness"].values())
    assert result["status"] == "unknown"
    assert result["accepted_fact"] is None


def test_legacy_preview_certificate_never_closes_clause() -> None:
    valid, reason = validate_certificate_envelope(
        {"schema_version": "zscope.evidence-certificate.v2", "status": "verified_true"}
    )
    assert valid is False
    assert reason == "legacy_preview"


def test_engine_resolves_conflict_programmatically_and_stays_shadow() -> None:
    proof_ir, obligation, _ = _artifacts(
        "source_sink_path_exists",
        {"source_node_uid": "B3", "sink_node_uid": "B1"},
        {"path_exists": True},
        roles=("confirmation", "counterproof"),
    )

    result = ProofKernelEngine().evaluate(proof_ir=proof_ir, obligation=obligation)

    assert result.proof_kernel_mode == "shadow"
    assert result.shadow_decision == "needs_review"
    assert result.reason_code == "programmatic_proof_conflict"


def test_cas_rejects_tampered_object_and_unsafe_reference(tmp_path: Path) -> None:
    store = ProofArtifactStore(tmp_path)
    reference = store.put("sample", {"value": 1})
    assert store.verify_ref(reference)
    digest = reference.split(":", 1)[1]
    path = tmp_path / "proof_objects" / f"{digest}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["payload"]["value"] = 2
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert store.verify_ref(reference) is False
    with pytest.raises(ValueError, match="invalid_proof_artifact_reference"):
        store.load("../proof_manifest.json")
    with pytest.raises(ValueError, match="proof_object_dependency_invalid"):
        store.put("child", {"value": 3}, dependency_refs=("sha256:" + "f" * 64,))
