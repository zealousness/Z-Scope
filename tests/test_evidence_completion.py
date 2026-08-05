from zscope.core.validation.evidence_completion import EvidenceCompletionQueue


def test_evidence_completion_promotes_only_backend_attached_proof_once() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "race",
        "validation_cluster_uid": "VAL_1",
        "evidence_completion_proofs": [
            {
                "outcome": "reject",
                "proof_kind": "lock_dominates_access",
                "producer_engine": "clang_ast_cfg",
                "fact_ids": ["cfg:1"],
                "code_hash": "code",
                "facts": ["lock_dominates_access", "all_accesses_guarded"],
                "complete": True,
            }
        ],
    }

    request = queue.complete(issue, validator_data={"verdict": "rejected"})

    assert request is not None
    assert request.missing_fact == "lock_or_happens_before"
    assert issue["evidence_completion_status"] == "completed"
    assert len(issue["deterministic_proofs"]) == 1
    assert queue.complete(issue, validator_data={"verdict": "rejected"}) is None


def test_evidence_completion_records_missing_fact_without_inventing_proof() -> None:
    queue = EvidenceCompletionQueue()
    issue = {"impact_level": "critical", "category": "bounds"}

    request = queue.complete(issue, validator_data={"verdict": "verified"})

    assert request is not None
    assert issue["evidence_completion_status"] == "requested"
    assert "deterministic_proofs" not in issue


def test_evidence_completion_derives_lock_proof_only_for_all_local_assignments() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "unsynchronized_shared_state",
        "rule": "clang_cfg_global_state_written_with_and_without_lock",
        "resource_signature": "state.current",
    }
    evidence = {
        "function_context": {
            "code": """
LOCK(&state.lock);
state.current = event;
UNLOCK(&state.lock);
LOCK(&state.lock);
state.current = NULL;
UNLOCK(&state.lock);
"""
        }
    }

    queue.complete(
        issue,
        validator_data={"verdict": "rejected"},
        validation_evidence=evidence,
    )

    assert issue["evidence_completion_status"] == "completed"
    assert issue["deterministic_proofs"][0]["proof_kind"] == "lock_dominates_access"


def test_evidence_completion_refuses_lock_proof_when_one_write_is_unlocked() -> None:
    queue = EvidenceCompletionQueue()
    issue = {
        "impact_level": "high",
        "category": "unsynchronized_shared_state",
        "rule": "clang_cfg_global_state_written_with_and_without_lock",
        "resource_signature": "state.current",
    }
    evidence = {
        "function_context": {
            "code": """
LOCK(&state.lock);
state.current = event;
UNLOCK(&state.lock);
state.current = NULL;
"""
        }
    }

    queue.complete(
        issue,
        validator_data={"verdict": "rejected"},
        validation_evidence=evidence,
    )

    assert issue["evidence_completion_status"] == "requested"
    assert "deterministic_proofs" not in issue
