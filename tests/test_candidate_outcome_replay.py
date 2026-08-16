import importlib.util
import json
from pathlib import Path


def _replay_module():
    path = Path(__file__).parents[1] / "scripts" / "replay_candidate_outcomes.py"
    spec = importlib.util.spec_from_file_location("candidate_outcome_replay", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_replay_is_read_only_and_emits_transition_table(tmp_path) -> None:
    replay = _replay_module()
    report = {
        "run_manifest": {"source_revision": "rev-a"},
        "candidate_terminal_states": [
            {
                "candidate_uid": "CAND_1",
                "validation_cluster_uid": "VAL_1",
                "terminal_disposition": "needs_review",
                "impact_level": "high",
                "category": "stack_escape",
                "rule": "clang_cfg_stack_address_passed_to_thread",
                "evidence_pack": {
                    "path": {"complete_in_function": True},
                    "ast_cfg": {
                        "events": [
                            {"kind": "stack_object", "line": 2, "variable": "job"},
                            {"kind": "thread_arg_escape", "line": 3, "variable": "job"},
                        ]
                    },
                },
                "code_snippet": "Job job;\npthread_create(&tid, NULL, worker, &job);\npthread_detach(tid);",
            }
        ],
    }
    input_path = tmp_path / "frozen-report.json"
    input_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    before = input_path.read_bytes()

    outcome = replay.replay_report(report, source_revision="rev-a")

    assert input_path.read_bytes() == before
    assert outcome["canonical_group_count"] == 1
    assert outcome["transitions"][0]["new_disposition"] == "confirmed"
    assert outcome["transitions"][0]["reason"] == "async_stack_address_escape"


def test_replay_revokes_archived_counterproof_that_current_provider_cannot_reproduce() -> None:
    replay = _replay_module()
    report = {
        "run_manifest": {"source_revision": "rev-a"},
        "candidate_terminal_states": [
            {
                "candidate_uid": "CAND_LOCK",
                "validation_cluster_uid": "VAL_LOCK",
                "terminal_disposition": "rejected_with_proof",
                "impact_level": "high",
                "category": "lock_protocol_violation",
                "rule": "clang_cfg_unlock_without_matching_lock",
                "evidence_pack": {"path": {"complete_in_function": True}},
                "deterministic_proofs": [
                    {
                        "outcome": "reject",
                        "proof_kind": "matching_lock_dominates_unlock",
                        "producer_engine": "clang_ast_cfg_lock_protocol",
                        "proof_version": "zscope.decision-proof.v4",
                        "fact_ids": ["cfg:2", "cfg:7"],
                        "cfg_nodes": ["2", "7"],
                        "code_hash": "a" * 64,
                        "facts": ["matching_lock_dominates_unlock"],
                        "completeness": "complete",
                    }
                ],
                "code_snippet": """
if (abort_batch) {
    UNLOCK(&state.lock);
    return -1;
}
LOCK(&state.lock);
update();
UNLOCK(&state.lock);
""",
            }
        ],
    }

    outcome = replay.replay_report(report, source_revision="rev-a")

    transition = outcome["transitions"][0]
    assert transition["old_disposition"] == "rejected_with_proof"
    assert transition["new_disposition"] == "needs_review"
    assert transition["reason"] == "archived_complete_proof_not_reproduced"
