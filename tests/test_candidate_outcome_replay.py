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
