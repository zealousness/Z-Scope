import json
from pathlib import Path

import pytest

from scripts.prepare_v3_action_canary import _inside, _select_currently_eligible
from scripts.prepare_v3_action_canary import _sha as canary_sha
from scripts.run_v3_action_canary import _verify_preflight
from zscope.orchestration.decision_trace import DecisionTraceError


def test_canary_excludes_historical_v3_clusters_without_executable_gap() -> None:
    rows = [
        {
            "validation_cluster_uid": "eligible-a",
            "required_fact_kinds": ["lockset"],
            "actions": [{"action_id": "action-a"}],
        },
        {
            "validation_cluster_uid": "empty",
            "required_fact_kinds": [],
            "actions": [],
        },
        {
            "validation_cluster_uid": "unsupported",
            "required_fact_kinds": ["caller_contract"],
            "actions": [],
        },
        {
            "validation_cluster_uid": "eligible-b",
            "required_fact_kinds": ["source_sink_reachability"],
            "actions": [{"action_id": "action-b"}],
        },
    ]

    selected, excluded = _select_currently_eligible(rows, limit=1)

    assert [row["validation_cluster_uid"] for row in selected] == ["eligible-a"]
    assert {
        row["validation_cluster_uid"]: row["current_v3_exclusion_reason"]
        for row in excluded
    } == {
        "empty": "empty_required_facts",
        "unsupported": "no_executable_action",
    }


def test_canary_source_lookup_is_answer_free_and_confined(tmp_path: Path) -> None:
    source_root = tmp_path / "input"
    source_root.mkdir()
    source = source_root / "source.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    assert _inside(source_root, "source.c") == source.resolve()

    outside = tmp_path / "outside.c"
    outside.write_text("int outside;\n", encoding="utf-8")
    with pytest.raises(DecisionTraceError, match="escapes answer-free root"):
        _inside(source_root, "../outside.c")

    forbidden = source_root / "ground_truth"
    forbidden.mkdir()
    (forbidden / "answer.c").write_text("int answer;\n", encoding="utf-8")
    with pytest.raises(DecisionTraceError, match="answer-bearing source path"):
        _inside(source_root, "ground_truth/answer.c")


def test_model_canary_requires_externally_bound_zero_model_preflight(
    tmp_path: Path,
) -> None:
    body = {
        "schema_version": "zscope.v3-action-canary-preflight.v1",
        "ready_for_model_canary": True,
        "model_calls": 0,
        "truth_inputs": 0,
        "clusters": [],
    }
    digest = canary_sha(body)
    path = tmp_path / "preflight.json"
    path.write_text(
        json.dumps({**body, "artifact_sha256": digest}),
        encoding="utf-8",
    )

    assert _verify_preflight(path, digest)["artifact_sha256"] == digest

    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["model_calls"] = 1
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(DecisionTraceError, match="artifact hash mismatch"):
        _verify_preflight(path, digest)
