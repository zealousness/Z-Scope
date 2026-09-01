from __future__ import annotations

import json
import socket
from pathlib import Path

from zscope.framework.llm_client import LLMClient

from p1_frozen_replay import replay_frozen_state


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "p1_frozen_replay"


def _forbid_external_call(*_args, **_kwargs):
    raise AssertionError("P1 frozen replay must not call a model or the network")


def test_p1_frozen_candidate_terminal_view_and_workflow_equivalence(monkeypatch) -> None:
    monkeypatch.setattr(LLMClient, "chat_completion", _forbid_external_call)
    monkeypatch.setattr(LLMClient, "run_conversation_with_tools", _forbid_external_call)
    monkeypatch.setattr(socket, "create_connection", _forbid_external_call)

    payload = json.loads((FIXTURE_ROOT / "input.json").read_text(encoding="utf-8"))
    expected = json.loads((FIXTURE_ROOT / "expected.json").read_text(encoding="utf-8"))

    migrated = replay_frozen_state(payload)

    # The frozen expected artifact records the historical P1 display
    # projection.  Proof-v4 deliberately must not recreate its structural
    # alias from legacy ``decision_proof`` material: neither confirmed row has
    # a frozen proof state, closure/root binding, exact terminal authority, or
    # call-path identity.  Keep the historical bytes immutable and assert the
    # deterministic, conservative migration instead.
    assert expected["finding_root_projection"]["finding_root_alias_count"] == 1
    assert (
        next(
            item
            for item in expected["terminal_outcomes"]
            if item["candidate_uid"] == "CAND_CONFIRM_B"
        )["candidate_disposition"]
        == "deduplicated_alias"
    )

    assert migrated["candidate_uids"] == expected["candidate_uids"]
    assert migrated["workflow"] == expected["workflow"]
    assert migrated["finding_root_projection"] == {
        "schema_version": "zscope.finding-root.v2",
        "input_outcome_count": 5,
        "display_input_count": 3,
        "finding_root_count": 3,
        "finding_root_alias_count": 0,
        "counts_by_merge_contract": {},
        "unprojectable_count": 0,
        "unprojectable_by_reason": {},
    }
    assert migrated["views"] == {
        "default": {
            "issue_count": 2,
            "included_needs_review_count": 0,
            "candidate_uids": ["CAND_CONFIRM_A", "CAND_CONFIRM_B"],
        },
        "with_needs_review": {
            "issue_count": 3,
            "included_needs_review_count": 1,
            "candidate_uids": ["CAND_CONFIRM_A", "CAND_CONFIRM_B", "CAND_REVIEW"],
        },
    }

    input_dispositions = {
        item["candidate_uid"]: item["terminal_disposition"]
        for item in payload["candidate_lifecycle_snapshot"]["outcomes"]
    }
    migrated_dispositions = {
        item["candidate_uid"]: item["candidate_disposition"]
        for item in migrated["terminal_outcomes"]
    }
    assert migrated_dispositions == input_dispositions
    for candidate_uid in ("CAND_CONFIRM_A", "CAND_CONFIRM_B"):
        outcome = next(
            item for item in migrated["terminal_outcomes"] if item["candidate_uid"] == candidate_uid
        )
        assert outcome["finding_root_merge_contract"] == "singleton"
        assert outcome["finding_root_alias_count"] == 0
        assert outcome["member_candidate_uids"] == [candidate_uid]


def test_p1_frozen_replay_manifest_hashes() -> None:
    import hashlib

    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    for name in ("input.json", "expected.json"):
        digest = hashlib.sha256((FIXTURE_ROOT / name).read_bytes()).hexdigest()
        assert digest == manifest["artifacts"][name]
    assert manifest["answer_free"] is True
    assert manifest["llm_calls"] == 0
    assert manifest["network_used"] is False
