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

    assert replay_frozen_state(payload) == expected


def test_p1_frozen_replay_manifest_hashes() -> None:
    import hashlib

    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    for name in ("input.json", "expected.json"):
        digest = hashlib.sha256((FIXTURE_ROOT / name).read_bytes()).hexdigest()
        assert digest == manifest["artifacts"][name]
    assert manifest["answer_free"] is True
    assert manifest["llm_calls"] == 0
    assert manifest["network_used"] is False
