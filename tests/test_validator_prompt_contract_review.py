"""Validator instructions must describe the evidence and arithmetic they admit."""

from pathlib import Path
import re

import pytest

from zscope.core.validation.claims import _CURRENT_FACT_REF_KINDS, _catalog_checks
from zscope.orchestration.specs import AgentSpec


def _prompt():
    path = Path(__file__).resolve().parents[1] / "zscope/agents/validator_agent/AGENT.md"
    return AgentSpec.from_markdown(path).to_prompt_block()


@pytest.mark.parametrize("kind", sorted(_CURRENT_FACT_REF_KINDS))
def test_prompt_lists_every_current_fact_kind_accepted_by_claim_replay(kind):
    assert kind in re.findall(r"`([^`]+)`", _prompt())
    _, failures = _catalog_checks(
        {
            "validator_evidence_ref_catalog": {"F": {"kind": kind, "summary": "当前事实"}},
            "decision_fact_slice": {"edge_uids" if kind.endswith("_edge") else "fact_uids": ["F"]},
        },
        {"evidence_refs": ["F"]},
    )
    assert failures == []


@pytest.mark.parametrize("bits", [8, 32, 64])
def test_prompt_unsigned_multiplication_guard_handles_zero_and_boundaries(bits):
    assert "`b == 0 || a <= SIZE_MAX / b`" in _prompt()
    maximum = (1 << bits) - 1
    values = (0, 1, 2, maximum // 2, maximum // 2 + 1, maximum - 1, maximum)
    for a in values:
        for b in values:
            safe = b == 0 or a <= maximum // b
            assert safe == (a * b <= maximum), (a, b)
