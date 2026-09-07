"""Tests for the LLM decision-explanation supplement (LLM-free decisions)."""

from types import SimpleNamespace

from zscope.config.v2 import _runtime_analysis, load_runtime_spec
from zscope.core.validation.explanation import (
    apply_decision_explanations,
    collect_unexplained_decisions,
    decision_disposition,
    explain_decision_with_llm,
)
from zscope.core.validation.runner import ValidationRunner

from tests.test_validation_runner import (
    FakeSnapshotStore,
    FakeUserConfig,
    FakeValidatorAgent,
    ValidationPipeline,
    _runner,
)


def _confirmed_issue(**overrides):
    issue = {
        "id": "ISSUE_1",
        "category": "security",
        "subcategory": "memory_bounds_integer",
        "function": "parse_header",
        "location": "src/parse.c:42",
        "description": "Unbounded multiplication feeds the allocator size.",
        "code": "void parse_header(void) { p = malloc(a * b); }",
        "validation_status": "validated",
        "candidate_disposition": "confirmed",
        "finding_kind": "verified_vulnerability",
        "deterministic_prevalidation_decision": "confirmed",
        "decision_proof": {
            "outcome": "confirm",
            "proof_kind": "memory_bounds_integer",
            "producer_engine": "evidence_completion",
            "summary": "未检查的分配大小算术运算先于任何溢出防护求值，并最终到达分配器",
            "scope": "完整证据",
            "facts": [{"kind": "value_range", "summary": "乘法结果未受约束"}],
        },
        "validation_reasoning": "未检查的分配大小算术运算先于任何溢出防护求值，并最终到达分配器",
        "attribution": {"decided_by": "deterministic_proof", "decision_level": "V0"},
    }
    issue.update(overrides)
    return issue


def _audit_observation(**overrides):
    issue = {
        "id": "OBS_1",
        "finding_kind": "audit_observation",
        "rejection_source": "static_analysis",
        "validation_status": "uncertain",
        "validation_reasoning": "静态验证门控",
    }
    issue.update(overrides)
    return issue


class FakeExplainerLLM:
    def __init__(self, replies=None, error=None):
        self.replies = list(replies or [])
        self.error = error
        self.calls = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        if self.error:
            raise self.error
        content = self.replies.pop(0) if self.replies else ""
        return {"choices": [{"message": {"content": content}}]}


def test_decision_disposition_selects_llm_free_report_decisions():
    assert decision_disposition(_confirmed_issue()) == "confirmed"
    assert decision_disposition(_audit_observation()) == "audit_observation"
    assert (
        decision_disposition(
            _confirmed_issue(deterministic_prevalidation_decision="evidence_conflict")
        )
        == "evidence_conflict"
    )


def test_decision_disposition_skips_non_targets():
    # Deterministic rejections never reach a report bucket, and shadow
    # candidates stay telemetry-only; neither should be explained.
    assert (
        decision_disposition(
            _confirmed_issue(deterministic_prevalidation_decision="rejected_with_proof")
        )
        is None
    )
    assert (
        decision_disposition(
            _confirmed_issue(
                deterministic_prevalidation_decision="shadow_observation",
                finding_kind="rollout_shadow_observation",
            )
        )
        is None
    )
    # Static suppression is dropped from the report too.
    assert (
        decision_disposition(_audit_observation(finding_kind="static_suppressed_false_positive"))
        is None
    )
    # Already explained issues stay untouched (idempotent pass).
    assert decision_disposition(_confirmed_issue(llm_explanation="已有解释")) is None


def test_collect_unexplained_decisions_reads_report_buckets():
    state = {
        "issues": [_confirmed_issue()],
        "observations": [_audit_observation()],
    }
    collected = collect_unexplained_decisions(state)
    assert len(collected) == 2
    missing_bucket = {"issues": [], "observations": []}
    assert collect_unexplained_decisions(missing_bucket) == []
    assert collect_unexplained_decisions({}) == []


def test_explain_decision_with_llm_parses_chinese_json():
    client = FakeExplainerLLM(
        replies=[
            '前缀 {"explanation": "该问题将未受保护的乘法结果直接传给 malloc，可能产生整数溢出。"} 后缀'
        ]
    )
    explanation = explain_decision_with_llm(client, _confirmed_issue())
    assert explanation == "该问题将未受保护的乘法结果直接传给 malloc，可能产生整数溢出。"
    messages, kwargs = client.calls[0]
    assert kwargs["trace_agent"] == "decision_explainer"
    assert kwargs["temperature"] == 0.0
    payload = messages[1]["content"]
    assert "confirmed" in payload
    assert "parse_header" in payload
    assert "未检查的分配大小算术运算" in payload


def test_explain_decision_with_llm_truncates_long_text():
    long_text = "解" * 2000
    client = FakeExplainerLLM(replies=['{"explanation": "%s"}' % long_text])
    explanation = explain_decision_with_llm(client, _confirmed_issue())
    assert explanation is not None
    assert len(explanation) <= 800


def test_explain_decision_with_llm_degrades_silently():
    failing = FakeExplainerLLM(error=RuntimeError("provider down"))
    assert explain_decision_with_llm(failing, _confirmed_issue()) is None
    malformed = FakeExplainerLLM(replies=["不是 JSON 的回复"])
    assert explain_decision_with_llm(malformed, _confirmed_issue()) is None
    assert explain_decision_with_llm(None, _confirmed_issue()) is None
    # A non-target issue never triggers a call.
    untouched = FakeExplainerLLM(replies=['{"explanation": "x"}'])
    assert explain_decision_with_llm(untouched, {"finding_kind": "rejected"}) is None
    assert untouched.calls == []


def test_apply_decision_explanations_respects_budget():
    first = _confirmed_issue(id="ISSUE_1")
    second = _confirmed_issue(id="ISSUE_2")
    state = {"issues": [first, second], "observations": []}
    client = FakeExplainerLLM(
        replies=[
            '{"explanation": "解释一"}',
            '{"explanation": "解释二"}',
        ]
    )
    stats = apply_decision_explanations(state, llm_client=client, budget=1, used=0)
    assert stats == {"candidates": 2, "explained": 1, "skipped_budget": 1, "failed": 0}
    assert first["llm_explanation"] == "解释一"
    assert "llm_explanation" not in second
    # The deterministic reasoning stays untouched and authoritative.
    assert first["validation_reasoning"] == (
        "未检查的分配大小算术运算先于任何溢出防护求值，并最终到达分配器"
    )
    # A later batch with an exhausted budget spends nothing more.
    stats = apply_decision_explanations(state, llm_client=client, budget=1, used=1)
    assert stats["explained"] == 0
    assert stats["skipped_budget"] == 1


def test_apply_decision_explanations_without_client_is_noop():
    issue = _confirmed_issue()
    state = {"issues": [issue], "observations": []}
    stats = apply_decision_explanations(state, llm_client=None, budget=5, used=0)
    assert stats == {"candidates": 0, "explained": 0, "skipped_budget": 0, "failed": 0}
    assert "llm_explanation" not in issue


def test_runtime_analysis_accepts_decision_explanation_keys():
    analysis = _runtime_analysis(
        {"llm_decision_explanation": False, "llm_decision_explanation_budget": 7}
    )
    assert analysis.llm_decision_explanation is False
    assert analysis.llm_decision_explanation_budget == 7


def test_runtime_spec_defaults_enable_decision_explanation():
    analysis = load_runtime_spec().analysis
    assert analysis.llm_decision_explanation is True
    assert analysis.llm_decision_explanation_budget == 50


def _explanation_runner(llm_clients, analysis):
    return _runner(
        FakeValidatorAgent([]),
        analysis=analysis,
        scan=SimpleNamespace(llm_profiles=SimpleNamespace(validation="default")),
        llm_clients=llm_clients,
    )


def _explanation_state():
    return {
        "issues": [_confirmed_issue()],
        "observations": [_audit_observation()],
        "notes": [],
    }


def test_runner_supplements_deterministic_decisions():
    client = FakeExplainerLLM(
        replies=[
            '{"explanation": "确定性证明确认分配大小未受约束。"}',
            '{"explanation": "静态门控将该告警转为审计观察。"}',
        ]
    )
    runner = _explanation_runner(
        {"default": client},
        SimpleNamespace(llm_decision_explanation=True, llm_decision_explanation_budget=5),
    )
    state = _explanation_state()
    runner._supplement_decision_explanations(state)
    assert state["issues"][0]["llm_explanation"] == "确定性证明确认分配大小未受约束。"
    assert state["observations"][0]["llm_explanation"] == "静态门控将该告警转为审计观察。"
    assert runner._decision_explanations_used == 2
    assert state["decision_explanations"]["explained"] == 2


def test_runner_decision_explanation_honors_config_switch_and_budget():
    client = FakeExplainerLLM(replies=['{"explanation": "x"}'])
    runner = _explanation_runner(
        {"default": client},
        SimpleNamespace(llm_decision_explanation=False, llm_decision_explanation_budget=5),
    )
    state = _explanation_state()
    runner._supplement_decision_explanations(state)
    assert client.calls == []
    assert "llm_explanation" not in state["issues"][0]

    budget_runner = _explanation_runner(
        {"default": client},
        SimpleNamespace(llm_decision_explanation=True, llm_decision_explanation_budget=0),
    )
    budget_runner._supplement_decision_explanations(state)
    assert client.calls == []


def test_runner_decision_explanation_without_client_is_noop():
    runner = _explanation_runner(
        {},
        SimpleNamespace(llm_decision_explanation=True, llm_decision_explanation_budget=5),
    )
    state = _explanation_state()
    runner._supplement_decision_explanations(state)
    assert "llm_explanation" not in state["issues"][0]
    assert "decision_explanations" not in state
