from types import SimpleNamespace

from zscope.core.analysis.analyzer import Analyzer
from zscope.core.validation.pipeline import ValidationPipeline


class FakeUserConfig:
    def __init__(self):
        self.false_positive = False
        self.baseline = None
        self.last_issue = None
        self.last_dedup_key = None

    def is_false_positive(self, func_name, location, category):
        return self.false_positive

    def get_finding_baseline_for_issue(self, issue, dedup_key):
        self.last_issue = issue
        self.last_dedup_key = dedup_key
        return self.baseline

    def get_finding_baseline(self, dedup_key):
        self.last_dedup_key = dedup_key
        return self.baseline


def test_validation_pipeline_applies_user_suppression() -> None:
    user_config = FakeUserConfig()
    user_config.false_positive = True
    pipeline = ValidationPipeline(user_config)
    issue = {
        "id": "ISSUE_1",
        "function": "entry",
        "location": "src/demo.c:42",
        "defect_class": "double_free",
    }

    decision = pipeline.apply_pre_validation_feedback(issue, "entry")

    assert decision is not None
    assert decision.rejection_source == "user_config"
    assert decision.report_bucket == "observations"
    assert issue["validation_status"] == "rejected"
    assert issue["finding_kind"] == "suppressed_false_positive"


def test_validation_pipeline_applies_stable_baseline_match() -> None:
    user_config = FakeUserConfig()
    user_config.baseline = {
        "status": "false_positive",
        "match_strategy": "stable_fingerprint",
    }
    pipeline = ValidationPipeline(user_config)
    issue = {
        "id": "ISSUE_2",
        "function": "entry",
        "location": "src/demo.c:57",
        "defect_class": "double_free",
        "rule": "resource_automaton",
        "dedup_key": "double_free|entry|src/demo.c:57",
    }

    decision = pipeline.apply_pre_validation_feedback(issue, "entry")

    assert decision is not None
    assert decision.rejection_source == "finding_baseline"
    assert decision.report_bucket == "observations"
    assert issue["validation_status"] == "rejected"
    assert issue["finding_kind"] == "suppressed_baseline"
    assert issue["baseline_match_strategy"] == "stable_fingerprint"
    assert user_config.last_dedup_key == issue["dedup_key"]


def _score(final_score: float) -> dict[str, float]:
    return {
        "rule_confidence": final_score,
        "path_completeness": final_score,
        "contract_consistency": final_score,
        "validation_confidence": final_score,
        "history_feedback": 0.5,
        "final_score": final_score,
    }


def test_validation_pipeline_reports_high_score_verified_issue() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_3", "confidence": 0.4}
    val_data = {
        "finding_kind": "verified_double_free",
        "reasoning": "confirmed path",
        "confidence_score": 0.9,
        "source": "alloc",
        "sink": "free",
    }

    outcome = pipeline.apply_validator_result(
        issue,
        val_data,
        verdict="verified",
        score_data=_score(0.85),
    )

    assert outcome.report_bucket == "issues"
    assert outcome.memory_status == "validated"
    assert issue["validation_status"] == "validated"
    assert issue["finding_kind"] == "verified_double_free"
    assert issue["confidence"] == 0.9
    assert issue["source"] == "alloc"
    assert issue["sink"] == "free"


def test_validation_pipeline_downgrades_mid_score_verified_issue() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_4"}

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "plausible but weak"},
        verdict="verified",
        score_data=_score(0.75),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"


def test_validation_pipeline_keeps_low_score_verified_issue_as_observation() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_5"}

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "verified but too little evidence"},
        verdict="verified",
        score_data=_score(0.55),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "uncertain"
    assert issue["validation_status"] == "uncertain"
    assert issue["finding_kind"] == "audit_observation"


def test_validation_pipeline_keeps_uncertain_validator_result_as_observation() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_6"}

    outcome = pipeline.apply_validator_result(
        issue,
        {"finding_kind": "needs_manual_review", "reasoning": "ambiguous alias"},
        verdict="uncertain",
        score_data=_score(0.9),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "uncertain"
    assert issue["validation_status"] == "uncertain"
    assert issue["finding_kind"] == "needs_manual_review"


def test_validation_pipeline_discards_rejected_validator_result() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_7"}

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "not reachable"},
        verdict="rejected",
        score_data=_score(0.9),
    )

    assert outcome.report_bucket is None
    assert outcome.memory_status == "rejected"
    assert issue["validation_status"] == "rejected"
    assert issue["finding_kind"] == "rejected"
    assert issue["rejection_source"] == "validator"


def test_validation_pipeline_keeps_validation_failure_pending() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_8"}

    outcome = pipeline.apply_validation_failure(issue, "timeout")

    assert outcome.report_bucket == "observations"
    assert issue["validation_status"] == "pending"
    assert issue["finding_kind"] == "validation_pending"
    assert issue["validation_error"] == "timeout"


def test_validation_pipeline_marks_unvalidated_issue_for_report() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_9"}

    outcome = pipeline.apply_unvalidated(issue, _score(0.45))

    assert outcome.report_bucket == "issues"
    assert outcome.memory_status is None
    assert issue["validation_status"] == "unvalidated"
    assert issue["finding_kind"] == "unvalidated_candidate"
    assert issue["final_score"] == 0.45


def test_validation_pipeline_static_audit_gate_skips_validator() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "CLANG_CFG_SIZE_LIMIT_MISMATCH_1",
        "validation_required": False,
        "finding_kind": "audit_observation",
        "audit_observation_reason": "design mismatch without a visible unsafe sink",
        "location": "src/demo.c:12",
    }

    decision = pipeline.apply_pre_validation_feedback(issue, "demo")

    assert decision is not None
    assert decision.action == "audit_observation"
    assert decision.report_bucket == "observations"
    assert issue["validation_status"] == "uncertain"
    assert issue["finding_kind"] == "audit_observation"
    assert issue["validation_reasoning"] == "design mismatch without a visible unsafe sink"


def test_validation_pipeline_score_components_use_evidence_and_history() -> None:
    user_config = FakeUserConfig()
    user_config.baseline = {"status": "verified"}
    pipeline = ValidationPipeline(user_config)
    issue = {
        "id": "ISSUE_10",
        "rule_confidence": 0.8,
        "evidence_pack": {"path": {"complete": True}},
        "dedup_key": "stable-key",
    }

    score = pipeline.score_components(
        issue,
        {"confidence_score": 0.9, "source": "arg", "sink": "free"},
    )

    assert score["rule_confidence"] == 0.8
    assert score["path_completeness"] == 1.0
    assert score["contract_consistency"] == 0.8
    assert score["validation_confidence"] == 0.9
    assert score["history_feedback"] == 1.0
    assert score["final_score"] == 0.89


def test_analyzer_keeps_pre_validation_suppression_as_audit_observation() -> None:
    user_config = FakeUserConfig()
    user_config.baseline = {"status": "false_positive", "match_strategy": "stable_fingerprint"}
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            agents=[SimpleNamespace(name="validator_agent", enabled=False)]
        )
    )
    analyzer.validation_pipeline = ValidationPipeline(user_config)
    state = {
        "pending_new_issues": [
            {
                "id": "ISSUE_11",
                "function": "entry",
                "location": "src/demo.c:99",
                "category": "memory_leak",
                "dedup_key": "old-line-key",
            }
        ],
        "agent_context": {"func_name": "entry"},
        "issues": [],
        "observations": [],
        "notes": [],
    }

    analyzer._step_validate_findings(state)

    assert state["issues"] == []
    assert state["pending_new_issues"] == []
    assert len(state["observations"]) == 1
    observation = state["observations"][0]
    assert observation["validation_status"] == "rejected"
    assert observation["finding_kind"] == "suppressed_baseline"
    assert observation["baseline_match_strategy"] == "stable_fingerprint"
