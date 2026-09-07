from types import SimpleNamespace

from test_review_fact_checks import compile_facts, issue
from test_validation_runner import _runner, _state, FakeCodeIndex

from zscope.common.validator_protocol import ValidatorResultV3
from zscope.framework.base import AgentResponse
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.reporting.views import build_report_views
from zscope.reporting.finding_roots import project_finding_roots
from zscope.common.issue_identity import deduplicate_issues
from zscope.config.config import AnalysisConfig


class UncertainAgent:
    def __init__(self):
        self.calls = []

    def run(self, data):
        self.calls.append(data)
        return AgentResponse(
            success=True,
            data=ValidatorResultV3(
                candidate_uid=data["finding_uid"],
                validation_cluster_uid=data["validation_cluster_uid"],
                validation_pass="initial",
                verdict="uncertain",
                reasoning="需要证明并发条件",
                positive_evidence=(),
                negative_evidence=(),
                evidence_refs=(),
                blocking_negative_evidence=False,
                missing_fact_request=None,
                stop_reason="decision_complete",
            ).to_dict(),
        )


def test_checked_parent_rejection_still_validates_related_candidate(compile_facts, tmp_path):
    store, _, path = compile_facts(
        "typedef struct N { char name[8]; } N;\nvoid f(N *node) { (void)node; }\n"
    )
    parent = issue(
        path,
        rule_id="clang_cfg_parent_release_without_owned_member_cleanup",
        description="common owned member node->tag not cleaned up",
        line=2,
    )
    parent["review_related_proposals"] = [
        {
            "file": str(path),
            "line": 2,
            "location": f"{path}:2",
            "function": "f",
            "category": "race",
            "source": "node->name",
            "sink": "access",
            "description": "another member requires investigation",
            "analysis_scope": "current_build",
            "trigger_condition": "concurrent callers",
            "evidence_refs": ["tool"],
        }
    ]
    agent = UncertainAgent()
    analysis = SimpleNamespace(
        validation_checked_proofs=True,
        validation_related_findings=True,
        llm_decision_explanation=False,
        snapshot_dir=str(tmp_path / "snapshots"),
    )
    index = FakeCodeIndex()
    index.get_function_impl = lambda *_args, **_kwargs: {
        "code": path.read_text(),
        "file": str(path),
    }
    runner = _runner(agent, analysis=analysis, code_index=index)
    runner.config.project.project_root = tmp_path
    runner.config.project.compile_commands_path = store.compile_commands
    main = CandidateLedger(project_root=str(tmp_path))
    CandidateRegistrar(main).register_issues(
        [parent], source="clang_ast_cfg", default_entry_identity="f"
    )
    main.freeze()
    state = _state(parent)
    state["candidate_ledger"] = main
    runner.run(state)
    assert parent["candidate_disposition"] == "rejected_with_proof"
    assert len(agent.calls) == 1
    assert len(state["review_related_candidates"]) == 1
    child = state["review_related_candidates"][0]
    assert child["candidate_disposition"] == "needs_review" and child["related_generation"] == 1
    snapshot = main.lifecycle_snapshot()
    assert len(snapshot["outcomes"]) == 2
    assert snapshot["summary"]["total"] == main.summary()["total"] == 2
    assert parent["review_checkpoint_id"] and child["review_checkpoint_id"]


def test_checkpoint_replay_retains_exact_prior_result_and_evidence(compile_facts, tmp_path):
    store, _, path = compile_facts("void f(void) { int n = 0; (void)n; }\n")
    candidate = issue(path, category="race", rule_id="unsupported", source="n", line=1)
    agent = UncertainAgent()
    analysis = SimpleNamespace(
        validation_review_checkpoint=True,
        llm_decision_explanation=False,
        snapshot_dir=str(tmp_path / "snapshots"),
    )
    index = FakeCodeIndex()
    index.get_function_impl = lambda *_args, **_kwargs: {
        "code": path.read_text(),
        "file": str(path),
    }
    runner = _runner(agent, analysis=analysis, code_index=index)
    runner.config.project.project_root = tmp_path
    runner.config.project.compile_commands_path = store.compile_commands
    runner.run(_state(candidate))
    prior = candidate["review_latest_result"]
    before_calls = len(agent.calls)
    frozen_evidence = candidate["review_validation_evidence"]
    replay = runner.replay_review_candidate(
        candidate, prior, investigate_uncertain=False, audit_rejection=False
    )
    assert len(agent.calls) == before_calls
    assert replay["candidate"]["candidate_uid"] == candidate["candidate_uid"]
    assert replay["candidate"]["review_latest_result"] == prior
    assert replay["candidate"]["review_validation_evidence"] == frozen_evidence
    assert replay["candidate"]["candidate_disposition"] == "needs_review"


def test_default_flags_and_conditional_risk_survive_report_deduplication():
    config = AnalysisConfig()
    for flag in (
        "validation_review_checkpoint",
        "validation_review_protocol",
        "validation_checked_proofs",
        "validation_positive_case",
        "validation_related_findings",
    ):
        assert getattr(config, flag) is False
    base = {
        "function": "f",
        "file": "a.c",
        "line": 3,
        "location": "a.c:3",
        "category": "race",
        "source": "shared",
        "sink": "shared++",
        "description": "access",
        "impact_level": "high",
    }
    current = {
        **base,
        "candidate_uid": "current",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
    }
    conditional = {
        **base,
        "candidate_uid": "conditional",
        "candidate_disposition": "needs_review",
        "validation_status": "needs_review",
        "analysis_scope": "conditional_source_branch",
        "trigger_condition": "!defined(LOCKS)",
    }
    assert len(deduplicate_issues([current.copy(), conditional.copy()])) == 2
    assert len(project_finding_roots([current, conditional]).outcomes) == 2
    views = build_report_views([current], [conditional])
    review = views["with_needs_review"]
    assert review["conditional_needs_review_count"] == 1
    assert len(review["issues"]) == 2
