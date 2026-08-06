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


def test_validation_pipeline_promotes_complete_confirmation_proof_without_llm_verdict() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_CFG_PROOF",
        "deterministic_proofs": [
            {
                "outcome": "confirm",
                "proof_kind": "deterministic_cfg_obligation_path",
                "producer_engine": "clang_ast_cfg_obligation_prover",
                "fact_ids": ["cfg:10:header_length", "cfg:14:header_length_copy"],
                "code_hash": "body-v1",
                "facts": ["source_to_sink_complete", "event_path_complete"],
                "completeness": "complete",
            }
        ],
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "validator remains uncertain"},
        verdict="uncertain",
        score_data=_score(0.2),
    )

    assert outcome.report_bucket == "issues"
    assert issue["candidate_disposition"] == "confirmed"
    assert issue["proof_provider"] == "clang_ast_cfg_obligation_prover"


def test_validation_pipeline_keeps_conflicting_complete_proofs_reviewable() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_PROOF_CONFLICT",
        "deterministic_proofs": [
            {
                "outcome": "confirm",
                "proof_kind": "deterministic_cfg_obligation_path",
                "producer_engine": "clang_ast_cfg_obligation_prover",
                "fact_ids": ["cfg:10", "cfg:14"],
                "code_hash": "body-v1",
                "facts": ["source_to_sink_complete", "event_path_complete"],
                "completeness": "complete",
            },
            {
                "outcome": "reject",
                "proof_kind": "guard_dominates_sink",
                "producer_engine": "clang_ast_cfg_guard_dominance",
                "fact_ids": ["cfg:11"],
                "code_hash": "body-v1",
                "facts": ["guard_dominates_sink"],
                "completeness": "complete",
            },
        ],
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "conflicting evidence"},
        verdict="verified",
        score_data=_score(0.9),
    )

    assert outcome.report_bucket == "observations"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["evidence_conflict"] is True


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
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"
    assert issue["candidate_disposition"] == "needs_review"


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
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"


def test_validation_pipeline_keeps_structural_uncertain_as_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_STRUCTURAL_UNCERTAIN",
        "defect_class": "premature_destroy",
        "category": "premature_destroy",
        "function": "_runtime_release_packet_pool",
        "location": "src/lifecycle.c:2348",
        "sink": "SAFE_FREE(g_runtime_pbuf_pool)",
        "positive_evidence": ["active_tasks > 0 branch releases shared pool"],
        "negative_evidence": ["no quiescence guard before release"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "SAFE_FREE(g_runtime_pbuf_pool)", "line": 2348},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "Plausible structural lifetime risk, but current callers do not prove exploitability."},
        verdict="uncertain",
        score_data=_score(0.71),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"


def test_validation_pipeline_keeps_permission_uncertain_as_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_PERMISSION_UNCERTAIN",
        "defect_class": "permission",
        "category": "permission",
        "function": "_runtime_open_named_segment",
        "location": "src/lifecycle.c:2552",
        "sink": "if ((requested_perm & 0004u) != 0) return -1",
        "positive_evidence": ["requested permission is checked against hard-coded mode"],
        "negative_evidence": ["requested permission is not applied to chmod/open mode"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "requested permission check", "line": 2552},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "Plausible permission issue, but current deployment may not expose this mode."},
        verdict="uncertain",
        score_data=_score(0.7),
    )

    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"


def test_validation_pipeline_keeps_strongly_disproved_permission_rejected() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_PERMISSION_SAFE",
        "defect_class": "permission",
        "category": "permission",
        "function": "open_segment",
        "location": "src/demo.c:12",
        "sink": "requested permission check",
        "positive_evidence": ["requested permission check"],
        "negative_evidence": ["missing requested permission application"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "requested permission check", "line": 12},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "Rejected: guard dominates all paths and all paths are protected by a later fchmod using requested permission."},
        verdict="rejected",
        score_data=_score(0.8),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["rejection_source"] == "validator_without_deterministic_proof"


def test_validation_pipeline_discards_rejected_validator_result() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_7"}

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "not reachable"},
        verdict="rejected",
        score_data=_score(0.9),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"
    assert issue["rejection_source"] == "validator_without_deterministic_proof"


def test_validation_pipeline_does_not_trust_validator_self_attested_proof() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_SAFE",
        "negative_evidence": ["the dominating guard bounds len before every sink path"],
        "evidence_refs": ["src/demo.c:8", "src/demo.c:12"],
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {
            "reasoning": "The guard dominates the sink.",
            "proof_kind": "guard_dominates_sink",
            "negative_evidence": ["len <= capacity on all CFG predecessors"],
            "evidence_refs": ["src/demo.c:8", "src/demo.c:12"],
        },
        verdict="rejected",
        score_data=_score(0.9),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["candidate_disposition"] == "needs_review"


def test_validation_pipeline_accepts_engine_verified_rejection_proof() -> None:
    def verify_engine_proof(issue, val_data):
        return (
            issue.get("engine_proof_id") == "CFG_PROOF_1"
            and val_data.get("proof_kind") == "guard_dominates_sink"
        )

    pipeline = ValidationPipeline(
        FakeUserConfig(),
        deterministic_proof_verifier=verify_engine_proof,
    )
    issue = {
        "id": "ISSUE_SAFE",
        "engine_proof_id": "CFG_PROOF_1",
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {
            "reasoning": "The guard dominates the sink.",
            "proof_kind": "guard_dominates_sink",
        },
        verdict="rejected",
        score_data=_score(0.9),
    )

    assert outcome.report_bucket is None
    assert outcome.memory_status == "rejected"
    assert issue["validation_status"] == "rejected"
    assert issue["candidate_disposition"] == "rejected_with_proof"
    assert issue["deterministic_rejection"] is True


def test_validation_pipeline_accepts_structured_lock_dominance_proof() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_LOCK_SAFE",
        "code_hash": "code-v1",
        "deterministic_proofs": [
            {
                "outcome": "reject",
                "proof_kind": "lock_dominates_access",
                "producer_engine": "clang_ast_cfg",
                "fact_ids": ["cfg:11", "cfg:27"],
                "code_hash": "code-v1",
                "facts": ["lock_dominates_access", "all_accesses_guarded"],
                "completeness": "complete",
                "scope": "all accesses to runtime.event",
            }
        ],
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "The named lock protects every access."},
        verdict="rejected",
        score_data=_score(0.8),
    )

    assert outcome.report_bucket is None
    assert issue["candidate_disposition"] == "rejected_with_proof"
    assert issue["decision_proof"]["proof_kind"] == "lock_dominates_access"


def test_validation_pipeline_promotes_complete_structured_positive_proof() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_BOUNDS",
        "code_hash": "code-v1",
        "deterministic_proofs": [
            {
                "outcome": "confirm",
                "proof_kind": "unguarded_source_to_sink",
                "producer_engine": "svf_value_flow",
                "fact_ids": ["flow:source", "flow:sink"],
                "code_hash": "code-v1",
                "facts": ["source_to_sink_complete", "missing_guard"],
                "complete": True,
            }
        ],
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "The path is exploitable."},
        verdict="verified",
        score_data=_score(0.55),
    )

    assert outcome.report_bucket == "issues"
    assert issue["candidate_disposition"] == "confirmed"
    assert issue["promotion_reason"] == "deterministic_confirmation_proof"


def test_validation_pipeline_corrects_rejected_allocator_mismatch_to_memory_leak() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "GRAPH_ALLOC_FREE_MISMATCH_1",
        "defect_class": "alloc_free_mismatch",
        "category": "alloc_free_mismatch",
        "function": "_release_node",
        "location": "src/demo.c:88",
        "sink": "_runtime_noop_free(node)",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "_runtime_noop_free(node)", "line": 88},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {
            "reasoning": (
                "The alloc_free_mismatch category is wrong. The actual issue is a memory leak: "
                "_runtime_noop_free does not release the object and callers always pass use_header_pool=1."
            ),
            "confidence_score": 0.88,
            "positive_evidence": ["actual memory leak through _runtime_noop_free"],
        },
        verdict="rejected",
        score_data=_score(0.78),
    )

    assert outcome.report_bucket == "issues"
    assert outcome.memory_status == "validated"
    assert issue["category"] == "memory_leak"
    assert issue["defect_class"] == "memory_leak"
    assert issue["original_category"] == "alloc_free_mismatch"
    assert issue["evidence_pack"]["original_category"] == "alloc_free_mismatch"
    assert "alloc_free_mismatch" in issue["evidence_pack"]["alternate_categories"]
    assert issue["validation_status"] == "validated"
    assert issue["validator_verdict"] == "corrected"


def test_validation_pipeline_explicit_corrected_category_can_remain_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "CLANG_CFG_INTEGER_OVERFLOW_1",
        "defect_class": "integer_overflow",
        "category": "integer_overflow",
        "function": "_copy_fragment",
        "location": "src/demo.c:44",
        "sink": "memcpy(fragment, source, copy_len)",
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {
            "corrected_category": "heap_overflow",
            "reasoning": "The overflow arithmetic claim is false, but this may instead be a heap buffer overflow.",
            "confidence_score": 0.65,
        },
        verdict="rejected",
        score_data=_score(0.68),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["category"] == "heap_overflow"
    assert issue["validation_status"] == "needs_review"


def test_validation_pipeline_downgrades_structural_rejection_to_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_STRUCTURAL_1",
        "defect_class": "held_lock_callback",
        "function": "notify",
        "location": "src/demo.c:42",
        "sink": "callback(entry)",
        "description": "External callback from registry is invoked while mutex is held.",
        "positive_evidence": ["callback sink under lock"],
        "negative_evidence": ["no guard preventing reentrant callback"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "callback(entry)", "line": 42},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "Rejected because the current callback in this sample is not attacker-controlled."},
        verdict="rejected",
        score_data=_score(0.82),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"
    assert issue["validator_verdict"] == "rejected"


def test_validation_pipeline_downgrades_protocol_count_sink_rejection_to_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_PROTOCOL_COUNT",
        "defect_class": "bounds",
        "category": "bounds",
        "cwe": "CWE-20",
        "function": "_runtime_read_control_magic",
        "location": "src/lifecycle.c:1383",
        "sink": "memcpy(preview, seed, (size_t)count)",
        "positive_evidence": ["count is read before magic validation", "count reaches memcpy"],
        "negative_evidence": ["no magic/signature comparison before the count reaches the sink"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "memcpy(preview, seed, (size_t)count)", "line": 1383},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "Rejected because the current sample does not prove external attacker control."},
        verdict="rejected",
        score_data=_score(0.82),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"


def test_validation_pipeline_downgrades_post_release_global_deref_rejection_to_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_PBUF_UAF",
        "defect_class": "use_after_free",
        "category": "use_after_free",
        "cwe": "CWE-416",
        "function": "_runtime_release_packet_pool",
        "location": "src/lifecycle.c:2351",
        "sink": "return g_runtime_pbuf_pool->active_tasks",
        "positive_evidence": ["g_runtime_pbuf_pool is released", "g_runtime_pbuf_pool is dereferenced after release"],
        "negative_evidence": ["no quiescence guard before release"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "return g_runtime_pbuf_pool->active_tasks", "line": 2351},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "Rejected because the current caller sample does not prove exploitability."},
        verdict="rejected",
        score_data=_score(0.82),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"


def test_validation_pipeline_keeps_hardcoded_empty_callback_rejected() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_STRUCTURAL_2",
        "defect_class": "held_lock_callback",
        "function": "notify",
        "location": "src/demo.c:42",
        "sink": "callback(entry)",
        "description": "Callback is invoked while mutex is held.",
        "negative_evidence": ["no guard preventing reentrant callback"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "callback(entry)", "line": 42},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {
            "reasoning": (
                "Rejected because the current code registers a hardcoded empty callback "
                "and has no external replacement path."
            )
        },
        verdict="rejected",
        score_data=_score(0.82),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"


def test_validation_pipeline_keeps_transferred_resource_rejected() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {
        "id": "ISSUE_STRUCTURAL_3",
        "defect_class": "memory_leak",
        "function": "insert_node",
        "location": "src/demo.c:77",
        "sink": "return -1",
        "positive_evidence": ["allocated node reaches insert helper"],
        "negative_evidence": ["no local free after error return"],
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "sink": {"operation": "return -1", "line": 77},
        },
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "Rejected because ownership is transferred to a global owner and inserted into the global tree."},
        verdict="rejected",
        score_data=_score(0.82),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["validation_status"] == "needs_review"


def test_validation_pipeline_closes_validation_failure_as_operational() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_8"}

    outcome = pipeline.apply_validation_failure(issue, "timeout")

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "engine_failed"
    assert issue["validation_status"] == "engine_failed"
    assert issue["candidate_disposition"] == "engine_failed"
    assert issue["finding_kind"] == "validation_engine_failed"
    assert issue["record_role"] == "operational_obligation"
    assert issue["validation_error"] == "timeout"


def test_validation_pipeline_marks_unvalidated_issue_for_report() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"id": "ISSUE_9"}

    outcome = pipeline.apply_unvalidated(issue, _score(0.45))

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status is None
    assert issue["validation_status"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"
    assert issue["candidate_disposition"] == "needs_review"
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
