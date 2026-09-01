from zscope.orchestration.candidate_envelope import (
    CANDIDATE_SCHEMA_VERSION,
    annotate_issue_identity,
)
from zscope.reporting.schema import (
    apply_report_schema_v2,
    coalesce_terminal_candidates,
    completeness_status,
    exit_code_for_report,
    needs_review_count,
    report_invariant_status,
    report_is_reusable,
    report_reuse_blockers,
)
from zscope.orchestration.runtime_authority import (
    RUNTIME_CACHE_EPOCH,
    build_runtime_authority_manifest,
)


def test_enabled_discovery_without_llm_is_partial_and_exit_two() -> None:
    report = {"issues": []}
    apply_report_schema_v2(
        report,
        state={
            "completeness": "complete",
            "engine_capabilities": {
                "active_discovery": {
                    "status": "planned_no_llm_client",
                    "reason": "analysis profile unavailable",
                }
            },
        },
        issues=[],
        observations=[],
        metadata={"run_id": "RUN"},
        entry_function="entry",
    )

    assert report["completeness"] == "partial"
    assert report["candidate_terminal_states"][0]["candidate_disposition"] == ("deferred_budget")
    assert exit_code_for_report(report, policy="legacy") == 2


def test_fast_disabled_discovery_does_not_mark_report_partial() -> None:
    assert (
        completeness_status(
            {
                "active_discovery": {
                    "enabled": False,
                    "status": "disabled_by_profile",
                }
            }
        )
        == "complete"
    )


def test_run_manifest_preserves_finding_root_v2_projection_summary() -> None:
    report = {"issues": []}
    projection = {
        "schema_version": "zscope.finding-root.v2",
        "input_outcome_count": 10,
        "finding_root_count": 8,
        "finding_root_alias_count": 2,
        "counts_by_merge_contract": {"same_candidate_uid": 2},
        "unprojectable_count": 0,
        "unprojectable_by_reason": {},
    }

    apply_report_schema_v2(
        report,
        state={
            "finding_root_count": 8,
            "finding_root_alias_count": 2,
            "finding_root_projection_summary": projection,
        },
        issues=[],
        observations=[],
        metadata={"run_id": "RUN"},
        entry_function="entry",
    )

    assert report["run_manifest"]["finding_root_count"] == 8
    assert report["run_manifest"]["finding_root_alias_count"] == 2
    assert report["run_manifest"]["finding_root_projection"] == projection


def test_report_invariant_rejects_open_evidence_completion() -> None:
    confirmed = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_1",
        "status": "validated",
        "obligation_uid": "OBL_1",
    }
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_2",
        "status": "needs_review",
        "obligation_uid": "OBL_2",
        "evidence_completion_status": "requested",
    }

    status = report_invariant_status(
        [confirmed],
        [review],
        [confirmed, review],
        canonical_projection=True,
        default_items=[confirmed],
        with_needs_review_items=[confirmed, review],
    )

    assert status["valid"] is False
    assert status["open_evidence_completion_count"] == 1


def test_report_invariant_accounts_all_terminal_dispositions_and_views() -> None:
    confirmed = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
        "status": "confirmed",
        "obligation_uid": "OBL_confirmed",
    }
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "status": "needs_review",
        "obligation_uid": "OBL_review",
    }
    rejected = {
        "candidate_disposition": "rejected_with_proof",
        "validation_cluster_uid": "VAL_rejected",
        "status": "rejected_with_proof",
        "obligation_uid": "OBL_rejected",
    }
    alias = {
        "candidate_disposition": "deduplicated_alias",
        "validation_cluster_uid": "VAL_alias",
        "status": "deduplicated_alias",
        "obligation_uid": "OBL_alias",
    }
    audit = {
        "candidate_disposition": "shadow_observation",
        "validation_cluster_uid": "VAL_audit",
        "status": "shadow_observation",
        "validation_status": "needs_review",
        "obligation_uid": "OBL_audit",
    }
    operational = {
        "candidate_disposition": "engine_failed",
        "record_role": "operational_obligation",
        "status": "engine_failed",
        "operational_uid": "OP_engine",
    }

    status = report_invariant_status(
        [confirmed],
        [review],
        [confirmed, review, rejected, alias, audit, operational],
        canonical_projection=True,
        default_items=[confirmed],
        with_needs_review_items=[confirmed, review],
    )

    assert status["valid"] is True
    assert status["terminal_outcome_count"] == 6
    assert status["terminal_outcome_conservation_passed"] is True
    assert status["terminal_disposition_counts"] == {
        "confirmed": 1,
        "deduplicated_alias": 1,
        "engine_failed": 1,
        "needs_review": 1,
        "rejected_with_proof": 1,
        "shadow_observation": 1,
    }
    assert status["deduplicated_alias_count"] == 1
    assert status["audit_observation_count"] == 1
    assert status["rejected_with_proof_count"] == 1
    assert status["operational_obligation_count"] == 1
    assert status["default_is_with_needs_review_subset"] is True
    assert status["all_canonical_needs_review_included"] is True
    assert needs_review_count([review, audit], [review, audit]) == 1


def test_report_invariant_rejects_unknown_terminal_or_missing_review_projection() -> None:
    confirmed = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
        "status": "confirmed",
    }
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "status": "needs_review",
    }
    unknown = {
        "candidate_disposition": "mystery_terminal",
        "validation_cluster_uid": "VAL_unknown",
        "status": "mystery_terminal",
    }

    status = report_invariant_status(
        [confirmed],
        [],
        [confirmed, review, unknown],
        canonical_projection=True,
    )

    assert status["valid"] is False
    assert status["unknown_terminal_disposition_count"] == 1
    assert status["terminal_outcome_conservation_passed"] is False
    assert status["all_canonical_needs_review_included"] is False


def test_report_invariant_rejects_actual_review_view_missing_default_member() -> None:
    confirmed = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
        "status": "confirmed",
    }
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "status": "needs_review",
    }

    status = report_invariant_status(
        [confirmed],
        [review],
        [confirmed, review],
        canonical_projection=True,
        default_items=[confirmed],
        with_needs_review_items=[review],
    )

    assert status["valid"] is False
    assert status["default_is_with_needs_review_subset"] is False
    assert status["all_canonical_needs_review_included"] is True


def test_report_invariant_rejects_extra_non_actionable_view_members() -> None:
    confirmed = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
        "status": "confirmed",
    }
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "status": "needs_review",
    }
    rejected = {
        "candidate_disposition": "rejected_with_proof",
        "validation_cluster_uid": "VAL_rejected",
        "status": "rejected_with_proof",
    }
    audit = {
        "candidate_disposition": "shadow_observation",
        "validation_cluster_uid": "VAL_audit",
        "status": "shadow_observation",
    }

    for extra in (rejected, audit):
        status = report_invariant_status(
            [confirmed],
            [review],
            [confirmed, review, rejected, audit],
            canonical_projection=True,
            default_items=[confirmed],
            with_needs_review_items=[confirmed, review, extra],
        )
        assert status["valid"] is False
        assert status["actual_with_needs_review_membership_exact"] is False


def test_report_invariant_rejects_duplicate_or_empty_view_identities() -> None:
    confirmed = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
        "status": "confirmed",
    }
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "status": "needs_review",
    }
    duplicate = report_invariant_status(
        [confirmed],
        [review],
        [confirmed, review],
        canonical_projection=True,
        default_items=[confirmed],
        with_needs_review_items=[confirmed, review, review],
    )
    assert duplicate["valid"] is False
    assert duplicate["view_membership_identities_unique"] is False

    empty = report_invariant_status(
        [confirmed],
        [review],
        [confirmed, review],
        canonical_projection=True,
        default_items=[confirmed],
        with_needs_review_items=[confirmed, {"candidate_disposition": "needs_review"}],
    )
    assert empty["valid"] is False
    assert empty["view_membership_identities_nonempty"] is False


def test_apply_report_schema_attaches_both_canonical_views_when_missing() -> None:
    confirmed = {
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
        "status": "confirmed",
        "obligation_uid": "OBL_confirmed",
    }
    review = {
        "candidate_disposition": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "status": "needs_review",
        "obligation_uid": "OBL_review",
    }
    report = {"issues": [confirmed]}
    apply_report_schema_v2(
        report,
        state={
            "canonical_outcome_projection": True,
            "candidate_terminal_states": [confirmed, review],
        },
        issues=[confirmed],
        observations=[review],
        metadata={"run_id": "RUN"},
        entry_function="entry",
    )

    assert set(report["report_views"]) == {"default", "with_needs_review"}
    assert report["run_manifest"]["report_invariant_status"]["valid"] is True


def test_candidate_envelope_separates_display_id_from_internal_occurrence() -> None:
    first = {
        "id": "ISSUE_1",
        "function": "sink",
        "entry_function": "entry_a",
        "location": r"src\demo.c:10",
        "category": "bounds",
        "source": "len",
        "sink": "buf[len]",
        "validation_status": "validated",
    }
    second = {
        **first,
        "entry_function": "entry_b",
    }

    first_envelope = annotate_issue_identity(
        first,
        project_id="demo",
        revision="abc123",
        run_id="run",
        ordinal=0,
        default_disposition="confirmed",
    )
    second_envelope = annotate_issue_identity(
        second,
        project_id="demo",
        revision="abc123",
        run_id="run",
        ordinal=1,
        default_disposition="confirmed",
    )

    assert first["id"] == second["id"] == "ISSUE_1"
    assert first_envelope.schema_version == CANDIDATE_SCHEMA_VERSION
    assert first["candidate_uid"] == second["candidate_uid"]
    assert first["occurrence_uid"] != second["occurrence_uid"]
    assert first["validation_cluster_uid"] == second["validation_cluster_uid"]
    assert first["context_signature"] != second["context_signature"]
    assert first["run_issue_uid"] != second["run_issue_uid"]


def test_candidate_identity_is_stable_across_checkout_roots_and_path_styles() -> None:
    windows = {
        "location": r"C:\work\demo\src\parser.c:42",
        "function": "parse",
        "category": "bounds",
        "source": {
            "expression": "len",
            "file": r"C:\work\demo\src\parser.c",
            "line": 38,
        },
        "sink": {
            "operation": "memcpy(dst, src, len)",
            "file": r"C:\work\demo\src\parser.c",
            "line": 42,
        },
    }
    linux = {
        **windows,
        "location": "/mnt/build/demo/src/parser.c:42",
        "source": {
            **windows["source"],
            "file": "/mnt/build/demo/src/parser.c",
        },
        "sink": {
            **windows["sink"],
            "file": "/mnt/build/demo/src/parser.c",
        },
    }

    first = annotate_issue_identity(
        windows,
        project_id="demo",
        project_root=r"C:\work\demo",
        revision="abc123",
        entry_function="parse",
    )
    second = annotate_issue_identity(
        linux,
        project_id="demo",
        project_root="/mnt/build/demo",
        revision="abc123",
        entry_function="parse",
    )

    assert first.candidate_uid == second.candidate_uid
    assert first.history_key == second.history_key
    assert windows["location"] != linux["location"]


def test_candidate_identity_is_idempotent_and_independent_of_detector_rule() -> None:
    first = {
        "id": "ISSUE_1",
        "location": "src/parser.c:42",
        "function": "parse",
        "category": "bounds",
        "rule": "regex_copy_rule",
        "source": "len",
        "sink": "memcpy(dst, src, len)",
        "evidence_pack": {
            "source": {"expression": "len", "file": "src/parser.c", "line": 38},
            "sink": {
                "operation": "memcpy(dst, src, len)",
                "file": "src/parser.c",
                "line": 42,
            },
        },
    }
    second = {
        **first,
        "id": "ISSUE_99",
        "rule": "clang_bounds_matcher",
        "evidence_pack": dict(first["evidence_pack"]),
    }

    initial = annotate_issue_identity(
        first,
        project_id="demo",
        project_root=".",
        revision="abc123",
        entry_function="parse",
    )
    first["evidence_pack"].update(
        {
            "candidate_uid": initial.candidate_uid,
            "evidence_hash": initial.evidence_hash,
            "context_signature": initial.context_signature,
        }
    )
    repeated = annotate_issue_identity(
        first,
        project_id="demo",
        project_root=".",
        revision="abc123",
        entry_function="parse",
    )
    alternate_detector = annotate_issue_identity(
        second,
        project_id="demo",
        project_root=".",
        revision="abc123",
        entry_function="parse",
    )

    assert repeated.candidate_uid == initial.candidate_uid
    assert repeated.evidence_hash == initial.evidence_hash
    assert alternate_detector.candidate_uid == initial.candidate_uid
    assert alternate_detector.validation_cluster_uid == initial.validation_cluster_uid
    assert alternate_detector.provenance_hash != initial.provenance_hash


def test_candidate_validation_cluster_separates_decision_constraints() -> None:
    base = {
        "location": "src/parser.c:42",
        "function": "parse",
        "category": "bounds",
        "source": "len",
        "sink": "memcpy(dst, src, len)",
    }
    guarded = annotate_issue_identity(
        {
            **base,
            "path_constraints": ["len <= sizeof(dst)"],
            "negative_evidence": ["guard dominates sink"],
        },
        project_id="demo",
        revision="abc123",
        entry_function="entry_a",
    )
    unguarded = annotate_issue_identity(
        {
            **base,
            "path_constraints": ["len is attacker controlled"],
            "negative_evidence": [],
        },
        project_id="demo",
        revision="abc123",
        entry_function="entry_b",
    )

    assert guarded.candidate_uid == unguarded.candidate_uid
    assert guarded.validation_cluster_uid != unguarded.validation_cluster_uid


def test_report_schema_marks_deferred_candidate_incomplete() -> None:
    report = {}
    observations = [
        {
            "id": "OBS_1",
            "validation_status": "needs_review",
            "candidate_disposition": "deferred_budget",
        }
    ]

    apply_report_schema_v2(
        report,
        state={},
        issues=[],
        observations=observations,
        metadata={"run_id": "RUN", "commit_sha": "abc"},
        entry_function="entry",
    )

    assert report["schema_version"] == 3
    assert report["finding_status"] == "clean"
    assert report["completeness"] == "degraded"
    assert report["scan_outcome"] == "incomplete"
    assert report["run_manifest"]["valid"] is False
    assert exit_code_for_report(report, policy="review") == 2
    assert exit_code_for_report(report, policy="confirmed") == 2


def test_report_schema_exposes_llm_usage_without_product_budget() -> None:
    report = {}
    llm_usage = {
        "consumed_tokens": 1_999_000,
        "usage_attribution": {"totals": {"total_tokens": 1_999_000}},
    }

    apply_report_schema_v2(
        report,
        state={"llm_usage": llm_usage},
        issues=[],
        observations=[],
        metadata={
            "run_id": "RUN",
            "scan_depth": "fast",
            "llm_usage": llm_usage,
        },
        entry_function="entry",
    )

    assert report["completeness"] == "complete"
    assert report["run_manifest"]["scan_depth"] == "fast"
    assert report["run_manifest"]["llm_usage_attribution"]["totals"]["total_tokens"] == 1_999_000
    assert "max_llm_tokens" not in report["run_manifest"]
    assert report["run_manifest"]["llm_usage"]["consumed_tokens"] == 1_999_000


def test_exit_policies_preserve_legacy_and_layered_behavior() -> None:
    needs_review = {"finding_status": "needs_review", "completeness": "complete"}
    confirmed = {"finding_status": "confirmed", "completeness": "complete"}
    clean = {"finding_status": "clean", "completeness": "complete"}

    assert exit_code_for_report(needs_review, policy="review") == 1
    assert exit_code_for_report(needs_review, policy="confirmed") == 0
    assert exit_code_for_report(confirmed, policy="confirmed") == 1
    assert exit_code_for_report(clean, policy="review") == 0
    assert exit_code_for_report(clean, policy="legacy", legacy_issue_count=1) == 1


def test_report_schema_exposes_engine_failure_as_review_terminal() -> None:
    report = {}

    apply_report_schema_v2(
        report,
        state={
            "engine_capabilities": {
                "clang_tooling": {
                    "status": "failed",
                    "reason": "clang timed out",
                }
            }
        },
        issues=[],
        observations=[],
        metadata={"run_id": "RUN"},
        entry_function="entry",
    )

    assert report["finding_status"] == "clean"
    assert report["completeness"] == "degraded"
    assert report["scan_outcome"] == "incomplete"
    assert report["run_manifest"]["needs_review_count"] == 0
    assert report["run_manifest"]["operational_obligation_count"] == 1
    terminal = report["candidate_terminal_states"]
    assert terminal[0]["candidate_disposition"] == "engine_failed"
    assert terminal[0]["engine"] == "clang_tooling"


def test_canonical_projection_counts_review_once_not_as_terminal_duplicate() -> None:
    report = {}
    issue = {
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
    }
    review = {
        "candidate_uid": "CAND_2",
        "validation_cluster_uid": "VAL_2",
        "candidate_disposition": "needs_review",
        "validation_status": "needs_review",
    }

    apply_report_schema_v2(
        report,
        state={
            "canonical_outcome_projection": True,
            "candidate_terminal_states": [issue, review],
        },
        issues=[issue],
        observations=[review],
        metadata={"run_id": "RUN"},
        entry_function="entry",
    )

    assert report["run_manifest"]["needs_review_count"] == 1
    assert report["needs_review_governance"]["by_disposition"] == {"needs_review": 1}
    assert report["run_manifest"]["report_invariant_status"]["valid"] is True


def test_interrupted_engine_marks_whole_report_interrupted() -> None:
    report = {}

    apply_report_schema_v2(
        report,
        state={
            "engine_capabilities": {
                "svf": {
                    "status": "interrupted",
                    "reason": "scan cancelled",
                }
            }
        },
        issues=[],
        observations=[],
        metadata={"run_id": "RUN"},
        entry_function="entry",
    )

    assert report["completeness"] == "interrupted"
    assert report["scan_outcome"] == "incomplete"
    assert exit_code_for_report(report, policy="review") == 2


def test_pending_engine_cannot_produce_complete_clean_report() -> None:
    report = {}

    apply_report_schema_v2(
        report,
        state={
            "engine_capabilities": {
                "index": {
                    "status": "pending",
                    "reason": "index build has not completed",
                }
            }
        },
        issues=[],
        observations=[],
        metadata={"run_id": "RUN"},
        entry_function="entry",
    )

    assert report["finding_status"] == "clean"
    assert report["completeness"] == "degraded"
    assert report["candidate_terminal_states"][0]["engine_status"] == "pending"


def test_terminal_coalescing_preserves_evidence_variants_and_safest_status() -> None:
    base = {
        "candidate_uid": "CAND_1",
        "occurrence_uid": "OCC_1",
        "context_signature": "CTX_1",
    }
    terminals = coalesce_terminal_candidates(
        [
            {
                **base,
                "evidence_hash": "EVIDENCE_A",
                "candidate_disposition": "confirmed",
            },
            {
                **base,
                "evidence_hash": "EVIDENCE_B",
                "candidate_disposition": "deferred_budget",
            },
            {
                **base,
                "evidence_hash": "EVIDENCE_A",
                "candidate_disposition": "engine_failed",
            },
        ]
    )

    assert len(terminals) == 2
    by_evidence = {item["evidence_hash"]: item for item in terminals}
    assert by_evidence["EVIDENCE_A"]["candidate_disposition"] == "engine_failed"
    assert by_evidence["EVIDENCE_A"]["terminal_conflicts"] == [
        "confirmed",
        "engine_failed",
    ]
    assert by_evidence["EVIDENCE_B"]["candidate_disposition"] == "deferred_budget"


def test_shadow_observation_is_a_closed_non_user_visible_terminal() -> None:
    shadow = {
        "candidate_uid": "CAND_SHADOW",
        "occurrence_uid": "OCC_SHADOW",
        "validation_cluster_uid": "VAL_SHADOW",
        "evidence_hash": "EVIDENCE_SHADOW",
        "context_signature": "CTX_SHADOW",
        "candidate_disposition": "shadow_observation",
        "status": "shadow_observation",
        "validation_status": "shadow",
        "rollout_visibility": "shadow",
    }
    report = {"issues": []}

    apply_report_schema_v2(
        report,
        state={
            "canonical_outcome_projection": True,
            "candidate_terminal_states": [shadow],
        },
        issues=[],
        observations=[],
        metadata={"run_id": "RUN", "rollout": {"stage": "semantic_shadow"}},
        entry_function="entry",
    )

    assert report["issues"] == []
    assert report["finding_status"] == "clean"
    assert report["run_manifest"]["needs_review_count"] == 0
    invariant = report["run_manifest"]["report_invariant_status"]
    assert invariant["valid"] is True
    assert invariant["shadow_observation_count"] == 1


def test_report_reuse_requires_complete_compatible_manifest_without_pending_work() -> None:
    authority = build_runtime_authority_manifest(
        source_tree_hash="a" * 40,
        config_sha256="b" * 64,
        backend_sha256="c" * 64,
        revisions={"proof_checker": "proof-checker.v2"},
    )
    reusable = {
        "schema_version": 3,
        "finding_status": "confirmed",
        "completeness": "complete",
        "issues": [
            {
                "candidate_disposition": "confirmed",
                "validation_status": "validated",
            }
        ],
        "candidate_terminal_states": [],
        "run_manifest": {
            "valid": True,
            "schema_version": "zscope.run-manifest.v2",
            "candidate_schema_version": "zscope.candidate.v3.3",
            "cache_epoch": RUNTIME_CACHE_EPOCH,
            "runtime_authority_manifest": authority,
            "runtime_authority_sha256": authority["content_sha256"],
            "decision_trace": {"complete": True},
            "config_hash": "CONFIG",
            "model_manifest_hash": "MODEL",
            "source_revision": "REV",
            "knowledge_db_version": "11",
        },
    }

    assert report_is_reusable(
        reusable,
        expected_manifest={
            "config_hash": "CONFIG",
            "model_manifest_hash": "MODEL",
            "source_revision": "REV",
            "knowledge_db_version": "11",
        },
    )

    incomplete = {
        **reusable,
        "finding_status": "needs_review",
        "candidate_terminal_states": [{"candidate_disposition": "deferred_budget"}],
    }
    blockers = report_reuse_blockers(incomplete)
    assert "finding_needs_review" in blockers
    assert "unresolved_candidate_terminal" in blockers
    assert not report_is_reusable(
        reusable,
        expected_manifest={"config_hash": "DIFFERENT"},
    )

    legacy_candidate_schema = {
        **reusable,
        "run_manifest": {
            **reusable["run_manifest"],
            "candidate_schema_version": "zscope.candidate.v2",
        },
    }
    assert "candidate_schema_mismatch" in report_reuse_blockers(legacy_candidate_schema)

    v32_candidate_schema = {
        **reusable,
        "run_manifest": {
            **reusable["run_manifest"],
            "candidate_schema_version": "zscope.candidate.v3.2",
        },
    }
    assert "candidate_schema_mismatch" in report_reuse_blockers(v32_candidate_schema)
    assert not report_is_reusable(v32_candidate_schema)
