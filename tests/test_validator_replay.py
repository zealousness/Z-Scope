import copy
import json
import os
from pathlib import Path

import pytest

from scripts.run_validator_replay import main as replay_cli_main
from zscope.benchmarking.replay_bundle import (
    ReplayBundleError,
    build_validator_replay_bundle,
    canonical_json_sha256,
    load_validator_replay_bundle,
    validate_validator_replay_bundle,
)
from zscope.benchmarking.validator_replay import (
    ValidatorReplayError,
    _selected_investigation_clusters,
    load_validator_arm_catalog,
    load_validator_replay_run,
    run_validator_replay,
    validate_validator_replay_run,
    validator_arm,
)


IDENTITY = {
    "executor_sha256": "d" * 64,
    "model_spec_sha256": "e" * 64,
    "prompt_sha256": "f" * 64,
}


def _report() -> dict:
    return {
        "run_manifest": {
            "source_tree_hash": "a" * 64,
            "config_hash": "b" * 64,
            "effective_rules_sha256": "c" * 64,
            "candidate_schema_version": "zscope.candidate.v3.3",
            "knowledge_db_version": "14",
        },
        "candidate_terminal_states": [
            {
                "validation_cluster_uid": "VAL-1",
                "candidate_uid": "CAND-2",
                "occurrence_uids": ["OCC-2"],
                "entries": ["entry_b"],
                "terminal_disposition": "confirmed",
                "issue": {
                    "candidate_uid": "CAND-2",
                    "category": "buffer_overflow",
                    "function": "sink",
                    "location": "src/demo.c:12",
                    "description": "unchecked length reaches copy",
                    "evidence_pack": {
                        "positive_evidence": ["entry_b reaches sink"],
                        "decision_facts": [
                            {
                                "fact_uid": "FACT_BASE",
                                "kind": "caller_contract",
                                "summary": "entry reaches sink",
                            }
                        ],
                    },
                },
            },
            {
                "validation_cluster_uid": "VAL-1",
                "candidate_uid": "CAND-1",
                "occurrence_uids": ["OCC-1"],
                "entries": ["entry_a"],
                "validation_status": "rejected",
                "issue": {
                    "candidate_uid": "CAND-1",
                    "category": "buffer_overflow",
                    "severity": "high",
                    "risk_score": 80,
                    "externally_reachable": True,
                    "function": "sink",
                    "location": "src/demo.c:12",
                    "description": "unchecked length reaches copy",
                    "evidence_pack": {
                        "negative_evidence": ["no dominating range guard"],
                        "frozen_fact_catalog": [
                            {
                                "fact_uid": "FACT_REACH",
                                "fact_kind": "source_sink_reachability",
                                "summary": "source reaches sink",
                            },
                            {
                                "fact_uid": "FACT_OWNERSHIP",
                                "fact_kind": "ownership_transfer",
                                "summary": "callee retains the resource",
                            },
                        ],
                    },
                },
            },
        ],
    }


def _result(call, *, verdict="verified", request=None, refs=(), stop="decision_complete"):
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": call.candidate_uid,
        "validation_cluster_uid": call.validation_cluster_uid,
        "pass": call.validation_pass,
        "verdict": verdict,
        "reasoning": "The frozen evidence supports this bounded decision.",
        "positive_evidence": ["frozen evidence reviewed"],
        "negative_evidence": [],
        "evidence_refs": list(refs),
        "blocking_negative_evidence": False,
        "missing_fact_request": request,
        "stop_reason": stop,
    }


def _response(call, result, *, usage=None):
    return {
        "result": result,
        "usage": usage
        or {
            "prompt_tokens": 100,
            "cached_prompt_tokens": 10,
            "completion_tokens": 20,
            "reasoning_tokens": 5,
            "total_tokens": 120,
            "tool_call_count": 0,
            "api_attempt_count": 1,
            "provider_reported": True,
        },
        "execution_identity": dict(IDENTITY),
    }


def test_bundle_unions_alias_evidence_facts_and_occurrences_order_independently() -> None:
    report = _report()
    bundle = build_validator_replay_bundle(report)
    reversed_report = copy.deepcopy(report)
    reversed_report["candidate_terminal_states"].reverse()

    assert (
        build_validator_replay_bundle(reversed_report)["bundle_sha256"] == bundle["bundle_sha256"]
    )
    group = bundle["canonical_groups"][0]
    assert group["candidate_uid"] == "CAND-1"
    assert group["candidate_uids"] == ["CAND-1", "CAND-2"]
    assert group["occurrence_uids"] == ["OCC-1", "OCC-2"]
    assert group["entries"] == ["entry_a", "entry_b", "sink"]
    assert group["evidence"]["positive_evidence"] == ["entry_b reaches sink"]
    assert group["evidence"]["negative_evidence"] == ["no dominating range guard"]
    assert group["facts"]["decision_facts"][0]["fact_uid"] == "FACT_BASE"
    assert {fact["fact_uid"] for fact in group["facts"]["frozen_fact_catalog"]} == {
        "FACT_REACH",
        "FACT_OWNERSHIP",
    }
    assert "frozen_fact_catalog" not in group["evidence"]
    assert bundle["contract"]["fact_partition"]["initial_keys"] == [
        "facts",
        "decision_facts",
        "decision_fact_graph",
        "fact_graph",
    ]
    assert group["hashes"]["evidence_sha256"] == canonical_json_sha256(group["evidence"])
    assert group["hashes"]["facts_sha256"] == canonical_json_sha256(group["facts"])


def test_bundle_binds_review_memory_projection_into_group_hashes() -> None:
    review_memory = {
        "schema_version": "zscope.validator-review-memory.v1",
        "authority": "advisory",
        "hints": [{
            "pattern_id": "pattern_1",
            "summary": "recheck current guard",
            "match_basis": ["cfg"],
            "required_checks": ["recheck CFG"],
            "counter_conditions": ["guard absent"],
            "evidence_refs": ["e1"],
        }],
        "selection": {"candidate_count": 1, "selected_count": 1, "omitted_count": 0, "token_budget": 1200},
    }
    bundle = build_validator_replay_bundle(_report(), review_memory=review_memory)
    assert bundle["review_memory"] == review_memory
    assert bundle["canonical_groups"][0]["review_memory"] == review_memory
    assert bundle["bundle_sha256"]
    validate_validator_replay_bundle(bundle)
    changed = copy.deepcopy(review_memory)
    changed["hints"][0]["pattern_id"] = "pattern_2"
    changed_bundle = build_validator_replay_bundle(_report(), review_memory=changed)
    assert changed_bundle["bundle_sha256"] != bundle["bundle_sha256"]


def test_validator_replay_input_projects_hashed_review_memory_advisory() -> None:
    from zscope.benchmarking.validator_replay import _group_to_validator_input

    review_memory = {"authority": "advisory", "hints": [{"pattern_id": "p1"}]}
    bundle = build_validator_replay_bundle(_report(), review_memory=review_memory)
    validator_input = _group_to_validator_input(
        bundle["canonical_groups"][0], validation_pass="initial"
    )
    assert validator_input["evidence_slice"]["review_memory"] == review_memory


def test_bundle_merges_stale_clusters_connected_by_candidate_or_occurrence() -> None:
    report = _report()
    duplicate = copy.deepcopy(report["candidate_terminal_states"][0])
    duplicate["validation_cluster_uid"] = "VAL-STALE"
    duplicate["occurrence_uids"] = ["OCC-ALIAS"]
    duplicate["issue"]["occurrence_uid"] = "OCC-1"
    report["candidate_terminal_states"].append(duplicate)

    bundle = build_validator_replay_bundle(report)

    assert bundle["group_count"] == 1
    assert bundle["canonical_groups"][0]["validation_cluster_uid"] == "VAL-1"
    assert bundle["canonical_groups"][0]["occurrence_uids"] == [
        "OCC-1",
        "OCC-2",
        "OCC-ALIAS",
    ]


def test_bundle_excludes_operational_obligations_without_candidate_evidence() -> None:
    report = _report()
    report["candidate_terminal_states"].insert(
        0,
        {
            "candidate_uid": "ENGINE-1",
            "occurrence_uid": "ENGINE-OCC-1",
            "record_role": "operational_obligation",
            "candidate_disposition": "engine_failed",
            "status": "engine_failed",
            "engine": "active_discovery",
            "engine_status": "partial",
        },
    )

    bundle = build_validator_replay_bundle(report)

    assert bundle["group_count"] == 1
    assert bundle["canonical_groups"][0]["candidate_uid"] == "CAND-1"


def test_bundle_requires_replay_identity_content_hashes_and_external_expected_hash() -> None:
    with pytest.raises(ReplayBundleError, match="source identity"):
        build_validator_replay_bundle(
            {"candidate_terminal_states": _report()["candidate_terminal_states"]}
        )


def test_bundle_fails_closed_when_initial_and_reservoir_facts_overlap() -> None:
    report = _report()
    reservoir = report["candidate_terminal_states"][1]["issue"]["evidence_pack"][
        "frozen_fact_catalog"
    ]
    report["candidate_terminal_states"][0]["issue"]["evidence_pack"]["decision_facts"] = [
        copy.deepcopy(reservoir[0])
    ]

    with pytest.raises(ReplayBundleError, match="both initial evidence and the frozen reservoir"):
        build_validator_replay_bundle(report)

    bundle = build_validator_replay_bundle(_report())
    bundle["canonical_groups"][0]["candidate_uid"] = "CAND-X"
    with pytest.raises(ReplayBundleError, match="candidate identities"):
        validate_validator_replay_bundle(bundle)

    valid = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    with pytest.raises(ValidatorReplayError, match="externally expected"):
        run_validator_replay(
            valid,
            validator_arm(catalog, "A"),
            executor=lambda call: _response(call, _result(call)),
            execution_identity=IDENTITY,
            expected_bundle_sha256="0" * 64,
            arm_catalog_sha256=catalog["catalog_sha256"],
        )


def test_replay_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text('{"schema_version":"one","schema_version":"two"}\n', encoding="utf-8")
    with pytest.raises(ReplayBundleError, match="duplicate JSON key"):
        load_validator_replay_bundle(path)


def test_arm_catalog_defines_hash_bound_a_through_e() -> None:
    catalog = load_validator_arm_catalog()
    assert [row["arm_id"] for row in catalog["arms"]] == list("ABCDE")
    assert catalog["arms"][0]["baseline"] is True
    assert catalog["arms"][2]["decision_policy"]["fact_recheck_enabled"] is True
    assert catalog["arms"][3]["decision_policy"]["investigation_trajectories"] == 1
    arm_e = catalog["arms"][4]
    assert arm_e["protocol_mode"] == "legacy_multi_turn_upper_bound"
    assert arm_e["decision_policy"]["investigation_trajectories"] == 0
    assert (
        arm_e["decision_policy"]["executor_usage_scope"]
        == "aggregate_all_http_attempts_in_legacy_session"
    )
    assert arm_e["limits"]["max_calls_per_group"] == 1
    assert arm_e["limits"]["expected_group_tokens"] == 17_000_000


def test_arm_c_uses_only_frozen_fact_delta_and_conserves_usage() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    calls = []

    def executor(call):
        calls.append(call)
        serialized = json.dumps(call.as_dict(), sort_keys=True)
        assert "ground_truth" not in serialized
        assert call.limits["tool_source"] == "frozen_replay_bundle_only"
        if call.validation_pass == "initial":
            assert "FACT_REACH" not in serialized
            assert "FACT_BASE" in serialized
            assert "frozen_fact_catalog" not in serialized
            assert "decision_facts" in serialized
            return _response(
                call,
                _result(
                    call,
                    verdict="uncertain",
                    request={
                        "fact_kind": "source_sink_reachability",
                        "reason": "reachability is required",
                    },
                    stop="missing_fact",
                ),
            )
        assert call.validation_pass == "evidence_recheck"
        assert "FACT_REACH" in call.validator_input["evidence_slice"]["evidence_ref_catalog"]
        return _response(call, _result(call, refs=("FACT_REACH",)))

    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "C"),
        executor=executor,
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        trial_index=2,
    )

    assert [call.validation_pass for call in calls] == ["initial", "evidence_recheck"]
    assert result["complete"] is True
    assert result["usage"]["call_count"] == 2
    assert result["usage"]["total_tokens"] == 240
    assert result["groups"][0]["terminal_result"]["verdict"] == "verified"
    assert result["contract"]["truth_scoring"] == "independent_after_replay"


def test_fact_resolution_without_new_frozen_delta_stops_without_v2_or_repair() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    calls = []

    def executor(call):
        calls.append(call)
        return _response(
            call,
            _result(
                call,
                verdict="uncertain",
                request={
                    "fact_kind": "caller_contract",
                    "reason": "requesting the already-visible caller contract must not create V2",
                },
                stop="missing_fact",
            ),
        )

    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "C"),
        executor=executor,
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
    )

    assert [call.call_kind for call in calls] == ["direct"]
    assert result["groups"][0]["terminal_result"]["stop_reason"] == "no_evidence_gain"
    assert result["groups"][0]["protocol_valid"] is True


def test_arm_b_repair_and_arm_d_investigation_are_bounded() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    seen_b = []

    def executor_b(call):
        seen_b.append(call.call_kind)
        result = {"malformed": True} if call.call_kind == "direct" else _result(call)
        return _response(call, result)

    repaired = run_validator_replay(
        bundle,
        validator_arm(catalog, "B"),
        executor=executor_b,
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
    )
    assert seen_b == ["direct", "format_repair"]
    assert repaired["complete"] is True
    assert repaired["groups"][0]["protocol_valid"] is True
    assert repaired["groups"][0]["protocol_errors"] == []
    assert repaired["groups"][0]["calls"][0]["protocol_errors"] == [
        "executor result violates ValidatorResult v3"
    ]

    seen_d = []
    investigation_turn = 0

    def executor_d(call):
        nonlocal investigation_turn
        seen_d.append(call.call_kind)
        if call.validation_pass == "initial":
            value = _result(
                call,
                verdict="uncertain",
                request={
                    "fact_kind": "source_sink_reachability",
                    "reason": "reachability is required",
                },
                stop="missing_fact",
            )
        elif call.validation_pass == "evidence_recheck":
            value = _result(call, verdict="uncertain", stop="no_evidence_gain")
        else:
            assert call.limits["investigation_trajectories"] == 1
            assert call.limits["max_tool_queries_per_trajectory"] == 2
            investigation_turn += 1
            if investigation_turn == 1:
                value = {
                    "schema_version": "zscope.validator-replay-action.v1",
                    "action": "query",
                    "query": {
                        "schema_version": "zscope.validator-replay-query.v1",
                        "query_kind": "fact_by_uid",
                        "key": "FACT_OWNERSHIP",
                        "reason": "resolve the remaining ownership question",
                    },
                    "result": None,
                }
            else:
                value = {
                    "schema_version": "zscope.validator-replay-action.v1",
                    "action": "terminal",
                    "query": None,
                    "result": _result(call),
                }
        return _response(call, value)

    investigated = run_validator_replay(
        bundle,
        validator_arm(catalog, "D"),
        executor=executor_d,
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
    )
    assert seen_d == [
        "direct",
        "fact_recheck",
        "bounded_investigation_turn",
        "bounded_investigation_turn",
    ]
    assert investigated["complete"] is True


def test_arm_e_delegates_one_legacy_session_and_accepts_aggregate_usage() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    calls = []

    def executor(call):
        calls.append(call)
        assert call.protocol_mode == "legacy_multi_turn_upper_bound"
        assert call.call_kind == "legacy_multi_turn_session"
        assert call.validation_pass == "initial"
        assert "requires_per_http_attempt_budget_admission" not in call.limits
        assert call.limits["legacy_session_expected_tokens"] == 17_000_000
        return _response(
            call,
            _result(call),
            usage={
                "prompt_tokens": 24_000,
                "cached_prompt_tokens": 4_000,
                "completion_tokens": 9_000,
                "reasoning_tokens": 3_000,
                "total_tokens": 33_000,
                "tool_call_count": 7,
                "api_attempt_count": 3,
                "provider_reported": True,
            },
        )

    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "E"),
        executor=executor,
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        expected_total_tokens=17_000_000,
    )

    assert len(calls) == 1
    assert result["complete"] is True
    assert result["groups"][0]["usage"]["call_count"] == 1
    assert result["groups"][0]["usage"]["api_attempt_count"] == 3
    assert result["usage"]["total_tokens"] == 33_000
    assert (
        result["contract"]["executor_invocation_scope"]
        == "one_complete_legacy_multi_turn_session_per_validation_cluster"
    )
    assert (
        result["contract"]["executor_usage_scope"]
        == "aggregate_all_http_attempts_in_legacy_session"
    )


def test_arm_e_cost_expectation_never_gates_execution() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    arm_e = validator_arm(catalog, "E")

    for expectation in (None, 17_000_001):
        result = run_validator_replay(
            bundle,
            arm_e,
            executor=lambda call: _response(call, _result(call)),
            execution_identity=IDENTITY,
            expected_bundle_sha256=bundle["bundle_sha256"],
            arm_catalog_sha256=catalog["catalog_sha256"],
            expected_total_tokens=expectation,
        )
        assert result["complete"] is True


def test_balanced_and_deep_investigation_gate_apply_risk_reachability_and_top_fraction() -> None:
    groups = []
    for index in range(40):
        groups.append(
            {
                "validation_cluster_uid": f"VAL-{index:02d}",
                "candidate": {
                    "severity": "critical" if index == 0 else "high",
                    "risk_score": 100 - index,
                    "externally_reachable": index != 1,
                },
                "evidence": {},
            }
        )
    catalog = load_validator_arm_catalog()
    balanced = validator_arm(catalog, "D")["decision_policy"]
    assert _selected_investigation_clusters(groups, balanced) == {"VAL-00", "VAL-02"}

    deep = dict(balanced)
    deep.update(
        {
            "investigation_depth": "deep",
            "investigation_risk_threshold": 60,
            "investigation_max_cluster_percent": 20,
            "investigation_trajectories": 2,
            "max_tool_queries_per_trajectory": 3,
        }
    )
    selected = _selected_investigation_clusters(groups, deep)
    assert len(selected) == 8
    assert "VAL-01" not in selected
    assert "VAL-00" in selected


def test_unknown_attempt_usage_is_measured_without_blocking_repair() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    arm = validator_arm(catalog, "B")

    preliminary = run_validator_replay(
        bundle,
        arm,
        executor=lambda _call: (_ for _ in ()).throw(ConnectionError("interrupted")),
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        expected_total_tokens=2_000_000,
    )
    reservation = preliminary["groups"][0]["calls"][0]["usage"]["total_tokens"]
    attempts = []

    result = run_validator_replay(
        bundle,
        arm,
        executor=lambda call: attempts.append(call)
        or (_ for _ in ()).throw(ConnectionError("interrupted")),
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        expected_total_tokens=reservation,
    )

    assert len(attempts) == 2
    usage = result["groups"][0]["calls"][0]["usage"]
    assert usage["total_tokens"] == reservation > 0
    assert usage["api_attempt_count"] == 1
    assert usage["provider_reported"] is False
    assert result["cost_expectation_met"] is False
    assert result["complete"] is False


def test_missing_usage_object_is_measured_and_format_repair_still_runs() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    arm = validator_arm(catalog, "B")

    def missing_usage(call):
        return {
            "result": {"malformed": True},
            "usage": {},
            "execution_identity": dict(IDENTITY),
        }

    preliminary = run_validator_replay(
        bundle,
        arm,
        executor=missing_usage,
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        expected_total_tokens=2_000_000,
    )
    reservation = preliminary["groups"][0]["calls"][0]["usage"]["total_tokens"]
    attempts = []

    result = run_validator_replay(
        bundle,
        arm,
        executor=lambda call: attempts.append(call) or missing_usage(call),
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        expected_total_tokens=reservation,
    )

    assert len(attempts) == 2
    call = result["groups"][0]["calls"][0]
    assert call["usage"]["total_tokens"] == reservation
    assert call["usage"]["provider_reported"] is False
    assert "unknown provider usage forfeited full reservation" in call["protocol_errors"]
    assert result["cost_expectation_met"] is False


def test_executor_trust_is_hash_bound_and_untrusted_runs_are_non_formal() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "A"),
        executor=lambda call: _response(call, _result(call)),
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
    )
    assert result["contract"]["executor_formal_eligible"] is False
    assert result["contract"]["executor_trust_mode"] == "untrusted_external"

    with pytest.raises(ValidatorReplayError, match="OCI evidence"):
        run_validator_replay(
            bundle,
            validator_arm(catalog, "A"),
            executor=lambda call: _response(call, _result(call)),
            execution_identity=IDENTITY,
            expected_bundle_sha256=bundle["bundle_sha256"],
            arm_catalog_sha256=catalog["catalog_sha256"],
            executor_trust={
                "mode": "trusted_oci_external",
                "oci_evidence_sha256": "not-a-hash",
            },
        )


def test_arm_e_legacy_budget_stop_is_not_treated_as_product_budget() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()

    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "E"),
        executor=lambda call: _response(
            call,
            _result(call, verdict="uncertain", stop="budget_exhausted"),
        ),
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        expected_total_tokens=2_000_000,
    )

    assert result["complete"] is False
    assert result["cost_expectation_met"] is True
    assert result["groups"][0]["execution_status"] == "invalid"


def test_cli_writes_truth_free_arm_ledger_with_injected_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_validator_replay_bundle(_report())
    bundle_path = tmp_path / "validator-replay-bundle.json"
    output = tmp_path / "arm-a-run.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    for key in list(os.environ):
        if "GROUND_TRUTH" in key.upper() or "BENCHMARK_TRUTH" in key.upper():
            monkeypatch.delenv(key, raising=False)

    code = replay_cli_main(
        [
            "--bundle",
            str(bundle_path),
            "--expected-bundle-sha256",
            bundle["bundle_sha256"],
            "--arm",
            "A",
            "--executor-sha256",
            IDENTITY["executor_sha256"],
            "--model-spec-sha256",
            IDENTITY["model_spec_sha256"],
            "--prompt-sha256",
            IDENTITY["prompt_sha256"],
            "--expected-total-tokens",
            "2000000",
            "--output",
            str(output),
        ],
        executor=lambda call: _response(call, _result(call)),
    )

    ledger = load_validator_replay_run(output)
    assert code == 0
    assert ledger["schema_version"] == "zscope.validator-replay-run.v1"
    assert ledger["answer_material_present"] is False
    assert ledger["bundle_sha256"] == bundle["bundle_sha256"]
    assert ledger["expected_total_tokens"] == 2_000_000
    assert ledger["cost_expectation_met"] is True
    serialized = json.dumps(ledger).lower()
    assert "ground_truth" not in serialized
    assert "matched_truth" not in serialized
    assert "oracle" not in serialized


def test_replay_run_validator_rejects_usage_tampering() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "A"),
        executor=lambda call: _response(call, _result(call)),
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
    )
    result["groups"][0]["usage"]["total_tokens"] += 1
    with pytest.raises(ValidatorReplayError, match="hash mismatch|group usage"):
        validate_validator_replay_run(result)


def test_replay_cost_expectation_does_not_stop_http_attempt() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()
    calls = []

    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "A"),
        executor=lambda call: calls.append(call) or _response(call, _result(call)),
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
        expected_total_tokens=1,
    )

    assert len(calls) == 1
    assert result["complete"] is True
    assert result["cost_expectation_met"] is False
    assert result["planned_group_count"] == 1
    assert result["groups"][0]["execution_status"] == "complete"
    assert result["usage"]["total_tokens"] > 1


def test_executor_cannot_mutate_the_frozen_call_contract() -> None:
    bundle = build_validator_replay_bundle(_report())
    catalog = load_validator_arm_catalog()

    def mutating_executor(call):
        call.validator_input["candidate_uid"] = "CAND-MUTATED"
        return _response(call, _result(call))

    result = run_validator_replay(
        bundle,
        validator_arm(catalog, "A"),
        executor=mutating_executor,
        execution_identity=IDENTITY,
        expected_bundle_sha256=bundle["bundle_sha256"],
        arm_catalog_sha256=catalog["catalog_sha256"],
    )
    assert result["complete"] is False
    assert "executor mutated the replay call input" in result["groups"][0]["protocol_errors"]
    assert "executor mutated the replay call contract" in result["groups"][0]["protocol_errors"]
