from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.alerts.verifier import AlertVerifier
from zscope.semantics.security_specs.archive import (
    archive_from_json_bytes,
    archive_from_xlsx,
    archive_to_json_bytes,
    archive_to_xlsx,
    build_archive,
    validate_archive,
)
from zscope.semantics.security_specs.canonical import content_sha256
from zscope.semantics.security_specs.compiler import SecuritySpecCompiler
from zscope.semantics.security_specs.miner import SecuritySpecMiner, SecuritySpecProposalEngine
from zscope.semantics.security_specs.models import (
    build_qualification,
    build_review_event,
    build_security_spec,
    transition_allowed,
    validate_qualification,
    validate_security_spec,
)
from zscope.semantics.security_specs.registry import PREDICATE_REGISTRY, validate_parameters
from zscope.semantics.security_specs.qualification import load_builtin_qualification
from zscope.semantics.security_specs.shadow import SecuritySpecShadowRuntime
from zscope.semantics.security_specs.store import SecuritySpecStore


HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def _qualification() -> dict:
    return build_qualification(
        registry_sha256=HASH_A,
        compiler_sha256=HASH_B,
        corpus_sha256=HASH_C,
        qualified_predicates=sorted(PREDICATE_REGISTRY),
        source_projects=["callback-service", "procedural-runtime", "raii-library"],
        metrics={
            "case_count": 120,
            "key_contract_recall": 0.9,
            "positive_unsupported_rate": 0.0,
            "safe_false_activation_count": 0,
            "evidence_resolution_rate": 1.0,
            "second_scan_llm_reduction": 1.0,
        },
        environment={"network": False, "llm": "counting-fake"},
    )


def _spec(
    *,
    predicate: str = "source",
    parameters: dict | None = None,
    status: str = "verified_scoped",
    qualification_ref: str = "",
    origin: str = "program",
    scope: dict | None = None,
    spec_uid: str = "",
    revision: int = 1,
    conflicts: tuple[str, ...] = (),
) -> dict:
    parameters = parameters or {"source_slot": "parameter:0", "label": "untrusted"}
    slots = sorted(
        {
            str(value)
            for key, raw in parameters.items()
            if key.endswith("slot") or key.endswith("slots")
            for value in (raw if isinstance(raw, list) else [raw])
        }
    )
    return build_security_spec(
        subject={
            "language": "c_cpp",
            "function_uid": "src/api.c::handle",
            "signature": "int handle(char *data)",
            "slot_uids": slots,
        },
        scope=scope or {"kind": "function", "target": "src/api.c::handle"},
        predicate=predicate,
        parameters=parameters,
        evidence_refs=["evidence:src/api.c:10"],
        dependency_hashes=[HASH_A, HASH_B],
        origin=origin,
        confidence=0.95,
        status=status,
        qualification_ref=qualification_ref,
        explanation="Exact API contract with source evidence.",
        impact_preview=["src/api.c::handle"],
        spec_uid=spec_uid,
        revision=revision,
        conflicts=conflicts,
    )


def test_registry_freezes_all_thirteen_operations() -> None:
    assert set(PREDICATE_REGISTRY) == {
        "source",
        "sink",
        "propagate",
        "sanitize",
        "acquire",
        "release",
        "transfer",
        "lock",
        "unlock",
        "state_transition",
        "sentinel",
        "callback_retains",
        "caller_contract",
    }
    assert validate_parameters("source", {"source_slot": "parameter:0", "label": "untrusted"}) == (
        True,
        "ok",
    )
    assert validate_parameters("source", {"query": "arbitrary()"})[0] is False


def test_security_spec_is_strict_and_content_addressed() -> None:
    spec = _spec()
    assert validate_security_spec(spec) == (True, "ok")
    tampered = copy.deepcopy(spec)
    tampered["parameters"]["label"] = "secret"
    assert validate_security_spec(tampered)[1] == "content_sha256_mismatch"
    unknown = {**spec, "query": "MATCH arbitrary"}
    assert validate_security_spec(unknown)[1] == "security_spec_schema_keys_mismatch"


def test_llm_may_only_propose() -> None:
    with pytest.raises(ValueError, match="llm_spec_cannot_activate"):
        _spec(origin="llm", status="verified_scoped")
    proposal = _spec(origin="llm", status="proposed")
    assert validate_security_spec(proposal) == (True, "ok")


def test_state_machine_is_finite() -> None:
    assert transition_allowed("proposed", "verified_scoped")
    assert transition_allowed("stable", "quarantined")
    assert not transition_allowed("stable", "proposed")
    assert not transition_allowed("rejected", "stable")


def test_qualification_requires_thresholds_and_three_projects() -> None:
    qualification = _qualification()
    assert validate_qualification(qualification) == (True, "ok")
    tampered = copy.deepcopy(qualification)
    tampered["metrics"]["safe_false_activation_count"] = 1
    assert validate_qualification(tampered)[1] == "content_sha256_mismatch"


def test_compiler_accepts_only_resolved_qualification_backed_stable_specs() -> None:
    qualification = _qualification()
    stable = _spec(status="stable", qualification_ref=qualification["content_sha256"])
    proposed = _spec(origin="llm", status="proposed")
    result = SecuritySpecCompiler().compile(
        [stable, proposed],
        qualification_hashes=[qualification["content_sha256"]],
        resolvable_evidence_refs=stable["evidence_refs"],
        current_dependency_hashes=[HASH_A, HASH_B],
    )
    assert result["mode"] == "shadow"
    assert [value["spec_uid"] for value in result["compiled_specs"]] == [stable["spec_uid"]]
    assert {value["reason"] for value in result["excluded_specs"]} == {
        "not_qualification_backed_stable"
    }


def test_compiler_fails_closed_on_stale_evidence_dependency_and_conflict() -> None:
    qualification = _qualification()
    qualification_hash = qualification["content_sha256"]
    left = _spec(status="stable", qualification_ref=qualification_hash)
    right = _spec(
        parameters={"source_slot": "parameter:0", "label": "secret"},
        status="stable",
        qualification_ref=qualification_hash,
        spec_uid="SPEC_" + "d" * 32,
    )
    result = SecuritySpecCompiler().compile(
        [left, right],
        qualification_hashes=[qualification_hash],
        resolvable_evidence_refs=left["evidence_refs"],
        current_dependency_hashes=[HASH_A],
    )
    assert result["compiled_specs"] == []
    assert {value["reason"] for value in result["excluded_specs"]} == {"dependency_stale"}
    result = SecuritySpecCompiler().compile(
        [left, right],
        qualification_hashes=[qualification_hash],
        resolvable_evidence_refs=left["evidence_refs"],
        current_dependency_hashes=[HASH_A, HASH_B],
    )
    assert result["compiled_specs"] == []
    assert result["conflict_spec_uids"] == sorted([left["spec_uid"], right["spec_uid"]])


def test_scope_narrowing_reports_exact_footprint() -> None:
    before = _spec(scope={"kind": "module", "target": "src"})
    after = _spec(
        scope={"kind": "function", "target": "src/api.c::handle"},
        spec_uid=before["spec_uid"],
        revision=2,
    )
    impact = SecuritySpecCompiler.impact_preview(
        before, after, dependents=["src/dependent.c::call"]
    )
    assert impact == {
        "invalidated": ["module:src", "src/dependent.c::call"],
        "added": ["function:src/api.c::handle"],
        "retained": ["src/api.c::handle"],
    }


def test_store_enforces_immutable_revisions_dependencies_and_review_chain(tmp_path: Path) -> None:
    store = SecuritySpecStore(tmp_path / "spec-store")
    qualification = _qualification()
    store.put_qualification(qualification)
    spec = _spec()
    reference = store.put_spec(
        spec,
        call_dependents=[("src/api.c::handle", "src/router.c::dispatch")],
    )
    assert store.cas.verify_ref(reference)
    assert store.get_spec(spec["spec_uid"]) == spec
    assert store.affected_spec_uids([HASH_A]) == {spec["spec_uid"]}
    assert store.affected_spec_uids_for_footprints([("function", "src/api.c::handle")]) == {
        spec["spec_uid"]
    }
    assert store.invalidation_impact([HASH_A]) == {
        "spec_uids": [spec["spec_uid"]],
        "function_uids": ["src/api.c::handle"],
        "dependent_function_uids": ["src/router.c::dispatch"],
    }
    mutated = _spec(
        parameters={"source_slot": "parameter:0", "label": "secret"},
        spec_uid=spec["spec_uid"],
    )
    with pytest.raises(ValueError, match="revision_is_immutable"):
        store.put_spec(mutated)
    invalid_transition = _spec(
        spec_uid=spec["spec_uid"],
        revision=2,
        status="observation",
    )
    with pytest.raises(ValueError, match="state_transition_not_allowed"):
        store.put_spec(invalid_transition)
    event = build_review_event(
        spec_uid=spec["spec_uid"],
        spec_revision=1,
        reviewer_identity="reviewer@example.invalid",
        reviewed_at="2026-08-18T00:00:00Z",
        reason="Scoped review",
        action="defer",
        before_spec_sha256=spec["content_sha256"],
        after_spec_sha256=spec["content_sha256"],
        scope_override={},
        dependency_impact=[],
        previous_event_sha256="0" * 64,
    )
    assert store.cas.verify_ref(store.put_review_event(event))
    bad_chain = build_review_event(
        spec_uid=spec["spec_uid"],
        spec_revision=1,
        reviewer_identity="reviewer@example.invalid",
        reviewed_at="2026-08-18T00:01:00Z",
        reason="Still deferred",
        action="defer",
        before_spec_sha256=spec["content_sha256"],
        after_spec_sha256=spec["content_sha256"],
        scope_override={},
        dependency_impact=[],
        previous_event_sha256="0" * 64,
    )
    with pytest.raises(ValueError, match="review_event_chain_mismatch"):
        store.put_review_event(bad_chain)


def test_proposal_engine_is_bounded_and_second_scan_has_zero_calls(tmp_path: Path) -> None:
    calls = []
    proposal = _spec(origin="llm", status="proposed")

    def propose(request: dict) -> dict:
        calls.append(request)
        return {"proposal_ids": [request["allowed_proposals"][0]["proposal_id"]]}

    engine = SecuritySpecProposalEngine(tmp_path, propose, model_profile_hash=HASH_A)
    kwargs = {
        "unit_id": "UNIT_1",
        "unit_fingerprint": HASH_B,
        "allowed_subjects": [proposal["subject"]],
        "allowed_scopes": [proposal["scope"]],
        "allowed_evidence_refs": proposal["evidence_refs"],
        "dependency_hashes": proposal["dependency_hashes"],
        "allowed_proposals": [proposal],
    }
    first = engine.propose(**kwargs)
    second = engine.propose(**kwargs)
    assert first == second
    assert engine.llm_call_count == 1
    assert len(calls) == 1
    assert "candidate" not in str(calls[0]).lower()


def test_proposal_engine_rejects_unprovided_evidence(tmp_path: Path) -> None:
    proposal = _spec(origin="llm", status="proposed")
    engine = SecuritySpecProposalEngine(
        tmp_path, lambda _request: {"proposal_ids": []}, model_profile_hash=HASH_A
    )
    with pytest.raises(ValueError, match="evidence_not_allowed"):
        engine.propose(
            unit_id="UNIT_1",
            unit_fingerprint=HASH_B,
            allowed_subjects=[proposal["subject"]],
            allowed_scopes=[proposal["scope"]],
            allowed_evidence_refs=["evidence:different"],
            dependency_hashes=proposal["dependency_hashes"],
            allowed_proposals=[proposal],
        )


def test_proposal_engine_rejects_model_invented_proposal_id(tmp_path: Path) -> None:
    proposal = _spec(origin="llm", status="proposed")
    engine = SecuritySpecProposalEngine(
        tmp_path,
        lambda _request: {"proposal_ids": ["SPECPROP_" + "f" * 32]},
        model_profile_hash=HASH_A,
    )
    with pytest.raises(ValueError, match="selected_unknown_proposal_id"):
        engine.propose(
            unit_id="UNIT_1",
            unit_fingerprint=HASH_B,
            allowed_subjects=[proposal["subject"]],
            allowed_scopes=[proposal["scope"]],
            allowed_evidence_refs=proposal["evidence_refs"],
            dependency_hashes=proposal["dependency_hashes"],
            allowed_proposals=[proposal],
        )


def test_shadow_runtime_compiles_only_qualification_backed_stable_specs(
    tmp_path: Path,
) -> None:
    qualification = _qualification()
    stable = _spec(status="stable", qualification_ref=qualification["content_sha256"])
    store = SecuritySpecStore(tmp_path / "shadow")
    store.put_qualification(qualification)

    result = SecuritySpecShadowRuntime(store).run(
        SimpleNamespace(language="c_cpp", functions=(), claims=()),
        qualification_hashes=[qualification["content_sha256"]],
        resolvable_evidence_refs=stable["evidence_refs"],
        current_dependency_hashes=stable["dependency_hashes"],
        additional_specs=[stable],
    )

    assert result["security_spec_mode"] == "shadow"
    assert result["active_product_effect"] == "none"
    assert result["compiled_spec_count"] == 1
    assert store.cas.verify_ref(result["artifact_refs"][-1])
    assert (store.root / "security_spec_manifest.json").is_file()

    verifier = object.__new__(AlertVerifier)
    verifier.config = SimpleNamespace(analysis=SimpleNamespace(snapshot_dir=str(tmp_path)))
    # The alert path uses the same snapshot/security_specs location as scans.
    store.root.rename(tmp_path / "security_specs")
    identity = verifier._security_spec_shadow_identity()
    assert identity["security_spec_root_manifest_sha256"] == result["root_manifest_sha256"]
    assert identity["security_spec_shadow_decision"]["compiled_spec_count"] == 1
    assert identity["security_spec_shadow_decision"]["active_product_effect"] == "none"


def test_builtin_qualification_promotes_exact_program_fact_only_in_shadow(
    tmp_path: Path,
) -> None:
    store = SecuritySpecStore(tmp_path / "security_specs")
    record = SimpleNamespace(
        function_uid="src/service.c::receive",
        signature="int receive(char *data)",
        code_hash=HASH_A,
        backend_coverage={"complete": True},
    )
    claim = SimpleNamespace(
        claim_id="CLAIM_SOURCE",
        subject_uid=record.function_uid,
        kind="input_origin",
        value={"slot": "parameter:0", "label": "network"},
        evidence_refs=("evidence:src/service.c:4",),
        origin="program",
        confidence=1.0,
    )
    semantic_map = SimpleNamespace(language="c_cpp", functions=(record,), claims=(claim,))
    dependencies = [HASH_A, content_sha256(record.backend_coverage)]
    qualification = load_builtin_qualification()
    runtime = SecuritySpecShadowRuntime(store)

    first = runtime.run(
        semantic_map,
        qualifications=[qualification],
        qualification_hashes=[qualification["content_sha256"]],
        resolvable_evidence_refs=claim.evidence_refs,
        current_dependency_hashes=dependencies,
    )
    second = runtime.run(
        semantic_map,
        qualifications=[qualification],
        qualification_hashes=[qualification["content_sha256"]],
        resolvable_evidence_refs=claim.evidence_refs,
        current_dependency_hashes=dependencies,
        additional_specs=store.list_specs(),
    )

    assert first["compiled_spec_count"] == second["compiled_spec_count"] == 1
    assert len(store.list_specs(latest_only=False)) == 1
    stable = store.list_specs()[0]
    assert stable["status"] == "stable"
    assert stable["qualification_ref"] == qualification["content_sha256"]
    assert first["active_product_effect"] == second["active_product_effect"] == "none"


def test_deterministic_miner_preserves_inexact_claim_as_observation() -> None:
    record = SimpleNamespace(
        function_uid="src/api.c::handle",
        signature="int handle(char *data)",
        code_hash=HASH_A,
        backend_coverage={"complete": True},
    )
    exact = SimpleNamespace(
        claim_id="CLAIM_1",
        subject_uid=record.function_uid,
        kind="input_origin",
        value={"slot": "parameter:0", "label": "untrusted"},
        evidence_refs=("evidence:src/api.c:10",),
        origin="program",
        confidence=1.0,
    )
    inexact = SimpleNamespace(
        claim_id="CLAIM_2",
        subject_uid=record.function_uid,
        kind="bounds_contract",
        value={},
        evidence_refs=("evidence:src/api.c:11",),
        origin="program",
        confidence=1.0,
    )
    result = SecuritySpecMiner().mine(
        SimpleNamespace(language="c_cpp", functions=(record,), claims=(exact, inexact))
    )
    assert len(result["specs"]) == 1
    assert result["specs"][0]["status"] == "verified_scoped"
    assert result["observations"] == [
        {"claim_id": "CLAIM_2", "reason": "subject_scope_or_parameters_not_exact"}
    ]

    llm_claim = copy.copy(exact)
    llm_claim.claim_id = "CLAIM_LLM"
    llm_claim.origin = "llm"
    llm_result = SecuritySpecMiner().mine(
        SimpleNamespace(language="c_cpp", functions=(record,), claims=(llm_claim,))
    )
    assert llm_result["specs"] == []
    assert llm_result["observations"] == [
        {"claim_id": "CLAIM_LLM", "reason": "llm_claim_requires_bounded_proposal_id"}
    ]


def test_json_and_xlsx_archive_round_trip_and_stale_rejection(tmp_path: Path) -> None:
    archive = build_archive(specs=[_spec()], qualifications=[_qualification()])
    assert validate_archive(archive) == (True, "ok")
    assert archive_from_json_bytes(archive_to_json_bytes(archive)) == archive
    path = tmp_path / "security-specs.xlsx"
    archive_to_xlsx(path, archive)
    assert archive_from_xlsx(path) == archive
    with pytest.raises(ValueError, match="archive_store_revision_stale"):
        archive_from_xlsx(path, expected_store_revision=HASH_A)


def test_archive_unknown_fields_and_hash_conflicts_fail_closed() -> None:
    archive = build_archive(specs=[_spec()])
    assert validate_archive({**archive, "unexpected": True})[1] == "archive_schema_keys_mismatch"
    tampered = copy.deepcopy(archive)
    tampered["specs"][0]["revision"] = 2
    assert validate_archive(tampered)[1] == "archive_bundle_hash_mismatch"
    with pytest.raises(ValueError, match="archive_json_duplicate_key"):
        archive_from_json_bytes(b'{"schema_version":"a","schema_version":"b"}')


def test_archive_rejects_broken_review_chain() -> None:
    spec = _spec()
    event = build_review_event(
        spec_uid=spec["spec_uid"],
        spec_revision=1,
        reviewer_identity="reviewer@example.invalid",
        reviewed_at="2026-08-18T00:00:00Z",
        reason="Deferred",
        action="defer",
        before_spec_sha256=spec["content_sha256"],
        after_spec_sha256=spec["content_sha256"],
        scope_override={},
        dependency_impact=[],
        previous_event_sha256="0" * 64,
    )
    archive = build_archive(specs=[spec], reviews=[event])
    broken = copy.deepcopy(archive)
    broken["reviews"][0]["previous_event_sha256"] = "f" * 64
    from zscope.semantics.security_specs.canonical import seal

    broken["reviews"][0] = seal(
        {key: value for key, value in broken["reviews"][0].items() if key != "content_sha256"}
    )
    body = {key: value for key, value in broken.items() if key != "bundle_sha256"}
    from zscope.semantics.security_specs.canonical import content_sha256

    broken["bundle_sha256"] = content_sha256(body)
    assert validate_archive(broken)[1] == "archive_review_chain_root_count"
