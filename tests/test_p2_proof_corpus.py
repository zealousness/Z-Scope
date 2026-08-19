import json
import hashlib
from collections import Counter
from pathlib import Path

from scripts.p2_proof_corpus import build_corpus
from zscope.core.validation.proof_kernel.canonical import seal_mapping
from zscope.core.validation.proof_kernel.checker import ProofChecker
from zscope.core.validation.proof_kernel.provider import ProofProvider


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/p2_proof_kernel/corpus.json"
SCHEMA_ROOT = ROOT / "zscope/core/validation/proof_kernel/schemas"


def test_committed_corpus_is_exact_deterministic_materialization() -> None:
    frozen = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert frozen == build_corpus()


def test_corpus_has_required_family_safe_and_metamorphic_coverage() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = corpus["cases"]
    assert corpus["answer_free"] is True
    assert corpus["model_calls"] == 0
    assert corpus["network"] is False
    assert len(cases) == corpus["case_count"] == 120
    assert sum(value["expected"]["safe_case"] for value in cases) == 80
    counts = Counter((value["family"], value["variant"]) for value in cases)
    for family in ("concurrency", "resource", "path_guard", "contract_type"):
        assert counts[(family, "positive")] == 10
        assert counts[(family, "near_miss_safe")] == 20
    assert set(corpus["structure_families"]) >= {"linear", "branching", "wrapped"}
    assert {
        "identifier_rename",
        "wrapper_extraction",
        "wrapper_inlining",
        "macro_equivalent",
        "branch_reorder",
        "fixed_pair",
    } <= set(corpus["transformations"])


def test_all_accepted_facts_recompute_offline_and_safe_false_acceptance_is_zero() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    safe_acceptances = []
    positive_acceptances = 0
    for case in corpus["cases"]:
        recomputed = ProofChecker().check(
            proof_ir=case["program_proof_ir"],
            obligation=case["proof_obligation"],
            action=case["evidence_action"],
            certificate=case["evidence_certificate"],
        )
        assert recomputed == case["proof_check_result"]
        if case["expected"]["safe_case"] and recomputed["status"] == "accepted":
            safe_acceptances.append(case["case_uid"])
        if not case["expected"]["safe_case"] and recomputed["status"] == "accepted":
            positive_acceptances += 1
    assert safe_acceptances == []
    assert positive_acceptances == 40


def test_java_preview_is_schema_compatible_but_fail_closed() -> None:
    case = build_corpus()["cases"][0]
    body = dict(case["program_proof_ir"])
    body.pop("proof_ir_uid")
    body.pop("content_sha256")
    body["language"] = "java"
    java_ir = seal_mapping(body, uid_field="proof_ir_uid", prefix="PROOFIR_")
    obligation_body = dict(case["proof_obligation"])
    obligation_body.pop("obligation_uid")
    obligation_body.pop("content_sha256")
    obligation_body["dependency_hashes"] = java_ir["dependency_hashes"]
    obligation = seal_mapping(obligation_body, uid_field="obligation_uid", prefix="POBL_")
    clause = obligation["confirmation_clauses"][0]
    action_body = dict(case["evidence_action"])
    action_body.pop("action_uid")
    action_body.pop("content_sha256")
    action_body["proof_ir_uid"] = java_ir["proof_ir_uid"]
    action_body["obligation_uid"] = obligation["obligation_uid"]
    action = seal_mapping(action_body, uid_field="action_uid", prefix="EVACTION_")
    certificate = ProofProvider().produce(proof_ir=java_ir, obligation=obligation, action=action)
    checked = ProofChecker().check(
        proof_ir=java_ir,
        obligation=obligation,
        action=action,
        certificate=certificate,
    )

    assert clause["predicate_id"] == action["predicate_id"]
    assert certificate["status"] == "unknown"
    assert checked["status"] == "unknown"
    assert checked["accepted_fact"] is None


def test_wheel_schemas_match_design_contracts_and_validate_frozen_artifacts() -> None:
    design_root = ROOT / "docs/design/zscope-2.0-security-architecture/schemas"
    for path in sorted(SCHEMA_ROOT.glob("*.json")):
        assert json.loads(path.read_text(encoding="utf-8")) == json.loads(
            (design_root / path.name).read_text(encoding="utf-8")
        )
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in SCHEMA_ROOT.glob("*.json")
    }
    case = build_corpus()["cases"][0]
    artifacts = {
        "program-proof-ir-v2.schema.json": case["program_proof_ir"],
        "proof-obligation-v2.schema.json": case["proof_obligation"],
        "evidence-action-v2.schema.json": case["evidence_action"],
        "evidence-certificate-v2.schema.json": case["evidence_certificate"],
        "proof-check-result-v2.schema.json": case["proof_check_result"],
        "function-security-summary-v2.schema.json": case["program_proof_ir"]["functions"][0],
    }
    for name, artifact in artifacts.items():
        schema = schemas[name]
        assert schema["additionalProperties"] is False
        assert set(artifact) == set(schema["required"])
        for field, contract in schema["properties"].items():
            if "const" in contract:
                assert artifact[field] == contract["const"]


def test_source_to_ir_baseline_binds_neutral_sources_and_clang_version() -> None:
    baseline = json.loads(
        (ROOT / "tests/fixtures/p2_proof_kernel/source-qualification.json").read_text(
            encoding="utf-8"
        )
    )
    assert baseline["semantic"]["clang_version"] == "21.1.8"
    assert baseline["semantic"]["case_count"] == 4
    assert baseline["llm_calls"] == 0
    assert baseline["network"] is False
    for case in baseline["semantic"]["cases"]:
        source = ROOT / case["source"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == case["source_sha256"]
