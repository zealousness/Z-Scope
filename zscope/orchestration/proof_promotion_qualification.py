"""Load the local P6 proof/promotion successor qualification.

The artifact is deliberately *not* a phase-completion or review authority.  It
only proves that the current source candidate passed the deterministic,
answer-free successor corpus.  P6 still requires the independently produced
review artifacts and the cold balanced qualification before completion.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from typing import Any, Mapping, Tuple

P6_PROOF_PROMOTION_QUALIFICATION_VERSION = "zscope.p6-proof-promotion-successor-qualification.v1"
P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE = "p6-proof-promotion-qualification.v1.json"
P2_CORPUS_FILE_SHA256 = "60d650de574b5ef3b659f9722cc7eca7b1e161e0120ab25ba44ed38861f27985"

SOURCE_BOUND_PATHS: Tuple[str, ...] = (
    "zscope/agents/base.py",
    "zscope/agents/hypothesis_hunter/AGENT.md",
    "zscope/agents/proof_engine/AGENT.md",
    "zscope/agents/proof_engine/agent.py",
    "zscope/alerts/verifier.py",
    "zscope/cli/cli.py",
    "zscope/cli/explain.py",
    "zscope/core/analysis/analyzer.py",
    "zscope/core/validation/__init__.py",
    "zscope/core/validation/audit_eligibility.py",
    "zscope/core/validation/authority.py",
    "zscope/core/validation/evidence_completion.py",
    "zscope/core/validation/fact_capabilities.py",
    "zscope/core/validation/function_ir.py",
    "zscope/core/validation/proof_kernel/__init__.py",
    "zscope/core/validation/proof_kernel/canonical.py",
    "zscope/core/validation/proof_kernel/checker.py",
    "zscope/core/validation/proof_kernel/closure.py",
    "zscope/core/validation/proof_kernel/engine.py",
    "zscope/core/validation/proof_kernel/lifecycle.py",
    "zscope/core/validation/proof_kernel/models.py",
    "zscope/core/validation/proof_kernel/provider.py",
    "zscope/core/validation/proof_kernel/registry.py",
    "zscope/core/validation/proof_kernel/schemas/evidence-action-v2.schema.json",
    "zscope/core/validation/proof_kernel/schemas/evidence-certificate-v2.schema.json",
    "zscope/core/validation/proof_kernel/schemas/function-security-summary-v2.schema.json",
    "zscope/core/validation/proof_kernel/schemas/program-proof-ir-v2.schema.json",
    "zscope/core/validation/proof_kernel/schemas/proof-check-result-v2.schema.json",
    "zscope/core/validation/proof_kernel/schemas/proof-obligation-v2.schema.json",
    "zscope/core/validation/proof_kernel/store.py",
    "zscope/core/validation/runner.py",
    "zscope/framework/llm_client.py",
    "zscope/framework/llm_usage.py",
    "zscope/orchestration/decision_trace.py",
    "zscope/orchestration/candidates.py",
    "zscope/orchestration/hypothesis_hunter/blind.py",
    "zscope/orchestration/hypothesis_hunter/catalog.py",
    "zscope/orchestration/hypothesis_hunter/lifecycle.py",
    "zscope/orchestration/hypothesis_hunter/models.py",
    "zscope/orchestration/hypothesis_hunter/planner.py",
    "zscope/orchestration/hypothesis_hunter/qualification.py",
    "zscope/orchestration/hypothesis_hunter/resource_proof.py",
    "zscope/orchestration/hypothesis_hunter/runtime.py",
    "zscope/orchestration/hypothesis_hunter/store.py",
    "zscope/orchestration/parallel_analyzer.py",
    "zscope/orchestration/proof_promotion_qualification.py",
    "zscope/orchestration/runtime_authority.py",
    "zscope/orchestration/schemas/p6-proof-promotion-qualification-v1.schema.json",
    "zscope/orchestration/schemas/runtime-authority-manifest-v1.schema.json",
    "zscope/retrieval/clang_tooling_evidence.py",
    "zscope/reporting/assembler.py",
    "zscope/reporting/finding_roots.py",
    "zscope/reporting/report.py",
    "zscope/reporting/schema.py",
    "zscope/reporting/views.py",
    "zscope/semantics/security_specs/runtime.py",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "requires_independent_review",
        "authorizes_phase_completion",
        "answer_free",
        "network",
        "llm_calls",
        "protocol_identity",
        "qualification_dependencies",
        "source_sha256",
        "case_counts",
        "acceptance",
        "content_sha256",
    }
)
_PROTOCOL_IDENTITY = {
    # These literals are the successor contract.  A future protocol revision
    # must update them explicitly and produce a new, independently reviewed
    # artifact rather than silently following imported runtime constants.
    "runtime_authority_schema_version": "zscope.runtime-authority-manifest.v1",
    "runtime_authority_protocol_revision": 2,
    "runtime_cache_epoch": "zscope.runtime-authority.p6-proof-v4",
    "frozen_proof_state_schema": "zscope.frozen-proof-state.v1",
    "proof_closure_evaluation_schema": "zscope.proof-closure-evaluation.v1",
    "promotion_certificate_schema": "zscope.promotion-certificate.v1",
    "terminal_authority_decision_schema": "zscope.terminal-authority-decision.v4",
    "hypothesis_hunter_mode": "active",
    "hypothesis_hunter_effect": "candidate_registration_only",
}
_DEPENDENCY_FIELDS = frozenset(
    {
        "p2_corpus_file_sha256",
        "p3_security_spec_qualification_sha256",
        "p4_hypothesis_qualification_sha256",
    }
)
_CASE_FIELDS = frozenset(
    {
        "p2_case_count",
        "complete_confirmation_count",
        "incomplete_needs_review_count",
        "safe_false_confirmation_count",
        "complete_counterproof_rejection_count",
        "fact_complete_without_proof_not_promoted_count",
        "tampered_promotion_fail_closed_count",
        "cross_obligation_fail_closed_count",
        "legacy_v3_fail_closed_count",
        "resource_exact_leak_binding_count",
        "resource_cleanup_binding_count",
        "resource_ownership_escape_rejected_count",
    }
)


def protocol_identity() -> dict[str, Any]:
    """Return the exact current source protocol bound by the artifact."""

    return dict(_PROTOCOL_IDENTITY)


def _content_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _resource_bytes(relative: str) -> bytes:
    parts = relative.split("/")
    if not parts or parts[0] != "zscope" or any(not value for value in parts):
        raise ValueError("successor_qualification_source_path_invalid")
    current = resources.files("zscope")
    for part in parts[1:]:
        current = current.joinpath(part)
    return current.read_bytes()


def current_source_hashes() -> dict[str, str]:
    return {path: hashlib.sha256(_resource_bytes(path)).hexdigest() for path in SOURCE_BOUND_PATHS}


def current_dependency_qualifications() -> dict[str, str]:
    from ..semantics.security_specs.qualification import (
        load_builtin_qualification as load_p3_qualification,
    )
    from .hypothesis_hunter.qualification import (
        load_builtin_qualification as load_p4_qualification,
    )

    return {
        "p2_corpus_file_sha256": P2_CORPUS_FILE_SHA256,
        "p3_security_spec_qualification_sha256": str(load_p3_qualification()["content_sha256"]),
        "p4_hypothesis_qualification_sha256": str(load_p4_qualification()["content_sha256"]),
    }


def validate_successor_qualification(raw: Mapping[str, Any]) -> tuple[bool, str]:
    """Validate the sealed artifact without granting phase-completion authority."""

    if set(raw) != _TOP_LEVEL_FIELDS:
        return False, "successor_qualification_fields_mismatch"
    if raw.get("schema_version") != P6_PROOF_PROMOTION_QUALIFICATION_VERSION:
        return False, "successor_qualification_schema_mismatch"
    if (
        raw.get("status") != "local_candidate_qualified"
        or raw.get("requires_independent_review") is not True
        or raw.get("authorizes_phase_completion") is not False
        or raw.get("answer_free") is not True
        or raw.get("network") is not False
        or raw.get("llm_calls") != 0
    ):
        return False, "successor_qualification_authority_boundary_invalid"
    protocol = raw.get("protocol_identity")
    if not isinstance(protocol, Mapping) or dict(protocol) != _PROTOCOL_IDENTITY:
        return False, "successor_qualification_protocol_identity_mismatch"
    dependencies = raw.get("qualification_dependencies")
    if not isinstance(dependencies, Mapping) or set(dependencies) != _DEPENDENCY_FIELDS:
        return False, "successor_qualification_dependencies_invalid"
    if any(_SHA256_RE.fullmatch(str(value or "")) is None for value in dependencies.values()):
        return False, "successor_qualification_dependency_hash_invalid"
    sources = raw.get("source_sha256")
    if not isinstance(sources, Mapping) or set(sources) != set(SOURCE_BOUND_PATHS):
        return False, "successor_qualification_source_set_mismatch"
    if any(_SHA256_RE.fullmatch(str(value or "")) is None for value in sources.values()):
        return False, "successor_qualification_source_hash_invalid"
    counts = raw.get("case_counts")
    if not isinstance(counts, Mapping) or set(counts) != _CASE_FIELDS:
        return False, "successor_qualification_case_counts_invalid"
    if any(type(value) is not int or value < 0 for value in counts.values()):
        return False, "successor_qualification_case_count_invalid"
    minimums = {
        "p2_case_count": 120,
        "complete_confirmation_count": 40,
        "incomplete_needs_review_count": 80,
        "complete_counterproof_rejection_count": 1,
        "fact_complete_without_proof_not_promoted_count": 1,
        "tampered_promotion_fail_closed_count": 1,
        "cross_obligation_fail_closed_count": 1,
        "legacy_v3_fail_closed_count": 1,
        "resource_exact_leak_binding_count": 1,
        "resource_cleanup_binding_count": 1,
        "resource_ownership_escape_rejected_count": 6,
    }
    if counts.get("safe_false_confirmation_count") != 0 or any(
        int(counts.get(key, 0)) < minimum for key, minimum in minimums.items()
    ):
        return False, "successor_qualification_acceptance_threshold_failed"
    acceptance = raw.get("acceptance")
    if not isinstance(acceptance, Mapping) or dict(acceptance) != {
        "passed": True,
        "reason_code": "local_candidate_successor_requires_independent_review",
    }:
        return False, "successor_qualification_acceptance_invalid"
    body = {key: value for key, value in raw.items() if key != "content_sha256"}
    if raw.get("content_sha256") != _content_sha256(body):
        return False, "successor_qualification_content_hash_mismatch"
    return True, "valid_local_candidate_qualification"


def validate_successor_freshness(raw: Mapping[str, Any]) -> tuple[bool, str]:
    valid, reason = validate_successor_qualification(raw)
    if not valid:
        return valid, reason
    if dict(raw["qualification_dependencies"]) != current_dependency_qualifications():
        return False, "successor_qualification_dependency_stale"
    if dict(raw["source_sha256"]) != current_source_hashes():
        return False, "successor_qualification_source_stale"
    return True, "fresh_local_candidate_qualification"


def load_successor_qualification() -> dict[str, Any]:
    resource = resources.files(__package__).joinpath(P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE)
    raw = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("successor_qualification_must_be_object")
    valid, reason = validate_successor_freshness(raw)
    if not valid:
        raise ValueError(reason)
    return raw
