"""P4 hypothesis-driven hunting in an authority-free shadow boundary."""

from .blind import CandidateBlindProjectionError, build_candidate_blind_projection
from .agent import HypothesisHunterAgent
from .catalog import HypothesisProofCatalog
from .models import (
    ATTACK_SURFACE_AUDIT_UNIT_VERSION,
    HYPOTHESIS_COVERAGE_OBSERVATION_VERSION,
    HYPOTHESIS_HUNT_REPORT_VERSION,
    HYPOTHESIS_OFFER_VERSION,
    LOCALIZED_COVERAGE_KEY_VERSION,
    SECURITY_HYPOTHESIS_VERSION,
    build_attack_surface_audit_unit,
    build_coverage_observation,
    build_hypothesis_offer,
    build_localized_coverage_key,
    materialize_security_hypothesis,
    validate_attack_surface_audit_unit,
    validate_coverage_observation,
    validate_hunt_report,
    validate_hypothesis_offer,
    validate_localized_coverage_key,
    validate_security_hypothesis,
)
from .planner import AttackSurfacePlanner, PlannedHunt
from .qualification import load_builtin_qualification
from .runtime import HypothesisHunterShadowRuntime
from .store import HypothesisArtifactStore, load_hypothesis_shadow_identity

__all__ = [
    "ATTACK_SURFACE_AUDIT_UNIT_VERSION",
    "CandidateBlindProjectionError",
    "HypothesisArtifactStore",
    "HypothesisHunterAgent",
    "HypothesisHunterShadowRuntime",
    "HypothesisProofCatalog",
    "HYPOTHESIS_COVERAGE_OBSERVATION_VERSION",
    "HYPOTHESIS_HUNT_REPORT_VERSION",
    "HYPOTHESIS_OFFER_VERSION",
    "LOCALIZED_COVERAGE_KEY_VERSION",
    "SECURITY_HYPOTHESIS_VERSION",
    "AttackSurfacePlanner",
    "PlannedHunt",
    "build_attack_surface_audit_unit",
    "build_candidate_blind_projection",
    "build_coverage_observation",
    "build_hypothesis_offer",
    "build_localized_coverage_key",
    "materialize_security_hypothesis",
    "validate_attack_surface_audit_unit",
    "validate_coverage_observation",
    "validate_hunt_report",
    "validate_hypothesis_offer",
    "validate_localized_coverage_key",
    "validate_security_hypothesis",
    "load_hypothesis_shadow_identity",
    "load_builtin_qualification",
]
