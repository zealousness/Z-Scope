"""Z-Scope 2.0 replayable proof kernel.

The package is deliberately independent from model clients and promotion code.
Providers may propose certificates, but only :class:`ProofChecker` can accept
one as a decision fact. P5 makes complete Checker closure the sole live
terminal authority.
"""

from .checker import ProofChecker
from .engine import ProofKernelEngine, ProofKernelEvaluation
from .provider import ProofProvider
from .models import (
    EVIDENCE_ACTION_VERSION,
    EVIDENCE_CERTIFICATE_VERSION,
    FUNCTION_SECURITY_SUMMARY_VERSION,
    PROGRAM_PROOF_IR_VERSION,
    PROOF_CHECK_RESULT_VERSION,
    PROOF_OBLIGATION_VERSION,
    build_evidence_action,
    build_proof_clause,
    build_proof_obligation,
    function_summary_from_graph,
    program_proof_ir_from_graph,
)
from .registry import (
    NON_EXECUTABLE_PREDICATES,
    POLARITY_ROLE_TERMINAL_MATRIX,
    PREDICATE_REGISTRY,
    PredicateSpec,
)
from .store import ProofArtifactStore

__all__ = [
    "EVIDENCE_ACTION_VERSION",
    "EVIDENCE_CERTIFICATE_VERSION",
    "FUNCTION_SECURITY_SUMMARY_VERSION",
    "PREDICATE_REGISTRY",
    "NON_EXECUTABLE_PREDICATES",
    "POLARITY_ROLE_TERMINAL_MATRIX",
    "PROGRAM_PROOF_IR_VERSION",
    "PROOF_CHECK_RESULT_VERSION",
    "PROOF_OBLIGATION_VERSION",
    "PredicateSpec",
    "ProofArtifactStore",
    "ProofChecker",
    "ProofKernelEngine",
    "ProofKernelEvaluation",
    "ProofProvider",
    "build_evidence_action",
    "build_proof_clause",
    "build_proof_obligation",
    "function_summary_from_graph",
    "program_proof_ir_from_graph",
]
