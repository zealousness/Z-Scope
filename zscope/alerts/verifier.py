"""Offline P5 verification for external alerts.

Alert verification never invokes a model or the Hypothesis Hunter.  A SARIF
producer may attach a frozen Proof Kernel input; otherwise the external signal
remains reviewable.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .adapter import ExternalAlert
from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..core.validation.authority import TerminalAuthorityEvaluator
from ..core.validation.proof_kernel.engine import ProofKernelEngine
from ..core.validation.proof_kernel.lifecycle import PROOF_KERNEL_MODE
from ..orchestration.decision_trace import ensure_decision_trace_store
from ..orchestration.hypothesis_hunter.store import load_hypothesis_manifest_identity
from ..orchestration.scheduler import VALIDATOR_ROLE, ScanScheduler
from ..reporting.attribution import FindingAttribution
from ..retrieval.code_index import CodeIndex
from ..semantics.security_specs.lifecycle import SECURITY_SPEC_MODE
from ..semantics.security_specs.manifest import load_manifest_identity


logger = logging.getLogger(__name__)


class AlertVerifier:
    """Reverify frozen proof artifacts attached to external alerts."""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: CodeIndex,
        user_config: Optional[UserConfigStore] = None,
        scheduler: Optional[ScanScheduler] = None,
    ) -> None:
        self.config = config
        self.code_index = code_index
        self.user_config = user_config
        self.scheduler = scheduler
        self.decision_trace_store = ensure_decision_trace_store(config)
        self.security_spec_identity = load_manifest_identity(
            Path(config.analysis.snapshot_dir) / "security_specs",
            consumer="alert_verify",
        )
        self.hypothesis_hunter_identity = load_hypothesis_manifest_identity(
            Path(config.analysis.snapshot_dir) / "hypothesis_hunter",
            consumer="alert_verify",
        )
        self.decision_trace_store.update_identity(self.security_spec_identity)
        self.decision_trace_store.update_identity(self.hypothesis_hunter_identity)
        self.terminal_authority = TerminalAuthorityEvaluator()

    def verify_alerts(
        self,
        alerts: List[ExternalAlert],
        max_workers: int = 1,
    ) -> List[Dict[str, Any]]:
        total = len(alerts)
        logger.info("Starting offline verification of %d alerts", total)
        worker_count = self._worker_count(total, max_workers)
        if worker_count <= 1:
            results = [
                self._verify_alert_safely(alert, idx, total) for idx, alert in enumerate(alerts, 1)
            ]
        elif getattr(self, "scheduler", None) is not None:
            scheduler = self.scheduler
            assert scheduler is not None
            by_index: Dict[int, Dict[str, Any]] = {}
            futures = {
                scheduler.submit(
                    VALIDATOR_ROLE,
                    self._verify_alert_safely,
                    alert,
                    idx,
                    total,
                ): idx
                for idx, alert in enumerate(alerts, 1)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    by_index[idx] = future.result()
                except Exception as exc:
                    by_index[idx] = self._make_error_result(alerts[idx - 1], idx, str(exc))
            results = [by_index[idx] for idx in range(1, total + 1)]
        else:
            by_index = {}
            with ThreadPoolExecutor(
                max_workers=worker_count,
                thread_name_prefix="zscope-alert-verifier",
            ) as executor:
                futures = {
                    executor.submit(self._verify_alert_safely, alert, idx, total): idx
                    for idx, alert in enumerate(alerts, 1)
                }
                for future in as_completed(futures):
                    idx = futures[future]
                    try:
                        by_index[idx] = future.result()
                    except Exception as exc:
                        by_index[idx] = self._make_error_result(alerts[idx - 1], idx, str(exc))
            results = [by_index[idx] for idx in range(1, total + 1)]

        trace_store = getattr(self, "decision_trace_store", None)
        for alert, result in zip(alerts, results):
            candidate_uid, cluster_uid = self._alert_identity(alert)
            result.setdefault("candidate_uid", candidate_uid)
            result.setdefault("validation_cluster_uid", cluster_uid)
            if trace_store is None:
                continue
            trace_store.bind_candidate(cluster_uid, candidate_uids=(candidate_uid,))
            disposition = str(result.get("candidate_disposition") or "engine_failed")
            memberships = (
                ("default", "with_needs_review")
                if disposition == "confirmed"
                else ("with_needs_review",) if disposition == "needs_review" else ("excluded",)
            )
            trace_store.finalize_issue(result, view_memberships=memberships)
        return results

    @staticmethod
    def _worker_count(alert_count: int, max_workers: int) -> int:
        if alert_count <= 1:
            return 1
        try:
            requested = int(max_workers or 1)
        except (TypeError, ValueError):
            requested = 1
        return max(1, min(alert_count, requested))

    @staticmethod
    def _alert_identity(alert: ExternalAlert) -> tuple[str, str]:
        identity = {
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "function": alert.function,
        }
        digest = hashlib.sha256(
            json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return f"CAND_ALERT_{digest}", f"VCL_ALERT_{digest}"

    def _verify_alert_safely(
        self,
        alert: ExternalAlert,
        idx: int,
        total: int,
    ) -> Dict[str, Any]:
        logger.info(
            "[%d/%d] Reverify %s:%d (%s)",
            idx,
            total,
            alert.file_path,
            alert.line,
            alert.rule_id,
        )
        try:
            return self._verify_single(alert, idx)
        except Exception as exc:
            logger.error("Failed to reverify alert %d: %s", idx, exc)
            return self._make_error_result(alert, idx, str(exc))

    @staticmethod
    def _proof_input(alert: ExternalAlert) -> Optional[Mapping[str, Any]]:
        raw = alert.raw if isinstance(alert.raw, Mapping) else {}
        properties = raw.get("properties")
        properties = properties if isinstance(properties, Mapping) else {}
        value = properties.get("zscopeProofKernelInput")
        if value is None:
            value = properties.get("zscope_proof_kernel_input")
        return value if isinstance(value, Mapping) else None

    def _verify_single(self, alert: ExternalAlert, idx: int) -> Dict[str, Any]:
        candidate_uid, cluster_uid = self._alert_identity(alert)
        proof_input = self._proof_input(alert)
        proof_decision: Dict[str, Any]
        checker_results: list[dict[str, Any]] = []
        artifact_refs: list[str] = []
        checker_refs: list[str] = []
        proof_root = ""
        integrity_status = "open_fail_closed"
        if proof_input is None:
            proof_decision = {
                "schema_version": "zscope.proof-kernel-evaluation.v1",
                "proof_kernel_mode": PROOF_KERNEL_MODE,
                "disposition": "needs_review",
                "reason_code": "alert_verify_frozen_proof_unavailable",
                "missing_fact_kinds": ["external_alert_program_evidence"],
                "artifact_refs": [],
                "checker_result_refs": [],
                "root_manifest_sha256": "",
            }
        elif set(proof_input) != {
            "proof_ir",
            "proof_obligation",
            "selected_action_uids",
        }:
            proof_decision = {
                "schema_version": "zscope.proof-kernel-evaluation.v1",
                "proof_kernel_mode": PROOF_KERNEL_MODE,
                "disposition": "needs_review",
                "reason_code": "alert_verify_proof_input_schema_invalid",
                "missing_fact_kinds": ["proof_kernel_input"],
                "artifact_refs": [],
                "checker_result_refs": [],
                "root_manifest_sha256": "",
            }
        else:
            try:
                evaluation = ProofKernelEngine().evaluate_selected_actions(
                    proof_ir=proof_input["proof_ir"],
                    obligation=proof_input["proof_obligation"],
                    selected_action_uids=proof_input["selected_action_uids"],
                )
                checker_results = [dict(value) for value in evaluation.check_results]
                artifact_refs = list(evaluation.artifact_refs)
                checker_refs = list(evaluation.checker_result_refs)
                proof_root = evaluation.root_manifest_sha256
                integrity_status = "verified"
                proof_decision = {
                    "schema_version": evaluation.schema_version,
                    "proof_kernel_mode": evaluation.proof_kernel_mode,
                    "disposition": evaluation.decision,
                    "reason_code": evaluation.reason_code,
                    "missing_fact_kinds": (
                        []
                        if evaluation.decision in {"confirmed", "rejected_with_proof"}
                        else ["proof_clause"]
                    ),
                    "artifact_refs": artifact_refs,
                    "checker_result_refs": checker_refs,
                    "root_manifest_sha256": proof_root,
                }
            except (KeyError, TypeError, ValueError) as exc:
                proof_decision = {
                    "schema_version": "zscope.proof-kernel-evaluation.v1",
                    "proof_kernel_mode": PROOF_KERNEL_MODE,
                    "disposition": "needs_review",
                    "reason_code": "alert_verify_proof_reverification_failed",
                    "missing_fact_kinds": ["proof_kernel_reverification"],
                    "artifact_refs": [],
                    "checker_result_refs": [],
                    "root_manifest_sha256": "",
                    "error": f"{type(exc).__name__}: {exc}"[:500],
                }

        disposition = str(proof_decision["disposition"])
        if disposition == "confirmed":
            terminal_reason = "CONFIRMED_DETERMINISTIC_PROOF"
            authority_name = "zscope.proof-checker"
        elif disposition == "rejected_with_proof":
            terminal_reason = "REJECTED_DETERMINISTIC_COUNTERPROOF"
            authority_name = "zscope.proof-checker"
        elif proof_decision["reason_code"] == "programmatic_proof_conflict":
            terminal_reason = "NEEDS_REVIEW_EVIDENCE_CONFLICT"
            authority_name = "zscope.proof-checker-conflict-resolver"
        else:
            disposition = "needs_review"
            terminal_reason = "NEEDS_REVIEW_OPEN_CLAUSES"
            authority_name = "zscope.proof-checker"
        proof_authority = {
            "schema_version": "zscope.terminal-authority-decision.v3",
            "terminal": True,
            "disposition": disposition,
            "reason_code": terminal_reason,
            "authority": authority_name,
            "next_action": "",
            "conflict_resolution": None,
            "checker_result_refs": checker_refs,
            "proof_root_sha256": proof_root,
            "integrity_status": integrity_status,
        }
        authority = self.terminal_authority.evaluate(
            {"proof_kernel_terminal_authority_decision": proof_authority}
        )
        disposition = authority.disposition
        security_identity = getattr(
            self,
            "security_spec_identity",
            {
                "security_spec_mode": SECURITY_SPEC_MODE,
                "security_spec_artifact_refs": [],
                "security_spec_decision": {
                    "active_product_effect": "semantic_input",
                    "reason_code": "alert_verify_security_spec_manifest_unavailable",
                },
            },
        )
        hunter_identity = getattr(
            self,
            "hypothesis_hunter_identity",
            {
                "hypothesis_hunter_mode": "active",
                "hypothesis_hunter_artifact_refs": [],
                "hypothesis_hunter_decision": {
                    "active_product_effect": "candidate_registration_only",
                    "reason_code": "alert_verify_hypothesis_manifest_unavailable",
                },
            },
        )
        return {
            "alert_id": f"ALERT_{idx}",
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
            "verdict": (
                "confirmed"
                if disposition == "confirmed"
                else "rejected" if disposition == "rejected_with_proof" else "uncertain"
            ),
            "policy_disposition": disposition,
            "validation_status": (
                "validated"
                if disposition == "confirmed"
                else "rejected" if disposition == "rejected_with_proof" else "needs_review"
            ),
            "candidate_disposition": disposition,
            "engine_status": "complete",
            "validation_reasoning": str(proof_decision["reason_code"]),
            "proof_kernel_mode": PROOF_KERNEL_MODE,
            "proof_kernel_decision": proof_decision,
            "proof_kernel_checker_results": checker_results,
            "proof_kernel_artifact_refs": artifact_refs,
            "proof_kernel_checker_result_refs": checker_refs,
            "proof_kernel_root_manifest_sha256": proof_root,
            "proof_kernel_reverification_status": integrity_status,
            "proof_kernel_terminal_authority_decision": proof_authority,
            "terminal_authority": authority.authority,
            "terminal_authority_decision": authority.to_dict(),
            "terminal_reason_codes": [authority.reason_code],
            "open_clause_ids": ([] if disposition != "needs_review" else ["proof_clause"]),
            "security_spec_mode": security_identity["security_spec_mode"],
            "security_spec_artifact_refs": list(security_identity["security_spec_artifact_refs"]),
            "security_spec_decision": dict(security_identity["security_spec_decision"]),
            "hypothesis_hunter_mode": hunter_identity["hypothesis_hunter_mode"],
            "hypothesis_hunter_artifact_refs": list(
                hunter_identity["hypothesis_hunter_artifact_refs"]
            ),
            "hypothesis_hunter_decision": dict(hunter_identity["hypothesis_hunter_decision"]),
            "attribution": FindingAttribution(
                discovered_by=("backend_signal",),
                discovery_details=({"tool": alert.tool, "native_rule_id": alert.rule_id},),
                decided_by="proof_engine",
                decision_level="V0",
                decision_details={"execution": "offline_checker_reverification"},
            ).to_dict(),
        }

    def close(self) -> None:
        return None

    def _make_error_result(self, alert: ExternalAlert, idx: int, error: str) -> Dict[str, Any]:
        candidate_uid, cluster_uid = self._alert_identity(alert)
        return {
            "alert_id": f"ALERT_{idx}",
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": cluster_uid,
            "tool": alert.tool,
            "rule_id": alert.rule_id,
            "file": alert.file_path,
            "line": alert.line,
            "original_message": alert.message,
            "original_severity": alert.severity.value,
            "validation_status": "pending",
            "candidate_disposition": "engine_failed",
            "engine_status": "failed",
            "verification_error": error,
            "verdict": "uncertain",
            "confidence": 0.0,
            "reasoning": f"offline proof reverification failed: {error}",
        }
