"""P5 planner, Hunter selection, proof replay, and live candidate registration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Any, Callable, Mapping, Optional, Sequence

from ...core.validation.proof_kernel import (
    PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
    ProofKernelEngine,
)
from ...framework.base import AgentResponse
from ...framework.llm_usage import (
    P6BalancedTokenAdmissionError,
    llm_usage_attribution_scope,
)
from ...semantics.security_map import SecuritySemanticMap
from ..candidates import CandidateRegistrar
from .lifecycle import ACTIVE_PRODUCT_EFFECT, HYPOTHESIS_HUNTER_MODE
from .blind import CandidateBlindProjectionError, build_candidate_blind_projection
from .models import (
    build_coverage_observation,
    materialize_security_hypothesis,
    validate_hunt_report,
)
from .planner import AttackSurfacePlanner, ProofBundleProvider
from .store import HypothesisArtifactStore


ReportRunner = Callable[[Mapping[str, Any], Mapping[str, Any], Sequence[Mapping[str, Any]]], Any]
P6_LOW_VALUE_HUNTER_RISK_CUTOFF = 60


class HypothesisHunterRuntime:
    """Register hypotheses without granting the Hunter terminal authority."""

    def __init__(
        self,
        store: HypothesisArtifactStore,
        *,
        risk_threshold: int,
        max_units: int | None = None,
        max_concurrent_calls: int = 8,
        prompt_revision: str = "hypothesis-hunter.v4",
        model_profile: str = "analysis",
    ) -> None:
        self.store = store
        self.planner = AttackSurfacePlanner(
            risk_threshold=risk_threshold,
            max_units=max_units,
        )
        self.prompt_revision = str(prompt_revision)
        self.model_profile = str(model_profile)
        self.max_concurrent_calls = max(1, min(8, int(max_concurrent_calls)))
        self.engine = ProofKernelEngine()

    def run(
        self,
        semantic_map: SecuritySemanticMap,
        *,
        candidate_registrar: CandidateRegistrar,
        security_spec_runtime: Mapping[str, Any] | None = None,
        covered_localized_keys: Sequence[str] = (),
        canonical_investigation_roots: Mapping[str, str] | None = None,
        proof_bundle_provider: ProofBundleProvider | None = None,
        report_runner: Optional[ReportRunner] = None,
    ) -> dict[str, Any]:
        planned = self.planner.plan(
            semantic_map,
            security_spec_runtime=security_spec_runtime,
            covered_localized_keys=covered_localized_keys,
            canonical_investigation_roots=canonical_investigation_roots,
            proof_bundle_provider=proof_bundle_provider,
        )
        references: list[str] = []
        hypotheses: list[dict[str, Any]] = []
        observations: list[dict[str, Any]] = []
        proof_decisions: list[dict[str, Any]] = []
        function_names = {
            value.function_uid: value.function_name for value in semantic_map.functions
        }
        llm_calls = 0
        soft_token_denials = 0
        cache_hits = 0
        coverage_status_counts = {"complete": 0, "partial": 0, "failed": 0}
        prepared: list[dict[str, Any]] = []

        for hunt in planned:
            unit = dict(hunt.audit_unit)
            offers = [dict(value) for value in hunt.offers]
            unit_ref = self.store.put("attack_surface_audit_unit", unit)
            references.append(unit_ref)
            offer_refs = [
                self.store.put("hypothesis_offer", value, dependency_refs=(unit_ref,))
                for value in offers
            ]
            references.extend(offer_refs)
            if not offers:
                coverage_status_counts["partial"] += 1
                observation = self._observation(unit, "no_executable_proof_offer")
                observations.append(observation)
                references.append(
                    self.store.put(
                        "hypothesis_coverage_observation",
                        observation,
                        dependency_refs=(unit_ref,),
                    )
                )
                continue
            try:
                projection = build_candidate_blind_projection(unit, offers)
            except (CandidateBlindProjectionError, ValueError) as exc:
                coverage_status_counts["failed"] += 1
                observation = self._observation(
                    unit,
                    "candidate_blind_projection_rejected",
                    missing_fields=(type(exc).__name__,),
                )
                observations.append(observation)
                references.append(
                    self.store.put(
                        "hypothesis_coverage_observation",
                        observation,
                        dependency_refs=(unit_ref,),
                    )
                )
                continue
            projection_ref = self.store.put(
                "candidate_blind_projection",
                projection,
                dependency_refs=(unit_ref, *offer_refs),
            )
            references.append(projection_ref)
            cache_key = self._cache_key(unit, offers, security_spec_runtime or {})
            report = self.store.load_cached_report(cache_key)
            if report is not None:
                valid, _ = validate_hunt_report(report, audit_unit=unit, offers=offers)
                if valid:
                    cache_hits += 1
                else:
                    report = None
            prepared.append(
                {
                    "unit": unit,
                    "offers": offers,
                    "offer_refs": offer_refs,
                    "projection": projection,
                    "projection_ref": projection_ref,
                    "cache_key": cache_key,
                    "report": report,
                    "cache_hit": report is not None,
                }
            )

        selected_report_runner = report_runner
        pending = [
            (index, value) for index, value in enumerate(prepared) if value["report"] is None
        ]
        if pending and selected_report_runner is not None:

            def run_report(value: Mapping[str, Any]) -> Any:
                unit = value["unit"]
                with llm_usage_attribution_scope(
                    stage="active_discovery",
                    agent="hypothesis_hunter",
                    audit_unit_uid=str(unit["audit_unit_uid"]),
                    call_kind=self._discovery_call_kind(unit),
                ):
                    return selected_report_runner(value["projection"], unit, value["offers"])

            # Submit stronger answer-free risk classes first.  ThreadPoolExecutor
            # uses a FIFO work queue, so the 10.5M soft watermark cannot let a
            # low-value Hunter unit reserve capacity ahead of a stronger unit.
            pending.sort(
                key=lambda pair: (
                    -self._discovery_risk_score(pair[1]["unit"]),
                    str(pair[1]["unit"].get("audit_unit_uid") or ""),
                    pair[0],
                )
            )
            llm_calls = len(pending)
            worker_count = min(self.max_concurrent_calls, len(pending))
            with ThreadPoolExecutor(
                max_workers=worker_count,
                thread_name_prefix="zscope-hypothesis-hunter",
            ) as executor:
                futures = {executor.submit(run_report, value): index for index, value in pending}
                for future in as_completed(futures):
                    index = futures[future]
                    try:
                        response = future.result()
                    except P6BalancedTokenAdmissionError as exc:
                        if exc.failure_class != "p6_token_soft_watermark":
                            raise
                        # This is an answer-free pre-provider refusal.  Keep
                        # the audit unit in the coverage manifest, but do not
                        # count it as a physical model call or silently fall
                        # back to another discovery path.
                        prepared[index]["report"] = None
                        prepared[index]["failure_reason"] = "p6_low_value_hunter_soft_watermark"
                        soft_token_denials += 1
                        continue
                    except Exception:
                        # A provider/transport failure belongs to exactly this
                        # audit unit.  The exception body must never enter an
                        # answer-free artifact or suppress sibling results.
                        prepared[index]["report"] = None
                        continue
                    prepared[index]["report"] = self._report_from_response(response)

        for value in prepared:
            unit = value["unit"]
            offers = value["offers"]
            offer_refs = value["offer_refs"]
            projection_ref = value["projection_ref"]
            cache_key = value["cache_key"]
            report = value["report"]
            if report is not None:
                valid, _ = validate_hunt_report(report, audit_unit=unit, offers=offers)
                if valid:
                    if not value["cache_hit"]:
                        self.store.save_cached_report(cache_key, report)
                else:
                    report = None
            if report is None:
                failure_reason = str(
                    value.get("failure_reason") or "hunter_report_unavailable_or_invalid"
                )
                coverage_status_counts[
                    (
                        "partial"
                        if failure_reason == "p6_low_value_hunter_soft_watermark"
                        else "failed"
                    )
                ] += 1
                observation = self._observation(
                    unit,
                    failure_reason,
                )
                observations.append(observation)
                references.append(
                    self.store.put(
                        "hypothesis_coverage_observation",
                        observation,
                        dependency_refs=(projection_ref,),
                    )
                )
                continue
            coverage_status = str(report.get("coverage_status") or "failed")
            coverage_status_counts[
                coverage_status if coverage_status in coverage_status_counts else "failed"
            ] += 1
            report_ref = self.store.put(
                "hypothesis_hunt_report",
                report,
                dependency_refs=(projection_ref,),
            )
            references.append(report_ref)
            if not report.get("selected_offers"):
                observation = self._observation(unit, "hunter_reported_no_signal")
                observations.append(observation)
                references.append(
                    self.store.put(
                        "hypothesis_coverage_observation",
                        observation,
                        dependency_refs=(report_ref,),
                    )
                )
                continue
            by_offer = {str(value["offer_uid"]): value for value in offers}
            by_offer_ref = {
                str(value["offer_uid"]): reference for value, reference in zip(offers, offer_refs)
            }
            for selection in report["selected_offers"]:
                offer = by_offer[str(selection["offer_uid"])]
                hypothesis = materialize_security_hypothesis(
                    offer=offer,
                    selection=selection,
                )
                hypothesis_ref = self.store.put(
                    "security_hypothesis",
                    hypothesis,
                    dependency_refs=(report_ref, by_offer_ref[str(offer["offer_uid"])]),
                )
                references.append(hypothesis_ref)
                hypotheses.append(hypothesis)
                proof = self.engine.evaluate_selected_actions(
                    proof_ir=offer["proof_ir"],
                    obligation=offer["proof_obligation"],
                    selected_action_uids=hypothesis["evidence_action_uids"],
                )
                registered_candidate_ids: list[str] = []
                if proof.decision != "rejected_with_proof":
                    function_uid = str((hypothesis.get("location") or {}).get("function_uid") or "")
                    issue = self._live_issue(
                        hypothesis,
                        offer=offer,
                        proof=asdict(proof),
                        function_name=function_names.get(function_uid, ""),
                    )
                    registration = candidate_registrar.register_issues(
                        (issue,),
                        source="hypothesis_hunter",
                        default_entry_identity=str(
                            (unit.get("root_entry_uids") or ["__project__"])[0]
                        ),
                        force_unconfirmed=True,
                    )
                    registered_candidate_ids = list(registration.candidate_ids)
                if proof.decision == "rejected_with_proof":
                    observation = self._observation(
                        unit,
                        "selected_hypothesis_counterproved",
                    )
                    observations.append(observation)
                    references.append(
                        self.store.put(
                            "hypothesis_coverage_observation",
                            observation,
                            dependency_refs=(hypothesis_ref,),
                        )
                    )
                elif proof.decision != "confirmed":
                    observation = self._observation(
                        unit,
                        "selected_hypothesis_not_proven",
                    )
                    observations.append(observation)
                    references.append(
                        self.store.put(
                            "hypothesis_coverage_observation",
                            observation,
                            dependency_refs=(hypothesis_ref,),
                        )
                    )
                proof_value = {
                    **asdict(proof),
                    "hypothesis_uid": hypothesis["hypothesis_uid"],
                    "registered_candidate_uids": registered_candidate_ids,
                }
                proof_decisions.append(proof_value)
                references.append(
                    self.store.put(
                        "hypothesis_proof_decision",
                        proof_value,
                        dependency_refs=(hypothesis_ref,),
                    )
                )

        reason_code_distribution: dict[str, int] = {}
        for value in (*observations, *self.planner.diagnostics):
            reason_code = str(value.get("reason_code") or "UNSPECIFIED")
            reason_code_distribution[reason_code] = reason_code_distribution.get(reason_code, 0) + 1
        coverage_summary = {
            "planned_unit_count": len(planned),
            "offer_count": sum(len(value.offers) for value in planned),
            "hypothesis_count": len(hypotheses),
            "observation_count": len(observations),
            "proof_decision_count": len(proof_decisions),
            "registered_candidate_count": len(
                {
                    candidate_uid
                    for value in proof_decisions
                    for candidate_uid in value.get("registered_candidate_uids") or []
                }
            ),
            "llm_call_count": llm_calls - soft_token_denials,
            "p6_soft_token_denied_count": soft_token_denials,
            "cache_hit_count": cache_hits,
            "planner_diagnostic_count": len(self.planner.diagnostics),
            "coverage_status_counts": coverage_status_counts,
            "reason_code_distribution": dict(sorted(reason_code_distribution.items())),
        }
        manifest = self.store.write_root_manifest(
            references,
            registered_candidate_uids=tuple(
                candidate_uid
                for value in proof_decisions
                for candidate_uid in value.get("registered_candidate_uids") or []
            ),
            coverage_summary=coverage_summary,
        )
        return {
            "schema_version": "zscope.hypothesis-hunter-runtime-result.v1",
            "mode": HYPOTHESIS_HUNTER_MODE,
            "active_product_effect": ACTIVE_PRODUCT_EFFECT,
            "status": "complete",
            "proof_decisions": proof_decisions,
            "artifact_refs": list(manifest["artifact_refs"]),
            "root_manifest_sha256": manifest["content_sha256"],
            "coverage_summary": coverage_summary,
            "planner_diagnostics": list(self.planner.diagnostics),
        }

    @staticmethod
    def _discovery_risk_score(unit: Mapping[str, Any]) -> int:
        """Return the sealed planner score without accepting bool coercion."""

        value = unit.get("risk_score")
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return max(0, min(100, value))

    @classmethod
    def _discovery_call_kind(cls, unit: Mapping[str, Any]) -> str:
        """Classify only low-risk Hunter selection for P6 soft admission.

        The attack-surface planner computes ``risk_score`` solely from frozen
        program/coverage facts.  A score below 60 is the fixed low-value
        discovery class.  Ordinary scans merely retain this attribution; only
        the sealed P6 balanced ledger enforces its soft watermark.
        """

        if cls._discovery_risk_score(unit) < P6_LOW_VALUE_HUNTER_RISK_CUTOFF:
            return "p6_low_value_hunter"
        return "hypothesis_selection"

    @staticmethod
    def _report_from_response(response: Any) -> dict[str, Any] | None:
        if isinstance(response, AgentResponse):
            return dict(response.data) if response.success else None
        if isinstance(response, Mapping):
            return dict(response)
        return None

    def _cache_key(
        self,
        unit: Mapping[str, Any],
        offers: Sequence[Mapping[str, Any]],
        spec_runtime: Mapping[str, Any],
    ) -> str:
        from ...core.validation.proof_kernel.canonical import content_sha256

        return content_sha256(
            {
                "unit_fingerprint_sha256": unit["unit_fingerprint_sha256"],
                "offer_hashes": [value["content_sha256"] for value in offers],
                "security_spec_manifest_sha256": str(
                    spec_runtime.get("root_manifest_sha256") or ""
                ),
                "proof_registry_revision": "proof-kernel.v4",
                "prompt_revision": self.prompt_revision,
                "model_profile": self.model_profile,
                "dependency_hashes": list(unit.get("dependency_hashes") or []),
            }
        )

    @staticmethod
    def _observation(
        unit: Mapping[str, Any],
        reason_code: str,
        *,
        missing_fields: Sequence[str] = (),
    ) -> dict[str, Any]:
        return build_coverage_observation(
            audit_unit_uid=str(unit["audit_unit_uid"]),
            unit_fingerprint_sha256=str(unit["unit_fingerprint_sha256"]),
            reason_code=reason_code,
            missing_fields=missing_fields,
            evidence_refs=unit.get("event_refs") or (),
            dependency_hashes=unit.get("dependency_hashes") or (),
        )

    @staticmethod
    def _live_issue(
        hypothesis: Mapping[str, Any],
        *,
        offer: Mapping[str, Any],
        proof: Mapping[str, Any],
        function_name: str = "",
    ) -> dict[str, Any]:
        location = hypothesis.get("location") or {}
        return {
            "id": str(hypothesis["hypothesis_uid"]),
            "category": str(hypothesis["defect_family"]),
            "defect_class": str(hypothesis["defect_family"]),
            "description": "Bounded security hypothesis queued for Proof Engine validation.",
            "function": str(function_name or location.get("function_uid") or ""),
            "file": str(location.get("file") or ""),
            "line": int(location.get("start_line") or 0),
            "location": dict(location),
            "source": str(hypothesis.get("source_ref") or ""),
            "sink": str(hypothesis.get("sink_ref") or ""),
            "resource": str(hypothesis.get("resource_ref") or ""),
            "candidate_source": "hypothesis_hunter",
            "audit_unit_uid": str(hypothesis["audit_unit_uid"]),
            "candidate_disposition": "needs_review",
            # Preserve the exact system-produced offer as the immutable
            # producer domain for the later v4 audit binding.  The Hunter
            # model may only select identifiers from this offer (the strict
            # report schema rejects proof/offer replacement fields), and the
            # Registrar copies this value into the candidate artifact before
            # Validator model output is applied.  Live authority still
            # rebuilds and revalidates the offer; this copy is not a receipt.
            "hypothesis_offer": dict(offer),
            "security_hypothesis": dict(hypothesis),
            "proof_kernel_evaluation": dict(proof),
            "proof_kernel_input": {
                "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
                "proof_ir": dict(offer["proof_ir"]),
                "proof_obligation": dict(offer["proof_obligation"]),
                "selected_action_uids": list(hypothesis["evidence_action_uids"]),
            },
            "attribution": {
                "schema_version": "zscope.finding-attribution.v2",
                "discovered_by": ["hypothesis_hunter"],
                "discovery_details": [
                    {
                        "kind": "hypothesis_hunter",
                        "source_id": str(hypothesis["offer_uid"]),
                    }
                ],
                "decided_by": "unresolved",
                "decision_level": "none",
                "decision_details": {},
            },
        }
