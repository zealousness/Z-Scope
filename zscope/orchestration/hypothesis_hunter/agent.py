"""Strict one-call, repository-tool-free P4 Hypothesis Hunter."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Dict, Mapping

from ...agents.base import JsonOutputSpec, JsonToolAgent
from ...framework.base import AgentResponse
from .blind import assert_candidate_blind
from .models import HYPOTHESIS_HUNT_REPORT_VERSION, validate_hunt_report


HYPOTHESIS_HUNTER_CONTRACT = """Schedule bounded deterministic investigation.
Select only system-provided offer, fact, evidence, and EvidenceAction identifiers.
An EvidenceAction selection asks the Proof Engine to evaluate a frozen predicate; it
does not assert that the predicate succeeds and does not grant terminal authority.
For every risk-relevant offer, select the listed actions needed to evaluate its proof
clauses even when no supporting fact exists yet, because those actions produce the
facts. Do not invent predicates, parameters, coverage, candidate state, or a terminal
disposition. Emit exactly one strict report through the required terminal tool. Use
an empty selection only when no listed action can investigate the offer.
"""


def _bounded_report_schema(projection: Mapping[str, Any]) -> dict[str, Any]:
    unit = projection.get("audit_unit")
    unit = unit if isinstance(unit, Mapping) else {}
    offers = [value for value in projection.get("offers") or [] if isinstance(value, Mapping)]
    offer_ids = [str(value.get("offer_uid") or "") for value in offers]
    action_ids = sorted(
        {
            str(action.get("action_uid") or "")
            for offer in offers
            for action in offer.get("evidence_actions") or []
            if isinstance(action, Mapping)
        }
    )
    fact_ids = sorted(
        {
            str(value)
            for offer in offers
            for name in (
                "supporting_fact_refs",
                "opposing_fact_refs",
                "unknown_fact_refs",
            )
            for value in offer.get(name) or []
            if str(value)
        }
    )
    evidence_ids = [str(value) for value in projection.get("allowed_evidence_refs") or []]
    string_set = {"type": "array", "uniqueItems": True, "items": {"type": "string"}}
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "audit_unit_uid",
            "unit_fingerprint_sha256",
            "coverage_status",
            "selected_offers",
            "reviewed_evidence_refs",
            "unresolved_reasons",
        ],
        "properties": {
            "schema_version": {"const": HYPOTHESIS_HUNT_REPORT_VERSION},
            "audit_unit_uid": {"const": str(unit.get("audit_unit_uid") or "")},
            "unit_fingerprint_sha256": {"const": str(unit.get("unit_fingerprint_sha256") or "")},
            "coverage_status": {"enum": ["complete", "partial", "failed"]},
            "selected_offers": {
                "type": "array",
                "uniqueItems": True,
                "maxItems": len(offer_ids),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "offer_uid",
                        "evidence_action_uids",
                        "supporting_fact_refs",
                        "opposing_fact_refs",
                        "unknown_fact_refs",
                        "evidence_refs",
                    ],
                    "properties": {
                        "offer_uid": {"type": "string", "enum": offer_ids},
                        "evidence_action_uids": {
                            **deepcopy(string_set),
                            "minItems": 1,
                            "items": {"type": "string", "enum": action_ids},
                        },
                        "supporting_fact_refs": {
                            **deepcopy(string_set),
                            "items": {"type": "string", "enum": fact_ids},
                        },
                        "opposing_fact_refs": {
                            **deepcopy(string_set),
                            "items": {"type": "string", "enum": fact_ids},
                        },
                        "unknown_fact_refs": {
                            **deepcopy(string_set),
                            "items": {"type": "string", "enum": fact_ids},
                        },
                        "evidence_refs": {
                            **deepcopy(string_set),
                            "minItems": 1,
                            "items": {"type": "string", "enum": evidence_ids},
                        },
                    },
                },
            },
            "reviewed_evidence_refs": {
                **deepcopy(string_set),
                "items": {"type": "string", "enum": evidence_ids},
            },
            "unresolved_reasons": {
                **deepcopy(string_set),
                "maxItems": 16,
                "items": {"type": "string", "maxLength": 240},
            },
        },
    }
    return schema


class HypothesisHunterAgent(JsonToolAgent):
    """One strict structured terminal call with no repository tools."""

    def __init__(self, llm_client: Any) -> None:
        super().__init__(
            name="hypothesis_hunter",
            description="Selects bounded proof actions for one candidate-blind attack unit.",
            llm_client=llm_client,
            tools=[],
        )

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        projection = input_data.get("projection")
        audit_unit = input_data.get("audit_unit")
        offers = input_data.get("offers")
        if (
            not isinstance(projection, Mapping)
            or not isinstance(audit_unit, Mapping)
            or not isinstance(offers, list)
        ):
            return AgentResponse(
                success=False,
                data={},
                error="hypothesis hunter requires projection, audit_unit, and offers",
            )
        assert_candidate_blind(projection)
        rendered = json.dumps(projection, ensure_ascii=False, sort_keys=True)
        prompt = (
            "Call emit_hypothesis_hunt_report immediately and return no prose. This is action "
            "scheduling, not a vulnerability verdict: selecting an EvidenceAction requests "
            "deterministic proof replay. Select only listed identifiers. For each risk-relevant "
            "offer, select the listed actions that evaluate its proof clauses; do not require "
            "pre-existing supporting facts. Return no selections only if no listed action can "
            "investigate the offer.\n" + rendered
        )
        spec = JsonOutputSpec(
            type_name="hypothesis_hunt_report",
            schema=_bounded_report_schema(projection),
            final_tool_name="emit_hypothesis_hunt_report",
            final_tool_description="Emit the bounded P4 hypothesis selection report.",
            validator=lambda value: validate_hunt_report(
                value,
                audit_unit=audit_unit,
                offers=offers,
            )[0],
            metadata_prefix="hypothesis_hunter",
        )
        return self._run_json_conversation(
            self._messages({"agent_contract": HYPOTHESIS_HUNTER_CONTRACT}, prompt),
            extractor=lambda content, result, conversation: self._extract_structured_json_payload(
                content,
                result,
                conversation,
                spec,
            ),
            trace_label=f"audit_unit={audit_unit.get('audit_unit_uid') or ''}",
            parse_label="hypothesis_hunt_report JSON",
            retry_prompt="Call the required terminal tool once with a valid bounded report.",
            max_iterations=1,
            max_json_retries=0,
            fail_on_truncated=True,
            json_output_spec=spec,
            require_structured_finalization=True,
            single_pass_final_tool=True,
        )
