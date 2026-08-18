from zscope.reporting.attribution import (
    FindingAttribution,
    serialize_finding_attribution,
)


def test_finding_attribution_serializes_discovery_and_decision_independently() -> None:
    attribution = FindingAttribution(
        discovered_by=("hypothesis_hunter", "deterministic_rule"),
        discovery_details=(
            {"kind": "hypothesis_hunter", "source_id": "AU_1"},
            {"kind": "deterministic_rule", "source_id": "RULE_1"},
        ),
        decided_by="proof_engine",
        decision_level="V2",
        decision_details={"validation_cluster_uid": "VAL_1"},
    )

    payload = serialize_finding_attribution(attribution)

    assert payload["schema_version"] == "zscope.finding-attribution.v2"
    assert payload["discovered_by"] == [
        "deterministic_rule",
        "hypothesis_hunter",
    ]
    assert payload["decided_by"] == "proof_engine"
    assert payload["decision_level"] == "V2"
    assert attribution.validation_errors() == []


def test_finding_attribution_reports_invalid_values_without_silently_relabeling() -> None:
    attribution = FindingAttribution.from_mapping(
        {
            "discovered_by": ["benchmark_magic"],
            "decided_by": "oracle",
            "decision_level": "V9",
        }
    )

    assert attribution.validation_errors() == [
        "invalid discovered_by: benchmark_magic",
        "invalid decided_by: oracle",
        "invalid decision_level: V9",
    ]
