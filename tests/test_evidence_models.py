from zscope.core.candidates.evidence_models import build_evidence_models


def test_build_evidence_models_preserves_four_fact_domains() -> None:
    models = build_evidence_models(
        {
            "source": "packet_len",
            "sink": "memcpy(dst, src, packet_len)",
            "resource_signature": "session",
            "entry_function": "handle_packet",
            "evidence_pack": {
                "value_flow": {"ranges": {"packet_len": [0, 4096]}},
                "ownership": {"transitions": ["allocated", "published", "freed"]},
                "concurrency": {"lockset": ["session_lock"]},
                "contract": {"error_paths": ["parse failure"]},
                "path": {"complete_to_entry": True},
            },
        }
    )

    assert set(models) == {
        "value_flow",
        "ownership_typestate",
        "concurrency",
        "cross_procedure_contract",
    }
    assert models["value_flow"]["ranges"]["packet_len"] == [0, 4096]
    assert models["cross_procedure_contract"]["complete_to_entry"] is True


def test_build_evidence_models_does_not_infer_missing_safety_facts() -> None:
    assert build_evidence_models({"category": "bounds"}) == {}
