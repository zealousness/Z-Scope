import json
from pathlib import Path

from zscope.orchestration.decision_trace import (
    DECISION_TRACE_MANIFEST_VERSION,
    DecisionTraceStore,
    load_decision_trace,
    verify_coverage_trace,
    verify_decision_trace,
)


def test_decision_trace_contract_persists_and_reverifies_offline(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_CONTRACT")
    store.append_event(
        "VAL_CONTRACT",
        stage="provider",
        actor="deterministic_provider",
        reason_code="FACT_UNKNOWN",
        details={"fact_uid": "FACT_CONTRACT"},
    )
    store.record_coverage_event(
        "AUDIT_CONTRACT",
        reason_code="PRODUCER_NO_SIGNAL",
        producer="candidate_blind_discovery",
        details={"function": "contract_entry"},
    )

    trace = store.trace("VAL_CONTRACT")
    assert verify_decision_trace(trace) == (True, "ok")
    persisted = next((tmp_path / "decision_traces").glob("*.json"))
    assert load_decision_trace(persisted) == trace

    manifest = store.snapshot()
    assert manifest["schema_version"] == DECISION_TRACE_MANIFEST_VERSION
    coverage_record = manifest["coverage_traces"]["AUDIT_CONTRACT"]
    coverage = json.loads((tmp_path / coverage_record["path"]).read_text(encoding="utf-8"))
    assert verify_coverage_trace(coverage) == (True, "ok")


def test_decision_trace_contract_rejects_rehashed_content_tampering(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    store.append_event(
        "VAL_TAMPER",
        stage="provider",
        actor="deterministic_provider",
        reason_code="FACT_UNKNOWN",
    )
    trace = store.trace("VAL_TAMPER")
    trace["events"][0]["reason_code"] = "FACT_VERIFIED_TRUE"

    valid, reason = verify_decision_trace(trace)

    assert valid is False
    assert "hash mismatch" in reason
