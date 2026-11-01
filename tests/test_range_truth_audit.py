import hashlib
import json
from pathlib import Path

from zscope.benchmarking.protocol import issue_matches


ROOT = Path(__file__).resolve().parents[1]
RANGE_ROOT = ROOT / "test" / "range"
TRUTH_PATH = RANGE_ROOT / "benchmark" / "ground_truth.json"
AUDIT_PATH = (
    RANGE_ROOT
    / "benchmark"
    / "maintenance"
    / "formal_verification_non_gt_audit.v1.json"
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _truth_by_id() -> dict[str, dict]:
    truth = _load(TRUTH_PATH)
    return {str(record["id"]): record for record in truth["vulnerabilities"]}


def test_range_v17_truth_count_ids_and_audit_retirements() -> None:
    truth = _load(TRUTH_PATH)
    records = truth["vulnerabilities"]
    ids = [str(record["id"]) for record in records]

    assert truth["version"] == 17
    assert truth["total_vulnerabilities"] == 141
    assert len(records) == 141
    assert len(ids) == len(set(ids))
    assert {f"ISSUE44-{index:03d}" for index in range(4, 11)} <= set(ids)
    assert {
        "RANGE-043",
        "RANGE-044",
        "ISSUE42-015",
        "ISSUE42-018",
        "ISSUE44-002",
    }.isdisjoint(ids)

    excluded = {str(record["id"]) for record in truth["excluded_vulnerabilities"]}
    assert {
        "RANGE-043",
        "RANGE-044",
        "ISSUE42-015",
        "ISSUE42-018",
        "ISSUE44-002",
    } <= excluded


def test_non_gt_audit_is_bound_to_current_fixture_sources() -> None:
    audit = _load(AUDIT_PATH)
    assert audit["schema_version"] == "zscope.range-independent-finding-audit.v1"
    assert len(audit["records"]) == 20

    for relative, expected in audit["source_snapshot"].items():
        actual = hashlib.sha256((RANGE_ROOT / relative).read_bytes()).hexdigest()
        assert actual == expected

    decisions = {int(record["csv_row"]): record for record in audit["records"]}
    assert {
        row: decisions[row]["truth_id"]
        for row in (1, 2, 7, 11, 22, 35, 43)
    } == {
        1: "ISSUE44-004",
        2: "ISSUE44-005",
        7: "ISSUE44-006",
        11: "ISSUE44-007",
        22: "ISSUE44-008",
        35: "ISSUE44-009",
        43: "ISSUE44-010",
    }
    assert {row: decisions[row]["truth_id"] for row in (6, 26, 30)} == {
        6: "RANGE-038",
        26: "ISSUE42-004",
        30: "ISSUE42-025",
    }
    assert decisions[39]["classification"] == "provable_fp"
    assert decisions[42]["classification"] == "provable_fp"
    assert decisions[42]["related_truth_id"] == "RANGE-045"


def test_existing_truth_anchors_cover_only_the_verified_root_mappings() -> None:
    truth = _truth_by_id()

    assert issue_matches(
        {
            "category": "memory_leak",
            "function": "_lifecycle_customize_transport_cleanup",
            "location": "src/lifecycle.c:605",
        },
        truth["RANGE-038"],
        line_tolerance=2,
    )
    assert issue_matches(
        {
            "category": "reader_state_race",
            "function": "_runtime_accept_session_frame",
            "location": "src/lifecycle.c:2871",
        },
        truth["ISSUE42-004"],
        line_tolerance=4,
    )
    assert issue_matches(
        {
            "category": "state_machine",
            "function": "_runtime_publish_process_record",
            "location": "src/lifecycle.c:2940",
        },
        truth["ISSUE42-025"],
        line_tolerance=4,
    )

    assert not issue_matches(
        {
            "category": "semantic_mismatch",
            "function": "_runtime_schedule_sleep_window",
            "location": "src/lifecycle.c:2268",
            "description": "A generated contract expects a cumulative eight-packet threshold.",
        },
        truth["ISSUE42-001"],
        line_tolerance=4,
    )
    assert not issue_matches(
        {
            "category": "memory_leak",
            "function": "td_handle_mesh_message",
            "location": "src/main.c:389",
            "description": "A generated contract expects duplicate-key EXPIRE to be idempotent.",
        },
        truth["RANGE-038"],
        line_tolerance=4,
    )


def test_definite_source_anchor_repairs_are_frozen() -> None:
    truth = _truth_by_id()
    expected = {
        "RANGE-009": (87, 87),
        "REAL-010": (1333, 1339),
        "REAL-016": (1400, 1409),
        "REAL-018": (1424, 1434),
        "REAL-019": (1436, 1446),
        "REAL-021": (1461, 1470),
        "REAL-022": (1472, 1480),
        "REAL-024": (1495, 1504),
        "REAL-025": (1506, 1515),
        "REAL-027": (1530, 1537),
        "REAL-028": (1539, 1548),
    }
    for truth_id, line_range in expected.items():
        assert (truth[truth_id]["line"], truth[truth_id]["end_line"]) == line_range
    assert (
        truth["REAL-032"]["secondary_line"],
        truth["REAL-032"]["secondary_end_line"],
    ) == (1424, 1434)
