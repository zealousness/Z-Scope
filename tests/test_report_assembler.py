from pathlib import Path

from zscope.reporting.report import ReportGenerator
from zscope.reporting.assembler import ReportAssembler


class FakeSnapshotStore:
    def __init__(self):
        self.saved = None

    def save_final_report(self, entry_func, report, location):
        self.saved = {
            "entry_func": entry_func,
            "report": report,
            "location": location,
        }


def test_report_assembler_builds_views_and_persists(tmp_path: Path) -> None:
    snapshot_store = FakeSnapshotStore()
    resolved = []

    def resolve_issues(items):
        resolved.append(len(items))

    def dedupe(items):
        return items[:1]

    assembler = ReportAssembler(
        ReportGenerator(tmp_path),
        snapshot_store,
        resolve_issue_locations=resolve_issues,
        deduplicate_observations=dedupe,
        metadata_factory=lambda state: {"run_id": state["run_id"], "version": "test"},
    )
    state = {
        "run_id": "RUN1",
        "entry_func": "entry",
        "agent_context": {"location": "src/demo.c:1"},
        "issues": [
            {
                "id": "ISSUE_1",
                "function": "entry",
                "location": "src/demo.c:10",
                "category": "memory_leak",
                "subcategory": "memory_leak",
                "description": "leak",
                "root_cause": "missing free",
                "suggested_fix": "free it",
                "confidence": 0.9,
                "impact_level": "medium",
            }
        ],
        "verified_hist_issues": [],
        "observations": [{"id": "OBS_1"}, {"id": "OBS_2"}],
        "notes": [],
        "any_failure": False,
    }

    report = assembler.build(state)
    saved = assembler.persist(state)

    assert report.overall_verdict == "issues_found"
    assert report.metadata["run_id"] == "RUN1"
    assert state["observations"] == [{"id": "OBS_1"}]
    assert "report_view_summary" in saved["metadata"]
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()
    assert snapshot_store.saved["entry_func"] == "entry"
    assert resolved == [1, 2]


def test_report_assembler_preserves_returned_report_metadata(tmp_path: Path) -> None:
    assembler = ReportAssembler(
        ReportGenerator(tmp_path),
        None,
        resolve_issue_locations=lambda items: None,
        deduplicate_observations=lambda items: items,
        metadata_factory=lambda state: {"run_id": state["run_id"]},
    )

    report = assembler.finalize_returned_report(
        {
            "run_id": "NEW",
            "final_report_dict": {"metadata": {"existing": True}},
        }
    )

    assert report["metadata"] == {"existing": True, "run_id": "NEW"}


def test_report_assembler_includes_needs_review_observation_with_recovered_location_in_review_view(
    tmp_path: Path,
) -> None:
    assembler = ReportAssembler(
        ReportGenerator(tmp_path),
        None,
        resolve_issue_locations=lambda items: None,
        deduplicate_observations=lambda items: items,
        metadata_factory=lambda state: {"run_id": state["run_id"], "version": "test"},
    )
    state = {
        "run_id": "RUN2",
        "entry_func": "entry",
        "agent_context": {"location": "src/demo.c:1"},
        "issues": [],
        "verified_hist_issues": [],
        "observations": [
            {
                "id": "OBS_1",
                "function": "sink_func",
                "location": "",
                "category": "memory_leak",
                "subcategory": "memory_leak",
                "validation_status": "needs_review",
                "finding_kind": "needs_review",
                "description": "candidate retained for review",
                "root_cause": "missing cleanup",
                "confidence": 0.7,
                "impact_level": "medium",
                "evidence_pack": {
                    "finding_summary": {"location": "src/recovered.c:88"},
                },
            }
        ],
        "notes": [],
        "any_failure": False,
    }

    report = assembler.build(state)

    with_review = report.report_views["with_needs_review"]["issues"]
    assert len(with_review) == 1
    assert with_review[0]["validation_status"] == "needs_review"
    assert with_review[0]["location"] == "src/recovered.c:88"
    assert with_review[0]["line"] == 88
