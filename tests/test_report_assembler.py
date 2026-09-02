from pathlib import Path

from zscope.orchestration.candidates import CandidateLedger
from zscope.orchestration.subagents import SubAgentTicket
from zscope.reporting.report import FinalReport, Issue, ReportGenerator
from zscope.reporting.assembler import ReportAssembler


class FakeSnapshotStore:
    def __init__(self):
        self.saved = None

    def save_final_report(self, index_name, report):
        self.saved = {
            "index_name": index_name,
            "report": report,
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
        "entry_index_name": "entry@src/demo.c:1-20",
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
    assert [item["id"] for item in state["observations"]] == ["OBS_1"]
    assert state["observations"][0]["candidate_schema_version"] == "zscope.candidate.v3.3"
    assert state["observations"][0]["run_issue_uid"].startswith("RUNISSUE_")
    assert saved["schema_version"] == 2
    assert saved["finding_status"] == "confirmed"
    assert saved["completeness"] == "complete"
    assert saved["run_manifest"]["run_id"] == "RUN1"
    assert "report_view_summary" in saved["metadata"]
    funnel = saved["metadata"]["candidate_funnel"]
    assert funnel["schema_version"] == "zscope.candidate-funnel.v1"
    assert funnel["stages"]["reported_findings"]["count"] == 1
    assert funnel["contract"]["linear_conversion_rates_valid"] is False
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()
    assert snapshot_store.saved["index_name"] == "entry@src/demo.c:1-20"
    assert resolved == [1, 2]


def test_report_assembler_can_skip_root_report_files(tmp_path: Path) -> None:
    snapshot_store = FakeSnapshotStore()
    assembler = ReportAssembler(
        ReportGenerator(tmp_path),
        snapshot_store,
        resolve_issue_locations=lambda items: None,
        deduplicate_observations=lambda items: items,
        metadata_factory=lambda state: {"run_id": state["run_id"]},
    )
    state = {
        "run_id": "RUN_BATCH",
        "entry_func": "entry",
        "entry_index_name": "entry@src/demo.c:1-20",
        "agent_context": {"location": "src/demo.c:1"},
        "issues": [],
        "verified_hist_issues": [],
        "observations": [],
        "notes": [],
        "any_failure": False,
    }

    assembler.build(state)
    saved = assembler.persist(state, write_root_reports=False)

    assert saved["entry_function"] == "entry"
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.md").exists()
    assert snapshot_store.saved["index_name"] == "entry@src/demo.c:1-20"


def test_markdown_report_includes_final_needs_review_view(tmp_path: Path) -> None:
    review = {
        "id": "OBS_1",
        "function": "entry",
        "location": "src/demo.c:10",
        "category": "reliability",
        "subcategory": "contract",
        "description": "The caller contract is uncertain.",
        "root_cause": "The input range is undocumented.",
        "suggested_fix": "Review the caller contract.",
        "confidence": 0.5,
        "impact_level": "medium",
        "candidate_disposition": "needs_review",
    }
    report = FinalReport(
        entry_function="entry",
        overall_verdict="no_issue_found",
        issues=[],
        report_views={"with_needs_review": {"issues": [review]}},
        finding_status="needs_review",
    )

    ReportGenerator(tmp_path).save_markdown_report(report)
    content = (tmp_path / "report.md").read_text(encoding="utf-8")

    assert "未发现已确认缺陷；存在待复核项。" in content
    assert "## 待复核问题" in content
    assert "The caller contract is uncertain." in content
    assert "*No needs_review observations.*" not in content


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


def test_report_assembler_terminalizes_and_routes_pending_ledger_candidates(
    tmp_path: Path,
) -> None:
    ledger = CandidateLedger(
        project_id="demo",
        project_root=str(tmp_path),
        revision="rev",
    )
    ledger.add(
        SubAgentTicket(
            id="CANDIDATE_1",
            skill="bounds_and_integer",
            task="Length can exceed the destination buffer.",
            trigger="memcpy",
            line=42,
            context_slice="memcpy(dst, src, len);",
            priority_score=85,
            origin="src/demo.c:40:len",
            sink="src/demo.c:42:memcpy",
            evidence={
                "function": "copy_message",
                "defect_class": "buffer_overflow",
                "source": {"file": "src/demo.c", "line": 40},
                "sink": {"file": "src/demo.c", "line": 42},
                "candidate_payload": {
                    "id": "CANDIDATE_1",
                    "function": "copy_message",
                    "location": "src/demo.c:42",
                    "category": "buffer_overflow",
                    "description": "Length can exceed the destination buffer.",
                },
            },
        ),
        source="clang_ast_cfg",
        call_path=["entry", "copy_message"],
        record_role="validation_obligation",
        entry_identity="src/demo.c::int entry(void)",
    )
    assembler = ReportAssembler(
        ReportGenerator(tmp_path),
        None,
        resolve_issue_locations=lambda items: None,
        deduplicate_observations=lambda items: items,
        metadata_factory=lambda state: {"run_id": state["run_id"]},
    )
    state = {
        "run_id": "RUN_LEDGER",
        "entry_func": "entry",
        "entry_identity": "src/demo.c::int entry(void)",
        "entry_index_name": "entry@src/demo.c:1-50",
        "issues": [],
        "verified_hist_issues": [],
        "observations": [],
        "notes": [],
        "any_failure": False,
        "candidate_ledger": ledger,
        "candidate_lifecycle_snapshot": ledger.lifecycle_snapshot(
            entry_identity="src/demo.c::int entry(void)"
        ),
    }

    report = assembler.build(state)

    # A queued candidate is an unfinished operational obligation, never a
    # security review row manufactured by report assembly.
    assert state["observations"] == []
    assert report.report_views["with_needs_review"]["issue_count"] == 0
    assert report.candidate_terminal_states == []
    assert report.completeness == "degraded"


def test_report_assembler_does_not_read_mutable_shared_ledger(tmp_path: Path) -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")
    ledger.add(
        SubAgentTicket(
            id="LEAD",
            skill="bounds",
            task="investigate",
            trigger="copy",
            line=1,
            context_slice="",
            priority_score=20,
            origin="src/demo.c:1",
            sink="src/demo.c:2",
        ),
        source="source_rule",
        call_path=["other_entry", "sink"],
    )
    assembler = ReportAssembler(
        ReportGenerator(tmp_path),
        None,
        resolve_issue_locations=lambda items: None,
        deduplicate_observations=lambda items: items,
        metadata_factory=lambda state: {"run_id": state["run_id"]},
    )
    state = {
        "run_id": "RUN_PURE",
        "entry_func": "entry",
        "issues": [],
        "verified_hist_issues": [],
        "observations": [],
        "notes": [],
        "any_failure": False,
        "candidate_ledger": ledger,
    }

    assembler.build(state)
    assert state["observations"] == []


def test_report_assembler_marks_undrained_validation_queue_incomplete(
    tmp_path: Path,
) -> None:
    assembler = ReportAssembler(
        ReportGenerator(tmp_path),
        None,
        resolve_issue_locations=lambda items: None,
        deduplicate_observations=lambda items: items,
        metadata_factory=lambda state: {"run_id": state["run_id"]},
    )
    state = {
        "run_id": "UNDRAINED",
        "entry_func": "entry",
        "agent_context": {"location": "src/demo.c:1"},
        "issues": [],
        "verified_hist_issues": [],
        "observations": [],
        "notes": [],
        "any_failure": False,
        "validation_queue_drained": False,
        "budget_exhaustion_policy": "observe",
    }

    assembler.build(state)
    saved = assembler.persist(state, write_root_reports=False)

    assert saved["completeness"] == "degraded"
    assert saved["run_manifest"]["valid"] is False
    assert saved["run_manifest"]["validation_queue_drained"] is False
    assert saved["run_manifest"]["release_gate_status"]["runtime_valid"] is False
    assert (
        "validation_queue_not_drained" in saved["run_manifest"]["release_gate_status"]["blockers"]
    )
