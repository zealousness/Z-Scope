"""Coordinator-owned fixed metadata projection, isolated from root and UI."""
from pathlib import Path
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
proof = json.loads((ROOT / "artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))
workspace = ROOT / ".coordination/20261014/workspaces/coordinator-lightweight-r18"
workspace.mkdir(exist_ok=False)
for name, sha in proof["after"].items():
    source = ROOT / name
    assert hashlib.sha256(source.read_bytes()).hexdigest() == sha
    target = workspace / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
source = workspace / "zscope/web/services.py"
old = source.read_text(encoding="utf-8")
needle = '"report_view_summary": metadata.get("report_view_summary"),'
assert old.count(needle) == 1
source.write_text(old.replace(needle, needle + '\n                "entry_instances": metadata.get("entry_instances"),\n                "job": metadata.get("job"),'), encoding="utf-8", newline="\n")
test = '''"""Fixed projection fields come from the already bound report snapshot."""
import json

from test_scan_jobs import make_project
from test_job_result_projection import SCANNER_SCRIPT, make_service, run_to_terminal
from zscope.reporting.job_result_projection import project_job_result
from zscope.web.services import ReportFeedbackService


def test_compact_report_preserves_distinct_instance_metadata_without_full_payload():
    instances = {"instance_analysis": [
        {"build_context_id": "base", "symbol_usr": "same-usr", "executed": True},
        {"build_context_id": "alt", "symbol_usr": "same-usr", "executed": False},
    ]}
    report = {"issues": [{"large": "private-payload"}], "metadata": {
        "entry_instances": instances, "job": {"job_id": "untrusted-display-value"},
        "arbitrary_runtime": "excluded",
    }}
    compact = ReportFeedbackService._lightweight_report(report)
    assert compact["metadata"]["entry_instances"] == instances
    assert compact["metadata"]["job"] == report["metadata"]["job"]
    assert "issues" not in compact
    assert "arbitrary_runtime" not in compact["metadata"]
    assert len(compact["metadata"]["entry_instances"]["instance_analysis"]) == 2


def test_missing_or_invalid_metadata_never_invents_instance_measurements():
    for report in ({}, {"metadata": None}, {"metadata": "legacy"}):
        compact = ReportFeedbackService._lightweight_report(report)
        assert compact["metadata"]["entry_instances"] is None
        assert compact["metadata"]["job"] is None


def test_actual_owner_projection_keeps_bound_instances_when_current_report_changes(tmp_path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    instances = {"instance_analysis": [
        {"build_context_id": "base", "symbol_usr": "usr-main", "confirmed": 0},
        {"build_context_id": "alt", "symbol_usr": "usr-main", "confirmed": 1},
    ]}
    metadata = {"entry_instances": instances, "job": {"job_id": "display-only-forged"}}
    script = SCANNER_SCRIPT.replace('BARE = {"issues": [FINDING]}',
        'REPORT["metadata"].update(' + repr(metadata) + ')\\nBARE = {"issues": [FINDING]}')
    scanner.write_text(script, encoding="utf-8")
    service = make_service(project, scanner, ["report"])
    job, terminal = run_to_terminal(service, request_id="r18-fixed-metadata")
    (project / "zscope_batch_report.json").write_text(json.dumps({"issues": [], "metadata": {
        "entry_instances": {"instance_analysis": [{"build_context_id": "foreign"}]}
    }}), encoding="utf-8")
    code, payload = project_job_result(service, job["job_id"], config_path=project / "zscope.yaml")
    assert code == 200 and payload["report_available"]
    assert payload["findings"]["report"]["metadata"]["entry_instances"] == instances
    assert payload["findings"]["report"]["metadata"]["job"] == metadata["job"]
    assert payload["binding"]["job_id"] == job["job_id"] != metadata["job"]["job_id"]
    assert payload["binding"]["run_id"] == terminal["run_id"]
    assert not payload["review_scope"]["shared_with_current"]
'''
(workspace / "tests/test_lightweight_instance_metadata.py").write_text(test, encoding="utf-8", newline="\n")
(HERE / "followups-r12/coordinator-lightweight-r18-baseline.json").write_text(json.dumps({"before": proof["after"], "workspace": str(workspace), "owns": ["zscope/web/services.py", "tests/test_lightweight_instance_metadata.py"]}, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"prepared": str(workspace), "root_product_changed": False}))
