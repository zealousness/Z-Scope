"""Capture actual root source bytes and known test evidence for a handoff stage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import datetime as dt
import xml.etree.ElementTree as ET
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
names = {item["path"] for item in baseline["files"]}
for receipt in HERE.glob("intake-*.json"):
    names.update(item["path"] for item in json.loads(receipt.read_text(encoding="utf-8"))["files"])
names.update({"zscope/web/acceptance_service.py", "zscope/web/scan_jobs_service.py",
              "tests/test_acceptance_http_api.py", "tests/test_scan_jobs_http_api.py",
              "zscope/web/static/dashboard_workbench.js", "zscope/web/static/dashboard_workbench.css",
              "tests/test_agent_workbench_ui.py", "tests/fixtures/agent_workbench_ui.cjs"})
names.add("tests/test_agent_integration_boundaries.py")
rows = []
missing = []
for name in sorted(names):
    file = ROOT / name
    if file.is_file():
        rows.append({"path": name, "sha256": hashlib.sha256(file.read_bytes()).hexdigest()})
    else:
        missing.append(name)
manifest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
tests = {}
for relative in ("artifacts/coordinator-jobs-final-20261014/results.xml",
                 str((HERE / "docs-after-jobs-integration.xml").relative_to(ROOT))):
    file = ROOT / relative
    tests[relative] = [dict(s.attrib) for s in ET.parse(file).getroot().findall("testsuite")]
old21 = ROOT / ".coordination/20261014/snapshot/docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/21_IMPLEMENTATION_STATUS.md"
new21 = ROOT / "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/21_IMPLEMENTATION_STATUS.md"
history_preserved = new21.read_bytes().startswith(old21.read_bytes())
out = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "scope": "current_root_source_stage_not_whole_package_acceptance",
       "source_manifest_sha256": manifest, "files": rows, "missing_baseline_files": missing,
       "original_21_history_prefix_preserved": history_preserved,
       "test_collections_do_not_sum": True, "tests": tests,
       "pending": ["S01_full_instance_analysis_and_cdb_reconciliation", "S08_JOB04_JOB06_real_scanner_wiring", "U01_complete_config_migration_and_consumers", "full_S07", "formal_S09", "other_DAG_scope"],
       "reserved_observation_thread": "user-confirmed delivered and archived; no old-round operation; independent acceptance not performed",
       "reserved_protocol_files_are_external_user_changes_not_coordinator_delivery": True}
(HERE / (sys.argv[1] if len(sys.argv) > 1 else "stage-source-evidence.json")).write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: value for key, value in out.items() if key != "files"}, ensure_ascii=False))
