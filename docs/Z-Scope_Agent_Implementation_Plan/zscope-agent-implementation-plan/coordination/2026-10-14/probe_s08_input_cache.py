"""Review a new S08 input-binding defect using a dummy, offline project."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORKSPACE = ROOT / ".coordination/20261014/workspaces/s08-owner"
sys.path.insert(0, str(WORKSPACE))
spec = importlib.util.spec_from_file_location("s08_review_config_fixture", WORKSPACE / "tests/test_config_v2.py")
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.jobs.fingerprint import compute_input_fingerprint

out = HERE / "review-repro/s08-input-cache"
if out.exists():
    raise SystemExit("review output already exists; inspect, do not overwrite")
project = out / "synthetic-project"
project.mkdir(parents=True)
source = project / "unit.c"
source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
config = fixture._write(project, fixture._config(project))
service_source = WORKSPACE / "zscope/orchestration/jobs/service.py"
before_code = hashlib.sha256(service_source.read_bytes()).hexdigest()
service = ScanJobService(config, spawn_owner=False)
initial = service._fingerprint(scan_depth=None)
time.sleep(0.1)
source.write_text("int main(void) { return 1234; }\n", encoding="utf-8")
cached_after = service._fingerprint(scan_depth=None)
fresh_after = compute_input_fingerprint(config, scan_depth=None)
result = {
    "synthetic_only": True, "no_scanner_or_model_started": True,
    "service_sha256": before_code,
    "service_bytes_stable_during_probe": before_code == hashlib.sha256(service_source.read_bytes()).hexdigest(),
    "initial_revision": initial["sha256"], "cached_after_revision": cached_after["sha256"],
    "fresh_after_revision": fresh_after["sha256"],
    "source_change_detected_by_fresh_computation": fresh_after["sha256"] != initial["sha256"],
    "cached_service_missed_source_change": cached_after["sha256"] == initial["sha256"] != fresh_after["sha256"],
}
(out / "review.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result))
