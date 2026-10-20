"""Require fresh live bytes and independent launcher review before publication."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016"

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

assert not (OUT / "review.json").exists() and not (OUT / "publication-guard.json").exists()
source = read(OUT / "source-evidence.json")
assert source["before"] == source["after"] and source["direct_source_unchanged"]
assert len(source["commands"]) == 6 and all(r["returncode"] == 0 for r in source["commands"])
assert all(sha(ROOT / p) == h for p, h in source["after"].items())
review_path = ROOT / "artifacts/root-launcher-review-r23-20261016/final-review.json"
review = read(review_path)
assert review["source_review_passed"] and review["tests_executed"] == 0
required = {str((HERE / name).relative_to(ROOT)) for name in ("intake_ui_r23.py", "verify_current_root_r23.py", "verify_joint_with_clock_r23.py", "root_runtime_preflight_r23.py", "publish_joint_r23.py", "publish_current_root_checked_r23.py")}
assert set(review["reviewed_hashes"]) == required
assert all(source["after"][p] == h == sha(ROOT / p) for p, h in review["reviewed_hashes"].items())
assert sha(Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")) == source["native_after"]
guard = {"at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "live_source_matches": True, "source_inputs": len(source["after"]), "source_evidence_sha256": sha(OUT / "source-evidence.json"), "review_sha256": sha(review_path), "publisher_sha256": sha(HERE / "publish_joint_r23.py"), "native_sha256": source["native_after"], "wsl_process_inspection": False}
(OUT / "publication-guard.json").write_text(json.dumps(guard, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
result = subprocess.run([sys.executable, str(HERE / "publish_joint_r23.py")])
assert result.returncode == 0
assert all(sha(ROOT / p) == h for p, h in source["after"].items())
assert sha(review_path) == guard["review_sha256"]
sys.exit(result.returncode)
