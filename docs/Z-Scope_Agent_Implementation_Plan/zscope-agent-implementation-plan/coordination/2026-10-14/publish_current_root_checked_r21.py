"""Recheck live bytes immediately before invoking the unchanged strict publisher."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-r21-verified-environment-20261015"
source = json.loads((out / "source-evidence.json").read_text(encoding="utf-8"))
assert len(source["commands"]) == 6 and all(r["returncode"] == 0 for r in source["commands"])
assert source["direct_source_unchanged"] and source["before"] == source["after"]
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_current = hashlib.sha256(native.read_bytes()).hexdigest()
assert native_current == source["native_before"] == source["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
publisher = HERE / "publish_joint_r21.py"
publisher_sha = hashlib.sha256(publisher.read_bytes()).hexdigest()
assert source["after"][publisher.relative_to(ROOT).as_posix()] == publisher_sha
review_path = ROOT / "artifacts/root-launcher-review-r21-20261016/review.json"
assert review_path.exists(), "wait for independent launcher source review before publication"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert hashlib.sha256(review_path.read_bytes()).hexdigest() == "5f09382311979177687afb376c4037b2022331065b076d8130aa08b6488c9626"
# Explicit blocking findings must be resolved before publishing, without
# weakening any executed test/quality gate or silently editing frozen inputs.
assert review["source_review_passed"] and review["blocking_findings"] == []
assert review["tests_executed"] == 0 and not review["product_changed"]
receipt = {"captured_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "native_current_sha256": native_current, "native_execution": False, "all_current_root_hashes_match_tested_after": True, "source_input_count": len(source["after"]), "publisher_sha256": publisher_sha, "publisher_unchanged_from_tested_input": True, "independent_launcher_review": review_path.relative_to(ROOT).as_posix(), "independent_launcher_review_sha256": hashlib.sha256(review_path.read_bytes()).hexdigest(), "clock_adjusted": False, "tests_modified": False, "quality_gates_modified": False, "whole_package_acceptance": False}
target = out / "publication-preflight.json"
assert not target.exists() and not (out / "review.json").exists()
target.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt), flush=True)
result = subprocess.run([sys.executable, str(publisher)], cwd=ROOT)
sys.exit(result.returncode)
