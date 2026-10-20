"""Authorize a necessary native receipt extension only in the new isolated successor."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017"
PREP = OUT / "preparation.json"
data = json.loads(PREP.read_text(encoding="utf-8"))
WORK = ROOT / data["workspace"]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
added = ["native/clang-indexer/main.cpp", "zscope/retrieval/build_context.py", "zscope/orchestration/jobs/scan_work.py"]
assert all(sha(WORK / p) == data["complete_inputs"][p] for p in added)
assert all(sha(ROOT / p) == v for p, v in data["root_inputs"].items())
old_tool = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
assert sha(old_tool) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
receipt = dict(actual_coordinator_task="/root", logical_task=data["logical_task"], actual_worker_task=data["actual_task"], authorized_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), original_preparation_sha256=sha(PREP), workspace=data["workspace"], added_paths={p: sha(WORK / p) for p in added}, allowed_implementation_scope="Complete ordinary include lookup receipt; Python currentness consumer and exact output producer wiring. HasInclude receipts stay independent; no basename-only authority.", original_tool_sha256=sha(old_tool), original_tool_readonly=True, new_tool_requires_real_build=True, new_tool_prefix_must_be_separate=True, native_receipt_plan_source_review_required_before_product_edits=True, codec_source_readonly=True, root1065_unchanged=True, stage_write=False, root_write=False, cost_failed_deliveries_preserved=1, s01_failed_deliveries_preserved=3)
target = OUT / "ownership-extension-native.json"
assert not target.exists()
target.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(extension_sha256=sha(target), added_paths=added, old_tool_unchanged=True)))
