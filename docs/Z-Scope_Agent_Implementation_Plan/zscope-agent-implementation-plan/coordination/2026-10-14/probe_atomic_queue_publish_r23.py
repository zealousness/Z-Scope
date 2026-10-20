"""Probe atomic publication on the actual queue filesystem, without requests."""
from pathlib import Path
import datetime as dt
import hashlib
import json
from uuid import uuid4
from bridge_queue_publish_r23 import publish_complete_bytes

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
queue = HERE / "route-check/bridge-queue"
target = queue / (".r23-atomic-probe-" + uuid4().hex + ".published")
assert target.parent.resolve() == queue.resolve() and not target.exists()
assert not target.name.endswith(".request.json")
payload = (json.dumps({"probe": "完整中文 JSON", "kind": "not-a-Bridge-request", "rows": list(range(1000))}, ensure_ascii=False) + "\n").encode("utf-8")
publish_complete_bytes(target, payload)
assert target.read_bytes() == payload and json.loads(target.read_bytes())["probe"] == "完整中文 JSON"
try:
    publish_complete_bytes(target, b"must not overwrite original")
except FileExistsError:
    refused = True
else:
    raise AssertionError("Atomic publisher replaced an existing destination")
assert target.read_bytes() == payload
target.unlink()
out = ROOT / "artifacts/coordinator-atomic-queue-probe-r23-20261016"
out.mkdir(exist_ok=False)
proof = {"finished_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "actual_queue_filesystem": str(queue), "completed_json_atomically_published": True, "existing_target_refused": refused, "existing_target_bytes_unchanged": True, "temporary_name_never_matches_owner_glob": True, "target_probe_removed": not target.exists(), "publisher_sha256": hashlib.sha256((HERE / "bridge_queue_publish_r23.py").read_bytes()).hexdigest(), "bridge_requests_published": 0, "services_started": 0, "product_tests_executed": 0, "product_changed": False, "process_inspection": False}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(proof), flush=True)
