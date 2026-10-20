"""Preserve the mistaken flag receipt and run the actual read-only asset verifier."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-current-integration-20261014"
path = OUT / "source-evidence.json"
proof = json.loads(path.read_text(encoding="utf-8"))
assert proof["direct_source_unchanged"]
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name, sha in proof["after"].items())
assert proof["commands"][-1]["returncode"] == 2 and proof["commands"][-1]["command"][-1] == "--verify"
command = [sys.executable, "scripts/portable/web_assets.py"]
started = dt.datetime.now(dt.timezone.utc).isoformat()
result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
(OUT / "command-6-corrected-web-assets.log").write_text(result.stdout + result.stderr, encoding="utf-8")
correction = {"command": command, "started_at": started, "returncode": result.returncode,
              "log": "artifacts/coordinator-current-integration-20261014/command-6-corrected-web-assets.log",
              "corrects_usage_error_of": "command-5.log", "original_failed_receipt_preserved": True}
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name, sha in proof["after"].items())
proof["correction"] = correction
proof["quality_success_after_command_correction"] = result.returncode == 0 and all(item["returncode"] == 0 for item in proof["commands"][:-1])
path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(correction))
raise SystemExit(result.returncode)
