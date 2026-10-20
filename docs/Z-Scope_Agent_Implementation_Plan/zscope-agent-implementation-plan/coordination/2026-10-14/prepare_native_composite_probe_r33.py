"""Add a coordinator-only probe without rewriting the original 1079-input receipt."""
from pathlib import Path
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-native-composite-r33-20261017"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-native-composite-r33"
SOURCE = ROOT / "artifacts/coordinator-native-classifier-probes-r33-20261017/test_native_classifier_currentness_r33.py"
TARGET = WORK / "tests/test_native_classifier_currentness_r33.py"
prep = json.loads((OUT / "preparation.json").read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert not TARGET.exists() and not (OUT / "probe-preparation.json").exists()
assert all(sha(WORK / path) == digest for path, digest in prep["complete_inputs"].items())
shutil.copyfile(SOURCE, TARGET)
assert sha(SOURCE) == sha(TARGET)
receipt = dict(actual_task="/root", previous_preparation_sha256=sha(OUT / "preparation.json"), frozen_external_probe=str(SOURCE), frozen_external_probe_sha256=sha(SOURCE), complete_inputs=prep["complete_inputs"] | {"tests/test_native_classifier_currentness_r33.py": sha(TARGET)}, stage_intake=False, root_intake=False)
(OUT / "probe-preparation.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(inputs=len(receipt["complete_inputs"]), probe_sha256=sha(SOURCE))))
