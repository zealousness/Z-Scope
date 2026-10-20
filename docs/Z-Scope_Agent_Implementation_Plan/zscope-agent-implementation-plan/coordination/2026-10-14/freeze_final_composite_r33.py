"""Bind formatting-only coordinator probe copy without touching old evidence."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
WORK=ROOT/".coordination/20261014/workspaces/coordinator-final-composite-r33"
OUT=ROOT/"artifacts/coordinator-final-composite-r33-20261017"
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
prep=json.loads((OUT/"preparation.json").read_text(encoding="utf-8"))
owned=prep["coordinator_owned_probe_style_path"]
original=ROOT/"artifacts/coordinator-native-classifier-probes-r33-20261017/test_native_classifier_currentness_r33.py"
assert all(sha(WORK/path)==digest for path,digest in prep["complete_before_probe_style"].items() if path!=owned)
assert ast.dump(ast.parse((WORK/owned).read_text(encoding="utf-8")))==ast.dump(ast.parse(original.read_text(encoding="utf-8")))
assert not (OUT/"input-freeze.json").exists()
receipt=dict(actual_task="/root",frozen_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),complete_inputs=prep["complete_before_probe_style"]|{owned:sha(WORK/owned)},original_preparation_sha256=sha(OUT/"preparation.json"),original_probe_sha256=sha(original),formatted_probe_sha256=sha(WORK/owned),probe_entire_AST_identical=True,producer_owned_product_and_tests_unchanged=True,stage_intake=False,root_intake=False)
(OUT/"input-freeze.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(inputs=len(receipt["complete_inputs"]),probe_sha256=receipt["formatted_probe_sha256"])))
