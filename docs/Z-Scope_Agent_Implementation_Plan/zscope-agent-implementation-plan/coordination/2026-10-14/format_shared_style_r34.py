"""Format two coordinator changes, proving the entire AST remains identical."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import subprocess
import sys
from root_runtime_preflight_r23 import inspect_root_runtime

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
WORK=ROOT/".coordination/20261014/workspaces/coordinator-shared-style-r34"
OUT=ROOT/"artifacts/coordinator-shared-style-r34-20261017"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sys.platform=="linux" and not sys.flags.optimize and Path.cwd().resolve()==WORK
runtime=inspect_root_runtime(require_slot=True)
prep=read(OUT/"preparation.json")
assert all(sha(WORK/p)==digest for p,digest in prep["complete_before_style"].items())
assert all(sha(ROOT/p)==digest for p,digest in prep["root_inputs"].items())
paths=prep["style_only_paths"]
with (OUT/"black-format.log").open("w",encoding="utf-8") as stream:
    result=subprocess.run([sys.executable,"-m","black",*paths],cwd=WORK,stdout=stream,stderr=subprocess.STDOUT)
assert result.returncode==0
assert all(ast.dump(ast.parse((WORK/p).read_text(encoding="utf-8")))==ast.dump(ast.parse((OUT/"before"/p).read_text(encoding="utf-8"))) for p in paths)
assert all(sha(WORK/p)==digest for p,digest in prep["complete_before_style"].items() if p not in paths)
assert all(sha(ROOT/p)==digest for p,digest in prep["root_inputs"].items())
for p in paths:
    target=OUT/"candidate"/p
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((WORK/p).read_bytes())
receipt=dict(actual_task="/root",frozen_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),complete_inputs=prep["complete_before_style"]|{p:sha(WORK/p) for p in paths},original_preparation_sha256=sha(OUT/"preparation.json"),style_before_sha256={p:sha(OUT/"before"/p) for p in paths},style_after_sha256={p:sha(WORK/p) for p in paths},entire_AST_identical=True,all_other_1080_inputs_unchanged=True,root1065_unchanged=True,black_returncode=0,runtime=runtime,stage_intake=False,root_intake=False)
assert not (OUT/"input-freeze.json").exists()
(OUT/"input-freeze.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(style_after=receipt["style_after_sha256"],entire_AST_identical=True)))
