"""Check the completed Linux JUnit while the remaining quality commands run."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
OUT=ROOT/"artifacts/coordinator-final-composite-r33-20261017/independent"
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
preflight=json.loads((OUT/"preflight.json").read_text(encoding="utf-8"))
expected=sum((Counter({(row[0],row[1]):row[2] for row in rows}) for rows in preflight["prior_counters"].values()),Counter())
tree=ET.parse(OUT/"results.xml").getroot()
actual=Counter((n.get("classname",""),n.get("name","")) for n in tree.iter("testcase"))
assert sum(expected.values())==len(expected)==148 and actual==expected
assert not list(tree.iter("failure")) and not list(tree.iter("error")) and not list(tree.iter("skipped"))
path=OUT/"test-checkpoint.json"
assert not path.exists()
receipt=dict(actual_task="/root",checked_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),tests=148,failures=0,errors=0,skipped=0,all_four_prior_counters_exact=True,preflight_sha256=sha(OUT/"preflight.json"),junit_sha256=sha(OUT/"results.xml"),remaining_quality_commands_still_pending=True,stage_intake=False,root_intake=False,joint_validation_passed=False)
path.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(tests=148,exact_counters=True,remaining_quality_pending=True)))
