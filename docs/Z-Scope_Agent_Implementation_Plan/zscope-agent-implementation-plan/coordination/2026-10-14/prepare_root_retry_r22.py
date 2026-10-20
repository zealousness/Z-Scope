"""One complete unchanged-product retry after explicit parallel/serial probes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
previous = ROOT / "artifacts/coordinator-r21-verified-environment-20261015"
source = json.loads((previous / "source-evidence.json").read_text(encoding="utf-8"))
assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest() == h for p,h in source["after"].items())
probe_path = ROOT / "artifacts/subagent-parallel-probe-r22-20261016/review.json"
probe = json.loads(probe_path.read_text(encoding="utf-8"))
assert probe["before"] == probe["after"] and probe["original_0_18_assertion_unchanged"]
assert probe["records"][0]["original_test_passed"] and probe["records"][0]["maximum_worker_overlap"] == 4
assert not probe["records"][1]["original_test_passed"] and probe["records"][1]["maximum_worker_overlap"] == 1
def once(text, a, b):
    assert text.count(a) == 1, a
    return text.replace(a,b)
main = (HERE / "verify_current_root_r21.py").read_text(encoding="utf-8")
main = once(main, 'startswith("coordinator-r21-")', 'startswith("coordinator-r22-")')
main = once(main, '"root_runtime_preflight_r21.py", "publish_joint_r21.py")', '"root_runtime_preflight_r21.py", "publish_joint_r21.py", "verify_current_root_r22.py", "verify_joint_retry_with_clock_r22.py", "publish_joint_r22.py")')
main = once(main, '"original_failed_union": "artifacts/coordinator-r20-job-cli-intaken-20261015/review.json",', '"original_failed_union": "artifacts/coordinator-r20-job-cli-intaken-20261015/review.json",\n    "immediately_preceding_failed_union": "artifacts/coordinator-r21-verified-environment-20261015/review.json",\n    "parallel_probe_sha256": "' + hashlib.sha256(probe_path.read_bytes()).hexdigest() + '",\n    "parallel_timing_assertion_unchanged": True,')
clock = (HERE / "verify_joint_retry_with_clock_r21.py").read_text(encoding="utf-8").replace('startswith("coordinator-r21-")','startswith("coordinator-r22-")').replace('"verify_current_root_r21.py"','"verify_current_root_r22.py"')
publisher = (HERE / "publish_joint_r21.py").read_text(encoding="utf-8")
publisher = once(publisher, 'OUT = ROOT / "artifacts/coordinator-r21-verified-environment-20261015"', 'OUT = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016"')
publisher = once(publisher, 'assert failed_cases <= new_cases, list((failed_cases - new_cases).items())[:10]', '''assert failed_cases <= new_cases, list((failed_cases - new_cases).items())[:10]
r21_cases = Counter((c.get("classname"), c.get("name")) for c in ET.parse(ROOT / "artifacts/coordinator-r21-verified-environment-20261015/results.xml").getroot().iter("testcase"))
assert r21_cases <= new_cases
probe_path = ROOT / "artifacts/subagent-parallel-probe-r22-20261016/review.json"
assert hashlib.sha256(probe_path.read_bytes()).hexdigest() == source["parallel_probe_sha256"]
assert source["parallel_timing_assertion_unchanged"]
assert source["after"]["tests/test_subagents_parallel.py"] == "1a7e5a43ce8ae095a9e802e16f307a9f0640c7b61ba5c4c68c439bee36c48699"''')
publisher = publisher.replace('rows["CURRENT-JOINT-R21"].update(status="current_complete', 'rows["CURRENT-JOINT-R22"].update(status="current_complete').replace('superseded_by="CURRENT-JOINT-R21"','superseded_by="CURRENT-JOINT-R22"')
publisher = once(publisher, 'ledger["current_accepted_stage"] = ', 'rows["CURRENT-JOINT-R21"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R22", failure_receipt="artifacts/coordinator-r21-verified-environment-20261015/review.json")\nledger["current_accepted_stage"] = ')
publisher = publisher.replace('R21 selected full union','R22 selected full union').replace('R21 current union passed;','R22 current union passed;').replace('R21 current selected full union passed','R22 current selected full union passed')
wrapper = (HERE / "publish_current_root_checked_r21.py").read_text(encoding="utf-8").replace('coordinator-r21-verified-environment-20261015','coordinator-r22-unchanged-union-20261016').replace('"publish_joint_r21.py"','"publish_joint_r22.py"')
created = {}
for name, content in {"verify_current_root_r22.py":main,"verify_joint_retry_with_clock_r22.py":clock,"publish_joint_r22.py":publisher,"publish_current_root_checked_r22.py":wrapper}.items():
    target = HERE/name
    assert not target.exists()
    compile(content,str(target),"exec")
    target.write_text(content,encoding="utf-8",newline="\n")
    created[name] = hashlib.sha256(target.read_bytes()).hexdigest()
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
identity = "CURRENT-JOINT-R22"
assert identity not in {r["id"] for r in ledger["tasks"]}
ledger["tasks"].append({"id":identity,"depends_on":["CURRENT-JOINT-R21","ASTRA-ROOT-LAUNCHER-REVIEW-R21"],"owner":"coordinator","status":"one_full_unchanged_product_retry_ready_after_parallel_and_serial_probe","artifact_available":False,"independent_acceptance":False,"integrated":False,"joint_verification":False,"is_current_root":False,"whole_package_complete":False,"product_or_test_changed":False,"prior_failure":"artifacts/coordinator-r21-verified-environment-20261015/review.json","diagnostic":"artifacts/subagent-parallel-probe-r22-20261016/review.json","checked_at":at})
rows={r["id"]:r for r in ledger["tasks"]}
pending,done,layers=set(rows),set(),[]
while pending:
    ready=sorted(p for p in pending if set(rows[p].get("depends_on",[]))<=done)
    assert ready
    layers.append(ready);done.update(ready);pending.difference_update(ready)
ledger.update(updated_at=at,topological_layers=layers)
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
receipt={"at":at,"created_launchers":created,"prior_source_inputs_unchanged":len(source["after"]),"product_or_test_changed":False,"test_files":169,"test_case_floor":2539,"original_0_18_assertion_retained":True,"six_commands_required":True,"automatic_retry_until_green":False,"reason":"Original parallel probe observed4 overlapping workers and passed; explicit serial negative control failed; one full unchanged-product trial, all failures retained"}
(HERE/"followups-r12/root-retry-r22-setup.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(receipt),flush=True)
