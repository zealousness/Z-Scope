"""Draft the mandatory permanent trace regression gate; preserve installed rev3."""
from pathlib import Path
import datetime as dt
import difflib
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/stage-joint-launcher-draft-r35-20261017/revision-4"
OLD = HERE / "verify_stage_joint_r35.py"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Unoptimized Linux Python required")
assert sha(OLD) == "ec9eb801255e6f3c171be76b4011345c92f25c0f2039e389bbdb22833fb087f1"
if BASE.exists():
    raise RuntimeError("Preserve existing revision")
text = OLD.read_text(encoding="utf-8")
old_sources = 'store_sources = {name: before[name] for name in ("zscope/orchestration/jobs/store.py", "tests/test_store_active_transactions_r35.py")}'
new_sources = 'store_sources = {name: before[name] for name in ("zscope/orchestration/jobs/store.py", "tests/test_store_active_transactions_r35.py", "tests/test_trace_callback_generation_probe_r35.py")}'
assert text.count(old_sources) == 1
text = text.replace(old_sources, new_sources)
old_counter = '    store_counter = cases(store_xml)\n'
new_counter = '''    store_counter = cases(store_xml)
    trace_xml = bind_ref(store["trace_results_xml"], refs)
    require(str(trace_xml) == store_independent["trace_results_xml"] and sha(trace_xml) == store_independent["trace_results_xml_sha256"], "Store permanent trace independent actual XML differs")
    green_junit(trace_xml)
    trace_counter = cases(trace_xml)
    trace_names = {"test_real_user_trace_callback_cannot_resurrect_issued_generation[" + route + "]" for route in ("connection_sql", "cursor_sql", "commit_api", "rollback_api", "normal_trace")}
    require(sum(trace_counter.values()) == len(trace_counter) == 5 and {name for _classname, name in trace_counter} == trace_names, "permanent five real SQLite cases changed or missing")
    require(all(classname == "tests.test_trace_callback_generation_probe_r35" and count == 1 and store_counter[identity] == count for identity, count in trace_counter.items() for classname, _name in [identity]), "permanent trace raw Counter not present exactly once in Store independent regression")
    require(case_rows(trace_counter) == store_independent["trace_case_counter"], "permanent trace independent raw Counter changed")
'''
assert text.count(old_counter) == 1
text = text.replace(old_counter, new_counter)
selection = '    require("tests/test_store_active_transactions_r35.py" in additions, "future Store test must join the final actual regression selection")\n'
assert text.count(selection) == 1
text = text.replace(selection, selection + '    require("tests/test_trace_callback_generation_probe_r35.py" in additions, "permanent five trace generation regressions must join the final actual selection")\n')
pin = '    INVENTORY: '
assert text.count(pin) == 1
text = text.replace(pin, '''    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/verify_stage_joint_r35.py": "ec9eb801255e6f3c171be76b4011345c92f25c0f2039e389bbdb22833fb087f1",
    "artifacts/store-active-transactions-r35-20261017/ownership-extension-trace-test.json": "4a6be7b2a004b89565ff3d77e63b09a59d81d5a2a92831aaf279eeab93360e9a",
    "artifacts/store-active-transactions-r35-20261017/ownership-trace-format-addendum.json": "e057e2afb7175ce83a6f6faf1fe2c497e1235b1b75d8a8667f7f739d94f20e11",
    INVENTORY: ''')
BASE.mkdir()
candidate = BASE / "verify_stage_joint_r35_rev4.py"
candidate.write_text(text, encoding="utf-8", newline="\n")
(BASE / "delta.diff").write_text("".join(difflib.unified_diff(OLD.read_text(encoding="utf-8").splitlines(True), text.splitlines(True), fromfile="installed-rev3", tofile="draft-rev4")), encoding="utf-8", newline="\n")
record = dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    original_installed_sha256=sha(OLD), candidate_sha256=sha(candidate), delta_sha256=sha(BASE / "delta.diff"),
    execution_authorized=False, execution_confirmed=False, new_readiness_receipt_required=True,
    change="Require the real permanent five-case trace regression source and independently passing raw Counter/XML in the final joint; all rev3 gates remain.",
    additional_store_owned_source="tests/test_trace_callback_generation_probe_r35.py",
    additional_intake_fields=["store_evidence.trace_results_xml", "store independent trace_results_xml", "store independent trace_results_xml_sha256", "store independent trace_case_counter"],
    installed_rev3_preserved=True, stage_root_products_unchanged=True)
(BASE / "preparation.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(record))
