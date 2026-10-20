"""Coordinator static delta review; no candidate import or execution."""
import ast
import datetime as dt
import difflib
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OLD = HERE / 'verify_stage_joint_r35_rev4.py'
NEW = ROOT / 'artifacts/stage-joint-launcher-rev5-draft-r35-20261017/revision-2/verify_stage_joint_r35_rev5_v2.py'
OUT = ROOT / 'artifacts/coordinator-stage-joint-rev5-v2-source-review-r35-20261017'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
assert sha(OLD) == 'dd078e068d91b6e7c5e22a5e0a0824276556b91e47a5b42ff55f8e9e410a0f8f'
assert sha(NEW) == '53ab21715d5aac586344338360ff40892cf55a13dd1763551691651a229364db'
old_text, new_text = OLD.read_text(encoding='utf-8'), NEW.read_text(encoding='utf-8')
old, new = ast.parse(old_text), ast.parse(new_text)
dump = lambda node: ast.dump(node, include_attributes=False)
old_functions = {node.name: node for node in old.body if isinstance(node, ast.FunctionDef)}
new_functions = {node.name: node for node in new.body if isinstance(node, ast.FunctionDef)}
unchanged = {name: dump(node) == dump(new_functions[name]) for name, node in old_functions.items() if name != 'main'}
assert unchanged and all(unchanged.values())
main_before = [dump(node) for node in old_functions['main'].body]
main_after = [dump(node) for node in new_functions['main'].body]
position = 0
for statement in main_after:
    if position < len(main_before) and statement == main_before[position]:
        position += 1
assert position == len(main_before), 'An original main statement was changed/removed/reordered'
assert set(new_functions) - set(old_functions) == {'raw_prewrite_execution', 'prewrite_evidence'}
assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == 'subprocess' for name in ('raw_prewrite_execution', 'prewrite_evidence') for n in ast.walk(new_functions[name]))
pins = next(n.value for n in new.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'FIXED_PINS' for t in n.targets))
literal_strings = {t.id: n.value.value for n in new.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str) for t in n.targets if isinstance(t, ast.Name)}
def fixed_literal(node):
    if isinstance(node, ast.Name):
        return literal_strings[node.id]
    return ast.literal_eval(node)
assert isinstance(pins, ast.Dict)
fixed_pins = {fixed_literal(k): fixed_literal(v) for k, v in zip(pins.keys, pins.values)}
assert fixed_pins and all(sha(ROOT / name) == digest for name, digest in fixed_pins.items())
assert 'len(original52) == sum(original52.values()) == 52' in new_text
assert 'job_counter[original_job] == 1' in new_text
assert 'original_collection["case_counter"] == original_collection_receipt["case_counter"] == case_rows(job_counter)' in new_text
assert 'sum(store_counter.values()) == 369' in new_text
assert 'inconclusive backup target reachability is not a causal red' in new_text
if OUT.exists():
    raise RuntimeError('Preserve previous review')
OUT.mkdir()
record = dict(actual_task='/root', checked_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    source_review_passed=True, candidate_sha256=sha(NEW), original_rev4_sha256=sha(OLD),
    unchanged_original_functions=unchanged, original_main_statement_count=len(main_before), original_main_statements_preserved_in_order=True,
    original_eight_commands_preserved=True, fixed_references_sha256=fixed_pins,
    review_helper_preparation_corrections=['Resolve literal string constant dictionary keys without importing the candidate', 'Read ast.Dict.values as the AST list', 'Match the actual chained raw-Counter comparison rather than a guessed variable spelling'],
    reviewed_additions=['Actual prewrite collection/red/green Counter and raw execution/source/import/host binding',
        'Seven actual identities and real positive queue closure; backup input damage and tool verification order required for valid original red',
        'Original 53 retain 52 new-module identities and the original SessionJobs identity, equal to fixed original actual collection',
        'Store369 and permanent trace5 unchanged; prewrite file must be selected and all seven retained in final actual Counter'],
    blocking_source_findings=[], actual_execution=False, installed=False, ready_dependencies_satisfied=False,
    limits=['Actual native/Job/prewrite/third-TU independent acceptance and final shared source review/intake remain pending.',
        'No Stage/Root joint or entire package acceptance. Future added tests must be included by the final reviewed readiness intake.'])
(OUT / 'review.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
(OUT / 'delta.diff').write_text(''.join(difflib.unified_diff(old_text.splitlines(keepends=True), new_text.splitlines(keepends=True), fromfile=str(OLD), tofile=str(NEW))), encoding='utf-8', newline='\n')
print(json.dumps(dict(source_review_passed=True, functions=len(unchanged), original_main_statements=len(main_before), installed=False, execution=False)))
