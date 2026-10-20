"""Bind a strict causal red, then add only the existing Session handoff inputs."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/coordinator-session-cost-r33-20261017"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-session-cost-r33"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def write(p, value):
    assert not p.exists()
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


red = read(BASE / "red2/review.json")
frozen = read(BASE / "test-freeze-v2.json")
assert red["valid_red"] and all(red["gates"].values())
assert red["junit"] == dict(tests=2, failures=1, errors=0, skipped=0)
tree = ET.parse(BASE / "red2/results.xml").getroot()
failed = [n for n in tree.iter("testcase") if n.find("failure") is not None]
assert len(failed) == 1
assert failed[0].get("name") == "test_real_instance_builder_retains_current_preentry_cost_and_service[True]"
message = "".join(failed[0].find("failure").itertext())
assert "total_tokens" in message and "assert 0 == 24" in message
write(BASE / "red2-causal-audit.json", dict(actual_task="/root", audited_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), strict_current_preentry_red_confirmed=True, red_receipt_sha256=sha(BASE / "red2/review.json"), red_xml_sha256=sha(BASE / "red2/results.xml"), True_native_factory_and_scope_preconditions_passed=True, False_control_passed=True, provider_requests=False, initial_invalid_red_preserved=True))
assert all(sha(WORK / p) == digest for p,digest in frozen["complete_inputs"].items())
path = "zscope/orchestration/scan_session.py"
before = (WORK / path).read_text(encoding="utf-8")
tree = ast.parse(before)
target = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_build_instance_analyzer")
calls = [n for n in ast.walk(target) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "ParallelAnalyzer"]
assert len(calls) == 1 and not {"llm_clients","project_knowledge_service","semantic_result"} & {k.arg for k in calls[0].keywords}
line = calls[0].lineno
lines = before.splitlines(keepends=True)
needle = "            code_index=code_index,\n"
position = next(i for i in range(line-1, calls[0].end_lineno) if lines[i] == needle)
lines.insert(position+1, '            llm_clients=state.get("llm_clients"),\n            project_knowledge_service=state.get("project_knowledge_service"),\n')
after = "".join(lines)
after_tree = ast.parse(after)
newtarget = next(n for n in ast.walk(after_tree) if isinstance(n, ast.FunctionDef) and n.name == "_build_instance_analyzer")
newcall = next(n for n in ast.walk(newtarget) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "ParallelAnalyzer")
newcall.keywords = [k for k in newcall.keywords if k.arg not in {"llm_clients","project_knowledge_service"}]
assert ast.dump(tree) == ast.dump(after_tree)
candidate = BASE / "candidate" / path
candidate.parent.mkdir(parents=True, exist_ok=False)
candidate.write_text(after, encoding="utf-8", newline="\n")
write(BASE / "candidate.json", dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), before_sha256={path:sha(WORK/path)}, candidate_sha256={path:sha(candidate)}, only_two_instance_builder_kwargs_added=True, all_other_AST_nodes_exact=True, global_semantic_result_still_excluded=True, strict_red_causal_audit_sha256=sha(BASE/"red2-causal-audit.json"), stage_intake=False, root_intake=False))
(WORK / path).write_bytes(candidate.read_bytes())
print(json.dumps(dict(candidate_sha256=sha(candidate), strict_red=True)))
