"""Coordinator migration of the readonly baseline plus precise test descriptions."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
workspace = ROOT / ".coordination/20261014/workspaces/native-hot-cache-r19"
out = ROOT / "artifacts/coordinator-native-hot-r19-migration-20261015"
out.mkdir(exist_ok=False)
baseline = json.loads((HERE / "followups-r12/native-hot-cache-r19-baseline.json").read_text(encoding="utf-8"))
originals = {r["path"]:r["sha256"] for r in baseline["files"]}
native_test = "tests/test_native_replay_hot_cache.py"
before = (workspace / native_test).read_bytes()
assert hashlib.sha256(before).hexdigest() == "ce363957f387c9093ed3f03053aac555b2c0ec72ffec353dc8f58ec2f7019b39"
target = out / "source-before" / native_test
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(before)
(out / "producer-delivery.md").write_bytes((workspace / "DELIVERY.md").read_bytes())
text = before.decode("utf-8")
text = text.replace("without executing any native tool process", "without AST extraction (version and loader queries are separate)")
text = text.replace("The reuse executed no native tool process: not a single cache", "TU byte stability alone does not count processes: not a single cache")
text = text.replace("Every test here runs", "Cache bytes establish artifact stability; actual extraction processes are\nindependently counted by the coordinator's native process probes.\n\nEvery test here runs", 1)
def executable_ast(value):
    tree = ast.parse(value)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
            node.body.pop(0)
    return ast.dump(tree, include_attributes=False)
assert executable_ast(before.decode("utf-8")) == executable_ast(text)
(workspace / native_test).write_text(text, encoding="utf-8", newline="\n")
old_test = "tests/test_incremental_replay.py"
assert hashlib.sha256((workspace / old_test).read_bytes()).hexdigest() == originals[old_test]
target = out / "source-before" / old_test
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes((workspace / old_test).read_bytes())
source = ROOT / ".coordination/20261014/workspaces/config-stop-at-r18" / old_test
dependency = json.loads((HERE / "followups-r12/config-stop-at-r18-dependencies.json").read_text(encoding="utf-8"))
final_sha = next(r["sha256"] for r in dependency["files"] if r["path"] == old_test)
assert hashlib.sha256(source.read_bytes()).hexdigest() == final_sha
(workspace / old_test).write_bytes(source.read_bytes())
proof = {"captured_at":dt.datetime.now(dt.timezone.utc).isoformat(),"coordinator_authored":True,"producer_write_permission_granted":False,"root_changed":False,"validated":False,"files":[{"path":old_test,"previous_sha256":originals[old_test],"sha256":final_sha}],"test_description_correction":{"path":native_test,"producer_sha256":hashlib.sha256(before).hexdigest(),"sha256":hashlib.sha256((workspace/native_test).read_bytes()).hexdigest(),"executable_ast_unchanged":True},"scope":"Exact native hot AST0 + full reuse assertion, preserving every mutation and clean/semantic checks. Test docs no longer infer zero processes from byte stability; native version/loader queries are disclosed separately.","evidence":"artifacts/coordinator-current-native-process-classified-r19-20261015/review.json"}
path = HERE / "followups-r12/native-hot-cache-r19-dependencies.json"
assert not path.exists()
path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
(out/"migration.json").write_bytes(path.read_bytes())
print(json.dumps({"root_changed":False,"coordinator_migration":proof["files"],"test_description_correction":proof["test_description_correction"]}),flush=True)
