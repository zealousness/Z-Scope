"""Stage explicit synthetic receipts and exact query contexts; root unchanged."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
proof = json.loads((ROOT / "artifacts/coordinator-contract-r12-r4-boundary-probes-20261015/review.json").read_text(encoding="utf-8"))
assert proof["returncode"] == 0 and proof["stable_frozen_inputs"]
source = ROOT / ".coordination/20261014/workspaces/coordinator-coordinator-contract-r12-r4-boundary-probes-20261015"
workspace = ROOT / ".coordination/20261014/workspaces/coordinator-contract-migration-r17"
assert not (HERE / "followups-r12/coordinator-contract-migration-r17-baseline.json").exists()
# A Windows long-path read can leave only baseline copies; resume that setup
# in Linux before any migration receipt or edits have been produced.
workspace.mkdir(exist_ok=True)
for name, sha in proof["before"].items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == sha
    target = workspace / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / name, target)
owns = ["tests/" + name + ".py" for name in ("test_contract_build_scope", "test_native_wrapper_inference", "test_single_slot_pool", "test_retention_protocols")]
(HERE / "followups-r12/coordinator-contract-migration-r17-baseline.json").write_text(json.dumps({"prepared_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task": {"id": "COORD-CONTRACT-MIGRATION-R17", "owns": owns}, "files": [{"path": name, "sha256": sha} for name, sha in proof["before"].items()], "source": str(source), "root_changed": False, "whole_package_complete": False}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def edit(name, changes):
    path = workspace / "tests" / name
    text = path.read_text(encoding="utf-8")
    for old, new in changes:
        assert text.count(old) == 1, (name, old[:80], text.count(old))
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8", newline="\n")

edit("test_contract_build_scope.py", [
    ("from dataclasses import replace\n", "from dataclasses import replace\nfrom copy import deepcopy\n"),
    ('''    matches = contracts.for_context(context()).match_call(
        "dispose", "deallocator", ["p"], facts={"p": {"non_null_identity": "p"}}
    )''', '''    # A build-only view is insufficient to select the native symbol.
    assert not contracts.for_context(context()).match_call("dispose", "deallocator", ["p"])
    with bind_call_context(context(), contracts):
        matches = contracts.for_context(context()).match_call(
            "dispose", "deallocator", ["p"], facts={"p": {"non_null_identity": "p"}}
        )'''),
    ('''@pytest.mark.parametrize("engine", ["regex", "clang_ast_cfg"])
def test_candidate_semantic_trace_uses_the_observed_build(engine):''', '''def caller_facts(build="a", usr="c:@F@dispose"):
    # Synthetic isolation fixture; real native extraction is tested separately.
    facts = deepcopy(context(build)["program_facts"])
    body = facts["functions"][0]
    body["owner"] = {"name": "run", "usr": "c:@F@run", "file": "unit.c"}
    body["parameters"][0].update(usr="c:unit.c@1@F@run@p", referenced_usr="c:unit.c@1@F@run@p")
    event = body["events"][0]
    event["expression"] = "dispose(p)"
    event["callee"] = {"name": "dispose", "usr": usr} if usr is not None else {"name": "dispose"}
    return facts


@pytest.mark.parametrize("engine", ["regex", "clang_ast_cfg"])
def test_candidate_semantic_trace_uses_the_observed_build(engine):'''),
    ('''generator.program_facts_provider = lambda *_: {"complete": True, "build_context_id": "a"}''', '''generator.program_facts_provider = lambda *_: caller_facts("a")'''),
    ('''generator.program_facts_provider = lambda *_: {"complete": True, "build_context_id": "b"}''', '''generator.program_facts_provider = lambda *_: caller_facts("b")'''),
])
path = workspace / "tests/test_contract_build_scope.py"
with path.open("a", encoding="utf-8", newline="\n") as stream:
    stream.write('''

@pytest.mark.parametrize("engine", ["regex", "clang_ast_cfg"])
@pytest.mark.parametrize("usr", [None, "", "c:@F@other"])
def test_candidate_semantic_trace_rejects_missing_or_foreign_callee_receipt(engine, usr):
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator

    semantics = default_local_pattern_semantics()
    semantics.contracts.add(ApiContract.from_row({"contract": derive_contracts(context(), registry())[0]}))
    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    generator = cls(semantics)
    generator.program_facts_provider = lambda *_: caller_facts("a", usr)
    generator.generate_issues("run", "void run(void *p) { if (p) dispose(p); }", "unit.c")
    assert not generator.last_semantic_events
''')

edit("test_native_wrapper_inference.py", [("""    with bind_build_scope(ctx):
        (contract,) = effective.contracts.find_for_call("make2")""", """    with bind_build_scope(ctx):
        assert not effective.contracts.find_for_call("make2")
    with bind_build_scope(outer):
        (contract,) = effective.contracts.find_for_call("make2")""")])

path = workspace / "tests/test_single_slot_pool.py"
text = path.read_text(encoding="utf-8")
start = text.index('        assert (\n            registry.release_status("pool_take", "pool_give", ["a", "p"], facts=values, **query)')
end = text.index('        transitions = registry.resolved_transitions(', start)
block = text[start:end]
text = text[:start] + '        # pool_take has no native call selecting pool_give. Bind its own\n        # deallocator body for the release query; keep the unknown case above.\n        with bind_build_scope(context("deallocator")):\n' + ''.join("    " + line if line.strip() else line for line in block.splitlines(keepends=True)) + text[end:]
old = '                    "fact_version": "zscope.program-events.v5",'
assert text.count(old) == 1
text = text.replace(old, '                    "complete": True,\n' + old)
old = '    snapshot = deterministic_contract_snapshot(ctx, registry)\n'
assert text.count(old) == 1
text = text.replace(old, '''    # This unit fixture supplies the wrapper's own synthetic native frame.
    body = ctx["program_facts"]["functions"][0]
    body["owner"] = {"name": "drop", "usr": "c:@F@drop"}
    body["events"] = [{"event_id": "call-1", "event_kind": "call", "expression": "pool_give(arena, p)", "arguments": ["arena", "p"], "contains_macro": False, "callee": {"name": "pool_give", "usr": "c:@F@pool_give"}}]
    missing = deepcopy(ctx)
    missing["program_facts"]["functions"][0]["events"][0]["callee"].pop("usr")
    assert deterministic_contract_snapshot(missing, registry) is None
    snapshot = deterministic_contract_snapshot(ctx, registry)
''')
path.write_text(text, encoding="utf-8", newline="\n")

edit("test_retention_protocols.py", [
    ('"owner": {"name": "enqueue"},', '"complete": True,\n                    "owner": {"name": "enqueue", "usr": "c:@F@enqueue"},'),
])
path = workspace / "tests/test_retention_protocols.py"
with path.open("a", encoding="utf-8", newline="\n") as stream:
    stream.write('''

def test_missing_native_owner_usr_cannot_publish_retention_effect():
    ctx = context()
    ctx["program_facts"]["functions"][0]["owner"].pop("usr")
    assert verify_retention_contract(proposal(), ctx) is None
''')
print(json.dumps({"workspace": str(workspace), "write_paths": owns, "root_changed": False}))
