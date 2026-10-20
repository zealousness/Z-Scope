"""Replay the real failing native candidate and record its first refusal gate."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
from root_runtime_preflight_r23 import inspect_root_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-contract-tests-r33"
OUT = ROOT / "artifacts/coordinator-contract-tests-r33-20261017"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sys.platform == "linux" and Path.cwd().resolve() == WORK and not sys.flags.optimize
prep = read(OUT / "preparation.json")
expected = prep["complete_baseline"] | prep["candidate_sha256"]
assert all(sha(WORK / path) == digest for path, digest in expected.items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
runtime = inspect_root_runtime(require_slot=True)
os.environ["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
sys.path.insert(0, str(WORK / "tests"))
from test_raii_lifecycle import cpp_project
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.validation.review_checks import RULE_CONTRACT_REVISIONS, checked_receipt
from zscope.rules.catalog import RuleCatalog, EffectiveRuleSet

observed = []
with tempfile.TemporaryDirectory(prefix="zscope-raii-gate-", dir="/tmp") as folder:
    fixture = cpp_project.__wrapped__(Path(folder))
    build = next(fixture)
    try:
        checker, _, index, path = build("void *p=malloc(8);\nGuard g(p);")
        code = index.get_function_impl("f", file_path=str(path), include_context=False)["code"]
        descriptor = RuleCatalog.builtin().require("clang_cfg_acquire_without_release_on_exit")
        assert not descriptor.default_enabled and descriptor.status == "experimental"
        policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang", enabled_ids=[descriptor.id]).policy
        generated = ClangAstCfgCandidateGenerator(rule_policy=policy, program_facts_provider=index.get_function_program_facts).generate_issues("f", code, str(path))
        candidates = [value for value in generated if value["rule_id"] == descriptor.id]
        assert candidates
        for candidate in candidates:
            candidate = policy.enrich_issue(candidate)
            assert candidate["build_context_id"] and candidate["rule_revision"] == 11
            checker.prepare(candidate)
            result = checker.check(candidate)
            observed.append(dict(rule_id=descriptor.id, rule_revision=candidate["rule_revision"], allowed_revisions=sorted(RULE_CONTRACT_REVISIONS[descriptor.id]), result=result, lifecycle_analysis_present=candidate.get("lifecycle_analysis") is not None, checked_receipt=bool(checked_receipt(candidate))))
    finally:
        fixture.close()
source_ok = all(sha(WORK / path) == digest for path, digest in expected.items())
root_ok = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert source_ok and root_ok
assert observed and all(row["result"]["reason"] == "unqualified_rule_contract_revision" and row["result"]["status"] == "unknown" for row in observed)
receipt = dict(actual_task="/root", observed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), runtime=runtime, actual_native_probe=True, reproduced_first_refusal_gate=True, observations=observed, input1077_unchanged=source_ok, root1065_unchanged=root_ok, probe_launcher_sha256=sha(Path(__file__)), source_acceptance=False, stage_intake=False, root_intake=False)
target = OUT / "raii-first-gate-probe.json"
assert not target.exists()
target.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=target.relative_to(ROOT).as_posix(), reproduced_first_refusal_gate=True, observations=observed)))
