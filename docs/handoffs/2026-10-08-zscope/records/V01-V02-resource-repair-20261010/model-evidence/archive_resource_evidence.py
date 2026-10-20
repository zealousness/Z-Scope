"""Archive this authorized repair, preserving failed attempts and raw evidence."""
import ast
import copy
import difflib
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

base = Path(__file__).resolve().parent
root = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
records = root / "docs/handoffs/2026-10-08-zscope/records"
destination = records / "V01-V02-resource-repair-20261010"
destination.mkdir(exist_ok=False)
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
write = lambda p, v: p.write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
first = json.loads((base / "ordinary-validation.json").read_text())
second = json.loads((base / "integrated-final-validation.json").read_text())
assert not first["changed_inputs"] and not second["changed_inputs"]
assert all(c["exit_code"] == 0 for c in second["checks"])
assert second["planned_test_only_delta_from_first_round"] == ["tests/test_dynamic_reproduction.py"]
final = copy.deepcopy(first)
updated = {"unit": second["checks"][0], "compileall": second["checks"][1]}
final["checks"] = [copy.deepcopy(updated.get(c["label"], c)) for c in first["checks"]]
assert all(c["exit_code"] == 0 for c in final["checks"])
final.update(overall="ordinary_checks_passed_real_checks_pending",
             product_sha256=second["product_sha256"],
             planned_between_window_changes=second["planned_test_only_delta_from_first_round"],
             changed_inputs_during_each_window=[], unexpected_changes=[],
             final_test_sha256=second["inputs_after"]["tests/test_dynamic_reproduction.py"],
             final_input_count=len(second["inputs_after"]))
final.pop("inputs_after", None)
final["final_inputs_before_documentation_update"] = second["inputs_after"]
final["validation_windows"] = {
    "first": "All source and test inputs stable; migrated unit tests initially missed hashlib import.",
    "second": "Only the missing test import changed; final unit and compileall rerun with stable inputs.",
    "compatibility_and_mypy": "Actual first-window passes against the identical final product source; not rerun for a test-only import.",
}


def archive_checks(checks, folder):
    target = destination / folder
    target.mkdir()
    for check in checks:
        for key, suffix in (("stdout", ".stdout.log"), ("stderr", ".stderr.log"), ("junit", ".xml")):
            if key in check:
                source = Path(check[key])
                path = target / (check["label"] + suffix)
                shutil.copyfile(source, path)
                assert digest(path) == digest(source)
                check[key] = str(path.relative_to(destination))


archive_checks(copy.deepcopy(first["checks"]), "ordinary-first-evidence")
archive_checks(final["checks"], "ordinary-evidence")
write(destination / "ordinary-first-validation.json", first)
write(destination / "integrated-final-validation.json", second)
write(destination / "ordinary-final-validation.json", final)
selected = ["packet-manifest.json", "model-answer.txt", "model-candidate-review.json",
            "candidate-review.json", "independent-review-accepted.json", "application-result.json",
            "candidate-regressions.json", "reviewed-regressions.json", "test-integration.json",
            "lifecycle-model.json", "lifecycle-model-corrected-observer.json", "lifecycle-reviewed.json",
            "test_resource_lifecycle.py", "check_resource_lifecycle.py", "finalize_review.py",
            "integrate_resource_tests.py", "rerun_integrated_tests.py", "run_acceptance.py",
            "archive_resource_evidence.py"]
model = destination / "model-evidence"
model.mkdir()
for name in selected:
    shutil.copyfile(base / name, model / name)
for pattern in ("candidate-regressions.*.log", "candidate-regressions.xml", "reviewed-regressions.*.log",
                "reviewed-regressions.xml", "lifecycle-*.log", "lifecycle-*.xml"):
    for path in base.glob(pattern):
        shutil.copyfile(path, model / path.name)
submission = json.loads((base / "submission-result.json").read_text())
submission["baseURL"] = "[user-approved volceapi.com gateway; exact endpoint retained only locally]"
submission["overlay"] = "[unchanged process configuration; credential reference not archived]"
write(model / "submission-result.json", submission)
for filename, relative in (("dynamic_reproduction.before.py", "zscope/core/validation/dynamic_reproduction.py"),
                           ("test_dynamic_reproduction.before.py", "tests/test_dynamic_reproduction.py")):
    before = (base / filename).read_text().splitlines(keepends=True)
    after = (root / relative).read_text().splitlines(keepends=True)
    name = "product.patch" if relative.startswith("zscope/") else "tests.patch"
    (destination / name).write_text("".join(difflib.unified_diff(before, after, fromfile="a/" + relative,
                                                              tofile="b/" + relative)), encoding="utf-8")
before_ast = ast.parse((base / "test_dynamic_reproduction.before.py").read_text())
after_ast = ast.parse((root / "tests/test_dynamic_reproduction.py").read_text())
functions = lambda tree: {n.name: ast.dump(n) for n in tree.body if isinstance(n, ast.FunctionDef)}
old, new = functions(before_ast), functions(after_ast)
assert all(new[k] == value for k, value in old.items())
totals = {key: sum((c.get("counts") or {}).get(key, 0) for c in final["checks"])
          for key in ("passed", "failed", "errors", "skipped")}
write(destination / "summary.json", {
    "at": datetime.now(timezone.utc).isoformat(), "user_authorized_exact_payload": True,
    "payload_bytes": 54628, "payload_sha256": submission["promptDigest"],
    "external_calls_this_round": 1, "model_session": submission["sessionId"],
    "model_tools_disabled": True, "credential_values_read_or_recorded": False,
    "source_sha256": final["product_sha256"], "ordinary_checks": totals,
    "original_test_function_asts_unchanged": len(old),
    "new_resource_test_cases": 13, "tracked_inputs": len(second["inputs_after"]),
    "input_windows_stable": True, "V01": "in_progress", "V02": "blocked",
    "current_revision_real_ASAN": "not_run; prior passed record remains historical",
    "real_TSAN": "not_run; existing fixed runtime unexpected memory mapping remains blocked",
    "formal_benchmark": "not_run", "install_download_permission_changes": False,
    "git_commit_push": False,
})
print(json.dumps({"destination": str(destination), "ordinary_checks": totals,
                  "source_sha256": final["product_sha256"], "tracked_inputs": len(second["inputs_after"])}))
