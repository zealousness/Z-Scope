"""Coordinator-only Stage joint candidate; never execute from the draft directory."""
from __future__ import annotations

from collections import Counter
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
INTAKE = ROOT / "artifacts/stage-shared-intake-r35-20261017/receipt.json"
OUT = ROOT / "artifacts/coordinator-stage-joint-r35-20261017"
PYTHON = "/home/zeal/venv313/bin/python"
OLD_TOOL = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
OLD_SHA = "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
NEW_TOOL = Path("/home/zeal/.cache/zscope-job-runtime-footprint-r34/install/bin/zscope-clang-indexer")
CONFIG_NAMES = ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml")
INVENTORY = "artifacts/native-regression-inventory-r34-20261017/receipt-final-v2.json"
CORE = "artifacts/stage-core-intake-r34-20261017/receipt.json"
CHECKPOINT = "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
FIXED_PINS = {
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/verify_stage_joint_r35.py": "ec9eb801255e6f3c171be76b4011345c92f25c0f2039e389bbdb22833fb087f1",
    "artifacts/store-active-transactions-r35-20261017/ownership-extension-trace-test.json": "4a6be7b2a004b89565ff3d77e63b09a59d81d5a2a92831aaf279eeab93360e9a",
    "artifacts/store-active-transactions-r35-20261017/ownership-trace-format-addendum.json": "e057e2afb7175ce83a6f6faf1fe2c497e1235b1b75d8a8667f7f739d94f20e11",
    INVENTORY: "34a4d4d2f95bc93d282b42b5c158c0636ff453c2867a9944cbcdd980c5572456",
    CORE: "bf8b9a73bec529743cd68c2e84a28a6f00af71375a531b6ce8181ee6cd17c138",
    CHECKPOINT: "b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f",
    "artifacts/store-active-transactions-r35-20261017/preparation.json": "39f38fb8e4815fc8dfa055479c43b3715853d84167625a3d3f65628a6b2f639c",
    "artifacts/coordinator-shared-style-r34-20261017/independent/review.json": "5c8914e1f12c706ee224f4195d93b83b2768604f3f8ba9ba2cbda409e0aa0aae",
    "artifacts/coordinator-shared-style-r34-20261017/independent/results.xml": "1a2a9a4180966c8cd5fa971daa2f5880f939e47c7ef17944ea181f4fbe2c03cc",
    "artifacts/coordinator-checkpoint-contract-r34-20261017/independent/review.json": "1e2250332212d71162a3a94d0f05452ff7cd08b495677251092684c54f4a585f",
    "artifacts/coordinator-checkpoint-contract-r34-20261017/independent/results.xml": "a07db060978ac83d3c09d0080a64a086f8becc85bdcffb5d3af36f0ee34d2539",
    "artifacts/coordinator-real-llvm-case-r34-20261017/review.json": "8298b19879519c1433a7e6b9b3fe9832a651134544161bd53fda112f73b9009e",
    "artifacts/coordinator-real-llvm-case-r34-20261017/results.xml": "dccac73f5b3734214b8908003d8f55baf3bc867c3fd1558911e6ac96842a9d0a",
    "artifacts/coordinator-joint-llvm-preflight-r34-20261017/receipt.json": "64423b2b287076ec40ed4bd5176d530780b0351cc28d2a5a17d1877e95173282",
    "artifacts/coordinator-stage-joint-r32-20261017/review.json": "15c6d6d5bda29c84246e5c45a19e65c9d2459ad316be1c63b198eb58742c3c90",
    "artifacts/s01-authority-probe-r24-20261016/test_s01_authority_probe.py": "5044fdb8c3cbfe4c9dd5eab051618ff5acacd5b25364e113e36de22f34471d26",
    "artifacts/coordinator-s01-repair-r31-r32-independent-20261017/authority-r24.xml": "1ac994956078f4051f35ea08d5073d738996c17ef89023dc5070c0dd0d2d3aa3",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/verify_stage_joint_r34.py": "d068bf0d95208ea99f12b2bb8ab10fd33a33d50a27b2d2cb6f131c948adf56b7",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/test_slot.py": "7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/root_runtime_preflight_r23.py": "37bdbfe76401407280598d39f89424211bb418ff8469b1dc0b2bfe89ce10b4e3",
}
PRIOR = {
    "root_r23": ("artifacts/coordinator-r23-ui-projection-union-20261016/results.xml", 2551),
    "stage_r30": ("artifacts/coordinator-stage-regression-r30-20261017/results.xml", 1147),
    "s01_r32": ("artifacts/coordinator-s01-repair-r31-r32-independent-20261017/results.xml", 209),
    "failed_stage_r32": ("artifacts/coordinator-stage-joint-r32-20261017/results.xml", 3543),
    "composite_r33": ("artifacts/coordinator-final-composite-r33-20261017/independent/results.xml", 148),
    "review_r33": ("artifacts/coordinator-review-revision-repair-r33-20261017/regression/results.xml", 271),
    "session_r33": ("artifacts/coordinator-session-cost-r33-20261017/regression/results.xml", 89),
    "currentness_original755": (".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33/focused-20261017T035157.866301Z/pytest.xml", 755),
    "failed_cost_r33": (".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/regression-usage/pytest.xml", 308),
    "core150": ("artifacts/coordinator-shared-style-r34-20261017/independent/results.xml", 150),
    "checkpoint10": ("artifacts/coordinator-checkpoint-contract-r34-20261017/independent/results.xml", 10),
    "llvm1": ("artifacts/coordinator-real-llvm-case-r34-20261017/results.xml", 1),
}
COST_TESTS = ["tests/test_instance_partial_recovery_integration.py", "tests/test_instance_result_recovery.py", "tests/test_job_bound_instance_results.py", "tests/test_instance_semantics_integration.py", "tests/test_instance_analysis.py", "tests/test_scan_checkpoint_resume.py", "tests/test_scan_session_instances.py", "tests/test_scan_session_jobs.py", "tests/test_scan_token_budget.py", "tests/test_report_views.py", "tests/test_report_schema_v2.py", "tests/test_parallel_entry_budget.py", "tests/test_parallel_markdown_report.py", "tests/test_global_modeler.py", "tests/test_semantic_modeling_usage.py", "tests/test_modeling_provider_usage.py", "tests/test_llm_client_tokens.py"]
NEW_TESTS = ["tests/test_instance_currentness_revocation_r33.py", "tests/test_instance_recovery_cost_r33.py", "tests/test_review_current_revisions_r33.py", "tests/test_native_classifier_currentness_r33.py", "tests/test_session_preentry_cost_r33.py"]
SESSION_TESTS = ["tests/test_wiki_workflow.py", "tests/test_wiki_service.py", "tests/test_validator_project_knowledge.py", "tests/test_scan_session_resume_svf.py"]
AUTHORITY = "artifacts/s01-authority-probe-r24-20261016/test_s01_authority_probe.py"
AUTHORITY_XML = "artifacts/coordinator-s01-repair-r31-r32-independent-20261017/authority-r24.xml"
ACTIVE_OUTPUT_CREATED = False


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest_required(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, label + " pending/invalid SHA")
    return value


def absolute_ref(value):
    path = Path(value)
    require(path.is_absolute() and path.is_file(), "missing/nonabsolute frozen reference: " + str(value))
    return str(path)


def merge_refs(target, additions):
    require(isinstance(additions, dict), "reference map must be an object")
    for name, digest in additions.items():
        name = absolute_ref(name)
        digest_required(digest, name)
        require(name not in target or target[name] == digest, "conflicting reference SHA: " + name)
        require(sha(name) == digest, "reference changed: " + name)
        target[name] = digest


def bind_ref(record, refs):
    require(isinstance(record, dict), "pending evidence reference")
    name = absolute_ref(record["path"])
    merge_refs(refs, {name: record["sha256"]})
    return Path(name)


def snapshot():
    return {p.relative_to(STAGE).as_posix(): sha(p) for p in STAGE.rglob("*") if p.is_file() and p.relative_to(STAGE).parts[0] != "artifacts" and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache"} for part in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


def configurations():
    return {p.relative_to(STAGE).as_posix(): sha(p) for name in CONFIG_NAMES for p in STAGE.rglob(name) if p.is_file()}


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


def case_rows(counter):
    return [list(key) + [value] for key, value in sorted(counter.items())]


def junit(path):
    tree = ET.parse(path).getroot()
    return {"tests": len(list(tree.iter("testcase"))), "failures": len(list(tree.iter("failure"))), "errors": len(list(tree.iter("error"))), "skipped": len(list(tree.iter("skipped")))}


def green_junit(path):
    value = junit(path)
    require(value["tests"] > 0 and value["failures"] == value["errors"] == value["skipped"] == 0, "not a complete no-skip green XML: " + str(path))
    return value


def safe_relative(name):
    path = Path(name)
    require(isinstance(name, str) and not path.is_absolute() and ".." not in path.parts and path.suffix == ".py", "only exact Stage Python paths are admitted")
    require((STAGE / path).is_file(), "selected input missing: " + name)
    return name


def chain(path):
    result = {}
    for item in (path, *path.parents, path.resolve(strict=True), *path.resolve(strict=True).parents):
        value = item.lstat()
        result[str(item)] = {"uid": value.st_uid, "gid": value.st_gid, "mode": value.st_mode, "physical": str(item.resolve(strict=True)), "symlink_target": os.readlink(item) if stat.S_ISLNK(value.st_mode) else None}
    return result


def file_identity(path):
    require(path.is_absolute() and path.is_file(), "missing host file: " + str(path))
    return {"sha256": sha(path), "physical": str(path.resolve(strict=True)), "chain": chain(path)}


def linked_identity(tool, environment):
    result = subprocess.run(["ldd", str(tool)], env=environment, capture_output=True, text=True, timeout=15)
    require(result.returncode == 0 and "not found" not in result.stdout + result.stderr, "ldd failed/missing library: " + str(tool))
    libraries = {Path(value) for value in re.findall(r"/[^\s()]+", result.stdout)}
    require(bool(libraries) and all(path.is_file() for path in libraries), "incomplete resolved ldd paths")
    # ASLR addresses are diagnostic data, not a stable identity. Pin every actual lexical/physical library and loader.
    bindings = {}
    for line in result.stdout.splitlines():
        paths = re.findall(r"/[^\s()]+", line)
        if paths:
            key = line.split("=>", 1)[0].strip() if "=>" in line else paths[0]
            require(key not in bindings, "duplicate ldd binding")
            bindings[key] = paths[-1]
    return {"tool": file_identity(tool), "bindings": bindings, "libraries": {str(path): file_identity(path) for path in sorted(libraries)}}


def standard_headers():
    result = {}
    for header in (Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")):
        value = file_identity(header)
        for item in value["chain"].values():
            require(item["uid"] == 0 and not item["mode"] & (stat.S_IWGRP | stat.S_IWOTH) and item["symlink_target"] is None, "glibc installation trust changed")
        result[str(header)] = value
    return result


def resource_headers(roots):
    require(isinstance(roots, list) and roots and len(set(roots)) == len(roots), "pending/ambiguous actual resource header roots")
    result = {}
    for value in roots:
        root = Path(value)
        require(root.is_absolute() and root.is_dir(), "missing actual resource-header root")
        entries = {".": {"chain": chain(root)}}
        for path in sorted(root.rglob("*")):
            entries[path.relative_to(root).as_posix()] = file_identity(path) if path.is_file() else {"chain": chain(path)}
        require(len(entries) > 1, "resource headers not captured")
        result[value] = entries
    return result


def host_inputs(intake, environment, svf_environment, validate_svf_llvm):
    require(sha(OLD_TOOL) == OLD_SHA, "old fixed tool changed")
    native = intake["new_native_tool"]
    require(native["path"] == str(NEW_TOOL), "new tool path is fixed")
    require(sha(NEW_TOOL) == digest_required(native["sha256"], "new tool") and native["sha256"] != OLD_SHA, "new binary SHA differs from frozen real build")
    require(str(NEW_TOOL.resolve(strict=True)) == native["physical"], "new binary physical identity changed")
    version = subprocess.run([str(NEW_TOOL), "--version"], env=environment, capture_output=True, text=True, timeout=15)
    require(version.returncode == 0, "new tool capability execution failed")
    capability = json.loads(version.stdout)
    require(capability == native["capability"] and capability.get("include_lookup_version") == 1 and capability.get("protocol") == "zscope.clang-facts.v2" and capability.get("position_encoding") == "utf-8" and str(capability.get("clang_version", "")).startswith("18."), "missing/changed new ordinary-lookup capability or LLVM18 binding")
    require(hashlib.sha256(version.stdout.encode()).hexdigest() == native["version_stdout_sha256"], "version bytes changed")
    tool_names = ("cmake", "gcc", "clang", "clangd", "gclang", "get-bc", "llvm-link", "llvm-nm", "wpa", "saber")
    tools = {name: shutil.which(name, path=environment.get("PATH")) for name in tool_names}
    require(all(tools.values()), "actual Linux login PATH tool missing")
    require(Path(tools["llvm-link"]).resolve(strict=True) == Path("/usr/lib/llvm-18/bin/llvm-link").resolve(strict=True), "LLVM18 selection changed")
    validate_svf_llvm("", tools["llvm-link"])
    runner_env = svf_environment("")
    ui_paths = (Path("/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"), Path("/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/package.json"), Path(shutil.which("node") or ""))
    return {"old_native": linked_identity(OLD_TOOL, environment), "new_native": linked_identity(NEW_TOOL, environment), "new_capability": capability, "new_version_stdout_sha256": native["version_stdout_sha256"], "standard_headers": standard_headers(), "resource_headers": resource_headers(native["resource_header_roots"]), "llvm_login_tools": {name: file_identity(Path(path)) for name, path in tools.items()}, "svf_runner": {name: linked_identity(Path(tools[name]), runner_env) for name in ("wpa", "saber")}, "ui": {str(path): file_identity(path) for path in ui_paths}}


def main():
    global ACTIVE_OUTPUT_CREATED
    require(HERE.name == "2026-10-14" and HERE.parent.name == "coordination", "candidate must first be reviewed and installed by coordinator into D")
    if sys.platform != "linux" or sys.executable != PYTHON or sys.flags.optimize or Path.cwd().resolve() != STAGE:
        raise RuntimeError("Fixed Linux Python, unoptimized mode and Stage cwd are required")
    if any(os.environ.get(key) for key in ("PYTHONOPTIMIZE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
        raise RuntimeError("Optimization and external pytest plugin/options are forbidden")
    require(os.getuid() != 0 and pwd.getpwuid(os.getuid()).pw_name == "zeal", "fixed ordinary Linux user zeal is required")
    intake = read(INTAKE)
    require(intake["schema"] == "zscope.stage-joint-intake.r35.v1" and intake["status"] == "ready" and intake["pending_dependencies"] == [], "aggregate intake dependencies still pending")
    require(intake["actual_task"] == "/root" and intake["stage_intake"] is True and intake["root_intake"] is False and intake["shared_source_review_passed"] is True and intake["bounded_independent_acceptance_passed"] is True and intake["new_native_source_review_passed"] is True and intake["new_native_job_independent_passed"] is True, "missing coordinator intake/source/native acceptance")
    require(intake["store_source_review_passed"] is True and intake["store_independent_passed"] is True, "Store seam source review/independent evidence still pending")
    require(intake["launcher_sha256"] == sha(Path(__file__)), "deployed launcher differs from reviewed candidate")
    refs = {}
    merge_refs(refs, intake["reference_sha256"])
    merge_refs(refs, {str(ROOT / name): digest for name, digest in FIXED_PINS.items()})
    merge_refs(refs, {str(Path(__file__)): intake["launcher_sha256"], str(INTAKE): sha(INTAKE)})
    core, checkpoint, inventory = read(ROOT / CORE), read(ROOT / CHECKPOINT), read(ROOT / INVENTORY)
    inventory_evidence_path = ROOT / "artifacts/native-regression-inventory-r34-20261017/inventory-evidence.json"
    merge_refs(refs, {str(inventory_evidence_path): inventory["artifacts_sha256_excluding_this_receipt_and_interpreter_cache"]["inventory-evidence.json"]})
    inventory_evidence = read(inventory_evidence_path)
    merge_refs(refs, core["reference_sha256"])
    merge_refs(refs, checkpoint["reference_sha256"])
    checkpoint_review = read(ROOT / "artifacts/coordinator-checkpoint-contract-r34-20261017/independent/review.json")
    merge_refs(refs, checkpoint_review["references_sha256"])
    require(core["stage_intake"] is True and core["selected150_and_seven_isolated_quality_commands_passed"] is True and checkpoint["checkpoint_contract_independent10_and_target_black_passed"] is True, "core/checkpoint prerequisites not accepted")
    build_path = bind_ref(intake["new_native_build_receipt"], refs)
    build = read(build_path)
    require(build["schema"] == "zscope.stage-native-build-evidence.r35.v1" and build["real_build_passed"] is True and build["old_install_unchanged"] is True, "real isolated native build pending")
    merge_refs(refs, build["reference_sha256"])
    require(build["binary_path"] == str(NEW_TOOL) and build["binary_sha256"] == intake["new_native_tool"]["sha256"] and build["capability"] == intake["new_native_tool"]["capability"], "native build/tool/capability binding differs")
    before = snapshot()
    require(before == intake["complete_inputs_after"] and len(before) == intake["complete_input_count"] and len(before) >= 1082, "complete actual Stage source set/SHA differs")
    config_before = configurations()
    require(config_before == intake["configuration_sha256"] == {"pyproject.toml": before["pyproject.toml"]}, "actual eight-basename configuration set must be the one frozen pyproject")
    native_sources = {p.relative_to(STAGE).as_posix(): sha(p) for p in (STAGE / "native/clang-indexer").rglob("*") if p.is_file()}
    require(native_sources == build["native_sources_sha256"] and len(native_sources) == 7, "all seven real native source/CMake/header inputs must match the real build")
    require(build["build_helper_sha256"] == before["scripts/build_clang_indexer.py"], "build helper differs from actual Stage source")
    source_review_path = bind_ref(intake["new_native_source_review"], refs)
    source_review = read(source_review_path)
    require(source_review["schema"] == "zscope.stage-native-source-review.r35.v1" and source_review["bounded_native_source_review_passed"] is True and source_review["complete_sources_sha256"] == before and source_review["native_sources_sha256"] == native_sources, "new native/Python source review not bound to actual complete source")
    merge_refs(refs, source_review["reference_sha256"])
    root_inputs = intake["root_inputs"]
    require(len(root_inputs) == 1065 and root_inputs == core["root_inputs"] == checkpoint["root_inputs"] and all(sha(ROOT / name) == digest for name, digest in root_inputs.items()), "Root1065 differs")
    job = intake["native_job_evidence"]
    job_review_path = bind_ref(job["independent_review"], refs)
    job_review = read(job_review_path)
    require(job_review["schema"] == "zscope.stage-native-job-evidence.r35.v1" and job_review["independent_native_job_passed"] is True and job_review["tool_sha256"] == build["binary_sha256"] and job_review["complete_inputs_sha256"] == before, "separate native job independent evidence not bound to current source/tool")
    merge_refs(refs, job_review["reference_sha256"])
    red_path, green_path = bind_ref(job["red_xml"], refs), bind_ref(job["green_xml"], refs)
    require(str(green_path) == job_review["results_xml"] and sha(green_path) == job_review["results_xml_sha256"], "job independent XML differs")
    require(job["red_test_sha256"] == job["green_test_sha256"] == before["tests/test_job_runtime_footprint_r34.py"], "new red/green formatted test bytes differ")
    job_counter = cases(red_path)
    require(bool(job_counter) and job_counter == cases(green_path), "actual full native-job red/green Counters differ")
    red_counts = junit(red_path)
    require(red_counts["tests"] == sum(job_counter.values()) and red_counts["failures"] > 0 and red_counts["errors"] == red_counts["skipped"] == 0, "original red must contain actual failures without setup errors or skips")
    red_audit_path = bind_ref(job["valid_red_audit"], refs)
    red_audit = read(red_audit_path)
    require(red_audit["schema"] == "zscope.stage-native-job-valid-red.r35.v1" and red_audit["actual_task"] == "/root" and red_audit["causal_review_passed"] is True and red_audit["evidence_guards_passed"] is True, "coordinator causal original-red audit missing")
    require(red_audit["results_xml"] == str(red_path) and red_audit["results_xml_sha256"] == sha(red_path) and red_audit["test_sha256"] == before["tests/test_job_runtime_footprint_r34.py"] and red_audit["case_counter"] == case_rows(job_counter) and red_audit["junit"] == red_counts, "causal audit is not bound to the exact actual red XML/test/Counter")
    merge_refs(refs, red_audit["reference_sha256"])
    raw_red_path = bind_ref(red_audit["raw_red_receipt"], refs)
    raw_red = read(raw_red_path)
    require(raw_red["test_started"] is True and raw_red["evidence_guards_passed"] is True and bool(raw_red["guards"]) and all(value is True for value in raw_red["guards"].values()), "raw original-red execution did not preserve all evidence guards")
    require(raw_red["new_test_sha256"] == red_audit["test_sha256"] and raw_red["case_counter"] == case_rows(job_counter) and raw_red["junit"] == red_counts and raw_red["artifact_sha256"]["results.xml"] == sha(red_path), "raw red receipt/test/actual XML identities differ")
    require(bool(raw_red["commands"]) and any(command["returncode"] == 1 for command in raw_red["commands"]), "actual original-red pytest failure execution absent")
    failed_identities = {(node.get("classname", ""), node.get("name", "")) for node in ET.parse(red_path).getroot().iter("testcase") if node.find("failure") is not None}
    targets = red_audit["valid_target_failure_identities"]
    require(isinstance(targets, list) and bool(targets) and all(isinstance(row, list) and len(row) == 2 and all(isinstance(value, str) for value in row) for row in targets), "actual causal failure targets missing")
    target_identities = {tuple(row) for row in targets}
    original_job = ("tests.test_scan_session_jobs", "test_job_scan_runs_exact_instances_on_the_queue")
    require(len(target_identities) == len(targets) and original_job in target_identities and target_identities <= failed_identities and all(job_counter[identity] == 1 for identity in target_identities), "original real job failure and causal targets must actually fail once in the frozen red XML")
    causal_projection = bind_ref(red_audit["causal_projection"], refs)
    require(str(causal_projection) in red_audit["reference_sha256"] and read(causal_projection)["causal_review_passed"] is True, "fixed per-ID first-cause projection absent")
    green_junit(green_path)
    store = intake["store_evidence"]
    store_review_path = bind_ref(store["source_review"], refs)
    store_review = read(store_review_path)
    store_sources = {name: before[name] for name in ("zscope/orchestration/jobs/store.py", "tests/test_store_active_transactions_r35.py", "tests/test_trace_callback_generation_probe_r35.py")}
    require(store_review["schema"] == "zscope.stage-store-source-review.r35.v1" and store_review["bounded_store_source_review_passed"] is True and store_review["owned_sources_sha256"] == store_sources, "Store source review not bound to actual owned source/test")
    merge_refs(refs, store_review["reference_sha256"])
    store_independent_path = bind_ref(store["independent_review"], refs)
    store_independent = read(store_independent_path)
    require(store_independent["schema"] == "zscope.stage-store-evidence.r35.v1" and store_independent["independent_store_passed"] is True and store_independent["owned_sources_sha256"] == store_sources, "Store independent evidence not bound to final owned source/test")
    merge_refs(refs, store_independent["reference_sha256"])
    store_xml = bind_ref(store["results_xml"], refs)
    require(str(store_xml) == store_independent["results_xml"] and sha(store_xml) == store_independent["results_xml_sha256"], "Store independent actual XML differs")
    green_junit(store_xml)
    store_counter = cases(store_xml)
    trace_xml = bind_ref(store["trace_results_xml"], refs)
    require(str(trace_xml) == store_independent["trace_results_xml"] and sha(trace_xml) == store_independent["trace_results_xml_sha256"], "Store permanent trace independent actual XML differs")
    green_junit(trace_xml)
    trace_counter = cases(trace_xml)
    trace_names = {"test_real_user_trace_callback_cannot_resurrect_issued_generation[" + route + "]" for route in ("connection_sql", "cursor_sql", "commit_api", "rollback_api", "normal_trace")}
    require(sum(trace_counter.values()) == len(trace_counter) == 5 and {name for _classname, name in trace_counter} == trace_names, "permanent five real SQLite cases changed or missing")
    require(all(classname == "tests.test_trace_callback_generation_probe_r35" and count == 1 and store_counter[identity] == count for identity, count in trace_counter.items() for classname, _name in [identity]), "permanent trace raw Counter not present exactly once in Store independent regression")
    require(case_rows(trace_counter) == store_independent["trace_case_counter"], "permanent trace independent raw Counter changed")
    r32_path = ROOT / "artifacts/coordinator-stage-joint-r32-20261017/review.json"
    merge_refs(refs, {str(r32_path): sha(r32_path)})
    r32 = read(r32_path)
    old_tests = r32["commands"][2]["argv"][6:-1]
    require(len(old_tests) == 198, "original ordered 198 selection changed")
    additions = intake["additional_regression_test_paths"]
    require(isinstance(additions, list) and len(additions) == len(set(additions)), "additional exact paths must be unique")
    for name in additions:
        safe_relative(name)
    require(set(inventory["additional_regression_test_paths"]) <= set(additions), "inventory six paths omitted")
    require("tests/test_store_active_transactions_r35.py" in additions, "future Store test must join the final actual regression selection")
    require("tests/test_trace_callback_generation_probe_r35.py" in additions, "permanent five trace generation regressions must join the final actual selection")
    tests = list(dict.fromkeys(old_tests + COST_TESTS + NEW_TESTS + SESSION_TESTS + additions))
    require(tests[:198] == old_tests, "ordered old198 changed")
    test_paths = [Path(name) if Path(name).is_absolute() else STAGE / name for name in tests]
    require(all(path.is_file() for path in test_paths), "selected file missing")
    require(len(test_paths) == len({path.resolve(strict=True) for path in test_paths}) == len({(path.stat().st_dev, path.stat().st_ino) for path in test_paths}), "physical/samefile test alias would duplicate collection")
    prior = {}
    for label, (name, count) in PRIOR.items():
        path = ROOT / name
        expected_digest = inventory_evidence["prior_xml"][label]["sha256"] if label in inventory_evidence["prior_xml"] else FIXED_PINS[name]
        merge_refs(refs, {str(path): expected_digest})
        prior[label] = cases(path)
        require(sum(prior[label].values()) == count, "original XML total changed: " + label)
        if label in inventory_evidence["prior_xml"]:
            require(case_rows(prior[label]) == inventory_evidence["prior_xml"][label]["case_counter"], "original raw Counter changed: " + label)
        else:
            green_junit(path)
    prior["new_native_job"] = job_counter
    prior["store_independent"] = store_counter
    expected_union = Counter()
    for label, counter in prior.items():
        for identity, count in counter.items():
            require(identity not in expected_union or expected_union[identity] == count, "prior Counter multiplicity conflict: " + label)
            expected_union[identity] = count
    authority, authority_xml = ROOT / AUTHORITY, ROOT / AUTHORITY_XML
    merge_refs(refs, {str(authority): sha(authority), str(authority_xml): sha(authority_xml)})
    authority_prior = cases(authority_xml)
    require(sum(authority_prior.values()) == 4, "separate authority4 changed")
    frozen_external_sha = {row["argument"]: row["sha256"] for row in inventory_evidence["selected_files"] if Path(row["argument"]).is_absolute()}
    for path in test_paths:
        if path.is_relative_to(STAGE):
            require(before[path.relative_to(STAGE).as_posix()] == sha(path), "selected Stage test not pinned")
        else:
            require(str(path) in frozen_external_sha, "external old198 test absent from frozen inventory")
            merge_refs(refs, {str(path): frozen_external_sha[str(path)]})
    core_review = read(ROOT / "artifacts/coordinator-shared-style-r34-20261017/independent/review.json")
    old_black = r32["commands"][6]["argv"]
    core_black = core_review["commands"][5]["argv"]
    require(old_black[:4] == core_black[:4] == [PYTHON, "-m", "black", "--check"], "prior Black scope unavailable")
    changed_python = sorted(name for name, digest in before.items() if name.endswith(".py") and core["complete_inputs_before"].get(name) != digest)
    require(changed_python == sorted(intake["changed_python_source_paths"]), "actual changed/new Python scope was omitted or expanded")
    black_paths = list(dict.fromkeys(old_black[4:] + core_black[4:] + changed_python))
    require(black_paths == intake["black_paths"], "Black must retain prior scope plus actual changed/new Python, without test-only additions")
    for name in black_paths:
        safe_relative(name)
        require(before[name] == sha(STAGE / name), "actual Black input is not source-pinned")
    env = os.environ.copy()
    env.update(Z_SCOPE_TEST_CLANG_INDEXER=str(NEW_TOOL), Z_SCOPE_TEST_LLVM="1", ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright", ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome", ZSCOPE_UI_MULTI_TARGET_EDITING="1")
    for key, directory in (("ZSCOPE_UI_EVIDENCE", "browser"), ("ZSCOPE_UI_CONFIG_EVIDENCE", "config"), ("ZSCOPE_UI_JOB_EVIDENCE", "owner"), ("ZSCOPE_INSTANCE_EVIDENCE", "native-browser"), ("ZSCOPE_UX_BOUNDARY_EVIDENCE", "boundaries")):
        env[key] = str(OUT / directory)
    # No pytest config/plugins/capture overrides; the one outer wrapper owns the ext4 temp/fd setup.
    OUT.mkdir(exist_ok=False)
    ACTIVE_OUTPUT_CREATED = True
    write(OUT / "startup.json", {"actual_task": "/root", "started_at_utc": now(), "complete_inputs": before, "reference_sha256": refs, "intake_dependencies_ready": True, "preflight_and_joint_not_yet_passed": True})
    from root_runtime_preflight_r23 import inspect_root_runtime
    sys.path.insert(0, str(STAGE))
    from zscope.retrieval.llvm_toolchain import svf_environment, validate_svf_llvm
    runtime_before = inspect_root_runtime(require_slot=True)
    host_before = host_inputs(intake, env, svf_environment, validate_svf_llvm)
    require(host_before == intake["host_inputs_after_independent"] == build["host_snapshot"], "actual old/new tool/libs/headers/trust/LLVM/UI inputs differ from independent freeze")
    commands = [
        [PYTHON, "-m", "mypy", "zscope"],
        [PYTHON, "-m", "mypy", "--no-incremental", "zscope"],
        [PYTHON, "-m", "pytest", "-q", f"--rootdir={STAGE}", f"--confcutdir={STAGE}", *tests, f"--junitxml={OUT / 'results.xml'}"],
        [PYTHON, "-m", "pytest", "-q", f"--rootdir={STAGE}", f"--confcutdir={STAGE}", str(authority), f"--junitxml={OUT / 'authority-r24.xml'}"],
        [PYTHON, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
        [PYTHON, "-m", "mypy", "scripts/agent_plan_evaluation.py"],
        [PYTHON, "-m", "black", "--check", *black_paths],
        [PYTHON, "scripts/portable/web_assets.py"],
    ]
    require(len(commands) == 8, "original eight commands must remain")
    write(OUT / "preflight.json", {"actual_task": "/root", "started_at_utc": now(), "source": before, "configurations": config_before, "root_inputs": root_inputs, "reference_sha256": refs, "old198": old_tests, "tests": tests, "black_paths": black_paths, "changed_python_source_paths": changed_python, "commands": commands, "prior_case_counters": {name: case_rows(counter) for name, counter in prior.items()}, "authority4_counter": case_rows(authority_prior), "native_job_red_counter": case_rows(job_counter), "runtime_before": runtime_before, "host_inputs_before": host_before, "explicit_test_environment": {name: env[name] for name in ("Z_SCOPE_TEST_CLANG_INDEXER", "Z_SCOPE_TEST_LLVM", "ZSCOPE_UI_PLAYWRIGHT_MODULE", "ZSCOPE_UI_CHROMIUM", "ZSCOPE_UI_MULTI_TARGET_EDITING")}, "default_fd_capture": True, "outer_test_slot_wrappers": 1, "root_intake": False})
    results = []
    for index, command in enumerate(commands):
        started = now()
        with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
            result = subprocess.run(command, cwd=STAGE, env=env, stdout=stream, stderr=subprocess.STDOUT)
        results.append({"argv": command, "returncode": result.returncode, "started_at_utc": started, "finished_at_utc": now()})
        write(OUT / f"command-{index}-receipt.json", results[-1])
        print(json.dumps({"command_index": index, "returncode": result.returncode}), flush=True)
    counts = {}
    counters = {}
    parse_errors = {}
    for name in ("results", "authority-r24"):
        try:
            counts[name], counters[name] = junit(OUT / f"{name}.xml"), cases(OUT / f"{name}.xml")
        except (OSError, ET.ParseError) as error:
            parse_errors[name] = {"type": type(error).__name__, "message": str(error)}
    actual = counters.get("results", Counter())
    preserved = {label: all(actual[identity] == count for identity, count in counter.items()) for label, counter in prior.items()}
    host_after = host_inputs(intake, env, svf_environment, validate_svf_llvm)
    runtime_after = inspect_root_runtime(require_slot=True)
    gates = {"complete_actual_stage_source_set_and_sha": snapshot() == before, "configuration_set_and_sha": configurations() == config_before, "root1065": all(sha(ROOT / name) == digest for name, digest in root_inputs.items()), "all_references": all(sha(name) == digest for name, digest in refs.items()), "old_new_tools_resolved_libs_resource_headers_trust_llvm_ui": host_after == host_before, "old_preflight_and_ext4_slot_still_valid": runtime_after == runtime_before, "all_original_and_new_counters_exact": all(preserved.values()), "separate_authority4_exact": counters.get("authority-r24") == authority_prior, "both_XML_files_parsed": not parse_errors and len(counts) == 2}
    passed = all(gates.values()) and all(item["returncode"] == 0 for item in results) and all(value["tests"] > 0 and value["failures"] == value["errors"] == value["skipped"] == 0 for value in counts.values())
    write(OUT / "review.json", {"actual_task": "/root", "finished_at_utc": now(), "commands": results, "junit": counts, "XML_parse_errors": parse_errors, "gates": gates, "prior_case_counters_preserved": preserved, "actual_counter": case_rows(actual), "host_inputs_after": host_after, "selected_stage_joint_checks_passed": passed, "full_stage_quality_passed": all(gates.values()) and all(results[index]["returncode"] == 0 for index in (0, 1, 4, 5, 6, 7)), "old_tool_passes_added_to_new_tool_acceptance": False, "separate_native_job_prerequisite_is_not_this_joint": True, "root_intake": False, "root_joint_verification": False, "full_repository_suite_run": False, "full_packages_complete": False, "real_project_effect_acceptance": False})
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        if ACTIVE_OUTPUT_CREATED and OUT.is_dir() and not (OUT / "aborted-review.json").exists():
            write(OUT / "aborted-review.json", {"actual_task": "/root", "finished_at_utc": now(), "error_type": type(error).__name__, "error": str(error), "selected_stage_joint_checks_passed": False, "all_required_gates_completed": False, "existing_logs_XML_and_per_command_receipts_preserved": True, "root_intake": False, "root_joint_verification": False})
        raise
