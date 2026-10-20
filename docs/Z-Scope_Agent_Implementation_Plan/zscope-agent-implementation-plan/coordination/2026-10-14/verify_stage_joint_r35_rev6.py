"""Coordinator-only Stage joint candidate; never execute from the draft directory."""
from __future__ import annotations

from collections import Counter
import datetime as dt
import hashlib
import importlib
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
INTAKE = ROOT / "artifacts/stage-shared-intake-r35-20261019/receipt.json"
OUT = ROOT / "artifacts/coordinator-stage-joint-r35-20261019"
PYTHON = "/home/zeal/venv313/bin/python"
OLD_TOOL = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
OLD_SHA = "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
NEW_TOOL = Path("/home/zeal/.cache/zscope-job-runtime-footprint-r34/install/bin/zscope-clang-indexer")
CONFIG_NAMES = ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml")
INVENTORY = "artifacts/native-regression-inventory-r34-20261017/receipt-final-v2.json"
CORE = "artifacts/stage-core-intake-r34-20261017/receipt.json"
CHECKPOINT = "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
FIXED_PINS = {
    "artifacts/coordinator-native-independent-launcher-draft-r35-20261019/revision-4/verify_native_job_independent_r35.py": "2289b8ac93b742638f0bd533aa46c055e9c665735d92d214795a321e24683fc9",
    "artifacts/coordinator-native-independent-launcher-draft-r35-20261019/revision-4/receipt.json": "a9f9b80a3533e86fd6f063942262836ff3d441aa6b66496f26929aeb9524596d",
    "artifacts/stage-joint-launcher-rev5-draft-r35-20261017/revision-2/verify_stage_joint_r35_rev5_v2.py": "53ab21715d5aac586344338360ff40892cf55a13dd1763551691651a229364db",
    "artifacts/coordinator-native-independent-launcher-draft-r35-20261017/revision-3/verify_native_job_independent_r35.py": "abaaad92a15258835c943a83051c99a4a130c955a9ce1ce86ad60ad90ec80c7b",
    "artifacts/stage-joint-launcher-rev5-draft-r35-20261017/verify_stage_joint_r35_rev5.py": "96026d7480ab7c4cc27001d6a21e3982fb4b9b5f4d386613953d41f31d6cdc0f",
    "artifacts/stage-joint-launcher-rev5-draft-r35-20261017/receipt.json": "b3e299ba0f55183f6d6564511d357fcb97a5b901e79a4279b1a63a408135ec44",
    "artifacts/job-runtime-footprint-source-review-r34-20261017/prewrite-probe-revised/review.json": "38667512b29636b03de43e6b38a96a2da4b374798c77a180a81271c6ce31fb91",
    "artifacts/job-runtime-footprint-source-review-r34-20261017/prewrite-probe-revised/prewrite-probe-draft-v3.py": "c9a465f15a5af3472bdba96ebcaf972285d1636ff698e0f791a8b2f615497697",
    "artifacts/job-runtime-footprint-source-review-r34-20261017/prewrite-probe-revised/prewrite-probe-runner-v2.py": "73954b7278ea9c5e7c225ac5b44e5601efcb1477eb8f59d75a1d5ead9cbc852c",
    ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/runner-v7/collect-lookup-v8/collected.json": "e87c045c1cb98b472f058e3bbb2f2ef148a83272d95355f34121b4f60fe99f1f",
    ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/runner-v7/collect-lookup-v8/receipt.json": "37269cc5e95786639fadf4cdf5f415acb00f6e48922cb052df2ebad424367908",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/verify_stage_joint_r35_rev4.py": "dd078e068d91b6e7c5e22a5e0a0824276556b91e47a5b42ff55f8e9e410a0f8f",
    "artifacts/stage-joint-launcher-source-review-r35-20261017/revision-4-review.json": "3a74271eb63c1e82539222441259d271d03b23a0ab1067fc9741445880219a1b",
    "artifacts/job-runtime-footprint-repair-r34-20261017/ownership-extension-prewrite-r35.json": "387b6a879bd4284b78725c8a6bdb421c5cbec0a447fc8ebfe19fd57093badc29",
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
PREWRITE_TEST = "tests/test_job_runtime_prewrite_r35.py"
ORIGINAL_JOB_TEST_SHA = "ac34d7a64e0998e052780fc1f23283875781fc784d2c1141b52e3b827cc09b57"
ORIGINAL_JOB_COLLECTION = ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/runner-v7/collect-lookup-v8"
# Obligations from the reviewed draft, not an assertion that collection has run.
PREWRITE_CLASS = "tests.test_job_runtime_prewrite_r35"
PREWRITE_POSITIVE_NAMES = {"test_prewrite_probe_native_job_positive_closes_queue[" + batch + "]" for batch in ("False", "True")}
PREWRITE_BACKUP_NAMES = {"test_batch_backup_link_to_actual_input_is_refused_before_copy[" + source + "-" + link + "]" for source in ("source", "header") for link in ("hardlink", "symlink")}
PREWRITE_TOOL_NAME = "test_revoked_real_tool_copy_is_refused_before_first_store_connection"
THIRD_TEST = "tests/test_job_indexed_input_prewrite_r35.py"
NATIVE_INDEPENDENT_WORK = ROOT / ".coordination/20261014/workspaces/coordinator-native-job-independent-r35"
NATIVE_INDEPENDENT_OUT = ROOT / "artifacts/coordinator-native-job-independent-r35-20261017/independent"
LEGAL_FIXTURES = ("test_job_runtime_footprint_r34", "test_job_runtime_prewrite_r35",
                  "test_scan_session_instances", "test_scan_session_jobs")
THIRD_NAMES = {"test_third_indexed_tu_normal_header_keeps_real_job_drained",
               "test_third_indexed_tu_runtime_header_is_refused_before_replace"}


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


def raw_prewrite_execution(record, phase, test_sha, counter, refs, final_source=None):
    raw_path = bind_ref(record["raw_receipt"], refs)
    freeze_path = bind_ref(record["phase_freeze"], refs)
    launcher_path = bind_ref(record["launcher"], refs)
    imported_path = bind_ref(record["imported_product_source"], refs)
    raw, frozen, imported = read(raw_path), read(freeze_path), read(imported_path)
    require(raw["phase"] == frozen["phase"] == phase and raw["command_started"] is True, "prewrite raw phase/real command absent")
    require(raw["freeze_sha256"] == sha(freeze_path) and frozen["launcher_sha256"] == sha(launcher_path), "prewrite raw freeze/launcher differs")
    merge_refs(refs, frozen["references_sha256"])
    require(raw["fixed_test_sha256"] == frozen["candidate_source_sha256"][PREWRITE_TEST] == test_sha, "prewrite raw/frozen test bytes differ")
    require(raw["candidate_before"] == raw["candidate_after"] == frozen["candidate_source_sha256"], "prewrite raw complete source set/SHA changed")
    require(raw["candidate_before"]["tests/test_job_runtime_footprint_r34.py"] == ORIGINAL_JOB_TEST_SHA, "original ac34/53 test was modified")
    if final_source is not None:
        require(raw["candidate_before"] == final_source, "prewrite green source is not the final complete Stage source")
    require(raw["case_counter"] == frozen["expected_case_counter"] == case_rows(counter), "prewrite actual/frozen/collected raw Counter differs")
    require(raw["evidence_guards_passed"] is True and bool(raw["guards"]) and all(value is True for value in raw["guards"].values()), "prewrite raw execution guards failed or missing")
    require(imported["valid"] is True and bool(imported["modules"]) and all(row["valid"] is True for row in imported["modules"].values()), "prewrite imported product provenance failed")
    require(raw["artifact_sha256"]["imported-product-source.json"] == sha(imported_path), "prewrite raw imported product receipt changed")
    require(bool(raw["artifact_sha256"]), "prewrite raw artifacts are missing")
    for name, digest in raw["artifact_sha256"].items():
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts and name != "receipt.json", "invalid raw prewrite artifact path")
        merge_refs(refs, {str(raw_path.parent / relative): digest})
    require(len(raw["commands"]) == 1 and raw["commands"][0]["returncode"] == (1 if phase == "red" else 0), "prewrite actual command exit differs from required phase")
    require(raw["test_started"] is (phase != "collect") and raw["passed"] is (phase != "red"), "prewrite raw execution classification differs")
    return raw


def prewrite_evidence(intake, before, build, refs):
    evidence = intake["prewrite_evidence"]
    require(intake["prewrite_independent_passed"] is True and evidence["status"] == "ready" and evidence["pending_dependencies"] == [], "prewrite actual evidence is pending")
    test_sha = before[PREWRITE_TEST]
    require(evidence["test_path"] == PREWRITE_TEST and evidence["red_test_sha256"] == evidence["green_test_sha256"] == test_sha, "prewrite original red/green/final source SHA differs")
    require(before["tests/test_job_runtime_footprint_r34.py"] == ORIGINAL_JOB_TEST_SHA, "original ac34/53 source SHA changed")
    planned = Counter((PREWRITE_CLASS, name) for name in PREWRITE_POSITIVE_NAMES | PREWRITE_BACKUP_NAMES | {PREWRITE_TOOL_NAME})
    collection_path = bind_ref(evidence["collection_review"], refs)
    collection = read(collection_path)
    require(collection["schema"] == "zscope.stage-prewrite-collection.r35.v1" and collection["actual_task"] == "/root" and collection["actual_collection_review_passed"] is True, "actual prewrite collection review missing")
    require(collection["test_path"] == PREWRITE_TEST and collection["test_sha256"] == test_sha and collection["case_counter"] == case_rows(planned), "actual seven identities differ from reviewed obligations; recollect/review explicitly")
    merge_refs(refs, collection["reference_sha256"])
    collected_path = bind_ref(collection["collected_json"], refs)
    collected = read(collected_path)
    require(collected["case_counter"] == collection["case_counter"], "prewrite actual collection artifact Counter differs")
    collected_nodeids = [PREWRITE_TEST + "::" + name for _classname, name in planned]
    require(Counter(collected["nodeids"]) == Counter(collected_nodeids), "prewrite raw collect nodeids differ or duplicate")
    raw_collect = raw_prewrite_execution(collection["execution"], "collect", test_sha, planned, refs)
    require(raw_collect["artifact_sha256"]["collected.json"] == sha(collected_path), "actual collected JSON not bound to raw receipt")
    red_path, green_path = bind_ref(evidence["red_xml"], refs), bind_ref(evidence["green_xml"], refs)
    red_counter, green_counter = cases(red_path), cases(green_path)
    require(red_counter == green_counter == planned and evidence["actual_counter"] == case_rows(red_counter) and evidence["actual_test_count"] == 7, "prewrite full actual red/green/collection Counter differs")
    require(junit(red_path) == {"tests": 7, "failures": 5, "errors": 0, "skipped": 0}, "prewrite red must be actual five failures plus two passes, no errors/skips")
    green_junit(green_path)
    red_nodes = {(node.get("classname", ""), node.get("name", "")): node for node in ET.parse(red_path).getroot().iter("testcase")}
    positives = {(PREWRITE_CLASS, name) for name in PREWRITE_POSITIVE_NAMES}
    negatives = set(planned) - positives
    require({identity for identity, node in red_nodes.items() if node.find("failure") is not None} == negatives, "prewrite positive controls failed or five intended negative failures differ")
    for identity in positives:
        properties = [node.get("value") for node in red_nodes[identity].findall("properties/property") if node.get("name") == "positive_job"]
        require(len(properties) == 1 and json.loads(properties[0]) == {"batch": identity[1].endswith("[True]"), "analyzed": 2, "checkpointed": True}, "prewrite positive control did not actually close the native queue")
    audit_path = bind_ref(evidence["valid_red_audit"], refs)
    audit = read(audit_path)
    require(audit["schema"] == "zscope.stage-prewrite-valid-red.r35.v1" and audit["actual_task"] == "/root" and audit["evidence_kind"] == "actual-red-execution-causality" and audit["causal_review_passed"] is True and audit["evidence_guards_passed"] is True, "static review cannot substitute for actual prewrite red causality")
    require(audit["results_xml"] == str(red_path) and audit["results_xml_sha256"] == sha(red_path) and audit["test_sha256"] == test_sha and audit["case_counter"] == case_rows(red_counter) and audit["junit"] == junit(red_path), "prewrite causal audit is not bound to the exact raw red XML/test/Counter")
    require(audit["positive_pass_identities"] == [list(identity) for identity in sorted(positives)] and audit["valid_target_failure_identities"] == [list(identity) for identity in sorted(negatives)], "prewrite actual red pass/failure identities differ")
    merge_refs(refs, audit["reference_sha256"])
    raw_red = raw_prewrite_execution(audit["execution"], "red", test_sha, red_counter, refs)
    require(raw_red["artifact_sha256"]["results.xml"] == sha(red_path) and raw_red["junit"] == junit(red_path), "prewrite raw red XML receipt changed")
    projection_path = bind_ref(audit["causal_projection"], refs)
    projection = read(projection_path)
    require(projection["schema"] == "zscope.stage-prewrite-first-cause.r35.v1" and projection["actual_task"] == "/root" and projection["causal_review_passed"] is True, "prewrite actual first-cause projection missing")
    require(projection["red_xml_sha256"] == sha(red_path) and projection["test_sha256"] == test_sha and projection["case_counter"] == case_rows(red_counter), "prewrite first-cause projection XML/test/Counter differs")
    merge_refs(refs, projection["reference_sha256"])
    rows = projection["cases"]
    require(isinstance(rows, list) and len(rows) == 5 and {tuple(row["identity"]) for row in rows} == negatives, "prewrite per-ID first-cause projection missing/duplicated")
    for row in rows:
        identity = tuple(row["identity"])
        failure = red_nodes[identity].find("failure")
        values = [node.get("value") for node in red_nodes[identity].findall("properties/property") if node.get("name") == "prewrite_observation"]
        require(len(values) == 1 and row["observation_property"] == "prewrite_observation" and row["observation_value_sha256"] == hashlib.sha256(values[0].encode()).hexdigest(), "prewrite first-cause observation is not actual XML property bytes")
        require(row["failure_element_sha256"] == hashlib.sha256(ET.tostring(failure, encoding="utf-8")).hexdigest(), "prewrite projected first failed assertion differs")
        observed = json.loads(values[0])
        require(len(observed["native_plans"]) == 1 and observed["native_plans"][0]["instances"] == observed["native_plans"][0]["current_contexts"] == 2 and observed["native_plans"][0]["tool_sha256"] == [build["binary_sha256"]], "prewrite target failed before the real current two-variant native plan")
        if identity[1] in PREWRITE_BACKUP_NAMES:
            require(observed["risk_gate_reached"] is True and observed["causal_classification"] == "actual_copy_or_exact_target_gate_reached", "inconclusive backup target reachability is not a causal red")
            require(row["first_failed_gate"] == "dangerous_copy_calls_empty" and bool(observed["dangerous_copy_calls"]) and observed["actual_input_before"]["sha256"] != observed["actual_input_after"]["sha256"], "prewrite backup red lacks actual forwarded input-alias copy damage")
            require("the real copy operation must never follow a link to an input" in (failure.text or ""), "prewrite backup first failure is an earlier unrelated guard")
        else:
            require(observed["risk_gate_reached"] is True and observed["causal_classification"] == "actual_revoked_tool_verifier_reached", "inconclusive revoked-tool target reachability is not a causal red")
            require(bool(observed["store_connects"]) and observed["store_connects"][0]["native_plan_finished"] is True, "prewrite revoked-tool red did not reach the first real Store connection")
            require(observed["tool_before"]["sha256"] == build["binary_sha256"] and observed["tool_revoked"]["sha256"] != observed["tool_before"]["sha256"] and observed["tool_revoked"]["mtime_ns"] == observed["tool_before"]["mtime_ns"], "prewrite tool control is not actual same-mtime byte revocation")
            revoked_gates = [gate for gate in observed["native_tool_gates"] if gate["recorded_tool_sha256"] == observed["tool_before"]["sha256"] and gate["actual_tool_sha256"] == observed["tool_revoked"]["sha256"] and gate.get("actual_current_result") is False]
            require(bool(revoked_gates), "prewrite red lacks the actual failed emitting-byte verifier")
            if row["first_failed_gate"] == "native_tool_verifier_before_store":
                require(not any(gate["store_connects_before_gate"] == 0 for gate in revoked_gates) and any(gate["store_connects_before_gate"] > 0 for gate in revoked_gates), "prewrite projected late verifier does not follow the real Store connection")
                require("the real emitting-byte verifier must observe the revoked tool before any Store connection" in (failure.text or ""), "prewrite tool first failure is not the actual v3 verifier-before-store guard")
            else:
                require(row["first_failed_gate"] == "store_connects_empty" and any(gate["store_connects_before_gate"] == 0 for gate in revoked_gates), "prewrite projected ignored preconnect verifier was not actually reached")
                require("withdrawn native authority must precede even a WAL-capable Store connection" in (failure.text or ""), "prewrite tool first failure is an earlier unrelated guard")
    independent_path = bind_ref(evidence["independent_review"], refs)
    independent = read(independent_path)
    require(independent["schema"] == "zscope.stage-prewrite-evidence.r35.v1" and independent["actual_task"] == "/root" and independent["independent_prewrite_passed"] is True and independent["tool_sha256"] == build["binary_sha256"] and independent["complete_inputs_sha256"] == before, "prewrite independent green is not bound to final source/tool")
    require(independent["results_xml"] == str(green_path) and independent["results_xml_sha256"] == sha(green_path) and independent["test_sha256"] == test_sha and independent["case_counter"] == case_rows(green_counter) and independent["junit"] == junit(green_path), "prewrite independent actual green XML/test/Counter differs")
    merge_refs(refs, independent["reference_sha256"])
    raw_green = raw_prewrite_execution(independent["execution"], "green", test_sha, green_counter, refs, before)
    require(raw_green["artifact_sha256"]["results.xml"] == sha(green_path) and raw_green["junit"] == junit(green_path), "prewrite raw green XML receipt changed")
    return red_counter


def actual_import_provenance(imported, product_root, source, refs, legal=None):
    require(imported["actual_task"] == "/root" and imported["valid"] is True
            and imported["modules"] and "zscope" in imported["modules"], "actual Root imported-product receipt missing")
    for name, item in imported["modules"].items():
        require(item["valid"] is True and (name == "zscope" or name.startswith("zscope.")), "invalid product import entry")
        if "path" in item:
            path = Path(item["path"])
            require(path.is_relative_to(product_root)
                    and source.get(path.relative_to(product_root).as_posix()) == item["sha256"], "recorded product import path/SHA differs")
        else:
            directory = product_root / name.replace(".", "/")
            require(item["namespace_paths"] and all(value == str(directory) for value in item["namespace_paths"])
                    and any(value.startswith(directory.relative_to(product_root).as_posix() + "/") for value in source), "recorded namespace differs")
    require(imported["modules"]["zscope"]["path"] == str(product_root / "zscope/__init__.py"), "actual product root differs")
    for item in imported["external_local_modules"].values():
        require(item["valid"] is True and refs.get(item["path"]) == item["sha256"], "recorded external import not frozen")
    if legal is not None:
        fixtures = imported["fixture_modules"]
        require(set(LEGAL_FIXTURES) <= set(fixtures), "actual four bare fixtures were not imported")
        for name, item in fixtures.items():
            basename = name.rsplit(".", 1)[-1]
            require(basename in LEGAL_FIXTURES and item["valid"] is True
                    and item["path"] == str(product_root / "tests" / (basename + ".py"))
                    and item["sha256"] == source["tests/" + basename + ".py"], "recorded legal fixture borrowed another tree")
        external = [item for item in imported["external_local_modules"].values() if item["path"] == str(legal)]
        require(external and all(item["sha256"] == refs[str(legal)] for item in external), "actual legal test import absent")


def final_native_group_evidence(intake, adapter, source, build, refs):
    # These are real Root executions by the independent launcher, not producer
    # aliases or a newly synthesized XML/Counter. The final Stage must have the
    # complete same1087 bytes, including the separately added third-TU test.
    ready_path = bind_ref(adapter["prerequisite_ready"], refs)
    ready = read(ready_path)
    require(ready["status"] == "ready" and ready["pending_dependencies"] == []
            and ready["actual_task"] == "/root" and ready["workspace"] == str(NATIVE_INDEPENDENT_WORK)
            and ready["complete_inputs_sha256"] == source and len(source) == 1087
            and ready["launcher_sha256"] == "2289b8ac93b742638f0bd533aa46c055e9c665735d92d214795a321e24683fc9"
            and ready["new_native_tool"]["sha256"] == build["binary_sha256"], "actual final independent ready/source/tool differs")
    merge_refs(refs, ready["reference_sha256"])
    aggregate_path = bind_ref(intake["native_job_evidence"]["independent_report"], refs)
    require(str(aggregate_path) == adapter["independent_report_path"]
            and aggregate_path == NATIVE_INDEPENDENT_OUT / "review.json", "actual Root aggregate path differs")
    aggregate = read(aggregate_path)
    labels = {"original53", "prewrite7", "third2", "s01_209", "core150", "checkpoint10",
              "native_related", "authority4", "llvm1", "legal_backup1"}
    require(aggregate["actual_task"] == "/root" and aggregate["passed"] is True
            and aggregate["independent_native_job_passed"] is True and aggregate["final_guard_passed"] is True
            and aggregate["errors"] == [] and aggregate["test_started"] is True
            and set(aggregate["groups"]) == labels and aggregate["groups"] == adapter["groups"]
            and len(aggregate["commands"]) == 16 and all(row["returncode"] == 0 for row in aggregate["commands"]), "actual ten groups plus six qualities did not fully pass")
    external = adapter["legal_backup_test"]
    legal = bind_ref(external, refs)
    own = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34"
    require(legal.is_relative_to(own) and legal.resolve(strict=True) == legal and legal.suffix == ".py"
            and legal.name.startswith("test_") and external == ready["groups"]["legal_backup1"]["external_test"], "actual immutable external test path differs")
    legal_review = read(bind_ref(ready["groups"]["legal_backup1"]["test_source_review"], refs))
    require(legal_review["source_review_passed"] is True
            and legal_review["source_sha256"].get(legal.relative_to(ROOT).as_posix()) == external["sha256"], "actual formatted legal test source review missing")
    merge_refs(refs, legal_review["reference_sha256"])
    counters = {}
    for label, count in (("original53", 53), ("prewrite7", 7), ("third2", 2), ("legal_backup1", 1)):
        group = adapter["groups"][label]
        raw_path = bind_ref({"path": group["raw_receipt"], "sha256": group["raw_receipt_sha256"]}, refs)
        require(raw_path == NATIVE_INDEPENDENT_OUT / label / "receipt.json", "Root actual raw group path differs")
        raw = read(raw_path)
        require(raw["actual_task"] == "/root" and raw["actual_agent_id"] == "/root"
                and raw["phase"] == "green" and raw["group"] == label
                and raw["test_started"] is True and raw["command_started"] is True and raw["passed"] is True
                and raw["evidence_guards_passed"] is True and raw["guards"] and all(value is True for value in raw["guards"].values())
                and raw["candidate_before"] == raw["candidate_after"] == source
                and len(raw["commands"]) == 1 and raw["commands"][0]["returncode"] == 0, "Root actual green/source/guards missing")
        require(raw["commands"][0]["argv"] == [PYTHON, str(HERE / "verify_native_job_independent_r35.py"), "--child", sha(ready_path), label, str(raw_path.parent)], "actual Root group invocation differs")
        for name, digest in raw["artifact_sha256"].items():
            path = Path(name)
            require(not path.is_absolute() and ".." not in path.parts and name != "receipt.json", "unsafe actual raw artifact")
            merge_refs(refs, {str(raw_path.parent / path): digest})
        frozen_path = raw_path.parent / "phase-freeze.json"
        require(refs.get(str(frozen_path)) == raw["freeze_sha256"], "actual group freeze SHA differs")
        frozen = read(frozen_path)
        require(frozen["phase"] == "green" and frozen["group"] == label
                and frozen["candidate_source_root"] == str(NATIVE_INDEPENDENT_WORK)
                and frozen["candidate_source_sha256"] == source
                and frozen["launcher_sha256"] == ready["launcher_sha256"], "actual group frozen source/launcher differs")
        merge_refs(refs, frozen["references_sha256"])
        xml = raw_path.parent / "results.xml"
        counter = cases(xml)
        counts = green_junit(xml)
        require(sum(counter.values()) == len(counter) == count
                and raw["case_counter"] == group["case_counter"] == frozen["expected_case_counter"] == case_rows(counter)
                and raw["junit"] == group["junit"] == counts, "actual group XML/Counter differs")
        imported = read(raw_path.parent / "imported-product-source.json")
        actual_import_provenance(imported, NATIVE_INDEPENDENT_WORK, source, refs, legal if label == "legal_backup1" else None)
        test = "tests/test_job_runtime_footprint_r34.py" if label == "original53" else THIRD_TEST if label == "third2" else PREWRITE_TEST
        require(raw["fixed_test_sha256"] == source[test], "Root raw group test bytes differ")
        if label == "legal_backup1":
            require(raw["fixed_external_test_sha256"] == external["sha256"], "Root external-test SHA differs from original seven")
        if label == "third2":
            require(counter == Counter(("tests.test_job_indexed_input_prewrite_r35", name) for name in THIRD_NAMES), "actual third identities changed")
        counters[label] = counter
    require(adapter["legal_backup_evidence_required"] is True
            and adapter["legal_backup_execution"] == adapter["groups"]["legal_backup1"]
            and adapter["legal_backup_xml"] == str(NATIVE_INDEPENDENT_OUT / "legal_backup1/results.xml")
            and adapter["legal_backup_xml_sha256"] == refs[adapter["legal_backup_xml"]], "actual legal group adapter missing")
    require(intake["prewrite_evidence"]["independent_review"] == adapter["prewrite_evidence_adapter"], "seven-case projection must refer to the same real Root group")
    return counters, legal


def external_configurations(paths):
    result = {}
    for path in paths:
        for parent in path.parents:
            for basename in CONFIG_NAMES:
                candidate = parent / basename
                if candidate.is_file():
                    result[str(candidate)] = sha(candidate)
    return result


def pytest_child(label, selection_sha):
    if sys.platform != "linux" or sys.executable != PYTHON or sys.flags.optimize or Path.cwd().resolve() != STAGE:
        raise RuntimeError("Fixed Linux/unoptimized Stage child is required")
    if any(os.environ.get(key) for key in ("PYTHONOPTIMIZE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
        raise RuntimeError("External optimization/pytest settings are forbidden")
    require(HERE.name == "2026-10-14" and HERE.parent.name == "coordination"
            and pwd.getpwuid(os.getuid()).pw_name == "zeal" and os.environ.get("ZSCOPE_COORDINATOR_TEST_SLOT"), "installed ordinary-user child under the held slot required")
    path = OUT / "pytest-selection.json"
    require(sha(path) == digest_required(selection_sha, "selection"), "actual selected-path record drift")
    selected = read(path)
    require(selected["actual_task"] == "/root" and selected["launcher_sha256"] == sha(Path(__file__))
            and snapshot() == selected["source"] and len(selected["source"]) == 1087
            and configurations() == selected["configurations"], "child complete source/config changed")
    refs = {}
    merge_refs(refs, selected["reference_sha256"])
    legal = bind_ref(selected["legal_backup_test"], refs)
    require(external_configurations([Path(value) for value in selected["external_tests"]]) == selected["external_configurations"], "child external configs changed")
    require(label in {"main", "authority"} and not any(name == "zscope" or name.startswith("zscope.") for name in sys.modules), "invalid child or product imported before source selection")
    paths = selected["tests"] if label == "main" else [str(ROOT / AUTHORITY)]
    for value in paths:
        physical = Path(value) if Path(value).is_absolute() else STAGE / value
        require(not value.startswith("-") and "::" not in value and physical.is_file(), "only fixed actual test files are accepted")
        if physical.is_relative_to(STAGE):
            require(selected["source"].get(physical.relative_to(STAGE).as_posix()) == sha(physical), "selected Stage file changed")
        else:
            require(refs.get(str(physical)) == sha(physical), "selected external file is not source-pinned")
    sys.path.insert(0, str(STAGE))
    sys.path.insert(0, str(STAGE / "tests"))
    import zscope
    require(Path(zscope.__file__).resolve() == STAGE / "zscope/__init__.py", "wrong actual Stage package")
    if label == "main":
        for name in LEGAL_FIXTURES:
            module = importlib.import_module(name)
            expected = STAGE / "tests" / (name + ".py")
            require(Path(module.__file__).resolve() == expected and sha(expected) == selected["source"]["tests/" + name + ".py"], "wrong actual Stage fixture")
    import pytest

    class ActualImports:
        def pytest_collection_finish(self, session):
            write(OUT / (label + "-collected-nodeids.json"), {"actual_task": "/root", "nodeids": [item.nodeid for item in session.items], "selection_sha256": selection_sha})

        def pytest_sessionfinish(self, session, exitstatus):
            modules, external, fixtures = {}, {}, {}
            for name, module in sorted(sys.modules.items()):
                filename = getattr(module, "__file__", None)
                path = Path(filename).resolve() if filename else None
                if label == "main" and name.rsplit(".", 1)[-1] in LEGAL_FIXTURES:
                    relative = "tests/" + name.rsplit(".", 1)[-1] + ".py"
                    fixtures[name] = {"path": str(path) if path else None, "sha256": sha(path) if path and path.is_file() else None,
                                      "valid": path == STAGE / relative and sha(path) == selected["source"][relative] if path and path.is_file() else False}
                if name == "zscope" or name.startswith("zscope."):
                    if path is not None:
                        relative = path.relative_to(STAGE).as_posix() if path.is_relative_to(STAGE) else None
                        value = sha(path) if path.is_file() else None
                        modules[name] = {"path": str(path), "sha256": value, "valid": relative in selected["source"] and selected["source"].get(relative) == value}
                    else:
                        directory = STAGE / name.replace(".", "/")
                        values = [str(Path(value).resolve()) for value in getattr(module, "__path__", ())]
                        matches = bool(values) and all(value == str(directory) for value in values) and any(value.startswith(directory.relative_to(STAGE).as_posix() + "/") for value in selected["source"])
                        modules[name] = {"namespace_paths": values, "valid": matches}
                elif path is not None and path.is_relative_to(ROOT) and not path.is_relative_to(STAGE) and path.is_file():
                    value = sha(path)
                    external[name] = {"path": str(path), "sha256": value, "valid": refs.get(str(path)) == value}
            valid = bool(modules) and all(item["valid"] for item in modules.values()) and all(item["valid"] for item in external.values())
            if label == "main":
                valid = valid and set(LEGAL_FIXTURES) <= set(fixtures) and all(item["valid"] for item in fixtures.values())
                valid = valid and any(item["path"] == str(legal) and item["valid"] for item in external.values())
            write(OUT / (label + "-imported-product-source.json"), {"actual_task": "/root", "valid": valid, "modules": modules, "external_local_modules": external, "fixture_modules": fixtures})
            if not valid:
                session.exitstatus = 2

    xml_name = "results.xml" if label == "main" else "authority-r24.xml"
    options = ["-q", "--rootdir=" + str(STAGE), "--confcutdir=" + str(STAGE), "--capture=fd", *paths, "--junitxml=" + str(OUT / xml_name)]
    write(OUT / (label + "-pytest-invocation.json"), {"actual_task": "/root", "argv": options, "workspace": str(STAGE), "selection_sha256": selection_sha, "source": selected["source"]})
    return pytest.main(options, plugins=[ActualImports()])


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
    require(intake["prewrite_independent_passed"] is True, "incremental prewrite actual collection/red/green/causal evidence still pending")
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
    require(before == intake["complete_inputs_after"] and len(before) == intake["complete_input_count"] == 1087, "complete final Stage1087 source set/SHA differs")
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
    native_group_counters, legal_backup_test = final_native_group_evidence(intake, job_review, before, build, refs)
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
    original_collection_path = ROOT / ORIGINAL_JOB_COLLECTION
    original_collection, original_collection_receipt = read(original_collection_path / "collected.json"), read(original_collection_path / "receipt.json")
    require(original_collection_receipt["evidence_guards_passed"] is True and original_collection_receipt["passed"] is True and all(value is True for value in original_collection_receipt["guards"].values()) and all(command["returncode"] == 0 for command in original_collection_receipt["commands"]), "frozen original53 actual collection did not pass")
    require(original_collection_receipt["new_test_sha256"] == ORIGINAL_JOB_TEST_SHA and original_collection_receipt["artifact_sha256"]["collected.json"] == sha(original_collection_path / "collected.json") and original_collection["case_counter"] == original_collection_receipt["case_counter"] == case_rows(job_counter), "original complete53 raw Counter/ac34 source differs from the fixed actual collection")
    original52 = Counter({identity: count for identity, count in job_counter.items() if identity[0] == "tests.test_job_runtime_footprint_r34"})
    require(len(job_counter) == sum(job_counter.values()) == 53 and len(original52) == sum(original52.values()) == 52 and job_counter[original_job] == 1 and set(job_counter) == set(original52) | {original_job}, "original53 must retain the complete raw Counter:52 native-job module cases plus the original SessionJobs identity")
    require(before["tests/test_job_runtime_footprint_r34.py"] == ORIGINAL_JOB_TEST_SHA, "original ac34 native-job source SHA changed")
    require(job_counter == native_group_counters["original53"], "original53 independent raw group differs")
    prewrite_counter = prewrite_evidence(intake, before, build, refs)
    require(prewrite_counter == native_group_counters["prewrite7"], "original7 independent raw group differs")
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
    require(len(store_counter) == sum(store_counter.values()) == 369, "full independent Store369 Counter changed")
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
    require(PREWRITE_TEST in additions, "incremental prewrite test must join the actual final joint selection")
    require(THIRD_TEST in additions and "tests/test_job_runtime_footprint_r34.py" in additions,
            "complete original53 and third2 actual files must join the final selection")
    require(intake["legal_backup_regression_test"] == job_review["legal_backup_test"], "mandatory external legal test declaration differs")
    tests = list(dict.fromkeys(old_tests + COST_TESTS + NEW_TESTS + SESSION_TESTS + additions + [str(legal_backup_test)]))
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
    prior["prewrite_independent"] = prewrite_counter
    prior["third_indexed_input_independent"] = native_group_counters["third2"]
    prior["legal_backup_independent"] = native_group_counters["legal_backup1"]
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
            if path == legal_backup_test:
                require(refs.get(str(path)) == job_review["legal_backup_test"]["sha256"], "mandatory legal external source drift")
            else:
                require(str(path) in frozen_external_sha, "external old198 test absent from frozen inventory")
                merge_refs(refs, {str(path): frozen_external_sha[str(path)]})
    core_review = read(ROOT / "artifacts/coordinator-shared-style-r34-20261017/independent/review.json")
    old_black = r32["commands"][6]["argv"]
    core_black = core_review["commands"][5]["argv"]
    require(old_black[:4] == core_black[:4] == [PYTHON, "-m", "black", "--check"], "prior Black scope unavailable")
    changed_python = sorted(name for name, digest in before.items() if name.endswith(".py") and core["complete_inputs_before"].get(name) != digest)
    require(changed_python == sorted(intake["changed_python_source_paths"]), "actual changed/new Python scope was omitted or expanded")
    black_paths = list(dict.fromkeys(old_black[4:] + core_black[4:] + changed_python + [str(legal_backup_test)]))
    require(black_paths == intake["black_paths"], "Black must retain prior scope plus actual changed/new Python, without test-only additions")
    for name in black_paths:
        if name == str(legal_backup_test):
            require(refs.get(name) == sha(name), "mandatory external Black input is not source-pinned")
        else:
            safe_relative(name)
            require(before[name] == sha(STAGE / name), "actual Black input is not source-pinned")
    external_tests = sorted({str(path) for path in test_paths if not path.is_relative_to(STAGE)} | {str(ROOT / AUTHORITY)})
    external_before = external_configurations([Path(path) for path in external_tests])
    allowed_external_configs = {str(ROOT / "pyproject.toml"), str(ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/pyproject.toml")}
    require(external_before == intake["external_configuration_sha256"] and set(external_before) <= allowed_external_configs
            and str(ROOT / "pyproject.toml") in external_before
            and all(value == before["pyproject.toml"] for value in external_before.values()), "external ancestors contain changed or unreviewed configs/conftest")
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
    selection_path = OUT / "pytest-selection.json"
    write(selection_path, {"actual_task": "/root", "launcher_sha256": sha(Path(__file__)), "source": before,
                           "configurations": config_before, "reference_sha256": dict(refs), "tests": tests,
                           "external_tests": external_tests, "external_configurations": external_before,
                           "legal_backup_test": job_review["legal_backup_test"]})
    selection_sha = sha(selection_path)
    merge_refs(refs, {str(selection_path): selection_sha})
    commands = [
        [PYTHON, "-m", "mypy", "zscope"],
        [PYTHON, "-m", "mypy", "--no-incremental", "zscope"],
        [PYTHON, str(Path(__file__)), "--pytest-child", "main", selection_sha],
        [PYTHON, str(Path(__file__)), "--pytest-child", "authority", selection_sha],
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
    import_errors = {}
    for label in ("main", "authority"):
        try:
            actual_import_provenance(read(OUT / (label + "-imported-product-source.json")), STAGE, before, refs,
                                     legal_backup_test if label == "main" else None)
        except Exception as error:
            import_errors[label] = {"type": type(error).__name__, "message": str(error)}
    host_after = host_inputs(intake, env, svf_environment, validate_svf_llvm)
    runtime_after = inspect_root_runtime(require_slot=True)
    gates = {"complete_actual_stage_source_set_and_sha": snapshot() == before, "configuration_set_and_sha": configurations() == config_before, "root1065": all(sha(ROOT / name) == digest for name, digest in root_inputs.items()), "all_references": all(sha(name) == digest for name, digest in refs.items()), "old_new_tools_resolved_libs_resource_headers_trust_llvm_ui": host_after == host_before, "old_preflight_and_ext4_slot_still_valid": runtime_after == runtime_before, "all_original_and_new_counters_exact": all(preserved.values()), "separate_authority4_exact": counters.get("authority-r24") == authority_prior, "both_XML_files_parsed": not parse_errors and len(counts) == 2}
    gates["both_real_pytest_children_imported_only_frozen_product_and_fixtures"] = not import_errors
    gates["external_ancestor_configuration_set_and_sha"] = external_configurations([Path(path) for path in external_tests]) == external_before
    passed = all(gates.values()) and all(item["returncode"] == 0 for item in results) and all(value["tests"] > 0 and value["failures"] == value["errors"] == value["skipped"] == 0 for value in counts.values())
    write(OUT / "native-prewrite-third-legal-counter-projection.json", {"actual_task": "/root", "evidence_kind": "projection-of-the-real-main-joint-XML-not-a-separate-execution",
          "results_xml": str(OUT / "results.xml"), "results_xml_sha256": sha(OUT / "results.xml") if (OUT / "results.xml").is_file() else None,
          "groups": {label: {"required_counter": case_rows(counter), "actual_counter": case_rows(Counter({identity: actual[identity] for identity in counter})), "exact": all(actual[identity] == count for identity, count in counter.items())} for label, counter in native_group_counters.items()},
          "import_errors": import_errors, "all_evidence_passed": passed})
    write(OUT / "review.json", {"actual_task": "/root", "finished_at_utc": now(), "commands": results, "junit": counts, "XML_parse_errors": parse_errors, "gates": gates, "prior_case_counters_preserved": preserved, "actual_counter": case_rows(actual), "host_inputs_after": host_after, "selected_stage_joint_checks_passed": passed, "full_stage_quality_passed": all(gates.values()) and all(results[index]["returncode"] == 0 for index in (0, 1, 4, 5, 6, 7)), "old_tool_passes_added_to_new_tool_acceptance": False, "separate_native_job_prerequisite_is_not_this_joint": True, "root_intake": False, "root_joint_verification": False, "full_repository_suite_run": False, "full_packages_complete": False, "real_project_effect_acceptance": False})
    return 0 if passed else 1


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--pytest-child":
        raise SystemExit(pytest_child(sys.argv[2], sys.argv[3]))
    if len(sys.argv) != 1:
        raise SystemExit("Only the fixed installed parent or its exact frozen-path child invocation is accepted")
    try:
        raise SystemExit(main())
    except Exception as error:
        if ACTIVE_OUTPUT_CREATED and OUT.is_dir() and not (OUT / "aborted-review.json").exists():
            write(OUT / "aborted-review.json", {"actual_task": "/root", "finished_at_utc": now(), "error_type": type(error).__name__, "error": str(error), "selected_stage_joint_checks_passed": False, "all_required_gates_completed": False, "existing_logs_XML_and_per_command_receipts_preserved": True, "root_intake": False, "root_joint_verification": False})
        raise
