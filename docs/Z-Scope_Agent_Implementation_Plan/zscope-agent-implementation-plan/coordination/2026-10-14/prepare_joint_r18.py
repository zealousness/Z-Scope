"""Extend the entire R17 collection for the next accepted UI/doc batch."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
source = (HERE / "verify_current_root_r17.py").read_text(encoding="utf-8")
needle = 'TESTS = list(dict.fromkeys(TESTS))\nassert all((ROOT/name).is_file() for name in TESTS)'
assert source.count(needle) == 1
source = source.replace(needle, '''assert {"ASTRA-INSTANCE-UI-R18", "DOC-IDENTITY-R18"} <= integrated, "R18 batch not intaken"
TESTS += ["tests/test_instance_coverage_ui.py", "tests/test_lightweight_instance_metadata.py", "tests/test_user_config_workbook_readme.py"]
TESTS = list(dict.fromkeys(TESTS))
assert all((ROOT/name).is_file() for name in TESTS)''')
needle = 'if WITH_MCP:\n    SOURCES += ["zscope/mcp/provider.py", "zscope/mcp/jobs_adapter.py"]'
assert source.count(needle) == 1
source = source.replace(needle, needle + '\nSOURCES += ["tests/fixtures/instance_coverage_ui.cjs"]')
needle = 'env["ZSCOPE_UI_JOB_EVIDENCE"] = str(OUT / "owner")'
assert source.count(needle) == 1
source = source.replace(needle, needle + '\nenv["ZSCOPE_INSTANCE_EVIDENCE"] = str(OUT / "native-browser")')
needle = '        command += ["tests/test_function_info_tool.py"]'
assert source.count(needle) == 1
source = source.replace(needle, needle + '\n        command += ["zscope/web/services.py", "tests/test_instance_coverage_ui.py", "tests/test_lightweight_instance_metadata.py"]')
needle = '    "astra_job_projection_r15_integrated": "ASTRA-JOB-PROJECTION-R15" in integrated,'
assert source.count(needle) == 1
source = source.replace(needle, needle + '\n    "astra_instance_native_ui_r18_integrated": "ASTRA-INSTANCE-UI-R18" in integrated,\n    "r18_native_ui_scope": "Actual native dual-macro fixture through ScanSession, detached owner, SQLite, bound HTTP and desktop/mobile browser; no synthetic report substitution for this new test; model boundary unexercised. Prior tests retain their controlled scanner/model boundaries.",')
source = source.replace('"artifacts/coordinator-runtime-r17-20261015.json"', '"artifacts/coordinator-runtime-r18-20261015.json"')
target = HERE / "verify_current_root_r18.py"
assert not target.exists()
target.write_text(source, encoding="utf-8", newline="\n")
plan = {"launcher_sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "inherits_entire_r17_collection": True, "additional_test_files": ["tests/test_instance_coverage_ui.py", "tests/test_lightweight_instance_metadata.py", "tests/test_user_config_workbook_readme.py"], "quality_commands": 6, "pytest_capture": "default fd/ext4", "root_product_changed": False, "requires": "R17 repaired current joint passed and accepted R18 batch intaken"}
(HERE / "joint-r18-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(plan))
