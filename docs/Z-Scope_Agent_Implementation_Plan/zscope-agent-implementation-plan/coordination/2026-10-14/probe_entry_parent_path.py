"""Reproduce an entry-file mapping error without native/model proof claims."""
from pathlib import Path
import hashlib
import json
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / "tests"))
from test_all_variant_scan import _make_context, _facts_row, _CannedFactsIndex
from zscope.retrieval.build_context import program_facts_result
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances

context = _make_context("bc-a", "unit.c")
facts = program_facts_result([_facts_row("c:@F@f", "f", "unit.c")], context=context)
index = _CannedFactsIndex([context], {("bc-a", "f", "../unit.c"): facts, ("bc-a", "f", ""): facts})
plan = plan_entry_instances(index, [FunctionEntry("f", file_path="../unit.c")])
output = {"synthetic_only": True, "requested_file": "../unit.c", "definition_file": "unit.c", "plan": plan.to_payload(), "source_sha256": hashlib.sha256((ROOT / "zscope/orchestration/entry_instances.py").read_bytes()).hexdigest()}
path = HERE / "review-repro/entry-parent-path"
path.mkdir(parents=True, exist_ok=True)
(path / "review.json").write_text(json.dumps(output, indent=2) + "\n")
print(json.dumps({"instances": len(plan.instances), "gap_reasons": [gap.reason for gap in plan.gaps]}))
