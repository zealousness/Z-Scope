"""Second-round scan seam and isolated real-build acceptance assertions."""
import json
import os
import runpy
from pathlib import Path

import pytest

from zscope.core.validation import dynamic_reproduction as d
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.orchestration.candidate_envelope import annotate_issue_identity

ROOT = Path(__file__).resolve().parents[4]


def test_missing_optional_candidate_identity_does_not_abort_scan_without_provider():
    # Ordinary rule candidates need not have an executable-plan identity yet.
    issue = {"id": "RULE_1", "candidate_uid": "candidate-1",
             "location": "ordinary.c:5", "function": "subject",
             "defect_class": "heap_buffer_overflow"}
    # The normal identity annotation supports projects without a Git revision.
    annotate_issue_identity(issue, project_id="local-project", project_root=str(ROOT), revision="")
    assert issue["project_id"] == "local-project" and not issue["revision"]
    d.register_dynamic_reproduction_plan_provider(None)
    outcome = d.attempt_dynamic_reproduction(issue, policy=d.DynamicReproductionPolicy(enabled=True))
    assert outcome is None
    assert issue["dynamic_reproduction_attempt"]["status"] in {
        "no_plan_provider", "candidate_identity_unavailable",
    }


@pytest.mark.skipif(os.environ.get("ZSCOPE_REVIEW_ISOLATED") != "1",
                    reason="real fixture requires the independent offline review container")
def test_build_generated_binary_can_complete_qualified_confirmation(tmp_path):
    h = runpy.run_path(str(ROOT / "tests/test_dynamic_reproduction_execution.py"))
    compiler = h["_require_sanitizer"]("asan")
    binary = tmp_path / "built-positive"
    argv = h["_compile_argv"]("heap_overflow_positive.c", binary, "asan", compiler)
    issue = h["_issue"]("heap_overflow_positive.c", function="zscope_dynamic_repro_positive",
                         defect_class="heap_buffer_overflow")
    plan = h["_plan"](issue, kind="asan", compiler=compiler, binary=binary,
                       binary_digest="", run_argv=(str(binary), "64"), run_cwd=tmp_path,
                       build=d.BuildSpec(argv=argv, cwd=str(h["FIXTURE_DIR"])))
    record = h["_runner"]("asan", compiler).execute(plan)
    assert record.outcome == "witness_observed", record.stderr_excerpt
    assert record.binary_digest
    replay = d.replay_witness(plan, h["_runner"]("asan", compiler), times=2)
    outcome = d.register_dynamic_reproduction(issue, plan=plan, record=record,
                                               replay=replay, policy=h["_policy"]())
    raw = os.environ.get("ZSCOPE_REVIEW_BUILD_EVIDENCE")
    if raw:
        Path(raw).write_text(json.dumps({"record": record.to_dict(), "replay": replay.to_dict(),
            "qualification": {"qualified": outcome.qualification.qualified,
                              "facts": outcome.qualification.facts,
                              "reasons": outcome.qualification.reasons}}, indent=2) + "\n", encoding="utf-8")
    assert outcome.qualification.qualified, outcome.qualification.reasons
    assert deterministic_decision_proof(issue, outcome="confirm") is not None
