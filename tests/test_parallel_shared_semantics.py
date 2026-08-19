import threading
from pathlib import Path

import pytest

from zscope.config.config import (
    AgentConfig,
    AnalysisConfig,
    ConcurrencyConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis import analyzer as analyzer_module
from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.candidates import CandidateTicket
from zscope.rules.catalog import RuleCatalogError
from zscope.semantics.models import LocalPatternSemantics


class FakeCodeIndex:
    backend = None
    backend_name = "regex"

    def get_file_snippet(self, _path: str, _start: int, _end: int) -> str:
        return "copy(dst, src, count);"

    def get_function_impl(self, _name: str, **_kwargs):
        return {"code": "void sink(void) { copy(dst, src, count); }"}

    def get_callers(self, _name: str, limit: int = 8):
        del limit
        return []

    def get_callees(self, _name: str, limit: int = 12):
        del limit
        return []


def _config(tmp_path: Path) -> ZScopeConfig:
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(),
        analysis=AnalysisConfig(
            snapshot_dir=str(tmp_path / "snapshots"),
            user_config_db=str(tmp_path / "user-config"),
        ),
        project=ProjectConfig(
            project_root=tmp_path,
            source_root=tmp_path,
            agents=[AgentConfig(name="proof_engine", task="validate")],
        ),
        concurrency=ConcurrencyConfig(entry_workers=3),
    )


def test_analyzer_initializes_java_project_file_rule_cache(tmp_path: Path) -> None:
    analyzer = analyzer_module.Analyzer(_config(tmp_path), code_index=FakeCodeIndex())

    assert analyzer._java_project_file_rule_cache is None
    assert analyzer._java_project_file_rule_emitted is False
    with analyzer._java_project_file_rule_cache_lock:
        assert analyzer._java_project_file_rule_cache is None


def test_scan_validation_queue_validates_one_shared_ledger_group(tmp_path) -> None:
    """Wrapper occurrences are merged before any validator work is scheduled."""

    config = _config(tmp_path)
    config.project.agents = []
    parallel = ParallelAnalyzer(config, code_index=FakeCodeIndex())
    ticket = CandidateTicket(
        id="RULE_1",
        skill="bounds",
        task="validate one structured bounds obligation",
        trigger="copy",
        line=12,
        context_slice="copy(dst, src, count);",
        priority_score=90,
        origin="src/demo.c:10",
        sink="src/demo.c:12",
        resource_kind="buffer",
        evidence={
            "candidate_uid": "CAND_SHARED",
            "evidence_hash": "evidence",
            "decision_evidence_hash": "decision",
            "validation_cluster_uid": "VAL_SHARED",
            "context_signature": "context",
            "candidate_payload": {
                "id": "RULE_1",
                "category": "bounds",
                "defect_class": "bounds",
                "function": "sink",
                "source": "count",
                "sink": "copy(dst, src, count)",
                "location": "src/demo.c:12",
            },
        },
    )
    parallel._candidate_ledger.add(
        ticket,
        source="clang_ast_cfg",
        call_path=["entry_a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_a",
    )
    parallel._candidate_ledger.add(
        ticket,
        source="graph_rule",
        call_path=["entry_b", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_b",
    )

    parallel._run_scan_validation_queue()

    with pytest.raises(RuntimeError, match="candidate ledger is frozen"):
        parallel._candidate_ledger.add(
            ticket,
            source="late_producer",
            record_role="validation_obligation",
        )

    assert parallel._global_validation_state["validation_group_count"] == 1
    assert parallel._global_validation_state["scan_level_raw_occurrence_count"] == 2
    snapshot = parallel._candidate_ledger.lifecycle_snapshot()
    assert snapshot["summary"]["validation_group_count"] == 1
    assert snapshot["summary"]["raw_occurrence_count"] == 2
    assert snapshot["outcomes"][0]["candidate_disposition"] == "needs_review"
    # This fixture deliberately has no Validator agent, so the runner closes
    # the one queued obligation as review without issuing an LLM attempt.
    # ``test_validation_runner_selects_one_representative_per_validation_cluster``
    # covers the corresponding one-validator-call coalescing behavior.
    assert snapshot["outcomes"][0]["validation_attempt_count"] == 0


def test_project_deterministic_fact_pass_collects_reachable_function_once(tmp_path) -> None:
    class ReachableCodeIndex:
        def get_function_impl(self, name, **_kwargs):
            code = {
                "entry_a": """
int entry_a(void) {
    return worker();
}
""",
                "entry_b": """
int entry_b(void) {
    return worker();
}
""",
                "worker": """
int worker(void) {
    Job job;
    pthread_create(&tid, NULL, thread_main, &job);
    pthread_detach(tid);
    return 0;
}
""",
            }.get(name)
            if code is None:
                return None
            return {
                "name": name,
                "index_name": f"{name}@src/demo.c",
                "file": "src/demo.c",
                "code": code,
            }

        def get_callees(self, name, limit=0):
            del limit
            return [{"name": "worker", "file": "src/demo.c"}] if name.startswith("entry_") else []

    config = _config(tmp_path)
    # This pass deliberately exercises the Clang CFG detector.  Rule
    # governance now excludes that engine when the weak ``regex`` backend is
    # selected, so make the required structure capability explicit here.
    config.indexing.backend = "unified"
    config.analysis.project_deterministic_fact_pass_v1 = True
    config.analysis.decision_fact_graph_v1 = True
    config.analysis.decision_context_v32 = True
    parallel = ParallelAnalyzer(config, code_index=ReachableCodeIndex())
    parallel._shared_local_pattern_semantics = LocalPatternSemantics()
    parallel._shared_semantic_overlay = {}

    parallel._run_project_deterministic_fact_pass(
        [FunctionEntry("entry_a"), FunctionEntry("entry_b")]
    )

    state = parallel._project_fact_pass_state
    assert state["status"] == "complete"
    assert state["reachable_functions"] == 3
    assert state["rule_candidate_counts"] == {
        "by_engine": {"cpp_clang_cfg": 2},
        "by_rule": {"clang_cfg_stack_address_passed_to_thread": 2},
        "total": 2,
    }
    records = parallel._candidate_ledger.records()
    stack_records = [record for record in records if record.defect_class == "stack_escape"]
    assert len(stack_records) == 1
    assert len(stack_records[0].occurrence_uids) == 2
    assert stack_records[0].ticket.skill == "stack_escape"
    candidate_payload = stack_records[0].ticket.evidence["candidate_payload"]
    assert candidate_payload["candidate_kind"] == "deterministic_rule"
    assert candidate_payload["rule_engine"] == "cpp_clang_cfg"
    assert candidate_payload["rule_revision"] == 1
    assert candidate_payload["rule_catalog_sha256"]


def test_project_deterministic_fact_pass_rejects_unregistered_rule_before_ledger(
    tmp_path, monkeypatch
) -> None:
    class SingleFunctionCodeIndex:
        def get_function_impl(self, name, **_kwargs):
            return {
                "name": name,
                "index_name": f"{name}@src/demo.c",
                "file": "src/demo.c",
                "code": "int entry(void) { return 0; }",
            }

        def get_callees(self, _name, limit=0):
            del limit
            return []

    class UnknownRuleGenerator:
        def __init__(self, *_args, **_kwargs):
            pass

        def generate_issues(self, *_args, **_kwargs):
            return [{"rule_id": "not_registered", "defect_class": "stack_escape"}]

    config = _config(tmp_path)
    config.indexing.backend = "unified"
    parallel = ParallelAnalyzer(config, code_index=SingleFunctionCodeIndex())
    parallel._shared_local_pattern_semantics = LocalPatternSemantics()
    parallel._shared_semantic_overlay = {}
    monkeypatch.setattr(
        parallel_module,
        "ClangAstCfgCandidateGenerator",
        UnknownRuleGenerator,
    )

    with pytest.raises(RuleCatalogError, match="unknown c_cpp rule id"):
        parallel._run_project_deterministic_fact_pass([FunctionEntry("entry")])

    assert parallel._candidate_ledger.records() == []
