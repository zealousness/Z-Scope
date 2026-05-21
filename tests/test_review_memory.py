from pathlib import Path

from zscope.config.user_config_store import UserConfigStore
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.memory import ReviewMemory


class FakeStore:
    def __init__(self):
        self.baseline = None
        self.false_positive = False
        self.upserted = None
        self.last_issue = None
        self.last_dedup_key = None

    def is_false_positive(self, func_name, location, category):
        self.last_suppression = (func_name, location, category)
        return self.false_positive

    def get_finding_baseline_for_issue(self, issue, dedup_key=""):
        self.last_issue = issue
        self.last_dedup_key = dedup_key
        return self.baseline

    def get_finding_baseline(self, dedup_key):
        self.last_dedup_key = dedup_key
        return self.baseline

    def upsert_finding_baseline(self, dedup_key, status, issue=None):
        self.upserted = (dedup_key, status, issue)


def test_review_memory_delegates_suppression_and_baseline_write() -> None:
    store = FakeStore()
    memory = ReviewMemory(store)

    assert not memory.is_false_positive("entry", "src/demo.c:42", "double_free")
    assert store.last_suppression == ("entry", "src/demo.c:42", "double_free")

    issue = {"id": "ISSUE_1"}
    memory.upsert_finding_baseline("dedup-1", "false_positive", issue)
    assert store.upserted == ("dedup-1", "false_positive", issue)

    memory.record_validator_memory("dedup-2", "validated", issue)
    assert store.upserted == ("dedup-2", "validated", issue)

    memory.record_validator_memory("dedup-3", None, issue)
    assert store.upserted == ("dedup-2", "validated", issue)


def test_review_memory_uses_user_config_stable_baseline_lookup(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path)
    memory = ReviewMemory(store)
    original_issue = {
        "category": "double_free",
        "function": "entry",
        "location": "src/demo.c:42",
        "rule": "resource_automaton",
        "sink": "free",
        "resource": "ctx",
        "dedup_key": "double_free|entry|src/demo.c:42",
    }
    shifted_issue = {
        **original_issue,
        "location": "src/demo.c:99",
        "dedup_key": "double_free|entry|src/demo.c:99",
    }

    memory.upsert_finding_baseline(
        original_issue["dedup_key"],
        "false_positive",
        original_issue,
    )

    baseline = memory.get_finding_baseline_for_issue(shifted_issue, shifted_issue["dedup_key"])

    assert baseline is not None
    assert baseline["status"] == "false_positive"
    assert baseline["match_strategy"] == "stable_fingerprint"


def test_review_memory_allows_line_shift_when_source_context_matches(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path)
    memory = ReviewMemory(store)
    original_issue = {
        "category": "double_free",
        "function": "entry",
        "location": "src/demo.c:42",
        "rule": "resource_automaton",
        "sink": "free",
        "resource": "ctx",
        "code_snippet": "42 | free(ctx);",
        "dedup_key": "double_free|entry|src/demo.c:42",
    }
    shifted_issue = {
        **original_issue,
        "location": "src/demo.c:99",
        "code_snippet": "99 | free(ctx);",
        "dedup_key": "double_free|entry|src/demo.c:99",
    }

    memory.upsert_finding_baseline(
        original_issue["dedup_key"],
        "false_positive",
        original_issue,
    )

    baseline = memory.get_finding_baseline_for_issue(shifted_issue, shifted_issue["dedup_key"])

    assert baseline is not None
    assert baseline["match_strategy"] == "stable_fingerprint"


def test_review_memory_rejects_stable_baseline_when_source_context_conflicts(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path)
    memory = ReviewMemory(store)
    original_issue = {
        "category": "double_free",
        "function": "entry",
        "location": "src/demo.c:42",
        "rule": "resource_automaton",
        "sink": "free",
        "resource": "ctx",
        "code_snippet": "free(ctx);",
        "dedup_key": "double_free|entry|src/demo.c:42",
    }
    shifted_issue = {
        **original_issue,
        "location": "src/demo.c:99",
        "code_snippet": "free(other_ctx);",
        "dedup_key": "double_free|entry|src/demo.c:99",
    }

    memory.upsert_finding_baseline(
        original_issue["dedup_key"],
        "false_positive",
        original_issue,
    )

    baseline = memory.get_finding_baseline_for_issue(shifted_issue, shifted_issue["dedup_key"])

    assert baseline is None


def test_validation_pipeline_queries_baselines_through_review_memory() -> None:
    store = FakeStore()
    store.baseline = {"status": "false_positive", "match_strategy": "dedup_key"}
    pipeline = ValidationPipeline(store)
    issue = {
        "category": "double_free",
        "function": "entry",
        "location": "src/demo.c:42",
        "dedup_key": "double_free|entry|src/demo.c:42",
    }

    decision = pipeline.apply_pre_validation_feedback(issue, "entry")

    assert isinstance(pipeline.review_memory, ReviewMemory)
    assert decision is not None
    assert decision.rejection_source == "finding_baseline"
    assert store.last_issue is issue
    assert store.last_dedup_key == issue["dedup_key"]
