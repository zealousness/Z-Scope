"""Build variants must never share decisions, aliases, or human rejections."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from zscope.common.issue_identity import (
    canonical_issue_key,
    deduplicate_issues,
    deduplicate_semantic_issues_programmatic,
    issues_have_destructive_equivalence,
    issues_may_share_root_cause,
    semantic_related_cluster_keys,
    source_sink_location_issue_key,
    stable_issue_fingerprint,
)
from zscope.config.user_config_store import UserConfigStore
from zscope.core.candidates.decision_facts import (
    DecisionFactGraph,
    DecisionFactGraphCache,
    attach_decision_facts,
)
from zscope.orchestration.candidate_envelope import annotate_issue_identity
from zscope.orchestration.candidates import CandidateLedger
from zscope.reporting.finding_roots import project_finding_roots
from zscope.reporting.issue_aggregation import project_issue_aggregation
from test_decision_facts import _signed_length_issue
from test_finding_roots import _outcome
from test_candidate_ledger import _ticket
from test_validation_runner import _runner
from test_build_context import native_variants


def issue(scope="a"):
    return {
        **_signed_length_issue(),
        "build_context_id": scope,
        "location": "src/parser.c:12",
        "file_path": "src/parser.c",
        "defect_class": "signed_unsigned",
        "resource": "count",
        "obligation_required_fact_kinds": [
            "source",
            "sink",
            "event:signed_io_result",
            "event:unsigned_length_sink",
        ],
        "source": "recv",
        "sink": "memcpy",
        "rule": "signed_length",
        "source_loc": {"file": "src/parser.c", "line": 10},
        "sink_loc": {"file": "src/parser.c", "line": 12},
        "code_snippet": "int count = recv(fd, buf, 4, 0); memcpy(dst, buf, count);",
    }


@pytest.mark.parametrize("other", ["b", ""])
def test_variant_identity_is_separate_at_all_decision_boundaries(other):
    left, right = issue(), issue(other)
    for key in (canonical_issue_key, source_sink_location_issue_key, stable_issue_fingerprint):
        assert key(left) and key(left) != key(right)
    assert not set(semantic_related_cluster_keys(left)) & set(semantic_related_cluster_keys(right))
    assert not issues_have_destructive_equivalence(left, right)
    assert not issues_may_share_root_cause(left, right, allow_cross_function_root=True)
    assert len(deduplicate_issues([deepcopy(left), deepcopy(right)])) == 2
    semantic, _ = deduplicate_semantic_issues_programmatic([deepcopy(left), deepcopy(right)])
    assert len(semantic) == 2
    envelopes = [
        annotate_issue_identity(item, project_id="demo", revision="rev-1") for item in (left, right)
    ]
    for name in (
        "candidate_uid",
        "history_key",
        "obligation_uid",
        "validation_cluster_uid",
        "decision_evidence_hash",
    ):
        assert getattr(envelopes[0], name) != getattr(envelopes[1], name)
    assert envelopes[0].build_context_id == "a"


def test_reannotation_cannot_retain_another_builds_cached_identity():
    value = issue()
    first = annotate_issue_identity(value)
    assert annotate_issue_identity(value) == first
    value["build_context_id"] = "b"
    second = annotate_issue_identity(value)
    assert second.candidate_uid != first.candidate_uid
    assert second.obligation_uid != first.obligation_uid
    assert value["identity_build_context_id"] == "b"


def test_combined_fact_graph_and_cache_do_not_fill_missing_facts_from_other_builds():
    left, right = issue(), issue("b")
    right["evidence_pack"]["ast_cfg"]["events"] = []
    cache = DecisionFactGraphCache()
    first = cache.get_or_build(left)
    same_source_other_build = cache.get_or_build(issue("b"))
    assert first is not same_source_other_build
    assert first.cache_key != same_source_other_build.cache_key
    assert not {f.fact_uid for f in first.facts} & {
        f.fact_uid for f in same_source_other_build.facts
    }
    combined = DecisionFactGraph.from_issues([left, right])
    a = attach_decision_facts(left, graph=combined)
    b = attach_decision_facts(right, graph=combined)
    assert a.decision_fact_slice.coverage == "complete"
    assert b.decision_fact_slice.coverage == "partial"
    assert b.decision_fact_slice.missing_fact_kinds
    assert not set(a.decision_fact_slice.fact_uids) & set(b.decision_fact_slice.fact_uids)
    unknown = attach_decision_facts(issue(""), graph=combined)
    assert not unknown.decision_fact_slice.fact_uids
    assert unknown.decision_fact_slice.coverage == "partial"


@pytest.mark.parametrize("cluster", [False, True])
def test_validator_cache_does_not_share_even_stale_cluster_ids(cluster):
    runner = _runner(None)
    items = [issue(scope) for scope in ("a", "b", "")]
    if cluster:
        for value in items:
            value["validation_cluster_uid"] = "stale-shared-cluster"
    keys = [
        runner._validator_cache_key(SimpleNamespace(raw_issue=value, issue_func="parse_packet"))
        for value in items
    ]
    assert all(keys) and len(set(keys)) == 3


def test_raw_tickets_keep_separate_ledger_records_and_same_build_coalesces():
    ledger = CandidateLedger()
    records = []
    for scope in ("a", "b", "", "a"):
        ticket = _ticket()
        ticket.evidence["build_context_id"] = scope
        record, _ = ledger.add(ticket, source="local_rule:entry")
        records.append(record)
    assert len({r.candidate_uid for r in records}) == 3
    assert records[0] is records[3]


@pytest.mark.parametrize("disposition", ["confirmed", "needs_review"])
def test_roots_and_same_site_projection_do_not_hide_other_variants(disposition):
    rows = []
    for n, scope in enumerate(("a", "b", "", "a")):
        value = _outcome(str(n), disposition=disposition)
        value.update(
            build_context_id=scope,
            sink_identity={"file": "src/owner.c", "line": 42, "operation": "free"},
        )
        rows.append(value)
    roots = project_finding_roots(rows)
    assert roots.finding_root_count == 3
    assert roots.finding_root_alias_count == 1
    projection = project_issue_aggregation(rows)
    assert projection.aggregation_count == 3
    assert projection.aggregation_alias_count == 1


def test_human_rejection_exact_and_fallback_matches_remain_build_scoped(tmp_path):
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    value = issue()
    store.upsert_finding_baseline("legacy-shared-key", "false_positive", value)
    assert store.get_finding_baseline_for_issue(value, "legacy-shared-key")
    assert store.get_finding_baseline_for_issue(value, "changed-line-key")
    for scope in ("b", ""):
        assert store.get_finding_baseline_for_issue(issue(scope), "legacy-shared-key") is None
        assert store.get_finding_baseline_for_issue(issue(scope), "changed-line-key") is None


def test_web_rejection_does_not_create_an_unscoped_suppression(tmp_path):
    from zscope.web.services import ReportFeedbackService
    from zscope.core.validation.pipeline import ValidationPipeline

    store = UserConfigStore(tmp_path / "user_config.xlsx")
    value = issue()
    value.update(validation_status="rejected", dedup_key=canonical_issue_key(value))
    result = ReportFeedbackService(store).persist_validation_feedback([value])
    assert result["baseline_upserts"] == 1
    assert result["suppression_upserts"] == 0
    # A preexisting positional rejection must not bypass the scoped baseline.
    store.add_false_positive_suppression(
        value["function"], value["location"], value["defect_class"]
    )
    pipeline = ValidationPipeline(store)
    assert pipeline.apply_pre_validation_feedback(issue("b"), value["function"]) is None
    assert (
        pipeline.apply_pre_validation_feedback(issue(), value["function"]).finding_kind
        == "suppressed_baseline"
    )


@pytest.mark.parametrize("engine", ["regex", "clang"])
def test_generators_only_bind_complete_unambiguous_current_facts(engine):
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator

    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    generator = cls()
    code = "void f(void) {\n char *p = malloc(4);\n free(p);\n free(p);\n}\n"
    for facts, expected in [
        ({"complete": True, "build_context_id": "a"}, "a"),
        ({"complete": True, "build_context_id": "b"}, "b"),
        ({"complete": False, "build_context_id": "a"}, ""),
        ({"complete": True, "build_context_id": "a", "reason": "stale_build_dependencies"}, ""),
        ({"reason": "ambiguous_build_context", "build_contexts": ["a", "b"]}, ""),
    ]:
        generator.program_facts_provider = lambda *_, result=facts: result
        candidates = generator.generate_issues("f", code, "unit.c")
        assert candidates
        for candidate in candidates:
            assert candidate.get("build_context_id", "") == expected
            assert candidate["evidence_pack"].get("build_context_id", "") == expected


@pytest.mark.parametrize("engine", ["regex", "clang"])
def test_real_native_variants_survive_generator_identity_and_ledger(native_variants, engine):
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.orchestration.candidates import CandidateRegistrar

    backend, root, cdb, _ = native_variants
    code = '#include "flags.h"\n#include <stdlib.h>\nvoid f(void) {\n char *p = malloc(4);\n free(p);\n free(p);\n}\n'
    (root / "unit.c").write_text(code, encoding="utf-8")
    assert backend.initialize(str(root), compile_commands_path=str(cdb))
    contexts = backend.get_build_contexts("unit.c")
    assert len(contexts) == 2
    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    ledger = CandidateLedger()
    registrar = CandidateRegistrar(ledger)
    uids = []
    for context in contexts:
        scope = context["build_context_id"]
        facts = backend.get_function_program_facts("f", "unit.c", build_context_id=scope)
        assert facts["complete"]
        generator = cls(program_facts_provider=lambda *_, result=facts: result)
        candidates = generator.generate_issues("f", code, "unit.c")
        assert candidates and all(item["build_context_id"] == scope for item in candidates)
        registrar.register_issues(candidates, source=engine)
        for candidate in candidates:
            ledger.mark_issue_terminal(candidate, disposition="needs_review", status="unvalidated")
        uids.append({item["validation_cluster_uid"] for item in candidates})
    assert not uids[0] & uids[1]
    snapshot = ledger.lifecycle_snapshot()
    expected = {c["build_context_id"] for c in contexts}
    assert {item["build_context_id"] for item in snapshot["records"]} == expected
    assert {item["issue"]["build_context_id"] for item in snapshot["outcomes"]} == expected
