from __future__ import annotations

from types import SimpleNamespace
from typing import Iterable

import pytest

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.adapters import clang_tooling_matcher_candidates_from_evidence
from zscope.core.candidates.graph import (
    FunctionView,
    GraphCandidateGenerator,
    GraphLine,
)
from zscope.core.candidates.java_rules import JavaRuleCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog


class _RulePolicy:
    def __init__(
        self,
        disabled: Iterable[str] = (),
        skills: dict[str, str] | None = None,
    ) -> None:
        self.disabled = set(disabled)
        self.skills = dict(skills or {})

    def is_enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disabled

    def descriptor(self, rule_id: str) -> object:
        return SimpleNamespace(skill=self.skills.get(rule_id, "resource_lifecycle"))


def _rule_ids(issues: list[dict[str, object]]) -> list[str]:
    return [str(issue.get("rule_id") or issue.get("rule") or "") for issue in issues]


def test_regex_generator_skips_disabled_rule_at_emitter() -> None:
    code = """
1 | int demo(size_t payload_len) {
2 |     void *response = malloc(payload_len * 2);
3 |     return response != NULL;
4 | }
"""
    baseline = RegexCandidateGenerator().generate_issues("demo", code, "src/demo.c")
    filtered = RegexCandidateGenerator(
        rule_policy=_RulePolicy({"inline_allocation_size_overflow"})
    ).generate_issues("demo", code, "src/demo.c")

    assert "inline_allocation_size_overflow" in _rule_ids(baseline)
    assert "inline_allocation_size_overflow" not in _rule_ids(filtered)
    issue = next(item for item in baseline if item["rule_id"] == "inline_allocation_size_overflow")
    descriptor = RuleCatalog.builtin().require("inline_allocation_size_overflow")
    assert issue["cwe"] == descriptor.cwe
    assert issue["skill"] == descriptor.skill
    assert issue["evidence_pack"]["cwe"] == descriptor.cwe
    assert issue["evidence_pack"]["skill"] == descriptor.skill


def test_clang_generator_skips_only_disabled_rule_at_emitter() -> None:
    code = """
10 | int demo(void) {
11 |     char *p = malloc(16);
12 |     free(p);
13 |     free(p);
14 |     p[0] = 1;
15 |     return 0;
16 | }
"""
    issues = ClangAstCfgCandidateGenerator(
        rule_policy=_RulePolicy({"clang_cfg_use_after_release"})
    ).generate_issues("demo", code, "src/demo.c")
    rules = _rule_ids(issues)

    assert "clang_cfg_use_after_release" not in rules
    assert "clang_cfg_same_object_released_twice" in rules


def test_regex_allowed_skills_uses_catalog_descriptor_not_class_fallback() -> None:
    code = """
1 | int demo(size_t payload_len) {
2 |     void *response = malloc(payload_len * 2);
3 |     return response != NULL;
4 | }
"""
    rule = "inline_allocation_size_overflow"
    generator = RegexCandidateGenerator(
        rule_policy=_RulePolicy(skills={rule: "ownership_contract"})
    )

    included = generator.generate_issues(
        "demo", code, "src/demo.c", allowed_skills={"ownership_contract"}
    )
    excluded = generator.generate_issues(
        "demo", code, "src/demo.c", allowed_skills={"bounds_and_integer"}
    )

    assert rule in _rule_ids(included)
    assert rule not in _rule_ids(excluded)


def test_graph_generator_filters_disabled_rule_before_final_dedupe() -> None:
    caller = FunctionView(
        name="caller",
        file_path="src/demo.c",
        signature="void caller(void)",
        lines=(
            GraphLine(1, "pthread_mutex_lock(&g_lock);", "1 | pthread_mutex_lock(&g_lock);", 0),
            GraphLine(2, "helper();", "2 | helper();", 1),
            GraphLine(
                3,
                "pthread_mutex_unlock(&g_lock);",
                "3 | pthread_mutex_unlock(&g_lock);",
                2,
            ),
        ),
        callees=("helper",),
    )
    callee = FunctionView(
        name="helper",
        file_path="src/demo.c",
        signature="void helper(void)",
        lines=(
            GraphLine(
                10,
                "pthread_mutex_lock(&g_lock);",
                "10 | pthread_mutex_lock(&g_lock);",
                0,
            ),
            GraphLine(
                11,
                "pthread_mutex_unlock(&g_lock);",
                "11 | pthread_mutex_unlock(&g_lock);",
                1,
            ),
        ),
        callees=(),
    )

    baseline = GraphCandidateGenerator(object()).generate_for_views([caller, callee])
    filtered = GraphCandidateGenerator(
        object(), rule_policy=_RulePolicy({"cross_function_recursive_lock"})
    ).generate_for_views([caller, callee])
    effective = EffectiveRuleSet.build(
        RuleCatalog.builtin(),
        language="c_cpp",
        backend="unified",
        disabled_ids=["cross_function_recursive_lock"],
    )
    strictly_filtered = GraphCandidateGenerator(
        object(), rule_policy=effective.policy
    ).generate_for_views([caller, callee])

    assert "cross_function_recursive_lock" in _rule_ids(baseline)
    assert "cross_function_recursive_lock" not in _rule_ids(filtered)
    assert "cross_function_recursive_lock" not in _rule_ids(strictly_filtered)


def test_java_generator_skips_disabled_rule_before_matching() -> None:
    code = "1 | st.executeQuery(query);"
    baseline = JavaRuleCandidateGenerator().generate_issues("demo", code, "Demo.java")
    filtered = JavaRuleCandidateGenerator(
        rule_policy=_RulePolicy({"java_sql_statement_execute"})
    ).generate_issues("demo", code, "Demo.java")

    assert "java_sql_statement_execute" in _rule_ids(baseline)
    assert "java_sql_statement_execute" not in _rule_ids(filtered)


def test_clang_matcher_adapter_skips_disabled_rule_with_real_policy() -> None:
    rule_id = "clang_ast_same_argument_released_twice"
    effective = EffectiveRuleSet.build(
        RuleCatalog.builtin(),
        language="c_cpp",
        backend="unified",
        disabled_ids=[rule_id],
    )
    tooling = {
        "ast_dump": {
            "summary": {
                "target_function": {
                    "matcher_facts": [
                        {
                            "rule_id": rule_id,
                            "category": "double_free",
                            "line": 7,
                            "callee": "free",
                            "resource_symbol": "p",
                        }
                    ]
                }
            }
        }
    }

    assert (
        clang_tooling_matcher_candidates_from_evidence(
            "demo",
            "src/demo.c",
            tooling,
            rule_policy=effective.policy,
        )
        == []
    )


@pytest.mark.parametrize(
    ("generator", "issue", "expected"),
    [
        (
            RegexCandidateGenerator(),
            {"id": "r", "defect_class": "memory_leak", "skill": "ownership_contract"},
            "ownership_contract",
        ),
        (
            ClangAstCfgCandidateGenerator(),
            {"id": "c", "defect_class": "bounds", "skill": "bounds_and_integer"},
            "bounds_and_integer",
        ),
        (
            JavaRuleCandidateGenerator(),
            {"id": "j", "defect_class": "sql_injection", "skill": "java_web_security"},
            "java_web_security",
        ),
    ],
)
def test_ticket_prefers_catalog_injected_skill(
    generator: object,
    issue: dict[str, object],
    expected: str,
) -> None:
    ticket = generator.issue_to_ticket(issue)  # type: ignore[attr-defined]

    assert ticket.skill == expected


def test_generators_do_not_keep_category_level_cwe_or_skill_truth() -> None:
    assert not hasattr(RegexCandidateGenerator, "_CWE_BY_CLASS")
    assert not hasattr(RegexCandidateGenerator, "_SKILL_BY_CLASS")
    assert not hasattr(ClangAstCfgCandidateGenerator, "_CWE_BY_CLASS")
    assert not hasattr(ClangAstCfgCandidateGenerator, "_SKILL_BY_CLASS")
    assert not hasattr(GraphCandidateGenerator, "_CWE_BY_CLASS")
    assert not hasattr(JavaRuleCandidateGenerator, "_SKILL_BY_CLASS")
