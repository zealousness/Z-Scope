from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from zscope.cli.rules import main
from zscope.rules.extensions import (
    Candidate,
    RuleContext,
    RulePackError,
    RuleRegistry,
    run_pack_tests,
)


def _pack(path: Path, *, rule_id: str = "acme.unsafe_copy", extra: str = "") -> Path:
    path.write_text(
        f"""rule_pack_version: 1
name: acme
rules:
  - id: {rule_id}
    language: c_cpp
    cwe: CWE-120
    defect_class: buffer_overflow
    severity: high
    match:
      pattern: '\\bstrcpy\\s*\\('
    guards:
      - '\\bstrcpy_s\\s*\\('
    evidence:
      rationale: unbounded copy
    skill: bounds_and_integer
tests:
  - rule_id: {rule_id}
    expect: true
    file: demo.c
    code: 'strcpy(dst, src);'
    candidate:
      defect_class: buffer_overflow
      skill: bounds_and_integer
  - rule_id: {rule_id}
    expect: false
    file: demo.c
    code: 'memcpy(dst, src, size);'
{extra}""",
        encoding="utf-8",
    )
    return path


def test_yaml_rule_pack_runs_positive_negative_and_snapshot_tests(tmp_path: Path) -> None:
    registry = RuleRegistry()
    pack = registry.load_pack(_pack(tmp_path / "pack.yaml"), known_skills=["bounds_and_integer"])

    assert run_pack_tests(pack, registry) == []
    candidates = registry.evaluate(
        RuleContext(
            language="c_cpp",
            project_root=tmp_path,
            function="copy",
            file_path="demo.c",
            code="strcpy(dst, src);",
        )
    )
    assert len(candidates) == 1
    assert candidates[0].to_issue()["candidate_source"] == "external_rule_pack"


def test_rule_pack_rejects_duplicate_ids_and_unknown_fields(tmp_path: Path) -> None:
    first = _pack(tmp_path / "first.yaml")
    second = _pack(tmp_path / "second.yaml")
    registry = RuleRegistry()
    registry.load_pack(first, known_skills=["bounds_and_integer"])
    with pytest.raises(RulePackError, match="duplicate rule id"):
        registry.load_pack(second, known_skills=["bounds_and_integer"])

    invalid = _pack(tmp_path / "invalid.yaml")
    invalid.write_text(invalid.read_text(encoding="utf-8") + "unexpected: true\n", encoding="utf-8")
    with pytest.raises(RulePackError, match="unknown pack fields"):
        RuleRegistry().load_pack(invalid, known_skills=["bounds_and_integer"])

    builtin_collision = _pack(
        tmp_path / "builtin-collision.yaml", rule_id="java_sql_statement_execute"
    )
    with pytest.raises(RulePackError, match="cannot override built-in rules"):
        RuleRegistry().load_pack(builtin_collision, known_skills=["bounds_and_integer"])


def test_rule_pack_enforces_language_skill_and_disabled_ids(tmp_path: Path) -> None:
    path = _pack(tmp_path / "pack.yaml")
    with pytest.raises(RulePackError, match="unknown Skill"):
        RuleRegistry().load_pack(path, known_skills=["resource_lifecycle"])

    registry = RuleRegistry(disabled_ids=["acme.unsafe_copy"])
    registry.load_pack(path, known_skills=["bounds_and_integer"])
    context = RuleContext(
        language="java",
        project_root=tmp_path,
        function="copy",
        file_path="Demo.java",
        code="strcpy(dst, src);",
    )
    assert registry.evaluate(context) == []
    assert (
        registry.evaluate(
            RuleContext(
                language="c_cpp",
                project_root=tmp_path,
                function="copy",
                file_path="demo.c",
                code="strcpy(dst, src);",
            )
        )
        == []
    )


def test_entry_point_provider_must_return_standard_candidates(monkeypatch, tmp_path: Path) -> None:
    class Rule:
        id = "acme.provider"
        language = "java"

        def evaluate(self, context: RuleContext):
            return [
                Candidate(
                    rule_id=self.id,
                    language=self.language,
                    cwe="CWE-78",
                    defect_class="command_injection",
                    severity="high",
                    skill="java_injection",
                    function=context.function,
                    file_path=context.file_path,
                    line=1,
                )
            ]

    class Provider:
        def rules(self):
            return [Rule()]

    class EntryPoint:
        name = "acme"

        @staticmethod
        def load():
            return Provider

    monkeypatch.setattr(
        RuleRegistry, "_provider_entry_points", staticmethod(lambda: {"acme": EntryPoint()})
    )
    registry = RuleRegistry()
    registry.load_providers(["acme"])
    candidates = registry.evaluate(
        RuleContext("java", tmp_path, "Demo.run", "Demo.java", "Runtime.exec(value)")
    )
    assert [item.rule_id for item in candidates] == ["acme.provider"]


def test_rules_cli_validate_and_test(tmp_path: Path) -> None:
    path = _pack(tmp_path / "pack.yaml")
    runner = CliRunner()
    assert runner.invoke(main, ["validate", str(path)]).exit_code == 0
    result = runner.invoke(main, ["test", str(path)])
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output
