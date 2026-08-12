from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

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
from zscope.core.analysis.analyzer import Analyzer
from zscope.rules.catalog import EffectiveRuleSet, RuleDescriptor


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

    duplicate_key = tmp_path / "duplicate-key.yaml"
    duplicate_key.write_text(
        "rule_pack_version: 1\nrule_pack_version: 1\nname: duplicate\nrules: []\n",
        encoding="utf-8",
    )
    with pytest.raises(RulePackError, match="duplicate YAML key"):
        RuleRegistry().load_pack(duplicate_key)

    boolean_version = tmp_path / "boolean-version.yaml"
    boolean_version.write_text(
        "rule_pack_version: true\nname: invalid\nrules: []\n",
        encoding="utf-8",
    )
    with pytest.raises(RulePackError, match="rule_pack_version must be 1"):
        RuleRegistry().load_pack(boolean_version)


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
        descriptor = RuleDescriptor(
            id="acme.provider",
            language="java",
            engine="ignored_by_registry",
            defect_class="command_injection",
            cwe="CWE-78",
            skill="java_injection",
            default_severity="high",
            revision=3,
            status="stable",
            title="Command execution",
            summary="Test provider command execution rule.",
            required_capabilities=("source_text",),
        )

        def evaluate(self, context: RuleContext):
            return [
                Candidate(
                    rule_id=self.descriptor.id,
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
    assert candidates[0].descriptor.engine == "python_provider"
    assert candidates[0].descriptor.source == "provider:acme"
    issue = candidates[0].to_issue()
    assert issue["candidate_source"] == "external_rule_provider"
    assert issue["rule_revision"] == 3


def test_provider_v2_rejects_missing_descriptor_and_mismatched_candidate(
    monkeypatch, tmp_path: Path
) -> None:
    class MissingDescriptor:
        def evaluate(self, context: RuleContext):
            return []

    class MissingProvider:
        def rules(self):
            return [MissingDescriptor()]

    class EntryPoint:
        name = "bad"

        @staticmethod
        def load():
            return MissingProvider

    monkeypatch.setattr(
        RuleRegistry, "_provider_entry_points", staticmethod(lambda: {"bad": EntryPoint()})
    )
    with pytest.raises(RulePackError, match="requires RuleDescriptor"):
        RuleRegistry().load_providers(["bad"])

    class WrongIdRule:
        descriptor = RuleDescriptor(
            id="acme.expected",
            language="c_cpp",
            engine="python_provider",
            defect_class="bounds",
            cwe="CWE-125",
            skill="bounds_and_integer",
            default_severity="high",
            revision=1,
            status="stable",
            title="Expected",
            summary="Expected rule.",
            required_capabilities=("source_text",),
        )

        def evaluate(self, context: RuleContext):
            return [Candidate("acme.other", context.function, context.file_path, 1)]

    class WrongIdProvider:
        def rules(self):
            return [WrongIdRule()]

    class WrongIdEntryPoint:
        name = "wrong"

        @staticmethod
        def load():
            return WrongIdProvider

    monkeypatch.setattr(
        RuleRegistry,
        "_provider_entry_points",
        staticmethod(lambda: {"wrong": WrongIdEntryPoint()}),
    )
    registry = RuleRegistry()
    registry.load_providers(["wrong"])
    with pytest.raises(RulePackError, match="returned candidate for"):
        registry.evaluate(RuleContext("c_cpp", tmp_path, "copy", "copy.c", ""))


def test_effective_rules_prevent_unavailable_provider_execution_and_analyzer_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = 0

    class ClangOnlyRule:
        descriptor = RuleDescriptor(
            id="acme.clang_only",
            language="c_cpp",
            engine="ignored_by_registry",
            defect_class="buffer_overflow",
            cwe="CWE-120",
            skill="bounds_and_integer",
            default_severity="high",
            revision=1,
            status="stable",
            title="Clang-only extension",
            summary="Requires structural Clang facts.",
            required_capabilities=("source_text", "clang_structure"),
        )

        def evaluate(self, context: RuleContext):
            nonlocal calls
            calls += 1
            return [Candidate(self.descriptor.id, context.function, context.file_path, 1)]

    class Provider:
        def rules(self):
            return [ClangOnlyRule()]

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
    effective = EffectiveRuleSet.build(
        registry.effective_catalog,
        language="c_cpp",
        backend="regex",
        extension_registry=registry,
    )
    registry.bind_effective_rules(effective)

    context = RuleContext("c_cpp", tmp_path, "copy", "copy.c", "strcpy(dst, src);")
    assert effective.state_for("acme.clang_only").state == "unavailable"
    assert registry.evaluate(context) == []
    assert calls == 0

    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path),
        rules=SimpleNamespace(packs=[], providers=["acme"]),
    )
    analyzer.effective_rules = effective
    analyzer._project_language = lambda: "c_cpp"  # type: ignore[method-assign]
    analyzer._candidate_backend_profile = lambda: {}  # type: ignore[method-assign]
    assert (
        analyzer._detect_extension_rule_candidates(
            {
                "entry_func": "copy",
                "impl_result": {"function": "copy", "file": "copy.c", "code": "strcpy"},
            }
        )
        == []
    )
    assert calls == 0


def test_effective_rules_prevent_disabled_and_cross_language_extension_execution(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class Rule:
        def __init__(self, descriptor: RuleDescriptor) -> None:
            self.descriptor = descriptor

        def evaluate(self, context: RuleContext):
            calls.append(self.descriptor.id)
            return [Candidate(self.descriptor.id, context.function, context.file_path, 1)]

    cpp = RuleDescriptor(
        id="acme.disabled",
        language="c_cpp",
        engine="python_provider",
        defect_class="buffer_overflow",
        cwe="CWE-120",
        skill="bounds_and_integer",
        default_severity="high",
        revision=1,
        status="stable",
        title="Disabled",
        summary="Disabled extension rule.",
        required_capabilities=("source_text",),
        source="provider:unit",
    )
    java = RuleDescriptor(
        id="acme.java",
        language="java",
        engine="python_provider",
        defect_class="command_injection",
        cwe="CWE-78",
        skill="java_injection",
        default_severity="high",
        revision=1,
        status="stable",
        title="Java",
        summary="Java extension rule.",
        required_capabilities=("source_text",),
        source="provider:unit",
    )
    registry = RuleRegistry(disabled_ids=[cpp.id])
    registry.add(Rule(cpp), source=cpp.source, descriptor=cpp)
    registry.add(Rule(java), source=java.source, descriptor=java)
    effective = EffectiveRuleSet.build(
        registry.effective_catalog,
        language="c_cpp",
        backend="unified",
        disabled_ids=[cpp.id],
        extension_registry=registry,
    )
    registry.bind_effective_rules(effective)

    assert registry.evaluate(RuleContext("c_cpp", tmp_path, "copy", "copy.c", "")) == []
    assert calls == []
    with pytest.raises(RulePackError, match="does not match effective rule language"):
        registry.evaluate(RuleContext("java", tmp_path, "Demo.run", "Demo.java", ""))


def test_provider_provenance_uses_distribution_and_hashes_rule_implementation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Rule:
        descriptor = RuleDescriptor(
            id="acme.provenance",
            language="c_cpp",
            engine="ignored",
            defect_class="buffer_overflow",
            cwe="CWE-120",
            skill="bounds_and_integer",
            default_severity="high",
            revision=1,
            status="stable",
            title="Provider provenance",
            summary="Provider provenance fixture.",
            required_capabilities=("source_text",),
        )

        def evaluate(self, context: RuleContext):
            return []

    class Provider:
        def rules(self):
            return [Rule()]

    class Distribution:
        name = "acme-security-rules"
        version = "1.2.3"

    class EntryPoint:
        name = "acme"
        dist = Distribution()

        @staticmethod
        def load():
            return Provider

    monkeypatch.setattr(
        RuleRegistry, "_provider_entry_points", staticmethod(lambda: {"acme": EntryPoint()})
    )
    registry = RuleRegistry()
    registry.load_providers(["acme"])

    descriptor = registry.effective_catalog.get("acme.provenance")
    assert descriptor is not None
    assert descriptor.source == "distribution:acme-security-rules@1.2.3"
    provenance = registry.extension_sources[0]
    assert provenance["source"] == descriptor.source
    assert provenance["distribution"] == "acme-security-rules"
    assert provenance["version"] == "1.2.3"
    assert provenance["sha256"] == provenance["implementation_sha256"]
    assert len(str(provenance["implementation_sha256"])) == 64
    labels = {item["label"] for item in provenance["implementation_components"]}
    assert {"provider", "provider_rules", "evaluate:acme.provenance"} <= labels
    provenance["implementation_components"][0]["sha256"] = "caller-mutated-copy"
    assert (
        registry.extension_sources[0]["implementation_components"][0]["sha256"]
        != "caller-mutated-copy"
    )


def test_provider_registry_rejects_duplicate_selection_and_installed_entrypoint_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EntryPoint:
        name = "acme"

    monkeypatch.setattr(
        "zscope.rules.extensions.importlib.metadata.entry_points",
        lambda: {"zscope.rule_providers": [EntryPoint(), EntryPoint()]},
    )
    with pytest.raises(RulePackError, match="duplicate installed rule provider entry point"):
        RuleRegistry._provider_entry_points()

    registry = RuleRegistry()
    with pytest.raises(RulePackError, match="duplicate provider names"):
        registry.load_providers(["acme", "acme"])


def test_bound_registry_is_sealed_and_exposes_detached_read_only_views(tmp_path: Path) -> None:
    registry = RuleRegistry()
    pack_path = _pack(tmp_path / "pack.yaml")
    registry.load_pack(pack_path, known_skills=["bounds_and_integer"])
    effective = EffectiveRuleSet.build(
        registry.effective_catalog,
        language="c_cpp",
        backend="regex",
        extension_sources=registry.extension_sources,
        extension_registry=registry,
    )
    registry.bind_effective_rules(effective)

    with pytest.raises(TypeError):
        registry.all_rules["new"] = registry.rules[0]  # type: ignore[index]
    with pytest.raises(TypeError):
        registry.extension_sources[0]["sha256"] = "changed"  # type: ignore[index]
    assert isinstance(registry.packs, tuple)

    with pytest.raises(RulePackError, match="sealed"):
        registry.bind_effective_rules(effective)
    with pytest.raises(RulePackError, match="sealed"):
        registry.load_pack(pack_path, known_skills=["bounds_and_integer"])
    with pytest.raises(RulePackError, match="sealed"):
        registry.load_providers([])


def test_provider_rule_evaluation_is_serialized_across_entry_workers(tmp_path: Path) -> None:
    active = 0
    maximum_active = 0
    guard = threading.Lock()

    class StatefulRule:
        descriptor = RuleDescriptor(
            id="acme.stateful",
            language="c_cpp",
            engine="python_provider",
            defect_class="buffer_overflow",
            cwe="CWE-120",
            skill="bounds_and_integer",
            default_severity="high",
            revision=1,
            status="stable",
            title="Stateful provider",
            summary="Provider fixture that is intentionally not thread-safe.",
            required_capabilities=("source_text",),
            source="provider:stateful",
        )

        def evaluate(self, context: RuleContext):
            nonlocal active, maximum_active
            with guard:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with guard:
                active -= 1
            return [Candidate(self.descriptor.id, context.function, context.file_path, 1)]

    registry = RuleRegistry()
    rule = StatefulRule()
    registry.add(rule, source=rule.descriptor.source, descriptor=rule.descriptor)
    effective = EffectiveRuleSet.build(
        registry.effective_catalog,
        language="c_cpp",
        backend="regex",
        extension_registry=registry,
    )
    registry.bind_effective_rules(effective)

    def run(position: int):
        return registry.evaluate(
            RuleContext("c_cpp", tmp_path, f"copy_{position}", "copy.c", "strcpy")
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(run, range(8)))

    assert maximum_active == 1
    assert [items[0].function for items in results] == [f"copy_{i}" for i in range(8)]


def test_rules_cli_validate_and_test(tmp_path: Path) -> None:
    path = _pack(tmp_path / "pack.yaml")
    runner = CliRunner()
    assert runner.invoke(main, ["validate", str(path)]).exit_code == 0
    result = runner.invoke(main, ["test", str(path)])
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output
