from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import zscope.orchestration.specs as specs_module
from zscope.agents.proof_engine.agent import ProofEngineAgent
from zscope.orchestration.agent_policy import attach_agent_contract
from zscope.orchestration.specs import AgentSpec, SkillSpec, SpecRegistry


def _write_spec_package(root: Path) -> None:
    agent_dir = root / "agents" / "demo_agent"
    skill_dir = root / "skills" / "demo_skill"
    workflow_dir = root / "workflows"
    agent_dir.mkdir(parents=True)
    skill_dir.mkdir(parents=True)
    workflow_dir.mkdir(parents=True)
    (agent_dir / "AGENT.md").write_text(
        "---\nname: demo_agent\nskills: [demo_skill]\n---\nagent body\n",
        encoding="utf-8",
    )
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo_skill\nlanguages: [c_cpp]\n---\nskill body\n",
        encoding="utf-8",
    )
    (workflow_dir / "default.yaml").write_text(
        "name: default\nmode: default\nsteps:\n  - id: validate_findings\n",
        encoding="utf-8",
    )


def test_spec_registry_reuses_cached_package_specs(monkeypatch, tmp_path: Path) -> None:
    package_root = tmp_path / "pkg"
    _write_spec_package(package_root)

    read_paths = []
    original_read_frontmatter = specs_module._read_frontmatter

    def counting_read_frontmatter(path: Path):
        read_paths.append(path)
        return original_read_frontmatter(path)

    monkeypatch.setattr(specs_module, "_read_frontmatter", counting_read_frontmatter)

    first = SpecRegistry(package_root=package_root)
    second = SpecRegistry(package_root=package_root)

    assert first.get_agent("demo_agent") is not None
    assert second.get_skill("demo_skill") is not None
    assert len(read_paths) == 2

    second.reload()

    assert len(read_paths) == 4


def test_spec_registry_loads_package_specs_once_under_concurrency(
    monkeypatch,
    tmp_path: Path,
) -> None:
    package_root = tmp_path / "pkg"
    _write_spec_package(package_root)

    read_paths = []
    original_read_frontmatter = specs_module._read_frontmatter

    def counting_read_frontmatter(path: Path):
        read_paths.append(path)
        return original_read_frontmatter(path)

    monkeypatch.setattr(specs_module, "_read_frontmatter", counting_read_frontmatter)

    with ThreadPoolExecutor(max_workers=12) as executor:
        registries = list(
            executor.map(lambda _index: SpecRegistry(package_root=package_root), range(24))
        )

    assert all(registry.get_agent("demo_agent") is not None for registry in registries)
    assert all(registry.get_skill("demo_skill") is not None for registry in registries)
    assert len(read_paths) == 2


def test_agent_prompt_block_preserves_full_contract_by_default() -> None:
    tail = "validator-contract-tail"
    spec = AgentSpec(name="large_agent", body=("x" * 5001) + tail)

    prompt = spec.to_prompt_block()

    assert prompt.endswith(spec.body)
    assert tail in prompt
    assert "[truncated]" not in prompt


def test_agent_prompt_block_keeps_explicit_truncation_compatibility() -> None:
    tail = "validator-contract-tail"
    spec = AgentSpec(name="large_agent", body=("x" * 5001) + tail)

    prompt = spec.to_prompt_block(max_chars=5000)

    assert prompt.endswith(("x" * 5000) + "\n\n[truncated]")
    assert tail not in prompt


def test_skill_prompt_block_preserves_full_contract_by_default() -> None:
    tail = "validator-skill-tail"
    spec = SkillSpec(name="large_skill", body=("x" * 6001) + tail)

    prompt = spec.to_prompt_block()

    assert prompt.endswith(spec.body)
    assert tail in prompt
    assert "[truncated]" not in prompt


def test_skill_prompt_block_keeps_explicit_truncation_compatibility() -> None:
    tail = "validator-skill-tail"
    spec = SkillSpec(name="large_skill", body=("x" * 6001) + tail)

    prompt = spec.to_prompt_block(max_chars=6000)

    assert prompt.endswith(("x" * 6000) + "\n\n[truncated]")
    assert tail not in prompt


def test_proof_engine_system_message_contains_the_complete_agent_contract() -> None:
    registry = SpecRegistry()
    spec = registry.get_agent("proof_engine")
    assert spec is not None
    assert len(spec.body) > 500

    context = {}
    attach_agent_contract(context, "proof_engine", registry)
    messages = ProofEngineAgent(object(), [])._messages(context, "validate this finding")
    system_prompt = str(messages[0]["content"])

    assert context["agent_contract"] == spec.to_prompt_block()
    assert system_prompt.endswith(spec.body)
    assert "[truncated]" not in system_prompt
    assert "Proof Checker" in system_prompt
    assert "Never invent a predicate" in system_prompt


def test_builtin_skills_declare_strict_language_scopes() -> None:
    registry = SpecRegistry()
    c_cpp = {
        "bounds_and_integer",
        "concurrency_lock_order",
        "null_and_failure",
        "ownership_contract",
        "resource_lifecycle",
        "shared_state_race",
        "stack_escape",
        "string_and_format",
        "temporal_memory",
    }
    java = {
        "java_authz",
        "java_concurrency",
        "java_crypto",
        "java_deserialization",
        "java_injection",
        "java_resource_lifecycle",
        "java_web_security",
    }
    shared = {
        "code_semantic_modeling",
        "evidence_validation",
        "snapshot_refresh_decision",
    }

    assert set(registry.skills) == c_cpp | java | shared
    assert {name for name, spec in registry.skills.items() if spec.languages == ["c_cpp"]} == c_cpp
    assert {name for name, spec in registry.skills.items() if spec.languages == ["java"]} == java
    assert {
        name for name, spec in registry.skills.items() if spec.languages == ["c_cpp", "java"]
    } == shared


@pytest.mark.parametrize(
    ("languages_line", "message"),
    [
        ("", "must be a non-empty YAML list"),
        ("languages: c_cpp\n", "must be a non-empty YAML list"),
        ("languages: []\n", "must be a non-empty YAML list"),
        ("languages: [python]\n", "unsupported skill language"),
        ("languages: [c_cpp, c_cpp]\n", "duplicate skill language"),
        ("languages: [c_cpp, 1]\n", "must be a non-empty string"),
    ],
)
def test_skill_spec_rejects_invalid_language_metadata(
    tmp_path: Path,
    languages_line: str,
    message: str,
) -> None:
    path = tmp_path / "skills" / "demo" / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text(
        f"---\nname: demo\n{languages_line}---\nskill body\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        SkillSpec.from_markdown(path)
