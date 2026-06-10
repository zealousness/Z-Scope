from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import zscope.orchestration.specs as specs_module
from zscope.orchestration.specs import SpecRegistry


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
        "---\nname: demo_skill\n---\nskill body\n",
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
