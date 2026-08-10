from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from zscope._version import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_package_version_is_semver_and_shared_by_user_surfaces() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", __version__)
    assert f"# Z-SCOPE v{__version__}" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"v{__version__}" in (ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    assert f"v{__version__}" in (ROOT / "zscope/web/static/index.html").read_text(encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/verify_release_version.py"),
            "--tag",
            f"v{__version__}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == __version__


def test_python_39_314_constraints_and_ci_are_declared() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.9"' in pyproject
    assert "target-version = ['py39']" in pyproject
    assert 'python_version = "3.9"' in pyproject
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for suffix, version in (
        ("39", "3.9"),
        ("310", "3.10"),
        ("311", "3.11"),
        ("312", "3.12"),
        ("313", "3.13"),
        ("314", "3.14"),
    ):
        constraint = ROOT / "requirements" / "constraints" / f"py{suffix}.txt"
        assert constraint.stat().st_size > 1000
        assert f'python: "{version}"' in workflow
        assert f'lock: "py{suffix}"' in workflow
    assert "scripts/check_mypy_baseline.py" in workflow
    assert "scripts/check_black_baseline.py" in workflow


def test_release_lock_contains_runtime_and_java_extra_but_not_dev_tools() -> None:
    lock = (ROOT / "requirements/release/py313.txt").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "cpgqls-client==" in lock
    assert "openai==" in lock
    assert "black==" not in lock
    assert "mypy==" not in lock
    assert "pytest==" not in lock
    assert "requirements/release/py313.txt" in workflow


def test_joern_client_is_java_optional_not_base_dependency() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dependencies, optional = pyproject.split("[project.optional-dependencies]", 1)
    assert "cpgqls-client" not in dependencies
    assert "cpgqls-client" in optional.split("[project.scripts]", 1)[0]


def test_release_and_ai_workflows_enforce_security_boundaries() -> None:
    ai = (ROOT / ".github/workflows/ai-review.yml").read_text(encoding="utf-8")
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "pull_request_target" not in ai
    assert "head.repo.full_name == github.repository" in ai
    assert "continue-on-error: true" in ai
    assert "environment: release" in release
    assert "--verify-tag" in release
    assert "Missing SHA256SUMS.sig" in installer
    assert "Refusing system-wide prefix" in installer
    assert 'install_requirement="zscope[java]"' in installer
    assert "command -v zstd" in installer
    assert ">>/etc/profile" not in installer.replace(" ", "")


def test_spdx_generation_is_reproducible_and_uses_unique_package_name(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("payload\n", encoding="utf-8")
    outputs = [tmp_path / "first.json", tmp_path / "second.json"]
    for output in outputs:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/generate_spdx_sbom.py"),
                "--root",
                str(source),
                "--version",
                "1.3.1",
                "--name",
                "zscope-deps-cpp-test",
                "--output",
                str(output),
            ],
            check=True,
            env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
        )
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    document = json.loads(outputs[0].read_text(encoding="utf-8"))
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["packages"][0]["name"] == "zscope-deps-cpp-test"
    assert document["packages"][0]["packageVerificationCode"]["packageVerificationCodeValue"]


def test_java_structural_baseline_does_not_claim_llm_accuracy() -> None:
    baseline = (ROOT / "test/java_range/benchmark/structural_baseline.json").read_text(
        encoding="utf-8"
    )
    assert '"truth_records": 58' in baseline
    assert '"rule_backed_truth_ids": 49' in baseline
    assert '"entry_functions": 54' in baseline
    assert '"java_rules": 48' in baseline
    assert '"llm_metrics_available": false' in baseline
