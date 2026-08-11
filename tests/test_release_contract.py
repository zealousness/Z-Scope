from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from zscope._version import __version__
from scripts.evaluate_release_candidate import evaluate_candidate
from scripts.generate_release_manifest import build_manifest
from scripts.verify_release_assets import verify_release_assets

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
    assert "test/range/benchmark test/java_range/benchmark" in workflow
    assert "zscope scripts test tests tools" not in workflow
    assert "scan_git_history_secrets.py --ref HEAD" in workflow


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
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    benchmark = (ROOT / ".github/workflows/formal-benchmark.yml").read_text(encoding="utf-8")
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
    workflows = "\n".join((ai, release, ci, benchmark))
    for action in (
        "actions/checkout@v7",
        "actions/setup-python@v7",
        "actions/setup-java@v5",
        "actions/github-script@v9",
        "actions/upload-artifact@v7",
        "actions/dependency-review-action@v5",
        "gitleaks/gitleaks-action@v3",
    ):
        assert action in workflows
    for deprecated in (
        "actions/checkout@v4",
        "actions/setup-python@v5",
        "actions/setup-java@v4",
        "actions/github-script@v7",
        "actions/upload-artifact@v4",
        "actions/dependency-review-action@v4",
        "gitleaks/gitleaks-action@v2",
    ):
        assert deprecated not in workflows


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


def test_release_manifest_and_hash_verification_are_consistent(tmp_path: Path) -> None:
    asset = tmp_path / f"zscope-app-{__version__}-linux-x86_64.tar.zst"
    cpp = tmp_path / "zscope-deps-cpp-test-linux-x86_64.tar.zst"
    java = tmp_path / "zscope-deps-java-test-linux-x86_64.tar.zst"
    licenses = tmp_path / f"third-party-licenses-{__version__}.tar.zst"
    installer = tmp_path / "install.sh"
    lock = tmp_path / "release-py313.txt"
    for path in (asset, cpp, java, licenses, installer, lock):
        path.write_text(path.name, encoding="utf-8")
    for name in (
        f"zscope-{__version__}.spdx.json",
        "zscope-deps-cpp-test.spdx.json",
        "zscope-deps-java-test.spdx.json",
    ):
        (tmp_path / name).write_text(
            json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": name}]}),
            encoding="utf-8",
        )
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text(
        json.dumps(build_manifest(tmp_path, __version__), indent=2) + "\n", encoding="utf-8"
    )
    names = [item["name"] for item in json.loads(manifest_path.read_text())["artifacts"]]
    names.append("release-manifest.json")
    sums = []
    import hashlib

    for name in names:
        digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        sums.append(f"{digest}  {name}")
    (tmp_path / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    (tmp_path / "SHA256SUMS.sig").write_bytes(b"test")
    (tmp_path / "public-key.pem").write_text("test", encoding="utf-8")

    result = verify_release_assets(
        tmp_path,
        verify_signature=False,
        inspect_archives=False,
    )

    assert result["passed"] is True
    assert result["package_version"] == __version__


def test_java_structural_baseline_does_not_claim_llm_accuracy() -> None:
    baseline = (ROOT / "test/java_range/benchmark/structural_baseline.json").read_text(
        encoding="utf-8"
    )
    assert '"truth_records": 58' in baseline
    assert '"rule_backed_truth_ids": 49' in baseline
    assert '"entry_functions": 54' in baseline
    assert '"java_rules": 48' in baseline
    assert '"llm_metrics_available": false' in baseline


def test_formal_archives_are_bound_to_exact_benchmark_commits() -> None:
    provenance_path = ROOT / "docs/releases/benchmark-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert provenance["package_version"] == __version__
    assert provenance["exact_release_sha_required"] is True
    for item in provenance["benchmarks"]:
        archive = json.loads((ROOT / item["archive"]).read_text(encoding="utf-8"))
        assert archive["benchmark_git_sha"] == item["git_sha"]
        assert len(archive["runs"]) == 5
        assert all(run["completeness"]["source_truth_isolated"] for run in archive["runs"])

    audit = evaluate_candidate(
        provenance_path,
        release_sha="f" * 40,
        version=__version__,
    )
    assert audit["status"] == "blocked"
    assert "cpp:benchmark_sha_not_release_sha" in audit["hard_blockers"]
    assert "cpp:sealed_set_not_verified" in audit["rc_blockers"]
