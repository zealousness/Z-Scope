from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from zscope._version import __version__
from scripts.evaluate_release_candidate import (
    CPP_FORMAL_LIMITS,
    _metric_gate_failures,
    evaluate_candidate,
)
from scripts.generate_release_manifest import build_manifest
from scripts.verify_release_assets import verify_release_assets

ROOT = Path(__file__).resolve().parents[1]


def _sqlite_sql_literals(path: Path) -> list[str]:
    """Return SQL-looking literals without importing the inspected module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    literals: list[str] = []
    for node in ast.walk(tree):
        value = ""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
        elif isinstance(node, ast.JoinedStr):
            value = "".join(
                (
                    part.value
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                    else "{}"
                )
                for part in node.values
            )
        normalized = value.lstrip().upper()
        if normalized.startswith(
            (
                "ALTER ",
                "CREATE ",
                "DELETE ",
                "DROP ",
                "INSERT ",
                "PRAGMA ",
                "REPLACE ",
                "SELECT ",
                "UPDATE ",
                "VACUUM ",
                "WITH ",
            )
        ):
            literals.append(value)
    return literals


def test_release_gate_requires_per_run_usage_and_attribution_invariants() -> None:
    failures = _metric_gate_failures(
        {
            "tokens": 1_000_000,
            "provider_usage_coverage": 0.99,
            "explicit_attribution_coverage": 1.0,
            "protocol_anomaly_count": 0,
            "telemetry_complete_rate": 1.0,
        },
        CPP_FORMAL_LIMITS,
        prefix="cpp:run_1",
    )
    assert failures == ["cpp:run_1_provider_usage_coverage_gate_failed"]

    legacy = _metric_gate_failures(
        {
            "confirmed_tp": 90,
            "precision": 98,
            "with_review_tp": 135,
            "with_review_raw_fp": 90,
            "needs_review": 100,
            "tokens": 1_000_000,
            "wall_seconds": 2_000,
        },
        CPP_FORMAL_LIMITS,
        prefix="cpp:legacy",
    )
    assert legacy == [
        "cpp:legacy_provider_usage_coverage_missing",
        "cpp:legacy_explicit_attribution_coverage_missing",
        "cpp:legacy_protocol_anomaly_count_missing",
        "cpp:legacy_telemetry_complete_rate_missing",
    ]


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
    assert "[tool.zscope.runtime-requirements]" in pyproject
    assert 'sqlite = ">=3.8.10.2"' in pyproject
    assert "target-version = ['py39']" in pyproject
    assert 'python_version = "3.9"' in pyproject
    assert '"orchestration/successor-runtime-review-evidence/*"' in pyproject
    assert '"orchestration/successor-runtime-review-evidence/**/*"' in pyproject
    assert '"orchestration/successor-runtime-review-integration-receipt.v1.json"' in pyproject
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
    assert "scripts/qualify_p6_proof_promotion.py --check" in workflow
    assert "scripts/check_p4_hypothesis_package.py dist/zscope-*.whl" in workflow
    assert "scripts/check_p5_runtime_authority_package.py" in workflow
    assert "scripts/project_successor_review_evidence.py check" in workflow
    assert "--expect-successor-status in_progress" not in workflow
    assert "current_successor_reviewed" in workflow
    assert "dist/zscope-*.whl" in workflow
    assert "tests/test_p6_proof_promotion_qualification.py" in workflow
    assert "tests/test_audit_eligibility.py" in workflow
    assert "test/range/benchmark test/java_range/benchmark" in workflow
    assert "zscope scripts test tests tools" not in workflow
    assert "scan_git_history_secrets.py --ref HEAD" in workflow
    assert "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in workflow
    assert "actions/dependency-review-action" not in workflow
    assert "dependency-policy:" in workflow
    assert "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266" in workflow
    assert "scripts/check_dependency_licenses.py" in workflow


def test_sqlite_queries_stay_compatible_with_declared_3_8_10_2_floor() -> None:
    sqlite_sources = []
    for source_root in (ROOT / "zscope", ROOT / "scripts"):
        for path in source_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"^\s*(?:import sqlite3|from sqlite3\b)", text, re.MULTILINE):
                sqlite_sources.append(path)

    forbidden = {
        "upsert": re.compile(r"\bON\s+CONFLICT\b|\bEXCLUDED\s*\.", re.IGNORECASE),
        "returning": re.compile(r"\bRETURNING\b", re.IGNORECASE),
        "window function": re.compile(
            r"\b(?:ROW_NUMBER|RANK|DENSE_RANK)\s*\(|\bOVER\s*\(", re.IGNORECASE
        ),
        "aggregate filter": re.compile(r"\bFILTER\s*\(", re.IGNORECASE),
        "ordered nulls": re.compile(r"\bNULLS\s+(?:FIRST|LAST)\b", re.IGNORECASE),
        "generated column": re.compile(r"\bGENERATED\s+ALWAYS\b", re.IGNORECASE),
        "strict table": re.compile(r"\)\s*STRICT\b", re.IGNORECASE),
        "new alter table": re.compile(
            r"\bALTER\s+TABLE\b[\s\S]*?\b(?:DROP|RENAME)\s+COLUMN\b", re.IGNORECASE
        ),
        "json function": re.compile(r"\bJSON_[A-Z_]+\s*\(", re.IGNORECASE),
        "new scalar function": re.compile(r"\b(?:FORMAT|IIF|UNIXEPOCH)\s*\(", re.IGNORECASE),
        "expression index": re.compile(
            r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b[\s\S]*?\bON\b\s+[^\s(]+\s*"
            r"\([^;)]*\b[A-Z_][A-Z0-9_]*\s*\(",
            re.IGNORECASE,
        ),
        "new join": re.compile(r"\b(?:RIGHT|FULL(?:\s+OUTER)?)\s+JOIN\b", re.IGNORECASE),
        "distinct comparison": re.compile(r"\bIS\s+(?:NOT\s+)?DISTINCT\s+FROM\b", re.IGNORECASE),
        "materialized cte": re.compile(r"\bMATERIALIZED\b", re.IGNORECASE),
        "vacuum into": re.compile(r"\bVACUUM\s+INTO\b", re.IGNORECASE),
        "pragma optimize": re.compile(r"\bPRAGMA\s+OPTIMIZE\b", re.IGNORECASE),
        "new pragma": re.compile(r"\bPRAGMA\s+TABLE_XINFO\b", re.IGNORECASE),
        "boolean literal": re.compile(r"\b(?:TRUE|FALSE)\b", re.IGNORECASE),
        "row value": re.compile(r"\([^()]+,\s*[^()]+\)\s+(?:IN|=|<|>)\s*\(", re.IGNORECASE),
    }
    violations = []
    for path in sqlite_sources:
        for sql in _sqlite_sql_literals(path):
            for feature, pattern in forbidden.items():
                if pattern.search(sql):
                    violations.append(f"{path.relative_to(ROOT)}: {feature}: {sql.strip()}")

    assert violations == []


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
    assert "benchmark_run_id:" in release
    assert "balanced_attestation_run_id:" in release
    assert "actions/download-artifact@v8" in release
    assert "--formal-artifact" in release
    assert "--balanced-default-attestation" in release
    assert "--balanced-attestation-workflow-run-id" in release
    assert ".github/workflows/formal-benchmark.yml" in release
    assert ".github/workflows/balanced-default-attestation.yml" in release
    assert "digest-mismatch: error" in release
    assert "org.opencontainers.image.revision" in benchmark
    assert "scanner image must be digest-pinned" in benchmark
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
        "actions/download-artifact@v8",
        "pypa/gh-action-pip-audit@1220774d901786e6f652ae159f7b6bc8fea6d266",
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
    assert "cpp:formal_artifact_required" in audit["hard_blockers"]
    assert "balanced_default_attestation_missing" in audit["rc_blockers"]


def test_release_rejects_unbound_balanced_attestation_workflow(tmp_path: Path) -> None:
    attestation = tmp_path / "attestation.json"
    attestation.write_text("{}\n", encoding="utf-8")

    audit = evaluate_candidate(
        ROOT / "docs/releases/benchmark-provenance.json",
        release_sha="f" * 40,
        version=__version__,
        balanced_attestation=attestation,
    )

    assert "balanced_default_attestation_workflow_run_id_missing" in audit["rc_blockers"]


def _write_formal_cpp_artifact(directory: Path, git_sha: str) -> None:
    runs = []
    for run_number in range(1, 6):
        run_dir = directory / f"run-{run_number:02d}"
        scan_input = run_dir / "scan-input"
        scan_input.mkdir(parents=True)
        (scan_input / "fixture.c").write_text("int main(void) { return 0; }\n")
        for name in ("report.json", "score.json"):
            (run_dir / name).write_text("{}\n", encoding="utf-8")
        (run_dir / "health.log").write_text("healthy\n", encoding="utf-8")
        (run_dir / "scan.log").write_text("scan complete\n", encoding="utf-8")
        (run_dir / "score.log").write_text("score complete\n", encoding="utf-8")
        run = {
            "run": run_number,
            "completed": True,
            "queue_empty": True,
            "gate_failures": [],
            "sealed_gate_failures": [],
            "completeness": {
                "report_present": True,
                "score_present": True,
                "summary_present": True,
                "backend_health_present": True,
                "queue_empty": True,
                "backend_valid": True,
                "source_truth_isolated": True,
            },
            "metrics": {
                "confirmed_tp": 90,
                "precision": 98.0,
                "with_review_tp": 134,
                "with_review_raw_fp": 80,
                "needs_review": 120,
                "tokens": 1_000_000,
                "wall_seconds": 2_000,
                "sealed_confirmed_recall_delta_pp": -1.0,
                "sealed_precision_delta_pp": -1.0,
            },
        }
        runs.append(run)
        (run_dir / "summary.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    aggregate = {
        "schema_version": "zscope.formal-benchmark.v2",
        "language": "cpp",
        "git_sha": git_sha,
        "git_tree": "a" * 40,
        "cold_runs": 5,
        "all_completed": True,
        "passed": True,
        "sealed_set_verified": True,
        "performance_outliers": [],
        "runs": runs,
    }
    (directory / "aggregate.json").write_text(
        json.dumps(aggregate, indent=2) + "\n", encoding="utf-8"
    )


def test_external_formal_artifact_breaks_release_sha_self_reference(tmp_path: Path) -> None:
    release_sha = "f" * 40
    artifact = tmp_path / "formal-cpp"
    artifact.mkdir()
    _write_formal_cpp_artifact(artifact, release_sha)

    audit = evaluate_candidate(
        ROOT / "docs/releases/benchmark-provenance.json",
        release_sha=release_sha,
        version=__version__,
        formal_artifacts={"cpp": artifact},
    )

    assert "cpp:benchmark_sha_not_release_sha" not in audit["hard_blockers"]
    assert "cpp:formal_artifact_schema_not_current" in audit["hard_blockers"]
    assert "balanced_default_attestation_missing" in audit["rc_blockers"]
    cpp = next(item for item in audit["benchmarks"] if item["language"] == "cpp")
    assert cpp["source"] == "workflow_artifact"
    assert cpp["benchmark_git_sha"] == release_sha

    aggregate_path = artifact / "aggregate.json"
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    aggregate["git_sha"] = "e" * 40
    aggregate_path.write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")
    mismatched = evaluate_candidate(
        ROOT / "docs/releases/benchmark-provenance.json",
        release_sha=release_sha,
        version=__version__,
        formal_artifacts={"cpp": artifact},
    )
    assert "cpp:benchmark_sha_not_release_sha" in mismatched["hard_blockers"]
