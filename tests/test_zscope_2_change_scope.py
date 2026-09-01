from scripts.check_zscope_2_change_scope import (
    classify_changes,
    classify_path,
    main,
    scope_errors,
)


def test_change_scope_classifies_governed_paths_without_overlap() -> None:
    assert classify_path("zscope/core/validation/runner.py") == "product"
    assert classify_path("zscope/benchmarking/p6_protocol.py") == "product"
    assert classify_path("zscope/benchmarking/isolation.py") == "product"
    assert classify_path("zscope/benchmarking/provider_runtime.py") == "product"
    assert classify_path("zscope/benchmarking/runner.py") == "product"
    assert classify_path("scripts/p6_balanced_quality_gate.py") == "product"
    assert classify_path("scripts/run_p6_cold_producer.py") == "product"
    assert classify_path("scripts/external_benchmark.py") == "product"
    assert classify_path("containers/p6/Containerfile") == "product"
    assert classify_path(".github/workflows/p6-pilot-validation.yml") == "product"
    assert classify_path("zscope/benchmarking/protocol.py") == "scorer"
    assert classify_path("zscope/benchmarking/benchmark_v5.py") == "scorer"
    assert classify_path("zscope/benchmarking/truth_contract.py") == "scorer"
    assert classify_path("zscope/cli/benchmark.py") == "scorer"
    assert classify_path("scripts/score_range_v5.py") == "scorer"
    assert classify_path("test/range/benchmark/ground_truth.json") == "truth_fixture"
    assert classify_path("test/range/benchmark/v16/ground_truth.json") == "truth_fixture"
    assert classify_path("test/range/benchmark/v16/review-packets/RANGE-001.json") == (
        "truth_fixture"
    )
    assert classify_path("test/range/benchmark/v16/review-packet-catalog.json") == ("truth_fixture")
    assert classify_path("test/range/benchmark/v16/reviews/normalized-decisions.json") == (
        "truth_fixture"
    )
    assert classify_path("test/range/benchmark/v16/pairs/CASE-001/manifest.json") == (
        "truth_fixture"
    )
    assert classify_path("scripts/generate_range_v16_review_packets.py") == "truth_fixture"
    assert classify_path("scripts/validate_range_v16_truth.py") == "truth_fixture"
    assert classify_path("test/range/src/lifecycle.c") == "truth_fixture"
    assert classify_path("tests/test_validation_runner.py") is None


def test_change_scope_allows_one_domain_with_tests_and_docs() -> None:
    paths = [
        "zscope/core/validation/runner.py",
        "tests/test_validation_runner.py",
        "docs/modules/analysis-pipeline.md",
    ]
    assert scope_errors(paths) == []
    assert classify_changes(paths)["product"] == ("zscope/core/validation/runner.py",)


def test_change_scope_allows_product_with_p6_control_plane() -> None:
    paths = [
        "zscope/core/validation/runner.py",
        "zscope/benchmarking/p6_balanced_orchestrator.py",
        "zscope/benchmarking/isolation.py",
        "zscope/benchmarking/provider_runtime.py",
        "zscope/benchmarking/runner.py",
        "scripts/p6_balanced_quality_gate.py",
        "scripts/run_p6_synthetic_replay.py",
        "scripts/external_benchmark.py",
        "containers/p6/Containerfile",
        ".github/actions/validate-p6-artifact/action.yml",
        ".github/workflows/p6-pilot-validation.yml",
    ]

    assert scope_errors(paths) == []
    assert classify_changes(paths)["product"] == tuple(sorted(paths))


def test_change_scope_rejects_p6_control_plane_with_truth_or_review_packets() -> None:
    for protected_path in (
        "test/range/benchmark/ground_truth.json",
        "test/range/benchmark/v16/ground_truth.json",
        "test/range/benchmark/v16/review-packets/RANGE-001.json",
        "test/range/benchmark/v16/review-packet-catalog.json",
        "test/range/src/lifecycle.c",
    ):
        errors = scope_errors(["zscope/benchmarking/p6_protocol.py", protected_path])
        assert len(errors) == 1
        assert "product" in errors[0]
        assert "truth_fixture" in errors[0]


def test_change_scope_rejects_p6_control_plane_with_frozen_scorer() -> None:
    for scorer_path in (
        "zscope/benchmarking/protocol.py",
        "zscope/benchmarking/benchmark_v5.py",
        "zscope/benchmarking/truth_contract.py",
        "zscope/cli/benchmark.py",
        "scripts/score_range_v5.py",
    ):
        errors = scope_errors(["zscope/benchmarking/p6_protocol.py", scorer_path])
        assert len(errors) == 1
        assert "product" in errors[0]
        assert "scorer" in errors[0]


def test_change_scope_rejects_product_and_truth() -> None:
    errors = scope_errors(["zscope/rules/analyzer.py", "test/range/benchmark/ground_truth.json"])
    assert len(errors) == 1
    assert "product" in errors[0]
    assert "truth_fixture" in errors[0]


def test_change_scope_rejects_truth_and_scorer() -> None:
    errors = scope_errors(["test/range/src/lifecycle.c", "zscope/benchmarking/protocol.py"])
    assert len(errors) == 1
    assert "truth_fixture" in errors[0]
    assert "scorer" in errors[0]


def test_change_scope_cli_returns_two_for_mixed_domains(capsys) -> None:
    code = main(
        [
            "--path",
            "zscope/orchestration/active_discovery.py",
            "--path",
            "scripts/compare_range_matchers.py",
        ]
    )
    assert code == 2
    assert "change-scope violation" in capsys.readouterr().err
