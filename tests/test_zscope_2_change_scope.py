from scripts.check_zscope_2_change_scope import (
    classify_changes,
    classify_path,
    main,
    scope_errors,
)


def test_change_scope_classifies_governed_paths_without_overlap() -> None:
    assert classify_path("zscope/core/validation/runner.py") == "product"
    assert classify_path("zscope/benchmarking/protocol.py") == "scorer"
    assert classify_path("test/range/benchmark/ground_truth.json") == "truth_fixture"
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
