from __future__ import annotations

from types import SimpleNamespace

from zscope.semantics import inference
from zscope.semantics.inference import (
    LocalPatternSemanticBuilder,
    iter_semantic_source_files,
)


def test_typedef_scan_ignores_generated_and_configured_trees(tmp_path) -> None:
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "types.h").write_text(
        "typedef unsigned int project_size;\n",
        encoding="utf-8",
    )
    for generated in (
        ".zscope_conversations",
        ".zscope_custom_cache",
        "benchmark_runs",
        "codeql_runs",
    ):
        path = tmp_path / generated / "nested"
        path.mkdir(parents=True)
        (path / "generated.h").write_text(
            f"typedef unsigned int {generated.strip('.').replace('-', '_')}_size;\n",
            encoding="utf-8",
        )
    excluded = tmp_path / "vendor"
    excluded.mkdir()
    (excluded / "vendor.h").write_text(
        "typedef unsigned int vendor_size;\n",
        encoding="utf-8",
    )

    builder = LocalPatternSemanticBuilder(
        SimpleNamespace(source_root=tmp_path, project_root=tmp_path),
        user_config=None,
        snapshot_store=None,
        exclude_paths=[excluded],
    )

    semantics = builder.scan_typedef_aliases()

    assert semantics.type_aliases == {"project_size": "unsigned int"}


def test_source_walk_prunes_directories_before_descent(monkeypatch, tmp_path) -> None:
    excluded = tmp_path / "vendor"
    observed: dict[str, list[str]] = {}

    def fake_walk(root, *, topdown, followlinks):
        assert topdown is True
        assert followlinks is False
        directory_names = [
            "src",
            "vendor",
            "benchmark_runs",
            "codeql_runs",
            ".zscope_conversations",
            ".zscope_arbitrary",
        ]
        yield str(root), directory_names, ["root.h", "README.md"]
        observed["remaining"] = list(directory_names)

    monkeypatch.setattr(inference.os, "walk", fake_walk)

    files = list(iter_semantic_source_files(tmp_path, [excluded]))

    assert files == [tmp_path.resolve() / "root.h"]
    assert observed["remaining"] == ["src"]
