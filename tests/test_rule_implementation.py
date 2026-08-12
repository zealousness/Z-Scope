from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest

from zscope.rules.catalog import RuleCatalog, RuleCatalogError
from zscope.rules import extensions
from zscope.rules.catalog import packaged_skill_languages
from zscope.rules.implementation import (
    clear_builtin_implementation_cache,
    discover_builtin_implementation,
    validate_builtin_implementation,
)


def test_builtin_implementation_inventory_matches_catalog_and_is_cached() -> None:
    clear_builtin_implementation_cache()
    first = discover_builtin_implementation()
    second = discover_builtin_implementation()

    assert second is first
    assert first.ids_for("cpp_regex")
    assert first.ids_for("cpp_clang_cfg")
    assert first.ids_for("cpp_clang_matcher")
    assert first.ids_for("cpp_graph")
    assert first.ids_for("java_local")
    assert "clang_cfg_allocation_size_arithmetic_without_overflow_guard" in first.ids_for(
        "cpp_clang_cfg"
    )
    validate_builtin_implementation(RuleCatalog.builtin())


def test_builtin_implementation_validation_rejects_missing_and_stale_catalog_ids() -> None:
    catalog = RuleCatalog.builtin()
    removed = "same_pointer_freed_twice"
    missing_descriptor = RuleCatalog(
        (item for item in catalog if item.id != removed),
        version=catalog.version,
        source_path=catalog.source_path,
        source_sha256=catalog.source_sha256,
    )
    with pytest.raises(
        RuleCatalogError,
        match=r"cpp_regex implementation IDs missing from catalog: same_pointer_freed_twice",
    ):
        validate_builtin_implementation(missing_descriptor)

    exemplar = catalog.require(removed)
    stale_descriptor = replace(exemplar, id="catalog_only_rule")
    catalog_only = RuleCatalog(
        (*catalog.descriptors, stale_descriptor),
        version=catalog.version,
        source_path=catalog.source_path,
        source_sha256=catalog.source_sha256,
    )
    with pytest.raises(
        RuleCatalogError,
        match=r"cpp_regex catalog IDs without implementation: catalog_only_rule",
    ):
        validate_builtin_implementation(catalog_only)


def test_builtin_implementation_validation_rejects_java_metadata_drift() -> None:
    catalog = RuleCatalog.builtin()
    target = catalog.require("java_sql_statement_execute")
    changed = replace(target, defect_class="command_injection")
    drifted = RuleCatalog(
        tuple(changed if item.id == target.id else item for item in catalog),
        version=catalog.version,
        source_path=catalog.source_path,
        source_sha256=catalog.source_sha256,
    )
    with pytest.raises(RuleCatalogError, match="implementation metadata"):
        validate_builtin_implementation(drifted)


def test_rule_catalog_public_and_private_state_is_frozen() -> None:
    catalog = RuleCatalog.builtin()

    with pytest.raises(FrozenInstanceError):
        catalog.version = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        catalog.source_path = "other"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        catalog._descriptors = ()  # type: ignore[misc]
    with pytest.raises(TypeError):
        catalog.aliases["new_alias"] = "same_pointer_freed_twice"  # type: ignore[index]


def test_shared_preflight_runs_builtin_implementation_check_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    config = SimpleNamespace(
        project=SimpleNamespace(project_root=str(tmp_path), language="c_cpp"),
        indexing=SimpleNamespace(backend="regex"),
        rules=SimpleNamespace(disabled_ids=(), packs=(), providers=()),
    )
    spec_registry = SimpleNamespace(
        skills={
            name: SimpleNamespace(languages=languages)
            for name, languages in packaged_skill_languages().items()
        }
    )

    def reject_drift(_catalog: RuleCatalog) -> None:
        raise RuleCatalogError("implementation drift marker")

    monkeypatch.setattr(extensions, "validate_builtin_implementation", reject_drift)
    with pytest.raises(RuleCatalogError, match="implementation drift marker"):
        extensions.preflight_rules(config, spec_registry=spec_registry)
