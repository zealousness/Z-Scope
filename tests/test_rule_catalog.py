from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from zscope.rules.catalog import (
    EffectiveRuleSet,
    RuleCatalog,
    RuleCatalogError,
    RuleDescriptor,
    external_descriptor,
    serialize_effective_rules,
)
from zscope.rules.implementation import discover_builtin_implementation


SKILL_LANGUAGES = {
    "bounds_and_integer": ("c_cpp",),
    "code_semantic_modeling": ("c_cpp", "java"),
    "concurrency_lock_order": ("c_cpp",),
    "evidence_validation": ("c_cpp", "java"),
    "java_authz": ("java",),
    "java_concurrency": ("java",),
    "java_crypto": ("java",),
    "java_deserialization": ("java",),
    "java_injection": ("java",),
    "java_resource_lifecycle": ("java",),
    "java_web_security": ("java",),
    "null_and_failure": ("c_cpp",),
    "ownership_contract": ("c_cpp",),
    "resource_lifecycle": ("c_cpp",),
    "shared_state_race": ("c_cpp",),
    "snapshot_refresh_decision": ("c_cpp", "java"),
    "stack_escape": ("c_cpp",),
    "string_and_format": ("c_cpp",),
    "temporal_memory": ("c_cpp",),
}


def _descriptor(**overrides):
    value = {
        "id": "sample_legacy_rule",
        "language": "c_cpp",
        "engine": "cpp_regex",
        "defect_class": "bounds",
        "cwe": "CWE-125",
        "skill": "bounds_and_integer",
        "default_severity": "high",
        "revision": 1,
        "status": "stable",
        "title": "Sample rule",
        "summary": "Sample built-in rule.",
        "required_capabilities": ["source_text"],
        "aliases": [],
        "legacy_id": True,
    }
    value.update(overrides)
    return value


def _write_catalog(path: Path, rules) -> Path:
    path.write_text(
        yaml.safe_dump(
            {"rule_catalog_version": 1, "rules": rules},
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return path


def test_builtin_catalog_covers_current_java_and_cpp_rule_engines() -> None:
    catalog = RuleCatalog.builtin(skill_languages=SKILL_LANGUAGES)
    by_engine = {
        engine: {item.id for item in catalog if item.engine == engine}
        for engine in {
            "java_local",
            "cpp_regex",
            "cpp_clang_cfg",
            "cpp_clang_matcher",
            "cpp_graph",
        }
    }
    inventory = discover_builtin_implementation()
    for engine, catalog_ids in by_engine.items():
        assert catalog_ids == inventory.ids_for(engine)
    assert len(catalog) == sum(len(rule_ids) for rule_ids in by_engine.values())
    assert all(item.legacy_id for item in catalog)


def test_catalog_rejects_duplicate_yaml_keys_and_unknown_fields(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "rule_catalog_version: 1\nrule_catalog_version: 1\nrules: []\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleCatalogError, match="duplicate YAML key"):
        RuleCatalog.from_path(duplicate, builtin=True, skill_languages=SKILL_LANGUAGES)

    unknown = _descriptor(unexpected=True)
    path = _write_catalog(tmp_path / "unknown.yaml", [unknown])
    with pytest.raises(RuleCatalogError, match="unknown fields: unexpected"):
        RuleCatalog.from_path(path, builtin=True, skill_languages=SKILL_LANGUAGES)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("language", "cpp", "unsupported language"),
        ("engine", "svf", "unsupported engine"),
        ("cwe", "125", "invalid CWE"),
        ("default_severity", "urgent", "invalid severity"),
        ("status", "preview", "invalid status"),
        ("revision", 0, "revision must be a positive integer"),
        ("required_capabilities", ["magic"], "unknown capabilities"),
    ],
)
def test_catalog_rejects_invalid_types_and_enums(
    tmp_path: Path, field: str, value, message: str
) -> None:
    path = _write_catalog(tmp_path / f"invalid-{field}.yaml", [_descriptor(**{field: value})])
    with pytest.raises(RuleCatalogError, match=message):
        RuleCatalog.from_path(path, builtin=True, skill_languages=SKILL_LANGUAGES)


def test_catalog_rejects_alias_collisions_and_skill_language_mismatch(tmp_path: Path) -> None:
    first = _descriptor(id="first_rule", aliases=["shared_alias"])
    second = _descriptor(id="second_rule", aliases=["shared_alias"])
    path = _write_catalog(tmp_path / "aliases.yaml", [first, second])
    with pytest.raises(RuleCatalogError, match="duplicate rule id or alias"):
        RuleCatalog.from_path(path, builtin=True, skill_languages=SKILL_LANGUAGES)

    mismatch = _descriptor(skill="java_injection")
    path = _write_catalog(tmp_path / "skill.yaml", [mismatch])
    with pytest.raises(RuleCatalogError, match="does not support c_cpp"):
        RuleCatalog.from_path(path, builtin=True, skill_languages=SKILL_LANGUAGES)


def test_new_builtin_ids_require_namespace_but_legacy_ids_are_preserved(tmp_path: Path) -> None:
    invalid = _descriptor(legacy_id=False)
    path = _write_catalog(tmp_path / "new-id.yaml", [invalid])
    with pytest.raises(RuleCatalogError, match="must use prefix"):
        RuleCatalog.from_path(path, builtin=True, skill_languages=SKILL_LANGUAGES)

    valid = _descriptor(id="zscope.c_cpp.cpp_regex.sample", legacy_id=False)
    path = _write_catalog(tmp_path / "valid-id.yaml", [valid])
    catalog = RuleCatalog.from_path(path, builtin=True, skill_languages=SKILL_LANGUAGES)
    assert catalog.require(valid["id"]).legacy_id is False

    external = external_descriptor(
        rule_id="acme.rule",
        language="c_cpp",
        engine="python_provider",
        defect_class="bounds",
        cwe="CWE-125",
        skill="bounds_and_integer",
        severity="high",
        title="Acme",
        summary="Acme extension.",
        source="provider:acme",
        aliases=("zscope.c_cpp.cpp_regex.reserved",),
    )
    builtin = RuleCatalog.builtin(skill_languages=SKILL_LANGUAGES)
    with pytest.raises(RuleCatalogError, match="aliases cannot use"):
        builtin.with_extensions((external,))


def test_effective_rule_set_applies_language_backend_and_strict_disabled_ids() -> None:
    catalog = RuleCatalog.builtin(skill_languages=SKILL_LANGUAGES)
    baseline = EffectiveRuleSet.build(catalog, language="c_cpp", backend="regex")
    assert "same_pointer_freed_twice" in baseline.enabled_ids
    assert "cross_function_lock_order_inversion" in baseline.enabled_ids
    assert "clang_cfg_use_after_release" in baseline.unavailable_ids

    disabled = EffectiveRuleSet.build(
        catalog,
        language="c_cpp",
        backend="regex",
        disabled_ids=["same_pointer_freed_twice", "clang_cfg_use_after_release"],
    )
    assert disabled.disabled_ids == {
        "same_pointer_freed_twice",
        "clang_cfg_use_after_release",
    }
    assert disabled.provenance.effective_sha256 != baseline.provenance.effective_sha256
    assert any("not applicable" in warning for warning in disabled.warnings)

    with pytest.raises(RuleCatalogError, match="duplicate rule id"):
        EffectiveRuleSet.build(
            catalog,
            language="c_cpp",
            backend="regex",
            disabled_ids=["same_pointer_freed_twice", "same_pointer_freed_twice"],
        )
    with pytest.raises(RuleCatalogError, match="did you mean"):
        EffectiveRuleSet.build(
            catalog,
            language="c_cpp",
            backend="regex",
            disabled_ids=["same_pointer_freed_twce"],
        )
    with pytest.raises(RuleCatalogError, match="is for java"):
        EffectiveRuleSet.build(
            catalog,
            language="c_cpp",
            backend="regex",
            disabled_ids=["java_command_execution"],
        )


def test_rule_policy_enriches_and_validates_catalog_metadata() -> None:
    catalog = RuleCatalog.builtin(skill_languages=SKILL_LANGUAGES)
    effective = EffectiveRuleSet.build(catalog, language="c_cpp", backend="unified")
    issue = effective.policy.enrich_issue(
        {
            "rule": "same_pointer_freed_twice",
            "evidence_pack": {"positive_evidence": ["two frees"]},
        }
    )
    descriptor = catalog.require("same_pointer_freed_twice")
    assert issue["rule_id"] == descriptor.id
    assert issue["rule_engine"] == "cpp_regex"
    assert issue["cwe"] == descriptor.cwe
    assert issue["skill"] == "temporal_memory"
    assert issue["evidence_pack"]["rule_revision"] == 1
    assert issue["evidence_pack"]["rule_descriptor"]["rule_id"] == descriptor.id

    with pytest.raises(RuleCatalogError, match="does not match catalog"):
        effective.policy.enrich_issue({"rule_id": descriptor.id, "defect_class": "memory_leak"})

    for defect_class, cwe in (
        ("buffer_underread", "CWE-127"),
        ("buffer_underwrite", "CWE-124"),
    ):
        variant = effective.policy.enrich_issue(
            {
                "rule_id": "clang_cfg_unchecked_pointer_backtrack",
                "defect_class": defect_class,
                "cwe": cwe,
            }
        )
        assert variant["defect_class"] == defect_class
        assert variant["cwe"] == cwe
        assert variant["skill"] == "bounds_and_integer"
    with pytest.raises(RuleCatalogError, match="not a registered legacy variant"):
        effective.policy.enrich_issue(
            {
                "rule_id": "clang_cfg_unchecked_pointer_backtrack",
                "defect_class": "buffer_overread",
                "cwe": "CWE-126",
            }
        )


def test_effective_rule_serialization_is_shared_and_complete() -> None:
    catalog = RuleCatalog.builtin(skill_languages=SKILL_LANGUAGES)
    effective = EffectiveRuleSet.build(
        catalog,
        language="java",
        backend="java_unified",
        disabled_ids=["java_command_execution"],
    )
    payload = serialize_effective_rules(effective)
    assert payload["schema_version"] == "zscope.rule-catalog.v1"
    assert payload["summary"] == {
        "total": 48,
        "enabled": 47,
        "disabled": 1,
        "unavailable": 0,
    }
    assert payload["disabled"] == [{"id": "java_command_execution", "reason": "disabled_by_config"}]
    row = next(item for item in payload["rules"] if item["id"] == "java_command_execution")
    assert row["source"] == "builtin"
    assert row["effective_status"] == "disabled"
    assert row["effective_reason"] == "disabled_by_config"
