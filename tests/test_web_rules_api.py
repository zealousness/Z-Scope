from __future__ import annotations

from io import BytesIO
from types import SimpleNamespace

import pytest

from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog, RuleDescriptor
from zscope.web import server
from zscope.web.services import RuleService


def _descriptor(
    rule_id: str,
    *,
    engine: str = "cpp_regex",
    capability: str = "source_text",
    title: str = "Test rule",
) -> RuleDescriptor:
    return RuleDescriptor(
        id=rule_id,
        language="c_cpp",
        engine=engine,
        defect_class="use_after_free",
        cwe="CWE-416",
        skill="temporal_memory",
        default_severity="high",
        revision=1,
        status="stable",
        title=title,
        summary="A deterministic test rule.",
        required_capabilities=(capability,),
        source="test-suite",
    )


@pytest.fixture
def effective_rules() -> EffectiveRuleSet:
    catalog = RuleCatalog(
        (
            _descriptor("test.enabled", title="Released object reuse"),
            _descriptor("test.disabled", title="Disabled release rule"),
            _descriptor(
                "test.unavailable",
                engine="cpp_clang_cfg",
                capability="clang_structure",
                title="Clang-only release rule",
            ),
        ),
        source_path="test-catalog.yaml",
        source_sha256="1" * 64,
    )
    return EffectiveRuleSet.build(
        catalog,
        language="c_cpp",
        backend="regex",
        disabled_ids=("test.disabled",),
        implementation_sha256="2" * 64,
    )


def test_rule_service_returns_shared_serialization_and_filters(
    monkeypatch, effective_rules: EffectiveRuleSet
) -> None:
    monkeypatch.setattr(
        "zscope.web.services.ConfigLoader.load",
        lambda _path: SimpleNamespace(effective_rules=effective_rules),
    )
    service = RuleService(default_name="zscope.yaml")

    payload = service.payload("status=enabled&q=CWE-416")

    assert payload["schema_version"] == "zscope.rule-catalog.v2"
    assert payload["catalog_sha256"] == "1" * 64
    assert payload["effective_sha256"]
    assert payload["language"] == "c_cpp"
    assert payload["backend"] == "regex"
    assert payload["summary"] == {
        "total": 1,
        "enabled": 1,
        "disabled": 0,
        "unavailable": 0,
    }
    assert payload["catalog_summary"]["total"] == 3
    assert [rule["id"] for rule in payload["rules"]] == ["test.enabled"]
    assert payload["rules"][0]["effective_reason"] == "enabled_by_default"
    assert payload["rules"][0]["qualification_state"] == "not_required"
    assert payload["facets"]["engines"] == ["cpp_clang_cfg", "cpp_regex"]


def test_rule_service_filters_engine_skill_catalog_status_and_search(
    monkeypatch, effective_rules: EffectiveRuleSet
) -> None:
    monkeypatch.setattr(
        "zscope.web.services.ConfigLoader.load",
        lambda _path: SimpleNamespace(effective_rules=effective_rules),
    )
    service = RuleService()

    payload = service.payload(
        "language=c_cpp&engine=cpp_clang_cfg&skill=temporal_memory&status=stable&q=clang-only"
    )

    assert [rule["id"] for rule in payload["rules"]] == ["test.unavailable"]
    assert payload["rules"][0]["required_capabilities"] == ["clang_structure"]
    assert payload["rules"][0]["source"] == "test-suite"


def test_rule_service_rejects_invalid_filters() -> None:
    service = RuleService()

    with pytest.raises(ValueError, match="language must be one of"):
        service.payload("language=python")
    with pytest.raises(ValueError, match="status must be one of"):
        service.payload("status=maybe")


def test_rules_get_route_is_read_only(monkeypatch) -> None:
    monkeypatch.setattr(
        server,
        "_rule_service",
        SimpleNamespace(payload=lambda query: {"query": query, "rules": []}),
    )
    handler = object.__new__(server.ZScopeHandler)
    handler.path = "/api/rules?engine=cpp_regex"
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((status, payload))

    handler.do_GET()

    assert sent == [(200, {"query": "engine=cpp_regex", "rules": []})]

    handler.path = "/api/rules"
    handler.headers = {"Content-Length": "0"}
    handler.rfile = BytesIO()
    errors = []
    handler.send_error = lambda status: errors.append(status)
    handler.do_POST()

    assert errors == [404]


def test_dashboard_exposes_read_only_rule_catalog_and_finding_link() -> None:
    html = server.WEB_DIR.joinpath("index.html").read_text(encoding="utf-8")

    assert "规则目录" in html
    assert "fetch(`/api/rules" in html
    assert "openRuleFromFinding(selectedFinding)" in html
    assert "rules.disabled_ids" in html
    assert "POST /api/rules" not in html
