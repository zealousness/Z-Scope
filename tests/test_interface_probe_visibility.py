"""M6 6.1 visibility: per-run interface-probe accounting surfaces in the report.

The custom-interface change stamps ``role``/``role_source`` on semantic
snapshots only; the probe usage events (``agent=user_config_interface_probe``)
are countable, but the A/B pilot needs a per-run aggregate block.  These tests
pin the accounting and the metadata/run-manifest passthrough.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict

import zscope.core.analysis.analyzer as analyzer_mod
from zscope.core.analysis.analyzer import Analyzer
from zscope.reporting.schema import build_run_manifest


def _probe_analyzer() -> Analyzer:
    analyzer = Analyzer.__new__(Analyzer)
    analyzer._interface_probe_used = 0
    analyzer._interface_probe_stats = {
        "probed": 0,
        "classified": 0,
        "declined": 0,
        "skipped_budget": 0,
        "skipped_known_role": 0,
        "roles": {},
        "classified_functions": [],
    }
    return analyzer


def _patch_probe(monkeypatch, decision: Any) -> None:
    monkeypatch.setattr(analyzer_mod, "classify_api_name", lambda name: "")
    monkeypatch.setattr(
        "zscope.orchestration.user_config_inference.classify_single_interface_with_llm",
        lambda *args, **kwargs: decision,
    )


def test_probe_stats_count_classified_and_declined(monkeypatch) -> None:
    analyzer = _probe_analyzer()

    class _Cfg:
        analysis = SimpleNamespace(llm_interface_inference=True, llm_interface_inference_budget=5)
        scan = SimpleNamespace(llm_profiles=SimpleNamespace(analysis="default"))
        project = SimpleNamespace(agents=[])

    analyzer.config = _Cfg()
    analyzer.user_config = SimpleNamespace(get_external_function=lambda name: False)
    analyzer.llm_clients = {"default": object()}
    monkeypatch.setattr(Analyzer, "_scan_role_llm_client", lambda self, role: object())
    _patch_probe(monkeypatch, {"kind": "lock_api", "confidence": 0.9})
    snapshot: Dict[str, Any] = {}
    analyzer._maybe_inject_interface_role("zzq_wrapper", snapshot, {})
    assert snapshot["role"] == "lock_api"
    assert snapshot["role_source"] == "llm_interface_probe"

    _patch_probe(monkeypatch, None)
    declined: Dict[str, Any] = {}
    analyzer._maybe_inject_interface_role("zzq_other", declined, {})
    assert declined["role"] == ""
    assert declined["role_source"] == "llm_interface_probe"

    stats = analyzer._interface_probe_stats
    assert stats["probed"] == 2
    assert stats["classified"] == 1
    assert stats["declined"] == 1
    assert stats["roles"] == {"lock_api": 1}
    assert stats["classified_functions"] == [
        {"function": "zzq_wrapper", "role": "lock_api", "confidence": 0.9}
    ]


def test_probe_stats_skip_reasons(monkeypatch) -> None:
    analyzer = _probe_analyzer()

    class _Cfg:
        analysis = SimpleNamespace(llm_interface_inference=True, llm_interface_inference_budget=1)
        scan = SimpleNamespace(llm_profiles=SimpleNamespace(analysis="default"))
        project = SimpleNamespace(agents=[])

    analyzer.config = _Cfg()
    analyzer.user_config = SimpleNamespace(get_external_function=lambda name: False)
    analyzer.llm_clients = {"default": object()}
    monkeypatch.setattr(Analyzer, "_scan_role_llm_client", lambda self, role: object())
    _patch_probe(monkeypatch, {"kind": "alloc_api", "confidence": 0.8})

    # Known role short-circuits without probing.
    analyzer._maybe_inject_interface_role("zzq_a", {"role": "lock_api"}, {})
    assert analyzer._interface_probe_stats["skipped_known_role"] == 1

    # The single budget slot is consumed; the next probe skips on budget.
    analyzer._maybe_inject_interface_role("zzq_b", {}, {})
    analyzer._maybe_inject_interface_role("zzq_c", {}, {})
    assert analyzer._interface_probe_used == 1
    assert analyzer._interface_probe_stats["skipped_budget"] == 1
    assert analyzer._interface_probe_stats["classified"] == 1


def test_cpp_normal_scan_with_semantics_never_calls_interface_probe(monkeypatch) -> None:
    analyzer = _probe_analyzer()
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            language="c_cpp", semantics_file="zscope.semantics.yaml", agents=[]
        ),
        analysis=SimpleNamespace(
            llm_interface_inference=True, llm_interface_inference_budget=50
        ),
        scan=SimpleNamespace(llm_profiles=SimpleNamespace(analysis="default")),
    )
    analyzer.user_config = SimpleNamespace(get_external_function=lambda name: False)
    analyzer.llm_clients = {"default": object()}
    monkeypatch.setattr(
        Analyzer,
        "_scan_role_llm_client",
        lambda self, role: (_ for _ in ()).throw(AssertionError("unexpected LLM probe")),
    )

    snapshot: Dict[str, Any] = {}
    assert analyzer._maybe_inject_interface_role("project_alloc", snapshot, {}) == {}
    assert analyzer._interface_probe_stats["probed"] == 0
    assert analyzer._interface_probe_stats["skipped_project_semantics_authority"] == 1


def test_run_manifest_carries_interface_probe_block() -> None:
    probe = {
        "probed": 3,
        "classified": 2,
        "declined": 1,
        "skipped_budget": 0,
        "skipped_known_role": 4,
        "skipped_external": 0,
        "skipped_no_client": 0,
        "errors": 0,
        "roles": {"lock_api": 2},
        "classified_functions": [{"function": "f", "role": "lock_api", "confidence": 0.9}],
    }
    manifest = build_run_manifest(
        {"interface_probe": probe},
        entry_function="main",
        finding="vulnerable",
        completeness="complete",
        issue_count=1,
        needs_review_count=0,
    )
    assert manifest["interface_probe"] == probe

    # Off/absent runs still report a zeroed block so A/B columns line up.
    manifest_zero = build_run_manifest(
        {},
        entry_function="main",
        finding="vulnerable",
        completeness="complete",
        issue_count=1,
        needs_review_count=0,
    )
    assert manifest_zero["interface_probe"]["probed"] == 0
    assert manifest_zero["interface_probe"]["roles"] == {}
