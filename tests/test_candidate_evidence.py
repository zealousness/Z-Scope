from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.evidence import (
    SemanticOverlayCompiler,
    _compiled_identifier_token_pattern,
    _contains_token,
    annotate_candidate_evidence,
    backend_profile_for_code_index,
    evidence_engines_for_profile,
)
from zscope.semantics.defaults import default_local_pattern_semantics


class FakeUserConfig:
    def list_external_functions(self):
        return [
            {
                "func_name": "VOS_MemAlloc",
                "kind": "allocator",
                "symbol_type": "macro",
                "memory_behavior": '{"allocates": true, "caller_owns_return": true}',
                "description": "project allocator macro",
            },
            {
                "func_name": "VOS_MemFree",
                "kind": "deallocator",
                "symbol_type": "function",
                "memory_behavior": '{"releases": true}',
            },
            {
                "func_name": "VOS_Lock",
                "kind": "lock",
                "symbol_type": "function",
                "concurrency_behavior": '{"acquires_lock": true}',
            },
        ]

    def list_paired_functions(self):
        return [
            {
                "category": "resource",
                "acquire_func": "SHM_FileOpen",
                "release_func": "SHM_FileClose",
                "description": "file handle lifecycle",
            }
        ]

    def list_dispatchers(self):
        return [{"dispatcher_name": "dispatch_msg", "handler_name": "on_msg"}]

    def list_module_lifecycle(self):
        return [{"symbol_name": "module_init", "kind": "init"}]

    def get_pointer_targets(self):
        return [{"pointer_location": "ops->create", "target_functions": '["SHM_FileCreate"]'}]

    def list_function_intents(self):
        return [{"func_name": "public_api", "concurrency_group": "api"}]


class UnifiedBackend:
    pass


class FakeUnifiedIndex:
    backend_name = "unified"
    backend = UnifiedBackend()


def test_semantic_overlay_compiles_user_config_models() -> None:
    overlay = SemanticOverlayCompiler(FakeUserConfig()).compile()

    summary = overlay["summary"]
    assert summary["resource_model_count"] >= 4
    assert summary["lock_model_count"] >= 1
    assert summary["macro_names"] == ["VOS_MemAlloc"]
    assert "VOS_MemAlloc" in summary["resource_names"]
    assert "VOS_Lock" in summary["lock_names"]
    assert overlay["resource_models"][0]["carrier"] == "return_value"
    assert any(row.get("name") == "malloc" for row in overlay["resource_models"])
    assert any(row.get("source") == "builtin_defaults" for row in overlay["resource_models"])


def test_builtin_semantics_defaults_feed_local_pattern_roles() -> None:
    semantics = default_local_pattern_semantics()

    assert semantics.allocators["malloc"] == ["builtin_defaults"]
    assert semantics.deallocators["free"] == ["builtin_defaults"]
    assert semantics.copy_sinks["memcpy"] == ["builtin_defaults"]


def test_candidate_annotation_is_backend_aware_and_requires_validation() -> None:
    issue = {"id": "RULE_1", "evidence_pack": {"candidate_source": "regex_local_rule"}}
    overlay = SemanticOverlayCompiler(FakeUserConfig()).compile()

    annotate_candidate_evidence(
        issue,
        backend_profile="unified",
        checker="unified_clang_svf_local_pattern_checker",
        overlay=overlay,
        path_kind="local_memory_concurrency",
    )

    assert issue["must_validate"] is True
    assert issue["backend_profile"] == "unified"
    assert issue["evidence_engines"] == [
        "clang_ast_cfg_checker",
        "clang_knowledgedb_callgraph_checker",
        "svf_value_flow_checker",
        "saber_memory_signal_adapter",
    ]
    assert issue["evidence_pack"]["candidate_is_conclusion"] is False
    assert issue["evidence_pack"]["semantic_overlays"]["macro_names"] == ["VOS_MemAlloc"]
    assert issue["evidence_pack"]["semantic_overlay_evidence"] == {}


def test_candidate_annotation_includes_relevant_overlay_rows_only() -> None:
    issue = {
        "id": "RULE_2",
        "function": "SHM_FileCreate",
        "source": "VOS_MemAlloc(size)",
        "sink": "ops->create",
        "positive_evidence": ["handler SHM_FileCreate is called through ops->create"],
        "evidence_pack": {},
    }
    overlay = SemanticOverlayCompiler(FakeUserConfig()).compile()

    annotate_candidate_evidence(
        issue,
        backend_profile="unified",
        checker="unified_clang_svf_local_pattern_checker",
        overlay=overlay,
    )

    evidence = issue["evidence_pack"]["semantic_overlay_evidence"]
    assert evidence["resource_models"][0]["name"] == "VOS_MemAlloc"
    assert evidence["macro_models"][0]["name"] == "VOS_MemAlloc"
    assert evidence["pointer_target_models"][0]["pointer_location"] == "ops->create"


def test_contains_token_preserves_matching_semantics_with_cached_identifier_regex() -> None:
    _compiled_identifier_token_pattern.cache_clear()

    assert _contains_token("call VOS_MemAlloc(size)", "VOS_MemAlloc")
    assert _contains_token("call VOS_MemAlloc(size)", "VOS_MemAlloc")
    assert not _contains_token("call VOS_MemAllocator(size)", "VOS_MemAlloc")
    assert _contains_token("handler is called through ops->create", "ops->create")
    assert not _contains_token("handler is called through ops create", "ops->create")

    assert _compiled_identifier_token_pattern.cache_info().hits >= 1


def test_analyzer_annotation_uses_active_backend_profile() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeUnifiedIndex()
    analyzer.user_config = FakeUserConfig()
    analyzer._semantic_overlay = None

    issues = analyzer._annotate_candidate_issues(
        [{"id": "GRAPH_1", "evidence_pack": {}}],
        checker=analyzer._graph_candidate_checker(),
        path_kind="cross_function_protocol",
    )

    assert backend_profile_for_code_index(FakeUnifiedIndex()) == "unified"
    assert evidence_engines_for_profile("unified") in [issues[0]["evidence_engines"]]
    assert issues[0]["evidence_pack"]["validation_required"] is True
    assert issues[0]["semantic_overlays"]["pointer_target_count"] == 1


def test_backend_profile_downgrades_when_backend_is_unavailable() -> None:
    class FailedUnifiedIndex:
        backend_name = "unified"
        backend = None

    assert backend_profile_for_code_index(FailedUnifiedIndex()) == "regex"



