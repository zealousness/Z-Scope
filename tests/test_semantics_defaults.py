from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.regex import LocalPatternSemantics, RegexCandidateGenerator
from zscope.semantics.defaults import default_checker_api_names, default_local_pattern_semantics


def test_packaged_default_semantics_feed_all_local_candidate_generators() -> None:
    semantics = default_local_pattern_semantics()

    assert "free" in semantics.deallocators
    assert "pthread_mutex_lock" in semantics.lock_apis
    assert "memcpy" in semantics.copy_sinks
    assert "pthread_rwlock_rdlock" in default_checker_api_names("extended_lock_apis")
    assert "strncpy" in default_checker_api_names("string_copy_sinks")
    assert "destroy" not in default_checker_api_names("graph_release_apis")

    regex = RegexCandidateGenerator()
    clang = ClangAstCfgCandidateGenerator()
    graph = GraphCandidateGenerator(object())

    assert "free" in regex._deallocator_names
    assert "free" in clang._release_names
    assert "pthread_rwlock_rdlock" in graph._lock_names


def test_explicit_semantics_extend_packaged_defaults() -> None:
    custom = LocalPatternSemantics()
    custom.add_api("allocator", "ProjectAlloc", "user_config")

    regex = RegexCandidateGenerator(custom)

    assert "malloc" in regex._allocator_names
    assert "ProjectAlloc" in regex._allocator_names
