from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.svf_value_flow import SvfValueFlowCandidateGenerator
from zscope.core.candidates.regex import LocalPatternSemantics


def test_svf_value_flow_normalizes_saber_bug_to_evidence_candidate() -> None:
    bug = {
        "source_func": "alloc_session",
        "sink_func": "cleanup_session",
        "bug_type": "NeverFree",
        "file_path": "src/session.c",
        "line": 77,
        "tool": "saber",
        "svf_group": "entry_api",
        "func_name": "api_open",
        "func_start": 70,
        "func_end": 90,
        "signature": "int api_open(void)",
        "flow_path": [
            {
                "function": "api_open",
                "file": "src/session.c",
                "line": 72,
                "code": "p = alloc_session();",
                "ssa_node": "v12",
                "llvm_value": "%p = call ptr @alloc_session()",
                "points_to": ["heap@alloc_session:72"],
                "alias_set": ["p"],
                "object_id": "heap@72",
            },
            {"function": "api_open", "file": "src/session.c", "line": 77, "code": "return -1;"},
        ],
    }

    issue = SvfValueFlowCandidateGenerator().generate_issues([bug], entry_func="entry")[0]

    assert issue["candidate_source"] == "svf_value_flow"
    assert issue["finding_kind"] == "svf_value_flow_candidate"
    assert issue["defect_class"] == "memory_leak"
    assert issue["evidence_pack"]["value_flow"]["svf_group"] == "entry_api"
    assert issue["evidence_pack"]["value_flow"]["backend_path"][0]["function"] == "api_open"
    assert issue["evidence_pack"]["value_flow"]["backend_path"][0]["ssa_node"] == "v12"
    assert issue["evidence_pack"]["value_flow"]["backend_path"][0]["points_to"] == ["heap@alloc_session:72"]
    assert issue["evidence_pack"]["path"]["backend"] == "SVF/Saber value-flow"
    assert "Backend value-flow path" in "\n".join(issue["positive_evidence"])
    assert "Validator must confirm" in "\n".join(issue["negative_evidence"])


def test_svf_value_flow_includes_source_level_reconstruction() -> None:
    bug = {
        "source_func": "alloc_session",
        "sink_func": "cleanup_session",
        "bug_type": "DoubleFree",
        "file_path": "src/session.c",
        "line": 88,
        "tool": "saber",
        "func_name": "cleanup_session",
    }

    def resolver(row, entry_func):
        assert row["bug_type"] == "DoubleFree"
        assert entry_func == "api_close"
        return {
            "entry_function": "api_close",
            "target_function": "cleanup_session",
            "call_path": ["api_close", "cleanup_session"],
            "complete_to_entry": True,
            "reported_snippet": "88 | free(session);",
        }

    issue = SvfValueFlowCandidateGenerator(source_path_resolver=resolver).generate_issues(
        [bug],
        entry_func="api_close",
    )[0]

    source_path = issue["evidence_pack"]["source_path"]
    assert source_path["complete_to_entry"] is True
    assert source_path["call_path"] == ["api_close", "cleanup_session"]
    assert "entry call path" in "\n".join(issue["positive_evidence"])


def test_analyzer_uses_svf_value_flow_candidates_for_unified_backend() -> None:
    class UnifiedBackend:
        pass

    class FakeDb:
        def get_enriched_taint_bugs(self, func_name: str = "", limit: int = 50, func_names=None):
            assert func_name == ""
            assert set(func_names or []) == {"entry", "cleanup"}
            return [
                {
                    "source_func": "alloc_obj",
                    "sink_func": "free_obj",
                    "bug_type": "DoubleFree",
                    "file_path": "src/demo.c",
                    "line": 12,
                    "tool": "saber",
                    "func_name": "cleanup",
                }
            ]

    class FakeIndex:
        backend_name = "unified"
        backend = UnifiedBackend()

        def get_callees(self, name: str, limit: int = 80):
            return {"entry": [{"name": "cleanup"}]}.get(name, [])

        def get_file_snippet(self, file_path: str, start_line: int, end_line: int):
            return {"file": file_path, "start_line": start_line, "end_line": end_line, "code": "12 | free(obj);\n"}

        def get_function_impl(self, name: str, max_lines: int = 40, warn_missing: bool = False):
            codes = {
                "alloc_obj": "1 | void alloc_obj(void) { obj = malloc(8); }\n",
                "cleanup": "1 | void cleanup(void) { free(obj); }\n",
                "free_obj": "1 | void free_obj(void) { free(obj); }\n",
            }
            return {
                "func_name": name,
                "file": "src/demo.c",
                "start_line": 1,
                "end_line": 20,
                "signature": f"void {name}(void)",
                "code": codes.get(name, f"1 | void {name}(void) {{}}\n"),
            }

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.user_config = object()
    analyzer._local_pattern_semantics = LocalPatternSemantics()
    analyzer._semantic_overlay = {
        "resource_models": [],
        "lock_models": [],
        "macro_models": [],
        "dispatcher_models": [],
        "lifecycle_models": [],
        "pointer_target_models": [],
        "function_intent_models": [],
    }
    analyzer._get_knowledge_db = lambda: FakeDb()

    issues = analyzer._detect_backend_signal_candidates({"entry_func": "entry"})

    svf = next(issue for issue in issues if issue["candidate_source"] == "svf_value_flow")
    assert svf["defect_class"] == "double_free"
    assert svf["evidence_checker"] == "svf_value_flow_checker"
    assert svf["evidence_pack"]["checker"] == "svf_value_flow_checker"
    assert svf["evidence_pack"]["source_path"]["call_path"] == ["entry", "cleanup"]
    assert "free(obj)" in svf["evidence_pack"]["source_path"]["reported_snippet"]
    source_level_flow = svf["evidence_pack"]["source_path"]["source_level_flow"]
    assert source_level_flow["schema"] == "svf_source_level_flow_v1"
    assert source_level_flow["complete_source_to_sink"] is True
    assert source_level_flow["object_symbols"] == ["obj"]
    assert source_level_flow["expression_edges"][0]["shared_object_symbols"] == ["obj"]
    assert source_level_flow["expression_edges"][1]["shared_object_symbols"] == ["obj"]
    assert [event["role"] for event in source_level_flow["events"]] == [
        "source",
        "reported_location",
        "sink",
    ]
    assert "Source-level flow events" in "\n".join(svf["positive_evidence"])
    assert "Source-level expression edges" in "\n".join(svf["positive_evidence"])
    assert svf["must_validate"] is True


def test_analyzer_uses_reachable_saber_bugs_for_backend_signal_candidates() -> None:
    class UnifiedBackend:
        pass

    class FakeDb:
        def get_enriched_taint_bugs(self, func_name: str = "", limit: int = 50, func_names=None):
            assert func_name == ""
            reachable = set(func_names or [])
            rows = [
                {
                    "source_func": "",
                    "sink_func": "",
                    "bug_type": "DoubleFree",
                    "file_path": "src/callee.c",
                    "line": 12,
                    "tool": "saber",
                    "func_name": "callee",
                },
                {
                    "source_func": "",
                    "sink_func": "",
                    "bug_type": "NeverFree",
                    "file_path": "src/unreachable.c",
                    "line": 5,
                    "tool": "saber",
                    "func_name": "unreachable",
                },
            ]
            return [row for row in rows if row["func_name"] in reachable]

    class FakeIndex:
        backend_name = "unified"
        backend = UnifiedBackend()

        def get_callees(self, name: str, limit: int = 80):
            return {"entry": [{"name": "callee"}]}.get(name, [])

        def get_file_snippet(self, file_path: str, start_line: int, end_line: int):
            return {"file": file_path, "start_line": start_line, "end_line": end_line, "code": "12 | free(obj);\n"}

        def get_function_impl(self, name: str, max_lines: int = 40, warn_missing: bool = False):
            return {
                "func_name": name,
                "file": "src/callee.c",
                "start_line": 1,
                "end_line": 20,
                "signature": f"void {name}(void)",
                "code": f"1 | void {name}(void) {{ free(obj); }}\n",
            }

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.user_config = object()
    analyzer._local_pattern_semantics = LocalPatternSemantics()
    analyzer._semantic_overlay = {
        "resource_models": [],
        "lock_models": [],
        "macro_models": [],
        "dispatcher_models": [],
        "lifecycle_models": [],
        "pointer_target_models": [],
        "function_intent_models": [],
    }
    analyzer._get_knowledge_db = lambda: FakeDb()

    issues = analyzer._detect_backend_signal_candidates({"entry_func": "entry"})

    svf_issues = [issue for issue in issues if issue["candidate_source"] == "svf_value_flow"]
    assert len(svf_issues) == 1
    assert svf_issues[0]["function"] == "callee"
    assert svf_issues[0]["must_validate"] is True
    assert svf_issues[0]["evidence_pack"]["source_path"]["call_path"] == ["entry", "callee"]


def test_analyzer_still_uses_entry_local_saber_bug_for_backend_signal_candidates() -> None:
    class UnifiedBackend:
        pass

    class FakeDb:
        def get_enriched_taint_bugs(self, func_name: str = "", limit: int = 50, func_names=None):
            assert "entry" in set(func_names or [])
            return [
                {
                    "source_func": "",
                    "sink_func": "",
                    "bug_type": "NeverFree",
                    "file_path": "src/entry.c",
                    "line": 9,
                    "tool": "saber",
                    "func_name": "entry",
                }
            ]

    class FakeIndex:
        backend_name = "unified"
        backend = UnifiedBackend()

        def get_callees(self, name: str, limit: int = 80):
            return []

        def get_file_snippet(self, file_path: str, start_line: int, end_line: int):
            return {"file": file_path, "start_line": start_line, "end_line": end_line, "code": "9 | return -1;\n"}

        def get_function_impl(self, name: str, max_lines: int = 40, warn_missing: bool = False):
            return {
                "func_name": name,
                "file": "src/entry.c",
                "start_line": 1,
                "end_line": 20,
                "signature": f"void {name}(void)",
                "code": "1 | void entry(void) { return; }\n",
            }

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.user_config = object()
    analyzer._local_pattern_semantics = LocalPatternSemantics()
    analyzer._semantic_overlay = {
        "resource_models": [],
        "lock_models": [],
        "macro_models": [],
        "dispatcher_models": [],
        "lifecycle_models": [],
        "pointer_target_models": [],
        "function_intent_models": [],
    }
    analyzer._get_knowledge_db = lambda: FakeDb()

    issues = analyzer._detect_backend_signal_candidates({"entry_func": "entry"})

    svf = next(issue for issue in issues if issue["candidate_source"] == "svf_value_flow")
    assert svf["function"] == "entry"
    assert svf["evidence_pack"]["source_path"]["call_path"] == ["entry"]


def test_unified_candidate_merge_combines_clang_and_svf_evidence_only() -> None:
    class UnifiedBackend:
        pass

    class FakeIndex:
        backend_name = "unified"
        backend = UnifiedBackend()

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    clang = {
        "candidate_id": "clang-1",
        "candidate_source": "clang_ast_cfg",
        "evidence_checker": "clang_ast_cfg_checker",
        "function": "cleanup",
        "location": "src/demo.c:42",
        "defect_class": "double_free",
        "rule": "clang_cfg_same_pointer_freed_twice",
        "source": "obj",
        "sink": "free(obj)",
        "positive_evidence": ["Clang saw two frees of obj."],
        "negative_evidence": ["Path feasibility still needs validation."],
        "evidence_pack": {
            "candidate_source": "clang_ast_cfg",
            "checker": "clang_ast_cfg_checker",
            "path": {"function": "cleanup"},
        },
    }
    svf = {
        "candidate_id": "svf-1",
        "candidate_source": "svf_value_flow",
        "evidence_checker": "svf_value_flow_checker",
        "function": "cleanup",
        "location": "src/demo.c:44",
        "defect_class": "double_free",
        "rule": "svf_value_flow_doublefree",
        "source": "alloc_obj",
        "sink": "free_obj",
        "positive_evidence": ["SVF/Saber reported DoubleFree."],
        "negative_evidence": ["Ownership transfer must be checked."],
        "evidence_pack": {
            "candidate_source": "svf_value_flow",
            "checker": "svf_value_flow_checker",
            "source_path": {
                "target_function": "cleanup",
                "reported_location": {"file": "src/demo.c", "line": 44},
                "call_path": ["entry", "cleanup"],
            },
            "value_flow": {"source_func": "alloc_obj", "sink_func": "free_obj"},
        },
    }

    merged = analyzer._merge_unified_evidence_candidates([clang, svf])

    assert len(merged) == 1
    assert merged[0]["candidate_id"] == "clang-1"
    assert merged[0]["unified_evidence_merged"] is True
    assert merged[0]["must_validate"] is True
    assert merged[0]["merged_candidate_sources"] == ["clang_ast_cfg", "svf_value_flow"]
    evidence = merged[0]["evidence_pack"]
    assert evidence["unified_backend_components"] == ["clang", "svf"]
    assert evidence["merged_backend_evidence"][0]["candidate_id"] == "svf-1"
    assert evidence["merged_backend_evidence"][0]["checker"] == "svf_value_flow_checker"
