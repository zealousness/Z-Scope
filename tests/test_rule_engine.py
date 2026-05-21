from zscope.core.analysis.analyzer import Analyzer
from zscope.rules.engine import RuleEngine


class FakeJoern:
    joern_path = "joern"

    def __init__(self):
        self.queries = []

    def query(self, cpgql: str):
        self.queries.append(cpgql)
        if "controlledBy" in cpgql or "dominatedBy" in cpgql:
            return [
                {
                    "method": "api_recv",
                    "lineNumber": 18,
                    "code": "VOS_MemCopy(dst, src, len)",
                    "controlDependencies": ["if (len <= dst_size)"],
                    "dominators": ["int api_recv(char *src, unsigned len)"],
                }
            ]
        if "cpg.call.name" in cpgql and "VOS_MemCopy" in cpgql:
            return [
                {
                    "method": "api_recv",
                    "filename": "src/api.c",
                    "lineNumber": 18,
                    "code": "VOS_MemCopy(dst, src, len)",
                    "callee": "VOS_MemCopy",
                    "arguments": ["dst", "src", "len"],
                    "nearestControls": ["if (len <= dst_size)"],
                    "controls": ["if (len <= dst_size)"],
                }
            ]
        if "reachableByFlows" not in cpgql:
            return []
        return [
            {
                "source": "api_recv",
                "sink": "VOS_MemCopy",
                "category": "buffer_overflow",
                "path": [
                    {"code": "int api_recv(char *src, unsigned len)", "lineNumber": 10, "filename": "src/api.c"},
                    {"code": "VOS_MemCopy(dst, src, len)", "lineNumber": 18, "filename": "src/api.c"},
                ],
            }
        ]


class FakeUserConfig:
    def list_function_intents(self):
        return [{"symbol_name": "api_recv", "intents": "external message boundary"}]

    def list_external_functions(self):
        return [{"func_name": "VOS_MemCopy", "kind": "copy"}]

    def list_paired_functions(self):
        return [{"acquire_func": "VOS_MemAlloc", "release_func": "VOS_MemFree", "category": "memory_leak"}]


def test_rule_engine_runs_configured_joern_data_flow_checks() -> None:
    joern = FakeJoern()
    matches = RuleEngine(joern, FakeUserConfig()).run_configured_data_flow_checks()

    assert matches
    match = matches[0]
    assert match.rule_id == "configured_data_flow_api_recv_memcpy" or match.rule_id == "configured_data_flow_api_recv_VOS_MemCopy"
    assert match.category == "buffer_overflow"
    assert match.func_name == "api_recv"
    assert match.line_number == 18
    assert "reachableByFlows" in joern.queries[0]
    assert match.evidence[0]["source_kind"] == "user_config:function_intents"


def test_joern_data_flow_match_normalizes_to_bounds_candidate() -> None:
    match = RuleEngine(FakeJoern(), FakeUserConfig()).run_configured_data_flow_checks()[0]
    analyzer = object.__new__(Analyzer)

    candidate = analyzer._joern_rule_match_to_candidate(match, "api_recv")

    assert candidate["candidate_source"] == "joern_cpg"
    assert candidate["defect_class"] == "bounds"
    assert candidate["rule"].startswith("configured_data_flow_api_recv_")
    assert "VOS_MemCopy" in "\n".join(candidate["positive_evidence"])


def test_rule_engine_runs_semantic_cpg_rule_library_with_user_config_sinks() -> None:
    joern = FakeJoern()
    matches = RuleEngine(joern, FakeUserConfig()).run_semantic_cpg_rule_library()

    match = next(item for item in matches if item.rule_id == "joern_semantic_VOS_MemCopy")
    assert match.category == "buffer_overflow"
    assert match.func_name == "api_recv"
    assert match.line_number == 18
    assert match.evidence[0]["query_family"] == "semantic_cpg_rule_library"
    assert match.evidence[0]["query_focus"] == "copy_sink_size_relation"
    assert match.evidence[0]["size_argument"] == "len"
    assert match.evidence[0]["control_context"] == ["if (len <= dst_size)"]
    assert match.evidence[0]["nearest_control_context"] == ["if (len <= dst_size)"]
    assert match.evidence[0]["guard_relation"] == "size_argument_guarded"
    assert match.evidence[0]["strict_control_dependencies"] == ["if (len <= dst_size)"]
    assert match.evidence[0]["dominator_context"] == ["int api_recv(char *src, unsigned len)"]
    assert match.evidence[0]["control_dependency_precision"] == "strict_cpg_control_dependency"
    assert "VOS_MemCopy" in "\n".join(joern.queries)


def test_rule_engine_pair_checks_emit_ownership_lifecycle_evidence() -> None:
    class PairJoern(FakeJoern):
        def query(self, cpgql: str):
            self.queries.append(cpgql)
            if "VOS_MemAlloc" in cpgql and "VOS_MemFree" in cpgql:
                return [{"name": "api_open", "filename": "src/api.c", "lineNumber": 22}]
            return []

    matches = RuleEngine(PairJoern(), FakeUserConfig()).run_paired_function_checks()

    assert matches[0].rule_id == "paired_VOS_MemAlloc_VOS_MemFree"
    assert matches[0].evidence[0]["query_family"] == "paired_ownership_lifecycle"


def test_rule_engine_semantic_sink_query_falls_back_when_nearest_controls_fail() -> None:
    class FallbackJoern(FakeJoern):
        def query(self, cpgql: str):
            self.queries.append(cpgql)
            if "nearestControls" in cpgql:
                raise RuntimeError("unsupported CPG step")
            if "cpg.call.name" in cpgql and "VOS_MemCopy" in cpgql:
                return [
                    {
                        "method": "api_recv",
                        "filename": "src/api.c",
                        "lineNumber": 18,
                        "code": "VOS_MemCopy(dst, src, len)",
                        "callee": "VOS_MemCopy",
                        "arguments": ["dst", "src", "len"],
                        "controls": ["if (len <= dst_size)"],
                    }
                ]
            return []

    joern = FallbackJoern()
    matches = RuleEngine(joern, FakeUserConfig()).run_semantic_cpg_rule_library()
    match = next(item for item in matches if item.rule_id == "joern_semantic_VOS_MemCopy")

    assert match.evidence[0]["guard_relation"] == "size_argument_guarded"
    assert match.evidence[0]["control_dependency_precision"] == "method_control_context"
    assert any("nearestControls" in query for query in joern.queries)


def test_rule_engine_batches_semantic_sink_queries() -> None:
    joern = FakeJoern()
    RuleEngine(joern, FakeUserConfig()).run_semantic_cpg_rule_library()

    sink_queries = [
        query
        for query in joern.queries
        if "cpg.call.name" in query and "arguments" in query and "VOS_MemCopy" in query
    ]
    assert len(sink_queries) == 1
    assert "memcpy" in sink_queries[0]
    assert "VOS_MemCopy" in sink_queries[0]


def test_rule_engine_emits_path_and_allocation_sink_evidence() -> None:
    class ExtraSinkJoern(FakeJoern):
        def query(self, cpgql: str):
            self.queries.append(cpgql)
            if "controlledBy" in cpgql or "dominatedBy" in cpgql:
                return []
            if "cpg.call.name" in cpgql:
                return [
                    {
                        "method": "api_open",
                        "filename": "src/api.c",
                        "lineNumber": 30,
                        "code": "fopen(path, \"r\")",
                        "callee": "fopen",
                        "arguments": ["path", '"r"'],
                        "nearestControls": ["if (path != NULL)"],
                        "controls": ["if (path != NULL)"],
                    },
                    {
                        "method": "api_alloc",
                        "filename": "src/api.c",
                        "lineNumber": 40,
                        "code": "malloc(len)",
                        "callee": "malloc",
                        "arguments": ["len"],
                        "nearestControls": ["if (len < max_len)"],
                        "controls": ["if (len < max_len)"],
                    },
                ]
            return []

    matches = RuleEngine(ExtraSinkJoern(), FakeUserConfig()).run_semantic_cpg_rule_library()
    by_rule = {match.rule_id: match for match in matches}

    assert by_rule["joern_semantic_fopen"].category == "path_traversal"
    assert by_rule["joern_semantic_fopen"].evidence[0]["path_argument"] == "path"
    assert by_rule["joern_semantic_fopen"].evidence[0]["guard_relation"] == "path_argument_guarded"
    assert by_rule["joern_semantic_malloc"].category == "integer_overflow"
    assert by_rule["joern_semantic_malloc"].evidence[0]["allocation_size_argument"] == "len"


def test_rule_engine_emits_operator_rule_evidence() -> None:
    class OperatorJoern(FakeJoern):
        def query(self, cpgql: str):
            self.queries.append(cpgql)
            if "controlledBy" in cpgql or "dominatedBy" in cpgql:
                return [
                    {
                        "method": "api_calc",
                        "lineNumber": 12,
                        "code": "len / divisor",
                        "controlDependencies": ["if (divisor != 0)"],
                        "dominators": ["int api_calc(int len, int divisor, int *p)"],
                    }
                ]
            if "<operator>" in cpgql:
                return [
                    {
                        "method": "api_calc",
                        "filename": "src/api.c",
                        "lineNumber": 12,
                        "code": "len / divisor",
                        "operator": "<operator>.division",
                        "arguments": ["len", "divisor"],
                        "nearestControls": ["if (divisor != 0)"],
                        "controls": ["if (divisor != 0)"],
                    },
                    {
                        "method": "api_calc",
                        "filename": "src/api.c",
                        "lineNumber": 14,
                        "code": "*p",
                        "operator": "<operator>.indirection",
                        "arguments": ["p"],
                        "nearestControls": [],
                        "controls": [],
                    },
                ]
            return []

    matches = RuleEngine(OperatorJoern(), FakeUserConfig()).run_semantic_cpg_rule_library()
    by_rule = {match.rule_id: match for match in matches}

    division = by_rule["joern_operator_division_or_modulo"]
    assert division.category == "integer_overflow"
    assert division.evidence[0]["divisor_argument"] == "divisor"
    assert division.evidence[0]["guard_relation"] == "divisor_guarded"

    deref = by_rule["joern_operator_pointer_dereference"]
    assert deref.category == "null_pointer_dereference"
    assert deref.evidence[0]["pointer_argument"] == "p"
    assert deref.evidence[0]["guard_relation"] == "no_relevant_guard_observed"
