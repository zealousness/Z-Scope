import threading
from pathlib import Path
from types import SimpleNamespace

from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.java_rules import JavaRuleCandidateGenerator
from zscope.orchestration.specs import SpecRegistry


class FakeCodeIndex:
    backend_name = "joern"
    language = "java"


class FakeJavaActiveAuditCodeIndex:
    backend_name = "java_unified"
    language = "java"

    def __init__(self, methods):
        self.methods = methods

    def find_java_methods_by_tokens(self, tokens, limit=8):
        compact_tokens = [
            "".join(ch for ch in str(token).lower() if ch.isalnum()) for token in tokens
        ]
        rows = []
        for name, impl in self.methods.items():
            haystack = "".join(
                ch
                for ch in " ".join([name, impl.get("file", ""), impl.get("code", "")]).lower()
                if ch.isalnum()
            )
            if any(token and token in haystack for token in compact_tokens):
                rows.append(
                    {
                        "qualified_name": name,
                        "name": name.rsplit(".", 1)[-1],
                        "file": impl["file"],
                        "start_line": impl.get("start_line", 1),
                        "language": "java",
                    }
                )
        return rows[:limit]

    def get_function_impl(self, func_name, *args, **kwargs):
        return self.methods.get(func_name)


def test_analyzer_uses_java_local_rules_for_java_project(monkeypatch) -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(language="java"),
    )
    analyzer.code_index = FakeCodeIndex()

    monkeypatch.setattr(analyzer, "_candidate_backend_profile", lambda: "joern")
    monkeypatch.setattr(
        analyzer,
        "_direct_callee_rule_scan_budget",
        lambda state: {
            "limit": 0,
            "max_depth": 0,
            "total_limit": 0,
        },
    )
    monkeypatch.setattr(
        analyzer, "_detect_direct_callee_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        analyzer, "_detect_java_project_file_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(analyzer, "_annotate_candidate_issues", lambda issues, **kwargs: issues)

    issues = analyzer._detect_local_rule_candidates(
        {
            "entry_func": "demo.App.handle:void(java.lang.String)",
            "impl_result": {
                "code": "1 | Runtime.getRuntime().exec(input);",
                "file": "src/main/java/demo/App.java",
            },
        }
    )

    assert len(issues) == 1
    assert issues[0]["candidate_source"] == "java_local_rule"
    assert issues[0]["defect_class"] == "command_injection"


def test_analyzer_uses_java_annotation_metadata_for_declarations(monkeypatch) -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(language="java"),
    )
    analyzer.code_index = FakeCodeIndex()

    monkeypatch.setattr(analyzer, "_candidate_backend_profile", lambda: "joern")
    monkeypatch.setattr(
        analyzer,
        "_direct_callee_rule_scan_budget",
        lambda state: {
            "limit": 0,
            "max_depth": 0,
            "total_limit": 0,
        },
    )
    monkeypatch.setattr(
        analyzer, "_detect_direct_callee_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        analyzer, "_detect_java_project_file_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(analyzer, "_annotate_candidate_issues", lambda issues, **kwargs: issues)

    issues = analyzer._detect_local_rule_candidates(
        {
            "entry_func": "com.example.UserMapper.findBySort:java.lang.Object(java.lang.String)",
            "impl_result": {
                "code": "7 | Object findBySort(String sort);",
                "file": "src/main/java/com/example/UserMapper.java",
                "declaration_only": True,
                "annotations": [
                    {
                        "name": "Select",
                        "code": '@Select("select * from users order by ${sort}")',
                        "lineNumber": 6,
                    }
                ],
            },
        }
    )

    assert len(issues) == 1
    assert issues[0]["rule"] == "java_mybatis_dollar_substitution"
    assert issues[0]["location"].endswith("UserMapper.java:6")


def test_analyzer_attaches_java_static_field_candidate_to_touching_entry(monkeypatch) -> None:
    analyzer = object.__new__(Analyzer)
    project_root = Path(__file__).resolve().parents[1] / "test/java_range"
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            language="java",
            project_root=project_root,
            source_root=project_root,
        ),
    )
    analyzer.code_index = FakeCodeIndex()

    monkeypatch.setattr(analyzer, "_candidate_backend_profile", lambda: "joern")
    monkeypatch.setattr(
        analyzer,
        "_direct_callee_rule_scan_budget",
        lambda state: {
            "limit": 0,
            "max_depth": 0,
            "total_limit": 0,
        },
    )
    monkeypatch.setattr(
        analyzer, "_detect_direct_callee_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        analyzer, "_detect_java_project_file_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(analyzer, "_annotate_candidate_issues", lambda issues, **kwargs: issues)

    issues = analyzer._detect_local_rule_candidates(
        {
            "entry_func": "com.zscope.resource.ResourceEntry.cache:java.util.Map(java.lang.String,java.lang.String)",
            "impl_result": {
                "code": (
                    "36 | public Map<String, String> cache(String key, String value) {\n"
                    "37 |   sharedCache.put(key, value);\n"
                    "38 |   return sharedCache;\n"
                    "39 | }"
                ),
                "file": "src/main/java/com/zscope/resource/ResourceEntry.java",
                "start_line": 36,
                "end_line": 39,
            },
        }
    )

    issue = next(item for item in issues if item["rule"] == "java_shared_mutable_static_state")
    assert issue["defect_class"] == "concurrency_race"
    assert issue["location"].endswith("ResourceEntry.java:14")
    assert issue["evidence_pack"]["source"]["line"] == 14
    assert issue["evidence_pack"]["sink"]["line"] == 37
    assert issue["evidence_pack"]["path"]["field_level_evidence"] is True


def test_analyzer_recovers_cors_annotation_from_framework_semantics(monkeypatch) -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(language="java"),
    )
    analyzer.code_index = FakeCodeIndex()

    monkeypatch.setattr(analyzer, "_candidate_backend_profile", lambda: "joern")
    monkeypatch.setattr(
        analyzer,
        "_direct_callee_rule_scan_budget",
        lambda state: {
            "limit": 0,
            "max_depth": 0,
            "total_limit": 0,
        },
    )
    monkeypatch.setattr(
        analyzer, "_detect_direct_callee_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        analyzer, "_detect_java_project_file_rule_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(analyzer, "_annotate_candidate_issues", lambda issues, **kwargs: issues)

    issues = analyzer._detect_local_rule_candidates(
        {
            "entry_func": "com.zscope.web.controller.SecuritySurfaceController.cors:java.lang.String(java.lang.String)",
            "impl_result": {
                "code": "31 | public String cors(String name) {\n32 |   return name;\n33 | }",
                "file": "src/main/java/com/zscope/web/controller/SecuritySurfaceController.java",
                "start_line": 31,
                "framework_semantics": {
                    "security_policies": [
                        {
                            "kind": "cors",
                            "allowed_origins": ["*"],
                            "line": 29,
                        }
                    ]
                },
            },
        }
    )

    assert any(issue["rule"] == "java_cors_wildcard" for issue in issues)
    cors = next(issue for issue in issues if issue["rule"] == "java_cors_wildcard")
    assert cors["location"].endswith("SecuritySurfaceController.java:29")
    assert cors["defect_class"] == "cors_misconfiguration"


def test_analyzer_scans_java_auxiliary_mapper_files(tmp_path) -> None:
    interface = tmp_path / "src/main/java/demo/UserMapper.java"
    interface.parent.mkdir(parents=True)
    interface.write_text(
        "package demo;\n"
        "\n"
        "public interface UserMapper {\n"
        "  Object findBySort(String sort);\n"
        "}\n",
        encoding="utf-8",
    )
    mapper = tmp_path / "src/main/resources/mappers/UserMapper.xml"
    mapper.parent.mkdir(parents=True)
    mapper.write_text(
        '<mapper namespace="demo.UserMapper">\n'
        '  <select id="findBySort">select * from users order by ${sort}</select>\n'
        "</mapper>\n",
        encoding="utf-8",
    )
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path, source_root=tmp_path),
    )
    analyzer._java_project_file_rule_cache = None
    analyzer._java_project_file_rule_cache_lock = threading.RLock()

    issues = analyzer._detect_java_project_file_rule_candidates(JavaRuleCandidateGenerator())

    assert any(issue["rule"] == "java_mybatis_dollar_substitution" for issue in issues)
    assert any(issue["location"].endswith("UserMapper.xml:2") for issue in issues)
    xml_issue = next(
        issue for issue in issues if issue["rule"] == "java_mybatis_dollar_substitution"
    )
    binding = xml_issue["mybatis_xml_binding"]
    assert xml_issue["function"] == "demo.UserMapper.findBySort"
    assert (
        xml_issue["secondary_function"]
        == "<project-file>:src/main/resources/mappers/UserMapper.xml"
    )
    assert binding["interface"] == "demo.UserMapper"
    assert binding["interface_file"] == "src/main/java/demo/UserMapper.java"
    assert binding["parameters"] == ["sort"]
    assert binding["bound_variables"] == ["sort"]
    assert binding["binding_precision"] == "xml_namespace_id_parameter_match"
    assert xml_issue["evidence_pack"]["mybatis_xml_binding"] == binding
    project_file_issue = next(
        issue for issue in issues if issue["rule"] == "java_mybatis_xml_project_text_substitution"
    )
    assert (
        project_file_issue["function"] == "<project-file>:src/main/resources/mappers/UserMapper.xml"
    )
    assert project_file_issue["secondary_function"] == "demo.UserMapper.findBySort"
    assert project_file_issue["location"].endswith("UserMapper.xml:2")
    assert project_file_issue["evidence_pack"]["path"]["complete_in_function"] is True
    assert project_file_issue["entry_agnostic"] is True
    assert project_file_issue["project_file_scope"] is True

    second_pass = analyzer._detect_java_project_file_rule_candidates(JavaRuleCandidateGenerator())
    assert second_pass == []


def test_analyzer_scans_java_annotation_mapper_files(tmp_path) -> None:
    interface = tmp_path / "src/main/java/demo/UserMapper.java"
    interface.parent.mkdir(parents=True)
    interface.write_text(
        "package demo;\n"
        "\n"
        "import org.apache.ibatis.annotations.Param;\n"
        "import org.apache.ibatis.annotations.Select;\n"
        "\n"
        "public interface UserMapper {\n"
        "  @Select(\"SELECT id, name FROM users WHERE name = '${name}'\")\n"
        '  Object findByNameUnsafe(@Param("name") String name);\n'
        "}\n",
        encoding="utf-8",
    )
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path, source_root=tmp_path),
    )
    analyzer._java_project_file_rule_cache = None
    analyzer._java_project_file_rule_cache_lock = threading.RLock()

    issues = analyzer._detect_java_project_file_rule_candidates(JavaRuleCandidateGenerator())

    issue = next(issue for issue in issues if issue["rule"] == "java_mybatis_dollar_substitution")
    assert issue["function"] == "demo.UserMapper.findByNameUnsafe"
    assert issue["location"].endswith("UserMapper.java:7")
    assert issue["defect_class"] == "sql_injection"
    assert issue["evidence_pack"]["source"]["kind"] == "mybatis_annotation_mapper_parameter"
    assert issue["evidence_pack"]["sink"]["line"] == 7


def test_analyzer_scans_java_properties_for_project_file_secrets(tmp_path) -> None:
    props = tmp_path / "src/main/resources/application.properties"
    props.parent.mkdir(parents=True)
    props.write_text(
        "external.service.token=1234567890abcdef\n" "cors.allowed-origins=*\n",
        encoding="utf-8",
    )
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path, source_root=tmp_path),
    )
    analyzer._java_project_file_rule_cache = None
    analyzer._java_project_file_rule_cache_lock = threading.RLock()

    issues = analyzer._detect_java_project_file_rule_candidates(JavaRuleCandidateGenerator())

    secret = next(issue for issue in issues if issue["defect_class"] == "secret_exposure")
    assert secret["function"] == "<project-file>:src/main/resources/application.properties"
    assert secret["location"].endswith("application.properties:1")
    assert secret["evidence_pack"]["source"]["kind"] == "java_project_secret_literal"
    assert secret["entry_agnostic"] is True


class FakeSkill:
    def __init__(self, name: str) -> None:
        self.name = name
        self.languages = ["java"] if name.startswith("java_") else ["c_cpp"]


class FakeSpecRegistry:
    names = [
        "bounds_and_integer",
        "resource_lifecycle",
        "java_injection",
        "java_web_security",
    ]

    def __init__(self) -> None:
        self.skills = {name: FakeSkill(name) for name in self.names}

    def get_skill(self, name: str):
        return self.skills.get(name)


class FakeFullJavaSpecRegistry(FakeSpecRegistry):
    names = [
        "bounds_and_integer",
        "resource_lifecycle",
        "java_injection",
        "java_web_security",
        "java_deserialization",
        "java_authz",
        "java_crypto",
        "java_resource_lifecycle",
        "java_concurrency",
    ]


def test_java_project_filters_candidate_skills_to_java_family() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(project=SimpleNamespace(language="java"))
    analyzer.spec_registry = FakeSpecRegistry()

    selection = analyzer._candidate_first_skill_selection([])

    assert selection.restricted is False
    assert selection.skills == ["java_injection", "java_web_security"]


def test_java_security_task_can_activate_all_java_skills() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(project=SimpleNamespace(language="java"))
    analyzer.spec_registry = FakeFullJavaSpecRegistry()

    selection = analyzer._candidate_first_skill_selection([])

    assert selection.skills == [
        "java_injection",
        "java_web_security",
        "java_deserialization",
        "java_authz",
        "java_crypto",
        "java_resource_lifecycle",
        "java_concurrency",
    ]


def test_java_empty_task_activates_every_language_scoped_analysis_skill() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(project=SimpleNamespace(language="java"))
    analyzer.spec_registry = SpecRegistry()

    selection = analyzer._candidate_first_skill_selection([])

    assert selection.restricted is False
    assert selection.skills == [
        "java_authz",
        "java_concurrency",
        "java_crypto",
        "java_deserialization",
        "java_injection",
        "java_resource_lifecycle",
        "java_web_security",
    ]


def test_c_project_filters_out_java_analysis_skills() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(project=SimpleNamespace(language="c_cpp"))
    analyzer.spec_registry = FakeSpecRegistry()

    selection = analyzer._candidate_first_skill_selection([])

    assert selection.restricted is False
    assert selection.skills == ["bounds_and_integer", "resource_lifecycle"]


def test_analyzer_builds_java_active_audit_context() -> None:
    analyzer = object.__new__(Analyzer)
    impl = {
        "qualified_name": "com.zscope.web.UserController.deleteUser:void(java.lang.String)",
        "file": "src/main/java/com/zscope/web/UserController.java",
        "structure_frontend_actual": "spoon",
        "structure_precision": "source_level_exact",
        "annotations": [{"name": "DeleteMapping", "code": '@DeleteMapping("/users/{id}")'}],
        "class_annotations": [{"name": "RestController"}],
        "framework_semantics": {
            "sources": [{"kind": "path_variable", "name": "id"}],
            "guards": [{"kind": "preauthorize", "code": "@PreAuthorize"}],
            "security_policies": [{"kind": "route_authz"}],
        },
        "callees": [
            {"name": "com.zscope.web.UserService.deleteUser:void(java.lang.String)", "line": 17},
            {"name": "java.util.Objects.requireNonNull"},
        ],
    }

    context = analyzer._build_java_active_audit_context(
        {"entry_func": impl["qualified_name"], "impl_result": impl},
        active_skills=["java_authz", "java_web_security"],
        candidate_signal_summary={"java_local_rule": 1},
        candidate_signals=[
            {
                "id": "JAVA_RULE_AUTHZ",
                "candidate_source": "java_local_rule",
                "defect_class": "authz_bypass",
            }
        ],
    )

    assert context["language"] == "java"
    assert context["structure_frontend_actual"] == "spoon"
    assert context["entry_kind"] == "controller"
    assert context["component"] == "controller"
    assert context["framework_sources"][0]["kind"] == "path_variable"
    assert context["reachable_callees"][0]["name"].endswith(
        "UserService.deleteUser:void(java.lang.String)"
    )
    assert context["review_policy"].startswith("LLM-only Java active findings")


def test_analyzer_marks_llm_only_java_issue_as_active_review_observation() -> None:
    analyzer = object.__new__(Analyzer)
    issue = {
        "id": "ISSUE_ACTIVE_AUTHZ",
        "category": "authz_bypass",
        "function": "deleteUser",
        "description": "Controller deletes a user without object ownership check.",
        "source": "@PathVariable id",
        "sink": "userRepository.deleteById(id)",
    }

    normalized = analyzer._normalize_java_active_audit_issues(
        [issue],
        {
            "entry_func": "com.zscope.web.UserController.deleteUser:void(java.lang.String)",
            "impl_result": {"file": "src/main/java/com/zscope/web/UserController.java"},
        },
        candidate_signals=[],
    )

    assert normalized[0]["candidate_source"] == "java_llm_active_audit"
    assert normalized[0]["finding_kind"] == "java_active_audit_observation"
    assert normalized[0]["active_audit_review_only"] is True
    assert normalized[0]["language"] == "java"
    assert normalized[0]["evidence_pack"]["active_audit_review_only"] is True


def test_analyzer_normalizes_java_active_audit_category_and_location() -> None:
    analyzer = object.__new__(Analyzer)
    issue = {
        "id": "ISSUE_ACTIVE_CORS",
        "category": "security",
        "function": "cors",
        "location": "securitysurfacecontroller.java:29",
        "description": '@CrossOrigin("*") allows wildcard CORS origins.',
    }

    normalized = analyzer._normalize_java_active_audit_issues(
        [issue],
        {
            "entry_func": "com.zscope.web.controller.SecuritySurfaceController.cors:java.lang.String(java.lang.String)",
            "impl_result": {
                "file": "src/main/java/com/zscope/web/controller/SecuritySurfaceController.java",
            },
        },
        candidate_signals=[],
    )

    assert normalized[0]["category"] == "cors_misconfiguration"
    assert normalized[0]["defect_class"] == "cors_misconfiguration"
    assert (
        normalized[0]["file"].lower()
        == "src/main/java/com/zscope/web/controller/securitysurfacecontroller.java"
    )
    assert (
        normalized[0]["location"].lower()
        == "src/main/java/com/zscope/web/controller/securitysurfacecontroller.java:29"
    )


def test_analyzer_normalizes_java_active_audit_field_categories_and_lines() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeJavaActiveAuditCodeIndex({})
    issues = [
        {
            "id": "ISSUE_ACTIVE_SECRET",
            "category": "weak_crypto",
            "function": "hardcodedSecret",
            "description": "CryptoEntry hardcodedSecret returns apiKey = 1234567890abcdef.",
            "evidence_pack": {
                "sink": {"file": "src/main/java/example/security/TokenKeys.java", "line": 13}
            },
        },
        {
            "id": "ISSUE_ACTIVE_RACE",
            "category": "race_condition",
            "function": "cache",
            "description": "ResourceEntry sharedCache static HashMap is mutated via sharedCache.put.",
            "evidence_pack": {
                "sink": {"file": "src/main/java/example/runtime/CacheApi.java", "line": 14}
            },
        },
        {
            "id": "ISSUE_ACTIVE_LEAK",
            "category": "stream_not_closed",
            "function": "leakFile",
            "description": "ResourceEntry.leakFile creates a FileInputStream that is not closed.",
            "evidence_pack": {
                "sink": {"file": "src/main/java/example/runtime/FileApi.java", "line": 17}
            },
        },
    ]

    normalized = analyzer._normalize_java_active_audit_issues(
        issues,
        {
            "entry_func": "com.zscope.resource.ResourceEntry.cache:java.util.Map(java.lang.String,java.lang.String)",
            "impl_result": {"file": "src/main/java/com/zscope/resource/ResourceEntry.java"},
        },
        candidate_signals=[],
    )

    by_id = {issue["id"]: issue for issue in normalized}
    assert by_id["ISSUE_ACTIVE_SECRET"]["category"] == "secret_exposure"
    assert (
        by_id["ISSUE_ACTIVE_SECRET"]["location"]
        == "src/main/java/example/security/TokenKeys.java:13"
    )
    assert by_id["ISSUE_ACTIVE_RACE"]["category"] == "concurrency_race"
    assert (
        by_id["ISSUE_ACTIVE_RACE"]["location"] == "src/main/java/example/runtime/CacheApi.java:14"
    )
    assert by_id["ISSUE_ACTIVE_LEAK"]["category"] == "resource_leak"
    assert by_id["ISSUE_ACTIVE_LEAK"]["location"] == "src/main/java/example/runtime/FileApi.java:17"


def test_analyzer_normalizes_java_active_audit_by_generic_code_index() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeJavaActiveAuditCodeIndex(
        {
            "acme.demo.PersistenceEndpoint.search:java.lang.Object(java.lang.String)": {
                "file": "src/main/java/acme/demo/PersistenceEndpoint.java",
                "start_line": 40,
                "code": (
                    "40 | public Object search(String name) throws Exception {\n"
                    '41 |   String sql = "SELECT * FROM users WHERE name=\'" + name + "\'";\n'
                    "42 |   PreparedStatement stmt = connection.prepareStatement(sql);\n"
                    "43 |   return stmt.executeQuery();\n"
                    "44 | }\n"
                ),
            },
            "acme.demo.XmlEndpoint.parse:java.lang.Object(java.lang.String)": {
                "file": "src/main/java/acme/demo/XmlEndpoint.java",
                "start_line": 80,
                "code": (
                    "80 | public Object parse(String payload) throws Exception {\n"
                    "81 |   XMLReader reader = XMLReaderFactory.createXMLReader();\n"
                    "82 |   reader.parse(new InputSource(new StringReader(payload)));\n"
                    "83 |   return null;\n"
                    "84 | }\n"
                ),
            },
            "acme.demo.BeanEndpoint.decode:java.lang.Object(java.lang.String)": {
                "file": "src/main/java/acme/demo/BeanEndpoint.java",
                "start_line": 120,
                "code": (
                    "120 | public Object decode(String payload) {\n"
                    "121 |   return new java.beans.XMLDecoder(new ByteArrayInputStream(payload.getBytes())).readObject();\n"
                    "122 | }\n"
                ),
            },
            "acme.demo.HtmlEndpoint.echo:java.lang.String(java.lang.String)": {
                "file": "src/main/java/acme/demo/HtmlEndpoint.java",
                "start_line": 150,
                "code": (
                    "150 | public String echo(String payload) {\n"
                    "151 |   return payload;\n"
                    "152 | }\n"
                ),
            },
        }
    )
    issues = [
        {
            "id": "ACTIVE_JDBC",
            "category": "security",
            "function": "search",
            "description": "PersistenceEndpoint uses prepareStatement(sql) after concatenating SQL injection input.",
        },
        {
            "id": "ACTIVE_XXE",
            "category": "security",
            "function": "parse",
            "description": "XmlEndpoint creates XMLReaderFactory and parses external entity XML.",
        },
        {
            "id": "ACTIVE_XMLDECODER",
            "category": "security",
            "function": "decode",
            "description": "BeanEndpoint calls XMLDecoder.readObject on attacker payload.",
        },
        {
            "id": "ACTIVE_XSS",
            "category": "security",
            "function": "echo",
            "description": "HtmlEndpoint returns payload directly, causing reflected XSS.",
        },
    ]

    normalized = analyzer._normalize_java_active_audit_issues(
        issues,
        {
            "entry_func": "acme.demo.PersistenceEndpoint.search:java.lang.Object(java.lang.String)",
            "impl_result": {
                "file": "src/main/java/acme/demo/PersistenceEndpoint.java",
            },
        },
        candidate_signals=[],
    )

    by_id = {issue["id"]: issue for issue in normalized}
    assert by_id["ACTIVE_JDBC"]["category"] == "sql_injection"
    assert by_id["ACTIVE_JDBC"]["rule"] == "java_jdbc_fake_prepared_statement"
    assert by_id["ACTIVE_JDBC"]["location"] == "src/main/java/acme/demo/PersistenceEndpoint.java:42"
    assert by_id["ACTIVE_XXE"]["category"] == "xxe"
    assert by_id["ACTIVE_XXE"]["rule"] == "java_xxe_factory"
    assert by_id["ACTIVE_XXE"]["location"] == "src/main/java/acme/demo/XmlEndpoint.java:81"
    assert by_id["ACTIVE_XMLDECODER"]["category"] == "unsafe_deserialization"
    assert by_id["ACTIVE_XMLDECODER"]["rule"] == "java_xmldecoder_readobject"
    assert by_id["ACTIVE_XMLDECODER"]["location"] == "src/main/java/acme/demo/BeanEndpoint.java:121"
    assert by_id["ACTIVE_XSS"]["category"] == "xss"
    assert by_id["ACTIVE_XSS"]["rule"] == "java_reflected_xss_response_body"
    assert by_id["ACTIVE_XSS"]["location"] == "src/main/java/acme/demo/HtmlEndpoint.java:151"


def test_java_runtime_normalization_has_no_benchmark_coordinate_literals() -> None:
    root = Path(__file__).resolve().parents[1]
    runtime_files = [
        root / "zscope/core/analysis/analyzer.py",
        root / "zscope/core/candidates/java_active_audit.py",
        root / "zscope/retrieval/code_index.py",
    ]
    forbidden = (
        "JavaSecLab",
        "top/whgojp",
        "JdbcController",
        "XXEController",
        "XMLDecoderController",
        "ReflectController",
        "StoreController",
        "application-prod.yml",
        "application-dev.yml",
        "application-docker.yml",
    )
    text = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)

    assert not any(marker in text for marker in forbidden)
