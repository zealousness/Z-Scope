import json
import shutil
from pathlib import Path

import pytest
import yaml

from zscope.config.config import ConfigLoader
from zscope.core.candidates.java_rules import JavaRuleCandidateGenerator
from zscope.retrieval.code_index import CodeIndex
from zscope.rules.engine import RuleEngine

BENCHMARK_ROOT = Path(__file__).resolve().parents[1] / "test" / "java_range"


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_java_range_benchmark_config_uses_unified_java_auto_detection(monkeypatch) -> None:
    config_path = BENCHMARK_ROOT / "zscope.benchmark.yaml"
    raw_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    monkeypatch.setenv("DASHSCOPE_API_KEY", "benchmark-test-key")
    monkeypatch.chdir(BENCHMARK_ROOT.parents[1])
    config = ConfigLoader.load(str(config_path))

    assert "java_profile" not in raw_config["project"]
    assert config.project.language == "java"
    assert config.project.java_profile == "auto"
    assert config.project.project_root == BENCHMARK_ROOT.resolve()
    assert config.project.source_root == BENCHMARK_ROOT.resolve()
    assert config.indexing.backend == "java_unified"
    assert config.indexing.java_structure_frontend == "auto"
    assert config.indexing.java_signal_backends == ["sootup", "wala", "codeql", "joern"]
    assert not (BENCHMARK_ROOT / "zscope.signals.yaml").exists()
    assert config.indexing.java_structure_db_path == ".zscope_knowledge/java_structure.db"
    assert config.analysis.snapshot_dir == "test/java_range/.zscope_snapshots"
    agents = {agent.name: agent for agent in config.project.agents}
    assert {
        "semantic_modeler",
        "vulnerability_analyzer",
        "validator_agent",
        "issue_reconciler_agent",
    } <= set(agents)
    assert agents["vulnerability_analyzer"].enabled is True
    assert "full Java category benchmark" in agents["vulnerability_analyzer"].task


def test_java_range_benchmark_manifest_is_consistent() -> None:
    entries = _load_json(BENCHMARK_ROOT / "benchmark" / "entries.json")
    truth = _load_json(BENCHMARK_ROOT / "benchmark" / "ground_truth.json")

    vulnerabilities = truth["vulnerabilities"]
    assert truth["benchmark"] == "zscope-java-generic"
    assert truth["suite"] == "java_range"
    assert truth["language"] == "java"
    assert truth["required_backend"] == "java_unified"
    assert truth["structure_frontend"] == "spoon"
    assert truth["coverage"]["build"] == "maven"
    assert truth["coverage"]["structure_precision"] == "source_level_exact"


def test_java_preview_structural_baseline_is_explicit_and_non_numeric_for_llm() -> None:
    baseline = _load_json(BENCHMARK_ROOT / "benchmark" / "structural_baseline.json")
    truth = _load_json(BENCHMARK_ROOT / "benchmark" / "ground_truth.json")
    entries = _load_json(BENCHMARK_ROOT / "benchmark" / "entries.json")
    vulnerabilities = truth["vulnerabilities"]

    assert baseline["package_version"] == "1.3.1"
    assert baseline["truth_records"] == len(truth["vulnerabilities"]) == 58
    assert (
        baseline["rule_backed_truth_ids"]
        == len({item["rule_id"] for item in truth["vulnerabilities"]})
        == 49
    )
    assert baseline["entry_functions"] == len(entries["functions"]) == 54
    assert baseline["java_rules"] == len(JavaRuleCandidateGenerator._RULES) == 48
    assert baseline["all_rules_have_fixture_coverage"] is True
    assert baseline["llm_metrics_available"] is False
    assert set(truth["coverage"]["components"]) == {
        "cli",
        "controller",
        "service",
        "mapper",
        "dto",
        "filter",
        "interceptor",
        "config",
        "persistence",
        "parser",
        "crypto",
        "runtime",
        "resource",
    }
    expected_rule_ids = {rule.rule_id for rule in JavaRuleCandidateGenerator._RULES}
    assert set(truth["coverage"]["rule_ids"]) == expected_rule_ids
    assert expected_rule_ids <= {
        rule_id
        for entry in entries["functions"]
        for rule_id in entry.get("covers_rule_ids", [])
        if rule_id.startswith("java_") and rule_id in expected_rule_ids
    }
    assert set(truth["coverage"]["security_categories"]) == {
        rule.defect_class for rule in JavaRuleCandidateGenerator._RULES
    }
    assert expected_rule_ids <= {item["rule_id"] for item in vulnerabilities}
    assert truth["total_vulnerabilities"] == len(vulnerabilities)
    assert len(entries["functions"]) == 54
    assert (BENCHMARK_ROOT / "pom.xml").exists()
    pom_text = (BENCHMARK_ROOT / "pom.xml").read_text(encoding="utf-8")
    for dependency in (
        "spring-boot-starter-web",
        "spring-boot-starter-security",
        "spring-boot-starter-data-jpa",
        "spring-kafka",
        "mybatis",
        "java-jwt",
        "mongodb-driver-sync",
        "jackson-databind",
        "snakeyaml",
        "xstream",
        "fastjson2",
        "freemarker",
        "groovy",
        "mvel2",
        "commons-jexl3",
    ):
        assert dependency in pom_text

    source_files = {
        path.relative_to(BENCHMARK_ROOT).as_posix()
        for path in (BENCHMARK_ROOT / "src" / "main" / "java").rglob("*.java")
    }
    entry_files = {entry["file_path"] for entry in entries["functions"]}
    truth_files = {item["file"] for item in vulnerabilities}

    assert entry_files <= source_files
    assert truth_files <= source_files

    for item in vulnerabilities:
        lines = (BENCHMARK_ROOT / item["file"]).read_text(encoding="utf-8").splitlines()
        assert 1 <= int(item["line"]) <= len(lines)
        assert int(item["line"]) <= int(item["end_line"]) <= len(lines)


def test_java_range_benchmark_fixture_covers_all_java_local_rules() -> None:
    generator = JavaRuleCandidateGenerator()
    seen_rule_ids = set()
    for path in (BENCHMARK_ROOT / "src" / "main" / "java").rglob("*.java"):
        relative_path = path.relative_to(BENCHMARK_ROOT).as_posix()
        text = "\n".join(
            f"{line_number} | {line}"
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            )
        )
        for issue in generator.generate_issues(
            f"<project-file>:{relative_path}",
            text,
            relative_path,
        ):
            seen_rule_ids.add(issue["rule"])

    assert seen_rule_ids == {rule.rule_id for rule in JavaRuleCandidateGenerator._RULES}


def test_java_range_benchmark_exercises_generic_entry_to_sink_flows() -> None:
    class SourceOnlyJoern:
        source_path = str(BENCHMARK_ROOT)

        def query(self, _cpgql: str):
            return []

    matches = RuleEngine(SourceOnlyJoern()).run_java_framework_data_flow_checks()
    rule_ids = {match.rule_id for match in matches}

    assert "java_source_entry_cross_layer_flow_command_injection" in rule_ids
    assert "java_source_entry_cross_layer_flow_path_traversal" in rule_ids
    assert "java_source_entry_cross_layer_flow_unsafe_deserialization" in rule_ids


@pytest.mark.skipif(
    shutil.which("mvn") is None or shutil.which("java") is None,
    reason="formal Java structure benchmark requires Maven and Java",
)
def test_java_range_benchmark_indexes_with_maven_spoon_structure(monkeypatch) -> None:
    config_path = BENCHMARK_ROOT / "zscope.benchmark.yaml"

    monkeypatch.setenv("DASHSCOPE_API_KEY", "benchmark-test-key")
    monkeypatch.chdir(BENCHMARK_ROOT.parents[1])
    config = ConfigLoader.load(str(config_path))

    code_index = CodeIndex(
        config.project.project_root,
        config.project.compile_commands_path,
        source_root=config.project.source_root,
        indexing_config=config.indexing,
        wait_for_cpg=True,
    )
    try:
        functions = code_index.list_functions(limit=1000)
        entries = _load_json(BENCHMARK_ROOT / "benchmark" / "entries.json")["functions"]
        missing = [
            entry["function_name"]
            for entry in entries
            if code_index.get_function_impl(entry["function_name"], warn_missing=False) is None
        ]
        assert not missing

        cli_main = code_index.get_function_impl(
            "com.zscope.cli.CliApp.main:void(java.lang.String[])",
            warn_missing=False,
        )
        library_load = code_index.get_function_impl(
            "com.zscope.cli.LibraryApi.load:java.lang.String(java.lang.String)",
            warn_missing=False,
        )
        controller_search = code_index.get_function_impl(
            "com.zscope.web.controller.UserController.search:java.util.List(java.lang.String)",
            warn_missing=False,
        )
        mapper_search = code_index.get_function_impl(
            "com.zscope.web.mapper.UserMapper.findByNameUnsafe:java.util.List(java.lang.String)",
            warn_missing=False,
        )
        dto_get_name = code_index.get_function_impl(
            "com.zscope.web.dto.UserDto.getName:java.lang.String()",
            warn_missing=False,
        )
        filter_entry = code_index.get_function_impl(
            "com.zscope.web.filter.JwtBypassFilter.doFilter:void(jakarta.servlet.ServletRequest,jakarta.servlet.ServletResponse,jakarta.servlet.FilterChain)",
            warn_missing=False,
        )
        interceptor_entry = code_index.get_function_impl(
            "com.zscope.web.interceptor.AdminInterceptor.preHandle:boolean(jakarta.servlet.http.HttpServletRequest,jakarta.servlet.http.HttpServletResponse,java.lang.Object)",
            warn_missing=False,
        )
        assert cli_main is not None
        assert library_load is not None
        assert controller_search is not None
        assert mapper_search is not None
        assert dto_get_name is not None
        assert filter_entry is not None
        assert interceptor_entry is not None
        assert (
            code_index.get_function_impl(
                "com.zscope.persistence.PersistenceEntry.jdbcSearch:java.sql.ResultSet(java.sql.Statement,java.lang.String)",
                warn_missing=False,
            )
            is not None
        )
        assert (
            code_index.get_function_impl(
                "com.zscope.parser.ParserEntry.thirdPartyDeserialize:java.lang.Object(java.lang.String)",
                warn_missing=False,
            )
            is not None
        )
        assert (
            code_index.get_function_impl(
                "com.zscope.crypto.CryptoEntry.trustAllHostname:void(javax.net.ssl.HttpsURLConnection)",
                warn_missing=False,
            )
            is not None
        )
        assert (
            code_index.get_function_impl(
                "com.zscope.runtime.RuntimeEntry.loadPlugin:java.lang.Class(java.net.URL[],java.lang.String)",
                warn_missing=False,
            )
            is not None
        )
        assert (
            code_index.get_function_impl(
                "com.zscope.resource.ResourceEntry.cache:java.util.Map(java.lang.String,java.lang.String)",
                warn_missing=False,
            )
            is not None
        )
        backend = getattr(code_index, "_backend", None)
        structure = getattr(backend, "structure_backend", backend)
        cli_main_metadata = structure.get_method(
            "com.zscope.cli.CliApp.main:void(java.lang.String[])"
        )
        library_load_metadata = structure.get_method(
            "com.zscope.cli.LibraryApi.load:java.lang.String(java.lang.String)"
        )
        controller_metadata = structure.get_method(
            "com.zscope.web.controller.UserController.search:java.util.List(java.lang.String)"
        )
        dto_metadata = structure.get_method("com.zscope.web.dto.UserDto.getName:java.lang.String()")
        assert cli_main_metadata["structure_frontend"] == "spoon"
        assert cli_main_metadata["structure_frontend_actual"] == "spoon"
        assert cli_main_metadata["structure_frontend_attempts"][0]["frontend"] == "spoon"
        assert cli_main_metadata["structure_frontend_attempts"][0]["status"] == "success"
        assert cli_main_metadata["structure_precision"] == "source_level_exact"
        assert library_load_metadata["structure_precision"] == "source_level_exact"
        assert dto_metadata["structure_precision"] == "source_level_exact"
        assert controller_metadata["framework_semantics"]["entry"]["is_entry"] is True

        callees = code_index.get_callees(
            "com.zscope.cli.LibraryApi.load:java.lang.String(java.lang.String)"
        )
        assert any("Loader.read" in str(row.get("fullName") or "") for row in callees)
        web_callees = code_index.get_callees(
            "com.zscope.web.controller.UserController.search:java.util.List(java.lang.String)"
        )
        assert any("UserService.search" in str(row.get("fullName") or "") for row in web_callees)

        structure_db = getattr(structure, "structure_db", None)
        assert structure_db is not None
        assert structure_db.class_count() >= 21
        assert structure_db.method_count() >= 80
        assert structure_db.list_call_edges()
        assert functions
    finally:
        code_index.close()
