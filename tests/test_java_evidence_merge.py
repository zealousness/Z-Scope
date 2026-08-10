from types import SimpleNamespace

from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.java_evidence import (
    java_candidate_dedup_key,
    merge_java_evidence_candidates,
    normalize_java_candidate,
)


def _java_local_path_candidate() -> dict:
    return {
        "id": "JAVA_RULE_PATH_TRAVERSAL",
        "candidate_id": "JAVA_RULE_PATH_TRAVERSAL",
        "candidate_source": "java_local_rule",
        "evidence_checker": "java_local_rule_checker",
        "function": "read",
        "location": "src/main/java/com/zscope/cli/Loader.java:8",
        "category": "path_traversal",
        "subcategory": "path_traversal",
        "defect_class": "path_traversal",
        "rule": "java_path_traversal_file_api",
        "source": "method parameter path",
        "sink": "Files.readString(Paths.get(path))",
        "positive_evidence": ["local Java file API rule matched"],
        "evidence_pack": {
            "language": "java",
            "candidate_source": "java_local_rule",
            "defect_class": "path_traversal",
            "rule": "java_path_traversal_file_api",
            "source": {
                "expression": "method parameter path",
                "line": 8,
                "file": "src/main/java/com/zscope/cli/Loader.java",
            },
            "sink": {
                "operation": "Files.readString(Paths.get(path))",
                "line": 8,
                "file": "src/main/java/com/zscope/cli/Loader.java",
            },
            "path": {"function": "read", "complete_in_function": False},
        },
    }


def _joern_path_candidate() -> dict:
    return {
        "id": "JOERN_PATH_TRAVERSAL",
        "candidate_id": "JOERN_PATH_TRAVERSAL",
        "candidate_source": "joern_cpg",
        "function": "com.zscope.cli.Loader.read",
        "location": "src/main/java/com/zscope/cli/Loader.java:8",
        "category": "path_traversal",
        "subcategory": "path_traversal",
        "defect_class": "path_traversal",
        "rule": "java_source_entry_cross_layer_flow_path_traversal",
        "source": "LibraryApi.load public parameter path",
        "sink": "return Files.readString(Paths.get(path));",
        "positive_evidence": ["Joern entry flow matched"],
        "evidence_pack": {
            "candidate_source": "joern_cpg",
            "defect_class": "path_traversal",
            "rule": "java_source_entry_cross_layer_flow_path_traversal",
            "source": {
                "expression": "Java entry source reaches path sink",
                "file": "src/main/java/com/zscope/cli/Loader.java",
                "line": 8,
            },
            "sink": {
                "operation": "return Files.readString(Paths.get(path));",
                "file": "src/main/java/com/zscope/cli/Loader.java",
                "line": 8,
            },
            "path": {
                "function": "com.zscope.cli.Loader.read",
                "entry_function": "com.zscope.cli.LibraryApi.load:java.lang.String(java.lang.String)",
                "complete_in_function": False,
            },
        },
    }


def test_normalize_java_candidate_adds_standard_evidence_fields() -> None:
    candidate = normalize_java_candidate(_java_local_path_candidate())

    assert candidate["language"] == "java"
    assert candidate["validation_required"] is True
    assert candidate["evidence_pack"]["language"] == "java"
    assert candidate["evidence_pack"]["source"]["kind"].startswith("java_")
    assert candidate["evidence_pack"]["sink"]["kind"] == "java_file_access"
    assert candidate["evidence_pack"]["source_sink_summary"]["sink_kind"] == "java_file_access"
    assert "framework_edges" in candidate["evidence_pack"]
    assert "root_cause_key" in candidate["evidence_pack"]
    assert candidate["dedup_key"] == java_candidate_dedup_key(candidate)


def test_normalize_java_candidate_drops_unknown_short_file_alias() -> None:
    candidate = normalize_java_candidate(
        {
            "id": "JAVA_THREADLOCAL",
            "candidate_source": "java_local_rule",
            "function": "afterCompletion",
            "file": "refreshtokeninterceptor.p",
            "line": 55,
            "category": "thread_local_leak",
            "description": "ThreadLocal UserHolder removeUser 未清理 afterCompletion",
            "evidence_pack": {
                "language": "java",
                "sink": {"operation": "UserHolder ThreadLocal missing remove"},
            },
        }
    )

    assert candidate["evidence_pack"]["source_sink_summary"]["file"] == ""


def test_normalize_java_candidate_marks_file_permission_sink_kind() -> None:
    candidate = normalize_java_candidate(
        {
            "id": "JAVA_RULE_FILE_PERMISSION",
            "candidate_source": "java_local_rule",
            "function": "makeShared",
            "location": "src/main/java/com/example/PermissionTool.java:4",
            "category": "insecure_file_permission",
            "subcategory": "insecure_file_permission",
            "defect_class": "insecure_file_permission",
            "rule": "java_insecure_file_permissions",
            "source": "temporary file path",
            "sink": 'PosixFilePermissions.fromString("rwxrwxrwx")',
            "evidence_pack": {
                "language": "java",
                "candidate_source": "java_local_rule",
                "defect_class": "insecure_file_permission",
                "rule": "java_insecure_file_permissions",
            },
        }
    )

    assert candidate["evidence_pack"]["sink"]["kind"] == "java_file_permission"
    assert candidate["evidence_pack"]["source"]["kind"].startswith("java_")


def test_merge_java_candidates_combines_local_and_joern_same_sink() -> None:
    merged = merge_java_evidence_candidates(
        [
            _java_local_path_candidate(),
            _joern_path_candidate(),
        ]
    )

    assert len(merged) == 1
    primary = merged[0]
    assert primary["candidate_id"] == "JOERN_PATH_TRAVERSAL"
    assert primary["java_evidence_merged"] is True
    assert primary["must_validate"] is True
    assert primary["merged_candidate_sources"] == ["joern_cpg", "java_local_rule"]
    pack = primary["evidence_pack"]
    assert pack["language"] == "java"
    assert pack["primary_evidence"]["candidate_id"] == "JOERN_PATH_TRAVERSAL"
    assert pack["alternate_evidence"][0]["candidate_id"] == "JAVA_RULE_PATH_TRAVERSAL"
    assert "java_local_rule_checker" in pack["evidence_engines"]


def test_merge_java_candidates_prefers_complete_cross_layer_flow() -> None:
    local = _java_local_path_candidate()
    cross_layer = _joern_path_candidate()
    cross_layer["candidate_id"] = "JAVA_CROSS_LAYER_PATH"
    cross_layer["candidate_source"] = "java_framework_flow"
    cross_layer["evidence_pack"]["candidate_source"] = "java_framework_flow"
    cross_layer["evidence_pack"]["path"].update(
        {
            "complete_to_entry": True,
            "call_path": [
                "com.zscope.cli.LibraryApi.load:java.lang.String(java.lang.String)",
                "com.zscope.cli.Loader.read",
            ],
            "call_edges": [
                {
                    "caller": "com.zscope.cli.LibraryApi.load:java.lang.String(java.lang.String)",
                    "callee": "com.zscope.cli.Loader.read",
                    "parameter_mapping": [{"actual": "path", "formal": "path"}],
                }
            ],
        }
    )

    merged = merge_java_evidence_candidates([local, cross_layer])

    assert len(merged) == 1
    assert merged[0]["candidate_id"] == "JAVA_CROSS_LAYER_PATH"
    assert merged[0]["evidence_pack"]["path"]["complete_to_entry"] is True
    assert (
        merged[0]["evidence_pack"]["alternate_evidence"][0]["candidate_id"]
        == "JAVA_RULE_PATH_TRAVERSAL"
    )


def test_merge_java_candidates_keeps_different_defects_separate() -> None:
    path = _java_local_path_candidate()
    command = _java_local_path_candidate()
    command["candidate_id"] = "JAVA_RULE_COMMAND"
    command["defect_class"] = "command_injection"
    command["category"] = "command_injection"
    command["subcategory"] = "command_injection"
    command["rule"] = "java_command_execution"
    command["sink"] = "Runtime.getRuntime().exec(cmd)"
    command["evidence_pack"]["defect_class"] = "command_injection"
    command["evidence_pack"]["rule"] = "java_command_execution"
    command["evidence_pack"]["sink"]["operation"] = "Runtime.getRuntime().exec(cmd)"

    merged = merge_java_evidence_candidates([path, command])

    assert len(merged) == 2


def test_analyzer_uses_java_evidence_merge_for_java_projects() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(project=SimpleNamespace(language="java"))

    merged = analyzer._merge_unified_evidence_candidates(
        [
            _java_local_path_candidate(),
            _joern_path_candidate(),
        ]
    )

    assert len(merged) == 1
    assert merged[0]["java_evidence_merged"] is True
