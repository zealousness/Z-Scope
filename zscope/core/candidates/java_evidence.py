"""Java candidate evidence normalization and merge helpers."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Set

from .adapters import candidate_source_name, parse_location_file_line
from ...retrieval.java_models import JAVA_EVIDENCE_PRECISION_RANK, normalize_java_evidence_precision

JAVA_CANDIDATE_SOURCES = {
    "java_local_rule",
    "java_llm_active_audit",
    "java_framework_flow",
    "java_project_file_rule",
    "java_mybatis_xml",
    "mybatis_xml",
}

_PATH_SEPARATORS_RE = re.compile(r"[\\/]+")
_TOKEN_RE = re.compile(r"[A-Za-z_]\w*")


def normalize_java_candidate(issue: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Java candidate fields in-place and return the same issue."""

    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    if not pack:
        issue["evidence_pack"] = pack

    candidate_source = candidate_source_name(issue) or "java_candidate"
    defect_class = (
        str(
            issue.get("defect_class")
            or issue.get("subcategory")
            or issue.get("category")
            or pack.get("defect_class")
            or ""
        )
        .replace("-", "_")
        .lower()
    )
    rule = str(issue.get("rule") or pack.get("rule") or "")

    pack.setdefault("schema", "candidate_evidence_v1")
    pack["language"] = "java"
    pack.setdefault("candidate_id", issue.get("candidate_id") or issue.get("id"))
    pack.setdefault("candidate_source", candidate_source)
    pack.setdefault("defect_class", defect_class)
    if rule:
        pack.setdefault("rule", rule)
    pack.setdefault("candidate_is_conclusion", False)
    pack.setdefault("validation_required", True)
    pack["precision"] = normalize_java_evidence_precision(
        str(
            pack.get("precision")
            or issue.get("precision")
            or _precision_from_source(candidate_source)
        )
    )
    pack.setdefault("confidence_tier", _confidence_tier(pack["precision"]))
    if pack.get("provider"):
        issue["provider"] = pack.get("provider")
    pack.setdefault("evidence_refs", issue.get("evidence_refs") or [])
    pack.setdefault("positive_evidence", issue.get("positive_evidence") or [])
    pack.setdefault("negative_evidence", issue.get("negative_evidence") or [])
    pack.setdefault("guards", issue.get("guards") or issue.get("guard_analysis") or [])
    pack.setdefault("limitations", issue.get("limitations") or issue.get("limitation") or [])

    source = pack.get("source") if isinstance(pack.get("source"), dict) else {}
    sink = pack.get("sink") if isinstance(pack.get("sink"), dict) else {}
    file_path, line = parse_location_file_line(str(issue.get("location") or ""))
    if not file_path:
        file_path = str(issue.get("file") or issue.get("file_path") or "")
    if not line:
        line = int(issue.get("line") or issue.get("line_number") or 0)
    file_path = _sanitize_java_path(file_path)
    source.setdefault("expression", issue.get("source") or "java input or derived value")
    source.setdefault("kind", _source_kind(issue, pack))
    if file_path:
        source.setdefault("file", file_path)
    if line:
        source.setdefault("line", line)
    sink.setdefault(
        "operation", issue.get("sink") or issue.get("code_snippet") or rule or defect_class
    )
    sink.setdefault("kind", _sink_kind(issue, pack))
    if file_path:
        sink.setdefault("file", file_path)
    if line:
        sink.setdefault("line", line)
    pack["source"] = source
    pack["sink"] = sink

    path = pack.get("path") if isinstance(pack.get("path"), dict) else {}
    path.setdefault("function", issue.get("function") or issue.get("func_name") or "")
    if issue.get("entry_function"):
        path.setdefault("entry_function", issue.get("entry_function"))
    if issue.get("call_path"):
        path.setdefault("call_path", issue.get("call_path"))
    if pack.get("call_path"):
        path.setdefault("call_path", pack.get("call_path"))
    if pack.get("call_path_edges"):
        path.setdefault("call_edges", pack.get("call_path_edges"))
    if issue.get("call_path") and not path.get("call_path"):
        path.setdefault("call_path", issue.get("call_path"))
    if issue.get("call_paths") and not path.get("call_paths"):
        path.setdefault("call_paths", issue.get("call_paths"))
    path.setdefault("complete_in_function", False)
    path.setdefault("guard_status", "unknown")
    pack["path"] = path

    pack["source_sink_summary"] = {
        "source_kind": source.get("kind"),
        "source": source.get("expression"),
        "sink_kind": sink.get("kind"),
        "sink": sink.get("operation"),
        "file": file_path,
        "line": line or None,
    }
    framework_edges = pack.get("framework_edges")
    if framework_edges is None:
        framework_edges = (
            pack.get("call_path_edges")
            or pack.get("propagation_edges")
            or pack.get("controller_service_mapper_edges")
            or []
        )
    pack["framework_edges"] = framework_edges if isinstance(framework_edges, list) else []
    pack["root_cause_key"] = java_candidate_dedup_key(issue)

    issue["language"] = "java"
    issue["candidate_source"] = candidate_source
    issue["defect_class"] = defect_class or issue.get("defect_class")
    issue["category"] = defect_class or issue.get("category")
    issue["subcategory"] = defect_class or issue.get("subcategory")
    issue["validation_required"] = True
    issue["must_validate"] = True
    issue["evidence_pack"] = pack
    issue["precision"] = pack.get("precision")
    issue["confidence_tier"] = pack.get("confidence_tier")
    issue.setdefault("candidate_role", "evidence_only")
    if file_path:
        issue["file"] = file_path
        if line and not issue.get("location"):
            issue["location"] = f"{file_path}:{line}"
    if line:
        issue["line"] = line
    issue["root_cause_key"] = issue.get("root_cause_key") or pack.get("root_cause_key")
    issue["dedup_key"] = issue.get("dedup_key") or java_candidate_dedup_key(issue)
    return issue


def merge_java_evidence_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge Java local-rule, Joern, framework, and project-file evidence."""

    merged: List[Dict[str, Any]] = []
    for candidate in candidates:
        if not _looks_like_java_candidate(candidate):
            merged.append(candidate)
            continue
        candidate = normalize_java_candidate(candidate)
        match = next(
            (
                existing
                for existing in merged
                if java_candidates_may_refer_same_issue(existing, candidate)
            ),
            None,
        )
        if match is None:
            merged.append(candidate)
            continue
        primary = _prefer_java_primary(match, candidate)
        secondary = match if primary is candidate else candidate
        if primary is candidate:
            index = merged.index(match)
            merged[index] = candidate
        attach_java_alternate_evidence(primary, secondary)
    return merged


def java_candidates_may_refer_same_issue(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    if not (_looks_like_java_candidate(left) and _looks_like_java_candidate(right)):
        return False
    left = normalize_java_candidate(left)
    right = normalize_java_candidate(right)
    if _defect_class(left) != _defect_class(right):
        return False

    left_mapper = _mapper_statement_key(left)
    right_mapper = _mapper_statement_key(right)
    if left_mapper and right_mapper:
        return left_mapper == right_mapper

    left_entry_sink = _entry_sink_key(left)
    right_entry_sink = _entry_sink_key(right)
    if left_entry_sink and right_entry_sink and left_entry_sink == right_entry_sink:
        return True

    left_file, left_line = _sink_file_line(left)
    right_file, right_line = _sink_file_line(right)
    if left_file and right_file and left_file == right_file:
        if left_line and right_line and abs(left_line - right_line) <= 4:
            return _sink_tokens(left) & _sink_tokens(right) or _same_sink_family(left, right)
        if _sink_operation_key(left) and _sink_operation_key(left) == _sink_operation_key(right):
            return True

    left_sink_func = _sink_function(left)
    right_sink_func = _sink_function(right)
    if left_sink_func and right_sink_func and left_sink_func == right_sink_func:
        return bool(_sink_tokens(left) & _sink_tokens(right))

    return False


def java_candidate_dedup_key(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    defect = _defect_class(issue)
    mapper = _mapper_statement_key(issue)
    if mapper:
        return "|".join(["java", defect, "mybatis", mapper])
    entry_sink = _entry_sink_key(issue)
    if entry_sink:
        return "|".join(["java", defect, entry_sink])
    sink_file, sink_line = _sink_file_line(issue)
    sink_func = _sink_function(issue)
    sink = _sink_operation_key(issue)
    source = pack.get("source") if isinstance(pack.get("source"), dict) else {}
    source_kind = str(source.get("kind") or "")
    root = _java_root_cause_token(issue)
    if root and (sink_file or sink_func):
        return "|".join(["java-root", defect, root, sink_file, sink_func])
    return "|".join(
        [
            "java",
            defect,
            sink_file,
            str(sink_line or ""),
            sink_func,
            sink,
            source_kind,
        ]
    )


def attach_java_alternate_evidence(primary: Dict[str, Any], secondary: Dict[str, Any]) -> None:
    primary_pack = (
        primary.get("evidence_pack") if isinstance(primary.get("evidence_pack"), dict) else {}
    )
    if not primary_pack:
        primary["evidence_pack"] = primary_pack
    secondary_pack = (
        secondary.get("evidence_pack") if isinstance(secondary.get("evidence_pack"), dict) else {}
    )

    primary_pack.setdefault("primary_evidence", _compact_java_candidate(primary))
    alternate = primary_pack.setdefault("alternate_evidence", [])
    compact = _compact_java_candidate(secondary)
    if isinstance(alternate, list) and compact not in alternate:
        alternate.append(compact)

    sources = primary.setdefault("merged_candidate_sources", [])
    if isinstance(sources, list):
        for source in (candidate_source_name(primary), candidate_source_name(secondary)):
            if source and source not in sources:
                sources.append(source)
    primary_pack["merged_candidate_sources"] = list(primary.get("merged_candidate_sources") or [])

    engines = primary_pack.setdefault("evidence_engines", [])
    if not isinstance(engines, list):
        engines = []
        primary_pack["evidence_engines"] = engines
    for engine in _evidence_engines(primary) + _evidence_engines(secondary):
        if engine and engine not in engines:
            engines.append(engine)

    for field in ("positive_evidence", "negative_evidence", "evidence_refs"):
        current = primary.setdefault(field, [])
        incoming = secondary.get(field) or secondary_pack.get(field) or []
        if not isinstance(current, list) or not isinstance(incoming, list):
            continue
        for item in incoming:
            if item not in current:
                current.append(item)
    primary["java_evidence_merged"] = True
    primary["validation_required"] = True
    primary["must_validate"] = True


def _prefer_java_primary(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    return right if _java_evidence_rank(right) > _java_evidence_rank(left) else left


def _java_evidence_rank(issue: Dict[str, Any]) -> int:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    path = pack.get("path") if isinstance(pack.get("path"), dict) else {}
    source = candidate_source_name(issue)
    rule = str(issue.get("rule") or pack.get("rule") or "")
    rank = 10
    if source == "java_local_rule":
        rank = 40
    if source in {"java_project_file_rule", "java_mybatis_xml", "mybatis_xml"}:
        rank = 45
    if "framework" in source:
        rank = 55
    if source == "joern_cpg":
        rank = 60
    if rule.startswith("java_source_entry_cross_layer_flow_"):
        rank = 70
    precision = normalize_java_evidence_precision(
        str(pack.get("precision") or issue.get("precision") or "")
    )
    rank += int(JAVA_EVIDENCE_PRECISION_RANK.get(precision, 0) / 10)
    if path.get("complete_in_function") is True:
        rank += 4
    if path.get("complete_to_entry") is True:
        rank += 12
    if path.get("call_edges") or path.get("call_path"):
        rank += 4
    return rank


def _precision_from_source(candidate_source: str) -> str:
    source = str(candidate_source or "").lower()
    if "codeql" in source or "joern" in source:
        return "exact_flow"
    if "sootup" in source or "wala" in source:
        return "typed_callgraph_flow"
    if "framework" in source or "mybatis" in source:
        return "framework_binding_flow"
    if "java_local_rule" in source:
        return "source_level_approx"
    return "source_level_approx"


def _confidence_tier(precision: str) -> str:
    rank = JAVA_EVIDENCE_PRECISION_RANK.get(normalize_java_evidence_precision(precision), 0)
    if rank >= 85:
        return "exact"
    if rank >= 70:
        return "typed"
    if rank >= 60:
        return "framework"
    if rank >= 40:
        return "approx"
    return "fallback"


def _looks_like_java_candidate(issue: Dict[str, Any]) -> bool:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    source = candidate_source_name(issue)
    rule = str(issue.get("rule") or pack.get("rule") or "")
    language = str(issue.get("language") or pack.get("language") or "").lower()
    location = " ".join(
        str(issue.get(key) or "") for key in ("location", "file", "file_path")
    ).lower()
    return (
        language == "java"
        or source in JAVA_CANDIDATE_SOURCES
        or rule.startswith("java_")
        or ".java" in location
        or "src/main/java" in location
    )


def _defect_class(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    return (
        str(
            issue.get("defect_class")
            or issue.get("subcategory")
            or issue.get("category")
            or pack.get("defect_class")
            or ""
        )
        .replace("-", "_")
        .lower()
    )


def _source_kind(issue: Dict[str, Any], pack: Dict[str, Any]) -> str:
    text = _issue_text(issue, pack)
    if "requestparam" in text or "requestbody" in text or "pathvariable" in text:
        return "java_http_request"
    if (
        "kafkalistener" in text
        or "rabbitlistener" in text
        or "jmslistener" in text
        or "payload" in text
    ):
        return "java_message_payload"
    if "system.getenv" in text:
        return "java_environment"
    if "system.getproperty" in text:
        return "java_system_property"
    if "scanner(system.in" in text or "readline" in text:
        return "java_stdin"
    if "public api" in text or "libraryapi" in text:
        return "java_public_api_parameter"
    return "java_input_or_derived_value"


def _sink_kind(issue: Dict[str, Any], pack: Dict[str, Any]) -> str:
    defect = _defect_class(issue)
    return {
        "sql_injection": "java_sql_execution",
        "jpa_injection": "java_jpa_query",
        "nosql_injection": "java_nosql_query",
        "command_injection": "java_command_execution",
        "path_traversal": "java_file_access",
        "ssrf": "java_http_client",
        "unsafe_deserialization": "java_deserialization",
        "xxe": "java_xml_parser",
        "jndi_injection": "java_jndi_lookup",
        "ldap_injection": "java_ldap_lookup",
        "template_injection": "java_template_engine",
        "code_injection": "java_expression_eval",
        "reflection_injection": "java_reflection",
        "dynamic_class_loading": "java_class_loading",
        "insecure_file_permission": "java_file_permission",
    }.get(defect, f"java_{defect or 'sink'}")


def _sink_file_line(issue: Dict[str, Any]) -> tuple[str, int]:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    sink = pack.get("sink") if isinstance(pack.get("sink"), dict) else {}
    file_path = str(sink.get("file") or issue.get("file") or issue.get("file_path") or "")
    line = int(sink.get("line") or issue.get("line") or issue.get("line_number") or 0)
    loc_file, loc_line = parse_location_file_line(str(issue.get("location") or ""))
    file_path = file_path or loc_file
    line = line or loc_line
    return _normalize_path(_sanitize_java_path(file_path)), line


def _sink_function(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    path = pack.get("path") if isinstance(pack.get("path"), dict) else {}
    return str(
        pack.get("sink_function")
        or path.get("sink_function")
        or path.get("target_function")
        or issue.get("sink_function")
        or issue.get("function")
        or ""
    ).lower()


def _entry_sink_key(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    path = pack.get("path") if isinstance(pack.get("path"), dict) else {}
    entry = str(
        pack.get("entry_function")
        or path.get("entry_function")
        or issue.get("entry_function")
        or issue.get("analyzed_from")
        or ""
    ).lower()
    sink_func = _sink_function(issue)
    sink = _sink_operation_key(issue)
    if entry and sink_func:
        return "|".join([entry, sink_func, sink])
    return ""


def _mapper_statement_key(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    candidates = [
        pack,
        pack.get("framework_evidence"),
        pack.get("cross_layer_flow_evidence"),
        pack.get("raw_match"),
    ]
    for value in candidates:
        if not isinstance(value, dict):
            continue
        namespace = str(value.get("namespace") or value.get("mapper_namespace") or "").lower()
        statement = str(
            value.get("statement_id")
            or value.get("statement")
            or value.get("mapper_statement_id")
            or ""
        ).lower()
        mapper = str(
            value.get("mapper_method") or value.get("method") or value.get("mapper") or ""
        ).lower()
        if namespace and statement:
            return f"{namespace}.{statement}"
        if mapper and statement:
            return f"{mapper}.{statement}"
    return ""


def _sink_operation_key(issue: Dict[str, Any]) -> str:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    sink = pack.get("sink") if isinstance(pack.get("sink"), dict) else {}
    value = str(sink.get("operation") or issue.get("sink") or issue.get("code_snippet") or "")
    value = value.lower().replace("\\", "/")
    value = re.sub(r"\s+", "", value)
    return value[:160]


def _sink_tokens(issue: Dict[str, Any]) -> Set[str]:
    text = _sink_operation_key(issue) + " " + _sink_function(issue)
    return {
        token.lower()
        for token in _TOKEN_RE.findall(text)
        if len(token) >= 3 and token.lower() not in {"java", "src", "main", "line"}
    }


def _same_sink_family(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return _sink_kind(left, left.get("evidence_pack") or {}) == _sink_kind(
        right, right.get("evidence_pack") or {}
    )


def _compact_java_candidate(issue: Dict[str, Any]) -> Dict[str, Any]:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    compact_pack = {
        key: deepcopy(pack.get(key))
        for key in (
            "schema",
            "language",
            "candidate_id",
            "candidate_source",
            "checker",
            "defect_class",
            "rule",
            "source",
            "sink",
            "path",
            "source_sink_summary",
            "framework_edges",
            "guards",
            "limitations",
            "root_cause_key",
            "path_kind",
            "cross_layer_flow_evidence",
            "framework_evidence",
            "path_precision",
            "positive_evidence",
            "negative_evidence",
        )
        if key in pack
    }
    return {
        "candidate_id": issue.get("candidate_id") or issue.get("id") or pack.get("candidate_id"),
        "candidate_source": candidate_source_name(issue),
        "checker": issue.get("evidence_checker") or pack.get("checker"),
        "function": issue.get("function"),
        "location": issue.get("location"),
        "defect_class": _defect_class(issue),
        "rule": issue.get("rule") or pack.get("rule"),
        "source": issue.get("source") or pack.get("source"),
        "sink": issue.get("sink") or pack.get("sink"),
        "dedup_key": java_candidate_dedup_key(issue),
        "evidence_pack": compact_pack,
    }


def _evidence_engines(issue: Dict[str, Any]) -> List[str]:
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    values: List[str] = []
    for source in (issue.get("evidence_engines"), pack.get("evidence_engines")):
        if isinstance(source, list):
            values.extend(str(item) for item in source if item)
    checker = issue.get("evidence_checker") or pack.get("checker")
    if checker:
        values.append(str(checker))
    source_name = candidate_source_name(issue)
    if source_name:
        values.append(f"{source_name}_checker")
    result: List[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _issue_text(*values: Any) -> str:
    return json.dumps(values, ensure_ascii=False, default=str).lower()


def _normalize_path(value: str) -> str:
    text = str(value or "").replace("\\", "/").lower()
    return _PATH_SEPARATORS_RE.sub("/", text)


def _sanitize_java_path(value: str) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if not text or text.lower().startswith("unknown_file"):
        return ""
    if "/" not in text and not text.lower().endswith(".java"):
        return ""
    marker = re.search(r"(src/(?:main|test)/java/[A-Za-z0-9_./$-]+\.java)", text)
    if marker:
        return marker.group(1)
    return text


def _java_root_cause_token(issue: Dict[str, Any]) -> str:
    text = _issue_text(issue)
    compact = re.sub(r"[^a-z0-9]+", "", text)
    if ("threadlocal" in compact or "userholder" in compact or "removeuser" in compact) and (
        "aftercompletion" in compact or "notcleared" in compact or "未清理" in text
    ):
        return "threadlocal_user_context_not_cleared"
    if ("idor" in compact or "bola" in compact or "越权" in text) and (
        "getbyid" in compact
        or "updatebyid" in compact
        or "requestbody" in compact
        or "pathvariable" in compact
    ):
        return "missing_object_authorization"
    if ("upload" in compact or "multipartfile" in compact or "文件上传" in text) and (
        "extension" in text or "contenttype" in compact or "白名单" in text or "suffix" in compact
    ):
        return "upload_extension_not_validated"
    if ("pathtraversal" in compact or "路径穿越" in text or "fileutildel" in compact) and (
        "delete" in compact or "filename" in compact
    ):
        return "file_path_traversal"
    if ("验证码" in text or "verificationcode" in compact) and (
        "loginfo" in compact or "日志" in text
    ):
        return "verification_code_logged"
    if ("验证码" in text or "verificationcode" in compact) and (
        "replay" in compact or "重放" in text or "未删除" in text
    ):
        return "verification_code_replay"
    if "rightpush" in compact or "缓存击穿" in text or "cachestampede" in compact:
        return "cache_check_then_fill"
    if ("zset" in compact or "score" in compact or "点赞" in text) and (
        "toctou" in compact or "score==null" in compact
    ):
        return "redis_zset_check_then_act"
    return ""
