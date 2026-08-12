"""Generic normalization for Java LLM active-audit observations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, cast

JAVA_ACTIVE_GENERIC_RULE = "java_llm_active_audit"


@dataclass(frozen=True)
class JavaCoordinateResolution:
    file: str = ""
    line: int = 0
    reason: str = ""
    confidence: float = 0.0

    @property
    def resolved(self) -> bool:
        return bool(self.file and self.line > 0)


class JavaActiveAuditNormalizer:
    """Normalize Java active-audit findings without project-specific names."""

    GENERIC_CATEGORIES = {
        "",
        "security",
        "logic",
        "race",
        "race_condition",
        "data_race",
        "shared_state_race",
        "memory_leak",
        "file_handle_leak",
        "stream_not_closed",
        "file_descriptor_leak",
        "weak_crypto",
        "crypto",
        "crypto_misuse",
        "resource_management",
        "resource_lifecycle",
    }

    @classmethod
    def normalize(
        cls,
        issue: Dict[str, Any],
        evidence_pack: Dict[str, Any],
        *,
        entry_func: str = "",
        entry_file: str = "",
        code_index: Any = None,
    ) -> Dict[str, Any]:
        """Normalize one LLM-only Java active-audit issue in place."""
        issue.setdefault("language", "java")
        issue.setdefault("candidate_source", "java_llm_active_audit")
        issue.setdefault("finding_kind", "java_active_audit_observation")
        issue.setdefault("active_audit_review_only", True)
        issue.setdefault("rule", JAVA_ACTIVE_GENERIC_RULE)
        issue.setdefault("evidence_refs", [])
        if entry_func:
            issue.setdefault("entry_function", entry_func)
            issue.setdefault("entry_path", [entry_func])

        evidence_pack["candidate_source"] = "java_llm_active_audit"
        evidence_pack["language"] = "java"
        evidence_pack["active_audit_review_only"] = True
        path = evidence_pack.setdefault("path", {})
        if isinstance(path, dict):
            if entry_func:
                path.setdefault("entry_function", entry_func)
                path.setdefault("entry_path", [entry_func])

        category = cls.infer_category(issue, evidence_pack)
        if category:
            issue["category"] = category
            issue["subcategory"] = category
            issue["defect_class"] = category
            evidence_pack["defect_class"] = category

        rule = cls.infer_rule(issue, evidence_pack, category)
        if rule and str(issue.get("rule") or "") in {"", JAVA_ACTIVE_GENERIC_RULE}:
            issue["rule"] = rule
            evidence_pack["rule"] = rule

        if entry_file and not (
            issue.get("file") or issue.get("file_path") or issue.get("location")
        ):
            issue["file"] = entry_file
        if entry_file:
            for key in ("source", "sink"):
                value = evidence_pack.get(key) if isinstance(evidence_pack.get(key), dict) else {}
                if not value:
                    value = {}
                    evidence_pack[key] = value
                value.setdefault("file", entry_file)

        resolution = JavaCoordinateResolver.resolve(
            issue,
            evidence_pack,
            entry_func=entry_func,
            entry_file=entry_file,
            code_index=code_index,
        )
        if resolution.resolved:
            cls._apply_resolution(issue, evidence_pack, resolution)
        elif resolution.reason:
            issue.setdefault("java_coordinate_resolution_reason", resolution.reason)
        return issue

    @classmethod
    def infer_category(cls, issue: Dict[str, Any], evidence_pack: Dict[str, Any]) -> str:
        current = (
            str(
                issue.get("defect_class")
                or issue.get("subcategory")
                or issue.get("category")
                or evidence_pack.get("defect_class")
                or ""
            )
            .replace("-", "_")
            .lower()
        )
        text = _flatten_json([issue, evidence_pack])
        compact = _compact(text)
        if current and current not in cls.GENERIC_CATEGORIES:
            return current
        if (
            "sqlinjection" in compact
            or "jdbctemplate" in compact
            or "preparedstatement" in compact
            or "createstatement" in compact
        ):
            return "sql_injection"
        if (
            "xss" in compact
            or "thutext" in compact
            or "returnpayload" in compact
            or "returnspayload" in compact
            or "modeladdattribute" in compact
            or "insertone" in compact
        ):
            return "xss"
        if "csrf" in compact:
            return "csrf"
        if "jsonp" in compact or ("callback" in compact and "crossorigin" in compact):
            return "jsonp_hijacking"
        if "xpath" in compact:
            return "xpath_injection"
        if "crossorigin" in compact or "cors" in compact or "allowedorigins" in compact:
            return "cors_misconfiguration"
        if (
            "authorization" in compact
            or "permitall" in compact
            or "securityfilterchain" in compact
            or "chain.dofilter" in text
            or "dofilter" in compact
            or "prehandle" in compact
            or "deletebyid" in compact
        ):
            return "authz_bypass"
        if (
            "hardcoded" in compact
            or "secret" in compact
            or "apikey" in compact
            or "api_key" in text
            or "hmac256" in compact
            or re.search(r"\bpassword\s*[:=]", text)
        ):
            return "secret_exposure"
        if "xmldecoder" in compact:
            return "unsafe_deserialization"
        if (
            "documentbuilderfactory" in compact
            or "xmlreaderfactory" in compact
            or "saxparserfactory" in compact
            or "xmlinputfactory" in compact
            or "xxe" in compact
            or "externalentity" in compact
        ):
            return "xxe"
        if (
            "redirect:" in text
            or "openredirect" in compact
            or ("redirect" in compact and "requestparam" in compact)
        ):
            return "open_redirect"
        if (
            "multipartfile" in compact
            or "getoriginalfilename" in compact
            or "transferto" in compact
        ):
            return "file_upload"
        if (
            "aes/ecb" in text
            or "des/ecb" in text
            or "cipher.getinstance" in text
            or "weakencrypt" in compact
        ):
            return "weak_crypto"
        if (
            "objectinputstream" in compact
            or "readobject" in compact
            or "fastjson" in compact
            or "snakeyaml" in compact
            or "xstream" in compact
        ):
            return "unsafe_deserialization"
        if "getresourceasstream" in compact or "resourceloader" in compact:
            return "path_traversal"
        if (
            "hashmap" in compact
            or "sharedcache" in compact
            or "sharedmutable" in compact
            or (
                "static" in compact
                and any(token in compact for token in ("map", "cache", "mutable", "put"))
            )
            or current in {"race", "race_condition", "data_race", "shared_state_race"}
        ):
            return "concurrency_race"
        if (
            "notclosed" in compact
            or "streamnotclosed" in compact
            or "fileinputstream" in compact
            or "zipinputstream" in compact
            or "closeable" in compact
            or current
            in {"memory_leak", "file_handle_leak", "stream_not_closed", "file_descriptor_leak"}
        ):
            return "resource_leak"
        return current

    @staticmethod
    def infer_rule(issue: Dict[str, Any], evidence_pack: Dict[str, Any], category: str) -> str:
        text = _flatten_json([issue, evidence_pack])
        compact = _compact(text)
        if category == "sql_injection":
            if "preparestatement" in compact and "sql" in compact:
                return "java_jdbc_fake_prepared_statement"
            if any(
                token in compact
                for token in ("jdbctemplate", "createstatement", "executequery", "executeupdate")
            ):
                return "java_jdbc_concatenated_sql"
        if category == "xxe":
            return "java_xxe_factory"
        if category == "unsafe_deserialization" and "xmldecoder" in compact:
            return "java_xmldecoder_readobject"
        if category == "secret_exposure":
            return "java_hardcoded_secret"
        if category == "xss":
            if any(token in compact for token in ("insertone", "repositorysave", "savepayload")):
                return "java_stored_xss_persistent_content"
            if any(
                token in compact for token in ("thutext", "modeladdattribute", "templatecontent")
            ):
                return "java_template_utext_xss"
            if any(
                token in compact
                for token in ("returnpayload", "returnspayload", "responsebody", "httpresponsebody")
            ):
                return "java_reflected_xss_response_body"
        return ""

    @staticmethod
    def _apply_resolution(
        issue: Dict[str, Any],
        evidence_pack: Dict[str, Any],
        resolution: JavaCoordinateResolution,
    ) -> None:
        issue["file"] = resolution.file
        issue["file_path"] = resolution.file
        issue["line"] = resolution.line
        issue["start_line"] = resolution.line
        issue["location"] = f"{resolution.file}:{resolution.line}"
        issue["java_coordinate_resolution_reason"] = resolution.reason
        issue["java_coordinate_resolution_confidence"] = resolution.confidence
        for key in ("source", "sink"):
            value = evidence_pack.get(key) if isinstance(evidence_pack.get(key), dict) else {}
            if not value:
                value = {}
                evidence_pack[key] = value
            value["file"] = resolution.file
            value["file_path"] = resolution.file
            if key == "source" or not value.get("line"):
                value["line"] = resolution.line


class JavaCoordinateResolver:
    """Resolve Java observation coordinates from evidence and project structure."""

    @classmethod
    def resolve(
        cls,
        issue: Dict[str, Any],
        evidence_pack: Dict[str, Any],
        *,
        entry_func: str = "",
        entry_file: str = "",
        code_index: Any = None,
    ) -> JavaCoordinateResolution:
        text = _flatten_json([issue, evidence_pack])
        category = (
            str(issue.get("category") or evidence_pack.get("defect_class") or "")
            .replace("-", "_")
            .lower()
        )
        rule = str(issue.get("rule") or evidence_pack.get("rule") or "")

        explicit = cls._explicit_coordinate(issue, evidence_pack)
        if explicit.resolved:
            if (
                entry_file
                and "/" not in explicit.file
                and entry_file.replace("\\", "/").lower().endswith("/" + explicit.file.lower())
            ):
                return JavaCoordinateResolution(
                    entry_file.replace("\\", "/"),
                    explicit.line,
                    f"{explicit.reason}_entry_file_disambiguated",
                    explicit.confidence,
                )
            return explicit

        source_root = cls._source_root(code_index)
        file_hint = cls._clean_java_path(
            str(issue.get("file_path") or issue.get("file") or entry_file or "")
        )
        entry_impl = cls._entry_impl(code_index, entry_func, entry_file)
        if entry_impl and not file_hint:
            file_hint = cls._clean_java_path(str(entry_impl.get("file") or ""))

        token_impl = cls._token_impl(code_index, text, category, rule)
        for impl, reason in ((token_impl, "token_method_sink"), (entry_impl, "entry_method_sink")):
            if not impl:
                continue
            resolved = cls._resolve_in_impl(impl, category, rule, text, reason)
            if resolved.resolved:
                return resolved

        resolved = cls._search_file(
            file_hint, source_root, category, rule, text, "file_sink_keyword"
        )
        if resolved.resolved:
            return resolved

        if category == "secret_exposure":
            resolved = cls._search_resource_secrets(source_root, text)
            if resolved.resolved:
                return resolved

        if entry_impl:
            file_path = cls._clean_java_path(str(entry_impl.get("file") or ""))
            line = _positive_int(entry_impl.get("start_line") or entry_impl.get("lineNumber"))
            if file_path and line and (category or rule):
                return JavaCoordinateResolution(file_path, line, "entry_method_start", 0.45)
        if file_hint:
            line = _positive_int(issue.get("line") or issue.get("start_line"))
            if line:
                return JavaCoordinateResolution(file_hint, line, "issue_file_line", 0.5)
        return JavaCoordinateResolution(reason="unresolved_java_coordinate")

    @classmethod
    def _explicit_coordinate(
        cls, issue: Dict[str, Any], evidence_pack: Dict[str, Any]
    ) -> JavaCoordinateResolution:
        values: List[Tuple[Any, str, float]] = []
        for key in ("sink", "source", "path"):
            values.append(
                (evidence_pack.get(key), f"evidence_{key}", 0.9 if key == "sink" else 0.84)
            )
        for key in ("file_path", "file", "location"):
            values.append((issue.get(key), f"issue_{key}", 0.72))
        for value, reason, confidence in values:
            file_path, line = cls._coordinate_from_value(value)
            if file_path and line:
                return JavaCoordinateResolution(file_path, line, reason, confidence)
        return JavaCoordinateResolution()

    @classmethod
    def _resolve_in_impl(
        cls,
        impl: Dict[str, Any],
        category: str,
        rule: str,
        text: str,
        reason: str,
    ) -> JavaCoordinateResolution:
        file_path = cls._clean_java_path(str(impl.get("file") or ""))
        if not file_path:
            return JavaCoordinateResolution()
        line = cls._line_from_numbered_code(str(impl.get("code") or ""), category, rule, text)
        if line:
            return JavaCoordinateResolution(file_path, line, reason, 0.78)
        return JavaCoordinateResolution()

    @classmethod
    def _search_file(
        cls,
        file_path: str,
        source_root: Optional[Path],
        category: str,
        rule: str,
        text: str,
        reason: str,
    ) -> JavaCoordinateResolution:
        if not (file_path and source_root):
            return JavaCoordinateResolution()
        full_path = source_root / file_path
        if not full_path.exists() or not full_path.is_file():
            return JavaCoordinateResolution()
        try:
            lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return JavaCoordinateResolution()
        line = cls._line_from_plain_lines(lines, category, rule, text)
        if line:
            return JavaCoordinateResolution(file_path, line, reason, 0.7)
        return JavaCoordinateResolution()

    @classmethod
    def _search_resource_secrets(
        cls, source_root: Optional[Path], text: str
    ) -> JavaCoordinateResolution:
        if not source_root:
            return JavaCoordinateResolution()
        resources = source_root / "src" / "main" / "resources"
        if not resources.exists():
            return JavaCoordinateResolution()
        secret_literals = _secret_literals(text)
        for pattern in ("*.yml", "*.yaml", "*.properties", "*.xml"):
            for path in sorted(resources.rglob(pattern)):
                try:
                    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    continue
                for line_no, line in enumerate(lines, start=1):
                    lowered = line.lower()
                    if not any(
                        token in lowered
                        for token in ("password", "secret", "api-key", "apikey", "token")
                    ):
                        continue
                    if secret_literals and not any(
                        literal.lower() in lowered for literal in secret_literals
                    ):
                        continue
                    return JavaCoordinateResolution(
                        path.relative_to(source_root).as_posix(),
                        line_no,
                        "resource_secret_keyword",
                        0.76,
                    )
        return JavaCoordinateResolution()

    @classmethod
    def _token_impl(
        cls, code_index: Any, text: str, category: str, rule: str
    ) -> Optional[Dict[str, Any]]:
        if code_index is None or not hasattr(code_index, "find_java_methods_by_tokens"):
            return None
        tokens = cls._query_tokens(text, category, rule)
        if not tokens:
            return None
        try:
            candidates = code_index.find_java_methods_by_tokens(tokens, limit=8)
        except Exception:
            return None
        for candidate in candidates:
            name = str(
                candidate.get("qualified_name")
                or candidate.get("method_full_name")
                or candidate.get("name")
                or ""
            )
            file_path = str(candidate.get("file") or candidate.get("filename") or "")
            impl = cls._entry_impl(code_index, name, file_path)
            if impl and cls._line_from_numbered_code(
                str(impl.get("code") or ""), category, rule, text
            ):
                return impl
        return None

    @staticmethod
    def _entry_impl(
        code_index: Any, entry_func: str, entry_file: str = ""
    ) -> Optional[Dict[str, Any]]:
        if code_index is None or not entry_func or not hasattr(code_index, "get_function_impl"):
            return None
        try:
            return cast(
                Optional[Dict[str, Any]],
                code_index.get_function_impl(entry_func, warn_missing=False, file_path=entry_file),
            )
        except TypeError:
            try:
                return cast(
                    Optional[Dict[str, Any]],
                    code_index.get_function_impl(entry_func, warn_missing=False),
                )
            except Exception:
                return None
        except Exception:
            return None

    @classmethod
    def _line_from_numbered_code(cls, code: str, category: str, rule: str, text: str) -> int:
        pairs: List[Tuple[int, str]] = []
        for raw in code.splitlines():
            match = re.match(r"\s*(\d+)\s*\|\s?(.*)$", raw)
            if match:
                pairs.append((int(match.group(1)), match.group(2)))
        return cls._line_from_pairs(pairs, category, rule, text)

    @classmethod
    def _line_from_plain_lines(
        cls, lines: Sequence[str], category: str, rule: str, text: str
    ) -> int:
        return cls._line_from_pairs(list(enumerate(lines, start=1)), category, rule, text)

    @classmethod
    def _line_from_pairs(
        cls, pairs: Sequence[Tuple[int, str]], category: str, rule: str, text: str
    ) -> int:
        if not pairs:
            return 0
        predicates = cls._line_predicates(category, rule, text)
        for predicate in predicates:
            for line_no, line in pairs:
                if predicate(line.lower(), _compact(line)):
                    return line_no
        return 0

    @staticmethod
    def _line_predicates(category: str, rule: str, text: str):
        def contains(*tokens: str):
            return lambda lower, compact: any(
                token.lower() in lower or _compact(token) in compact for token in tokens
            )

        if rule == "java_jdbc_fake_prepared_statement":
            return [contains("prepareStatement")]
        if rule == "java_jdbc_concatenated_sql" or category == "sql_injection":
            return [
                contains("executeQuery", "executeUpdate", "JdbcTemplate", "createStatement"),
                contains("String sql"),
            ]
        if rule == "java_xmldecoder_readobject":
            return [contains("readObject"), contains("XMLDecoder")]
        if rule == "java_xxe_factory" or category == "xxe":
            return [
                contains(
                    "DocumentBuilderFactory",
                    "XMLReaderFactory",
                    "SAXParserFactory",
                    "XMLInputFactory",
                    "SAXReader",
                )
            ]
        if rule == "java_stored_xss_persistent_content":
            return [contains("insertOne", ".save", ".update")]
        if rule == "java_template_utext_xss":
            return [contains("model.addAttribute", "th:utext", "templateContent")]
        if rule == "java_reflected_xss_response_body" or category == "xss":
            return [
                contains("return payload", "return input", "return content", "return html"),
                contains("ResponseBody"),
            ]
        if category == "secret_exposure":
            return [contains("password", "secret", "apiKey", "api-key", "HMAC256")]
        if category == "concurrency_race":
            return [contains("static", "HashMap", "shared", ".put")]
        if category == "resource_leak":
            return [
                contains("new FileInputStream", "newInputStream", "ZipInputStream", "Closeable")
            ]
        if category == "open_redirect":
            return [contains("redirect:", "sendRedirect")]
        if category == "file_upload":
            return [contains("transferTo", "getOriginalFilename", "MultipartFile")]
        if category == "path_traversal":
            return [
                contains("Paths.get", "Path.of", "new File", "Files.read", "getResourceAsStream")
            ]
        if category in {"weak_crypto", "crypto_misuse"}:
            return [contains("Cipher.getInstance", "AES/ECB", "DES/ECB")]
        return []

    @classmethod
    def _query_tokens(cls, text: str, category: str, rule: str) -> List[str]:
        tokens = []
        if category:
            tokens.append(category)
        if rule:
            tokens.extend(part for part in str(rule).split("_") if part and part.lower() != "java")
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text):
            lowered = token.lower()
            if lowered in {"java", "src", "main", "string", "payload", "security", "issue"}:
                continue
            tokens.append(token)
        return list(dict.fromkeys(tokens))[:64]

    @staticmethod
    def _source_root(code_index: Any) -> Optional[Path]:
        root = getattr(code_index, "source_root", None) if code_index is not None else None
        if root:
            return Path(root)
        return None

    @classmethod
    def _coordinate_from_value(cls, value: Any) -> Tuple[str, int]:
        if value in (None, ""):
            return "", 0
        if isinstance(value, dict):
            line = _positive_int(
                value.get("line")
                or value.get("line_number")
                or value.get("lineNumber")
                or value.get("start_line")
                or value.get("startLine")
            )
            for key in (
                "file",
                "file_path",
                "filename",
                "module_path",
                "location",
                "loc",
                "reported_location",
            ):
                file_path, parsed_line = cls._coordinate_from_text(str(value.get(key) or ""))
                if file_path:
                    return file_path, parsed_line or line or 0
            return "", 0
        if isinstance(value, (list, tuple)):
            for item in value[:16]:
                file_path, line = cls._coordinate_from_value(item)
                if file_path and line:
                    return file_path, line
            return "", 0
        return cls._coordinate_from_text(str(value))

    @classmethod
    def _coordinate_from_text(cls, value: str) -> Tuple[str, int]:
        text = str(value or "").replace("\\", "/")
        match = re.search(
            r"((?:src/(?:main|test)/java|src/main/resources)/[A-Za-z0-9_./$-]+\.(?:java|kt|scala|yml|yaml|xml|properties))(?::(\d+))?",
            text,
            flags=re.IGNORECASE,
        )
        if match:
            return cls._clean_java_path(match.group(1)), _positive_int(match.group(2)) or 0
        match = re.search(
            r"([A-Za-z0-9_.$-]+\.(?:java|kt|scala))(?::(\d+))?", text, flags=re.IGNORECASE
        )
        if match:
            return cls._clean_java_path(match.group(1)), _positive_int(match.group(2)) or 0
        return "", 0

    @staticmethod
    def _clean_java_path(value: str) -> str:
        text = str(value or "").replace("\\", "/").strip().strip("`'\"")
        match = re.search(
            r"((?:src/(?:main|test)/java|src/main/resources)/[A-Za-z0-9_./$-]+\.(?:java|kt|scala|yml|yaml|xml|properties))",
            text,
            flags=re.IGNORECASE,
        )
        if match:
            return match.group(1)
        if "/" not in text and re.match(
            r"^[A-Za-z0-9_.$-]+\.(?:java|kt|scala)$", text, flags=re.IGNORECASE
        ):
            return text
        return ""


def _flatten_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str).lower()


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _positive_int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def _secret_literals(text: str) -> List[str]:
    values: List[str] = []
    for match in re.finditer(
        r"(?i)\b(?:password|secret|api[_-]?key|token)\s*[:=]\s*[\"']?([A-Za-z0-9_.$@!#%-]{6,})",
        text,
    ):
        values.append(match.group(1))
    for match in re.finditer(r"`([^`]{6,80})`", text):
        values.append(match.group(1))
    return values[:8]
