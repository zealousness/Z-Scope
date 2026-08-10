"""Entry-point discovery for Java projects."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..common.utils import matches_configured_path
from ..retrieval.code_index import CodeIndex
from .entry_discovery import EntryCandidate, EntryDiscoveryResult

JAVA_WEB_PROMPT = (
    "Java web framework entry. Treat request path, query parameters, headers, body, "
    "cookies, uploaded files, and framework-bound DTO fields as untrusted. Audit "
    "authorization, validation, injection sinks, path/URL construction, deserialization, "
    "XXE, SSRF, and persistence side effects along the reachable service call chain."
)
JAVA_MAIN_PROMPT = (
    "Java command-line entry. Treat args, environment, files, stdin, and system "
    "properties as untrusted. Audit parsing, path/command construction, deserialization, "
    "resource cleanup, and privileged operations reachable from this method."
)
JAVA_MESSAGE_PROMPT = (
    "Java message listener entry. Treat message payload, headers, keys, topics, and "
    "ack/retry metadata as untrusted. Audit deserialization, validation, idempotency, "
    "authorization-by-topic assumptions, injection sinks, and transaction boundaries."
)
JAVA_SCHEDULED_PROMPT = (
    "Java scheduled/background entry. Audit shared state, resource cleanup, retries, "
    "transaction boundaries, stale credentials/configuration, and unsafe calls made "
    "without a request-scoped security context."
)
JAVA_SERVLET_PROMPT = (
    "Java Servlet entry. Treat HttpServletRequest parameters, headers, body, session, "
    "cookies, and uploaded content as untrusted. Audit authorization, validation, "
    "injection sinks, response redirects, file/URL construction, and resource cleanup."
)
JAVA_LIBRARY_PROMPT = (
    "Java library public API entry. Treat public method parameters as caller-controlled "
    "unless the caller contract proves otherwise. Audit command/path/URL construction, "
    "deserialization, injection sinks, reflection/class loading, resource lifecycle, and "
    "thread-safety effects reachable from this API."
)


class JavaEntryDiscovery:
    """Classifies Java methods that are likely externally or periodically reachable."""

    WEB_MAPPING_ANNOTATIONS = (
        "RequestMapping",
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
    )
    WEB_CLASS_ANNOTATIONS = ("RestController", "Controller")
    JAX_RS_HTTP_ANNOTATIONS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD")
    MESSAGE_ANNOTATIONS = ("KafkaListener", "RabbitListener", "JmsListener")
    SCHEDULED_ANNOTATIONS = ("Scheduled",)
    CLI_ANNOTATIONS = ("Command", "Option", "Parameters")
    SERVLET_METHODS = {"doGet", "doPost", "doPut", "doDelete", "doPatch", "service"}
    ACCESSOR_METHOD_RE = re.compile(r"^(?:get|set|is)[A-Z_].*")
    LOW_VALUE_PACKAGE_RE = re.compile(
        r"(?:^|/)(?:dto|entity|entities|model|models|pojo|vo|bo|domain)(?:/|$)",
        re.IGNORECASE,
    )
    LOW_VALUE_METHOD_NAMES = {
        "build",
        "builder",
        "canEqual",
        "clone",
        "equals",
        "hashCode",
        "toBuilder",
        "toString",
    }

    def __init__(
        self,
        code_index: CodeIndex,
        max_functions: int = 10000,
        header_files: Optional[List[str]] = None,
        project_root: Optional[Path] = None,
        source_root: Optional[Path] = None,
        search_root: Optional[Path] = None,
    ):
        self.code_index = code_index
        self.max_functions = max_functions
        # Java reuses header_files as optional source path filters for compatibility.
        self.path_filters = header_files or []
        self.project_root = Path(project_root).resolve() if project_root else None
        self.source_root = Path(source_root).resolve() if source_root else self.project_root
        self.search_root = Path(search_root).resolve() if search_root else None
        self._method_impl_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        self._context_cache: Dict[str, str] = {}

    def discover(self, max_candidates: int = 200) -> EntryDiscoveryResult:
        candidates: List[EntryCandidate] = []
        for name in self._list_methods_for_discovery():
            impl = self._get_method_impl(name)
            if not impl:
                continue
            file_path = str(impl.get("file") or "")
            if file_path and not file_path.endswith(".java"):
                continue
            if self.path_filters and not matches_configured_path(file_path, self.path_filters):
                continue
            if not self._is_in_search_root(file_path):
                continue

            context = self._method_context(impl)
            if self._is_low_value_java_entry(
                simple_name=self._simple_method_name(name, impl), impl=impl, context=context
            ):
                continue
            candidates.extend(self._candidates_for_method(name, impl, context))

        merged = self._merge_candidates(candidates)
        merged.sort(key=lambda c: (-c.confidence, c.function_name))
        selected = merged[:max_candidates]

        summary: Dict[str, int] = {}
        for candidate in selected:
            summary[candidate.exposure] = summary.get(candidate.exposure, 0) + 1

        if any(c.exposure in {"java_web", "java_servlet"} for c in selected):
            exposure_kind = "java_web_or_servlet"
        elif any(c.exposure == "java_message_listener" for c in selected):
            exposure_kind = "java_message_listener"
        elif any(c.exposure in {"java_main", "java_cli_command"} for c in selected):
            exposure_kind = "java_cli"
        elif any(c.exposure == "java_library_api" for c in selected):
            exposure_kind = "java_library"
        elif any(c.exposure == "java_scheduled" for c in selected):
            exposure_kind = "java_background"
        else:
            exposure_kind = "configured_or_internal_only"

        notes = []
        if not selected:
            notes.append(
                "No Java framework, servlet, listener, scheduled, or main entry candidates were found."
            )
        if len(merged) > len(selected):
            notes.append(f"Truncated {len(merged)} candidates to {len(selected)} by confidence.")
        return EntryDiscoveryResult(
            exposure_kind=exposure_kind,
            candidates=selected,
            summary=summary,
            notes=notes,
        )

    def _candidates_for_method(
        self,
        name: str,
        impl: Dict[str, Any],
        context: str,
    ) -> List[EntryCandidate]:
        candidates: List[EntryCandidate] = []
        simple_name = self._simple_method_name(name, impl)
        file_path = str(impl.get("file") or "")
        line = int(impl.get("start_line") or 0)
        annotations = self._annotation_names(context)

        if self._is_spring_web_entry(annotations):
            route = self._route_hint(context)
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_web",
                    reasons=self._annotation_reasons(annotations, route),
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_WEB_PROMPT,
                    confidence=0.92,
                )
            )

        if self._is_jax_rs_entry(annotations):
            route = self._route_hint(context)
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_web",
                    reasons=self._annotation_reasons(annotations, route),
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_WEB_PROMPT,
                    confidence=0.9,
                )
            )

        message_annotations = sorted(set(annotations).intersection(self.MESSAGE_ANNOTATIONS))
        if message_annotations:
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_message_listener",
                    reasons=[f"annotation:{annotation}" for annotation in message_annotations],
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_MESSAGE_PROMPT,
                    confidence=0.9,
                )
            )

        if set(annotations).intersection(self.SCHEDULED_ANNOTATIONS):
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_scheduled",
                    reasons=["annotation:Scheduled"],
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_SCHEDULED_PROMPT,
                    confidence=0.82,
                )
            )

        if self._is_servlet_entry(simple_name, context):
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_servlet",
                    reasons=[f"servlet_method:{simple_name}"],
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_SERVLET_PROMPT,
                    confidence=0.88,
                )
            )

        if self._is_main_entry(simple_name, impl, context):
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_main",
                    reasons=["public_static_main"],
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_MAIN_PROMPT,
                    confidence=0.78,
                )
            )

        cli_annotations = sorted(set(annotations).intersection(self.CLI_ANNOTATIONS))
        if cli_annotations and self._looks_like_cli_handler(simple_name, context):
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_cli_command",
                    reasons=[f"annotation:{annotation}" for annotation in cli_annotations],
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_MAIN_PROMPT,
                    confidence=0.76,
                )
            )

        if self._is_library_public_api(simple_name, impl, context, annotations):
            candidates.append(
                EntryCandidate(
                    function_name=str(impl.get("qualified_name") or name),
                    exposure="java_library_api",
                    reasons=["public_api_method"],
                    file_path=file_path,
                    line=line,
                    custom_prompt=JAVA_LIBRARY_PROMPT,
                    confidence=self._library_api_confidence(simple_name, impl, context),
                )
            )

        return candidates

    def _is_low_value_java_entry(
        self,
        simple_name: str,
        impl: Dict[str, Any],
        context: str,
    ) -> bool:
        """Filter Java methods that are commonly generated or data-only accessors."""

        if simple_name in self.LOW_VALUE_METHOD_NAMES:
            return True
        file_path = str(impl.get("file") or "").replace("\\", "/")
        signature = str(impl.get("signature") or "")
        text = f"{context}\n{signature}"
        if simple_name.startswith("<"):
            return True
        if self.ACCESSOR_METHOD_RE.match(simple_name):
            return True
        if self.LOW_VALUE_PACKAGE_RE.search(file_path):
            if re.search(
                r"(?m)^\s*public\s+[A-Za-z0-9_<>, ?.\[\]]+\s+"
                + re.escape(simple_name)
                + r"\s*\([^)]*\)\s*\{",
                text,
            ):
                return True
            if "lombok." in text.lower() or re.search(
                r"@\s*(?:Data|Getter|Setter|Builder|Value)\b", text
            ):
                return True
        if "generated" in file_path.lower() or "/target/" in file_path or "/build/" in file_path:
            return True
        return False

    def _library_api_confidence(
        self,
        simple_name: str,
        impl: Dict[str, Any],
        context: str,
    ) -> float:
        file_path = str(impl.get("file") or "").replace("\\", "/").lower()
        text = context.lower()
        confidence = 0.62
        if "/service/" in file_path or "/service/" in text:
            confidence += 0.08
        if re.search(
            r"\b(?:request|param|payload|message|file|path|url|uri|cmd|command|sql|query|body|token|header)\b",
            text,
        ):
            confidence += 0.06
        if re.search(
            r"\b(?:save|update|delete|create|login|send|handle|process|upload|download|execute|query)\b",
            simple_name.lower(),
        ):
            confidence += 0.04
        return min(confidence, 0.74)

    def _list_methods_for_discovery(self) -> List[str]:
        if self.search_root:
            try:
                return self.code_index.list_functions(
                    limit=self.max_functions,
                    file_root=self.search_root,
                )
            except TypeError:
                pass
        return self.code_index.list_functions(limit=self.max_functions)

    def _get_method_impl(self, name: str) -> Optional[Dict[str, Any]]:
        if name in self._method_impl_cache:
            return self._method_impl_cache[name]
        try:
            impl = self.code_index.get_function_impl(name, include_context=False)
        except TypeError:
            impl = self.code_index.get_function_impl(name)
        self._method_impl_cache[name] = impl
        return impl

    def _method_context(self, impl: Dict[str, Any]) -> str:
        file_path = str(impl.get("file") or "")
        start_line = max(1, int(impl.get("start_line") or 1) - 16)
        end_line = max(
            start_line, int(impl.get("end_line") or impl.get("start_line") or start_line)
        )
        method_key = str(impl.get("qualified_name") or impl.get("func_name") or "")
        cache_key = f"{method_key}:{file_path}:{start_line}:{end_line}"
        if cache_key in self._context_cache:
            return self._context_cache[cache_key]

        code = str(impl.get("code") or "")
        snippet_text = ""
        if file_path and hasattr(self.code_index, "get_file_snippet"):
            try:
                snippet = self.code_index.get_file_snippet(file_path, start_line, end_line)
            except TypeError:
                snippet = None
            if isinstance(snippet, dict):
                snippet_text = str(snippet.get("code") or "")
        context = self._strip_number_prefixes(f"{snippet_text}\n{code}")
        self._context_cache[cache_key] = context
        return context

    @staticmethod
    def _strip_number_prefixes(code: str) -> str:
        return re.sub(r"^\s*\d+\s*\|\s*", "", str(code or ""), flags=re.MULTILINE)

    @staticmethod
    def _annotation_names(context: str) -> List[str]:
        names = []
        for match in re.finditer(r"@\s*([A-Za-z_][A-Za-z0-9_$.]*)", context):
            name = match.group(1).split(".")[-1]
            if name not in names:
                names.append(name)
        return names

    def _is_spring_web_entry(self, annotations: Sequence[str]) -> bool:
        return bool(set(annotations).intersection(self.WEB_MAPPING_ANNOTATIONS))

    def _is_jax_rs_entry(self, annotations: Sequence[str]) -> bool:
        ann = set(annotations)
        return "Path" in ann and bool(ann.intersection(self.JAX_RS_HTTP_ANNOTATIONS))

    def _is_servlet_entry(self, simple_name: str, context: str) -> bool:
        if simple_name not in self.SERVLET_METHODS:
            return False
        return "HttpServletRequest" in context or "ServletRequest" in context

    @staticmethod
    def _is_main_entry(simple_name: str, impl: Dict[str, Any], context: str) -> bool:
        signature = str(impl.get("signature") or "")
        text = f"{simple_name}\n{signature}\n{context}"
        return (
            simple_name == "main"
            and "static" in text
            and "void" in text
            and ("String[]" in text or "java.lang.String[]" in text or "String..." in text)
        )

    @staticmethod
    def _looks_like_cli_handler(simple_name: str, context: str) -> bool:
        return (
            simple_name in {"run", "call", "execute"}
            or "Callable<" in context
            or "Runnable" in context
        )

    def _is_library_public_api(
        self,
        simple_name: str,
        impl: Dict[str, Any],
        context: str,
        annotations: Sequence[str],
    ) -> bool:
        if simple_name in {"main"} or simple_name.startswith("<"):
            return False
        if self._is_servlet_entry(simple_name, context):
            return False
        if set(annotations).intersection(
            set(self.WEB_MAPPING_ANNOTATIONS)
            | set(self.JAX_RS_HTTP_ANNOTATIONS)
            | set(self.MESSAGE_ANNOTATIONS)
            | set(self.SCHEDULED_ANNOTATIONS)
            | set(self.CLI_ANNOTATIONS)
        ):
            return False
        file_path = str(impl.get("file") or "")
        if "/org/springframework/" in file_path or file_path.startswith(
            "src/main/java/org/springframework/"
        ):
            return False
        signature = str(impl.get("signature") or "")
        text = f"{context}\n{signature}"
        if " public " not in f" {text}" and not re.search(r"(?m)^\s*public\s+", text):
            return False
        if re.search(r"\b(?:private|protected)\s+" + re.escape(simple_name) + r"\s*\(", text):
            return False
        return "(" in text and ")" in text

    @staticmethod
    def _simple_method_name(name: str, impl: Dict[str, Any]) -> str:
        raw = str(impl.get("name") or name or "")
        if ":" in raw:
            raw = raw.split(":", 1)[0]
        if "." in raw:
            raw = raw.rsplit(".", 1)[-1]
        return raw

    def _annotation_reasons(self, annotations: Sequence[str], route: str = "") -> List[str]:
        reasons = [f"annotation:{annotation}" for annotation in annotations]
        if route:
            reasons.append(f"route:{route}")
        return sorted(set(reasons))

    @staticmethod
    def _route_hint(context: str) -> str:
        routes: List[str] = []
        for match in re.finditer(
            r"@\s*(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|Path)"
            r"\s*\((?P<args>[^)]*)\)",
            context,
        ):
            args = match.group("args")
            text_match = re.search(r'"([^"]+)"', args)
            if text_match:
                routes.append(text_match.group(1))
        return " ".join(dict.fromkeys(routes))

    def _merge_candidates(self, candidates: Iterable[EntryCandidate]) -> List[EntryCandidate]:
        by_name: Dict[str, EntryCandidate] = {}
        for candidate in candidates:
            existing = by_name.get(candidate.function_name)
            if not existing:
                by_name[candidate.function_name] = candidate
                continue
            exposures = list(
                dict.fromkeys(existing.exposure.split("+") + candidate.exposure.split("+"))
            )
            reasons = sorted(set(existing.reasons + candidate.reasons))
            prompts = [existing.custom_prompt, candidate.custom_prompt]
            existing.exposure = "+".join(exposures)
            existing.reasons = reasons
            existing.custom_prompt = " ".join(dict.fromkeys(p for p in prompts if p))
            existing.confidence = max(existing.confidence, candidate.confidence)
        return list(by_name.values())

    def _is_in_search_root(self, file_path: str) -> bool:
        if not self.search_root:
            return True
        if not file_path:
            return False
        resolved = self._resolve_candidate_path(file_path)
        try:
            resolved.relative_to(self.search_root)
            return True
        except ValueError:
            return False

    def _resolve_candidate_path(self, file_path: str) -> Path:
        path = Path(file_path)
        if path.is_absolute():
            return path.resolve()
        bases = [base for base in (self.source_root, self.project_root) if base is not None]
        candidates = [(base / path).resolve() for base in bases]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        if candidates:
            return candidates[0]
        return path.resolve()
