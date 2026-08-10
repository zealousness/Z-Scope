"""Java source structure extraction.

The production boundary is JSON-friendly records.  Spoon and JavaParser
sidecars can emit the same contract; when no sidecar succeeds, this module uses
a conservative built-in parser so the rest of the Java architecture can be
exercised without Joern owning source structure.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .java_models import (
    JavaAnnotationRecord,
    JavaCallableRecord,
    JavaClassRecord,
    JavaParameterRecord,
)

logger = logging.getLogger(__name__)

_JAVA_METHOD_RE = re.compile(
    r"(?P<mods>(?:(?:public|protected|private|static|final|abstract|synchronized|native|strictfp|default)\s+)*)"
    r"(?:(?P<return>[A-Za-z_$][\w$.\[\]<>?,\s]*?)\s+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^()]*)\)"
    r"\s*(?:throws\s+[^{;]+)?(?P<tail>[{;])"
)
_ANNOTATION_RE = re.compile(r"@(?P<name>[A-Za-z_$][\w$.]*)(?P<args>\s*\([^)]*\))?")
_CALL_RE = re.compile(r"(?:(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*\(")
_CALL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "throw",
    "new",
    "super",
    "this",
    "try",
    "synchronized",
}
_SKIP_DIRS = {
    ".git",
    ".gradle",
    ".idea",
    "build",
    "generated",
    "generated-sources",
    "node_modules",
    "out",
    "target",
}


class JavaSourceExtractor:
    """Extract Java classes and methods from a source tree."""

    def __init__(
        self,
        *,
        frontend: str = "auto",
        extractor_command: Optional[Sequence[str]] = None,
    ) -> None:
        self.frontend = self._normalize_frontend(frontend)
        self.extractor_command = list(extractor_command or [])
        self.last_error = ""

    def extract(
        self,
        source_root: Path,
        *,
        project_root: Optional[Path] = None,
        allow_builtin_fallback: bool = True,
    ) -> List[JavaClassRecord]:
        source_root = Path(source_root).resolve()
        project_root = Path(project_root or source_root).resolve()
        sidecar = self._extract_with_sidecar(source_root, project_root)
        if sidecar is not None:
            return sidecar
        if not allow_builtin_fallback:
            return []
        return self._extract_builtin(source_root)

    @staticmethod
    def _normalize_frontend(frontend: str) -> str:
        text = str(frontend or "auto").strip().lower().replace("-", "_")
        if text in {"spoon", "javaparser", "builtin", "auto"}:
            return text
        return "auto"

    def _extract_with_sidecar(
        self, source_root: Path, project_root: Path
    ) -> Optional[List[JavaClassRecord]]:
        self.last_error = ""
        if not self.extractor_command:
            self.last_error = "no sidecar command configured"
            return None
        cmd = self._sidecar_command(source_root, project_root)
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(source_root),
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        except Exception as exc:
            self.last_error = f"failed to start: {exc}"
            logger.warning("Java structure sidecar failed to start: %s", exc)
            return None
        if proc.returncode != 0:
            self.last_error = (proc.stderr or proc.stdout or f"exit code {proc.returncode}")[-2000:]
            logger.warning("Java structure sidecar failed: %s", proc.stderr[-2000:])
            return None
        try:
            payload = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            self.last_error = "non-JSON output"
            logger.warning("Java structure sidecar returned non-JSON output")
            return None
        try:
            return self._classes_from_payload(payload, frontend=self.frontend)
        except Exception as exc:
            self.last_error = f"payload decode failed: {exc}"
            logger.warning("Java structure sidecar payload could not be decoded: %s", exc)
            return None

    def _sidecar_command(self, source_root: Path, project_root: Path) -> List[str]:
        command = [str(part) for part in self.extractor_command]
        source_text = str(source_root)
        project_text = str(project_root)
        has_placeholder = False
        result: List[str] = []
        for part in command:
            if "{source_root}" in part:
                has_placeholder = True
                part = part.replace("{source_root}", source_text)
            if "{project_root}" in part:
                has_placeholder = True
                part = part.replace("{project_root}", project_text)
            if "{source_root}" not in part and "{project_root}" not in part:
                result.append(part)
            else:
                result.append(part)
        if not has_placeholder:
            result.append(source_text)
        return result

    def _extract_builtin(self, source_root: Path) -> List[JavaClassRecord]:
        classes: List[JavaClassRecord] = []
        for path in self._java_files(source_root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            class_record = self._parse_file(source_root, path, text)
            if class_record is not None:
                classes.append(class_record)
        return classes

    @staticmethod
    def _java_files(source_root: Path) -> List[Path]:
        files: List[Path] = []
        for path in source_root.rglob("*.java"):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            files.append(path)
        return sorted(files)

    def _parse_file(self, source_root: Path, path: Path, text: str) -> Optional[JavaClassRecord]:
        lines = text.splitlines()
        package = self._package_name(text)
        class_match = re.search(
            r"\b(?P<kind>class|interface|enum|record)\s+(?P<name>[A-Za-z_$][\w$]*)\b",
            self._strip_comments_keep_lines(text),
        )
        if not class_match:
            return None
        class_name = class_match.group("name")
        kind = class_match.group("kind")
        full_name = f"{package}.{class_name}" if package else class_name
        class_line = text[: class_match.start()].count("\n") + 1
        class_annotations = self._leading_annotations(lines, class_line)
        fields = self._parse_fields(text)
        methods = self._parse_methods(
            source_root=source_root,
            path=path,
            lines=lines,
            package=package,
            class_name=class_name,
            class_full_name=full_name,
            class_annotations=class_annotations,
        )
        return JavaClassRecord(
            name=class_name,
            full_name=full_name,
            package=package,
            file=self._relative_path(source_root, path),
            start_line=class_line,
            end_line=len(lines),
            kind=kind,
            annotations=class_annotations,
            fields=fields,
            methods=methods,
        )

    def _parse_methods(
        self,
        *,
        source_root: Path,
        path: Path,
        lines: Sequence[str],
        package: str,
        class_name: str,
        class_full_name: str,
        class_annotations: Sequence[JavaAnnotationRecord],
    ) -> List[JavaCallableRecord]:
        text = "\n".join(lines)
        clean = self._strip_annotations_keep_lines(self._strip_comments_keep_lines(text))
        methods: List[JavaCallableRecord] = []
        for match in _JAVA_METHOD_RE.finditer(clean):
            if self._brace_depth_before(clean, match.start()) > 1:
                continue
            method_name = match.group("name")
            if method_name in _CALL_KEYWORDS:
                continue
            start_line = clean[: match.start()].count("\n") + 1
            declaration_line = clean[match.start() : match.end()].splitlines()[0].strip()
            if self._looks_like_control_statement(declaration_line):
                continue
            tail = match.group("tail")
            end_line = start_line
            if tail == "{":
                end_line = self._method_body_end_line(clean, match.end() - 1, start_line)
            params = self._parse_parameters(match.group("params") or "")
            return_type = (match.group("return") or "").strip()
            if not return_type and method_name == class_name:
                return_type = "void"
            signature = self._signature(return_type, params)
            qualified = f"{class_full_name}.{method_name}:{signature}"
            annotations = self._leading_annotations(lines, start_line)
            body = "\n".join(lines[start_line - 1 : max(start_line, end_line)])
            call_body = body
            if "{" in call_body:
                first, rest = call_body.split("{", 1)
                call_body = (" " * len(first)) + "{" + rest
            methods.append(
                JavaCallableRecord(
                    name=method_name,
                    qualified_name=qualified,
                    class_name=class_name,
                    class_full_name=class_full_name,
                    package=package,
                    file=self._relative_path(source_root, path),
                    start_line=start_line,
                    end_line=end_line,
                    signature=signature,
                    declaration_code=declaration_line.rstrip("{;").strip(),
                    return_type=return_type,
                    parameters=params,
                    annotations=list(annotations),
                    class_annotations=list(class_annotations),
                    calls=self._parse_calls(call_body, start_line),
                    is_declaration=tail == ";",
                    is_public="public" in str(match.group("mods") or "").split(),
                    is_static="static" in str(match.group("mods") or "").split(),
                    frontend=self.frontend if self.frontend != "auto" else "builtin",
                    precision=(
                        "regex_or_builtin_fallback"
                        if self.frontend in {"auto", "builtin"}
                        else "source_level_approx"
                    ),
                )
            )
        return methods

    @staticmethod
    def _strip_comments_keep_lines(text: str) -> str:
        text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        return re.sub(r"//.*", "", text)

    @staticmethod
    def _strip_annotations_keep_lines(text: str) -> str:
        return re.sub(r"(?m)^[ \t]*@[A-Za-z_$][\w$.]*(?:\s*\([^)]*\))?[ \t]*$", "", text)

    @staticmethod
    def _package_name(text: str) -> str:
        match = re.search(r"(?m)^\s*package\s+([\w.]+)\s*;", text)
        return match.group(1) if match else ""

    @staticmethod
    def _relative_path(source_root: Path, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(source_root.resolve())).replace("\\", "/")
        except ValueError:
            return str(path).replace("\\", "/")

    @classmethod
    def _leading_annotations(
        cls, lines: Sequence[str], line_number: int
    ) -> List[JavaAnnotationRecord]:
        annotations: List[JavaAnnotationRecord] = []
        idx = max(0, line_number - 2)
        while idx >= 0:
            raw = lines[idx].strip()
            if not raw:
                idx -= 1
                continue
            if raw.startswith("@"):
                annotations[:0] = cls._annotation_records(raw, idx + 1)
                idx -= 1
                continue
            break
        return annotations

    @staticmethod
    def _annotation_records(line: str, line_number: int) -> List[JavaAnnotationRecord]:
        records: List[JavaAnnotationRecord] = []
        for match in _ANNOTATION_RE.finditer(line):
            raw_name = match.group("name")
            args = match.group("args") or ""
            simple = raw_name.rsplit(".", 1)[-1]
            records.append(
                JavaAnnotationRecord(
                    name=simple,
                    full_name=raw_name,
                    code=f"@{raw_name}{args}",
                    line=line_number,
                )
            )
        return records

    @classmethod
    def _parse_parameters(cls, params_text: str) -> List[JavaParameterRecord]:
        params: List[JavaParameterRecord] = []
        for raw_param in cls._split_top_level(params_text, ","):
            raw = raw_param.strip()
            if not raw:
                continue
            annotations = cls._annotation_records(raw, -1)
            without_annotations = _ANNOTATION_RE.sub("", raw)
            without_annotations = re.sub(r"\bfinal\s+", "", without_annotations).strip()
            parts = without_annotations.rsplit(None, 1)
            if len(parts) != 2:
                continue
            type_name, name = parts
            name = name.strip().lstrip("...").strip()
            params.append(
                JavaParameterRecord(
                    name=name,
                    type_full_name=type_name.strip(),
                    code=raw,
                    annotations=annotations,
                )
            )
        return params

    @staticmethod
    def _split_top_level(text: str, delimiter: str) -> List[str]:
        parts: List[str] = []
        start = 0
        depth = 0
        for idx, ch in enumerate(text):
            if ch == "<":
                depth += 1
            elif ch == ">" and depth:
                depth -= 1
            elif ch == delimiter and depth == 0:
                parts.append(text[start:idx])
                start = idx + 1
        parts.append(text[start:])
        return parts

    @staticmethod
    def _signature(return_type: str, params: Sequence[JavaParameterRecord]) -> str:
        ret = re.sub(r"\s+", " ", str(return_type or "void").strip()) or "void"
        param_types = ",".join(re.sub(r"\s+", " ", p.type_full_name).strip() for p in params)
        return f"{ret}({param_types})"

    @staticmethod
    def _looks_like_control_statement(declaration: str) -> bool:
        return bool(
            re.match(r"^(?:if|for|while|switch|catch|try|return|throw)\b", declaration.strip())
        )

    @staticmethod
    def _brace_depth_before(text: str, index: int) -> int:
        depth = 0
        for ch in text[: max(0, index)]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
        return depth

    @staticmethod
    def _method_body_end_line(clean_text: str, open_brace_index: int, start_line: int) -> int:
        depth = 0
        for idx in range(open_brace_index, len(clean_text)):
            ch = clean_text[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return clean_text[: idx + 1].count("\n") + 1
        return start_line

    @staticmethod
    def _parse_fields(text: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        clean = JavaSourceExtractor._strip_comments_keep_lines(text)
        for line in clean.splitlines():
            stripped = line.strip()
            if not stripped.endswith(";") or "(" in stripped:
                continue
            match = re.search(
                r"(?:(?:private|protected|public|static|final|volatile|transient)\s+)*"
                r"(?P<type>[A-Za-z_$][\w$.\[\]<>?,\s]*)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:=.*)?;",
                stripped,
            )
            if match:
                fields[match.group("name")] = re.sub(r"\s+", " ", match.group("type")).strip()
        return fields

    @staticmethod
    def _parse_calls(body: str, start_line: int) -> List[Dict[str, Any]]:
        calls: List[Dict[str, Any]] = []
        for line_offset, raw_line in enumerate(body.splitlines()):
            line = re.sub(r'"(?:\\.|[^"\\])*"', '""', raw_line)
            for match in _CALL_RE.finditer(line):
                name = match.group("name")
                if name in _CALL_KEYWORDS:
                    continue
                calls.append(
                    {
                        "name": name,
                        "method": name,
                        "receiver": match.group("receiver") or "",
                        "code": raw_line.strip(),
                        "line": start_line + line_offset,
                        "arguments": JavaSourceExtractor._call_arguments(line, match.end() - 1),
                    }
                )
        return calls

    @staticmethod
    def _call_arguments(line: str, open_paren_index: int) -> List[str]:
        depth = 0
        start = open_paren_index + 1
        for idx in range(open_paren_index, len(line)):
            if line[idx] == "(":
                depth += 1
            elif line[idx] == ")":
                depth -= 1
                if depth == 0:
                    args = line[start:idx]
                    return [
                        part.strip()
                        for part in JavaSourceExtractor._split_top_level(args, ",")
                        if part.strip()
                    ]
        return []

    @staticmethod
    def _classes_from_payload(payload: Any, *, frontend: str) -> List[JavaClassRecord]:
        classes: List[JavaClassRecord] = []
        rows = (
            payload
            if isinstance(payload, list)
            else payload.get("classes", []) if isinstance(payload, dict) else []
        )
        for row in rows:
            if not isinstance(row, dict):
                continue
            annotations = [
                JavaAnnotationRecord(
                    name=str(a.get("name") or a.get("fullName") or "").rsplit(".", 1)[-1],
                    full_name=str(a.get("fullName") or a.get("name") or ""),
                    code=str(a.get("code") or ""),
                    line=int(a.get("lineNumber") or a.get("line") or -1),
                )
                for a in row.get("annotations", [])
                if isinstance(a, dict)
            ]
            methods = []
            package = str(row.get("package") or "")
            class_name = str(row.get("name") or row.get("class_name") or "")
            full_name = str(
                row.get("fullName")
                or row.get("full_name")
                or (f"{package}.{class_name}" if package else class_name)
            )
            for method in row.get("methods", []) or []:
                if not isinstance(method, dict):
                    continue
                metadata = dict(method)
                metadata.setdefault("class_name", class_name)
                metadata.setdefault("class_full_name", full_name)
                metadata.setdefault("package", package)
                metadata.setdefault("frontend", frontend)
                methods.append(_callable_from_mapping(metadata, annotations))
            classes.append(
                JavaClassRecord(
                    name=class_name,
                    full_name=full_name,
                    package=package,
                    file=str(row.get("file") or row.get("filename") or ""),
                    start_line=int(row.get("start_line") or row.get("lineNumber") or 1),
                    end_line=int(row.get("end_line") or row.get("lineNumberEnd") or 1),
                    kind=str(row.get("kind") or "class"),
                    annotations=annotations,
                    fields=dict(row.get("fields") or {}),
                    methods=methods,
                )
            )
        return classes


def _callable_from_mapping(
    row: Dict[str, Any], class_annotations: Sequence[JavaAnnotationRecord]
) -> JavaCallableRecord:
    annotations = [
        JavaAnnotationRecord(
            name=str(a.get("name") or a.get("fullName") or "").rsplit(".", 1)[-1],
            full_name=str(a.get("fullName") or a.get("name") or ""),
            code=str(a.get("code") or ""),
            line=int(a.get("lineNumber") or a.get("line") or -1),
        )
        for a in row.get("annotations", [])
        if isinstance(a, dict)
    ]
    params = []
    for param in row.get("parameters", []) or row.get("parameterAnnotations", []) or []:
        if not isinstance(param, dict):
            continue
        params.append(
            JavaParameterRecord(
                name=str(param.get("name") or ""),
                type_full_name=str(param.get("typeFullName") or param.get("type") or ""),
                code=str(param.get("code") or ""),
                annotations=[
                    JavaAnnotationRecord(
                        name=str(a.get("name") or a.get("fullName") or "").rsplit(".", 1)[-1],
                        full_name=str(a.get("fullName") or a.get("name") or ""),
                        code=str(a.get("code") or ""),
                        line=int(a.get("lineNumber") or a.get("line") or -1),
                    )
                    for a in param.get("annotations", [])
                    if isinstance(a, dict)
                ],
            )
        )
    class_full = str(row.get("class_full_name") or row.get("classFullName") or "")
    name = str(row.get("name") or "")
    signature = str(
        row.get("signature")
        or JavaSourceExtractor._signature(str(row.get("return_type") or "void"), params)
    )
    qualified = str(
        row.get("qualified_name") or row.get("fullName") or f"{class_full}.{name}:{signature}"
    )
    return JavaCallableRecord(
        name=name,
        qualified_name=qualified,
        class_name=str(row.get("class_name") or class_full.rsplit(".", 1)[-1]),
        class_full_name=class_full,
        package=str(row.get("package") or ""),
        file=str(row.get("file") or row.get("filename") or ""),
        start_line=int(row.get("start_line") or row.get("lineNumber") or 1),
        end_line=int(row.get("end_line") or row.get("lineNumberEnd") or row.get("start_line") or 1),
        signature=signature,
        declaration_code=str(row.get("declaration_code") or row.get("code") or ""),
        return_type=str(row.get("return_type") or ""),
        parameters=params,
        annotations=annotations,
        class_annotations=list(class_annotations),
        calls=list(row.get("calls") or []),
        is_declaration=bool(row.get("is_declaration") or row.get("declaration_only")),
        is_public=bool(row.get("is_public")),
        is_static=bool(row.get("is_static")),
        frontend=str(row.get("frontend") or "sidecar"),
        precision=str(
            row.get("precision") or row.get("structure_precision") or "framework_binding_flow"
        ),
    )
