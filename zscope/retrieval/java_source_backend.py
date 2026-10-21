"""Java source-structure backend.

This backend owns Java source facts: classes, methods, annotations, parameters,
framework entry metadata, and a lightweight source-level call graph.  Joern,
SootUp, WALA, and CodeQL should be layered on top as signal providers rather
than being required for basic Java structure.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..common.portable import bundle_root, default_tool, java_jar
from ..semantics.java_frameworks import build_java_framework_semantics
from .backend_base import CodeBackend
from .java_models import JavaCallableRecord, JavaClassRecord
from .java_structure_db import JavaStructureDB
from .java_source_extractor import JavaSourceExtractor

logger = logging.getLogger(__name__)


class JavaSourceBackend(CodeBackend):
    """Backend that indexes Java source structure via Spoon/JavaParser style records."""

    def __init__(
        self,
        *,
        frontend: str = "auto",
        extractor_command: Optional[List[str]] = None,
        structure_db_path: str = "",
    ) -> None:
        self.requested_frontend = self._normalize_frontend(frontend)
        self.frontend = self.requested_frontend
        self.extractor_command = self._normalize_extractor_command(extractor_command)
        self.structure_db_path = str(structure_db_path or "")
        self.frontend_attempts: List[Dict[str, Any]] = []
        self.frontend_fallback_reason = ""
        self._source_path: Optional[Path] = None
        self._project_root: Optional[Path] = None
        self._status = "idle"
        self._classes: Dict[str, JavaClassRecord] = {}
        self._methods: Dict[str, JavaCallableRecord] = {}
        self._aliases: Dict[str, str] = {}
        self._callers: Dict[str, List[Dict[str, Any]]] = {}
        self._callees: Dict[str, List[Dict[str, Any]]] = {}
        self._structure_db: Optional[JavaStructureDB] = None

    @classmethod
    def _normalize_frontend(cls, frontend: str) -> str:
        text = str(frontend or "auto").strip().lower().replace("-", "_")
        return text if text in {"auto", "spoon", "javaparser", "builtin"} else "auto"

    def _normalize_extractor_command(self, extractor_command: Optional[List[str]]) -> List[str]:
        command = [str(part) for part in (extractor_command or []) if str(part).strip()]
        return command

    @classmethod
    def _ensure_default_spoon_jar(cls, source_root: Path, project_root: Path) -> tuple[str, str]:
        bundled = java_jar("structure-spoon")
        if bundled is not None:
            return str(bundled), ""
        if not cls._find_maven_project_root(project_root, source_root):
            return "", "pom.xml not found for Spoon MavenLauncher"
        mvn = shutil.which("mvn")
        if not mvn:
            return "", "mvn not found on PATH"
        repo_root = Path(__file__).resolve().parents[2]
        spoon_dir = repo_root / "tools" / "java-structure-spoon"
        jar = spoon_dir / "target" / "zscope-java-structure-spoon-0.1.0.jar"
        if jar.exists():
            return str(jar), ""
        pom = spoon_dir / "pom.xml"
        if not pom.exists():
            return "", f"missing Spoon sidecar pom: {pom}"
        try:
            subprocess.run(
                [mvn, "-q", "-DskipTests", "package"],
                cwd=str(spoon_dir),
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        except Exception as exc:
            return "", f"Spoon sidecar build failed to start: {exc}"
        if jar.exists():
            return str(jar), ""
        return "", f"Spoon sidecar build did not produce {jar}"

    @staticmethod
    def _ensure_default_javaparser_jar() -> tuple[str, str]:
        bundled = java_jar("structure-javaparser")
        if bundled is not None:
            return str(bundled), ""
        mvn = shutil.which("mvn")
        if not mvn:
            return "", "mvn not found on PATH"
        repo_root = Path(__file__).resolve().parents[2]
        parser_dir = repo_root / "tools" / "java-structure-javaparser"
        jar = parser_dir / "target" / "zscope-java-structure-javaparser-0.1.0.jar"
        if jar.exists():
            return str(jar), ""
        pom = parser_dir / "pom.xml"
        if not pom.exists():
            return "", f"missing JavaParser sidecar pom: {pom}"
        try:
            subprocess.run(
                [mvn, "-q", "-DskipTests", "package"],
                cwd=str(parser_dir),
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
        except Exception as exc:
            return "", f"JavaParser sidecar build failed to start: {exc}"
        if jar.exists():
            return str(jar), ""
        return "", f"JavaParser sidecar build did not produce {jar}"

    @staticmethod
    def _find_maven_project_root(project_root: Path, source_root: Path) -> Optional[Path]:
        for start in (project_root, source_root):
            cursor = Path(start).resolve()
            while cursor != cursor.parent:
                if (cursor / "pom.xml").exists():
                    return cursor
                cursor = cursor.parent
            if (cursor / "pom.xml").exists():
                return cursor
        return None

    def initialize(self, source_path: str, **kwargs) -> bool:
        self._status = "building"
        self._source_path = Path(source_path).resolve()
        self._project_root = Path(kwargs.get("project_root", source_path)).resolve()
        try:
            classes = self._extract_classes_with_fallbacks()
            self._load_classes(classes)
            self._persist_structure_db(classes)
            self._status = "ready"
            logger.info(
                "Java source backend indexed %d classes and %d methods using %s frontend",
                len(self._classes),
                len(self._methods),
                self.frontend,
            )
            return True
        except Exception as exc:
            logger.exception("Java source backend failed: %s", exc)
            self._status = "error"
            return False

    def _extract_classes_with_fallbacks(self) -> List[JavaClassRecord]:
        if self._source_path is None:
            raise RuntimeError("Java source path is not initialized")
        project_root = self._project_root or self._source_path
        self.frontend_attempts = []
        self.frontend_fallback_reason = ""
        last_reason = ""
        for frontend in self._frontend_plan():
            if frontend == "builtin":
                classes = JavaSourceExtractor(frontend="builtin").extract(
                    self._source_path,
                    project_root=project_root,
                )
                self.frontend = "builtin"
                self._record_frontend_attempt(frontend, "success", [], "")
                self.frontend_fallback_reason = last_reason
                return classes

            command, reason = self._command_for_frontend(frontend, self._source_path, project_root)
            if not command:
                last_reason = reason or "sidecar command unavailable"
                self._record_frontend_attempt(frontend, "skipped", [], last_reason)
                continue
            extractor = JavaSourceExtractor(frontend=frontend, extractor_command=command)
            classes = extractor.extract(
                self._source_path,
                project_root=project_root,
                allow_builtin_fallback=False,
            )
            if classes:
                self.frontend = frontend
                self._record_frontend_attempt(frontend, "success", command, "")
                self.frontend_fallback_reason = last_reason
                return classes
            last_reason = extractor.last_error or "sidecar returned no classes"
            self._record_frontend_attempt(frontend, "failed", command, last_reason)
        if self.extractor_command or bundle_root() is not None:
            raise RuntimeError(f"Java structure extraction failed: {last_reason}")
        self.frontend = "builtin"
        self.frontend_fallback_reason = last_reason
        return []

    def _frontend_plan(self) -> List[str]:
        if self.extractor_command:
            return ["spoon" if self.requested_frontend == "auto" else self.requested_frontend]
        if self.requested_frontend == "auto":
            return ["spoon", "javaparser"] if bundle_root() else ["spoon", "javaparser", "builtin"]
        if self.requested_frontend in {"spoon", "javaparser"}:
            return (
                [self.requested_frontend] if bundle_root() else [self.requested_frontend, "builtin"]
            )
        return ["builtin"]

    def _command_for_frontend(
        self,
        frontend: str,
        source_root: Path,
        project_root: Path,
    ) -> tuple[List[str], str]:
        if frontend == "spoon":
            if not self._find_maven_project_root(project_root, source_root):
                return [], "pom.xml not found for Spoon MavenLauncher"
            if not shutil.which("mvn"):
                return [], "mvn not found on PATH"
        if self.extractor_command and (
            self.requested_frontend == frontend
            or (self.requested_frontend == "auto" and frontend == "spoon")
        ):
            return list(self.extractor_command), ""
        if frontend == "spoon":
            jar, reason = self._ensure_default_spoon_jar(source_root, project_root)
            if not jar:
                return [], reason
            maven_root = self._find_maven_project_root(project_root, source_root) or project_root
            return [
                default_tool("java"),
                "-jar",
                jar,
                "--project-root",
                str(maven_root),
                "{source_root}",
            ], ""
        if frontend == "javaparser":
            jar, reason = self._ensure_default_javaparser_jar()
            if not jar:
                return [], reason
            return [
                default_tool("java"),
                "-jar",
                jar,
                "--project-root",
                "{project_root}",
                "{source_root}",
            ], ""
        return [], "unknown frontend"

    def _record_frontend_attempt(
        self,
        frontend: str,
        status: str,
        command: List[str],
        reason: str,
    ) -> None:
        self.frontend_attempts.append(
            {
                "frontend": frontend,
                "status": status,
                "command": list(command),
                "reason": reason,
            }
        )

    def close(self) -> None:
        if self._structure_db is not None:
            self._structure_db.close()
            self._structure_db = None
        self._status = "idle"

    def status(self) -> str:
        return self._status

    @property
    def source_path(self) -> Optional[str]:
        return str(self._source_path) if self._source_path else None

    @property
    def project_root(self) -> Optional[str]:
        return str(self._project_root) if self._project_root else None

    @property
    def structure_db(self) -> Optional[JavaStructureDB]:
        return self._structure_db

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        if self._status == "idle" and self._source_path is not None:
            self.initialize(
                str(self._source_path), project_root=self._project_root or self._source_path
            )
        result: Dict[str, Dict[str, Any]] = {}
        for full_name, method in self._methods.items():
            metadata = self._method_metadata(method)
            aliases = [
                method.name,
                full_name,
                full_name.split(":", 1)[0],
                f"{method.class_name}.{method.name}",
                f"{method.class_full_name}.{method.name}",
            ]
            metadata["aliases"] = [alias for alias in aliases if alias]
            result[full_name] = metadata
        return result

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        key = self._resolve_method_key(name)
        if not key:
            return None
        return self._method_metadata(self._methods[key])

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self.get_callees(name, limit=limit)

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        key = self._resolve_method_key(func_name)
        if not key:
            return []
        return list(self._callees.get(key, []))[:limit]

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        key = self._resolve_method_key(func_name)
        if not key:
            return []
        return list(self._callers.get(key, []))[:limit]

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        key = self._resolve_class_key(type_name)
        if not key:
            return None
        return self._classes[key].to_type_info()

    def list_type_infos(self) -> List[Dict[str, Any]]:
        """Return each extracted Java type once, including its complete source range."""
        unique: Dict[str, JavaClassRecord] = {}
        for record in self._classes.values():
            unique.setdefault(record.full_name, record)
        return [unique[name].to_type_info() for name in sorted(unique)]

    def get_data_flow(
        self,
        source_func: str,
        source_param: str,
        sink_pattern: str,
    ) -> List[Dict[str, Any]]:
        return []

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        return []

    def get_header_declared_functions(
        self,
        header_files: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        return []

    def _load_classes(self, classes: List[JavaClassRecord]) -> None:
        self._classes.clear()
        self._methods.clear()
        self._aliases.clear()
        self._callers.clear()
        self._callees.clear()
        for class_record in classes:
            self._classes[class_record.full_name] = class_record
            self._classes.setdefault(class_record.name, class_record)
            for method in class_record.methods:
                self._methods[method.qualified_name] = method
                self._register_alias(method.qualified_name, method.qualified_name)
                self._register_alias(method.name, method.qualified_name)
                self._register_alias(method.qualified_name.split(":", 1)[0], method.qualified_name)
                self._register_alias(f"{method.class_name}.{method.name}", method.qualified_name)
                self._register_alias(
                    f"{method.class_full_name}.{method.name}", method.qualified_name
                )
        self._build_call_graph()

    def _build_call_graph(self) -> None:
        simple_to_methods: Dict[str, List[JavaCallableRecord]] = {}
        class_method_to_key: Dict[tuple[str, str], str] = {}
        for key, method in self._methods.items():
            simple_to_methods.setdefault(method.name, []).append(method)
            class_method_to_key[(method.class_full_name, method.name)] = key
            class_method_to_key[(method.class_name, method.name)] = key

        for caller_key, method in self._methods.items():
            callees: List[Dict[str, Any]] = []
            for call in method.calls:
                if not isinstance(call, dict):
                    continue
                call_name = str(call.get("name") or call.get("method") or "")
                declared_full_name = str(call.get("fullName") or "")
                declaring_type = str(call.get("declaring_type") or "")
                target_key = declared_full_name if declared_full_name in self._methods else ""
                if not target_key and declaring_type:
                    target_key = class_method_to_key.get((declaring_type, call_name), "")
                if not target_key:
                    target_key = class_method_to_key.get((method.class_full_name, call_name), "")
                target_method: Optional[JavaCallableRecord] = None
                if target_key:
                    target_method = self._methods.get(target_key)
                elif len(simple_to_methods.get(call_name, [])) == 1:
                    target_method = simple_to_methods[call_name][0]
                    target_key = target_method.qualified_name
                if target_method is None:
                    callee_record = {
                        "name": call_name,
                        "fullName": call_name,
                        "filename": method.file,
                        "lineNumber": int(call.get("line") or 0),
                        "signature": "",
                        "language": "java",
                        "source": "java_source_structure_unresolved",
                    }
                else:
                    callee_record = {
                        "name": target_method.name,
                        "fullName": target_method.qualified_name,
                        "qualified_name": target_method.qualified_name,
                        "filename": target_method.file,
                        "lineNumber": target_method.start_line,
                        "signature": target_method.signature,
                        "language": "java",
                        "source": "java_source_structure",
                        "call_line": int(call.get("line") or 0),
                        "call_code": str(call.get("code") or ""),
                    }
                    self._callers.setdefault(target_key or target_method.qualified_name, []).append(
                        {
                            "name": method.name,
                            "fullName": caller_key,
                            "qualified_name": caller_key,
                            "filename": method.file,
                            "lineNumber": int(call.get("line") or method.start_line),
                            "signature": method.signature,
                            "language": "java",
                            "source": "java_source_structure",
                        }
                    )
                callees.append(callee_record)
            self._callees[caller_key] = self._dedupe_callees(callees)

    @staticmethod
    def _dedupe_callees(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        result: List[Dict[str, Any]] = []
        for row in rows:
            key = (
                row.get("fullName") or row.get("name"),
                row.get("lineNumber") or row.get("call_line") or 0,
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(row)
        return result

    def _method_metadata(self, method: JavaCallableRecord) -> Dict[str, Any]:
        metadata = method.to_method_metadata()
        metadata["framework_semantics"] = build_java_framework_semantics(metadata)
        metadata["structure_frontend"] = method.frontend
        metadata["structure_frontend_actual"] = self.frontend
        metadata["structure_frontend_attempts"] = list(self.frontend_attempts)
        if self.frontend_fallback_reason:
            metadata["structure_frontend_fallback_reason"] = self.frontend_fallback_reason
        metadata["structure_precision"] = method.to_method_metadata().get("structure_precision")
        if metadata["structure_precision"] == "regex_or_builtin_fallback":
            metadata.setdefault("analysis_limitations", []).append(
                "Java source structure was extracted by builtin fallback; prefer Spoon/JavaParser sidecar for full type and build semantics."
            )
        return metadata

    def _persist_structure_db(self, classes: List[JavaClassRecord]) -> None:
        if not self.structure_db_path:
            return
        method_metadata = {
            method.qualified_name: self._method_metadata(method)
            for class_record in classes
            for method in class_record.methods
        }
        if self._structure_db is None:
            self._structure_db = JavaStructureDB(self.structure_db_path)
        self._structure_db.replace_project(classes, method_metadata)

    def _resolve_method_key(self, name: str) -> str:
        raw = str(name or "").strip()
        if raw in self._methods:
            return raw
        if raw in self._aliases:
            return self._aliases[raw]
        if "(" in raw:
            head = raw.split("(", 1)[0]
            if head in self._aliases:
                return self._aliases[head]
        return ""

    def _resolve_class_key(self, name: str) -> str:
        raw = str(name or "").strip()
        if raw in self._classes:
            return raw
        simple = raw.rsplit(".", 1)[-1]
        return simple if simple in self._classes else ""

    def _register_alias(self, alias: str, key: str) -> None:
        alias = str(alias or "").strip()
        if not alias:
            return
        existing = self._aliases.get(alias)
        if existing and existing != key:
            self._aliases.pop(alias, None)
            return
        self._aliases[alias] = key
