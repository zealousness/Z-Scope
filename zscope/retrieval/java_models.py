"""Shared Java structure and signal records.

These records are the boundary between Java source frontends
(Spoon/JavaParser or the built-in fallback parser), graph/taint backends, and
the existing Z-SCOPE candidate pipeline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

JAVA_EVIDENCE_PRECISION_RANK = {
    "exact_flow": 90,
    "typed_callgraph_flow": 76,
    "framework_binding_flow": 64,
    "source_level_exact": 56,
    "source_level_approx": 48,
    "regex_or_builtin_fallback": 28,
}


def normalize_java_evidence_precision(value: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    return text if text in JAVA_EVIDENCE_PRECISION_RANK else "source_level_approx"


@dataclass(frozen=True)
class JavaAnnotationRecord:
    name: str
    code: str = ""
    full_name: str = ""
    line: int = -1

    def to_backend_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "fullName": self.full_name or self.name,
            "code": self.code or (f"@{self.name}" if self.name else ""),
            "lineNumber": self.line,
        }


@dataclass(frozen=True)
class JavaParameterRecord:
    name: str
    type_full_name: str = ""
    code: str = ""
    annotations: List[JavaAnnotationRecord] = field(default_factory=list)

    def to_backend_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "typeFullName": self.type_full_name,
            "code": self.code
            or " ".join(part for part in [self.type_full_name, self.name] if part),
            "annotations": [annotation.to_backend_dict() for annotation in self.annotations],
        }


@dataclass(frozen=True)
class JavaCallableRecord:
    name: str
    qualified_name: str
    class_name: str
    class_full_name: str
    package: str
    file: str
    start_line: int
    end_line: int
    signature: str
    declaration_code: str = ""
    return_type: str = ""
    parameters: List[JavaParameterRecord] = field(default_factory=list)
    annotations: List[JavaAnnotationRecord] = field(default_factory=list)
    class_annotations: List[JavaAnnotationRecord] = field(default_factory=list)
    calls: List[Dict[str, Any]] = field(default_factory=list)
    is_declaration: bool = False
    is_public: bool = False
    is_static: bool = False
    frontend: str = "builtin"
    precision: str = "source_level_approx"

    def to_method_metadata(self) -> Dict[str, Any]:
        parameter_annotations = [parameter.to_backend_dict() for parameter in self.parameters]
        return {
            "name": self.name,
            "fullName": self.qualified_name,
            "qualified_name": self.qualified_name,
            "method_full_name": self.qualified_name,
            "class_name": self.class_name,
            "class_full_name": self.class_full_name,
            "package": self.package,
            "filename": self.file,
            "file": self.file,
            "lineNumber": self.start_line,
            "lineNumberEnd": self.end_line,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "signature": self.signature,
            "code": self.declaration_code,
            "declaration_code": self.declaration_code,
            "return_type": self.return_type,
            "annotations": [annotation.to_backend_dict() for annotation in self.annotations],
            "parameterAnnotations": parameter_annotations,
            "parameter_annotations": parameter_annotations,
            "classAnnotations": [
                annotation.to_backend_dict() for annotation in self.class_annotations
            ],
            "class_annotations": [
                annotation.to_backend_dict() for annotation in self.class_annotations
            ],
            "calls": list(self.calls),
            "is_declaration": self.is_declaration,
            "is_public": self.is_public,
            "is_static": self.is_static,
            "language": "java",
            "frontend": self.frontend,
            "structure_precision": normalize_java_evidence_precision(self.precision),
        }


@dataclass(frozen=True)
class JavaClassRecord:
    name: str
    full_name: str
    package: str
    file: str
    start_line: int
    end_line: int
    kind: str = "class"
    annotations: List[JavaAnnotationRecord] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict)
    methods: List[JavaCallableRecord] = field(default_factory=list)

    def to_type_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "fullName": self.full_name,
            "kind": self.kind,
            "filename": self.file,
            "lineNumber": self.start_line,
            "lineNumberEnd": self.end_line,
            "members": [
                {"name": name, "typeFullName": type_name}
                for name, type_name in sorted(self.fields.items())
            ],
            "annotations": [annotation.to_backend_dict() for annotation in self.annotations],
            "language": "java",
        }


@dataclass(frozen=True)
class JavaCallEdge:
    caller: str
    callee: str
    call_name: str
    file: str = ""
    line: int = 0
    call_type: str = "source_structure"
    confidence: float = 0.55
    precision: str = "source_level_approx"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class JavaFlowSignal:
    rule_id: str
    category: str
    source: Dict[str, Any]
    sink: Dict[str, Any]
    path: List[Dict[str, Any]] = field(default_factory=list)
    score: float = 6.0
    provider: str = "java_signal"
    limitation: str = ""
    precision: str = "source_level_approx"
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class JavaProviderCapability:
    provider: str
    call_graph: bool = False
    data_flow: bool = False
    taint: bool = False
    path_problem: bool = False
    framework_semantics: bool = False
    precision: str = "source_level_approx"
    stage: str = "mvp"
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["precision"] = normalize_java_evidence_precision(self.precision)
        return data


@dataclass(frozen=True)
class JavaProviderStatus:
    provider: str
    available: bool
    initialized: bool = False
    degraded_reason: str = ""
    signals_collected: int = 0
    call_edges_collected: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class JavaProviderEvidence:
    provider: str
    rule_id: str
    category: str
    source: Dict[str, Any]
    sink: Dict[str, Any]
    path: List[Dict[str, Any]] = field(default_factory=list)
    guards: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    precision: str = "source_level_approx"
    confidence: float = 0.5
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["precision"] = normalize_java_evidence_precision(self.precision)
        return data
