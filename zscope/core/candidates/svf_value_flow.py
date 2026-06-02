"""SVF/Saber value-flow candidate normalization.

SVF and Saber produce backend facts, not final findings.  This adapter converts
KnowledgeDB taint/signature rows into the same evidence-only candidate shape
used by the local, Clang, graph, and backend-signal candidate layers.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Callable, Dict, Iterable, List, Optional

SourcePathResolver = Callable[[Dict[str, Any], str], Dict[str, Any]]


class SvfValueFlowCandidateGenerator:
    """Normalize SVF/Saber memory findings into validator-facing candidates."""

    _CWE_BY_CLASS = {
        "memory_leak": "CWE-401",
        "double_free": "CWE-415",
        "use_after_free": "CWE-416",
        "null_pointer_dereference": "CWE-476",
        "memory_safety": "CWE-664",
    }
    _SKILL_BY_CLASS = {
        "memory_leak": "resource_lifecycle",
        "double_free": "temporal_memory",
        "use_after_free": "temporal_memory",
        "null_pointer_dereference": "null_and_failure",
        "memory_safety": "resource_lifecycle",
    }

    def __init__(self, source_path_resolver: Optional[SourcePathResolver] = None):
        self.source_path_resolver = source_path_resolver

    def generate_issues(
        self,
        bugs: Iterable[Dict[str, Any]],
        *,
        entry_func: str = "",
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        allowed = set(allowed_skills) if allowed_skills is not None else None
        issues = []
        for bug in bugs:
            issue = self.bug_to_issue(dict(bug), entry_func=entry_func)
            skill = self._SKILL_BY_CLASS.get(str(issue.get("defect_class")), "resource_lifecycle")
            if allowed is not None and skill not in allowed:
                continue
            issues.append(issue)
        return self._dedupe(issues)

    def bug_to_issue(self, bug: Dict[str, Any], *, entry_func: str = "") -> Dict[str, Any]:
        bug_type = str(bug.get("bug_type") or bug.get("type") or "memory_safety")
        defect_class = self._class_from_bug_type(bug_type)
        file_path = str(bug.get("file_path") or "")
        line = int(bug.get("line") or bug.get("func_start") or 0)
        func = str(bug.get("func_name") or bug.get("source_func") or entry_func or "")
        source_func = str(bug.get("source_func") or func or "svf_source")
        sink_func = str(bug.get("sink_func") or bug_type or "svf_sink")
        tool = str(bug.get("tool") or "saber")
        svf_group = str(bug.get("svf_group") or "default")
        svf_groups = [
            str(group)
            for group in (bug.get("svf_groups") or [svf_group])
            if str(group)
        ]
        rule = f"svf_value_flow_{self._normalize_key(bug_type)}"
        candidate_id = self._candidate_id(defect_class, func, file_path, line, rule, source_func, sink_func)
        location = f"{file_path}:{line}" if file_path else f"{func}:{line}"
        positive = [
            f"{tool} reported `{bug_type}` at {location}",
            f"SVF source `{source_func}` flows to sink `{sink_func}`",
        ]
        if bug.get("signature"):
            positive.append(f"Clang function signature: {bug.get('signature')}")
        if bug.get("func_start") or bug.get("func_end"):
            positive.append(f"Containing function range: {bug.get('func_start', 0)}-{bug.get('func_end', 0)}")
        backend_path = self._normalize_backend_path(bug)
        if backend_path:
            positive.append("Backend value-flow path: " + self._format_backend_path(backend_path))
        negative = [
            "Validator must confirm source-to-sink feasibility on the concrete C path.",
            "Ownership transfer, wrapper semantics, and user configuration may suppress this candidate.",
        ]
        value_flow = {
            "tool": tool,
            "svf_group": svf_group,
            "svf_groups": svf_groups,
            "bug_type": bug_type,
            "source_func": source_func,
            "sink_func": sink_func,
            "function": func,
            "file": file_path,
            "line": line,
            "function_start": int(bug.get("func_start") or 0),
            "function_end": int(bug.get("func_end") or 0),
            "signature": str(bug.get("signature") or ""),
            "interprocedural": bool(source_func and sink_func and source_func != sink_func),
            "backend_path": backend_path,
            "raw_backend_row": self._compact_bug(bug),
        }
        source_path = self._resolve_source_path(bug, entry_func)
        if source_path:
            if source_path.get("complete_to_entry"):
                positive.append(
                    "Source-level reconstruction found entry call path: "
                    + " -> ".join(source_path.get("call_path") or [])
                )
            snippet = str(source_path.get("reported_snippet") or "").strip()
            if snippet:
                positive.append("Source snippet near SVF location: " + self._one_line(snippet))
            flow = source_path.get("source_level_flow") if isinstance(source_path.get("source_level_flow"), dict) else {}
            events = flow.get("events") if isinstance(flow.get("events"), list) else []
            if events:
                positive.append("Source-level flow events: " + self._format_flow_events(events))
            edges = flow.get("expression_edges") if isinstance(flow.get("expression_edges"), list) else []
            if edges:
                positive.append("Source-level expression edges: " + self._format_expression_edges(edges))
        evidence_pack = {
            "candidate_id": candidate_id,
            "candidate_source": "svf_value_flow",
            "checker": "svf_value_flow_checker",
            "defect_class": defect_class,
            "rule": rule,
            "source": {"expression": source_func, "file": file_path, "line": line},
            "sink": {"operation": sink_func, "file": file_path, "line": line},
            "path": {
                "function": func,
                "entry_function": entry_func,
                "backend": "SVF/Saber value-flow",
                "complete_in_function": False,
                "path_constraints": [
                    "SVF/Saber produced a backend memory/value-flow signal",
                    "validator must reconcile LLVM-level fact with source-level ownership semantics",
                ],
            },
            "value_flow": value_flow,
            "source_path": source_path,
            "positive_evidence": positive,
            "negative_evidence": negative,
            "evidence_refs": [],
        }
        confidence = self._confidence_for(defect_class)
        return {
            "id": candidate_id,
            "candidate_id": candidate_id,
            "function": func,
            "location": location,
            "category": defect_class,
            "subcategory": defect_class,
            "defect_class": defect_class,
            "finding_kind": "svf_value_flow_candidate",
            "candidate_source": "svf_value_flow",
            "evidence_checker": "svf_value_flow_checker",
            "rule": rule,
            "cwe": self._CWE_BY_CLASS.get(defect_class, ""),
            "description": f"SVF/Saber reported `{bug_type}` in `{func}`.",
            "root_cause": "SVF/Saber value-flow analysis produced a memory lifetime signal requiring source-level validation.",
            "suggested_fix": "Validate the reported flow, then fix the ownership, lifetime, or failure-path contract.",
            "confidence": confidence,
            "rule_confidence": confidence,
            "impact_level": "high" if defect_class in {"use_after_free", "double_free"} else "medium",
            "reasoning": self._readable_reasoning(defect_class, bug_type, func, location, source_func, sink_func),
            "source": source_func,
            "sink": sink_func,
            "dedup_key": "|".join([defect_class, file_path.replace("\\", "/").lower(), str(line), source_func, sink_func]),
            "positive_evidence": positive,
            "negative_evidence": negative,
            "evidence_pack": evidence_pack,
            "evidence_refs": [],
        }

    @classmethod
    def _class_from_bug_type(cls, bug_type: str) -> str:
        text = str(bug_type or "").replace("_", " ").replace("-", " ").lower()
        compact = re.sub(r"\s+", "", text)
        if "doublefree" in compact or "dfree" in compact:
            return "double_free"
        if "useafterfree" in compact or "uaf" in compact:
            return "use_after_free"
        if "neverfree" in compact or "leak" in text:
            return "memory_leak"
        if "null" in text:
            return "null_pointer_dereference"
        return "memory_safety"

    @staticmethod
    def _confidence_for(defect_class: str) -> float:
        if defect_class in {"use_after_free", "double_free"}:
            return 0.82
        if defect_class == "memory_leak":
            return 0.76
        return 0.7

    @staticmethod
    def _readable_reasoning(
        defect_class: str,
        bug_type: str,
        func: str,
        location: str,
        source_func: str,
        sink_func: str,
    ) -> str:
        return "\n".join(
            [
                f"SVF/Saber value-flow checker reported `{bug_type}` as `{defect_class}`.",
                f"Location: `{func}` at `{location}`.",
                f"Source: `{source_func}`.",
                f"Sink: `{sink_func}`.",
                "This is evidence only; Validator must confirm source-level reachability, ownership transfer, and guards.",
            ]
        )

    def _resolve_source_path(self, bug: Dict[str, Any], entry_func: str) -> Dict[str, Any]:
        if not self.source_path_resolver:
            return {}
        try:
            result = self.source_path_resolver(dict(bug), entry_func)
        except Exception as exc:
            return {
                "complete_to_entry": False,
                "reconstruction_error": str(exc),
            }
        return result if isinstance(result, dict) else {}

    @staticmethod
    def _one_line(value: str, limit: int = 220) -> str:
        compact = " ".join(str(value or "").split())
        return compact[: limit - 3] + "..." if len(compact) > limit else compact

    @classmethod
    def _format_flow_events(cls, events: List[Dict[str, Any]], limit: int = 260) -> str:
        parts = []
        for event in events[:5]:
            role = str(event.get("role") or "event")
            symbol = str(event.get("symbol") or "")
            file_path = str(event.get("file") or "")
            line = int(event.get("line") or 0)
            location = f"{file_path}:{line}" if file_path and line else file_path or str(line or "")
            parts.append(f"{role} `{symbol}` @ {location}".strip())
        return cls._one_line(" -> ".join(parts), limit=limit)

    @classmethod
    def _format_expression_edges(cls, edges: List[Dict[str, Any]], limit: int = 260) -> str:
        parts = []
        for edge in edges[:5]:
            shared = ",".join(str(item) for item in edge.get("shared_object_symbols") or [])
            suffix = f" via `{shared}`" if shared else ""
            parts.append(f"{edge.get('from_role')}->{edge.get('to_role')}{suffix}")
        return cls._one_line(" ; ".join(parts), limit=limit)

    @classmethod
    def _normalize_backend_path(cls, bug: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = (
            bug.get("backend_path")
            or bug.get("flow_path")
            or bug.get("path_elements")
            or bug.get("path")
            or bug.get("trace")
            or []
        )
        if isinstance(raw, str):
            rows: Iterable[Any] = [part.strip() for part in re.split(r"\s*(?:->|=>|\n)\s*", raw) if part.strip()]
        elif isinstance(raw, list):
            rows = raw
        else:
            return []
        result: List[Dict[str, Any]] = []
        for idx, item in enumerate(rows):
            if isinstance(item, dict):
                code = str(item.get("code") or item.get("statement") or item.get("expr") or item.get("node") or "")
                function = str(item.get("function") or item.get("func") or item.get("method") or "")
                file_path = str(item.get("file") or item.get("filename") or item.get("file_path") or "")
                line = int(item.get("line") or item.get("lineNumber") or 0)
                ssa_node = str(item.get("ssa_node") or item.get("ssa") or item.get("node_id") or item.get("id") or "")
                llvm_value = str(item.get("llvm_value") or item.get("value") or item.get("ir") or "")
                points_to = item.get("points_to") or item.get("pointsTo") or item.get("pointees") or []
                alias_set = item.get("alias_set") or item.get("aliasSet") or item.get("aliases") or []
                object_id = str(item.get("object_id") or item.get("objectId") or item.get("allocation_site") or "")
            else:
                code = str(item)
                function = ""
                file_path = ""
                line = 0
                ssa_node = ""
                llvm_value = ""
                points_to = []
                alias_set = []
                object_id = ""
            result.append(
                {
                    "index": idx,
                    "function": function,
                    "file": file_path,
                    "line": line,
                    "code": cls._one_line(code, limit=180),
                    "ssa_node": ssa_node,
                    "llvm_value": cls._one_line(llvm_value, limit=180),
                    "points_to": cls._string_list(points_to),
                    "alias_set": cls._string_list(alias_set),
                    "object_id": object_id,
                }
            )
        return result[:32]

    @staticmethod
    def _string_list(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item) for item in value if str(item)][:16]
        if isinstance(value, str) and value:
            return [value]
        return []

    @classmethod
    def _format_backend_path(cls, path: List[Dict[str, Any]], limit: int = 260) -> str:
        parts = []
        for item in path[:6]:
            label = str(item.get("function") or item.get("code") or item.get("index"))
            line = int(item.get("line") or 0)
            if line:
                label = f"{label}:{line}"
            parts.append(label)
        return cls._one_line(" -> ".join(parts), limit=limit)

    @staticmethod
    def _candidate_id(*parts: Any) -> str:
        digest = hashlib.sha1("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:12]
        return f"SVF_VALUE_FLOW_{digest}"

    @staticmethod
    def _normalize_key(value: str) -> str:
        return re.sub(r"[^a-z0-9_]+", "_", str(value or "").lower()).strip("_") or "memory_signal"

    @staticmethod
    def _compact_bug(bug: Dict[str, Any]) -> Dict[str, Any]:
        return {
            str(key): value
            for key, value in bug.items()
            if value not in (None, "", [], {})
        }

    @staticmethod
    def _dedupe(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = str(issue.get("dedup_key") or issue.get("candidate_id") or issue.get("id"))
            deduped.setdefault(key, issue)
        return list(deduped.values())
