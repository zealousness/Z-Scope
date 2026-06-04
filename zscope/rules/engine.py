"""
Rule engine for Z-SCOPE rule-driven analysis mode.
Executes Joern built-in/community rules and custom paired-function checks.
"""

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..common.joern_client import JoernClient
from ..config.user_config_store import UserConfigStore

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    category: str
    score: float
    func_name: str
    file_path: str
    line_number: int
    code_snippet: str = ""
    evidence: List[dict] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "score": self.score,
            "function": self.func_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "evidence": self.evidence,
        }


class RuleEngine:
    """Executes Joern rules and custom checks, returns RuleMatch list."""

    def __init__(self, joern_client: JoernClient, user_config: Optional[UserConfigStore] = None):
        self.joern = joern_client
        self.user_config = user_config

    def run_builtin_scan(self) -> List[RuleMatch]:
        """Run Joern built-in scan rules via run.scan."""
        result = self.joern.query("run.scan.toJson")
        return self._parse_scan_result(result)

    def run_custom_scripts(self, script_dir: str) -> List[RuleMatch]:
        """Run .sc scripts from a directory."""
        matches = []
        scripts = sorted(Path(script_dir).glob("*.sc"))
        for script in scripts:
            try:
                proc = subprocess.run(
                    [self.joern.joern_path, "--script", str(script)],
                    capture_output=True, text=True, timeout=300,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    try:
                        data = json.loads(proc.stdout)
                        matches.extend(self._parse_script_output(data, script.stem))
                    except json.JSONDecodeError:
                        logger.debug("Non-JSON output from %s", script.name)
            except Exception as e:
                logger.error("Script %s failed: %s", script.name, e)
        return matches

    def run_paired_function_checks(self) -> List[RuleMatch]:
        """Check paired functions (e.g. malloc/free) using CPGQL."""
        if not self.user_config:
            return []
        pairs = self.user_config.list_paired_functions()
        matches = []
        for pair in pairs:
            acq = pair["acquire_func"]
            rel = pair["release_func"]
            cat = pair.get("category", "resource")
            new_matches = self._check_one_pair(acq, rel, cat)
            matches.extend(new_matches)
        return matches

    def run_configured_data_flow_checks(self) -> List[RuleMatch]:
        """Check user-declared entry/source functions for flows into risky sinks."""
        if not self.user_config:
            return []
        sources = self._configured_source_functions()
        sinks = self._configured_sink_functions()
        if not sources or not sinks:
            return []
        matches: List[RuleMatch] = []
        for source in sources[:20]:
            for sink in sinks[:30]:
                matches.extend(self._check_source_to_sink_flow(source, sink))
        return matches

    def run_semantic_cpg_rule_library(self) -> List[RuleMatch]:
        """Run bounded CPG sink rules that become Validator-reviewed evidence."""
        matches = self._check_semantic_sink_calls(self._configured_sink_functions()[:80])
        matches.extend(self._check_semantic_operator_rules(self._operator_rule_specs()))
        return matches

    def _check_one_pair(self, acquire: str, release: str, category: str) -> List[RuleMatch]:
        """Check that every call to acquire has a matching release in the same function."""
        acquire_q = self._cpg_regex(acquire)
        release_q = self._cpg_regex(release)
        query = (
            f'cpg.method.filter(m => m.callee.name("{acquire_q}").nonEmpty '
            f'&& m.callee.name("{release_q}").isEmpty)'
            f'.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1))).l.toJson'
        )
        result = self.joern.query(query)
        if not isinstance(result, list):
            return []
        matches = []
        for item in result:
            name = item.get("name", "")
            if not name or name.startswith("<"):
                continue
            line_value = item.get("lineNumber", -1)
            matches.append(RuleMatch(
                rule_id=f"paired_{acquire}_{release}",
                rule_name=f"Missing {release} for {acquire}",
                category=category,
                score=6.0,
                func_name=name,
                file_path=str(item.get("filename", "")),
                line_number=int(line_value if line_value is not None else -1),
                evidence=[
                    {
                        "query_family": "paired_ownership_lifecycle",
                        "acquire": acquire,
                        "release": release,
                        "limitation": (
                            "Same-function release is missing in the CPG summary. The Validator "
                            "must check ownership transfer, caller cleanup, and custom release aliases."
                        ),
                    }
                ],
            ))
        return matches

    def _check_source_to_sink_flow(self, source: str, sink: Dict[str, str]) -> List[RuleMatch]:
        source_q = self._cpg_regex(source)
        sink_q = self._cpg_regex(sink["name"])
        query = (
            f'def src = cpg.method.name("{source_q}").parameter\n'
            f'def snk = cpg.call.name("{sink_q}").argument\n'
            f'sink(snk).reachableByFlows(source(src))'
            f'.map(f => Map("source" -> "{self._cpg_string(source)}", '
            f'"sink" -> "{self._cpg_string(sink["name"])}", '
            f'"category" -> "{self._cpg_string(sink["category"])}", '
            f'"path" -> f.elements.map(e => '
            f'Map("code" -> e.code, "lineNumber" -> e.lineNumber.getOrElse(-1), '
            f'"filename" -> e.file.name.headOption.getOrElse(""))).l'
            f')).l.toJson'
        )
        result = self.joern.query(query)
        if not isinstance(result, list):
            return []
        matches: List[RuleMatch] = []
        for item in result:
            if not isinstance(item, dict):
                continue
            path = item.get("path") if isinstance(item.get("path"), list) else []
            last = path[-1] if path and isinstance(path[-1], dict) else {}
            line_value = last.get("lineNumber", -1)
            file_path = str(last.get("filename") or "")
            code = str(last.get("code") or "")
            matches.append(
                RuleMatch(
                    rule_id=f"configured_data_flow_{source}_{sink['name']}",
                    rule_name=f"Configured data flow from {source} to {sink['name']}",
                    category=sink["category"],
                    score=7.0,
                    func_name=source,
                    file_path=file_path,
                    line_number=int(line_value if line_value is not None else -1),
                    code_snippet=code,
                    evidence=[
                        {
                            "source": source,
                            "sink": sink["name"],
                            "sink_category": sink["category"],
                            "path": path,
                            "source_kind": "user_config:function_intents",
                            "sink_kind": sink.get("kind", "configured_sink"),
                        }
                    ],
                )
            )
        return matches

    def _check_semantic_sink_calls(self, sinks: List[Dict[str, Any]]) -> List[RuleMatch]:
        sinks = [sink for sink in sinks if str(sink.get("name") or "").strip()]
        if not sinks:
            return []
        sink_regex = self._sink_name_regex(sinks)
        result = self._query_semantic_sink_rows(sink_regex, include_nearest=True)
        if not isinstance(result, list):
            result = self._query_semantic_sink_rows(sink_regex, include_nearest=False)
        if not isinstance(result, list):
            return []
        sink_by_name = {str(sink.get("name") or ""): sink for sink in sinks}
        strict_by_call = self._strict_control_evidence_by_call_regex(sink_regex)
        matches: List[RuleMatch] = []
        for item in result:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or item.get("name") or "")
            if not method or method.startswith("<"):
                continue
            line_value = item.get("lineNumber", -1)
            code = str(item.get("code") or "")
            callee = str(item.get("callee") or "")
            sink = sink_by_name.get(callee)
            if sink is None:
                continue
            strict = strict_by_call.get(self._call_key(method, line_value, code), {})
            if strict:
                item = {**item, **strict}
            argument_evidence = self._sink_argument_evidence(sink, item)
            matches.append(
                RuleMatch(
                    rule_id=f"joern_semantic_{callee}",
                    rule_name=f"Semantic CPG sink call: {callee}",
                    category=str(sink.get("category") or "backend_signal"),
                    score=self._semantic_sink_score(str(sink.get("category") or "")),
                    func_name=method,
                    file_path=str(item.get("filename") or ""),
                    line_number=int(line_value if line_value is not None else -1),
                    code_snippet=code,
                    evidence=[
                        {
                            "query_family": "semantic_cpg_rule_library",
                            "sink": callee,
                            "sink_category": sink.get("category"),
                            "sink_kind": sink.get("kind", "default_sink"),
                            "code": code,
                            **argument_evidence,
                            "limitation": (
                                "This CPG rule identifies a risky API call. The Validator must "
                                "confirm argument trust, size relation, format control, and path feasibility."
                            ),
                        }
                    ],
                )
            )
        return matches

    def _query_semantic_sink_rows(self, sink_regex: str, *, include_nearest: bool) -> Any:
        controls_expr = (
            f'"nearestControls" -> c.method.controlStructure'
            f'.filter(cs => cs.lineNumber.isDefined && c.lineNumber.isDefined && cs.lineNumber.get <= c.lineNumber.get)'
            f'.sortBy(cs => -cs.lineNumber.get).code.l.take(6), '
            if include_nearest
            else ""
        )
        query = (
            f'cpg.call.name("{sink_regex}")'
            f'.map(c => Map("method" -> c.method.name, '
            f'"filename" -> c.file.name.headOption.getOrElse(""), '
            f'"lineNumber" -> c.lineNumber.getOrElse(-1), '
            f'"code" -> c.code, "callee" -> c.name, '
            f'"arguments" -> c.argument.code.l, '
            f'{controls_expr}'
            f'"controls" -> c.method.controlStructure.code.l.take(8))).l.toJson'
        )
        return self._safe_query(query)

    def _check_semantic_operator_rules(self, specs: List[Dict[str, Any]]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for spec in specs:
            operators = [str(op) for op in spec.get("operators", []) if str(op)]
            if not operators:
                continue
            operator_regex = self._operator_name_regex(operators)
            result = self._query_semantic_operator_rows(operator_regex, include_nearest=True)
            if not isinstance(result, list):
                result = self._query_semantic_operator_rows(operator_regex, include_nearest=False)
            if not isinstance(result, list):
                continue
            strict_by_call = self._strict_control_evidence_by_call_regex(operator_regex)
            for item in result:
                if not isinstance(item, dict):
                    continue
                method = str(item.get("method") or "")
                if not method or method.startswith("<"):
                    continue
                operator = str(item.get("operator") or "")
                if operator not in operators:
                    continue
                line_value = item.get("lineNumber", -1)
                code = str(item.get("code") or "")
                strict = strict_by_call.get(self._call_key(method, line_value, code), {})
                if strict:
                    item = {**item, **strict}
                evidence = self._operator_argument_evidence(spec, item)
                matches.append(
                    RuleMatch(
                        rule_id=str(spec.get("rule_id") or "joern_operator_rule"),
                        rule_name=str(spec.get("rule_name") or f"Semantic CPG operator: {operator}"),
                        category=str(spec.get("category") or "backend_signal"),
                        score=float(spec.get("score") or 5.8),
                        func_name=method,
                        file_path=str(item.get("filename") or ""),
                        line_number=int(line_value if line_value is not None else -1),
                        code_snippet=code,
                        evidence=[
                            {
                                "query_family": "semantic_cpg_operator_rule_library",
                                "operator": operator,
                                "code": code,
                                **evidence,
                                "limitation": str(
                                    spec.get("limitation")
                                    or "This CPG operator rule is a syntactic candidate; Validator must confirm data/control feasibility."
                                ),
                            }
                        ],
                    )
                )
        return matches

    def _query_semantic_operator_rows(self, operator_regex: str, *, include_nearest: bool) -> Any:
        controls_expr = (
            f'"nearestControls" -> c.method.controlStructure'
            f'.filter(cs => cs.lineNumber.isDefined && c.lineNumber.isDefined && cs.lineNumber.get <= c.lineNumber.get)'
            f'.sortBy(cs => -cs.lineNumber.get).code.l.take(6), '
            if include_nearest
            else ""
        )
        query = (
            f'cpg.call.name("{operator_regex}").take(300)'
            f'.map(c => Map("method" -> c.method.name, '
            f'"filename" -> c.file.name.headOption.getOrElse(""), '
            f'"lineNumber" -> c.lineNumber.getOrElse(-1), '
            f'"code" -> c.code, "operator" -> c.name, '
            f'"arguments" -> c.argument.code.l, '
            f'{controls_expr}'
            f'"controls" -> c.method.controlStructure.code.l.take(8))).l.toJson'
        )
        return self._safe_query(query)

    def _safe_query(self, query: str) -> Any:
        try:
            return self.joern.query(query)
        except Exception as exc:
            logger.debug("Joern query failed: %s", exc)
            return None

    def _strict_control_evidence_by_call_regex(self, sink_regex: str) -> Dict[tuple[str, int, str], Dict[str, Any]]:
        query = (
            f'cpg.call.name("{sink_regex}")'
            f'.map(c => Map("method" -> c.method.name, '
            f'"lineNumber" -> c.lineNumber.getOrElse(-1), '
            f'"code" -> c.code, '
            f'"controlDependencies" -> c.controlledBy.code.l.take(8), '
            f'"dominators" -> c.dominatedBy.code.l.take(8))).l.toJson'
        )
        result = self._safe_query(query)
        if not isinstance(result, list):
            return {}
        mapping: Dict[tuple[str, int, str], Dict[str, Any]] = {}
        for item in result:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or "")
            line_value = int(item.get("lineNumber") or -1)
            code = str(item.get("code") or "")
            mapping[self._call_key(method, line_value, code)] = {
                "controlDependencies": item.get("controlDependencies") if isinstance(item.get("controlDependencies"), list) else [],
                "dominators": item.get("dominators") if isinstance(item.get("dominators"), list) else [],
            }
        return mapping

    @staticmethod
    def _call_key(method: str, line_value: Any, code: str) -> tuple[str, int, str]:
        try:
            line = int(line_value if line_value is not None else -1)
        except (TypeError, ValueError):
            line = -1
        return (str(method or ""), line, " ".join(str(code or "").split()))

    @staticmethod
    def _sink_argument_evidence(sink: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
        args = item.get("arguments") if isinstance(item.get("arguments"), list) else []
        controls = item.get("controls") if isinstance(item.get("controls"), list) else []
        category = str(sink.get("category") or "")
        kind = str(sink.get("kind") or "")
        evidence: Dict[str, Any] = {
            "arguments": [str(arg) for arg in args[:8]],
            "control_context": [str(ctrl) for ctrl in controls[:8]],
            "has_control_context": bool(controls),
        }
        if category == "buffer_overflow" or "copy" in kind:
            evidence["size_argument"] = str(args[2]) if len(args) >= 3 else ""
            evidence["destination_argument"] = str(args[0]) if args else ""
            evidence["source_argument"] = str(args[1]) if len(args) >= 2 else ""
            evidence["query_focus"] = "copy_sink_size_relation"
        elif category == "format_string" or "format" in kind:
            evidence["format_argument"] = RuleEngine._configured_arg(args, sink, "format_arg_index", 0)
            evidence["query_focus"] = "format_string_control"
        elif category == "command_injection" or "command" in kind:
            evidence["command_argument"] = RuleEngine._configured_arg(args, sink, "command_arg_index", 0)
            evidence["query_focus"] = "command_string_control"
        elif category == "path_traversal" or "path" in kind or "file" in kind:
            evidence["path_argument"] = RuleEngine._configured_arg(args, sink, "path_arg_index", 0)
            evidence["query_focus"] = "path_argument_control"
        elif category == "integer_overflow" or "allocation" in kind:
            evidence["allocation_size_argument"] = RuleEngine._configured_arg(args, sink, "size_arg_index", 0)
            if str(sink.get("name") or "") == "calloc" and len(args) >= 2:
                evidence["allocation_count_argument"] = str(args[0])
                evidence["allocation_element_size_argument"] = str(args[1])
            evidence["query_focus"] = "allocation_size_control"
        else:
            evidence["query_focus"] = "sink_call_argument_context"
        evidence.update(RuleEngine._control_dependency_evidence(evidence, item))
        return evidence

    @staticmethod
    def _operator_argument_evidence(spec: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
        args = item.get("arguments") if isinstance(item.get("arguments"), list) else []
        controls = item.get("controls") if isinstance(item.get("controls"), list) else []
        evidence: Dict[str, Any] = {
            "arguments": [str(arg) for arg in args[:8]],
            "control_context": [str(ctrl) for ctrl in controls[:8]],
            "has_control_context": bool(controls),
            "query_focus": str(spec.get("query_focus") or "operator_argument_context"),
        }
        operand_key = str(spec.get("operand_key") or "")
        if operand_key:
            evidence[operand_key] = RuleEngine._configured_arg(
                args,
                spec,
                "operand_index",
                int(spec.get("operand_index", 0) or 0),
            )
        evidence.update(RuleEngine._control_dependency_evidence(evidence, item))
        return evidence

    @staticmethod
    def _configured_arg(args: List[Any], sink: Dict[str, Any], key: str, fallback: int) -> str:
        try:
            index = int(sink.get(key, fallback))
        except (TypeError, ValueError):
            index = fallback
        return str(args[index]) if 0 <= index < len(args) else ""

    @staticmethod
    def _control_dependency_evidence(evidence: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
        strict_controls = item.get("controlDependencies") if isinstance(item.get("controlDependencies"), list) else []
        dominators = item.get("dominators") if isinstance(item.get("dominators"), list) else []
        nearest = item.get("nearestControls") if isinstance(item.get("nearestControls"), list) else []
        all_controls = list(strict_controls) if strict_controls else (list(nearest) if nearest else list(evidence.get("control_context") or []))
        interesting = [
            str(evidence.get(key) or "")
            for key in (
                "size_argument",
                "destination_argument",
                "source_argument",
                "format_argument",
                "command_argument",
                "path_argument",
                "allocation_size_argument",
                "allocation_count_argument",
                "allocation_element_size_argument",
                "divisor_argument",
                "shift_amount_argument",
                "pointer_argument",
            )
            if str(evidence.get(key) or "")
        ]
        relevant = []
        for control in all_controls:
            control_text = str(control)
            if any(re.search(rf"\b{re.escape(symbol)}\b", control_text) for symbol in interesting):
                relevant.append(control_text)
        relation = "no_relevant_guard_observed"
        if relevant:
            if evidence.get("size_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['size_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "size_argument_guarded"
            elif evidence.get("format_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['format_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "format_argument_guarded"
            elif evidence.get("command_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['command_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "command_argument_guarded"
            elif evidence.get("path_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['path_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "path_argument_guarded"
            elif evidence.get("allocation_size_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['allocation_size_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "allocation_size_guarded"
            elif evidence.get("divisor_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['divisor_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "divisor_guarded"
            elif evidence.get("shift_amount_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['shift_amount_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "shift_amount_guarded"
            elif evidence.get("pointer_argument") and any(
                re.search(rf"\b{re.escape(str(evidence['pointer_argument']))}\b", guard)
                for guard in relevant
            ):
                relation = "pointer_argument_guarded"
            else:
                relation = "sink_argument_guarded"
        return {
            "strict_control_dependencies": [str(ctrl) for ctrl in strict_controls[:8]],
            "dominator_context": [str(dom) for dom in dominators[:8]],
            "nearest_control_context": [str(ctrl) for ctrl in nearest[:6]],
            "relevant_control_context": relevant[:6],
            "guard_relation": relation,
            "control_dependency_precision": (
                "strict_cpg_control_dependency"
                if strict_controls or dominators
                else ("line_ordered_control_context" if nearest else "method_control_context")
            ),
        }

    @staticmethod
    def _semantic_sink_score(category: str) -> float:
        category = str(category or "").lower()
        if category in {"command_injection", "format_string"}:
            return 6.8
        if category in {"buffer_overflow", "bounds"}:
            return 6.5
        if category in {"path_traversal", "integer_overflow"}:
            return 6.2
        if category in {"null_pointer_dereference"}:
            return 6.1
        return 5.8

    def _configured_source_functions(self) -> List[str]:
        method = getattr(self.user_config, "list_function_intents", None)
        if not callable(method):
            return []
        try:
            rows = method()
        except Exception:
            return []
        names = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("symbol_name") or row.get("func_name") or "").strip()
            if name and name not in names:
                names.append(name)
        return names

    def _configured_sink_functions(self) -> List[Dict[str, str]]:
        defaults = [
            {"name": "memcpy", "category": "buffer_overflow", "kind": "default_copy_sink"},
            {"name": "memmove", "category": "buffer_overflow", "kind": "default_copy_sink"},
            {"name": "bcopy", "category": "buffer_overflow", "kind": "default_copy_sink"},
            {"name": "strcpy", "category": "buffer_overflow", "kind": "default_string_sink"},
            {"name": "strncpy", "category": "buffer_overflow", "kind": "default_string_sink"},
            {"name": "strcat", "category": "buffer_overflow", "kind": "default_string_sink"},
            {"name": "strncat", "category": "buffer_overflow", "kind": "default_string_sink"},
            {"name": "gets", "category": "buffer_overflow", "kind": "default_unsafe_input_sink"},
            {"name": "sprintf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "1"},
            {"name": "snprintf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "2"},
            {"name": "vsprintf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "1"},
            {"name": "vsnprintf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "2"},
            {"name": "printf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "0"},
            {"name": "fprintf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "1"},
            {"name": "vprintf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "0"},
            {"name": "vfprintf", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "1"},
            {"name": "syslog", "category": "format_string", "kind": "default_format_sink", "format_arg_index": "1"},
            {"name": "system", "category": "command_injection", "kind": "default_command_sink"},
            {"name": "popen", "category": "command_injection", "kind": "default_command_sink", "command_arg_index": "0"},
            {"name": "execl", "category": "command_injection", "kind": "default_exec_sink", "command_arg_index": "0"},
            {"name": "execlp", "category": "command_injection", "kind": "default_exec_sink", "command_arg_index": "0"},
            {"name": "execle", "category": "command_injection", "kind": "default_exec_sink", "command_arg_index": "0"},
            {"name": "execv", "category": "command_injection", "kind": "default_exec_sink", "command_arg_index": "0"},
            {"name": "execvp", "category": "command_injection", "kind": "default_exec_sink", "command_arg_index": "0"},
            {"name": "execve", "category": "command_injection", "kind": "default_exec_sink", "command_arg_index": "0"},
            {"name": "fopen", "category": "path_traversal", "kind": "default_file_path_sink", "path_arg_index": "0"},
            {"name": "open", "category": "path_traversal", "kind": "default_file_path_sink", "path_arg_index": "0"},
            {"name": "creat", "category": "path_traversal", "kind": "default_file_path_sink", "path_arg_index": "0"},
            {"name": "unlink", "category": "path_traversal", "kind": "default_file_path_sink", "path_arg_index": "0"},
            {"name": "remove", "category": "path_traversal", "kind": "default_file_path_sink", "path_arg_index": "0"},
            {"name": "rename", "category": "path_traversal", "kind": "default_file_path_sink", "path_arg_index": "0"},
            {"name": "malloc", "category": "integer_overflow", "kind": "default_allocation_size_sink", "size_arg_index": "0"},
            {"name": "calloc", "category": "integer_overflow", "kind": "default_allocation_size_sink", "size_arg_index": "1"},
            {"name": "realloc", "category": "integer_overflow", "kind": "default_allocation_size_sink", "size_arg_index": "1"},
        ]
        sinks = list(defaults)
        method = getattr(self.user_config, "list_external_functions", None)
        if not callable(method):
            return self._dedupe_sinks(sinks)
        try:
            rows = method()
        except Exception:
            return self._dedupe_sinks(sinks)
        for row in rows:
            if not isinstance(row, dict):
                continue
            kind = str(row.get("kind") or "").lower()
            name = str(row.get("func_name") or row.get("symbol_name") or "").strip()
            if not name:
                continue
            if kind == "copy":
                sinks.append({"name": name, "category": "buffer_overflow", "kind": "user_config:copy"})
            elif kind in {"format", "format_sink"}:
                sinks.append({"name": name, "category": "format_string", "kind": "user_config:format"})
            elif kind in {"command", "command_sink"}:
                sinks.append({"name": name, "category": "command_injection", "kind": "user_config:command"})
        return self._dedupe_sinks(sinks)

    @staticmethod
    def _operator_rule_specs() -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": "joern_operator_division_or_modulo",
                "rule_name": "Division or modulo operator with data-dependent divisor",
                "category": "integer_overflow",
                "score": 6.0,
                "operators": ["<operator>.division", "<operator>.modulo"],
                "operand_key": "divisor_argument",
                "operand_index": 1,
                "query_focus": "division_or_modulo_divisor_control",
                "limitation": (
                    "Validator must prove the divisor can be zero on a feasible path; "
                    "nearby guards and dominating checks are included as counter-evidence."
                ),
            },
            {
                "rule_id": "joern_operator_shift_amount",
                "rule_name": "Shift operator with data-dependent amount",
                "category": "integer_overflow",
                "score": 5.8,
                "operators": ["<operator>.shiftLeft", "<operator>.logicalShiftRight", "<operator>.arithmeticShiftRight"],
                "operand_key": "shift_amount_argument",
                "operand_index": 1,
                "query_focus": "shift_amount_range_control",
                "limitation": (
                    "Validator must check operand width, signedness, and whether the shift amount is range-limited."
                ),
            },
            {
                "rule_id": "joern_operator_pointer_dereference",
                "rule_name": "Pointer dereference requiring nullability review",
                "category": "null_pointer_dereference",
                "score": 5.9,
                "operators": ["<operator>.indirection"],
                "operand_key": "pointer_argument",
                "operand_index": 0,
                "query_focus": "pointer_nullability_control",
                "limitation": (
                    "Validator must confirm the pointer may be null and that no caller or dominating guard proves non-null."
                ),
            },
        ]

    @staticmethod
    def _dedupe_sinks(sinks: List[Dict[str, str]]) -> List[Dict[str, str]]:
        seen = set()
        result = []
        for sink in sinks:
            key = sink["name"]
            if key in seen:
                continue
            seen.add(key)
            result.append(sink)
        return result

    def _sink_name_regex(self, sinks: List[Dict[str, Any]]) -> str:
        names = [str(sink.get("name") or "").strip() for sink in sinks if str(sink.get("name") or "").strip()]
        if len(names) == 1:
            return self._cpg_regex(names[0])
        return "^(?:" + "|".join(self._cpg_regex(name) for name in names) + ")$"

    def _operator_name_regex(self, operators: List[str]) -> str:
        if len(operators) == 1:
            return self._cpg_regex(operators[0])
        return "^(?:" + "|".join(self._cpg_regex(operator) for operator in operators) + ")$"

    @staticmethod
    def _cpg_regex(value: str) -> str:
        return re.escape(str(value or "").strip())

    @staticmethod
    def _cpg_string(value: str) -> str:
        return str(value or "").replace("\\", "\\\\").replace('"', '\\"')

    def _parse_scan_result(self, result: Any) -> List[RuleMatch]:
        """Parse Joern run.scan JSON output."""
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                return []
        if not isinstance(result, list):
            return []
        matches = []
        for item in result:
            line_value = item.get("lineNumber", -1)
            matches.append(RuleMatch(
                rule_id=str(item.get("name", "unknown")),
                rule_name=str(item.get("title", item.get("name", ""))),
                category=str(item.get("tags", ["unknown"])[0] if item.get("tags") else "unknown"),
                score=float(item.get("score", 5.0)),
                func_name=str(item.get("methodFullName", item.get("methodName", ""))),
                file_path=str(item.get("filename", "")),
                line_number=int(line_value if line_value is not None else -1),
                code_snippet=str(item.get("code", "")),
                evidence=item.get("evidence", []),
            ))
        return matches

    def _parse_script_output(self, data: Any, script_name: str) -> List[RuleMatch]:
        """Parse custom script JSON output into RuleMatch list."""
        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []
        matches = []
        for item in data:
            if not isinstance(item, dict):
                continue
            line_value = item.get("line_number", item.get("lineNumber", -1))
            matches.append(RuleMatch(
                rule_id=str(item.get("rule_id", script_name)),
                rule_name=str(item.get("rule_name", script_name)),
                category=str(item.get("category", "custom")),
                score=float(item.get("score", 5.0)),
                func_name=str(item.get("function", item.get("func_name", ""))),
                file_path=str(item.get("file_path", item.get("filename", ""))),
                line_number=int(line_value if line_value is not None else -1),
                code_snippet=str(item.get("code_snippet", item.get("code", ""))),
                evidence=item.get("evidence", []),
            ))
        return matches
