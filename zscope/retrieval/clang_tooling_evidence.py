"""Optional Clang tooling evidence collection.

The main candidate checker can run without libclang or clang binaries.  When a
compile database and clang executable are available, this helper can attach
tool-level AST/CFG command metadata, and optionally short dump excerpts, to the
same evidence pack consumed by the Validator.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Mapping, Optional, Sequence, cast


def _as_dict(value: Any) -> Dict[str, Any]:
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


class ClangToolingEvidenceProvider:
    """Build and optionally execute clang AST/CFG evidence commands."""

    _COPY_SINKS = {"memcpy", "memmove", "strncpy", "snprintf"}
    _UNBOUNDED_COPY_SINKS = {"strcpy", "strcat", "sprintf", "gets"}
    _FORMAT_SINKS = {"printf", "fprintf", "sprintf", "snprintf", "syslog"}
    _COMMAND_SINKS = {"system", "popen", "execl", "execlp", "execle", "execv", "execvp"}
    _RESOURCE_ACQUIRES = {"malloc", "calloc", "realloc", "strdup", "strndup"}
    _RESOURCE_RELEASES = {"free", "delete"}

    def __init__(
        self,
        compile_commands_path: Optional[Path],
        *,
        clang_path: str = "clang",
        execute: Optional[bool] = None,
        timeout: int = 20,
    ):
        self.compile_commands_path = Path(compile_commands_path) if compile_commands_path else None
        self.clang_path = clang_path
        self.execute = bool(
            os.environ.get("ZSCOPE_ENABLE_CLANG_TOOLING") == "1" if execute is None else execute
        )
        self.timeout = timeout
        self._commands: Optional[List[Dict[str, Any]]] = None
        self._result_cache: Dict[tuple[str, str, int, int], Dict[str, Any]] = {}
        self._cache_lock = Lock()

    def collect_for_function(
        self,
        *,
        func_name: str,
        file_path: str,
        start_line: int = 0,
        end_line: int = 0,
    ) -> Dict[str, Any]:
        cache_key = (func_name, self._normalize_path(file_path), int(start_line), int(end_line))
        with self._cache_lock:
            cached = self._result_cache.get(cache_key)
            if cached is not None:
                return cast(Dict[str, Any], json.loads(json.dumps(cached, ensure_ascii=False)))
        command = self._compile_command_for(file_path)
        evidence: Dict[str, Any] = {
            "schema": "clang_tooling_evidence_v1",
            "function": func_name,
            "file": file_path,
            "range": {"start_line": start_line, "end_line": end_line},
            "compile_commands_path": str(self.compile_commands_path or ""),
            "compile_command_found": bool(command),
            "clang_path": self.clang_path,
            "execution_enabled": self.execute,
        }
        if not command:
            evidence["status"] = "compile_command_not_found"
            return evidence
        source_path = self._source_path(command)
        if source_path and source_path.is_file():
            try:
                import hashlib

                evidence["code_snapshot_sha256"] = hashlib.sha256(
                    source_path.read_bytes()
                ).hexdigest()
                evidence["resolved_source_file"] = str(source_path)
            except OSError:
                pass
        ast_cmd = self._tool_command(command, ast=True)
        cfg_cmd = self._tool_command(command, ast=False)
        evidence["ast_dump_command"] = ast_cmd
        evidence["cfg_dump_command"] = cfg_cmd
        if not self.execute:
            evidence["status"] = "command_prepared_not_executed"
            return evidence
        if not shutil.which(ast_cmd[0]):
            evidence["status"] = "clang_not_found"
            return evidence
        evidence["ast_dump"] = self._run_tool(
            ast_cmd,
            summary_kind="ast",
            func_name=func_name,
            source_path=source_path,
            start_line=start_line,
            end_line=end_line,
        )
        evidence["cfg_dump"] = self._run_tool(cfg_cmd, summary_kind="cfg", func_name=func_name)
        evidence["status"] = "executed"
        with self._cache_lock:
            self._result_cache[cache_key] = json.loads(json.dumps(evidence, ensure_ascii=False))
        return evidence

    @staticmethod
    def _source_path(compile_row: Dict[str, Any]) -> Optional[Path]:
        raw = str(compile_row.get("file") or "")
        if not raw:
            return None
        path = Path(raw)
        if not path.is_absolute():
            directory = Path(str(compile_row.get("directory") or "."))
            path = directory / path
        try:
            return path.resolve()
        except OSError:
            return path

    def _compile_command_for(self, file_path: str) -> Dict[str, Any]:
        target = self._normalize_path(file_path)
        for row in self._load_compile_commands():
            row_file = self._normalize_path(str(row.get("file") or ""))
            if (
                row_file == target
                or row_file.endswith("/" + target)
                or target.endswith("/" + row_file)
            ):
                return row
        return {}

    def _load_compile_commands(self) -> List[Dict[str, Any]]:
        if self._commands is not None:
            return self._commands
        if not self.compile_commands_path or not self.compile_commands_path.exists():
            self._commands = []
            return self._commands
        try:
            data = json.loads(self.compile_commands_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._commands = []
            return self._commands
        if isinstance(data, dict) and isinstance(data.get("commands"), list):
            data = data["commands"]
        self._commands = (
            [dict(item) for item in data if isinstance(item, dict)]
            if isinstance(data, list)
            else []
        )
        return self._commands

    def _tool_command(self, compile_row: Dict[str, Any], *, ast: bool) -> List[str]:
        args = self._compile_args(compile_row)
        if not args:
            return [self.clang_path]
        source_file = str(compile_row.get("file") or args[-1])
        filtered = self._filter_compile_args(args)
        if ast:
            return [
                self.clang_path,
                "-Xclang",
                "-ast-dump=json",
                "-fsyntax-only",
                *filtered,
                source_file,
            ]
        return [
            self.clang_path,
            "--analyze",
            "-Xclang",
            "-analyzer-checker=debug.DumpCFG",
            "-o",
            os.devnull,
            *filtered,
            source_file,
        ]

    @staticmethod
    def _compile_args(compile_row: Dict[str, Any]) -> List[str]:
        if isinstance(compile_row.get("arguments"), list):
            return [str(arg) for arg in compile_row["arguments"]]
        command = str(compile_row.get("command") or "")
        if not command:
            return []
        try:
            return shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return command.split()

    @staticmethod
    def _filter_compile_args(args: List[str]) -> List[str]:
        filtered: List[str] = []
        skip_next = False
        source_suffixes = (".c", ".cc", ".cpp", ".cxx", ".C")
        for idx, arg in enumerate(args[1:]):
            if skip_next:
                skip_next = False
                continue
            if arg in {"-c", "-S", "-E"}:
                continue
            if arg == "-o":
                skip_next = True
                continue
            if arg.startswith("-o"):
                continue
            if arg.endswith(source_suffixes):
                continue
            filtered.append(arg)
        return filtered

    def _run_tool(
        self,
        command: List[str],
        *,
        summary_kind: str = "",
        func_name: str = "",
        source_path: Optional[Path] = None,
        start_line: int = 0,
        end_line: int = 0,
    ) -> Dict[str, Any]:
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout)
        except Exception as exc:
            return {"ok": False, "error": str(exc), "command": command}
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        output = stdout + ("\n" + stderr if stderr else "")
        result = {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "command": command,
            "excerpt": output[:4000],
            "line_count": len(output.splitlines()),
        }
        if summary_kind == "ast":
            # Clang writes diagnostics to stderr even when the AST JSON on
            # stdout is complete.  Appending those diagnostics makes valid
            # JSON unparsable and silently strips every AST-derived call and
            # source location from FunctionIR.
            result["summary"] = self._summarize_ast_json(
                stdout,
                func_name=func_name,
                source_path=source_path,
                start_line=start_line,
                end_line=end_line,
            )
        elif summary_kind == "cfg":
            result["summary"] = self._summarize_cfg_dump(output, func_name=func_name)
        return result

    @classmethod
    def _summarize_ast_json(
        cls,
        output: str,
        *,
        func_name: str = "",
        source_path: Optional[Path] = None,
        start_line: int = 0,
        end_line: int = 0,
    ) -> Dict[str, Any]:
        try:
            root = json.loads(output)
        except json.JSONDecodeError as exc:
            return {"parse_ok": False, "error": str(exc), "function": func_name}
        if not isinstance(root, dict):
            return {"parse_ok": False, "error": "AST root is not an object", "function": func_name}
        source_offsets = cls._source_line_offsets(source_path)
        declarations = cls._walk_function_declarations(root)
        project_defined_names = frozenset(
            str(node.get("name") or "")
            for node, _qualified_name in declarations
            if cls._function_decl_is_definition(node) and str(node.get("name") or "")
        )
        project_defined_identities = frozenset(
            identity
            for node, _qualified_name in declarations
            if cls._function_decl_is_definition(node)
            for _name, identity in (cls._declaration_identity(node),)
            if identity
        )
        functions: List[Dict[str, Any]] = []
        target_definitions: List[Dict[str, Any]] = []
        for node, qualified_name in declarations:
            if node.get("kind") not in {"FunctionDecl", "CXXMethodDecl"}:
                continue
            name = str(node.get("name") or "")
            if not name:
                continue
            summary = cls._summarize_function_decl(
                node,
                source_offsets=source_offsets,
                qualified_name=qualified_name,
                project_defined_names=project_defined_names,
                project_defined_identities=project_defined_identities,
            )
            functions.append(summary)
            if not func_name or qualified_name != func_name:
                continue
            if not cls._function_decl_is_definition(node):
                continue
            line = int(summary.get("line") or 0)
            finish = int(summary.get("end_line") or line)
            if start_line and finish and finish < start_line:
                continue
            if end_line and line and line > end_line:
                continue
            target_definitions.append(summary)
        target_summary = target_definitions[0] if len(target_definitions) == 1 else {}
        return {
            "parse_ok": True,
            "function": func_name,
            "function_count": len(functions),
            "functions": functions[:24],
            "project_defined_function_names": sorted(project_defined_names),
            "project_defined_function_declarations": sorted(project_defined_identities),
            "target_function": target_summary,
            "target_function_unique": len(target_definitions) == 1,
        }

    @classmethod
    def _summarize_function_decl(
        cls,
        node: Dict[str, Any],
        *,
        source_offsets: Sequence[int] = (),
        qualified_name: str = "",
        project_defined_names: frozenset[str] = frozenset(),
        project_defined_identities: frozenset[str] = frozenset(),
    ) -> Dict[str, Any]:
        max_value_facts = 128
        parameters: List[Dict[str, Any]] = []
        var_decls: List[Dict[str, Any]] = []
        call_exprs: List[Dict[str, Any]] = []
        call_assignments: List[Dict[str, Any]] = []
        conversions: List[Dict[str, Any]] = []
        terminating_guards: List[Dict[str, Any]] = []
        binary_ops: List[Dict[str, Any]] = []
        unary_ops: List[Dict[str, Any]] = []
        return_count = 0
        if_count = 0
        located_nodes = cls._walk_ast_with_lines(node, source_offsets=source_offsets)
        node_lines = {id(child): line for child, line in located_nodes}
        for child, child_line in located_nodes:
            kind = str(child.get("kind") or "")
            if kind == "ParmVarDecl":
                parameters.append(
                    {
                        "name": str(child.get("name") or ""),
                        "type": cls._qual_type(child),
                        "line": child_line,
                    }
                )
            elif kind == "VarDecl":
                var_decls.append(
                    {
                        "name": str(child.get("name") or ""),
                        "type": cls._qual_type(child),
                        "line": child_line,
                        "storage_class": str(child.get("storageClass") or ""),
                    }
                )
                target = str(child.get("name") or "")
                for nested in cls._walk_ast(child):
                    if target and nested.get("kind") == "CallExpr":
                        call_assignments.append(
                            {
                                "target": target,
                                **cls._call_expr_summary(
                                    nested,
                                    line=node_lines.get(id(nested), child_line),
                                    project_defined_names=project_defined_names,
                                    project_defined_identities=project_defined_identities,
                                ),
                            }
                        )
                        break
            elif kind == "CallExpr":
                call_exprs.append(
                    cls._call_expr_summary(
                        child,
                        line=child_line,
                        project_defined_names=project_defined_names,
                        project_defined_identities=project_defined_identities,
                    )
                )
            elif kind == "BinaryOperator":
                raw_inner = child.get("inner")
                inner = raw_inner if isinstance(raw_inner, list) else []
                binary_ops.append(
                    {
                        "opcode": str(child.get("opcode") or ""),
                        "line": child_line,
                        "type": cls._qual_type(child),
                        "refs": cls._decl_refs_in_node(child),
                    }
                )
                if str(child.get("opcode") or "") == "=" and len(inner) >= 2:
                    targets = cls._decl_refs_in_node(inner[0])
                    for nested in cls._walk_ast(inner[1]):
                        if targets and nested.get("kind") == "CallExpr":
                            call_assignments.append(
                                {
                                    "target": targets[0],
                                    **cls._call_expr_summary(
                                        nested,
                                        line=node_lines.get(id(nested), child_line),
                                        project_defined_names=project_defined_names,
                                        project_defined_identities=project_defined_identities,
                                    ),
                                }
                            )
                            break
            elif kind == "UnaryOperator":
                unary_ops.append(
                    {
                        "opcode": str(child.get("opcode") or ""),
                        "line": child_line,
                        "type": cls._qual_type(child),
                    }
                )
            elif kind in {
                "ImplicitCastExpr",
                "CStyleCastExpr",
                "CXXStaticCastExpr",
                "CXXFunctionalCastExpr",
            }:
                raw_inner = child.get("inner")
                inner = raw_inner if isinstance(raw_inner, list) else []
                source = next((value for value in inner if isinstance(value, dict)), {})
                conversions.append(
                    {
                        "cast_kind": kind,
                        "line": child_line,
                        "source_type": cls._qual_type(source),
                        "target_type": cls._qual_type(child),
                        "refs": cls._decl_refs_in_node(child),
                    }
                )
            elif kind == "IfStmt":
                if_count += 1
                guard = cls._terminating_guard_summary(child)
                if guard:
                    terminating_guards.append(guard)
            elif kind == "ReturnStmt":
                return_count += 1
        value_fact_collections = (
            parameters,
            call_assignments,
            call_exprs,
            conversions,
            terminating_guards,
            binary_ops,
        )
        return {
            "name": qualified_name or str(node.get("name") or ""),
            "line": cls._node_line(node, source_offsets=source_offsets),
            "end_line": cls._node_end_line(node, source_offsets=source_offsets),
            "type": cls._qual_type(node),
            "storage_class": str(node.get("storageClass") or ""),
            "parameters": parameters[:max_value_facts],
            "var_decls": var_decls[:32],
            "call_exprs": call_exprs[:max_value_facts],
            "call_assignments": call_assignments[:max_value_facts],
            "conversions": conversions[:max_value_facts],
            "terminating_guards": terminating_guards[:max_value_facts],
            "binary_ops": binary_ops[:max_value_facts],
            "unary_ops": unary_ops[:32],
            "matcher_facts": cls._ast_matcher_facts(call_exprs, binary_ops, unary_ops),
            "value_fact_coverage_complete": (
                len(var_decls) <= 32
                and all(len(values) <= max_value_facts for values in value_fact_collections)
                and all(bool(value.get("callee_binding_complete")) for value in call_exprs)
            ),
            "return_count": return_count,
            "if_count": if_count,
        }

    @classmethod
    def _call_expr_summary(
        cls,
        node: Dict[str, Any],
        *,
        line: int = 0,
        project_defined_names: frozenset[str] = frozenset(),
        project_defined_identities: frozenset[str] = frozenset(),
    ) -> Dict[str, Any]:
        inner = node.get("inner") if isinstance(node.get("inner"), list) else []
        args = inner[1:] if inner else []
        argument_refs = [cls._decl_refs_in_node(arg) for arg in args if isinstance(arg, dict)]
        callee, declaration_identity = cls._direct_call_decl_identity(node)
        project_definition = bool(
            callee
            and callee in project_defined_names
            and declaration_identity in project_defined_identities
        )
        return {
            "callee": callee,
            "callee_decl_identity": declaration_identity,
            "callee_binding_complete": bool(callee and declaration_identity),
            "callee_decl_origin": (
                ("translation_unit_definition" if project_definition else "external_declaration")
                if callee and declaration_identity
                else "unresolved"
            ),
            "callee_project_definition": project_definition,
            "line": line or cls._loc_line(node),
            "result_type": cls._qual_type(node),
            "arg_count": len(args),
            "argument_kinds": [str(arg.get("kind") or "") for arg in args if isinstance(arg, dict)][
                :8
            ],
            "argument_types": [cls._qual_type(arg) for arg in args if isinstance(arg, dict)][:8],
            "argument_refs": argument_refs[:8],
            "argument_ref_types": [
                cls._decl_ref_types_in_node(arg) for arg in args if isinstance(arg, dict)
            ][:8],
            "first_argument_refs": argument_refs[0] if argument_refs else [],
        }

    @classmethod
    def _terminating_guard_summary(cls, node: Dict[str, Any]) -> Dict[str, Any]:
        raw_inner = node.get("inner")
        inner = raw_inner if isinstance(raw_inner, list) else []
        if len(inner) < 2 or not isinstance(inner[0], dict) or not isinstance(inner[1], dict):
            return {}
        condition = inner[0]
        then_branch = inner[1]
        if not any(value.get("kind") == "ReturnStmt" for value in cls._walk_ast(then_branch)):
            return {}
        comparisons: List[Dict[str, Any]] = []
        for value in cls._walk_ast(condition):
            if value.get("kind") != "BinaryOperator" or str(value.get("opcode") or "") not in {
                "<",
                "<=",
                ">",
                ">=",
                "==",
                "!=",
            }:
                continue
            raw_operands = value.get("inner")
            operands = raw_operands if isinstance(raw_operands, list) else []
            if len(operands) < 2 or not all(isinstance(item, dict) for item in operands[:2]):
                continue
            comparisons.append(
                {
                    "opcode": str(value.get("opcode") or ""),
                    "lhs_refs": cls._decl_refs_in_node(operands[0]),
                    "rhs_refs": cls._decl_refs_in_node(operands[1]),
                    "lhs_integer_literals": cls._integer_literals_in_node(operands[0]),
                    "rhs_integer_literals": cls._integer_literals_in_node(operands[1]),
                }
            )
        if not comparisons:
            return {}
        return {
            "line": cls._loc_line(node),
            "comparisons": comparisons[:16],
            "terminates_then_branch": True,
        }

    @classmethod
    def _ast_matcher_facts(
        cls,
        call_exprs: List[Dict[str, Any]],
        binary_ops: List[Dict[str, Any]],
        unary_ops: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        facts: List[Dict[str, Any]] = []
        acquire_count = 0
        release_count = 0
        released: Dict[str, Dict[str, Any]] = {}
        for call in call_exprs:
            callee = str(call.get("callee") or "")
            if not callee:
                continue
            project_definition = call.get("callee_project_definition") is True
            arg_refs = cls._flat_arg_refs(call)
            external_release = callee in cls._RESOURCE_RELEASES and not project_definition
            if not external_release:
                for arg in sorted(set(arg_refs) & set(released)):
                    facts.append(
                        {
                            "rule_id": "clang_ast_release_then_call_argument_use",
                            "category": "use_after_free",
                            "callee": callee,
                            "line": int(call.get("line") or 0),
                            "resource_symbol": arg,
                            "release_line": int(released[arg].get("line") or 0),
                            "use_line": int(call.get("line") or 0),
                            "validation": (
                                "AST call ordering shows a released symbol reused as a call argument; "
                                "Validator must confirm aliasing, path feasibility, and ownership."
                            ),
                        }
                    )
            if callee in cls._UNBOUNDED_COPY_SINKS and not project_definition:
                facts.append(cls._matcher_fact("clang_ast_unbounded_copy_sink", "bounds", call))
            elif callee in cls._COPY_SINKS and not project_definition:
                facts.append(cls._matcher_fact("clang_ast_copy_size_relation", "bounds", call))
            if callee in cls._FORMAT_SINKS and not project_definition:
                facts.append(
                    cls._matcher_fact("clang_ast_format_string_control", "format_string", call)
                )
            if callee in cls._COMMAND_SINKS and not project_definition:
                facts.append(
                    cls._matcher_fact("clang_ast_command_string_control", "command_injection", call)
                )
            if callee in cls._RESOURCE_ACQUIRES and not project_definition:
                acquire_count += 1
                facts.append(
                    cls._matcher_fact("clang_ast_resource_acquire_call", "resource_lifecycle", call)
                )
            if external_release:
                release_count += 1
                facts.append(
                    cls._matcher_fact("clang_ast_resource_release_call", "resource_lifecycle", call)
                )
                first_refs = [
                    str(item) for item in call.get("first_argument_refs") or [] if str(item)
                ]
                if first_refs:
                    resource = first_refs[0]
                    previous = released.get(resource)
                    if previous:
                        facts.append(
                            {
                                "rule_id": "clang_ast_same_argument_released_twice",
                                "category": "double_free",
                                "callee": callee,
                                "line": int(call.get("line") or 0),
                                "resource_symbol": resource,
                                "first_release_line": int(previous.get("line") or 0),
                                "second_release_line": int(call.get("line") or 0),
                                "validation": (
                                    "AST call ordering shows the same argument released twice; "
                                    "Validator must confirm path feasibility and aliasing."
                                ),
                            }
                        )
                    released[resource] = call
        if acquire_count or release_count:
            facts.append(
                {
                    "rule_id": "clang_ast_resource_balance_summary",
                    "category": "resource_lifecycle",
                    "acquire_call_count": acquire_count,
                    "release_call_count": release_count,
                    "binary_operator_count": len(binary_ops),
                    "unary_operator_count": len(unary_ops),
                    "validation": "Validator must check ownership transfer, aliasing, and path-sensitive balance.",
                }
            )
        return facts[:48]

    @staticmethod
    def _matcher_fact(rule_id: str, category: str, call: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "rule_id": rule_id,
            "category": category,
            "callee": str(call.get("callee") or ""),
            "line": int(call.get("line") or 0),
            "arg_count": int(call.get("arg_count") or 0),
            "argument_kinds": list(call.get("argument_kinds") or []),
            "argument_refs": list(call.get("argument_refs") or []),
            "first_argument_refs": list(call.get("first_argument_refs") or []),
            "validation": "AST matcher fact only; Validator must confirm data/control feasibility.",
        }

    @staticmethod
    def _flat_arg_refs(call: Dict[str, Any]) -> List[str]:
        refs: List[str] = []
        for item in call.get("argument_refs") or []:
            if isinstance(item, list):
                refs.extend(str(ref) for ref in item if str(ref))
        return refs

    @classmethod
    def _summarize_cfg_dump(cls, output: str, *, func_name: str = "") -> Dict[str, Any]:
        section, unique, section_error = cls._cfg_function_section(output, func_name=func_name)
        blocks: Dict[str, Dict[str, Any]] = {}
        expression_nodes: Dict[str, Dict[str, Any]] = {}
        expression_nodes_valid = True
        current = ""
        for raw in section.splitlines():
            line = raw.rstrip()
            header = re.match(r"\s*\[B(?P<id>\d+)(?P<label>[^\]]*)\]", line)
            if header:
                current = "B" + header.group("id")
                label = header.group("label") or ""
                blocks.setdefault(
                    current,
                    {
                        "id": current,
                        "label": label.strip(),
                        "statements": [],
                        "statement_nodes": [],
                        "successors": [],
                        "predecessors": [],
                    },
                )
                continue
            if not current:
                continue
            stmt = re.match(r"\s*(?P<number>\d+):\s*(?P<code>.+)$", line)
            if stmt:
                code = stmt.group("code").strip()
                ref = f"[{current}.{int(stmt.group('number'))}]"
                if ref in expression_nodes:
                    expression_nodes_valid = False
                node = {
                    "ref": ref,
                    "block": current,
                    "ordinal": len(blocks[current]["statement_nodes"]),
                    "code": code,
                }
                expression_nodes[ref] = node
                blocks[current]["statement_nodes"].append(node)
                blocks[current]["statements"].append(code)
                continue
            succ = re.search(r"\bSuccs\s*\([^)]*\):(?P<items>.*)$", line)
            if succ:
                blocks[current]["successors"].extend(cls._cfg_block_ids(succ.group("items")))
                continue
            pred = re.search(r"\bPreds\s*\([^)]*\):(?P<items>.*)$", line)
            if pred:
                blocks[current]["predecessors"].extend(cls._cfg_block_ids(pred.group("items")))
        block_list = list(blocks.values())
        semantic_by_block, semantic_complete = cls._cfg_semantic_statements(
            expression_nodes,
            valid=expression_nodes_valid,
        )
        return {
            "parse_ok": bool(blocks),
            "function": func_name,
            "function_section_unique": unique,
            "parse_error": section_error,
            "block_count": len(block_list),
            "entry_blocks": [
                block["id"] for block in block_list if "ENTRY" in block.get("label", "")
            ],
            "exit_blocks": [
                block["id"] for block in block_list if "EXIT" in block.get("label", "")
            ],
            "edge_count": sum(len(block.get("successors", [])) for block in block_list),
            "truncated": False,
            "semantic_statements_complete": semantic_complete,
            "blocks": [
                {
                    "id": block["id"],
                    "label": block.get("label", ""),
                    "successors": block.get("successors", []),
                    "predecessors": block.get("predecessors", []),
                    "statements": block.get("statements", []),
                    "semantic_statements": semantic_by_block.get(block["id"], []),
                }
                for block in block_list
            ],
        }

    @classmethod
    def _cfg_semantic_statements(
        cls,
        nodes: Mapping[str, Mapping[str, Any]],
        *,
        valid: bool,
    ) -> tuple[Dict[str, List[str]], bool]:
        """Collapse ``debug.DumpCFG`` expression fragments into root statements.

        Clang's numbered CFG entries form an expression DAG, not a list of C
        statements.  Treating every fragment as a statement can turn a cast
        annotation such as ``ssize_t (...)`` into a fabricated function call,
        while losing the enclosing ``memcpy``/``pthread_create`` expression.
        This reducer follows only Clang's explicit ``[B<n>.<m>]`` identities.
        Missing references, duplicate identities and cycles fail closed.

        Cast nodes are transparent here because their exact source/target
        types remain bound by the typed AST summary.  The resulting text is
        used only to bind a typed AST call/access to a reachable CFG node.
        """

        if not valid:
            return {}, False
        if not nodes:
            return {}, True
        reference_pattern = re.compile(r"\[B\d+\.\d+\]")
        referenced: set[str] = set()
        for value in nodes.values():
            refs = reference_pattern.findall(str(value.get("code") or ""))
            if any(ref not in nodes for ref in refs):
                return {}, False
            referenced.update(refs)

        rendered: Dict[str, str] = {}
        active: set[str] = set()

        def render(ref: str) -> str:
            if ref in rendered:
                return rendered[ref]
            if ref in active or ref not in nodes:
                raise ValueError("invalid_cfg_expression_graph")
            active.add(ref)
            code = str(nodes[ref].get("code") or "").strip()
            refs = reference_pattern.findall(code)
            if len(refs) == 1 and cls._cfg_is_transparent_cast(code, refs[0]):
                value = render(refs[0])
            else:
                value = code
                for child_ref in dict.fromkeys(refs):
                    child = render(child_ref)
                    # The parentheses around a reference are semantic when
                    # the preceding reference is a callee.  Stripping them
                    # turns ``[callee]([arg])`` into ``freearg``.  Preserve
                    # the CFG spelling and let transparent cast nodes remove
                    # only their *own* redundant wrapper.
                    value = value.replace(child_ref, child)
                value = re.sub(
                    r"(?<=[,(])(\s*)\(([0-9]+)\)(?=\s*[,)]\s*)",
                    r"\1\2",
                    value,
                )
            active.remove(ref)
            if not value.strip() or reference_pattern.search(value):
                raise ValueError("invalid_cfg_expression_projection")
            rendered[ref] = value.strip()
            return rendered[ref]

        roots = [
            ref
            for ref, value in sorted(
                nodes.items(),
                key=lambda item: (
                    str(item[1].get("block") or ""),
                    int(item[1].get("ordinal") or 0),
                ),
            )
            if ref not in referenced
        ]
        if not roots:
            return {}, False
        result: Dict[str, List[str]] = {}
        try:
            for ref in roots:
                node = nodes[ref]
                result.setdefault(str(node.get("block") or ""), []).append(render(ref))
        except ValueError:
            return {}, False
        # Every CFG node belongs to exactly one rendered root expression.  A
        # valid root plus a detached reference cycle must not make the partial
        # projection look complete.
        return result, len(rendered) == len(nodes)

    @staticmethod
    def _cfg_is_transparent_cast(code: str, ref: str) -> bool:
        escaped = re.escape(ref)
        return bool(
            re.fullmatch(rf"\s*\(\s*{escaped}\s*\)\s*", code)
            or re.fullmatch(
                rf"\s*\(?\s*{escaped}\s*\)?\s*" rf"\((?:ImplicitCastExpr|CStyleCastExpr),.*\)\s*",
                code,
            )
            or re.fullmatch(
                rf"\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*{escaped}\s*" rf"\(CStyleCastExpr,.*\)\s*",
                code,
            )
        )

    @staticmethod
    def _cfg_function_section(output: str, *, func_name: str) -> tuple[str, bool, str]:
        """Isolate one function from clang ``debug.DumpCFG`` output.

        Clang prints a declaration line immediately before each function's Bn
        blocks.  Reusing B0/B1 from another function would create a fabricated
        path certificate, so ambiguous sections fail closed.  A header-less
        snippet remains supported for deterministic unit fixtures.
        """

        text = str(output or "")
        lines = text.splitlines()
        headers: list[tuple[int, str]] = []
        for index, line in enumerate(lines):
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("[")
                or re.match(r"^\d+:\s", stripped)
                or "=" in stripped
            ):
                continue
            if re.search(r"\b[A-Za-z_]\w*\s*\([^;]*\)\s*(?:const)?\s*$", stripped):
                headers.append((index, stripped))
        if not headers:
            return text, True, ""
        matches = [
            (index, header)
            for index, header in headers
            if re.search(rf"\b{re.escape(func_name)}\s*\(", header)
        ]
        if len(matches) != 1:
            return "", False, "function_section_missing_or_ambiguous"
        start = matches[0][0] + 1
        following = [index for index, _ in headers if index > matches[0][0]]
        end = min(following) if following else len(lines)
        return "\n".join(lines[start:end]), True, ""

    @staticmethod
    def _cfg_block_ids(value: str) -> List[str]:
        return ["B" + item for item in re.findall(r"\bB(\d+)\b", value or "")]

    @classmethod
    def _walk_ast(cls, node: Any) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        if isinstance(node, dict):
            result.append(node)
            for child in node.get("inner") or []:
                result.extend(cls._walk_ast(child))
        elif isinstance(node, list):
            for child in node:
                result.extend(cls._walk_ast(child))
        return result

    @classmethod
    def _walk_function_declarations(
        cls,
        node: Any,
        scope: tuple[str, ...] = (),
    ) -> List[tuple[Dict[str, Any], str]]:
        result: List[tuple[Dict[str, Any], str]] = []
        if not isinstance(node, dict):
            return result
        kind = str(node.get("kind") or "")
        name = str(node.get("name") or "")
        next_scope = scope
        if kind in {"NamespaceDecl", "RecordDecl", "CXXRecordDecl"} and name:
            next_scope = (*scope, name)
        if kind in {"FunctionDecl", "CXXMethodDecl"} and name:
            qualified = "::".join((*scope, name)) if scope else name
            result.append((node, qualified))
        for child in node.get("inner") or []:
            result.extend(cls._walk_function_declarations(child, next_scope))
        return result

    @staticmethod
    def _function_decl_is_definition(node: Mapping[str, Any]) -> bool:
        return any(
            isinstance(child, dict) and child.get("kind") == "CompoundStmt"
            for child in node.get("inner") or []
        )

    @staticmethod
    def _source_line_offsets(source_path: Optional[Path]) -> tuple[int, ...]:
        if source_path is None:
            return ()
        try:
            raw = source_path.read_bytes()
        except OSError:
            return ()
        offsets = [0]
        offsets.extend(index + 1 for index, value in enumerate(raw) if value == 10)
        return tuple(offsets)

    @staticmethod
    def _line_for_offset(offsets: Sequence[int], offset: Any) -> int:
        if not offsets or not isinstance(offset, int) or offset < 0:
            return 0
        import bisect

        return bisect.bisect_right(offsets, offset)

    @classmethod
    def _node_line(
        cls,
        node: Mapping[str, Any],
        *,
        source_offsets: Sequence[int] = (),
        fallback: int = 0,
    ) -> int:
        loc = _as_dict(node.get("loc"))
        range_data = _as_dict(node.get("range"))
        begin = _as_dict(range_data.get("begin"))
        for value in (loc.get("line"), begin.get("line")):
            if isinstance(value, int) and value > 0:
                return value
        for value in (loc.get("offset"), begin.get("offset")):
            line = cls._line_for_offset(source_offsets, value)
            if line:
                return line
        return fallback

    @classmethod
    def _node_end_line(
        cls,
        node: Mapping[str, Any],
        *,
        source_offsets: Sequence[int] = (),
    ) -> int:
        range_data = _as_dict(node.get("range"))
        end = _as_dict(range_data.get("end"))
        value = end.get("line")
        if isinstance(value, int) and value > 0:
            return value
        return cls._line_for_offset(source_offsets, end.get("offset")) or cls._node_line(
            node,
            source_offsets=source_offsets,
        )

    @classmethod
    def _walk_ast_with_lines(
        cls,
        node: Any,
        *,
        source_offsets: Sequence[int],
        inherited_line: int = 0,
    ) -> List[tuple[Dict[str, Any], int]]:
        result: List[tuple[Dict[str, Any], int]] = []
        if not isinstance(node, dict):
            return result
        line = cls._node_line(node, source_offsets=source_offsets, fallback=inherited_line)
        result.append((node, line))
        for child in node.get("inner") or []:
            result.extend(
                cls._walk_ast_with_lines(
                    child,
                    source_offsets=source_offsets,
                    inherited_line=line,
                )
            )
        return result

    @classmethod
    def _direct_call_decl_identity(cls, node: Mapping[str, Any]) -> tuple[str, str]:
        inner = node.get("inner") if isinstance(node.get("inner"), list) else []
        if not inner or not isinstance(inner[0], dict):
            return "", ""
        callee_node: Mapping[str, Any] = inner[0]
        while str(callee_node.get("kind") or "") in {
            "ImplicitCastExpr",
            "ParenExpr",
            "CStyleCastExpr",
        }:
            children = [
                value for value in callee_node.get("inner") or [] if isinstance(value, dict)
            ]
            if len(children) != 1:
                return "", ""
            callee_node = children[0]
        if callee_node.get("kind") != "DeclRefExpr":
            return "", ""
        referenced = _as_dict(callee_node.get("referencedDecl"))
        return cls._declaration_identity(referenced)

    @classmethod
    def _declaration_identity(cls, declaration: Mapping[str, Any]) -> tuple[str, str]:
        declaration_kind = str(declaration.get("kind") or "")
        if declaration_kind not in {"FunctionDecl", "CXXMethodDecl"}:
            return "", ""
        name = str(declaration.get("name") or "")
        qual_type = cls._qual_type(dict(declaration))
        if not name or not qual_type:
            return "", ""
        # Do not persist Clang's process-local pointer-shaped declaration id.
        # Kind/name/type is deterministic across identical source artifacts;
        # overloads have distinct function types.
        identity = json.dumps(
            {"kind": declaration_kind, "name": name, "type": qual_type},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return name, identity

    @classmethod
    def _first_decl_ref_name(cls, node: Any) -> str:
        for child in cls._walk_ast(node):
            if child.get("kind") == "DeclRefExpr" and child.get("referencedDecl"):
                ref = _as_dict(child.get("referencedDecl"))
                return str(ref.get("name") or child.get("name") or "")
            if child.get("kind") == "DeclRefExpr" and child.get("name"):
                return str(child.get("name") or "")
        return ""

    @classmethod
    def _decl_refs_in_node(cls, node: Any) -> List[str]:
        refs: List[str] = []
        for child in cls._walk_ast(node):
            if not isinstance(child, dict) or child.get("kind") != "DeclRefExpr":
                continue
            ref_name = ""
            referenced = child.get("referencedDecl")
            if isinstance(referenced, dict):
                ref_name = str(referenced.get("name") or "")
            ref_name = ref_name or str(child.get("name") or "")
            if ref_name and ref_name not in refs:
                refs.append(ref_name)
        return refs[:8]

    @classmethod
    def _decl_ref_types_in_node(cls, node: Any) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for child in cls._walk_ast(node):
            if not isinstance(child, dict) or child.get("kind") != "DeclRefExpr":
                continue
            referenced = child.get("referencedDecl")
            referenced = referenced if isinstance(referenced, dict) else {}
            name = str(referenced.get("name") or child.get("name") or "")
            if not name:
                continue
            type_name = cls._qual_type(referenced) or cls._qual_type(child)
            result.setdefault(name, type_name)
        return dict(sorted(result.items()))

    @classmethod
    def _integer_literals_in_node(cls, node: Any) -> List[str]:
        values: List[str] = []
        for child in cls._walk_ast(node):
            if not isinstance(child, dict) or child.get("kind") != "IntegerLiteral":
                continue
            value = str(child.get("value") or "")
            if value and value not in values:
                values.append(value)
        return values[:8]

    @staticmethod
    def _qual_type(node: Dict[str, Any]) -> str:
        type_data = _as_dict(node.get("type"))
        return str(type_data.get("qualType") or "")

    @staticmethod
    def _loc_line(node: Dict[str, Any]) -> int:
        loc = _as_dict(node.get("loc"))
        line = loc.get("line")
        if isinstance(line, int):
            return line
        range_data = _as_dict(node.get("range"))
        begin = _as_dict(range_data.get("begin"))
        line = begin.get("line")
        return int(line) if isinstance(line, int) else 0

    @staticmethod
    def _normalize_path(path: str) -> str:
        return str(path or "").replace("\\", "/").lstrip("./")
