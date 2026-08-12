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
from typing import Any, Dict, List, Optional, cast


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

    def collect_for_function(
        self,
        *,
        func_name: str,
        file_path: str,
        start_line: int = 0,
        end_line: int = 0,
    ) -> Dict[str, Any]:
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
        evidence["ast_dump"] = self._run_tool(ast_cmd, summary_kind="ast", func_name=func_name)
        evidence["cfg_dump"] = self._run_tool(cfg_cmd, summary_kind="cfg", func_name=func_name)
        evidence["status"] = "executed"
        return evidence

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
    ) -> Dict[str, Any]:
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout)
        except Exception as exc:
            return {"ok": False, "error": str(exc), "command": command}
        output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        result = {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "command": command,
            "excerpt": output[:4000],
            "line_count": len(output.splitlines()),
        }
        if summary_kind == "ast":
            result["summary"] = self._summarize_ast_json(output, func_name=func_name)
        elif summary_kind == "cfg":
            result["summary"] = self._summarize_cfg_dump(output, func_name=func_name)
        return result

    @classmethod
    def _summarize_ast_json(cls, output: str, *, func_name: str = "") -> Dict[str, Any]:
        try:
            root = json.loads(output)
        except json.JSONDecodeError as exc:
            return {"parse_ok": False, "error": str(exc), "function": func_name}
        if not isinstance(root, dict):
            return {"parse_ok": False, "error": "AST root is not an object", "function": func_name}
        functions: List[Dict[str, Any]] = []
        target_summary: Dict[str, Any] = {}
        for node in cls._walk_ast(root):
            if node.get("kind") != "FunctionDecl":
                continue
            name = str(node.get("name") or "")
            if not name:
                continue
            summary = cls._summarize_function_decl(node)
            functions.append(summary)
            if func_name and name == func_name:
                target_summary = summary
        return {
            "parse_ok": True,
            "function": func_name,
            "function_count": len(functions),
            "functions": functions[:24],
            "target_function": target_summary,
        }

    @classmethod
    def _summarize_function_decl(cls, node: Dict[str, Any]) -> Dict[str, Any]:
        var_decls: List[Dict[str, Any]] = []
        call_exprs: List[Dict[str, Any]] = []
        binary_ops: List[Dict[str, Any]] = []
        unary_ops: List[Dict[str, Any]] = []
        return_count = 0
        if_count = 0
        for child in cls._walk_ast(node):
            kind = str(child.get("kind") or "")
            if kind == "VarDecl":
                var_decls.append(
                    {
                        "name": str(child.get("name") or ""),
                        "type": cls._qual_type(child),
                        "line": cls._loc_line(child),
                    }
                )
            elif kind == "CallExpr":
                call_exprs.append(cls._call_expr_summary(child))
            elif kind == "BinaryOperator":
                binary_ops.append(
                    {
                        "opcode": str(child.get("opcode") or ""),
                        "line": cls._loc_line(child),
                        "type": cls._qual_type(child),
                    }
                )
            elif kind == "UnaryOperator":
                unary_ops.append(
                    {
                        "opcode": str(child.get("opcode") or ""),
                        "line": cls._loc_line(child),
                        "type": cls._qual_type(child),
                    }
                )
            elif kind == "ReturnStmt":
                return_count += 1
            elif kind == "IfStmt":
                if_count += 1
        return {
            "name": str(node.get("name") or ""),
            "line": cls._loc_line(node),
            "type": cls._qual_type(node),
            "storage_class": str(node.get("storageClass") or ""),
            "var_decls": var_decls[:32],
            "call_exprs": call_exprs[:32],
            "binary_ops": binary_ops[:32],
            "unary_ops": unary_ops[:32],
            "matcher_facts": cls._ast_matcher_facts(call_exprs, binary_ops, unary_ops),
            "return_count": return_count,
            "if_count": if_count,
        }

    @classmethod
    def _call_expr_summary(cls, node: Dict[str, Any]) -> Dict[str, Any]:
        inner = node.get("inner") if isinstance(node.get("inner"), list) else []
        args = inner[1:] if inner else []
        argument_refs = [cls._decl_refs_in_node(arg) for arg in args if isinstance(arg, dict)]
        return {
            "callee": cls._first_decl_ref_name(node),
            "line": cls._loc_line(node),
            "result_type": cls._qual_type(node),
            "arg_count": len(args),
            "argument_kinds": [str(arg.get("kind") or "") for arg in args if isinstance(arg, dict)][
                :8
            ],
            "argument_refs": argument_refs[:8],
            "first_argument_refs": argument_refs[0] if argument_refs else [],
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
            arg_refs = cls._flat_arg_refs(call)
            if callee not in cls._RESOURCE_RELEASES:
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
            if callee in cls._UNBOUNDED_COPY_SINKS:
                facts.append(cls._matcher_fact("clang_ast_unbounded_copy_sink", "bounds", call))
            elif callee in cls._COPY_SINKS:
                facts.append(cls._matcher_fact("clang_ast_copy_size_relation", "bounds", call))
            if callee in cls._FORMAT_SINKS:
                facts.append(
                    cls._matcher_fact("clang_ast_format_string_control", "format_string", call)
                )
            if callee in cls._COMMAND_SINKS:
                facts.append(
                    cls._matcher_fact("clang_ast_command_string_control", "command_injection", call)
                )
            if callee in cls._RESOURCE_ACQUIRES:
                acquire_count += 1
                facts.append(
                    cls._matcher_fact("clang_ast_resource_acquire_call", "resource_lifecycle", call)
                )
            if callee in cls._RESOURCE_RELEASES:
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
        blocks: Dict[str, Dict[str, Any]] = {}
        current = ""
        for raw in str(output or "").splitlines():
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
                        "successors": [],
                        "predecessors": [],
                    },
                )
                continue
            if not current:
                continue
            stmt = re.match(r"\s*\d+:\s*(?P<code>.+)$", line)
            if stmt:
                blocks[current]["statements"].append(stmt.group("code").strip())
                continue
            succ = re.search(r"\bSuccs\s*\([^)]*\):(?P<items>.*)$", line)
            if succ:
                blocks[current]["successors"].extend(cls._cfg_block_ids(succ.group("items")))
                continue
            pred = re.search(r"\bPreds\s*\([^)]*\):(?P<items>.*)$", line)
            if pred:
                blocks[current]["predecessors"].extend(cls._cfg_block_ids(pred.group("items")))
        block_list = list(blocks.values())
        return {
            "parse_ok": bool(blocks),
            "function": func_name,
            "block_count": len(block_list),
            "entry_blocks": [
                block["id"] for block in block_list if "ENTRY" in block.get("label", "")
            ],
            "exit_blocks": [
                block["id"] for block in block_list if "EXIT" in block.get("label", "")
            ],
            "edge_count": sum(len(block.get("successors", [])) for block in block_list),
            "blocks": [
                {
                    "id": block["id"],
                    "label": block.get("label", ""),
                    "successors": block.get("successors", [])[:8],
                    "predecessors": block.get("predecessors", [])[:8],
                    "statements": block.get("statements", [])[:8],
                }
                for block in block_list[:32]
            ],
        }

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
