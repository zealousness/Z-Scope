"""Immutable compiler facts for review checks, separate from model projections.

The on-disk payload is never truncated. A complete compiler translation unit
is not a complete project call graph: that distinction is explicit throughout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, cast


FACT_VERSION = "zscope.complete-validation-facts.v4"
_STORE_LOCK = threading.Lock()


def scan_compiler_facts(index: Any, root: Path, commands: Path, directory: Path) -> "CompleteFactStore":
    """Share immutable compiler facts across candidate and validation workers."""
    key = (str(root.resolve()), str(commands.resolve()), str(directory.resolve()))
    with _STORE_LOCK:
        stores = getattr(index, "_complete_fact_stores", None)
        if stores is None:
            stores = {}
            setattr(index, "_complete_fact_stores", stores)
        if key not in stores:
            compiler = "clang"
            try:
                rows = json.loads(commands.read_text(encoding="utf-8"))
                drivers = set()
                for row in rows:
                    args = row.get("arguments") or shlex.split(row.get("command", ""))
                    driver = shutil.which(args[0]) or str(Path(row.get("directory") or root) / args[0])
                    drivers.add(str(Path(driver).resolve()))
                if len(drivers) == 1:
                    driver = next(iter(drivers))
                    if re.fullmatch(r"clang(?:\+\+)?(?:-[\d.]+)?", Path(driver).name):
                        compiler = driver
            except (OSError, ValueError, KeyError, IndexError, TypeError):
                pass  # The normal binding gate reports the precise failure.
            stores[key] = CompleteFactStore(root, commands, directory, clang=compiler)
        return cast(CompleteFactStore, stores[key])


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def preprocessor_current(probe: Any) -> bool:
    """Recheck positive and negative compiler lookups, not just old depfiles.

    Reusing AST/CFG is allowed only while the current preprocessed input matches.
    This also covers macro-computed includes, include_next and __has_include.
    Probe commands come from compiler-bound facts; proof callers authenticate the
    receipt before invoking this function. No shell or model-supplied command.
    """
    if not isinstance(probe, dict) or not probe.get("command") or not probe.get("sha256"):
        return False
    try:
        result = subprocess.run(
            probe["command"],
            cwd=probe["directory"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=probe["timeout"],
        )
        return (
            result.returncode == 0
            and hashlib.sha256(result.stdout.encode()).hexdigest() == probe["sha256"]
        )
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        return False


def walk_ast(node: Any) -> Iterable[Dict[str, Any]]:
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get("inner", []):
        yield from walk_ast(child)


def split_cfg(text: str, *, identity: str = "") -> list[Dict[str, Any]]:
    """Keep function-local block namespaces and every edge/statement.

    DumpCFG is diagnostic output, so unfamiliar/truncated layouts remain
    incomplete. Checkers must also identify the matching AST function.
    """
    functions: list[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    block: Optional[Dict[str, Any]] = None
    for raw in text.splitlines():
        if raw and not raw[0].isspace() and "(" in raw and not raw.startswith("warning:"):
            current = {"signature": raw, "blocks": [], "complete": False}
            functions.append(current)
            block = None
        header = re.match(r"\s*\[(B\d+)([^\]]*)\]", raw)
        if header and current is not None:
            block = {
                "id": header[1],
                "label": header[2].strip(),
                "statements": [],
                "successors": [],
                "predecessors": [],
            }
            current["blocks"].append(block)
        elif block is not None:
            edge = re.search(r"\b(Succs|Preds)\s*\((\d+)\):(.*)", raw)
            if edge:
                values = re.findall(r"\bB\d+\b", edge[3])
                block["successors" if edge[1] == "Succs" else "predecessors"] = values
                # Clang prints a pruned back-edge for do { ... } while (0),
                # including ordinary statement macros. Preserve that edge and
                # its constant-false proof instead of calling it missing CFG.
                terminator = next((s for s in block["statements"] if s.startswith("T: do ")), "")
                test = re.search(r"while \[(B\d+)\.(\d+)\]$", terminator)
                constant_false = bool(test and test[1] == block["id"] and
                    any(re.fullmatch(rf"{test[2]}:\s*0", s) for s in block["statements"]))
                pruned = (edge[1] == "Succs" and constant_false and int(edge[2]) == 2
                          and re.fullmatch(r"\s*NULL\s+B\d+\s*", edge[3]))
                if pruned:
                    block["pruned_successors"] = [{"slot": 0, "reason": "constant_false_do_while"}]
                elif len(values) != int(edge[2]) or "NULL" in edge[3]:
                    block["unresolved_edge"] = True
            elif raw.strip():
                block["statements"].append(raw.strip())
    for ordinal, fn in enumerate(functions):
        fn["function_local_id"] = (
            "CFG_FN_"
            + digest(
                {"translation_unit": identity, "signature": fn["signature"], "ordinal": ordinal}
            )[:24]
        )
        blocks = fn["blocks"]
        for item in blocks:
            item["qualified_id"] = fn["function_local_id"] + ":" + item["id"]
        ids = {b["id"] for b in blocks}
        fn["complete"] = bool(
            blocks
            and len(ids) == len(blocks)
            and sum("ENTRY" in b["label"] for b in blocks) == 1
            and sum("EXIT" in b["label"] for b in blocks) == 1
            and all(not b.get("unresolved_edge") for b in blocks)
            and all(e in ids for b in blocks for e in b["successors"] + b["predecessors"])
            and all(
                b["id"] in next(other for other in blocks if other["id"] == edge)["predecessors"]
                for b in blocks
                for edge in b["successors"]
                if edge in ids
            )
        )
    return functions


def macro_branches(source: str, file: str) -> list[Dict[str, Any]]:
    """Preserve source alternatives; never guess whether an alternative builds."""
    stack: list[Dict[str, Any]] = []
    records: list[Dict[str, Any]] = []
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        start = index + 1
        line = lines[index]
        while line.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            line = line.rstrip()[:-1] + lines[index]
        index += 1
        match = re.match(r"\s*#\s*(\w+)\b(.*)", line)
        if not match:
            continue
        kind, value = match[1], match[2].strip()
        if kind in {"if", "ifdef", "ifndef"}:
            predicate = value if kind == "if" else f"defined({value})"
            if kind == "ifndef":
                predicate = f"!({predicate})"
            stack.append({"seen": [predicate], "current": predicate})
        elif kind in {"elif", "else"} and stack:
            frame = stack[-1]
            excluded = " || ".join(f"({x})" for x in frame["seen"])
            frame["current"] = f"!({excluded})" + (f" && ({value})" if kind == "elif" else "")
            if kind == "elif":
                frame["seen"].append(value)
        elif kind == "endif" and stack:
            stack.pop()
        elif kind in {"define", "undef"}:
            defined = re.match(r"([A-Za-z_]\w*)(\([^)]*\))?(.*)", value)
            if not defined:
                continue
            body = defined[3].strip()
            records.append(
                {
                    "name": defined[1],
                    "parameters": defined[2] or "",
                    "body": body,
                    "file": file,
                    "line": start,
                    "directive": kind,
                    "condition": " && ".join(f"({f['current']})" for f in stack) or "1",
                    "empty_operation": kind == "define"
                    and bool(not body or re.fullmatch(r"do\s*\{\s*\}\s*while\s*\(\s*0\s*\)", body)),
                    "active": None,
                }
            )
    return records


class CompleteFactStore:
    """Compiler-backed immutable facts with dependency-checked disk reuse."""

    def __init__(
        self,
        project_root: Path,
        compile_commands: Path,
        directory: Path,
        *,
        clang: str = "clang",
        timeout: int = 60,
    ):
        self.project_root = project_root.resolve()
        self.compile_commands = compile_commands.resolve()
        self.directory = directory.resolve()
        self.clang = shutil.which(clang) or clang
        self.timeout = timeout
        self._lock = threading.RLock()
        self._cache: Dict[str, str] = {}
        self._collected: set[str] = set()
        self._decoded_facts: Dict[str, Any] = {}

    def driver_bound(self) -> bool:
        """Return True when every compile_commands driver is the fact compiler.

        The fact store derives claims with Clang; a database recorded for a
        GCC/cc build describes a different program (attribute annotations,
        errno expansion, macro-branch activity all differ).  One scan of the
        distinct drivers answers whether checked proofs can be issued at all.
        """
        fact_clang = Path(self.clang).resolve()
        try:
            rows = json.loads(self.compile_commands.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if not isinstance(rows, list) or not rows:
            return False
        drivers: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            command = row.get("arguments") or shlex.split(
                str(row.get("command", "")), posix=os.name != "nt"
            )
            if not command:
                return False
            driver = shutil.which(str(command[0]))
            if not driver:
                driver = str(
                    (Path(row.get("directory") or self.project_root) / str(command[0])).resolve()
                )
            drivers.add(str(Path(driver).resolve()))
        return bool(drivers) and drivers == {str(fact_clang)}

    def is_trusted(self, uid: str) -> bool:
        # A file with a self-consistent digest is not compiler provenance.
        # Restored checkpoints must collect again before issuing a proof.
        return uid in self._collected

    @staticmethod
    def compiler_environment() -> Dict[str, str]:
        return {
            key: os.environ.get(key, "")
            for key in (
                "CPATH",
                "C_INCLUDE_PATH",
                "CPLUS_INCLUDE_PATH",
                "OBJC_INCLUDE_PATH",
                "SDKROOT",
                "INCLUDE",
                "MACOSX_DEPLOYMENT_TARGET",
                "SOURCE_DATE_EPOCH",
                "CLANG_CONFIG_FILE_SYSTEM_DIR",
                "CLANG_CONFIG_FILE_USER_DIR",
            )
        }

    def _run(self, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.clang, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout,
        )

    def _row(self, file: Path) -> Dict[str, Any]:
        rows = json.loads(self.compile_commands.read_text(encoding="utf-8"))
        matches = []
        for row in rows:
            cwd = Path(row.get("directory") or self.project_root)
            source = Path(row.get("file") or "")
            if not source.is_absolute():
                source = cwd / source
            if source.resolve() == file.resolve():
                matches.append(row)
        unique = {digest(row): row for row in matches}
        if len(unique) != 1:
            raise ValueError("compile_command_missing_or_ambiguous")
        return next(iter(unique.values()))

    @staticmethod
    def _args(row: Dict[str, Any]) -> list[str]:
        args = row.get("arguments") or shlex.split(row.get("command", ""), posix=os.name != "nt")
        filtered: list[str] = []
        skip = False
        for arg in args[1:]:
            if skip:
                skip = False
                continue
            if arg in {"-o", "-MF", "-MT", "-MQ", "-MJ"}:
                skip = True
            elif arg in {"-c", "-S", "-E", "-MD", "-MMD", "-MP", "-MG"}:
                continue
            elif re.match(r"^-(?:o|MF|MT|MQ|MJ).+", arg):
                continue
            else:
                filtered.append(str(arg))
        return filtered

    @staticmethod
    def _hash_files(files: Iterable[str]) -> Dict[str, str]:
        return {
            name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in sorted(set(files))
        }

    def collect(self, file: str) -> Dict[str, Any]:
        """Failure yields explicit unknown; it never creates a partial proof."""
        with self._lock:
            try:
                source = Path(file)
                source = (
                    (self.project_root / source).resolve()
                    if not source.is_absolute()
                    else source.resolve()
                )
                source.relative_to(self.project_root)
                row = self._row(source)
                cwd = Path(row.get("directory") or self.project_root).resolve()
                command = row.get("arguments") or shlex.split(
                    row.get("command", ""), posix=os.name != "nt"
                )
                driver = shutil.which(command[0]) if command else None
                if not driver and command:
                    driver = str((cwd / command[0]).resolve())
                # Switching GCC/wrapper/target-prefixed drivers can change
                # predefined macros and ABI. Until an adapter binds those
                # semantics, do not certify the substituted Clang build.
                if not driver or Path(driver).resolve() != Path(self.clang).resolve():
                    raise ValueError("compile_driver_not_bound_to_fact_compiler")
                args = self._args(row)
                if any(
                    arg.startswith(
                        ("@", "-fplugin=", "-fmodule", "--config", "-include-pch", "-include-pth")
                    )
                    or arg in {"-load", "-fplugin"}
                    for arg in args
                ):
                    raise ValueError("unbound_response_file_or_compiler_plugin")
                version = self._run(["--version"], cwd)
                if version.returncode:
                    raise ValueError("compiler_identity_unavailable")
                compiler = {"path": str(Path(self.clang).resolve()), "version": version.stdout}
                environment = self.compiler_environment()
                key = digest(
                    {
                        "row": row,
                        "compiler": compiler,
                        "environment": environment,
                        "schema": FACT_VERSION,
                    }
                )
                cached = self._cache.get(key)
                if cached:
                    prior = self.load(cached)
                    if prior.get("complete"):
                        return self.descriptor(prior)
                dependencies = self._run([*args, "-M", "-MT", "zscope_facts"], cwd)
                if dependencies.returncode or ":" not in dependencies.stdout:
                    raise ValueError("dependency_inventory_failed")
                dep_text = re.sub(r"\\\r?\n", "", dependencies.stdout).split(":", 1)[1]
                names = [str((cwd / p).resolve()) for p in shlex.split(dep_text)]
                names.extend(
                    [str(source), str(self.compile_commands), str(Path(self.clang).resolve())]
                )
                before = self._hash_files(names)
                pp = self._run([*args, "-E", "-dD"], cwd)
                ast = self._run([*args, "-fsyntax-only", "-Xclang", "-ast-dump=json"], cwd)
                cfg = self._run(
                    [
                        *args,
                        "--analyze",
                        "-Xclang",
                        "-analyzer-checker=debug.DumpCFG",
                        "-o",
                        os.devnull,
                    ],
                    cwd,
                )
                if ast.returncode or cfg.returncode or pp.returncode:
                    failed = ast if ast.returncode else cfg if cfg.returncode else pp
                    raise ValueError("compiler_fact_extraction_failed: " + failed.stderr[-1000:])
                tree = json.loads(ast.stdout)
                after = self._hash_files(names)
                if before != after or environment != self.compiler_environment():
                    raise ValueError("dependencies_changed_during_extraction")
                probe = {
                    "command": [self.clang, *args, "-E", "-dD"],
                    "directory": str(cwd),
                    "timeout": self.timeout,
                    "sha256": hashlib.sha256(pp.stdout.encode()).hexdigest(),
                }
                if not preprocessor_current(probe):
                    raise ValueError("compiler_lookups_changed_during_extraction")
                macros: list[Dict[str, Any]] = []
                for name in before:
                    path = Path(name)
                    try:
                        path.relative_to(self.project_root)
                    except ValueError:
                        continue
                    if path.suffix.lower() in {
                        ".c",
                        ".cc",
                        ".cpp",
                        ".cxx",
                        ".h",
                        ".hh",
                        ".hpp",
                        ".hxx",
                        ".inc",
                        ".ph",
                    }:
                        macros.extend(macro_branches(path.read_text(encoding="utf-8"), name))
                # -dD retains source line markers and emits only active directives.
                active: Dict[str, tuple[str, int]] = {}
                executed: set[tuple[str, int]] = set()
                pp_file, pp_line = "", 0
                for line in pp.stdout.splitlines():
                    marker = re.match(r'#\s+(\d+)\s+"([^"]+)"', line)
                    if marker:
                        pp_line = int(marker[1])
                        pp_file = str((cwd / marker[2]).resolve())
                        continue
                    define = re.match(r"#define\s+(\w+)", line)
                    undef = re.match(r"#undef\s+(\w+)", line)
                    if define:
                        active[define[1]] = (pp_file, pp_line)
                        executed.add((pp_file, pp_line))
                    if undef:
                        active.pop(undef[1], None)
                        executed.add((pp_file, pp_line))
                    pp_line += 1
                for macro in macros:
                    macro["active"] = (macro["file"], macro["line"]) in executed
                    macro["final_definition"] = active.get(macro["name"]) == (
                        macro["file"],
                        macro["line"],
                    )
                    macro["use_site_semantics"] = "read_compiler_ast_at_expansion_location"
                    macro["alias"] = (
                        macro["body"] if re.fullmatch(r"[A-Za-z_]\w*", macro["body"]) else None
                    )
                payload = {
                    "schema_version": FACT_VERSION,
                    "source": str(source),
                    "compile_command": row,
                    "compiler": compiler,
                    "dependencies": before,
                    "complete": True,
                    "compiler_environment": environment,
                    "coverage_scope": "compiled_translation_unit",
                    "project_call_graph_complete": False,
                    "ast": tree,
                    "cfg": split_cfg(
                        cfg.stderr + "\n" + cfg.stdout,
                        identity=digest(
                            {"source": str(source), "dependencies": before, "compile_command": row}
                        ),
                    ),
                    "cfg_raw": cfg.stderr + "\n" + cfg.stdout,
                    "macros": macros,
                    "preprocessor": pp.stdout,
                    "preprocessor_probe": probe,
                }
                uid = "CF_" + digest(payload)
                payload["fact_store_id"] = uid
                self.directory.mkdir(parents=True, exist_ok=True)
                target = self.directory / f"{uid}.json"
                temporary = target.with_suffix(f".{uuid.uuid4().hex}.tmp")
                temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                temporary.replace(target)
                self._cache[key] = uid
                self._collected.add(uid)
                return self.descriptor(payload)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                return {
                    "schema_version": FACT_VERSION,
                    "complete": False,
                    "reason": str(exc)[:300],
                    "coverage_scope": "unknown",
                }

    def load(self, uid: str) -> Dict[str, Any]:
        if not re.fullmatch(r"CF_[0-9a-f]{64}", uid):
            return {"complete": False, "reason": "invalid_fact_store_id"}
        # A self-consistent disk payload is not permission to run its probe.
        # Restored evidence must be collected using this store's bound command.
        if uid not in self._collected:
            return {"complete": False, "reason": "compiler_lookup_requires_current_collection"}
        try:
            from ..reporting.shared_objects import ObjectEncoder, ObjectDecoder
            path = self.directory / f"{uid}.json"
            stat = path.stat()
            stamp = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
            with self._lock:
                cached = self._decoded_facts.get(uid)
                if cached is not None and cached[0] == stamp:
                    decoder = cached[1]
                    data = decoder.decode(decoder.root_node)
                else:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    raw = {k: v for k, v in data.items() if k != "fact_store_id"}
                    if "CF_" + digest(raw) != uid:
                        raise ValueError("fact_payload_tampered")
                    envelope = ObjectEncoder().envelope(data)
                    decoder = ObjectDecoder(envelope)
                    self._decoded_facts[uid] = (stamp, decoder)
                    data = decoder.root
            if self._hash_files(data["dependencies"]) != data["dependencies"]:
                raise ValueError("stale_fact_dependencies")
            if data.get("compiler_environment") != self.compiler_environment():
                raise ValueError("stale_compiler_environment")
            if not preprocessor_current(data.get("preprocessor_probe")):
                raise ValueError("stale_compiler_lookup_dependencies")
            return cast(Dict[str, Any], data)
        except (OSError, ValueError, KeyError) as exc:
            return {"complete": False, "reason": str(exc)}

    @staticmethod
    def descriptor(data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: data.get(key)
            for key in (
                "schema_version",
                "fact_store_id",
                "complete",
                "coverage_scope",
                "project_call_graph_complete",
                "source",
                "compiler",
            )
        }

    def query(
        self, uid: str, kind: str, *, offset: int = 0, limit: int = 20, symbol: str = ""
    ) -> Dict[str, Any]:
        data = self.load(uid)
        if not data.get("complete"):
            return data
        if kind == "ast_nodes":
            roots = (
                [
                    n
                    for n in walk_ast(data["ast"])
                    if n.get("kind") == "FunctionDecl" and n.get("name") == symbol
                ]
                if symbol
                else [data["ast"]]
            )
            values = [
                {
                    **{k: v for k, v in n.items() if k != "inner"},
                    "children": [c.get("id") for c in n.get("inner", [])],
                }
                for root in roots
                for n in walk_ast(root)
            ]
        elif kind == "functions":
            values = [
                n
                for n in walk_ast(data["ast"])
                if n.get("kind") == "FunctionDecl"
                and any(c.get("kind") == "CompoundStmt" for c in n.get("inner", []))
            ]
            values = [n for n in values if not symbol or n.get("name") == symbol]
        elif kind == "types":
            values = [
                n
                for n in walk_ast(data["ast"])
                if n.get("kind") in {"RecordDecl", "CXXRecordDecl"}
                and n.get("completeDefinition")
                and (not symbol or n.get("name") == symbol)
            ]
        elif kind in {"cfg", "macros"}:
            values = data[kind]
            if symbol:
                values = [
                    v
                    for v in values
                    if (
                        v.get("name") == symbol
                        if kind == "macros"
                        else bool(re.search(r"\b" + re.escape(symbol) + r"\s*\(", v["signature"]))
                    )
                ]
        else:
            return {"complete": False, "reason": "unknown_query_kind"}
        offset, limit = max(0, int(offset)), max(1, min(100, int(limit)))
        end = min(len(values), offset + limit)
        return {
            **self.descriptor(data),
            "items": values[offset:end],
            "total": len(values),
            "display_truncated": end < len(values),
            "next_offset": end if end < len(values) else None,
            "query": {"kind": kind, "symbol": symbol},
            "note": "Query exhaustion does not establish project/path coverage.",
        }
