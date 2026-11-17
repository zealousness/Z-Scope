#!/usr/bin/env python3
"""Check whether discovered Range entries cover the scored functions.

When a KnowledgeDB is available, coverage means actual forward call-graph
reachability.  The fallback mode is intentionally named ``direct_entry_identity``:
without a call graph it can only prove that a scored function itself is an entry.

Function nodes are path-aware because C projects may contain same-named static or
platform-specific functions.  Entry identities additionally include the full
signature obtained from the discovery payload or the KnowledgeDB.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import sqlite3
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

FUNC_DEF_RE = re.compile(r"(?m)^[A-Za-z_][\w\s\*\(\),]*\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{")


@dataclass(frozen=True, order=True)
class FunctionNode:
    name: str
    file_path: str


@dataclass(frozen=True)
class FunctionRecord:
    name: str
    file_path: str
    signature: str
    is_declaration: bool


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return data


def resolve_entry_list(config_path: Path) -> Path | None:
    if not config_path.exists():
        return None
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("entry_functions_list:"):
            value = stripped.split(":", 1)[1].strip().strip("'\"")
            return (config_path.parent / value).resolve()
    return None


def resolve_configured_knowledge_db(config_path: Path, root: Path) -> Path | None:
    """Resolve the simple scalar used by Range configs without importing YAML."""

    if not config_path.exists():
        return None
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("knowledge_db_path:"):
            continue
        value = stripped.split(":", 1)[1].strip().strip("'\"")
        if not value:
            return None
        path = Path(value)
        if not path.is_absolute():
            path = root / path
        return path.resolve()
    return None


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in ("src", "include", "internal"):
        base = root / rel
        if base.exists():
            files.extend(base.rglob("*.c"))
            files.extend(base.rglob("*.h"))
            files.extend(base.rglob("*.ph"))
    return sorted(files)


def normalize_path(value: Any, root: Path | None = None) -> str:
    raw = str(value or "").strip().replace("\\", "/")
    if not raw:
        return ""
    normalized = posixpath.normpath(raw)
    if root is not None:
        root_text = posixpath.normpath(str(root.resolve()).replace("\\", "/"))
        if normalized.casefold() == root_text.casefold():
            return "."
        prefix = root_text.rstrip("/") + "/"
        if normalized.casefold().startswith(prefix.casefold()):
            normalized = normalized[len(prefix) :]
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def paths_match(left: str, right: str) -> bool:
    a = normalize_path(left)
    b = normalize_path(right)
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def function_name(value: Any) -> str:
    """Extract a symbol from either ``name`` or legacy ``name(types)`` syntax."""

    text = str(value or "").strip()
    return text.split("(", 1)[0].strip()


def normalize_signature(value: Any) -> str:
    text = str(value or "").strip().rstrip(";{").strip()
    return re.sub(r"\s+", "", text)


def find_function_defs(root: Path) -> dict[str, list[FunctionRecord]]:
    defs: dict[str, list[FunctionRecord]] = {}
    for path in source_files(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in FUNC_DEF_RE.finditer(text):
            name = match.group(1)
            rel = path.relative_to(root).as_posix()
            signature = text[match.start() : match.end() - 1].strip()
            defs.setdefault(name, []).append(
                FunctionRecord(
                    name=name,
                    file_path=rel,
                    signature=signature,
                    is_declaration=False,
                )
            )
    return defs


def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


class KnowledgeCallGraph:
    """Path-aware view of the KnowledgeDB's direct and indirect call edges."""

    def __init__(
        self,
        db_path: Path,
        *,
        root: Path,
        source_defs: Mapping[str, Sequence[FunctionRecord]],
    ) -> None:
        self.db_path = db_path.resolve()
        self.root = root
        self.records_by_name: dict[str, list[FunctionRecord]] = defaultdict(list)
        self.caller_files_by_name: dict[str, set[str]] = defaultdict(set)
        self.adjacency: dict[FunctionNode, set[FunctionNode]] = defaultdict(set)
        self.direct_edge_count = 0
        self.indirect_edge_count = 0

        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        try:
            if not _table_exists(connection, "functions"):
                raise SystemExit(f"{self.db_path} has no functions table")
            if not _table_exists(connection, "call_edges"):
                raise SystemExit(f"{self.db_path} has no call_edges table")

            for row in connection.execute(
                "SELECT name, file_path, signature, is_declaration FROM functions"
            ):
                name = str(row["name"] or "")
                if not name:
                    continue
                self.records_by_name[name].append(
                    FunctionRecord(
                        name=name,
                        file_path=normalize_path(row["file_path"], root),
                        signature=str(row["signature"] or ""),
                        is_declaration=bool(row["is_declaration"]),
                    )
                )

            direct_rows = list(
                connection.execute(
                    "SELECT caller_name, caller_file, callee_name, callee_file " "FROM call_edges"
                )
            )
            indirect_rows = (
                list(
                    connection.execute(
                        "SELECT caller_name, call_file, callee_name " "FROM indirect_calls"
                    )
                )
                if _table_exists(connection, "indirect_calls")
                else []
            )
        finally:
            connection.close()

        # Source parsing fills gaps in a partially populated functions table.
        for name, records in source_defs.items():
            known = {
                (
                    record.file_path,
                    normalize_signature(record.signature),
                    record.is_declaration,
                )
                for record in self.records_by_name.get(name, [])
            }
            for record in records:
                key = (
                    normalize_path(record.file_path, root).casefold(),
                    normalize_signature(record.signature),
                    record.is_declaration,
                )
                if key in known:
                    continue
                self.records_by_name[name].append(
                    FunctionRecord(
                        name=record.name,
                        file_path=normalize_path(record.file_path, root),
                        signature=record.signature,
                        is_declaration=record.is_declaration,
                    )
                )

        for row in direct_rows:
            caller = str(row["caller_name"] or "")
            caller_file = normalize_path(row["caller_file"], root)
            if caller and caller_file:
                self.caller_files_by_name[caller].add(caller_file)
        for row in indirect_rows:
            caller = str(row["caller_name"] or "")
            caller_file = normalize_path(row["call_file"], root)
            if caller and caller_file:
                self.caller_files_by_name[caller].add(caller_file)

        for row in direct_rows:
            caller_name = str(row["caller_name"] or "")
            caller_file = normalize_path(row["caller_file"], root)
            callee_name = str(row["callee_name"] or "")
            callee_file = normalize_path(row["callee_file"], root)
            if not caller_name or not caller_file or not callee_name:
                continue
            source = FunctionNode(caller_name, caller_file)
            targets = self._resolve_callee_nodes(callee_name, callee_file)
            self.adjacency[source].update(targets)
            self.direct_edge_count += 1

        for row in indirect_rows:
            caller_name = str(row["caller_name"] or "")
            caller_file = normalize_path(row["call_file"], root)
            callee_name = str(row["callee_name"] or "")
            if not caller_name or not callee_name:
                continue
            sources = (
                {FunctionNode(caller_name, caller_file)}
                if caller_file
                else self.definition_nodes(caller_name)
            )
            targets = self._resolve_callee_nodes(callee_name, "")
            for source in sources:
                self.adjacency[source].update(targets)
            self.indirect_edge_count += 1

    def records_matching_path(self, name: str, file_path: str) -> list[FunctionRecord]:
        return [
            record
            for record in self.records_by_name.get(name, [])
            if paths_match(record.file_path, file_path)
        ]

    def definition_nodes(
        self,
        name: str,
        *,
        signature: str = "",
    ) -> set[FunctionNode]:
        normalized_signature = normalize_signature(signature)
        records = [
            record for record in self.records_by_name.get(name, []) if not record.is_declaration
        ]
        if normalized_signature:
            signature_matches = [
                record
                for record in records
                if normalize_signature(record.signature) == normalized_signature
            ]
            if signature_matches:
                records = signature_matches
        nodes = {
            FunctionNode(record.name, record.file_path) for record in records if record.file_path
        }
        if not nodes:
            nodes = {
                FunctionNode(name, file_path)
                for file_path in self.caller_files_by_name.get(name, set())
            }
        return nodes

    def _resolve_callee_nodes(self, name: str, file_hint: str) -> set[FunctionNode]:
        if file_hint:
            matched_records = self.records_matching_path(name, file_hint)
            definitions = [record for record in matched_records if not record.is_declaration]
            if definitions:
                return {FunctionNode(record.name, record.file_path) for record in definitions}
            declarations = [record for record in matched_records if record.is_declaration]
            for declaration in declarations:
                resolved = self.definition_nodes(
                    name,
                    signature=declaration.signature,
                )
                if resolved:
                    return resolved
            matching_callers = {
                FunctionNode(name, path)
                for path in self.caller_files_by_name.get(name, set())
                if paths_match(path, file_hint)
            }
            if matching_callers:
                return matching_callers
            return {FunctionNode(name, file_hint)}

        resolved = self.definition_nodes(name)
        return resolved or {FunctionNode(name, "")}

    def entry_signatures(self, entry: Mapping[str, Any]) -> list[str]:
        explicit = str(entry.get("signature") or entry.get("full_signature") or "").strip()
        if explicit:
            return [explicit]
        name = function_name(entry.get("function_name"))
        file_path = normalize_path(entry.get("file_path"), self.root)
        signatures = {
            record.signature
            for record in self.records_matching_path(name, file_path)
            if record.signature
        }
        return sorted(signatures)

    def entry_nodes(self, entry: Mapping[str, Any]) -> set[FunctionNode]:
        name = function_name(entry.get("function_name"))
        file_path = normalize_path(entry.get("file_path"), self.root)
        exact_records = self.records_matching_path(name, file_path)
        exact_definitions = [record for record in exact_records if not record.is_declaration]
        if exact_definitions:
            return {FunctionNode(record.name, record.file_path) for record in exact_definitions}
        exact_callers = {
            FunctionNode(name, path)
            for path in self.caller_files_by_name.get(name, set())
            if paths_match(path, file_path)
        }
        if exact_callers:
            return exact_callers

        signatures = self.entry_signatures(entry)
        nodes: set[FunctionNode] = set()
        for signature in signatures:
            nodes.update(self.definition_nodes(name, signature=signature))
        return nodes or self.definition_nodes(name)

    def reachable_from(self, roots: Iterable[FunctionNode]) -> set[FunctionNode]:
        reachable = set(roots)
        pending = deque(reachable)
        while pending:
            caller = pending.popleft()
            for callee in self.adjacency.get(caller, set()):
                if callee in reachable:
                    continue
                reachable.add(callee)
                pending.append(callee)
        return reachable


def _source_signatures_for_entry(
    entry: Mapping[str, Any],
    source_defs: Mapping[str, Sequence[FunctionRecord]],
    *,
    root: Path,
) -> list[str]:
    explicit = str(entry.get("signature") or entry.get("full_signature") or "").strip()
    if explicit:
        return [explicit]
    name = function_name(entry.get("function_name"))
    file_path = normalize_path(entry.get("file_path"), root)
    exact = {
        record.signature
        for record in source_defs.get(name, [])
        if paths_match(record.file_path, file_path) and record.signature
    }
    return sorted(exact)


def entry_identity_keys(
    entries: Sequence[Mapping[str, Any]],
    *,
    root: Path,
    source_defs: Mapping[str, Sequence[FunctionRecord]],
    graph: KnowledgeCallGraph | None,
) -> tuple[list[tuple[str, str]], list[str]]:
    keys: list[tuple[str, str]] = []
    displays: list[str] = []
    for entry in entries:
        name = function_name(entry.get("function_name"))
        file_path = normalize_path(entry.get("file_path"), root)
        signatures = (
            graph.entry_signatures(entry)
            if graph is not None
            else _source_signatures_for_entry(entry, source_defs, root=root)
        )
        if not signatures:
            # This remains path-aware and avoids collapsing same-named entries.
            # The unresolved marker is also surfaced through missing definitions.
            signatures = [str(entry.get("function_name") or name) + "(?)"]
        for signature in signatures:
            key = (file_path, normalize_signature(signature))
            keys.append(key)
            displays.append(f"{file_path}::{signature}")
    return keys, displays


def truth_function_refs(vulnerability: Mapping[str, Any]) -> list[FunctionNode]:
    refs: list[FunctionNode] = []
    primary_name = function_name(vulnerability.get("function"))
    primary_file = normalize_path(vulnerability.get("file"))
    if primary_name and primary_file:
        refs.append(FunctionNode(primary_name, primary_file))
    secondary_name = function_name(vulnerability.get("secondary_function"))
    secondary_file = normalize_path(
        vulnerability.get("secondary_file") or vulnerability.get("file")
    )
    if secondary_name and secondary_file:
        refs.append(FunctionNode(secondary_name, secondary_file))
    return refs


def node_is_reachable(target: FunctionNode, reachable: Iterable[FunctionNode]) -> bool:
    return any(
        node.name == target.name and paths_match(node.file_path, target.file_path)
        for node in reachable
    )


def evaluate_coverage(
    *,
    root: Path,
    entries: Sequence[Mapping[str, Any]],
    vulnerabilities: Sequence[Mapping[str, Any]],
    knowledge_db: Path | None,
    require_all_functions: bool = False,
) -> tuple[dict[str, Any], bool]:
    root = root.resolve()
    source_defs = find_function_defs(root)
    graph = (
        KnowledgeCallGraph(knowledge_db, root=root, source_defs=source_defs)
        if knowledge_db is not None
        else None
    )

    identity_keys, identity_displays = entry_identity_keys(
        entries,
        root=root,
        source_defs=source_defs,
        graph=graph,
    )
    identity_counts = Counter(identity_keys)
    duplicate_identities = sorted(
        {
            identity_displays[index]
            for index, key in enumerate(identity_keys)
            if identity_counts[key] > 1
        }
    )

    entry_names = [
        function_name(entry.get("function_name"))
        for entry in entries
        if function_name(entry.get("function_name"))
    ]
    duplicate_names = sorted(name for name, count in Counter(entry_names).items() if count > 1)

    missing_definitions: list[str] = []
    for entry in entries:
        name = function_name(entry.get("function_name"))
        if not source_defs.get(name) and not (graph is not None and graph.definition_nodes(name)):
            file_path = normalize_path(entry.get("file_path"), root)
            missing_definitions.append(f"{file_path}::{entry.get('function_name') or name}")

    roots: set[FunctionNode]
    if graph is not None:
        roots = set()
        for entry in entries:
            roots.update(graph.entry_nodes(entry))
        reachable = graph.reachable_from(roots)
        mode = "call_graph_reachability"
    else:
        roots = {
            FunctionNode(
                function_name(entry.get("function_name")),
                normalize_path(entry.get("file_path"), root),
            )
            for entry in entries
            if function_name(entry.get("function_name"))
            and normalize_path(entry.get("file_path"), root)
        }
        reachable = roots
        mode = "direct_entry_identity"

    missing_truth: list[str] = []
    missing_truth_details: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        refs = truth_function_refs(vulnerability)
        coverage = [node_is_reachable(ref, reachable) for ref in refs]
        covered = bool(refs) and all(coverage) if require_all_functions else any(coverage)
        if covered:
            continue
        rendered = [f"{ref.file_path}::{ref.name}" for ref in refs]
        requirement = "all not reachable" if require_all_functions else "none reachable"
        vuln_id = str(vulnerability.get("id") or "")
        missing_truth.append(f"{vuln_id}: {requirement}: {', '.join(rendered)}")
        missing_truth_details.append(
            {
                "id": vuln_id,
                "required_functions": rendered,
                "reachable": coverage,
            }
        )

    unique_identity_count = len(set(identity_keys))
    output: dict[str, Any] = {
        # Kept for compatibility, but now counts path+signature identities.
        "entries": unique_identity_count,
        "entry_records": len(entries),
        "entry_identities": unique_identity_count,
        "ground_truth": len(vulnerabilities),
        "missing_truth_entry": missing_truth,
        "missing_truth_reachability": missing_truth_details,
        # Kept as diagnostic information; same names in different files are valid.
        "duplicate_entry_names": duplicate_names,
        "duplicate_entry_identities": duplicate_identities,
        "missing_entry_definitions": sorted(set(missing_definitions)),
        # The old bare-name ambiguity check was invalid for static/platform code.
        "duplicate_entry_definitions": {},
        "mode": mode,
        "require_all_functions": bool(require_all_functions),
        "root_nodes": len(roots),
        "reachable_function_nodes": len(reachable),
    }
    if graph is not None:
        output["knowledge_db"] = str(graph.db_path)
        output["call_graph"] = {
            "direct_edges": graph.direct_edge_count,
            "indirect_edges": graph.indirect_edge_count,
            "root_nodes": len(roots),
            "reachable_nodes": len(reachable),
        }

    valid = not (missing_truth or duplicate_identities or missing_definitions)
    return output, valid


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("test/range"))
    parser.add_argument("--config", type=Path, default=Path("test/range/zscope.benchmark.yaml"))
    parser.add_argument(
        "--entries",
        type=Path,
        default=Path("test/range/benchmark/deterministic_entries.json"),
        help="Entry manifest to check; formal auto-discovery runs pass their generated run artifact.",
    )
    parser.add_argument(
        "--truth",
        type=Path,
        default=Path("test/range/benchmark/ground_truth.json"),
    )
    parser.add_argument(
        "--knowledge-db",
        type=Path,
        default=None,
        help="KnowledgeDB used for path-aware forward call-graph reachability.",
    )
    parser.add_argument(
        "--require-all-functions",
        action="store_true",
        help="Require both primary and secondary truth functions to be reachable.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    entries_path = args.entries.resolve() if args.entries else resolve_entry_list(args.config)
    if entries_path is None:
        raise SystemExit(f"Cannot resolve entry_functions_list from {args.config}")

    knowledge_db = args.knowledge_db
    if knowledge_db is None:
        configured = resolve_configured_knowledge_db(args.config, root)
        if configured is not None and configured.exists():
            knowledge_db = configured
    elif not knowledge_db.exists():
        raise SystemExit(f"KnowledgeDB does not exist: {knowledge_db}")
    if knowledge_db is not None:
        knowledge_db = knowledge_db.resolve()

    entries_data = load_json(entries_path)
    truth_data = load_json(args.truth)
    raw_entries = entries_data.get("functions", [])
    raw_vulnerabilities = truth_data.get("vulnerabilities", [])
    if not isinstance(raw_entries, list):
        raise SystemExit(f"{entries_path} field 'functions' must be an array")
    if not isinstance(raw_vulnerabilities, list):
        raise SystemExit(f"{args.truth} field 'vulnerabilities' must be an array")
    entries = [item for item in raw_entries if isinstance(item, dict)]
    vulnerabilities = [item for item in raw_vulnerabilities if isinstance(item, dict)]

    output, valid = evaluate_coverage(
        root=root,
        entries=entries,
        vulnerabilities=vulnerabilities,
        knowledge_db=knowledge_db,
        require_all_functions=args.require_all_functions,
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if not valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
