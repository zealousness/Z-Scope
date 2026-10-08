"""Static def-use path queries over versioned compiler program facts."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

from .symbols import SymbolCatalog, normalize_project_path


def _value_key(value: Dict[str, Any]) -> str:
    usr = str(value.get("usr") or "")
    if usr:
        base = str(value.get("base_expression") or "")
        return f"usr:{usr}:{base}"
    name = str(value.get("qualified_name") or value.get("name") or "")
    location = value.get("location") or {}
    if name:
        return f"name:{name}:{normalize_project_path(location.get('file'))}:{location.get('line') or 0}"
    return "expr:" + str(value.get("expression") or "")


def _value_name(value: Dict[str, Any]) -> str:
    return str(value.get("name") or value.get("qualified_name") or value.get("expression") or "")


class FlowQueryService:
    """Build bounded evidence paths without treating backend findings as data flow."""

    FACT_VERSION = "zscope.program-events.v5"

    def __init__(self, code_index: Any, catalog: SymbolCatalog) -> None:
        self.code_index = code_index
        self.catalog = catalog

    def trace_clang(
        self,
        function_name: str,
        file_path: str,
        source: Dict[str, Any],
        sink: Dict[str, Any],
        *,
        include_may_alias: bool,
        max_call_depth: int,
        max_paths: int,
        _visited: Optional[Set[Tuple[str, str, str]]] = None,
    ) -> Dict[str, Any]:
        facts = self.code_index.get_function_program_facts(function_name, file_path)
        functions = facts.get("functions") or []
        version = facts.get("fact_version") or (
            functions[0].get("fact_version") if len(functions) == 1 else None
        )
        if version != self.FACT_VERSION:
            return {
                "status": "unavailable",
                "reason": "backend_unavailable",
                "paths": [],
                "providers": ["clang_cfg"] if functions else [],
                "missing": ["program_events_v5"],
                "details": {"fact_version": version, "alias": "unavailable"},
            }
        if len(functions) != 1 or not facts.get("complete"):
            return {
                "status": "partial",
                "reason": "not_observed_with_partial_coverage",
                "paths": [],
                "providers": ["clang_cfg"],
                "missing": ["complete_cfg"],
                "details": {"fact_version": version, "alias": "unavailable"},
            }
        function = functions[0]
        graph = self._build_graph(function)
        source_nodes = self._select_source(graph, source)
        sink_nodes = self._select_sink(graph, sink)
        raw_paths, node_limited = self._paths_bounded(
            graph["adjacency"], source_nodes, sink_nodes, max_paths
        )
        paths = [self._format_path(graph, path, include_may_alias) for path in raw_paths]
        visited = set(_visited or set())
        unresolved_calls = 0
        depth_limited = False
        if len(paths) < max_paths:
            if max_call_depth > 0:
                cross_paths, unresolved_calls, depth_limited = self._trace_callees(
                    function_name,
                    file_path,
                    function,
                    graph,
                    source_nodes,
                    sink,
                    caller_sink_nodes=sink_nodes,
                    include_may_alias=include_may_alias,
                    max_call_depth=max_call_depth,
                    max_paths=max_paths - len(paths),
                    visited=visited,
                )
                paths.extend(cross_paths)
            elif self._reachable_call_nodes(graph, source_nodes) - sink_nodes:
                depth_limited = True
        alias_status = "unavailable" if include_may_alias else "not_requested"
        coverage_partial = bool(
            include_may_alias or unresolved_calls or depth_limited or node_limited
        )
        reason = (
            "paths_observed"
            if paths
            else (
                "not_observed_with_partial_coverage"
                if coverage_partial
                else "complete_search_no_path"
            )
        )
        return {
            "status": "partial" if coverage_partial else "ok",
            "reason": reason,
            "paths": paths,
            "providers": ["clang_cfg"],
            "missing": (
                (["alias_evidence"] if include_may_alias else [])
                + (["unresolved_dispatch"] if unresolved_calls else [])
                + (["call_depth_bound"] if depth_limited else [])
                + (["path_node_bound"] if node_limited else [])
            ),
            "details": {
                "fact_version": version,
                "alias": alias_status,
                "source_matches": len(source_nodes),
                "sink_matches": len(sink_nodes),
                "unresolved_calls": unresolved_calls,
                "call_depth_limited": depth_limited,
                "path_node_limited": node_limited,
            },
        }

    def trace_joern(
        self,
        function_name: str,
        source: Dict[str, Any],
        sink: Dict[str, Any],
        *,
        max_paths: int,
    ) -> Dict[str, Any]:
        if source.get("kind") != "parameter" or sink.get("kind") != "call":
            return {
                "status": "unsupported",
                "reason": "unsupported_selector",
                "paths": [],
                "providers": ["joern"],
                "missing": ["selector_support"],
                "details": {},
            }
        backend = getattr(self.code_index, "_backend", None)
        getter = getattr(backend, "get_data_flow", None)
        if not callable(getter):
            return {
                "status": "unavailable",
                "reason": "backend_unavailable",
                "paths": [],
                "providers": [],
                "missing": ["joern"],
                "details": {},
            }
        rows = list(getter(function_name, str(source["name"]), str(sink["query"])) or [])[
            :max_paths
        ]
        paths = []
        for row in rows:
            nodes = []
            for index, item in enumerate(row.get("path") or []):
                nodes.append(
                    {
                        "node_id": f"n{index + 1}",
                        "kind": "joern_node",
                        "expression": str(item.get("code") or ""),
                        "location": self._normalize_location(
                            {
                                "file": item.get("filename"),
                                "line": item.get("lineNumber"),
                            }
                        ),
                    }
                )
            edges = [
                {
                    "kind": "def_use",
                    "from": nodes[index]["node_id"],
                    "to": nodes[index + 1]["node_id"],
                    "guard": "",
                    "evidence": {"provider": "joern", "confidence": 1.0},
                }
                for index in range(max(0, len(nodes) - 1))
            ]
            paths.append(self._path_record(nodes, edges, classification="may"))
        return {
            "status": "ok",
            "reason": "paths_observed" if paths else "complete_search_no_path",
            "paths": paths,
            "providers": ["joern"],
            "missing": [],
            "details": {"alias": "joern_managed"},
        }

    def _build_graph(self, function: Dict[str, Any]) -> Dict[str, Any]:
        events = list(function.get("events") or [])
        cfg_edges = list(function.get("cfg_edges") or [])
        parameters = list(function.get("parameters") or [])
        nodes: Dict[str, Dict[str, Any]] = {}
        node_values: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        events_by_block: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        blocks: Set[int] = set()
        for event in events:
            block = int(event.get("block") or 0)
            blocks.add(block)
            events_by_block[block].append(event)
        predecessors: Dict[int, Set[int]] = defaultdict(set)
        guarded_blocks: Dict[int, List[str]] = defaultdict(list)
        for edge in cfg_edges:
            source = int(edge.get("from") or 0)
            target = int(edge.get("to") or 0)
            blocks.update((source, target))
            predecessors[target].add(source)
            condition = str(edge.get("condition") or "")
            branch = str(edge.get("branch") or "unknown")
            if condition:
                guarded_blocks[target].append(f"{condition} is {branch}")

        parameter_defs: Dict[str, Set[str]] = defaultdict(set)
        for index, parameter in enumerate(parameters):
            node_id = f"param:{index}"
            parameter_defs[_value_key(parameter)].add(node_id)
            nodes[node_id] = self._value_node(
                node_id, "parameter", parameter, function.get("location") or {}
            )
            node_values[node_id] = {"defs": [parameter], "uses": []}

        in_defs: Dict[int, Dict[str, Set[str]]] = {block: {} for block in blocks}
        out_defs: Dict[int, Dict[str, Set[str]]] = {block: {} for block in blocks}
        changed = True
        attempts = 0
        while changed and attempts < max(8, len(blocks) * 4):
            changed = False
            attempts += 1
            for block in sorted(blocks):
                incoming: Dict[str, Set[str]] = defaultdict(set)
                if not predecessors.get(block):
                    for key, definitions in parameter_defs.items():
                        incoming[key].update(definitions)
                for predecessor in predecessors.get(block, set()):
                    for key, definitions in out_defs.get(predecessor, {}).items():
                        incoming[key].update(definitions)
                state = {key: set(value) for key, value in incoming.items()}
                for event in sorted(
                    events_by_block.get(block, []), key=lambda item: int(item.get("ordinal") or 0)
                ):
                    event_node = self._definition_node_id(event)
                    for definition in event.get("defs") or []:
                        state[_value_key(definition)] = {event_node}
                if incoming != in_defs[block] or state != out_defs[block]:
                    in_defs[block] = dict(incoming)
                    out_defs[block] = state
                    changed = True

        adjacency: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for block in sorted(blocks):
            state = {key: set(value) for key, value in in_defs.get(block, {}).items()}
            for event in sorted(
                events_by_block.get(block, []), key=lambda item: int(item.get("ordinal") or 0)
            ):
                node_id = self._event_node_id(event)
                nodes[node_id] = self._event_node(node_id, event, guarded_blocks.get(block, []))
                defs = [dict(value) for value in event.get("defs") or []]
                uses = [dict(value) for value in event.get("uses") or []]
                node_values[node_id] = {"defs": defs, "uses": uses}
                for used in uses:
                    reaching = state.get(_value_key(used), set())
                    for definition in sorted(reaching):
                        adjacency[definition].append(
                            {
                                "to": node_id,
                                "kind": "def_use",
                                "guard": "; ".join(guarded_blocks.get(block, [])),
                                "provider": "clang_cfg",
                                "confidence": 1.0,
                                "value_key": _value_key(used),
                                "unique_definition": len(reaching) == 1,
                                "identity_complete": bool(used.get("identity_complete", True)),
                            }
                        )
                definition_node = self._definition_node_id(event)
                if definition_node != node_id:
                    nodes[definition_node] = {
                        "node_id": definition_node,
                        "kind": "call_result",
                        "event_kind": "call_result",
                        "expression": str(
                            event.get("assignment_target")
                            or event.get("expression")
                            or "call result"
                        ),
                        "callee": str(nodes[node_id].get("callee") or ""),
                        "location": dict(nodes[node_id].get("location") or {}),
                        "guards": list(nodes[node_id].get("guards") or []),
                    }
                    node_values[definition_node] = {"defs": defs, "uses": []}
                    # A call result is a definition, but arguments do not
                    # automatically flow into it.  That bridge is added only
                    # after a real callee parameter-to-return path is found.
                for definition in defs:
                    state[_value_key(definition)] = {definition_node}
        return {
            "nodes": nodes,
            "values": node_values,
            "adjacency": adjacency,
            "events": events,
        }

    def _select_source(self, graph: Dict[str, Any], selector: Dict[str, Any]) -> Set[str]:
        kind = str(selector.get("kind") or "")
        name = str(selector.get("name") or "")
        result: Set[str] = set()
        for node_id, node in graph["nodes"].items():
            values = graph["values"].get(node_id, {})
            identities = list(values.get("defs") or []) + list(values.get("uses") or [])
            if (
                kind == "parameter"
                and node.get("kind") == "parameter"
                and any(_value_name(value) == name for value in identities)
            ):
                result.add(node_id)
            elif kind in {"variable", "global"} and any(
                _value_name(value) == name
                and (kind != "global" or value.get("value_kind") == "global")
                for value in identities
            ):
                result.add(node_id)
            elif kind == "location" and self._location_matches(
                node.get("location") or {}, selector
            ):
                result.add(node_id)
        return result

    def _select_sink(self, graph: Dict[str, Any], selector: Dict[str, Any]) -> Set[str]:
        kind = str(selector.get("kind") or "")
        result: Set[str] = set()
        pattern = None
        if kind == "call" and selector.get("match_mode", "exact") == "regex":
            pattern = re.compile(str(selector.get("query") or ""))
        for node_id, node in graph["nodes"].items():
            values = graph["values"].get(node_id, {})
            identities = list(values.get("defs") or []) + list(values.get("uses") or [])
            if kind == "call" and node.get("event_kind") == "call":
                callee = str(node.get("callee") or "")
                query = str(selector.get("query") or "")
                if (pattern and pattern.search(callee)) or (
                    pattern is None and (callee == query or callee.rsplit("::", 1)[-1] == query)
                ):
                    result.add(node_id)
            elif kind == "return" and node.get("event_kind") == "return":
                result.add(node_id)
            elif kind in {"variable", "global"} and any(
                _value_name(value) == str(selector.get("name") or "")
                and (kind != "global" or value.get("value_kind") == "global")
                for value in identities
            ):
                result.add(node_id)
            elif kind == "location" and self._location_matches(
                node.get("location") or {}, selector
            ):
                result.add(node_id)
        return result

    def _reachable_call_nodes(self, graph: Dict[str, Any], sources: Set[str]) -> Set[str]:
        reached = set(sources)
        queue = deque(sorted(sources))
        while queue:
            current = queue.popleft()
            for edge in graph["adjacency"].get(current, []):
                target = str(edge["to"])
                if target not in reached:
                    reached.add(target)
                    queue.append(target)
        return {
            node_id
            for node_id in reached
            if (graph["nodes"].get(node_id) or {}).get("event_kind") == "call"
        }

    def _trace_callees(
        self,
        function_name: str,
        file_path: str,
        function: Dict[str, Any],
        graph: Dict[str, Any],
        source_nodes: Set[str],
        sink: Dict[str, Any],
        *,
        caller_sink_nodes: Set[str],
        include_may_alias: bool,
        max_call_depth: int,
        max_paths: int,
        visited: Set[Tuple[str, str, str]],
    ) -> Tuple[List[Dict[str, Any]], int, bool]:
        paths: List[Dict[str, Any]] = []
        unresolved = 0
        depth_limited = False
        events = {self._event_node_id(event): event for event in graph["events"]}
        for call_node in sorted(
            self._reachable_call_nodes(graph, source_nodes) - caller_sink_nodes
        ):
            if len(paths) >= max_paths:
                break
            event = events.get(call_node)
            if not event:
                continue
            prefixes = self._paths(
                graph["adjacency"], source_nodes, {call_node}, max_paths - len(paths)
            )
            targets = self._call_targets(function_name, file_path, event)
            if not targets:
                unresolved += 1
                continue
            for prefix in prefixes:
                argument_indexes = self._tainted_argument_indexes(event, prefix)
                if not argument_indexes:
                    unresolved += 1
                    continue
                prefix_record = self._format_path(graph, prefix, include_may_alias)
                for argument_index in argument_indexes:
                    for target, dispatch, provider, confidence in targets:
                        if len(paths) >= max_paths:
                            break
                        parameter_name = self._parameter_name(target, argument_index)
                        if not parameter_name:
                            unresolved += 1
                            continue
                        callsite = str(event.get("event_id") or call_node)
                        cycle_key = (
                            str(target.get("symbol_id") or target.get("qualified_name") or ""),
                            callsite,
                            parameter_name,
                        )
                        if cycle_key in visited:
                            depth_limited = True
                            continue
                        nested_visited = set(visited)
                        nested_visited.add(cycle_key)
                        target_name = str(
                            target.get("index_name")
                            or target.get("qualified_name")
                            or target["name"]
                        )
                        target_file = str(target.get("file") or "")
                        if sink.get("kind") != "return":
                            nested = self.trace_clang(
                                target_name,
                                target_file,
                                {"kind": "parameter", "name": parameter_name},
                                sink,
                                include_may_alias=include_may_alias,
                                max_call_depth=max_call_depth - 1,
                                max_paths=max_paths - len(paths),
                                _visited=nested_visited,
                            )
                            if nested.get("details", {}).get("call_depth_limited"):
                                depth_limited = True
                            if nested.get("reason") == "backend_unavailable":
                                unresolved += 1
                            for nested_path in nested.get("paths") or []:
                                paths.append(
                                    self._combine_paths(
                                        prefix_record,
                                        nested_path,
                                        dispatch=dispatch,
                                        provider=provider,
                                        confidence=confidence,
                                        argument_index=argument_index,
                                    )
                                )
                                if len(paths) >= max_paths:
                                    break
                        if len(paths) >= max_paths:
                            break

                        result_node = self._definition_node_id(event)
                        if result_node == call_node or result_node not in graph["nodes"]:
                            continue
                        suffixes = self._paths(
                            graph["adjacency"],
                            {result_node},
                            caller_sink_nodes,
                            max_paths - len(paths),
                        )
                        if not suffixes:
                            continue
                        returns = self.trace_clang(
                            target_name,
                            target_file,
                            {"kind": "parameter", "name": parameter_name},
                            {"kind": "return"},
                            include_may_alias=include_may_alias,
                            max_call_depth=max_call_depth - 1,
                            max_paths=max_paths - len(paths),
                            _visited=nested_visited,
                        )
                        if returns.get("details", {}).get("call_depth_limited"):
                            depth_limited = True
                        if returns.get("reason") == "backend_unavailable":
                            unresolved += 1
                        for return_path in returns.get("paths") or []:
                            for suffix in suffixes:
                                paths.append(
                                    self._combine_return_path(
                                        prefix_record,
                                        return_path,
                                        self._format_path(graph, suffix, include_may_alias),
                                        dispatch=dispatch,
                                        provider=provider,
                                        confidence=confidence,
                                        argument_index=argument_index,
                                    )
                                )
                                if len(paths) >= max_paths:
                                    break
                            if len(paths) >= max_paths:
                                break
        return paths, unresolved, depth_limited

    def _tainted_argument_indexes(
        self,
        event: Dict[str, Any],
        prefix: Tuple[List[str], List[Dict[str, Any]]],
    ) -> List[int]:
        _nodes, edges = prefix
        value_key = str(edges[-1].get("value_key") or "") if edges else ""
        argument_uses = event.get("argument_uses") or []
        if not argument_uses:
            argument_uses = [[item] for item in event.get("argument_objects") or []]
        matched = []
        for index, values in enumerate(argument_uses):
            candidates = values if isinstance(values, list) else [values]
            if any(
                isinstance(value, dict) and (not value_key or _value_key(value) == value_key)
                for value in candidates
            ):
                matched.append(index)
        return matched

    def _call_targets(
        self, function_name: str, file_path: str, event: Dict[str, Any]
    ) -> List[Tuple[Dict[str, Any], str, str, float]]:
        callee = event.get("callee") or {}
        callee_name = str(callee.get("qualified_name") or callee.get("name") or "")
        callee_file = normalize_project_path(
            callee.get("file") or (callee.get("location") or {}).get("file")
        )
        candidates: List[Tuple[Dict[str, Any], str, str, float]] = []
        if callee_name:
            records = self.catalog.search(callee_name, ["function", "method"], "exact", None)
            if not records and "::" in callee_name:
                records = self.catalog.search(
                    callee_name.rsplit("::", 1)[-1],
                    ["function", "method"],
                    "exact",
                    None,
                )
            callee_usr = str(callee.get("usr") or "")
            if callee_usr:
                exact_usr = [
                    item
                    for item in records
                    if str((item.get("raw") or {}).get("usr") or "") == callee_usr
                ]
                if exact_usr:
                    records = exact_usr
            if callee_file:
                exact_file = [
                    item
                    for item in records
                    if normalize_project_path(item.get("file")) == callee_file
                ]
                if exact_file:
                    records = exact_file
            if len(records) == 1:
                candidates.append((records[0], "direct", "clang_cfg", 1.0))
                return candidates

        database = self._database()
        getter = getattr(database, "get_indirect_call_records", None) if database else None
        if not callable(getter):
            return []
        simple_name = str(function_name).split("@", 1)[0]
        line = int((event.get("location") or {}).get("line") or 0)
        event_file = normalize_project_path((event.get("location") or {}).get("file"))
        for row in getter(simple_name, caller_file=file_path, limit=100000) or []:
            row_line = int(row.get("call_line") or 0)
            row_file = normalize_project_path(row.get("call_file"))
            if line and row_line and line != row_line:
                continue
            if (
                event_file
                and row_file
                and not (
                    event_file == row_file
                    or event_file.endswith("/" + row_file)
                    or row_file.endswith("/" + event_file)
                )
            ):
                continue
            records = self.catalog.search(
                str(row.get("name") or ""),
                ["function", "method"],
                "exact",
                None,
            )
            for record in records:
                candidates.append(
                    (
                        record,
                        "svf_resolved",
                        str(row.get("source") or "svf"),
                        float(row.get("confidence") or 0.0),
                    )
                )
        unique: Dict[Tuple[str, str], Tuple[Dict[str, Any], str, str, float]] = {}
        for item in candidates:
            unique[(str(item[0].get("symbol_id") or ""), item[1])] = item
        return list(unique.values())

    def _parameter_name(self, target: Dict[str, Any], index: int) -> str:
        facts = self.code_index.get_function_program_facts(
            str(target.get("index_name") or target.get("qualified_name") or target["name"]),
            str(target.get("file") or ""),
        )
        functions = facts.get("functions") or []
        if len(functions) != 1 or facts.get("fact_version") != self.FACT_VERSION:
            return ""
        parameters = functions[0].get("parameters") or []
        if index < 0 or index >= len(parameters):
            return ""
        return _value_name(parameters[index])

    def _database(self) -> Any:
        backend = getattr(self.code_index, "_backend", None)
        database = getattr(backend, "db", None)
        if database is not None:
            return database
        return getattr(getattr(backend, "_clang", None), "db", None)

    def _combine_paths(
        self,
        caller: Dict[str, Any],
        callee: Dict[str, Any],
        *,
        dispatch: str,
        provider: str,
        confidence: float,
        argument_index: int,
    ) -> Dict[str, Any]:
        caller_nodes = [dict(item) for item in caller.get("nodes") or []]
        callee_nodes = [dict(item) for item in callee.get("nodes") or []]
        caller_map = {
            str(node.get("node_id") or ""): f"n{index + 1}"
            for index, node in enumerate(caller_nodes)
        }
        callee_map = {
            str(node.get("node_id") or ""): f"n{len(caller_nodes) + index + 1}"
            for index, node in enumerate(callee_nodes)
        }
        nodes = caller_nodes + callee_nodes
        for index, node in enumerate(nodes):
            node["node_id"] = f"n{index + 1}"
        caller_edges = [dict(item) for item in caller.get("edges") or []]
        callee_edges = [dict(item) for item in callee.get("edges") or []]
        edges: List[Dict[str, Any]] = []
        for edge in caller_edges:
            edge["from"] = caller_map.get(str(edge.get("from") or ""), str(edge.get("from") or ""))
            edge["to"] = caller_map.get(str(edge.get("to") or ""), str(edge.get("to") or ""))
            edges.append(edge)
        for edge in callee_edges:
            edge["from"] = callee_map.get(str(edge.get("from") or ""), str(edge.get("from") or ""))
            edge["to"] = callee_map.get(str(edge.get("to") or ""), str(edge.get("to") or ""))
            edges.append(edge)
        caller_count = len(caller.get("nodes") or [])
        if caller_count and len(nodes) > caller_count:
            edges.insert(
                len(caller_edges),
                {
                    "kind": "argument",
                    "from": f"n{caller_count}",
                    "to": f"n{caller_count + 1}",
                    "guard": "",
                    "evidence": {
                        "provider": provider,
                        "confidence": max(0.0, min(1.0, confidence)),
                        "dispatch": dispatch,
                        "argument_index": argument_index,
                    },
                },
            )
        guards = sorted({str(edge.get("guard") or "") for edge in edges if edge.get("guard")})
        classification = (
            "must"
            if caller.get("classification") == "must"
            and callee.get("classification") == "must"
            and dispatch == "direct"
            and not guards
            else "may"
        )
        return self._path_record(nodes, edges, classification=classification)

    def _combine_return_path(
        self,
        caller_prefix: Dict[str, Any],
        callee_return: Dict[str, Any],
        caller_suffix: Dict[str, Any],
        *,
        dispatch: str,
        provider: str,
        confidence: float,
        argument_index: int,
    ) -> Dict[str, Any]:
        """Join caller argument, proven callee return, and caller result use."""
        segments = (caller_prefix, callee_return, caller_suffix)
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        maps: List[Dict[str, str]] = []
        for segment in segments:
            mapping: Dict[str, str] = {}
            for raw in segment.get("nodes") or []:
                node = dict(raw)
                old_id = str(node.get("node_id") or "")
                new_id = f"n{len(nodes) + 1}"
                mapping[old_id] = new_id
                node["node_id"] = new_id
                nodes.append(node)
            maps.append(mapping)
        for segment, mapping in zip(segments, maps):
            for raw in segment.get("edges") or []:
                edge = dict(raw)
                edge["from"] = mapping.get(str(edge.get("from") or ""), edge.get("from"))
                edge["to"] = mapping.get(str(edge.get("to") or ""), edge.get("to"))
                edges.append(edge)

        prefix_count = len(caller_prefix.get("nodes") or [])
        return_count = len(callee_return.get("nodes") or [])
        if prefix_count and return_count:
            edges.append(
                {
                    "kind": "argument",
                    "from": f"n{prefix_count}",
                    "to": f"n{prefix_count + 1}",
                    "guard": "",
                    "evidence": {
                        "provider": provider,
                        "confidence": max(0.0, min(1.0, confidence)),
                        "dispatch": dispatch,
                        "argument_index": argument_index,
                    },
                }
            )
        if return_count and caller_suffix.get("nodes"):
            edges.append(
                {
                    "kind": "return",
                    "from": f"n{prefix_count + return_count}",
                    "to": f"n{prefix_count + return_count + 1}",
                    "guard": "",
                    "evidence": {
                        "provider": provider,
                        "confidence": max(0.0, min(1.0, confidence)),
                        "dispatch": dispatch,
                    },
                }
            )
        guards = {str(edge.get("guard") or "") for edge in edges if edge.get("guard")}
        classification = (
            "must"
            if all(segment.get("classification") == "must" for segment in segments)
            and dispatch == "direct"
            and not guards
            else "may"
        )
        return self._path_record(nodes, edges, classification=classification)

    @staticmethod
    def _paths(
        adjacency: Dict[str, List[Dict[str, Any]]],
        sources: Set[str],
        sinks: Set[str],
        limit: int,
    ) -> List[Tuple[List[str], List[Dict[str, Any]]]]:
        found, _truncated = FlowQueryService._paths_bounded(adjacency, sources, sinks, limit)
        return found

    @staticmethod
    def _paths_bounded(
        adjacency: Dict[str, List[Dict[str, Any]]],
        sources: Set[str],
        sinks: Set[str],
        limit: int,
    ) -> Tuple[List[Tuple[List[str], List[Dict[str, Any]]]], bool]:
        found: List[Tuple[List[str], List[Dict[str, Any]]]] = []
        queue: Deque[Tuple[str, List[str], List[Dict[str, Any]]]] = deque(
            (source, [source], []) for source in sorted(sources)
        )
        truncated = False
        while queue and len(found) < limit:
            current, nodes, edges = queue.popleft()
            if current in sinks:
                found.append((nodes, edges))
                continue
            if len(nodes) >= 200:
                if adjacency.get(current):
                    truncated = True
                continue
            for edge in adjacency.get(current, []):
                target = str(edge["to"])
                if target in nodes:
                    continue
                queue.append((target, nodes + [target], edges + [edge]))
        return found, truncated

    def _format_path(
        self,
        graph: Dict[str, Any],
        path: Tuple[List[str], List[Dict[str, Any]]],
        include_may_alias: bool,
    ) -> Dict[str, Any]:
        node_ids, raw_edges = path
        nodes = [dict(graph["nodes"][node_id]) for node_id in node_ids]
        mapped = {old: f"n{index + 1}" for index, old in enumerate(node_ids)}
        for node in nodes:
            node["node_id"] = mapped[node["node_id"]]
        edges = [
            {
                "kind": edge["kind"],
                "from": mapped[node_ids[index]],
                "to": mapped[str(edge["to"])],
                "guard": edge.get("guard") or "",
                "evidence": {
                    "provider": edge.get("provider") or "clang_cfg",
                    "confidence": float(edge.get("confidence") or 0.0),
                    **({"dispatch": edge.get("dispatch")} if edge.get("dispatch") else {}),
                },
            }
            for index, edge in enumerate(raw_edges)
        ]
        has_guard = any(edge["guard"] for edge in edges)
        has_call = any(node.get("event_kind") == "call" for node in nodes[:-1]) or any(
            edge.get("kind") == "return" for edge in raw_edges
        )
        uncertain_identity = any(
            edge.get("unique_definition") is False or edge.get("identity_complete") is False
            for edge in raw_edges
        )
        classification = (
            "may" if include_may_alias or has_guard or has_call or uncertain_identity else "must"
        )
        return self._path_record(nodes, edges, classification=classification)

    @staticmethod
    def _path_record(
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        *,
        classification: str,
    ) -> Dict[str, Any]:
        truncated = len(nodes) > 200
        if truncated:
            nodes = nodes[:200]
            retained = {str(node.get("node_id") or "") for node in nodes}
            edges = [
                edge
                for edge in edges
                if str(edge.get("from") or "") in retained and str(edge.get("to") or "") in retained
            ]
            classification = "may"
        payload = "\x1f".join(
            f"{node.get('expression')}@{(node.get('location') or {}).get('file')}:{(node.get('location') or {}).get('line')}"
            for node in nodes
        )
        return {
            "path_id": "flow:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24],
            "classification": classification,
            "nodes": nodes,
            "edges": edges,
            "guards": sorted({edge["guard"] for edge in edges if edge["guard"]}),
            "truncated": truncated,
        }

    def _normalize_location(self, location: Dict[str, Any]) -> Dict[str, Any]:
        file_path = str(location.get("file") or "")
        if file_path:
            try:
                file_path = self.code_index._normalize_path(Path(file_path))
            except (OSError, ValueError):
                file_path = normalize_project_path(file_path)
        return {
            "file": file_path or None,
            "line": self._positive_coordinate(location.get("line")),
            "column": self._positive_coordinate(location.get("column")),
        }

    @staticmethod
    def _positive_coordinate(value: Any) -> Optional[int]:
        try:
            result = int(value)
        except (TypeError, ValueError):
            return None
        return result if result > 0 else None

    def _value_node(
        self, node_id: str, kind: str, value: Dict[str, Any], fallback_location: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "node_id": node_id,
            "kind": kind,
            "expression": str(value.get("expression") or _value_name(value)),
            "location": self._normalize_location(value.get("location") or fallback_location),
        }

    def _event_node(
        self, node_id: str, event: Dict[str, Any], guards: Iterable[str]
    ) -> Dict[str, Any]:
        callee = event.get("callee") or {}
        return {
            "node_id": node_id,
            "kind": (
                "call_argument"
                if event.get("event_kind") == "call"
                else str(event.get("event_kind") or "statement")
            ),
            "event_kind": str(event.get("event_kind") or "statement"),
            "expression": str(event.get("expression") or event.get("operation") or ""),
            "callee": str(callee.get("qualified_name") or callee.get("name") or ""),
            "location": self._normalize_location(event.get("location") or {}),
            "guards": list(guards),
        }

    @staticmethod
    def _event_node_id(event: Dict[str, Any]) -> str:
        return "event:" + str(
            event.get("event_id") or f"{event.get('block', 0)}:{event.get('ordinal', 0)}"
        )

    @classmethod
    def _definition_node_id(cls, event: Dict[str, Any]) -> str:
        node_id = cls._event_node_id(event)
        if event.get("event_kind") == "call" and event.get("defs"):
            return node_id + ":result"
        return node_id

    @staticmethod
    def _location_matches(location: Dict[str, Any], selector: Dict[str, Any]) -> bool:
        expected_file = normalize_project_path(selector.get("file_path"))
        actual_file = normalize_project_path(location.get("file"))
        return int(location.get("line") or 0) == int(selector.get("line") or 0) and (
            not expected_file
            or actual_file == expected_file
            or actual_file.endswith("/" + expected_file)
        )
