"""Replayable, function-local IR used by deterministic evidence providers.

This module intentionally consumes Clang's real CFG dump.  It does not accept
the candidate generator's brace-based pseudo blocks as proof material.  The
graph is conservative: an ambiguous function section, unresolved subject, or
missing CFG edge makes universal predicates unknown rather than safe.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


FUNCTION_IR_VERSION = "zscope.function-ir-graph.v3"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _symbols(text: str) -> Tuple[str, ...]:
    ignored = {
        "if",
        "else",
        "return",
        "sizeof",
        "true",
        "false",
        "null",
        "nullptr",
        "struct",
        "const",
        "unsigned",
        "signed",
        "int",
        "long",
        "short",
        "void",
    }
    return tuple(
        dict.fromkeys(
            token
            for token in re.findall(r"\b[A-Za-z_]\w*\b", text or "")
            if token.lower() not in ignored
        )
    )


@dataclass(frozen=True)
class FunctionIRStatement:
    statement_uid: str
    block_uid: str
    ordinal: int
    text: str
    source_line: int = 0


@dataclass(frozen=True)
class FunctionIREvent:
    event_uid: str
    block_uid: str
    statement_uid: str
    kind: str
    callee: str
    subject_symbols: Tuple[str, ...]
    source_line: int = 0


@dataclass(frozen=True)
class FunctionIRBlock:
    block_uid: str
    label: str
    successors: Tuple[str, ...]
    predecessors: Tuple[str, ...]
    statements: Tuple[FunctionIRStatement, ...]


@dataclass(frozen=True)
class FunctionIRGraph:
    function: str
    file: str
    entry_block_uid: str
    exit_block_uids: Tuple[str, ...]
    blocks: Tuple[FunctionIRBlock, ...]
    events: Tuple[FunctionIREvent, ...]
    ast_calls: Tuple[Dict[str, Any], ...]
    ast_value_facts: Tuple[Dict[str, Any], ...]
    ast_value_coverage_complete: bool
    code_snapshot_sha256: str
    backend_sha256: str
    coverage_complete: bool
    unresolved_dynamic_edges: bool
    ir_sha256: str
    schema_version: str = FUNCTION_IR_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def block_map(self) -> Dict[str, FunctionIRBlock]:
        return {block.block_uid: block for block in self.blocks}

    @property
    def statement_map(self) -> Dict[str, FunctionIRStatement]:
        return {
            statement.statement_uid: statement
            for block in self.blocks
            for statement in block.statements
        }

    @property
    def event_map(self) -> Dict[str, FunctionIREvent]:
        return {event.event_uid: event for event in self.events}

    @classmethod
    def from_clang_evidence(
        cls,
        evidence: Mapping[str, Any],
        *,
        function: str,
        file: str,
    ) -> Optional["FunctionIRGraph"]:
        cfg_dump = evidence.get("cfg_dump")
        ast_dump = evidence.get("ast_dump")
        cfg_dump = cfg_dump if isinstance(cfg_dump, Mapping) else {}
        ast_dump = ast_dump if isinstance(ast_dump, Mapping) else {}
        cfg = cfg_dump.get("summary")
        ast = ast_dump.get("summary")
        cfg = cfg if isinstance(cfg, Mapping) else {}
        ast = ast if isinstance(ast, Mapping) else {}
        if not cfg.get("parse_ok") or str(cfg.get("function") or "") != function:
            return None
        if cfg.get("function_section_unique") is not True:
            return None
        raw_blocks = cfg.get("blocks")
        if not isinstance(raw_blocks, Sequence) or isinstance(raw_blocks, (str, bytes)):
            return None
        ast_target = ast.get("target_function")
        ast_target = ast_target if isinstance(ast_target, Mapping) else {}
        raw_calls = ast_target.get("call_exprs")
        calls = tuple(dict(item) for item in raw_calls or [] if isinstance(item, Mapping))
        provenance_required = str(evidence.get("schema") or "") == "clang_tooling_evidence_v1"
        raw_project_names = ast.get("project_defined_function_names")
        raw_project_declarations = ast.get("project_defined_function_declarations")
        project_names = tuple(
            str(value or "")
            for value in raw_project_names or []
            if isinstance(value, str) and value
        )
        project_declarations = tuple(
            str(value or "")
            for value in raw_project_declarations or []
            if isinstance(value, str) and value
        )

        def declaration_identity_valid(identity: str, callee: str = "") -> bool:
            try:
                value = json.loads(identity)
            except (TypeError, json.JSONDecodeError):
                return False
            if not isinstance(value, dict) or set(value) != {"kind", "name", "type"}:
                return False
            if value.get("kind") not in {"FunctionDecl", "CXXMethodDecl"}:
                return False
            if not isinstance(value.get("name"), str) or not str(value.get("type") or ""):
                return False
            if callee and value.get("name") != callee:
                return False
            return identity == json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )

        project_declaration_names = tuple(
            str(json.loads(value).get("name") or "")
            for value in project_declarations
            if declaration_identity_valid(value)
        )
        project_metadata_complete = bool(
            isinstance(raw_project_names, list)
            and isinstance(raw_project_declarations, list)
            and list(project_names) == sorted(set(project_names))
            and list(project_declarations) == sorted(set(project_declarations))
            and all(declaration_identity_valid(value) for value in project_declarations)
            and set(project_declaration_names) == set(project_names)
        )

        def call_project_definition(call: Mapping[str, Any]) -> bool:
            callee = str(call.get("callee") or "")
            identity = str(call.get("callee_decl_identity") or "")
            return bool(callee in project_names and identity in project_declarations)

        def call_provenance_valid(call: Mapping[str, Any]) -> bool:
            if not provenance_required:
                return True
            callee = str(call.get("callee") or "")
            identity = str(call.get("callee_decl_identity") or "")
            origin = str(call.get("callee_decl_origin") or "")
            marker = call.get("callee_project_definition")
            if not callee or not identity:
                return not callee and not identity and origin == "unresolved" and marker is False
            expected_project = call_project_definition(call)
            expected_origin = (
                "translation_unit_definition" if expected_project else "external_declaration"
            )
            return bool(
                project_metadata_complete
                and declaration_identity_valid(identity, callee)
                and marker is expected_project
                and origin == expected_origin
            )

        governed_api_provenance_complete = bool(
            not provenance_required
            or (project_metadata_complete and all(call_provenance_valid(call) for call in calls))
        )
        value_facts: list[Dict[str, Any]] = []

        def add_value_fact(fact_kind: str, raw: Mapping[str, Any]) -> None:
            body = {"fact_kind": fact_kind, **dict(raw)}
            value_facts.append(
                {
                    "fact_uid": "ASTVAL_" + _sha(body)[:32],
                    **body,
                }
            )

        for value in ast_target.get("parameters") or []:
            if isinstance(value, Mapping) and str(value.get("name") or ""):
                add_value_fact("parameter", value)
        for value in ast_target.get("var_decls") or []:
            if isinstance(value, Mapping) and str(value.get("name") or ""):
                # Local declarations are part of the ownership identity
                # domain.  Without them, a statement such as ``p = malloc``
                # cannot be distinguished from a global or out-parameter
                # assignment and therefore cannot close a leak obligation.
                add_value_fact("variable_declaration", value)
        for value in ast_target.get("call_assignments") or []:
            if isinstance(value, Mapping) and str(value.get("target") or ""):
                add_value_fact("call_assignment", value)
        for call in calls:
            argument_types = list(call.get("argument_types") or [])
            argument_refs = list(call.get("argument_refs") or [])
            argument_ref_types = list(call.get("argument_ref_types") or [])
            for index in range(max(len(argument_types), len(argument_refs))):
                add_value_fact(
                    "call_argument",
                    {
                        "callee": str(call.get("callee") or ""),
                        "callee_decl_identity": str(call.get("callee_decl_identity") or ""),
                        "callee_decl_origin": str(call.get("callee_decl_origin") or ""),
                        "callee_project_definition": (
                            call.get("callee_project_definition") is True
                        ),
                        "line": int(call.get("line") or 0),
                        "argument_index": index,
                        "argument_type": str(
                            argument_types[index] if index < len(argument_types) else ""
                        ),
                        "refs": list(argument_refs[index] if index < len(argument_refs) else []),
                        "ref_types": dict(
                            argument_ref_types[index]
                            if index < len(argument_ref_types)
                            and isinstance(argument_ref_types[index], Mapping)
                            else {}
                        ),
                    },
                )
        for value in ast_target.get("conversions") or []:
            if isinstance(value, Mapping):
                add_value_fact("integer_conversion", value)
        for value in ast_target.get("terminating_guards") or []:
            if isinstance(value, Mapping):
                add_value_fact("terminating_guard", value)
        for value in ast_target.get("binary_ops") or []:
            if isinstance(value, Mapping):
                add_value_fact("binary_operator", value)
        value_facts.sort(key=lambda value: str(value.get("fact_uid") or ""))
        ast_value_coverage_complete = bool(
            ast.get("parse_ok") is True
            and ast_target
            and ast_target.get("value_fact_coverage_complete") is True
        )
        blocks: list[FunctionIRBlock] = []
        events: list[FunctionIREvent] = []
        block_ids = {str(item.get("id") or "") for item in raw_blocks if isinstance(item, Mapping)}
        semantic_cfg = any(
            isinstance(item, Mapping) and "semantic_statements" in item for item in raw_blocks
        )
        block_texts: Dict[str, Tuple[str, ...]] = {}
        for raw_block in raw_blocks:
            if not isinstance(raw_block, Mapping):
                continue
            block_uid = str(raw_block.get("id") or "")
            raw_statements = (
                raw_block.get("semantic_statements")
                if semantic_cfg
                else raw_block.get("statements")
            )
            block_texts[block_uid] = tuple(
                str(value or "").strip() for value in raw_statements or []
            )
        typed_call_bindings: Dict[Tuple[str, int], Tuple[Dict[str, Any], ...]] = {}
        typed_call_mapping_complete = not semantic_cfg
        if semantic_cfg and ast_value_coverage_complete:
            typed_call_bindings, typed_call_mapping_complete = cls._typed_call_bindings(
                block_texts,
                calls,
                tuple(
                    dict(value)
                    for value in ast_target.get("call_assignments") or []
                    if isinstance(value, Mapping)
                ),
            )
        for raw_block in raw_blocks:
            if not isinstance(raw_block, Mapping):
                continue
            block_uid = str(raw_block.get("id") or "")
            if not block_uid:
                continue
            statements: list[FunctionIRStatement] = []
            per_callee_index: Dict[str, int] = {}
            for ordinal, raw_text in enumerate(block_texts.get(block_uid, ())):
                text = str(raw_text or "").strip()
                statement_uid = (
                    "STMT_"
                    + _sha(
                        {"function": function, "block": block_uid, "ordinal": ordinal, "text": text}
                    )[:32]
                )
                bound_calls = typed_call_bindings.get((block_uid, ordinal), ())
                callee = "" if semantic_cfg else cls._callee(text)
                line = 0
                if not semantic_cfg and callee:
                    matching_lines = [
                        int(value.get("line") or 0)
                        for value in calls
                        if str(value.get("callee") or "") == callee
                    ]
                    index = per_callee_index.get(callee, 0)
                    if index < len(matching_lines):
                        line = matching_lines[index]
                    per_callee_index[callee] = index + 1
                statement = FunctionIRStatement(
                    statement_uid=statement_uid,
                    block_uid=block_uid,
                    ordinal=ordinal,
                    text=text,
                    source_line=line,
                )
                statements.append(statement)
                event_calls = bound_calls or (({"callee": callee, "line": line},) if callee else ())
                for call_index, bound_call in enumerate(event_calls):
                    event_callee = str(bound_call.get("callee") or "")
                    event_line = int(bound_call.get("line") or 0)
                    kind = cls._event_kind(
                        event_callee,
                        text,
                        callee_project_definition=call_project_definition(bound_call),
                        callee_provenance_valid=call_provenance_valid(bound_call),
                    )
                    if not kind:
                        continue
                    event_subject_text = cls._call_arguments(text) or text
                    if kind == "resource_acquire" and "=" in text:
                        event_subject_text = text.split("=", 1)[0]
                    events.append(
                        FunctionIREvent(
                            event_uid="EVENT_"
                            + _sha(
                                {
                                    "statement_uid": statement_uid,
                                    "kind": kind,
                                    "callee": event_callee,
                                    "call_index": call_index,
                                }
                            )[:32],
                            block_uid=block_uid,
                            statement_uid=statement_uid,
                            kind=kind,
                            callee=event_callee,
                            subject_symbols=_symbols(event_subject_text),
                            source_line=event_line,
                        )
                    )
                if not event_calls:
                    kind = cls._event_kind("", text)
                    if kind:
                        events.append(
                            FunctionIREvent(
                                event_uid="EVENT_"
                                + _sha(
                                    {
                                        "statement_uid": statement_uid,
                                        "kind": kind,
                                        "callee": "",
                                        "call_index": 0,
                                    }
                                )[:32],
                                block_uid=block_uid,
                                statement_uid=statement_uid,
                                kind=kind,
                                callee="",
                                subject_symbols=_symbols(text),
                                source_line=0,
                            )
                        )
            successors = tuple(
                value
                for value in (str(item) for item in raw_block.get("successors") or [])
                if value in block_ids
            )
            predecessors = tuple(
                value
                for value in (str(item) for item in raw_block.get("predecessors") or [])
                if value in block_ids
            )
            blocks.append(
                FunctionIRBlock(
                    block_uid=block_uid,
                    label=str(raw_block.get("label") or ""),
                    successors=successors,
                    predecessors=predecessors,
                    statements=tuple(statements),
                )
            )
        entries = tuple(str(value) for value in cfg.get("entry_blocks") or [] if str(value))
        exits = tuple(str(value) for value in cfg.get("exit_blocks") or [] if str(value))
        built_block_ids = tuple(block.block_uid for block in blocks)
        built_block_set = set(built_block_ids)
        raw_edges_valid = all(
            str(target) in built_block_set
            for raw_block in raw_blocks
            if isinstance(raw_block, Mapping) and str(raw_block.get("id") or "")
            for target in (
                *(raw_block.get("successors") or []),
                *(raw_block.get("predecessors") or []),
            )
        )
        edge_identities_unique = all(
            len(block.successors) == len(set(block.successors))
            and len(block.predecessors) == len(set(block.predecessors))
            for block in blocks
        )
        successor_map = {block.block_uid: set(block.successors) for block in blocks}
        reachable = {entries[0]} if len(entries) == 1 and entries[0] in built_block_set else set()
        pending = list(reachable)
        while pending:
            current = pending.pop()
            for target in successor_map.get(current, set()):
                if target not in reachable:
                    reachable.add(target)
                    pending.append(target)
        reachable_terminals = {value for value in reachable if not successor_map.get(value)}
        coverage_complete = bool(
            len(entries) == 1
            and entries[0] in built_block_set
            and exits
            and blocks
            and len(built_block_ids) == len(set(built_block_ids))
            and len(exits) == len(set(exits))
            and set(exits) <= built_block_set
            and set(exits) == reachable_terminals
            and raw_edges_valid
            and edge_identities_unique
            and governed_api_provenance_complete
            and cfg.get("truncated") is not True
            and cfg.get("parse_error") in (None, "")
            and (
                not semantic_cfg
                or (cfg.get("semantic_statements_complete") is True and typed_call_mapping_complete)
            )
        )
        dependency = {
            "function": function,
            "file": file,
            "cfg": cfg,
            "ast_target": ast_target,
        }
        code_hash = str(evidence.get("code_snapshot_sha256") or _sha(dependency))
        backend_hash = _sha(
            {
                "clang_path": evidence.get("clang_path"),
                "ast_command": evidence.get("ast_dump_command"),
                "cfg_command": evidence.get("cfg_dump_command"),
            }
        )
        body = {
            "function": function,
            "file": file,
            "entry_block_uid": entries[0] if entries else "",
            "exit_block_uids": exits,
            "blocks": [asdict(value) for value in blocks],
            "events": [asdict(value) for value in events],
            "ast_calls": calls,
            "ast_value_facts": value_facts,
            "ast_value_coverage_complete": ast_value_coverage_complete,
            "code_snapshot_sha256": code_hash,
            "backend_sha256": backend_hash,
            "coverage_complete": coverage_complete,
            "unresolved_dynamic_edges": bool(evidence.get("unresolved_dynamic_edges")),
            "schema_version": FUNCTION_IR_VERSION,
        }
        return cls(
            function=function,
            file=file,
            entry_block_uid=entries[0] if entries else "",
            exit_block_uids=exits,
            blocks=tuple(blocks),
            events=tuple(events),
            ast_calls=calls,
            ast_value_facts=tuple(value_facts),
            ast_value_coverage_complete=ast_value_coverage_complete,
            code_snapshot_sha256=code_hash,
            backend_sha256=backend_hash,
            coverage_complete=coverage_complete,
            unresolved_dynamic_edges=bool(evidence.get("unresolved_dynamic_edges")),
            ir_sha256=_sha(body),
        )

    def reachable(self, source_block: str, sink_block: str) -> Tuple[str, ...]:
        if source_block not in self.block_map or sink_block not in self.block_map:
            return ()
        queue: list[tuple[str, Tuple[str, ...]]] = [(source_block, (source_block,))]
        seen = {source_block}
        while queue:
            current, path = queue.pop(0)
            if current == sink_block:
                return path
            for successor in self.block_map[current].successors:
                if successor not in seen:
                    seen.add(successor)
                    queue.append((successor, (*path, successor)))
        return ()

    def statement_reachable(
        self,
        source_statement_uid: str,
        sink_statement_uid: str,
    ) -> Tuple[str, ...]:
        """Return a CFG path while respecting order inside one basic block."""

        source = self.statement_map.get(source_statement_uid)
        sink = self.statement_map.get(sink_statement_uid)
        if source is None or sink is None:
            return ()
        if source.block_uid == sink.block_uid:
            return (source.block_uid,) if source.ordinal <= sink.ordinal else ()
        return self.reachable(source.block_uid, sink.block_uid)

    def statement_dominates(
        self,
        guard_statement_uid: str,
        sink_statement_uid: str,
    ) -> bool:
        """Check block dominance plus statement order for same-block guards."""

        guard = self.statement_map.get(guard_statement_uid)
        sink = self.statement_map.get(sink_statement_uid)
        if guard is None or sink is None:
            return False
        if guard.block_uid == sink.block_uid:
            return guard.ordinal < sink.ordinal
        return guard.block_uid in self.dominators().get(sink.block_uid, frozenset())

    def event_precedes(self, left_event_uid: str, right_event_uid: str) -> Tuple[str, ...]:
        """Return the event path without allowing reversed same-block order."""

        left = self.event_map.get(left_event_uid)
        right = self.event_map.get(right_event_uid)
        if left is None or right is None:
            return ()
        return self.statement_reachable(left.statement_uid, right.statement_uid)

    def dominators(self) -> Dict[str, frozenset[str]]:
        ids = set(self.block_map)
        if not self.entry_block_uid or self.entry_block_uid not in ids:
            return {}
        result: Dict[str, set[str]] = {
            block: ({block} if block == self.entry_block_uid else set(ids)) for block in ids
        }
        changed = True
        while changed:
            changed = False
            for block in ids - {self.entry_block_uid}:
                predecessors = self.block_map[block].predecessors
                if not predecessors:
                    new = {block}
                else:
                    common = set(ids)
                    for predecessor in predecessors:
                        common.intersection_update(result.get(predecessor, set()))
                    new = {block, *common}
                if new != result[block]:
                    result[block] = new
                    changed = True
        return {key: frozenset(value) for key, value in result.items()}

    def must_hold_locksets(self) -> Dict[str, frozenset[str]]:
        """Forward must analysis; CFG joins intersect predecessor states."""

        blocks = self.block_map
        if not self.coverage_complete or not self.entry_block_uid:
            return {}
        in_sets: Dict[str, Optional[set[str]]] = {key: None for key in blocks}
        in_sets[self.entry_block_uid] = set()
        out_sets: Dict[str, set[str]] = {key: set() for key in blocks}
        changed = True
        iterations = 0
        while changed and iterations <= max(8, len(blocks) * 4):
            changed = False
            iterations += 1
            for block_uid, block in blocks.items():
                if block_uid != self.entry_block_uid:
                    predecessor_sets = [
                        out_sets[value] for value in block.predecessors if value in out_sets
                    ]
                    incoming = (
                        set.intersection(*(set(value) for value in predecessor_sets))
                        if predecessor_sets
                        else set()
                    )
                    if in_sets[block_uid] != incoming:
                        in_sets[block_uid] = incoming
                        changed = True
                state = set(in_sets[block_uid] or set())
                for event in self.events:
                    if event.block_uid != block_uid or not event.subject_symbols:
                        continue
                    subject = event.subject_symbols[0]
                    if event.kind == "lock_acquire":
                        state.add(subject)
                    elif event.kind == "lock_release":
                        state.discard(subject)
                if out_sets[block_uid] != state:
                    out_sets[block_uid] = state
                    changed = True
        return {key: frozenset(value or set()) for key, value in in_sets.items()}

    def must_hold_locksets_at_statements(self) -> Dict[str, frozenset[str]]:
        """Return the must-held locks immediately before every statement.

        Block-entry state alone is insufficient when a lock operation and the
        protected access share a CFG block.  This projection preserves the
        fixed-point join semantics and then replays events in statement order.
        """

        block_inputs = self.must_hold_locksets()
        event_by_statement = {event.statement_uid: event for event in self.events}
        result: Dict[str, frozenset[str]] = {}
        for block in self.blocks:
            state = set(block_inputs.get(block.block_uid, frozenset()))
            for statement in sorted(block.statements, key=lambda value: value.ordinal):
                result[statement.statement_uid] = frozenset(state)
                event = event_by_statement.get(statement.statement_uid)
                if event is None or not event.subject_symbols:
                    continue
                subject = event.subject_symbols[0]
                if event.kind == "lock_acquire":
                    state.add(subject)
                elif event.kind == "lock_release":
                    state.discard(subject)
        return result

    def resource_outstanding_at_exits(self, subject: str) -> Dict[str, bool]:
        """Conservatively track whether ``subject`` may remain owned at exits.

        The join is union/OR: cleanup is complete only when no incoming path
        can retain the resource.  This supports early returns and same-block
        acquire/release ordering without treating a dependency hash as proof.
        """

        blocks = self.block_map
        if not self.coverage_complete or not self.entry_block_uid or not subject:
            return {}
        incoming: Dict[str, bool] = {key: False for key in blocks}
        outgoing: Dict[str, bool] = {key: False for key in blocks}
        event_by_statement = {event.statement_uid: event for event in self.events}
        changed = True
        iterations = 0
        while changed and iterations <= max(8, len(blocks) * 4):
            changed = False
            iterations += 1
            for block_uid, block in blocks.items():
                if block_uid == self.entry_block_uid:
                    state = False
                else:
                    state = any(outgoing.get(value, False) for value in block.predecessors)
                if incoming[block_uid] != state:
                    incoming[block_uid] = state
                    changed = True
                for statement in sorted(block.statements, key=lambda value: value.ordinal):
                    event = event_by_statement.get(statement.statement_uid)
                    if event is None or subject not in event.subject_symbols:
                        continue
                    if event.kind == "resource_acquire":
                        state = True
                    elif event.kind == "resource_release":
                        state = False
                if outgoing[block_uid] != state:
                    outgoing[block_uid] = state
                    changed = True
        return {value: outgoing[value] for value in self.exit_block_uids if value in outgoing}

    def event_blocks(self, *kinds: str, subject: str = "") -> Tuple[str, ...]:
        wanted = set(kinds)
        return tuple(
            dict.fromkeys(
                event.block_uid
                for event in self.events
                if event.kind in wanted
                and (not subject or subject in event.subject_symbols or subject == event.callee)
            )
        )

    @classmethod
    def _typed_call_bindings(
        cls,
        block_texts: Mapping[str, Sequence[str]],
        calls: Sequence[Mapping[str, Any]],
        assignments: Sequence[Mapping[str, Any]],
    ) -> tuple[Dict[Tuple[str, int], Tuple[Dict[str, Any], ...]], bool]:
        """Bind typed AST calls to reconstructed CFG statement roots.

        Callee identity always comes from Clang's typed AST.  Statement text is
        used only to locate that already-proven symbol inside the CFG expression
        root.  A declaration initializer appears twice in ``debug.DumpCFG``
        (the call-expression root and the source-level declaration); the exact
        typed ``call_assignment`` selects the declaration and shadows only its
        immediately preceding plain call root.  Every other ambiguity fails
        closed instead of guessing a callee from cast/type text.
        """

        locations = [
            (block_uid, ordinal, str(text or "").strip())
            for block_uid, statements in block_texts.items()
            for ordinal, text in enumerate(statements)
        ]
        normalized_calls = [dict(value) for value in calls]
        if any(not str(value.get("callee") or "") for value in normalized_calls):
            return {}, False
        bindings: Dict[Tuple[str, int], list[Dict[str, Any]]] = {}
        mapped_call_indexes: set[int] = set()
        used_pairs: set[Tuple[Tuple[str, int, str], str]] = set()
        shadowed_locations: set[Tuple[str, int, str]] = set()

        def contains_call(text: str, callee: str) -> bool:
            return bool(re.search(rf"\b{re.escape(callee)}\s*\(", text))

        for assignment in assignments:
            callee = str(assignment.get("callee") or "")
            target = str(assignment.get("target") or "")
            line = int(assignment.get("line") or 0)
            if not callee or not target:
                return {}, False
            call_indexes = [
                index
                for index, call in enumerate(normalized_calls)
                if index not in mapped_call_indexes
                and str(call.get("callee") or "") == callee
                and int(call.get("line") or 0) == line
            ]
            assignment_locations = [
                location
                for location in locations
                if (location, callee) not in used_pairs
                and contains_call(location[2], callee)
                and re.search(
                    rf"\b{re.escape(target)}\b\s*=\s*.*\b{re.escape(callee)}\s*\(",
                    location[2],
                )
            ]
            if len(call_indexes) != 1 or len(assignment_locations) != 1:
                return {}, False
            call_index = call_indexes[0]
            location = assignment_locations[0]
            mapped_call_indexes.add(call_index)
            used_pairs.add((location, callee))
            bindings.setdefault(location[:2], []).append(normalized_calls[call_index])

            # Clang emits the initializer call expression immediately before
            # the source-level VarDecl without linking the two root entries.
            # Shadow that one exact plain call root; any additional candidate
            # remains ambiguous and is rejected below.
            plain_roots = [
                candidate
                for candidate in locations
                if (candidate, callee) not in used_pairs
                and candidate[0] == location[0]
                and candidate[1] == location[1] - 1
                and re.fullmatch(
                    rf"\s*{re.escape(callee)}\s*\(.*\)\s*;?\s*",
                    candidate[2],
                )
            ]
            if len(plain_roots) > 1:
                return {}, False
            if plain_roots:
                shadowed_locations.add(plain_roots[0])

        callees = sorted(
            {str(call.get("callee") or "") for call in normalized_calls if call.get("callee")}
        )
        for callee in callees:
            call_indexes = [
                index
                for index, call in enumerate(normalized_calls)
                if index not in mapped_call_indexes and str(call.get("callee") or "") == callee
            ]
            call_locations = [
                location
                for location in locations
                if (location, callee) not in used_pairs
                and location not in shadowed_locations
                and contains_call(location[2], callee)
            ]
            if len(call_indexes) != len(call_locations):
                return {}, False
            if len(call_indexes) == 1:
                resolved = [(call_indexes[0], call_locations[0])]
            else:
                # CFG block order is not source/AST order.  Repeated calls may
                # only be paired when their typed, ordered argument references
                # select one unique reconstructed root in both directions.
                candidates = {
                    call_index: [
                        location
                        for location in call_locations
                        if not bindings.get(location[:2])
                        or {
                            int(bound.get("line") or 0)
                            for bound in bindings[location[:2]]
                            if int(bound.get("line") or 0) > 0
                        }
                        in (
                            set(),
                            {int(normalized_calls[call_index].get("line") or 0)},
                        )
                        if cls._typed_call_matches_location(
                            normalized_calls[call_index],
                            location[2],
                        )
                    ]
                    for call_index in call_indexes
                }
                if any(len(values) != 1 for values in candidates.values()):
                    return {}, False
                selected = [values[0] for values in candidates.values()]
                if len(set(selected)) != len(selected):
                    return {}, False
                resolved = [(call_index, candidates[call_index][0]) for call_index in call_indexes]
            for call_index, location in resolved:
                mapped_call_indexes.add(call_index)
                used_pairs.add((location, callee))
                bindings.setdefault(location[:2], []).append(normalized_calls[call_index])

        if mapped_call_indexes != set(range(len(normalized_calls))):
            return {}, False
        bound_names = {
            location: {str(call.get("callee") or "") for call in values}
            for location, values in bindings.items()
        }
        for block_uid, ordinal, text in locations:
            location = (block_uid, ordinal, text)
            if location in shadowed_locations:
                continue
            names = cls._semantic_call_names(text)
            if names - bound_names.get((block_uid, ordinal), set()):
                return {}, False
        return (
            {
                location: tuple(values)
                for location, values in sorted(bindings.items(), key=lambda item: item[0])
            },
            True,
        )

    @staticmethod
    def _semantic_call_names(statement: str) -> set[str]:
        """Return call-shaped identifiers that require typed AST coverage."""

        excluded = {
            "if",
            "while",
            "for",
            "switch",
            "sizeof",
            "alignof",
            "_Alignof",
            "static_cast",
            "reinterpret_cast",
            "const_cast",
            "dynamic_cast",
        }
        return {
            value
            for value in re.findall(r"\b([A-Za-z_]\w*)\s*\(", str(statement or ""))
            if value not in excluded
        }

    @classmethod
    def _typed_call_matches_location(
        cls,
        call: Mapping[str, Any],
        statement: str,
    ) -> bool:
        """Match one typed call to one CFG root using ordered DeclRef identity.

        This helper never discovers a callee.  The callee and argument
        references already come from Clang's typed AST; the reconstructed CFG
        text is only accepted as their unique reachable location.
        """

        callee = str(call.get("callee") or "")
        raw_refs = call.get("argument_refs")
        if not callee or not isinstance(raw_refs, list):
            return False
        arguments = cls._call_argument_groups(statement, callee)
        raw_arg_count = call.get("arg_count")
        try:
            expected_count = int(raw_arg_count) if raw_arg_count is not None else len(raw_refs)
        except (TypeError, ValueError):
            expected_count = len(raw_refs)
        if arguments is None or expected_count != len(arguments) or len(raw_refs) != len(arguments):
            return False
        for refs, argument in zip(raw_refs, arguments):
            if not isinstance(refs, list):
                return False
            normalized_refs = [str(value or "") for value in refs if str(value or "")]
            if any(
                re.search(rf"\b{re.escape(ref)}\b", argument) is None for ref in normalized_refs
            ):
                return False
        return True

    @staticmethod
    def _call_argument_groups(statement: str, callee: str) -> Optional[Tuple[str, ...]]:
        matches = list(re.finditer(rf"\b{re.escape(callee)}\s*\(", statement or ""))
        if len(matches) != 1:
            return None
        start = matches[0].end()
        groups: list[str] = []
        current: list[str] = []
        paren_depth = 1
        bracket_depth = 0
        brace_depth = 0
        quote = ""
        escaped = False
        for char in str(statement or "")[start:]:
            if quote:
                current.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if char in {'"', "'"}:
                quote = char
                current.append(char)
                continue
            if char == "(":
                paren_depth += 1
                current.append(char)
            elif char == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    value = "".join(current).strip()
                    if value or groups:
                        groups.append(value)
                    return tuple(groups)
                if paren_depth < 0:
                    return None
                current.append(char)
            elif char == "[":
                bracket_depth += 1
                current.append(char)
            elif char == "]":
                if bracket_depth <= 0:
                    return None
                bracket_depth -= 1
                current.append(char)
            elif char == "{":
                brace_depth += 1
                current.append(char)
            elif char == "}":
                if brace_depth <= 0:
                    return None
                brace_depth -= 1
                current.append(char)
            elif char == "," and paren_depth == 1 and bracket_depth == 0 and brace_depth == 0:
                groups.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        return None

    @staticmethod
    def _callee(text: str) -> str:
        matches = re.findall(r"\b([A-Za-z_]\w*)\s*\(", text or "")
        return matches[-1] if matches else ""

    @staticmethod
    def _call_arguments(text: str) -> str:
        match = re.search(r"\b[A-Za-z_]\w*\s*\((.*)\)", text or "")
        return match.group(1) if match else ""

    @staticmethod
    def _event_kind(
        callee: str,
        text: str,
        *,
        callee_project_definition: bool = False,
        callee_provenance_valid: bool = True,
    ) -> str:
        name = callee.lower()
        # Governed API names are meaningful only when Clang binds the call to
        # a declaration outside this translation unit.  A project-defined
        # function named ``malloc``, ``free`` or ``pthread_create`` remains an
        # ordinary call and must not mint resource/thread/lock proof events.
        if name and callee_project_definition:
            return "call"
        governed_names = {
            "pthread_mutex_lock",
            "pthread_rwlock_rdlock",
            "pthread_rwlock_wrlock",
            "mtx_lock",
            "pthread_mutex_unlock",
            "pthread_rwlock_unlock",
            "mtx_unlock",
            "malloc",
            "calloc",
            "realloc",
            "strdup",
            "open",
            "fopen",
            "socket",
            "free",
            "close",
            "fclose",
            "munmap",
            "pthread_create",
            "thrd_create",
            "pthread_join",
            "thrd_join",
        }
        if name in governed_names and not callee_provenance_valid:
            return "call"
        if name in {
            "pthread_mutex_lock",
            "pthread_rwlock_rdlock",
            "pthread_rwlock_wrlock",
            "mtx_lock",
        }:
            return "lock_acquire"
        if name in {"pthread_mutex_unlock", "pthread_rwlock_unlock", "mtx_unlock"}:
            return "lock_release"
        if name in {"malloc", "calloc", "realloc", "strdup", "open", "fopen", "socket"}:
            return "resource_acquire"
        if name in {"free", "close", "fclose", "munmap"}:
            return "resource_release"
        if name in {"pthread_create", "thrd_create"}:
            return "thread_create"
        if name in {"pthread_join", "thrd_join"}:
            return "thread_join"
        if re.search(r"\breturn\b", text or ""):
            return "return"
        return "call" if callee else ""


def graph_from_mapping(raw: Mapping[str, Any]) -> FunctionIRGraph:
    """Strict helper for persisted and test-supplied graphs."""

    if str(raw.get("schema_version") or "") != FUNCTION_IR_VERSION:
        raise ValueError("unsupported FunctionIRGraph schema")
    blocks: list[FunctionIRBlock] = []
    events: list[FunctionIREvent] = []
    for raw_block in raw.get("blocks") or []:
        if not isinstance(raw_block, Mapping):
            raise ValueError("FunctionIRGraph block must be an object")
        statements = tuple(
            FunctionIRStatement(**dict(value))
            for value in raw_block.get("statements") or []
            if isinstance(value, Mapping)
        )
        blocks.append(
            FunctionIRBlock(
                block_uid=str(raw_block.get("block_uid") or ""),
                label=str(raw_block.get("label") or ""),
                successors=tuple(str(value) for value in raw_block.get("successors") or []),
                predecessors=tuple(str(value) for value in raw_block.get("predecessors") or []),
                statements=statements,
            )
        )
    for value in raw.get("events") or []:
        if isinstance(value, Mapping):
            normalized = dict(value)
            normalized["subject_symbols"] = tuple(normalized.get("subject_symbols") or [])
            events.append(FunctionIREvent(**normalized))
    graph = FunctionIRGraph(
        function=str(raw.get("function") or ""),
        file=str(raw.get("file") or ""),
        entry_block_uid=str(raw.get("entry_block_uid") or ""),
        exit_block_uids=tuple(str(value) for value in raw.get("exit_block_uids") or []),
        blocks=tuple(blocks),
        events=tuple(events),
        ast_calls=tuple(
            dict(value) for value in raw.get("ast_calls") or [] if isinstance(value, Mapping)
        ),
        ast_value_facts=tuple(
            dict(value) for value in raw.get("ast_value_facts") or [] if isinstance(value, Mapping)
        ),
        ast_value_coverage_complete=raw.get("ast_value_coverage_complete") is True,
        code_snapshot_sha256=str(raw.get("code_snapshot_sha256") or ""),
        backend_sha256=str(raw.get("backend_sha256") or ""),
        coverage_complete=raw.get("coverage_complete") is True,
        unresolved_dynamic_edges=raw.get("unresolved_dynamic_edges") is True,
        ir_sha256=str(raw.get("ir_sha256") or ""),
    )
    body = graph.to_dict()
    supplied = body.pop("ir_sha256", "")
    if not supplied or supplied != _sha(body):
        raise ValueError("FunctionIRGraph hash mismatch")
    return graph
