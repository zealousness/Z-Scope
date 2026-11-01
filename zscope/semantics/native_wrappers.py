"""Bounded native value flow for direct C allocation wrappers.

This adapts the existing CFG/USR receipt into ApiContract, not another lifetime
checker. Unsupported input is diagnostic and cannot fall back to token authority.
The supported slice includes direct malloc-family allocation/reallocation and
release wrappers.  Protocol pools, indirect calls and C++ remain excluded.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import re
from pathlib import Path
from typing import Any, Mapping, TypedDict

from .build_scope import context_build_id, source_scope_problem
from .contract_conditions import compare, conjunction, evaluate, negate, predicate_errors
from .contracts import (
    ApiContract,
    ContractRegistry,
    ObjectBinding,
    SymbolIdentity,
    code_tokens,
    digest,
    CONTRACT_COMPILER_VERSION,
)

TRUE = {"op": "true"}

# A generic ``standard_operation`` role only tells consumers that an API is
# not an allocator/releaser.  Publishing every project helper around strlen,
# strcmp, memcpy, and similar operations created hundreds of human-review
# rows without giving any rule a mechanism it could replay.  These path-state
# queries are the deliberately small composable subset whose delegated root
# is consumed by the TOCTOU/path protocol rules.  Other standard operations
# remain visible in native function facts and are analysed in their bodies;
# they are not promoted into reviewer-owned project contracts.
DISCOVERABLE_STANDARD_OPERATION_ROOTS = frozenset(
    {"access", "stat", "lstat", "faccessat", "fstatat"}
)


class NativeInference(TypedDict):
    attempted: bool
    contracts: list[dict[str, Any]]
    reasons: list[str]


class Unsupported(Exception):
    pass


def compact(value: Any) -> str:
    return "".join(code_tokens(str(value or "")))


def literal(value: Any) -> dict[str, Any]:
    return {"kind": "literal", "value": value}


def impossible(guard: dict[str, Any]) -> bool:
    return (
        guard == {"op": "false"}
        or evaluate(guard) == "does_not_apply"
        or "contradictory_effect_condition" in predicate_errors(guard)
    )


def implies(guard: dict[str, Any], condition: dict[str, Any]) -> bool:
    return (
        condition == TRUE
        or condition == guard
        or impossible(conjunction([guard, negate(condition)]))
    )


@dataclass
class State:
    values: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: dict[str, dict[str, Any]] = field(default_factory=dict)
    outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    guard: dict[str, Any] = field(default_factory=lambda: dict(TRUE))
    releases: set[str] = field(default_factory=set)
    acquired: set[str] = field(default_factory=set)
    outward_releases: dict[str, dict[str, Any]] = field(default_factory=dict)
    path: list[int] = field(default_factory=list)
    returned: dict[str, Any] | None = None
    opaque_calls: list[str] = field(default_factory=list)


class NativeWrapper:
    def __init__(self, context: Mapping[str, Any], registry: ContractRegistry):
        self.context, self.registry = context, registry.for_context(context)
        self.facts = context.get("program_facts") or {}
        self.build = context_build_id(context)
        self.body: dict[str, Any] = {}
        self.names: dict[str, str] = {}
        self.fields: dict[str, str] = {}
        self.locals: set[str] = set()
        self.unsigned_parameters: set[str] = set()
        self.parameters: list[str] = []
        self.bindings: dict[str, ObjectBinding] = {}
        self.resources: dict[str, dict[str, Any]] = {}
        self.input_resources: dict[str, dict[str, Any]] = {}
        self.roots: dict[str, ApiContract] = {}
        self.sites: list[dict[str, Any]] = []
        self.steps = 0

    def source_file(self, path: str) -> str:
        value = Path(path)
        root = str(self.context.get("project_root") or "")
        if not value.is_absolute() and root:
            value = Path(root) / value
        return str(value.resolve()) if value.is_absolute() else str(value)

    def prepare(self, *, allow_record_values: bool = False) -> None:
        from .contract_compiler import closing

        bodies = self.facts.get("functions") or []
        if (
            source_scope_problem(self.context)
            or not self.build
            or not self.facts.get("complete")
            or len(bodies) != 1
        ):
            raise Unsupported("native_scope_unavailable")
        body = self.body = bodies[0]
        if (
            not str(self.context.get("file_path", "")).endswith(".c")
            or not body.get("complete")
            or not body.get("owner", {}).get("usr")
            or self.source_file(str(body["owner"].get("file") or ""))
            != self.source_file(str(self.context.get("file_path") or ""))
            or body["owner"].get("name") != self.context.get("func_name")
            or body.get("fact_version") != "zscope.program-events.v7"
            or body.get("lifecycle_value_facts_version") != "zscope.lifecycle-value-facts.v1"
        ):
            raise Unsupported("native_value_receipt_unavailable")
        if any(not isinstance(body.get(k), int) for k in ("cfg_entry", "cfg_exit")) or any(
            not isinstance(body.get(k), list) for k in ("events", "cfg_edges", "parameters")
        ):
            raise Unsupported("native_cfg_unavailable")
        if body.get("return_value_kind") not in {"pointer", "integer", "void"}:
            raise Unsupported("unsupported_wrapper_return")
        if body.get("return_value_kind") == "integer" and (
            body.get("return_integer_unsigned") or int(body.get("return_integer_bits") or 0) < 32
        ):
            raise Unsupported("return_conversion_unclosed")
        for parameter in body.get("parameters", []):
            name, usr = parameter.get("name"), parameter.get("usr")
            if not name or not usr or parameter.get("referenced_usr") != usr:
                raise Unsupported("parameter_identity_missing")
            self.names[name] = usr
            self.locals.add(usr)
            if parameter.get("integer_unsigned"):
                self.unsigned_parameters.add(usr)
            self.parameters.append(name)
        source = compact(self.context.get("code"))
        tokens = code_tokens(str(self.context.get("code") or ""))
        source_guards = {
            "".join(tokens[i + 2 : closing(tokens, i + 1)])
            for i, token in enumerate(tokens[:-1])
            if token in {"if", "while"} and tokens[i + 1] == "("
        }
        native_guards = {
            compact(edge["condition"])
            for edge in body.get("cfg_edges", [])
            if edge.get("condition")
        }

        def guard_atoms(values: set[str]) -> set[str]:
            atoms: set[str] = set()
            for value in values:
                current: list[str] = []
                depth = 0
                for token in code_tokens(value):
                    if token == "(":
                        depth += 1
                    elif token == ")":
                        depth = max(0, depth - 1)
                    if depth == 0 and token in {"&&", "||"}:
                        if current:
                            atoms.add(compact("".join(current)))
                            current = []
                        continue
                    current.append(token)
                if current:
                    atoms.add(compact("".join(current)))
            return atoms

        # Clang may materialize short-circuit operands as separate CFG edge
        # predicates.  The native CFG remains authoritative for grouping and
        # reachability, while this source-currentness check compares the exact
        # predicate leaves so a changed source guard cannot reuse old facts.
        if guard_atoms(source_guards) != guard_atoms(native_guards):
            raise Unsupported("native_cfg_condition_conflict")
        marker = "@F@" + str(body["owner"].get("name") or "") + "@"
        for event in body.get("events", []):
            if (
                event.get("contains_macro") is False
                and compact(event.get("expression")) not in source
            ):
                raise Unsupported("source_native_conflict")
            for value in [
                *event.get("defs", []),
                *event.get("uses", []),
                *(v for group in event.get("argument_uses", []) for v in group),
            ]:
                if any(
                    value.get(k)
                    for k in (
                        "overlapping_storage",
                        "volatile_or_atomic",
                        "floating_value",
                    )
                ) or (value.get("record_value") and not allow_record_values):
                    raise Unsupported("unsupported_native_value_kind")
                bits = value.get("integer_bits", 0)
                if bits and (
                    bits < 32
                    or (
                        value.get("integer_unsigned")
                        and value.get("usr") not in self.unsigned_parameters
                        and value.get("value_kind") != "local"
                    )
                ):
                    raise Unsupported("scalar_conversion_unclosed")
                name, usr = value.get("name"), value.get("usr")
                if not name or not usr:
                    continue
                if value.get("value_kind") == "field":
                    expr = compact(value.get("expression"))
                    if expr in self.fields and self.fields[expr] != usr:
                        raise Unsupported("ambiguous_field_identity")
                    self.fields[expr] = usr
                else:
                    if name in self.names and self.names[name] != usr:
                        raise Unsupported("shadowed_local_identity")
                    self.names[name] = usr
                    if value.get("value_kind") == "local" or marker in usr:
                        self.locals.add(usr)

    def location(self, text: str, state: State) -> str:
        from .contract_compiler import unparen

        text = "".join(unparen(code_tokens(text)))
        if text in self.names:
            return self.names[text]
        if text.startswith("*"):
            pointer = self.value(text[1:], state)
            if pointer.get("kind") == "address":
                return str(pointer["location"])
            if pointer.get("kind") == "argument" and not pointer.get("member_path"):
                binding = ObjectBinding("output_argument", pointer["index"])
                key = "output:" + digest(asdict(binding))
                self.bindings[key] = binding
                return key
        match = re.fullmatch(r"([A-Za-z_]\w*)->([A-Za-z_]\w*)", text)
        if match and text in self.fields:
            receiver = self.value(match[1], state)
            if receiver.get("kind") == "argument" and not receiver.get("member_path"):
                binding = ObjectBinding("argument", receiver["index"], member_path="->" + match[2])
                key = "field:" + digest([asdict(binding), self.fields[text]])
                self.bindings[key] = binding
                return key
        raise Unsupported("unresolved_store_identity")

    def value(self, text: str, state: State) -> dict[str, Any]:
        from .contract_compiler import unparen

        text = compact(text)
        if text in {"((void*)0)", "NULL"}:
            return literal(None)
        text = "".join(unparen(code_tokens(text)))
        # Preserve object identity across an explicit C pointer cast of a
        # native-observed call result.  Clang emits the nested CallExpr and
        # its exact result target separately from the declaration initializer
        # (for example ``char *p = (char *)safe_malloc(n)``).  The cast cannot
        # create a new allocation or alias; only an already replayed exact
        # call may pass this narrow path.
        pointer_cast = re.fullmatch(
            r"\((?:(?:const|volatile|restrict|struct|union|enum)" r"|[A-Za-z_]\w*)+\*+\)(.+)",
            text,
        )
        if pointer_cast and pointer_cast.group(1) in state.calls:
            return state.calls[pointer_cast.group(1)]
        if re.fullmatch(r"-?\d+", text):
            literal_value = int(text)
            if not -(2**31) <= literal_value < 2**31:
                raise Unsupported("integer_range_unclosed")
            return literal(literal_value)
        if text.startswith("&"):
            return {"kind": "address", "location": self.location(text[1:], state)}
        if text in state.calls:
            return state.calls[text]
        derived_calls = [
            (call, value)
            for call, value in state.calls.items()
            if text.startswith(call) and re.fullmatch(re.escape(call) + r"(?:[+-]\d+)+", text)
        ]
        if len(derived_calls) == 1:
            call, value = derived_calls[0]
            return {
                "kind": "derived_value",
                "expression": text,
                "base": value,
                "suffix": text[len(call) :],
            }
        location = self.location(text, state)
        if location not in state.values:
            raise Unsupported("value_not_defined_in_current_frame")
        return state.values[location]

    def predicate(self, text: str, state: State) -> dict[str, Any]:
        from .contract_compiler import source_predicate, unparen

        text = "".join(unparen(code_tokens(text)))
        aliases = {
            name: state.values[usr] for name, usr in self.names.items() if usr in state.values
        }
        result = source_predicate(code_tokens(text), self.parameters, aliases)
        if result.get("op") == "unknown" or predicate_errors(result):
            raise Unsupported("branch_value_unclosed")
        return result

    def mapped(self, value: Any, args: list[dict[str, Any]], returned: dict[str, Any]) -> Any:
        if isinstance(value, list):
            return [self.mapped(v, args, returned) for v in value]
        if not isinstance(value, dict):
            return value
        if value.get("kind") == "return":
            return returned
        if value.get("kind") == "argument":
            index = value.get("index", value.get("argument_index"))
            if (
                type(index) is not int
                or not 0 <= index < len(args)
                or value.get("member_path")
                or value.get("address_of")
            ):
                raise Unsupported("root_condition_mapping_unclosed")
            return args[index]
        return {k: self.mapped(v, args, returned) for k, v in value.items()}

    def interface_mapped(self, value: Any, args: list[dict[str, Any]]) -> Any:
        """Map a root protocol reference into the wrapper's public frame."""
        if isinstance(value, list):
            return [self.interface_mapped(item, args) for item in value]
        if not isinstance(value, dict):
            return value
        kind = value.get("kind")
        if kind == "return":
            return {"kind": "return"}
        if kind == "argument":
            index = value.get("index", value.get("argument_index"))
            if type(index) is not int or not 0 <= index < len(args):
                raise Unsupported("root_protocol_mapping_unclosed")
            mapped = args[index]
            if mapped.get("kind") != "argument" or mapped.get("member_path"):
                raise Unsupported("root_protocol_mapping_unclosed")
            return {"kind": "argument", "index": mapped["index"]}
        return {key: self.interface_mapped(item, args) for key, item in value.items()}

    def opaque_call(self, event: dict[str, Any], state: State) -> None:
        """Retain a side-effecting call only for a later non-export-path check.

        The call may not consume the tracked resource or define a value used by
        the wrapper.  ``run`` subsequently proves it occurs only on exits that
        do not export the acquisition.  This admits logging on allocation
        failure without treating arbitrary successful-path helpers as harmless.
        """
        target = self.call_target(event)
        if target.get("usr"):
            raise Unsupported("opaque_call_result_unclosed")
        tracked_locations = {
            location
            for location, value in state.values.items()
            if value.get("kind") == "call_result" and str(value.get("name") or "") in self.resources
        }
        used = {
            str(value.get("usr") or "")
            for group in event.get("argument_uses", [])
            for value in group
            if isinstance(value, dict)
        }
        if tracked_locations & used:
            raise Unsupported("opaque_call_observes_resource")
        state.opaque_calls.append(str(event.get("event_id") or event.get("expression") or "call"))

    @staticmethod
    def call_target(event: Mapping[str, Any]) -> dict[str, Any]:
        target = event.get("object") or {}
        if isinstance(target, dict) and target.get("usr"):
            return target
        definitions = [
            value
            for value in event.get("defs", []) or []
            if isinstance(value, dict) and value.get("usr")
        ]
        # Nested calls inside a declaration/assignment are emitted separately;
        # their single native def is the value-transfer target.
        return definitions[0] if len(definitions) == 1 else {}

    def call(self, event: dict[str, Any], state: State) -> None:
        from .contract_compiler import _base_cases

        callee = event.get("callee") or {}
        if not callee.get("usr"):
            raise Unsupported("indirect_or_unresolved_call")
        # Native events already identify the exact callee. Discovery runs
        # outside a scanner's call-context binding, so omitting USR here
        # incorrectly rejects every pinned project wrapper in the next layer.
        rows = self.registry.find_for_call(str(callee.get("name") or ""), usr=str(callee["usr"]))
        if len(rows) != 1 or not rows[0].effects_trusted:
            self.opaque_call(event, state)
            return
        root = rows[0]
        if (
            root.source == "builtin_defaults"
            and callee.get("has_definition")
            and not callee.get("is_system_header")
        ):
            raise Unsupported("project_shadows_standard")
        if root.symbol.file_path and self.source_file(root.symbol.file_path) != self.source_file(
            str(callee.get("location", {}).get("file") or "")
        ):
            raise Unsupported("root_symbol_mismatch")
        if root.role in {"standard_operation", "copy"}:
            if (
                (root.protocol and root.protocol.get("kind") != "standard_api_effects")
                or root.protocol.get("transitions")
                or root.resource_domain
            ):
                raise Unsupported("root_effect_not_supported")
        elif (
            (root.protocol and root.protocol.get("kind") != "standard_api_effects")
            or root.resource_domain
            or root.resource_family != "malloc"
            or root.role not in {"allocator", "calloc", "reallocator", "deallocator"}
            or (root.protocol.get("transitions") and root.role != "reallocator")
        ):
            raise Unsupported("root_effect_not_supported")
        if root.preconditions != TRUE:
            raise Unsupported("root_precondition_unclosed")
        self.roots[digest(root.to_dict())] = root
        args = [self.value(text, state) for text in event.get("arguments", [])]
        site = str(event["location"]["offset"])
        returned = {"kind": "call_result", "name": self.body["owner"]["usr"] + ":" + site}
        state.calls[compact(event["expression"])] = returned
        target = self.call_target(event)
        if target.get("usr"):
            if target["usr"] not in self.locals:
                raise Unsupported("external_store")
            state.values[target["usr"]] = returned
        if root.role == "standard_operation":
            return
        if root.role == "copy":
            index = root.carrier.argument_index
            if (
                root.carrier.kind != "argument"
                or root.carrier.member_path
                or index is None
                or index >= len(args)
            ):
                raise Unsupported("copy_carrier_unclosed")
            destination = args[index]
            resource = str(destination.get("name") or "")
            if resource not in self.resources or resource in state.releases:
                raise Unsupported("copy_destination_not_tracked_resource")
            return
        if root.role == "deallocator":
            index = root.carrier.argument_index
            if (
                root.carrier.kind != "argument"
                or root.carrier.member_path
                or index is None
                or index >= len(args)
            ):
                raise Unsupported("release_carrier_unclosed")
            condition = [
                self.mapped(c["when"], args, returned)
                for c in _base_cases(root)
                if c["effect"] == "applies"
            ]
            # A nullable free is a possible release until non-null is known.
            # It may clean an error exit, but forbids exporting that value as live.
            if not any(
                implies(state.guard, c) or c == compare(args[index], "!=", None) for c in condition
            ):
                raise Unsupported("release_condition_unclosed")
            value = args[index]
            if value.get("kind") == "literal" and value.get("value") in {None, 0}:
                return
            if value.get("kind") == "argument" and not value.get("member_path"):
                uid = "input:" + digest(value)
                if state.acquired or uid in state.outward_releases:
                    raise Unsupported("mixed_or_repeated_input_release")
                binding = ObjectBinding("argument", value["index"])
                previous_release = self.input_resources.get(uid)
                if previous_release and previous_release["root"] != root:
                    raise Unsupported("branch_dependent_release_root")
                self.input_resources[uid] = {"root": root, "carrier": binding}
                when = condition[0] if len(condition) == 1 else {"op": "any", "items": condition}
                state.outward_releases[uid] = conjunction([state.guard, when])
                return
            resource = str(value.get("name") or "")
            if resource not in self.resources or resource in state.releases:
                raise Unsupported("unknown_or_repeated_internal_release")
            acquire = self.resources[resource]["root"]
            if not self.registry.allows(acquire.symbol.name, root.symbol.name):
                raise Unsupported("release_pair_unclosed")
            state.releases.add(resource)
            return
        resource_value = returned
        if state.outward_releases:
            raise Unsupported("mixed_input_release_and_acquisition")
        if root.carrier.kind == "output_argument":
            index = root.carrier.argument_index
            if index is None or index >= len(args) or root.carrier.member_path:
                raise Unsupported("acquisition_output_unclosed")
            arg = args[index]
            if arg.get("kind") == "address":
                location = str(arg["location"])
            elif arg.get("kind") == "argument":
                location = self.location("*" + self.parameters[arg["index"]], state)
            else:
                raise Unsupported("acquisition_output_unclosed")
            resource_value = {"kind": "call_result", "name": returned["name"] + ":resource"}
            state.values[location] = resource_value
            if location in self.bindings:
                state.outputs[location] = resource_value
        elif root.carrier.kind != "return":
            raise Unsupported("acquisition_carrier_unclosed")
        uid = resource_value["name"]
        previous = self.resources.get(uid)
        if previous and previous["arguments"] != args:
            raise Unsupported("branch_dependent_resource_arguments")
        self.resources[uid] = {
            "root": root,
            "event": event,
            "value": resource_value,
            "arguments": args,
            "success": [
                self.mapped(c["when"], args, returned)
                for c in _base_cases(root)
                if c["effect"] == "applies"
            ],
            "failure": [
                self.mapped(c["when"], args, returned)
                for c in _base_cases(root)
                if c["effect"] == "no_effect"
            ],
        }
        state.acquired.add(uid)
        if len(state.acquired) > 1:
            raise Unsupported("multiple_internal_resources")

    def walk(self, block: int, state: State) -> list[State]:
        if block in state.path or len(state.path) > 32:
            raise Unsupported("cyclic_or_deep_cfg")
        state.path.append(block)
        if block == self.body.get("cfg_exit"):
            return [state]
        events = sorted(
            (e for e in self.body["events"] if e["block"] == block), key=lambda e: e["ordinal"]
        )
        seen = set()
        for event in events:
            self.steps += 1
            if self.steps > 512:
                raise Unsupported("native_flow_budget")
            kind = event.get("event_kind")
            if kind == "call":
                key = (event.get("location", {}).get("offset"), event.get("callee", {}).get("usr"))
                if key in seen:
                    continue
                seen.add(key)
                primary = [
                    e
                    for e in events
                    if e.get("event_kind") == "call"
                    and (e.get("location", {}).get("offset"), e.get("callee", {}).get("usr")) == key
                    and e.get("contains_macro") is False
                ]
                # A macro such as LOG_ERROR may expand directly to one
                # source-resolved call without a second non-macro CallExpr.
                # It is still safe to replay as an opaque call when the exact
                # callee USR is present.  Multiple expansion calls remain
                # ambiguous and are rejected.
                if not primary:
                    expanded = [
                        e
                        for e in events
                        if e.get("event_kind") == "call"
                        and (
                            e.get("location", {}).get("offset"),
                            e.get("callee", {}).get("usr"),
                        )
                        == key
                        and e.get("callee", {}).get("usr")
                    ]
                    if len(expanded) == 1:
                        primary = expanded
                if len(primary) != 1:
                    raise Unsupported("ambiguous_native_call_site")
                event = primary[0]
            if (
                event.get("contains_macro") is not False
                and not event.get("null_pointer_constant")
                and not (kind == "call" and (event.get("callee") or {}).get("usr"))
            ):
                raise Unsupported("macro_effect_unclosed")
            self.sites.append(
                {
                    "event_id": event.get("event_id"),
                    "location": event.get("location"),
                    "defs": [v.get("usr") for v in event.get("defs", []) if v.get("usr")],
                    "uses": [v.get("usr") for v in event.get("uses", []) if v.get("usr")],
                }
            )
            if kind == "call":
                self.call(event, state)
            elif kind in {"assignment", "declaration_initializer"}:
                destination = self.location(event["assignment_target"], state)
                if destination in self.unsigned_parameters:
                    raise Unsupported("unsigned_parameter_write_unclosed")
                value = self.value(event["assignment_value"], state)
                state.values[destination] = value
                if destination in self.bindings:
                    state.outputs[destination] = value
                elif destination not in self.locals:
                    raise Unsupported("external_store")
            elif kind == "return":
                state.returned = (
                    self.value(event["return_value"], state)
                    if event.get("return_value")
                    else literal(None)
                )
                return [state]
            elif kind == "statement":
                # Native guard leaves are pure only within this expression subset.
                if event.get("null_pointer_constant"):
                    continue
                if (
                    event.get("ast_kind") == "DeclStmt"
                    and event.get("defs")
                    and all(v.get("usr") in self.locals for v in event["defs"])
                    and not set(code_tokens(event.get("expression", "")))
                    & {"=", "(", "[", "{", "static", "extern", "_Thread_local"}
                ):
                    continue  # Declared, still undefined until a checked write.
                try:
                    self.value(event["expression"], state)
                except Unsupported:
                    self.predicate(event["expression"], state)
            else:
                raise Unsupported("unsupported_native_event:" + str(kind))
        outgoing = [e for e in self.body["cfg_edges"] if e["from"] == block]
        if not outgoing:
            raise Unsupported("missing_cfg_exit")
        result = []
        for edge in outgoing:
            child = deepcopy(state)
            if edge.get("condition"):
                if edge.get("branch") not in {"true", "false"}:
                    raise Unsupported("unknown_cfg_branch")
                condition = self.predicate(edge["condition"], child)
                child.guard = conjunction(
                    [child.guard, condition if edge["branch"] == "true" else negate(condition)]
                )
            elif len(outgoing) != 1:
                raise Unsupported("unlabelled_cfg_branch")
            if not impossible(child.guard):
                result.extend(self.walk(edge["to"], child))
        return result

    def run(self) -> list[dict[str, Any]]:
        self.prepare()
        initial = State(
            values={
                self.names[n]: {"kind": "argument", "index": i}
                for i, n in enumerate(self.parameters)
            }
        )
        states = self.walk(self.body["cfg_entry"], initial)
        if self.input_resources:
            if self.resources or len(self.input_resources) != 1:
                raise Unsupported("multiple_interface_effects")
            uid, released = next(iter(self.input_resources.items()))
            whens = list(
                {
                    digest(s.outward_releases[uid]): s.outward_releases[uid]
                    for s in states
                    if uid in s.outward_releases
                }.values()
            )
            when = whens[0] if len(whens) == 1 else {"op": "any", "items": whens}
            return [
                self.contract(
                    released["root"],
                    released["carrier"],
                    [
                        {"when": when, "effect": "applies"},
                        {"when": negate(when), "effect": "no_effect"},
                    ],
                    {},
                )
            ]
        if not states or len(self.resources) != 1:
            raise Unsupported("not_a_single_resource_wrapper")
        uid, resource = next(iter(self.resources.items()))
        root = resource["root"]
        carrier: ObjectBinding | None = None
        cases: list[dict[str, Any]] = []
        for state in states:
            if len(state.outputs) > 1:
                raise Unsupported("multiple_output_slots_without_alias_proof")
            returned = state.returned or {}
            exports = [key for key, value in state.outputs.items() if value == resource["value"]]
            if returned == resource["value"]:
                if self.body["return_value_kind"] != "pointer":
                    raise Unsupported("resource_return_conversion_unclosed")
                if exports:
                    raise Unsupported("additional_external_retention")
                current = ObjectBinding("return")
                condition = compare({"kind": "return"}, "!=", None)
                success = (
                    root.carrier.kind == "return"
                    and any(
                        c in (TRUE, compare(resource["value"], "!=", None))
                        for c in resource["success"]
                    )
                ) or any(implies(state.guard, c) for c in resource["success"])
            elif (
                returned.get("kind") == "literal"
                and returned.get("value") in {None, 0}
                and self.body["return_value_kind"] == "pointer"
            ):
                cases.append(
                    {"when": compare({"kind": "return"}, "==", None), "effect": "no_effect"}
                )
                continue
            elif returned.get("kind") == "literal" and self.body["return_value_kind"] == "integer":
                condition = compare({"kind": "return"}, "==", returned["value"])
                if not exports or any(implies(state.guard, c) for c in resource["failure"]):
                    cases.append({"when": condition, "effect": "no_effect"})
                    continue
                if len(exports) != 1:
                    raise Unsupported("multiple_output_carriers")
                current = self.bindings[exports[0]]
                success = any(implies(state.guard, c) for c in resource["success"])
            else:
                raise Unsupported("borrowed_or_unresolved_return")
            if uid in state.releases:
                raise Unsupported("resource_released_before_export")
            if uid not in state.acquired or not success:
                raise Unsupported("acquisition_success_unclosed")
            if state.opaque_calls:
                raise Unsupported("opaque_call_on_export_path")
            if carrier is not None and carrier != current:
                raise Unsupported("inconsistent_output_carrier")
            carrier = current
            cases.append({"when": condition, "effect": "applies"})
        if carrier is None:
            raise Unsupported("no_live_resource_export")
        for case in cases:
            if any(c["when"] == case["when"] and c["effect"] != case["effect"] for c in cases):
                raise Unsupported("ambiguous_return_status")
        applies = list(
            {digest(c["when"]): c["when"] for c in cases if c["effect"] == "applies"}.values()
        )
        # All exits have been enumerated. Other returned status values do not
        # export this acquisition; this also composes explicit != 0 wrappers.
        success_when: dict[str, Any] = (
            applies[0] if len(applies) == 1 else {"op": "any", "items": applies}
        )
        cases = [
            {"when": success_when, "effect": "applies"},
            {"when": negate(success_when), "effect": "no_effect"},
        ]
        protocol = {}
        extent = root.protocol.get("allocation_extent")
        if extent:
            mapped_extent = self.mapped(extent, resource["arguments"], resource["value"])
            if all(v.get("kind") in {"argument", "literal"} for v in mapped_extent):
                protocol = {
                    "kind": "standard_api_effects",
                    "transitions": [],
                    "allocation_extent": mapped_extent,
                }
        if root.role == "reallocator":
            transitions = root.protocol.get("transitions") or []
            if not transitions:
                raise Unsupported("reallocation_protocol_missing")
            protocol = {
                **protocol,
                "kind": "standard_api_effects",
                "transitions": self.interface_mapped(transitions, resource["arguments"]),
            }
        return [self.contract(root, carrier, cases, protocol)]

    def contract(
        self,
        root: ApiContract,
        carrier: ObjectBinding,
        cases: list[dict[str, Any]],
        protocol: dict[str, Any],
    ) -> dict[str, Any]:
        from .contract_review import proof_key

        return {
            "symbol": asdict(
                SymbolIdentity.from_value(
                    {"usr": self.body["owner"]["usr"]},
                    name=self.context.get("func_name"),
                    file_path=self.context.get("file_path"),
                    signature=self.context.get("signature"),
                    build_context_id=self.build,
                )
            ),
            "role": root.role,
            "carrier": asdict(carrier),
            "conditions": [],
            "preconditions": dict(TRUE),
            "effect_cases": list({digest(c): c for c in cases}.values()),
            "pairs": (
                [asdict(p.release) for p in self.registry.pairs if p.acquire == root.symbol]
                if root.role != "deallocator"
                else [asdict(p.acquire) for p in self.registry.pairs if p.release == root.symbol]
            ),
            "resource_family": root.resource_family,
            "protocol": protocol,
            "source": "inferred:semantic_modeling",
            "confidence": 1.0,
            "delegates": [
                {
                    "symbol": asdict(root.symbol),
                    "role": root.role,
                    "carrier": asdict(root.carrier),
                    "transparent": True,
                }
            ],
            "evidence": [
                {
                    "function_usr": self.body["owner"]["usr"],
                    "build_context_id": self.build,
                    "native_input_hash": digest(self.body),
                    "sites": list({digest(s): s for s in self.sites}.values()),
                }
            ],
            "verification": {
                "method": "source_composition",
                "checker": "native_wrapper_value_flow.v2",
                "mapping_verified": True,
                "proof_authority": False,
                "effect_strength": "must_under_guard",
                "compiler_version": CONTRACT_COMPILER_VERSION,
                "source_hash": digest(code_tokens(str(self.context.get("code") or ""))),
                "proof_dependencies": sorted({proof_key(r) for r in self.roots.values()}),
                "native_input_hash": digest(self.body),
                "fresh_no_alias": False,
                "assumptions": [
                    assumption
                    for r in self.roots.values()
                    for assumption in (
                        deepcopy(r.verification.get("assumptions", []))
                        + (
                            [{"symbol": asdict(r.symbol), "source": r.source}]
                            if not r.source.startswith("inferred")
                            and r.source != "builtin_defaults"
                            else []
                        )
                    )
                ],
            },
        }


def _infer_returned_standard_operation(
    context: Mapping[str, Any], registry: ContractRegistry
) -> list[dict[str, Any]]:
    """Compile a transparent predicate/query wrapper around one exact root.

    This deliberately covers only a single direct ``standard_operation`` used
    in the wrapper's return expression.  It is enough for project predicates
    such as ``file_exists(path) -> stat(path, ...)`` without treating an
    arbitrary function that happens to call ``stat`` as a semantic wrapper.
    """

    from .contract_review import proof_key

    wrapper = NativeWrapper(context, registry)
    wrapper.prepare(allow_record_values=True)
    unique_events: dict[tuple[str, int, str], Mapping[str, Any]] = {}
    for raw in wrapper.body.get("events", []) or []:
        if not isinstance(raw, Mapping) or raw.get("event_kind") != "call":
            continue
        raw_callee = raw.get("callee")
        callee: Mapping[str, Any] = raw_callee if isinstance(raw_callee, Mapping) else {}
        raw_location = raw.get("location")
        location: Mapping[str, Any] = raw_location if isinstance(raw_location, Mapping) else {}
        key = (
            str(callee.get("usr") or callee.get("name") or ""),
            int(location.get("offset") or 0),
            str(raw.get("expression") or ""),
        )
        unique_events[key] = raw
    if len(unique_events) != 1:
        return []
    event = next(iter(unique_events.values()))
    raw_callee = event.get("callee")
    callee = raw_callee if isinstance(raw_callee, Mapping) else {}
    callee_name = str(callee.get("name") or "")
    roots = [
        row
        for row in wrapper.registry.find_for_call(callee_name, usr=str(callee.get("usr") or ""))
        if row.role == "standard_operation"
        and row.effects_trusted
        and row.symbol.name in DISCOVERABLE_STANDARD_OPERATION_ROOTS
    ]
    if len(roots) != 1:
        return []
    root = roots[0]
    if (
        root.source == "builtin_defaults"
        and callee.get("has_definition")
        and not callee.get("is_system_header")
    ):
        raise Unsupported("project_shadows_standard")
    callee_usr = str(callee.get("usr") or callee.get("referenced_usr") or "")
    if root.symbol.usr and callee_usr != root.symbol.usr:
        raise Unsupported("root_symbol_mismatch")
    source = str(context.get("code") or "")
    if not re.search(rf"\breturn\b[^;]*\b{re.escape(callee_name)}\s*\(", source, re.S):
        return []
    arguments = [str(value or "").strip() for value in event.get("arguments", []) or []]
    carrier = ObjectBinding("unknown")
    if root.carrier.kind == "argument" and root.carrier.argument_index is not None:
        root_index = root.carrier.argument_index
        if root_index >= len(arguments):
            raise Unsupported("standard_wrapper_argument_missing")
        expression = arguments[root_index]
        parameter_index = next(
            (
                index
                for index, name in enumerate(wrapper.parameters)
                if compact(expression) == compact(name)
            ),
            None,
        )
        if parameter_index is None:
            raise Unsupported("standard_wrapper_argument_mapping_unclosed")
        carrier = ObjectBinding("argument", parameter_index)
    elif root.carrier.kind == "return":
        carrier = ObjectBinding("return")
    else:
        raise Unsupported("standard_wrapper_carrier_unsupported")

    cases: list[dict[str, Any]] = [{"when": dict(TRUE), "effect": "applies"}]
    if carrier.kind == "argument" and carrier.argument_index is not None:
        name = wrapper.parameters[carrier.argument_index]
        if re.search(
            rf"\bif\s*\(\s*!\s*{re.escape(name)}\s*\)\s*(?:\{{\s*)?return\b",
            source,
        ):
            bound = {"kind": "argument", "index": carrier.argument_index}
            cases = [
                {"when": compare(bound, "!=", None), "effect": "applies"},
                {"when": compare(bound, "==", None), "effect": "no_effect"},
            ]
    owner = wrapper.body.get("owner") or {}
    raw_location = event.get("location")
    location = raw_location if isinstance(raw_location, Mapping) else {}
    return [
        {
            "symbol": asdict(
                SymbolIdentity.from_value(
                    owner,
                    name=context.get("func_name"),
                    file_path=context.get("file_path"),
                    signature=context.get("signature"),
                    build_context_id=wrapper.build,
                )
            ),
            "role": "standard_operation",
            "carrier": asdict(carrier),
            "conditions": [],
            "preconditions": dict(TRUE),
            "effect_cases": cases,
            "pairs": [],
            "resource_family": root.resource_family,
            "protocol": deepcopy(root.protocol),
            "source": "inferred:semantic_modeling",
            "confidence": 1.0,
            "delegates": [
                {
                    "symbol": asdict(root.symbol),
                    "role": root.role,
                    "carrier": asdict(root.carrier),
                    "transparent": True,
                }
            ],
            "evidence": [
                {
                    "function_usr": str(owner.get("usr") or ""),
                    "build_context_id": wrapper.build,
                    "native_input_hash": digest(wrapper.body),
                    "sites": [
                        {
                            "callee": asdict(root.symbol),
                            "callee_usr": callee_usr,
                            "line": int(location.get("line") or 0),
                            "offset": int(location.get("offset") or 0),
                            "expression": str(event.get("expression") or ""),
                        }
                    ],
                }
            ],
            "verification": {
                "method": "source_composition",
                "checker": "native_standard_wrapper_value_flow.v1",
                "mapping_verified": True,
                "proof_authority": False,
                "effect_strength": "must_under_guard",
                "compiler_version": CONTRACT_COMPILER_VERSION,
                "source_hash": digest(code_tokens(source)),
                "proof_dependencies": [proof_key(root)],
                "native_input_hash": digest(wrapper.body),
                "fresh_no_alias": False,
                "assumptions": [],
            },
        }
    ]


def infer_native_wrapper(context: Mapping[str, Any], registry: ContractRegistry) -> NativeInference:
    """Claim bounded native resource and transparent standard wrappers."""
    facts = context.get("program_facts") or {}
    standard_error = ""
    if facts:
        try:
            standard_contracts = _infer_returned_standard_operation(context, registry)
        except Unsupported as exc:
            standard_contracts = []
            standard_error = str(exc)
        else:
            standard_error = ""
        if standard_contracts:
            return {"attempted": True, "contracts": standard_contracts, "reasons": []}
    rows = [
        c
        for c in registry.for_context(context).contracts
        if c.role in {"allocator", "calloc", "reallocator", "deallocator"}
        and (not c.protocol or c.protocol.get("kind") == "standard_api_effects")
        and (c.role == "reallocator" or not c.protocol.get("transitions"))
        and not c.resource_domain
    ]
    names = {c.symbol.name for c in rows}
    tokens = code_tokens(str(context.get("code") or ""))
    applicable = bool(facts) and any(
        t in names and tokens[i + 1] == "(" for i, t in enumerate(tokens[:-1])
    )
    if not applicable:
        lock_names = {
            c.symbol.name
            for c in registry.for_context(context).contracts
            if c.role in {"lock", "unlock"} and c.effects_trusted
        }
        lock_applicable = bool(facts) and any(
            token in lock_names and tokens[index + 1] == "("
            for index, token in enumerate(tokens[:-1])
        )
        if lock_applicable:
            return {
                "attempted": True,
                "contracts": [],
                "reasons": ["void_or_status_hiding_lock_wrapper_not_authorized"],
            }
        if standard_error:
            return {"attempted": True, "contracts": [], "reasons": [standard_error]}
        return {"attempted": False, "contracts": [], "reasons": []}
    try:
        contracts = NativeWrapper(context, registry).run()
        return {"attempted": True, "contracts": contracts, "reasons": []}
    except Unsupported as exc:
        return {"attempted": True, "contracts": [], "reasons": [str(exc)]}
