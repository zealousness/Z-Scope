"""Bounded native value flow for direct C allocation wrappers.

This adapts the existing CFG/USR receipt into ApiContract, not another lifetime
checker. Unsupported input is diagnostic and cannot fall back to token authority.
The first slice excludes protocol pools, realloc, indirect calls and C++.
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

    def prepare(self) -> None:
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
            or body.get("fact_version") != "zscope.program-events.v5"
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
        if source_guards != native_guards:
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
                        "record_value",
                        "floating_value",
                    )
                ):
                    raise Unsupported("unsupported_native_value_kind")
                bits = value.get("integer_bits", 0)
                if bits and (
                    bits < 32
                    or (
                        value.get("integer_unsigned")
                        and value.get("usr") not in self.unsigned_parameters
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
        if re.fullmatch(r"-?\d+", text):
            value = int(text)
            if not -(2**31) <= value < 2**31:
                raise Unsupported("integer_range_unclosed")
            return literal(value)
        if text.startswith("&"):
            return {"kind": "address", "location": self.location(text[1:], state)}
        if text in state.calls:
            return state.calls[text]
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
            index = value.get("index")
            if (
                type(index) is not int
                or not 0 <= index < len(args)
                or value.get("member_path")
                or value.get("address_of")
            ):
                raise Unsupported("root_condition_mapping_unclosed")
            return args[index]
        return {k: self.mapped(v, args, returned) for k, v in value.items()}

    def call(self, event: dict[str, Any], state: State) -> None:
        from .contract_compiler import _base_cases

        callee = event.get("callee") or {}
        if not callee.get("usr"):
            raise Unsupported("indirect_or_unresolved_call")
        rows = self.registry.find_for_call(str(callee.get("name") or ""))
        if len(rows) != 1 or not rows[0].effects_trusted:
            raise Unsupported("opaque_or_unverified_call")
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
        if (
            (root.protocol and root.protocol.get("kind") != "standard_api_effects")
            or root.protocol.get("transitions")
            or root.resource_domain
            or root.resource_family != "malloc"
            or root.role not in {"allocator", "calloc", "deallocator"}
        ):
            raise Unsupported("root_effect_not_supported")
        if root.preconditions != TRUE:
            raise Unsupported("root_precondition_unclosed")
        self.roots[digest(root.to_dict())] = root
        args = [self.value(text, state) for text in event.get("arguments", [])]
        site = str(event["location"]["offset"])
        returned = {"kind": "call_result", "name": self.body["owner"]["usr"] + ":" + site}
        state.calls[compact(event["expression"])] = returned
        target = event.get("object") or {}
        if target.get("usr"):
            if target["usr"] not in self.locals:
                raise Unsupported("external_store")
            state.values[target["usr"]] = returned
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
                if len(primary) != 1:
                    raise Unsupported("ambiguous_native_call_site")
                event = primary[0]
            if event.get("contains_macro") is not False and not event.get("null_pointer_constant"):
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
                    {},
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
                "checker": "native_wrapper_value_flow.v1",
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


def infer_native_wrapper(context: Mapping[str, Any], registry: ContractRegistry) -> NativeInference:
    """Only claim the native heap-wrapper subset; pools retain their own checker."""
    facts = context.get("program_facts") or {}
    rows = [
        c
        for c in registry.for_context(context).contracts
        if c.role in {"allocator", "calloc", "deallocator"}
        and (not c.protocol or c.protocol.get("kind") == "standard_api_effects")
        and not c.protocol.get("transitions")
        and not c.resource_domain
    ]
    names = {c.symbol.name for c in rows}
    tokens = code_tokens(str(context.get("code") or ""))
    applicable = bool(facts) and any(
        t in names and tokens[i + 1] == "(" for i, t in enumerate(tokens[:-1])
    )
    if not applicable:
        return {"attempted": False, "contracts": [], "reasons": []}
    try:
        contracts = NativeWrapper(context, registry).run()
        return {"attempted": True, "contracts": contracts, "reasons": []}
    except Unsupported as exc:
        return {"attempted": True, "contracts": [], "reasons": [str(exc)]}
