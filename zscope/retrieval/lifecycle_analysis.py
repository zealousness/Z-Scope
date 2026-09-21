"""Compiler-bound, object-sensitive lifecycle obligations.

The structured AST supplies control-flow splits; the caller must also provide a
complete compiler CFG. Unsupported control flow is an explicit unknown exit,
never an implicit clean exit. This module neither reads model verdicts nor
assigns proof authority: ReviewClaimChecker binds and signs any refutation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, cast

from ..semantics.contracts import ContractRegistry, digest
from .validation_facts import walk_ast

LIFECYCLE_FACT_VERSION = "zscope.lifecycle-obligations.v2"
ACQUISITIONS = {"allocator", "calloc", "reallocator", "io_acquire"}


def lifecycle_facts(
    store: Any,
    registry: ContractRegistry,
    data: dict[str, Any],
    function: dict[str, Any],
    source: str,
) -> dict[str, Any]:
    from .analysis_facts import scan_fact_cache

    return cast(
        dict[str, Any],
        scan_fact_cache(store).compute(
            (
                LIFECYCLE_FACT_VERSION,
                data["fact_store_id"],
                str(function.get("id")),
                registry.version,
            ),
            lambda: LifecycleAnalysis(registry, data, function, source).run(),
        ),
    )


def unwrap(node: dict[str, Any]) -> dict[str, Any]:
    while node.get("kind") in {"ParenExpr", "ImplicitCastExpr", "CStyleCastExpr", "ConstantExpr"}:
        children = node.get("inner", [])
        if len(children) != 1:
            break
        if node.get("kind") in {"ImplicitCastExpr", "CStyleCastExpr"} and node.get(
            "castKind"
        ) not in {
            "LValueToRValue",
            "ArrayToPointerDecay",
            "FunctionToPointerDecay",
            "NoOp",
            "BitCast",
            "NullToPointer",
        }:
            break
        node = children[0]
    return node


def identity(node: dict[str, Any]) -> str:
    node = unwrap(node)
    kind, children = node.get("kind"), node.get("inner", [])
    if kind in {"VarDecl", "ParmVarDecl"}:
        return str(node.get("id") or "")
    if kind == "DeclRefExpr":
        return str(node.get("referencedDecl", {}).get("id") or "")
    if kind == "MemberExpr" and children:
        return (
            identity(children[0]) + "." + str(node.get("referencedMemberDecl") or node.get("name"))
        )
    if kind == "UnaryOperator" and node.get("opcode") in {"&", "*"} and children:
        value = identity(children[0])
        return str(node["opcode"]) + value if value else ""
    return ""


def expression(node: dict[str, Any]) -> str:
    node = unwrap(node)
    kind, children = node.get("kind"), node.get("inner", [])
    if kind in {"VarDecl", "ParmVarDecl"}:
        return str(node.get("name") or "")
    if kind == "DeclRefExpr":
        return str(node.get("referencedDecl", {}).get("name") or "")
    if kind in {"IntegerLiteral", "StringLiteral", "CharacterLiteral"}:
        return str(node.get("value", ""))
    if kind in {"GNUNullExpr", "CXXNullPtrLiteralExpr"}:
        return "NULL"
    if kind == "MemberExpr" and children:
        return (
            expression(children[0]) + ("->" if node.get("isArrow") else ".") + str(node.get("name"))
        )
    if kind == "UnaryOperator" and children:
        return str(node.get("opcode") or "") + expression(children[0])
    if kind == "BinaryOperator" and len(children) == 2:
        return (
            "(" + expression(children[0]) + str(node.get("opcode")) + expression(children[1]) + ")"
        )
    return ""


def invocation(node: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    node = unwrap(node)
    children = node.get("inner", [])
    if node.get("kind") != "CallExpr" or not children:
        return "", []
    callee = unwrap(children[0]).get("referencedDecl", {})
    return (
        str(callee.get("name") or "") if callee.get("kind") == "FunctionDecl" else ""
    ), children[1:]


def location(node: dict[str, Any], source: str) -> tuple[int, int]:
    value = node.get("loc") or node.get("range", {}).get("begin", {})
    value = value.get("expansionLoc", value)
    offset = int(value.get("offset", -1))
    return int(value.get("line") or (source[:offset].count("\n") + 1 if offset >= 0 else 0)), offset


@dataclass
class PathState:
    aliases: dict[str, str] = field(default_factory=dict)
    resources: dict[str, str] = field(default_factory=dict)
    non_null: set[str] = field(default_factory=set)
    null: set[str] = field(default_factory=set)
    constraints: list[dict[str, Any]] = field(default_factory=list)
    transfers: dict[str, str] = field(default_factory=dict)
    terminated: bool = False
    complete: bool = True
    exit_line: int = 0
    object_versions: dict[str, str] = field(default_factory=dict)


class LifecycleAnalysis:
    """One function's possible obligations, preserving unknown side effects."""

    def __init__(
        self,
        registry: ContractRegistry,
        data: dict[str, Any],
        function: dict[str, Any],
        source: str,
    ):
        self.registry, self.data, self.function, self.source = registry, data, function, source
        self.acquisitions: dict[str, dict[str, Any]] = {}
        self.uses: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.gaps: set[str] = set()
        self.globals = {
            n["id"] for n in data.get("ast", {}).get("inner", []) if n.get("kind") == "VarDecl"
        }
        self.parameters = {
            n["id"] for n in function.get("inner", []) if n.get("kind") == "ParmVarDecl"
        }
        self.definitions = {
            n.get("name")
            for n in walk_ast(data.get("ast", {}))
            if n.get("kind") == "FunctionDecl"
            and any(c.get("kind") == "CompoundStmt" for c in n.get("inner", []))
        }

    def run(self) -> dict[str, Any]:
        body: dict[str, Any] = next(
            (n for n in self.function.get("inner", []) if n.get("kind") == "CompoundStmt"), {}
        )
        initial = PathState(object_versions={p: "input:" + p for p in self.parameters})
        if any(
            str(n.get("kind", "")).startswith("CXX")
            or n.get("kind") in {"ExprWithCleanups", "GCCAsmStmt", "MSAsmStmt", "SEHTryStmt"}
            for n in walk_ast(self.function)
        ):
            initial.complete = False
            self.gaps.add("cpp_cleanup_or_exception_effects_unclosed")
        states = self._statement(body, [initial]) if body else []
        obligations = []
        for uid, acquire in self.acquisitions.items():
            exits = [
                {
                    "state": s.resources.get(uid, "not_acquired"),
                    "constraints": s.constraints,
                    "owner": s.transfers.get(uid, ""),
                    "complete": s.complete,
                    "exit_line": s.exit_line,
                }
                for s in states
            ]
            complete = bool(states) and all(s.complete for s in states)
            kinds = {e["state"] for e in exits}
            safe = complete and kinds <= {
                "not_acquired",
                "released",
                "returned",
                "output_transferred",
            }
            obligations.append(
                {
                    **acquire,
                    "exits": exits,
                    "complete": complete,
                    "status": (
                        "discharged"
                        if safe
                        else "unresolved" if "unknown" in kinds or not complete else "open"
                    ),
                    "reason": (
                        "all_exits_release_or_transfer_same_object"
                        if safe
                        else "ownership_or_exit_unclosed"
                    ),
                }
            )
        return {
            "schema_version": LIFECYCLE_FACT_VERSION,
            "contract_version": self.registry.version,
            "function": self.function.get("name"),
            "obligations": obligations,
            "uses": self.uses,
            "events": self.events,
            "gaps": sorted(self.gaps),
            "complete": bool(states) and all(s.complete for s in states),
        }

    def _resource(self, node: dict[str, Any], state: PathState) -> str:
        key = identity(node)
        return state.aliases.get(key, "")

    def _object_identity(self, node: dict[str, Any], state: PathState) -> str:
        key = identity(node)
        if key.startswith("&"):
            return "address:" + key[1:]
        if not key:
            return ""
        root, dot, member = key.partition(".")
        return state.object_versions.get(
            key, state.object_versions.get(root, "input:" + root) + dot + member
        )

    def _domain(self, contract: Any, args: list[dict[str, Any]], state: PathState) -> str:
        binding = contract.resource_domain
        if binding is None:
            return ""
        if (
            binding.kind == "argument"
            and binding.argument_index is not None
            and binding.argument_index < len(args)
        ):
            obj = self._object_identity(args[binding.argument_index], state)
            if obj and not binding.member_path:
                return obj
        self.gaps.add("pool_identity_unclosed")
        return "unknown:pool"

    def _assign_version(self, key: str, value: dict[str, Any], state: PathState) -> None:
        if not key:
            return
        version = self._object_identity(value, state)
        for existing in list(state.aliases):
            if existing.startswith(key + "."):
                state.aliases.pop(existing, None)
        state.object_versions[key] = version or "assignment:" + str(value.get("id"))

    def _unknown(self, state: PathState, reason: str, *, affected: set[str] | None = None) -> None:
        self.gaps.add(reason)
        for uid in (set(state.resources) if affected is None else affected):
            if state.resources.get(uid) not in {None, "not_acquired", "released"}:
                state.resources[uid] = "unknown"

    def _use(self, node: dict[str, Any], state: PathState) -> None:
        kind, children = node.get("kind"), node.get("inner", [])
        if children and (
            kind == "ArraySubscriptExpr"
            or kind == "MemberExpr"
            and node.get("isArrow")
            or kind == "UnaryOperator"
            and node.get("opcode") == "*"
        ):
            uid = self._resource(children[0], state)
            if uid:
                self.uses.append(
                    {
                        "acquisition_id": uid,
                        "line": location(node, self.source)[0],
                        "non_null": uid in state.non_null,
                        "state": state.resources.get(uid),
                        "constraints": list(state.constraints),
                    }
                )

    def _call(
        self, node: dict[str, Any], state: PathState, target: str = "", target_text: str = ""
    ) -> str:
        name, args = invocation(node)
        contracts = [
            c
            for c in self.registry.find(name)
            if not (c.source.startswith("builtin") and name in self.definitions)
        ]
        actual = [expression(arg) for arg in args]
        if not name or not contracts:
            affected = {self._resource(n, state) for arg in args for n in walk_ast(arg)} - {""}
            self._unknown(state, "opaque_call_argument_effects", affected=affected)
            for argument in args:
                key = identity(argument)
                if key.startswith("&"):
                    state.aliases.pop(key[1:], None)
                    state.object_versions[key[1:]] = "opaque_call:" + str(node.get("id"))
            return ""
        trusted = [c for c in contracts if c.effects_trusted]
        for argument in args:
            if identity(argument).startswith("&"):
                key = identity(argument)[1:]
                uid = state.aliases.get(key)
                if uid:
                    self._unknown(state, "address_exposed_to_call", affected={uid})
                    state.aliases.pop(key, None)
                state.object_versions[key] = "call:" + str(node.get("id"))
        acquisitions = [c for c in trusted if c.role in ACQUISITIONS]
        returned = ""
        if acquisitions:
            bindings = {
                (
                    c.carrier.kind,
                    c.carrier.argument_index,
                    c.carrier.member_path,
                    c.role,
                    c.resource_family,
                    c.resource_domain,
                    digest(c.effect_cases),
                    digest(c.preconditions),
                )
                for c in acquisitions
            }
            if len(bindings) != 1:
                self._unknown(state, "ambiguous_acquisition_carrier")
                return ""
            contract = acquisitions[0]
            line, offset = location(node, self.source)
            uid = digest(
                {
                    "file": self.data.get("source"),
                    "function": self.function.get("name"),
                    "compile_context": self.data.get(
                        "command_fingerprint", self.data.get("compile_command", "")
                    ),
                    "offset": offset,
                    "spelling": node.get("range", {}).get("begin", {}).get("spellingLoc", {}),
                    "api": name,
                    "role": contract.role,
                }
            )
            carrier = target
            if contract.carrier.kind == "output_argument":
                index = contract.carrier.argument_index
                if index is not None and index < len(args):
                    carrier = identity(args[index])
                    carrier = carrier[1:] if carrier.startswith("&") else "*" + carrier
                    target_text = contract.carrier.resolve(actual)
            if (
                contract.carrier.kind not in {"return", "output_argument"}
                or contract.carrier.member_path
            ):
                self.gaps.add("unsupported_acquisition_carrier")
                return ""
            domain = self._domain(contract, args, state)
            self.acquisitions.setdefault(
                uid,
                {
                    "acquisition_id": uid,
                    "api": name,
                    "line": line,
                    "offset": offset,
                    "object": target_text or "$return",
                    "role": contract.role,
                    "resource_family": contract.resource_family,
                    "resource_domain": domain,
                    "allocation_extent": self.registry.allocation_extent(name, actual),
                    "source_evidence": self.data.get("fact_store_id", ""),
                    "success_conditions": {
                        "preconditions": contract.preconditions,
                        "effect_cases": contract.effect_cases,
                    },
                    "initial_owner": "current_function",
                    "negative_is_failure": all(
                        case.get("when")
                        == {
                            "op": "compare",
                            "left": {"kind": "return"},
                            "operator": ">=",
                            "right": {"kind": "literal", "value": 0},
                        }
                        for case in contract.effect_cases
                        if case.get("effect") == "applies"
                    )
                    and bool(contract.effect_cases),
                },
            )
            applicability = contract.applicability(actual, target_text)
            state.resources[uid] = "not_acquired" if applicability == "does_not_apply" else "held"
            if carrier:
                state.aliases[carrier] = uid
            if contract.role == "reallocator" and applicability != "does_not_apply":
                # Both old/new obligations survive until the standard protocol
                # and zero-size behavior have been resolved for this call.
                state.resources[uid] = "unknown"
                self.gaps.add("reallocation_transition_unclosed")
            if contract.carrier.kind == "return":
                returned = uid
            elif applicability != "does_not_apply":
                state.resources[uid] = "unknown"
                self.gaps.add("output_acquisition_status_unclosed")
        for contract in trusted:
            if contract.role not in {"deallocator", "io_release", "ownership_transfer"}:
                continue
            binding = contract.carrier
            index = binding.argument_index
            if (
                binding.kind != "argument"
                or index is None
                or index >= len(args)
                or binding.member_path
            ):
                self.gaps.add("release_carrier_unresolved")
                continue
            uid = self._resource(args[index], state)
            if not uid:
                continue
            acq = self.acquisitions[uid]
            obj = expression(args[index])
            known = {obj: {"non_null_identity": uid}}
            effect = contract.applicability(actual, "", known)
            if contract.role == "ownership_transfer":
                state.resources[uid] = "unknown"
                state.transfers[uid] = name
                self.gaps.add("container_owner_lifetime_unclosed")
            elif self.registry.allows(acq["api"], name) and effect == "applies":
                domain = self._domain(contract, args, state)
                if (
                    domain == "unknown:pool"
                    or domain != acq["resource_domain"]
                    or (
                        contract.resource_family
                        and acq["resource_family"]
                        and contract.resource_family != acq["resource_family"]
                    )
                ):
                    self.gaps.add("release_resource_domain_mismatch")
                    continue
                state.resources[uid] = "released"
                self.events.append(
                    {
                        "kind": "release",
                        "acquisition_id": uid,
                        "api": name,
                        "line": location(node, self.source)[0],
                    }
                )
            else:
                self._unknown(state, "conditional_or_unpaired_release", affected={uid})
        if not trusted:
            self._unknown(
                state,
                "unverified_contract",
                affected={self._resource(a, state) for a in args} - {""},
            )
        return returned

    def _eval(
        self, node: dict[str, Any], state: PathState, target: str = "", target_text: str = ""
    ) -> str:
        node = unwrap(node)
        kind, children = node.get("kind"), node.get("inner", [])
        self._use(node, state)
        if (
            kind == "ConditionalOperator"
            and len(children) == 3
            and not any(
                n.get("kind") in {"CallExpr", "CompoundAssignOperator"}
                or n.get("opcode") in {"=", "++", "--"}
                for n in walk_ast(node)
            )
        ):
            self._eval(children[0], state)
            values = []
            for truth, part in zip((True, False), children[1:]):
                branch = deepcopy(state)
                if self._refine(children[0], truth, branch):
                    values.append(self._eval(part, branch))
            return values[0] if values and len(set(values)) == 1 else ""
        if kind in {
            "ConditionalOperator",
            "BinaryConditionalOperator",
            "StmtExpr",
            "CXXNewExpr",
            "CXXDeleteExpr",
        }:
            state.complete = False
            self._unknown(state, "unsupported_expression_control_flow:" + str(kind))
        if kind == "BinaryOperator" and node.get("opcode") in {"&&", "||"}:
            if any(
                n.get("kind") == "CallExpr" or n.get("opcode") in {"=", "++", "--"}
                for n in walk_ast(node)
            ):
                state.complete = False
                self._unknown(state, "short_circuit_side_effects")
        if kind == "CallExpr":
            for child in children[1:]:
                if any(
                    n.get("kind") == "CompoundAssignOperator"
                    or n.get("opcode") in {"=", "++", "--"}
                    for n in walk_ast(child)
                ):
                    state.complete = False
                    self._unknown(state, "call_argument_side_effects_unclosed")
                if unwrap(child).get("kind") == "CallExpr":
                    self._eval(child, state)
                else:
                    for part in walk_ast(child):
                        self._use(part, state)
            return self._call(node, state, target, target_text)
        if kind == "BinaryOperator" and node.get("opcode") == "=" and len(children) == 2:
            left, right = children
            for part in walk_ast(left):
                self._use(part, state)
            key = identity(left)
            previous = state.aliases.get(key)
            uid = self._eval(right, state, key, expression(left))
            self._assign_version(key, right, state)
            if uid:
                state.aliases[key] = uid
                root = key.split(".")[0]
                if (
                    key.startswith("*")
                    and key[1:] in self.parameters
                    and state.object_versions.get(key[1:]) == "input:" + key[1:]
                ):
                    state.resources[uid] = "output_transferred"
                    state.transfers[uid] = expression(left)
                elif key.startswith("*"):
                    self._unknown(state, "indirect_owner_identity_unclosed", affected={uid})
                elif root in self.globals or "." in key:
                    self._unknown(state, "persistent_owner_lifetime_unclosed", affected={uid})
                    state.transfers[uid] = expression(left)
            else:
                state.aliases.pop(key, None)
            if (
                previous
                and previous != uid
                and state.resources.get(previous) in {"held", "output_transferred"}
            ):
                state.resources[previous] = "held"
                state.transfers.pop(previous, None)
                self.events.append(
                    {
                        "kind": "owner_overwrite",
                        "acquisition_id": previous,
                        "line": location(node, self.source)[0],
                    }
                )
            return uid
        if children and (
            kind == "CompoundAssignOperator"
            or kind == "UnaryOperator"
            and node.get("opcode") in {"++", "--"}
        ):
            key = identity(children[0])
            uid = self._resource(children[0], state)
            if uid:
                self._unknown(state, "pointer_version_changed", affected={uid})
                state.aliases.pop(key, None)
            if key:
                state.object_versions[key] = "mutation:" + str(node.get("id"))
        if kind == "BinaryOperator" and node.get("opcode") in {"+", "-"}:
            affected = {self._resource(child, state) for child in children} - {""}
            if affected:
                self._unknown(state, "derived_pointer_requires_base_mapping", affected=affected)
        for child in children:
            self._eval(child, state)
        return self._resource(node, state)

    def _refine(self, node: dict[str, Any], truth: bool, state: PathState) -> bool:
        node = unwrap(node)
        children = node.get("inner", [])
        op = node.get("opcode")
        if node.get("kind") == "UnaryOperator" and op == "!" and children:
            return self._refine(children[0], not truth, state)
        if op in {"&&", "||"} and len(children) == 2:
            if op == "&&" and truth or op == "||" and not truth:
                return all(self._refine(c, truth, state) for c in children)
            return True
        uid = self._resource(node, state)
        non_null = truth
        if uid and self.acquisitions[uid]["negative_is_failure"]:
            return True  # descriptor zero is valid; a bare truth test is not a failure test
        if op in {"==", "!=", "<", ">=", ">", "<="} and len(children) == 2:
            uid = self._resource(children[0], state)
            value = expression(children[1])
            if value not in {"0", "NULL"}:
                return True
            if op in {"==", "!="}:
                if (
                    uid
                    and self.acquisitions[uid]["role"] == "io_acquire"
                    and "*" not in children[0].get("type", {}).get("qualType", "")
                ):
                    return True  # descriptor zero is a successful acquisition
                non_null = truth == (op == "!=")
            elif uid and self.acquisitions[uid]["negative_is_failure"] and op in {"<", ">="}:
                non_null = truth == (op == ">=")
            else:
                return True
        if not uid:
            return True
        if non_null:
            if uid in state.null:
                return False
            state.non_null.add(uid)
        else:
            if uid in state.non_null:
                return False
            state.null.add(uid)
            state.resources[uid] = "not_acquired"
        return True

    def _statement(self, node: dict[str, Any], states: list[PathState]) -> list[PathState]:
        kind, children = node.get("kind"), node.get("inner", [])
        if len(states) > 128:
            for state in states:
                state.complete = False
                self._unknown(state, "path_budget_incomplete")
            return states
        if kind == "CompoundStmt":
            for child in children:
                states = self._statement(child, states)
            return states
        result = []
        for state in states:
            if state.terminated:
                result.append(state)
                continue
            if kind == "IfStmt" and len(children) in {2, 3} and not node.get("hasInit"):
                self._eval(children[0], state)
                for truth in (True, False):
                    branch = deepcopy(state)
                    branch.constraints.append(
                        {
                            "expression": expression(children[0]),
                            "branch_taken": truth,
                            "line": location(children[0], self.source)[0],
                        }
                    )
                    if not self._refine(children[0], truth, branch):
                        continue
                    part = children[1] if truth else children[2] if len(children) == 3 else {}
                    result.extend(self._statement(part, [branch]) if part else [branch])
                continue
            if kind == "DoStmt" and len(children) == 2 and expression(children[1]) == "0":
                result.extend(self._statement(children[0], [state]))
                continue
            if kind == "DeclStmt":
                for decl in children:
                    if decl.get("kind") == "VarDecl" and decl.get("inner"):
                        self._eval(decl["inner"][-1], state, identity(decl), expression(decl))
                        self._assign_version(identity(decl), decl["inner"][-1], state)
                        uid = self._resource(decl["inner"][-1], state)
                        if uid:
                            state.aliases[identity(decl)] = uid
            elif kind == "ReturnStmt":
                uid = self._eval(children[0], state) if children else ""
                if uid and state.resources.get(uid) == "held":
                    state.resources[uid] = "returned"
                    state.transfers[uid] = "caller"
                state.terminated = True
                state.exit_line = location(node, self.source)[0]
            elif kind in {
                "ForStmt",
                "WhileStmt",
                "DoStmt",
                "SwitchStmt",
                "GotoStmt",
                "IndirectGotoStmt",
                "CXXTryStmt",
                "CXXThrowExpr",
                "LabelStmt",
                "IfStmt",
                "BreakStmt",
                "ContinueStmt",
            }:
                state.complete = False
                self._unknown(state, "unsupported_control_flow:" + kind)
                # Keep discovering sites, but no claim about an exit can be
                # certified from a single traversal of a loop/switch body.
                for child in children:
                    self._eval(child, state)
            else:
                self._eval(node, state)
            result.append(state)
        return result
