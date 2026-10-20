"""Compile caller-visible contracts from source and explicit callee contracts.

This module runs only during semantic modeling. No project spelling, benchmark
interface, or prose classification is an input to role inference. The source
reader is deliberately conservative; unsupported C expressions remain unknown.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import re
from typing import Any, Mapping

from .contract_conditions import (
    compare,
    conjunction,
    negate,
    predicate_errors,
    legacy_predicate,
    predicates_overlap,
)
from .contracts import (
    ApiContract,
    ContractRegistry,
    ObjectBinding,
    SymbolIdentity,
    CONTRACT_COMPILER_VERSION,
    code_tokens,
    digest,
    ACQUIRE_ROLES,
    RELEASE_ROLES,
)

TRUE = {"op": "true"}
UNKNOWN = {"op": "unknown"}


def split_tokens(tokens: list[str], separator: str = ",") -> list[list[str]]:
    result: list[list[str]] = [[]]
    depth = 0
    for token in tokens:
        if token == separator and depth == 0:
            result.append([])
        else:
            result[-1].append(token)
        depth += int(token in {"(", "[", "{"}) - int(token in {")", "]", "}"})
    return result


def closing(tokens: list[str], start: int) -> int:
    opening = tokens[start]
    end = {"(": ")", "[": "]", "{": "}"}.get(opening, "")
    depth = 0
    for i in range(start, len(tokens)):
        depth += int(tokens[i] == opening) - int(tokens[i] == end)
        if depth == 0:
            return i
    return len(tokens) - 1


def unparen(tokens: list[str]) -> list[str]:
    while tokens and tokens[0] == "(" and closing(tokens, 0) == len(tokens) - 1:
        tokens = tokens[1:-1]
    return tokens


def _pointer_identity_value(tokens: list[str]) -> list[str]:
    """Remove simple C object-pointer casts, never integer casts or arithmetic."""
    tokens = unparen(tokens)
    while tokens and tokens[0] == "(":
        end = closing(tokens, 0)
        target = tokens[1:end]
        if (
            end >= len(tokens) - 1
            or "*" not in target
            or not all(word == "*" or re.fullmatch(r"[A-Za-z_]\w*", word) for word in target)
        ):
            break
        tokens = unparen(tokens[end + 1 :])
    return tokens


def _address_of_slot(tokens: list[str], name: str) -> bool:
    """Taking a member/element address does not expose its root pointer slot."""
    for i, token in enumerate(tokens):
        if token != "&":
            continue
        j = i + 1
        while j < len(tokens) and tokens[j] == "(":
            j += 1
        if j >= len(tokens) or tokens[j] != name:
            continue
        j += 1
        while j < len(tokens) and tokens[j] == ")":
            j += 1
        if j == len(tokens) or tokens[j] not in {"->", ".", "["}:
            return True
    return False


def parameter_names(context: Mapping[str, Any]) -> list[str]:
    tokens = code_tokens(str(context.get("signature") or context.get("code") or ""))
    name = str(context.get("func_name") or "")
    start = next(
        (i + 1 for i, token in enumerate(tokens[:-1]) if token == name and tokens[i + 1] == "("), -1
    )
    if start < 0:
        return []
    result = []
    for group in split_tokens(tokens[start + 1 : closing(tokens, start)]):
        if not group or group == ["void"]:
            continue
        pointer = re.search(r"\(\s*\*\s*(\w+)\s*\)", " ".join(group))
        identifiers = [t for t in group if re.fullmatch(r"[A-Za-z_]\w*", t)]
        result.append(pointer[1] if pointer else identifiers[-1] if identifiers else "")
    return result


def reference(
    tokens: list[str], parameters: list[str], aliases: Mapping[str, Any] | None = None
) -> dict[str, Any] | None:
    tokens = _pointer_identity_value(tokens)
    aliases = aliases or {}
    if not tokens:
        return None
    if tokens[0] == "&":
        base = reference(unparen(tokens[1:]), parameters, aliases)
        if (
            base
            and base.get("kind") == "argument"
            and base.get("member_path")
            and not base.get("address_of")
        ):
            return {**base, "address_of": True}
        return None
    if len(tokens) == 1:
        name = tokens[0]
        if name in aliases:
            value = aliases[name]
            return dict(deepcopy(value)) if isinstance(value, Mapping) else None
        if name in {"NULL", "nullptr"}:
            return {"kind": "literal", "value": None}
        if re.fullmatch(r"\d+", name):
            return {"kind": "literal", "value": int(name)}
        if name in parameters:
            return {"kind": "argument", "index": parameters.index(name)}
    if len(tokens) == 2 and tokens[0] == "-" and tokens[1].isdigit():
        return {"kind": "literal", "value": -int(tokens[1])}
    if tokens and (tokens[0] in parameters or tokens[0] in aliases):
        base = reference(tokens[:1], parameters, aliases)
        tail = "".join(tokens[1:])
        if (
            base
            and base.get("kind") == "argument"
            and not base.get("address_of")
            and re.fullmatch(r"(?:(?:\.|->)[A-Za-z_]\w*|\[\d+\])+", tail)
        ):
            return {**base, "member_path": str(base.get("member_path") or "") + tail}
    return None


def source_predicate(
    tokens: list[str], parameters: list[str], aliases: Mapping[str, Any]
) -> dict[str, Any]:
    tokens = unparen(tokens)
    for operator, op in (("||", "any"), ("&&", "all")):
        parts = split_tokens(tokens, operator)
        if len(parts) > 1:
            return {"op": op, "items": [source_predicate(p, parameters, aliases) for p in parts]}
    if tokens and tokens[0] == "!":
        return negate(source_predicate(tokens[1:], parameters, aliases))
    for operator in ("==", "!=", "<=", ">=", "<", ">"):
        parts = split_tokens(tokens, operator)
        if len(parts) == 2:
            left, right = [reference(p, parameters, aliases) for p in parts]
            if left and right:
                return {"op": "compare", "left": left, "operator": operator, "right": right}
            return dict(UNKNOWN)
    ref = reference(tokens, parameters, aliases)
    return compare(ref, "!=", None) if ref else dict(UNKNOWN)


@dataclass
class SourceCall:
    name: str
    arguments: list[str]
    result: str
    guard: dict[str, Any]
    token_offset: int
    occurrence: int = 0
    aliases_at_call: dict[str, Any] = field(default_factory=dict)

    @property
    def result_identity(self) -> str:
        return (
            "call:"
            + digest(
                {"callee": self.name, "arguments": self.arguments, "occurrence": self.occurrence}
            )[:20]
        )


@dataclass
class FunctionFacts:
    parameters: list[str]
    calls: list[SourceCall] = field(default_factory=list)
    returns: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    return_offsets: list[int] = field(default_factory=list)
    aliases: dict[str, Any] = field(default_factory=dict)
    assignments: dict[str, str] = field(default_factory=dict)
    complete: bool = True
    unknown_calls: set[str] = field(default_factory=set)
    opaque_calls: list[SourceCall] = field(default_factory=list)
    assignment_counts: dict[str, int] = field(default_factory=dict)
    local_variables: set[str] = field(default_factory=set)


def read_source_facts(context: Mapping[str, Any], registry: ContractRegistry) -> FunctionFacts:
    """Read block/if/return structure, preserving the guards on each operation."""
    tokens = code_tokens(str(context.get("code") or ""))
    facts = FunctionFacts(parameter_names(context))
    from .call_context import callee_usr_map
    from .build_scope import source_scope_problem

    if source_scope_problem(context):
        facts.complete = False
        return facts
    registry = registry.for_context(context)
    # Each callee token resolves through this body's own native call receipts:
    # a pinned publication is only known for a callee whose exact USR the
    # facts name, and a callee without a receipt stays unknown regardless of
    # how many records share its name.
    callee_usr = callee_usr_map(context)
    name = str(context.get("func_name") or "")
    start = next(
        (i + 1 for i, token in enumerate(tokens[:-1]) if token == name and tokens[i + 1] == "("), -1
    )
    if start < 0:
        facts.complete = False
        return facts
    if not context.get("is_macro"):
        declarations = split_tokens(tokens[start + 1 : closing(tokens, start)])
        facts.local_variables.update(
            parameter
            for parameter, declaration in zip(facts.parameters, declarations)
            if not set(declaration) & {"&", "&&", "volatile"}
        )
    start = closing(tokens, start) + 1
    is_macro = bool(context.get("is_macro"))
    facts.unknown_calls = {
        token
        for i, token in enumerate(tokens[start:-1], start)
        if tokens[i + 1] == "("
        and re.fullmatch(r"[A-Za-z_]\w*", token)
        and token not in {"if", "while", "for", "switch", "sizeof", "return", "alignof", "_Alignof"}
        and (
            not registry.find_for_call(token, usr=callee_usr.get(token, ""))
            or any(
                not c.effects_trusted
                for c in registry.find_for_call(token, usr=callee_usr.get(token, ""))
            )
        )
    }
    if any(tokens[i : i + 2] == ["(", "*"] for i in range(start, len(tokens) - 1)):
        facts.unknown_calls.add("<indirect>")

    def statement(begin: int, end: int, guard: dict[str, Any]) -> None:
        words = tokens[begin:end]
        if not words:
            return
        incoming_aliases = deepcopy(facts.aliases)
        assignment = split_tokens(words, "=")
        declaration = unparen(assignment[0])
        if (
            len(declaration) > 1
            and re.fullmatch(r"[A-Za-z_]\w*", declaration[-1])
            and re.fullmatch(r"[A-Za-z_]\w*", declaration[0])
            and all(re.fullmatch(r"[A-Za-z_]\w*", word) or word == "*" for word in declaration[:-1])
            and not set(declaration)
            & {"return", "static", "extern", "thread_local", "_Thread_local", "volatile"}
        ):
            facts.local_variables.add(declaration[-1])
        assigned = ""
        if len(assignment) == 2:
            left = unparen(assignment[0])
            lvalue = "".join(left)
            assigned = (
                lvalue
                if (len(left) == 1 or left[:1] == ["*"] or left[1:2] in (["->"], ["."], ["["]))
                else next((t for t in reversed(left) if re.fullmatch(r"[A-Za-z_]\w*", t)), "")
            )
            facts.assignments[assigned] = "".join(_pointer_identity_value(assignment[1]))
            facts.assignment_counts[assigned] = facts.assignment_counts.get(assigned, 0) + 1
            # Invalidate the prior call/parameter binding before binding a new
            # direct call result below. A later guard must not use its old value.
            facts.aliases[assigned] = reference(assignment[1], facts.parameters, incoming_aliases)
        is_return = words[0] == "return"
        if is_return:
            facts.returns.append(("".join(_pointer_identity_value(words[1:])), deepcopy(guard)))
            facts.return_offsets.append(begin)
        i = begin
        while i + 1 < end:
            known = bool(registry.find_for_call(tokens[i], usr=callee_usr.get(tokens[i], "")))
            if tokens[i + 1] != "(" or not (known or tokens[i] in facts.unknown_calls):
                i += 1
                continue
            stop = closing(tokens, i + 1)
            if stop >= end:
                break
            result = assigned or ("$return" if is_return or (is_macro and begin == start) else "")
            value = assignment[1] if assigned else words[1:] if is_return else words
            if result and _pointer_identity_value(value) != tokens[i : stop + 1]:
                result = ""
            call = SourceCall(
                tokens[i],
                ["".join(p) for p in split_tokens(tokens[i + 2 : stop])],
                result,
                deepcopy(guard),
                i,
                aliases_at_call=incoming_aliases,
            )
            call.occurrence = sum(
                c.name == call.name and c.arguments == call.arguments
                for c in {c.token_offset: c for c in [*facts.calls, *facts.opaque_calls]}.values()
            )
            if known:
                facts.calls.append(call)
            if call.name in facts.unknown_calls:
                facts.opaque_calls.append(call)
            for local in facts.local_variables:
                if any(
                    _address_of_slot(code_tokens(argument), local) for argument in call.arguments
                ):
                    facts.aliases[local] = None
                    facts.assignments[local] = "<address_escaped>"
                    facts.assignment_counts[local] = facts.assignment_counts.get(local, 0) + 1
            # An opaque callee's returned value is still a concrete SSA-like
            # observation. Its effects remain unknown, but a frozen local
            # result can distinguish cleanup from successful return paths.
            if result and result != "$return":
                facts.aliases[result] = {"kind": "call_result", "name": call.result_identity}
            i = stop + 1

    def condition_expression(begin: int, end: int, guard: dict[str, Any]) -> dict[str, Any]:
        words: list[str] = []
        cursor = begin
        has_call = False
        while cursor < end:
            if (
                cursor + 1 < end
                and tokens[cursor + 1] == "("
                and (
                    registry.find_for_call(tokens[cursor], usr=callee_usr.get(tokens[cursor], ""))
                    or tokens[cursor] in facts.unknown_calls
                )
            ):
                stop = closing(tokens, cursor + 1)
                if stop >= end:
                    facts.complete = False
                    return dict(UNKNOWN)
                statement(cursor, stop + 1, guard)
                observed = {
                    c.token_offset: c
                    for c in [*facts.calls, *facts.opaque_calls]
                    if c.token_offset == cursor
                }
                if len(observed) != 1:
                    facts.complete = False
                    return dict(UNKNOWN)
                call = next(iter(observed.values()))
                placeholder = f"_zscope_condition_{cursor}"
                while placeholder in tokens:
                    placeholder += "_"
                call.result = placeholder
                facts.local_variables.add(placeholder)
                facts.assignment_counts[placeholder] = 1
                facts.aliases[placeholder] = {"kind": "call_result", "name": call.result_identity}
                facts.assignments[placeholder] = call.name + "(" + ",".join(call.arguments) + ")"
                words.append(placeholder)
                cursor = stop + 1
                has_call = True
            else:
                words.append(tokens[cursor])
                cursor += 1
        if has_call and any(token in {"&&", "||", "=", "?", ","} for token in words):
            # Short-circuit/assignment conditions need a separate effect path;
            # never claim complete straight-line coverage for these expressions.
            facts.complete = False
        return source_predicate(words, facts.parameters, facts.aliases)

    def walk(i: int, end: int, guard: dict[str, Any]) -> tuple[int, bool]:
        if i >= end:
            return i, False
        if tokens[i] == "{":
            stop = closing(tokens, i)
            cursor, remaining = i + 1, guard
            while cursor < stop:
                before = cursor
                if tokens[cursor] == "if" and cursor + 1 < stop and tokens[cursor + 1] == "(":
                    cond_end = closing(tokens, cursor + 1)
                    condition = condition_expression(cursor + 2, cond_end, remaining)
                    cursor, exits = walk(cond_end + 1, stop, conjunction([remaining, condition]))
                    if cursor < stop and tokens[cursor] == "else":
                        cursor, else_exits = walk(
                            cursor + 1, stop, conjunction([remaining, negate(condition)])
                        )
                        if exits and else_exits:
                            return stop + 1, True
                        if else_exits:
                            remaining = conjunction([remaining, condition])
                    elif exits:
                        remaining = conjunction([remaining, negate(condition)])
                else:
                    cursor, exits = walk(cursor, stop, remaining)
                    if exits:
                        return stop + 1, True
                if cursor <= before:
                    facts.complete = False
                    break
            return stop + 1, False
        if tokens[i] == "if" and i + 1 < end and tokens[i + 1] == "(":
            stop = closing(tokens, i + 1)
            condition = condition_expression(i + 2, stop, guard)
            cursor, _ = walk(stop + 1, end, conjunction([guard, condition]))
            if cursor < end and tokens[cursor] == "else":
                cursor, _ = walk(cursor + 1, end, conjunction([guard, negate(condition)]))
            return cursor, False
        if tokens[i] == "do" and i + 1 < end and tokens[i + 1] == "{":
            cursor, _ = walk(i + 1, end, guard)
            if tokens[cursor : cursor + 4] == ["while", "(", "0", ")"]:
                return min(cursor + 5, end), False
            facts.complete = False
            return end, False
        if tokens[i] in {"for", "while", "switch", "goto", "try"}:
            facts.complete = False
            return end, False
        stop = i
        while stop < end and tokens[stop] != ";":
            if tokens[stop] in {"(", "["}:
                stop = closing(tokens, stop)
            stop += 1
        statement(i, stop, guard)
        return min(stop + 1, end), tokens[i] == "return"

    if start < len(tokens):
        walk(start, len(tokens), dict(TRUE))
    return facts


def _parameter_alias_expression(
    expression: str, parameters: list[str], aliases: Mapping[str, Any]
) -> tuple[str, bool]:
    """Resolve a frozen copy of an incoming parameter, preserving pointer operations."""
    words = code_tokens(expression)
    root = next((i for i, word in enumerate(words) if re.fullmatch(r"[A-Za-z_]\w*", word)), -1)
    if root < 0 or any(word not in {"&", "*", "("} for word in words[:root]):
        return expression, False
    if (
        "&" in words[:root]
        and "*" not in words[:root]
        and not any(word not in {")"} for word in words[root + 1 :])
    ):
        return expression, False  # Address of a local pointer slot, not its copied value.
    ref = aliases.get(words[root])
    if not isinstance(ref, Mapping) or ref.get("kind") != "argument":
        return expression, False
    index = ref.get("index")
    if not isinstance(index, int) or not 0 <= index < len(parameters):
        return expression, False
    replacement = parameters[index] + str(ref.get("member_path") or "")
    if ref.get("address_of"):
        replacement = "&" + replacement
    words[root : root + 1] = code_tokens(replacement)
    return "".join(words), True


def _binding(
    expression: str, parameters: list[str], *, output: bool = False, implicit_output: bool = False
) -> ObjectBinding | None:
    words = unparen(code_tokens(ObjectBinding("return").resolve([], expression)))
    address_of = False
    dereferences = int(implicit_output)
    while words[:1] in (["&"], ["*"]):
        dereferences += int(words[0] == "*")
        if dereferences > 1:
            return None  # More than one dereference needs an explicit access path.
        output |= words[0] == "*"
        address_of |= words[0] == "&"
        words = unparen(words[1:])
    if not words:
        return None
    tail = "".join(words[1:])
    if tail and not re.fullmatch(r"(?:(?:\.|->)[A-Za-z_]\w*|\[\d+\])+", tail):
        return None
    if words[0] in parameters:
        if output and tail and address_of:
            address_of = False
        return ObjectBinding(
            "output_argument" if output else "argument",
            parameters.index(words[0]),
            tail,
            address_of=address_of,
        )
    return None


def _global_binding(expression: str, context: Mapping[str, Any]) -> ObjectBinding | None:
    words = _pointer_identity_value(code_tokens(expression))
    address_of = words[:1] == ["&"]
    clean = "".join(unparen(words[1:]) if address_of else words)
    names = {
        str(row.get("name"))
        for row in context.get("referenced_globals", [])
        if isinstance(row, dict)
    }
    if re.fullmatch(r"[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*", clean):
        if re.split(r"\.|->", clean)[0] in names:
            return ObjectBinding("global", global_name=clean, address_of=address_of)
    return None


def _map_predicate(
    predicate: Any, call: SourceCall, facts: FunctionFacts, *, returned: bool
) -> dict[str, Any]:
    if not isinstance(predicate, dict):
        return dict(UNKNOWN)
    result = deepcopy(predicate)
    op = result.get("op")
    if op in {"all", "any"}:
        result["items"] = [
            _map_predicate(x, call, facts, returned=returned) for x in result["items"]
        ]
    elif op == "not":
        result["item"] = _map_predicate(result["item"], call, facts, returned=returned)
    elif op == "compare":
        for side in ("left", "right"):
            ref = result[side]
            if ref.get("kind") == "return":
                result[side] = (
                    {"kind": "return"}
                    if returned
                    else {"kind": "call_result", "name": call.result_identity}
                )
            elif ref.get("kind") == "argument":
                index = ref.get("index", -1)
                result[side] = (
                    reference(
                        code_tokens(
                            ObjectBinding(
                                "argument",
                                index,
                                str(ref.get("member_path") or ""),
                                address_of=bool(ref.get("address_of")),
                            ).resolve(call.arguments)
                        ),
                        facts.parameters,
                        call.aliases_at_call,
                    )
                    if 0 <= index < len(call.arguments)
                    else None
                )
                if result[side] is None:
                    return dict(UNKNOWN)
    return result


def _map_composite_protocol(
    base: ApiContract,
    call: SourceCall,
    facts: FunctionFacts,
    context: Mapping[str, Any],
    carrier: ObjectBinding,
    outward_return: bool,
) -> dict[str, Any]:
    if base.protocol.get("kind") != "standard_api_effects":
        return deepcopy(base.protocol)
    transitions = []
    for transition in base.protocol.get("transitions", []):
        actions = []
        valid = True
        for action in transition.get("actions", []):
            mapped = {"kind": action["kind"]}
            if "lock_mode" in action:
                mapped["lock_mode"] = action["lock_mode"]
            for key in ("object", "old", "new", "callback", "context"):
                if key not in action:
                    continue
                original = ObjectBinding.from_value(action[key])
                binding: ObjectBinding | None
                if original.kind == "return":
                    binding = carrier
                else:
                    expression, _ = _parameter_alias_expression(
                        original.resolve(call.arguments, call.result),
                        facts.parameters,
                        call.aliases_at_call,
                    )
                    binding = _binding(expression, facts.parameters) or _global_binding(
                        expression, context
                    )
                if binding is None:
                    valid = False
                    break
                mapped[key] = asdict(binding)
            actions.append(mapped)
        if valid:
            transitions.append(
                {
                    "when": conjunction(
                        [
                            call.guard,
                            _map_predicate(
                                transition["when"], call, facts, returned=outward_return
                            ),
                        ]
                    ),
                    "actions": actions,
                }
            )
    protocol = {**deepcopy(base.protocol), "transitions": transitions}
    if "allocation_extent" in protocol:
        protocol["allocation_extent"] = [
            _map_predicate(compare(ref, ">=", 0), call, facts, returned=outward_return).get(
                "left", {"kind": "unknown"}
            )
            for ref in protocol["allocation_extent"]
        ]
    return protocol


def _base_cases(contract: ApiContract) -> list[dict[str, Any]]:
    if contract.effect_cases:
        return [
            dict(case, when=branch)
            for case in contract.effect_cases
            for branch in (
                case["when"]["items"]
                if case.get("effect") == "applies" and case.get("when", {}).get("op") == "any"
                else [case["when"]]
            )
        ]
    if contract.source != "builtin_defaults":
        return [{"when": legacy_predicate(contract.conditions), "effect": "applies"}]
    if contract.role in {"allocator", "calloc", "reallocator"}:
        predicate = compare({"kind": "return"}, "!=", None)
    elif contract.role == "io_acquire":
        predicate = compare({"kind": "return"}, ">=", 0)
    elif contract.role in {"lock", "unlock"}:
        predicate = compare({"kind": "return"}, "==", 0)
    elif contract.role == "deallocator":
        predicate = compare(
            {"kind": "argument", "index": contract.carrier.argument_index or 0}, "!=", None
        )
    else:
        predicate = dict(TRUE)
    return [
        {"when": predicate, "effect": "applies"},
        {
            "when": negate(predicate) if predicate != TRUE else {"op": "false"},
            "effect": "no_effect",
        },
    ]


def _excluded_failure_calls(
    context: Mapping[str, Any],
    facts: FunctionFacts,
    call: SourceCall,
    base: ApiContract,
    carrier: ObjectBinding,
    aliases: set[str],
) -> list[dict[str, Any]] | None:
    """Prove opaque calls cannot execute when this primitive succeeds.

    This deliberately handles only an immutable, unescaped local result of one
    allocation/lock primitive. It does not infer that a logger is harmless.
    """
    if not facts.unknown_calls:
        return []
    if (
        not facts.complete
        or base.role not in {"allocator", "calloc", "reallocator", "lock", "unlock"}
        or not re.fullmatch(r"[A-Za-z_]\w*", call.result)
        or call.result not in facts.local_variables
        or facts.assignment_counts.get(call.result) != 1
        or {c.name for c in facts.opaque_calls} != facts.unknown_calls
    ):
        return None
    tokens = code_tokens(str(context.get("code") or ""))
    # Mutation, lambdas, method dispatch and inline assembly need richer facts.
    if set(tokens) & {
        "++",
        "--",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "|=",
        "&=",
        "^=",
        "<<=",
        ">>=",
        "[",
        "asm",
        "__asm__",
    }:
        return None
    for opaque in facts.opaque_calls:
        if tokens[max(0, opaque.token_offset - 1) : opaque.token_offset] in (["->"], ["."], ["::"]):
            return None
    for alias in aliases | {call.result}:
        if (
            alias not in facts.local_variables
            or not re.fullmatch(r"[A-Za-z_]\w*", alias)
            or _address_of_slot(tokens, alias)
        ):
            return None
        if facts.assignment_counts.get(alias, 0) > 1:
            return None
    if base.role in {"allocator", "calloc", "reallocator"}:
        # A non-null return must denote this primitive's value, not an alternate
        # global/borrowed pointer returned on a different branch.
        if carrier.kind != "return" or any(
            value not in aliases | {"NULL", "nullptr", "0"} for value, _ in facts.returns
        ):
            return None
    success = [
        conjunction([call.guard, _map_predicate(case["when"], call, facts, returned=False)])
        for case in _base_cases(base)
        if case["effect"] == "applies"
    ]

    # By-value parameter slots are also immutable when they are neither written
    # nor address-taken. Macro parameters and C++ references are not local slots.
    frozen_parameters = set()
    function = str(context.get("func_name") or "")
    start = next(
        (i + 1 for i in range(len(tokens) - 1) if tokens[i] == function and tokens[i + 1] == "("),
        -1,
    )
    declarations = split_tokens(tokens[start + 1 : closing(tokens, start)]) if start >= 0 else []
    if not context.get("is_macro"):
        for index, parameter in enumerate(facts.parameters):
            if (
                index < len(declarations)
                and not (set(declarations[index]) & {"&", "&&"})
                and not facts.assignment_counts.get(parameter)
                and not _address_of_slot(tokens, parameter)
            ):
                frozen_parameters.add(index)

    # Contradiction must use a frozen local value, not mutable global/member state.
    def result_atoms(predicate: dict[str, Any]) -> list[dict[str, Any]]:
        if predicate.get("op") == "all":
            return [a for p in predicate.get("items", []) for a in result_atoms(p)]
        if predicate.get("op") == "compare":
            ref = predicate.get("left") or {}
            if ref == {"kind": "call_result", "name": call.result_identity} or (
                ref.get("kind") == "argument"
                and ref.get("index") in frozen_parameters
                and not ref.get("member_path")
            ):
                return [predicate]
        return []

    certificates = []
    for opaque in facts.opaque_calls:
        if not success or not all(
            "contradictory_effect_condition"
            in predicate_errors(conjunction(result_atoms(opaque.guard) + result_atoms(condition)))
            for condition in success
        ):
            return None
        certificates.append(
            {
                "callee": opaque.name,
                "call_token_offset": opaque.token_offset,
                "guard": deepcopy(opaque.guard),
                "basis": "incompatible_effect_guard",
            }
        )
    return certificates


def transparent_pair_compatible(
    acquire: ApiContract, release: ApiContract, registry: ContractRegistry
) -> bool:
    """Compose proven adapters through an explicit underlying protocol edge.

    This is also needed while modeling callers, before the workbook publication
    materializes the derived edges. Sharing a release endpoint is insufficient.
    """
    if acquire.role not in ACQUIRE_ROLES or release.role not in RELEASE_ROLES:
        return False
    if not acquire.effects_trusted or not release.effects_trusted:
        return False
    if acquire.symbol.build_context_id != release.symbol.build_context_id:
        return False
    return any(
        a.get("transparent") is True
        and b.get("transparent") is True
        and registry.allows(
            str(a.get("symbol", {}).get("name")),
            str(b.get("symbol", {}).get("name")),
        )
        for a in acquire.delegates
        for b in release.delegates
    )


def _source_pair_compatible(
    acquire: str,
    release: str,
    registry: ContractRegistry,
    *,
    acquire_usr: str = "",
    release_usr: str = "",
) -> bool:
    return registry.allows(acquire, release) or any(
        transparent_pair_compatible(a, b, registry)
        for a in registry.find_for_call(acquire, usr=acquire_usr)
        for b in registry.find_for_call(release, usr=release_usr)
    )


def _frozen_guard_atoms(
    context: Mapping[str, Any], facts: FunctionFacts, predicate: dict[str, Any]
) -> list[dict[str, Any]]:
    """Comparisons whose value cannot change between a release and a return."""
    tokens = code_tokens(str(context.get("code") or ""))
    if set(tokens) & {"++", "--", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>="}:
        return []

    def unescaped(name: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z_]\w*", name)) and not _address_of_slot(tokens, name)

    stable_results = {
        c.result_identity
        for c in [*facts.calls, *facts.opaque_calls]
        if c.result in facts.local_variables
        and unescaped(c.result)
        and facts.assignment_counts.get(c.result) == 1
    }
    name = str(context.get("func_name") or "")
    start = next(
        (i + 1 for i in range(len(tokens) - 1) if tokens[i] == name and tokens[i + 1] == "("), -1
    )
    declarations = split_tokens(tokens[start + 1 : closing(tokens, start)]) if start >= 0 else []
    stable_parameters = {
        i
        for i, p in enumerate(facts.parameters)
        if not context.get("is_macro")
        and i < len(declarations)
        and not (set(declarations[i]) & {"&", "&&"})
        and unescaped(p)
        and not facts.assignment_counts.get(p)
    }

    def atoms(value: dict[str, Any]) -> list[dict[str, Any]]:
        if value.get("op") == "all":
            return [a for item in value.get("items", []) for a in atoms(item)]
        ref = value.get("left") or {}
        if value.get("op") == "compare" and (
            ref.get("kind") == "call_result"
            and ref.get("name") in stable_results
            or ref.get("kind") == "argument"
            and ref.get("index") in stable_parameters
            and not ref.get("member_path")
        ):
            return [value]
        return []

    return atoms(predicate)


def _release_can_reach_return(
    context: Mapping[str, Any],
    facts: FunctionFacts,
    acquire: SourceCall,
    release: SourceCall,
    base: ApiContract,
    aliases: set[str],
) -> bool:
    success = [
        _map_predicate(case["when"], acquire, facts, returned=False)
        for case in _base_cases(base)
        if case["effect"] == "applies"
    ]
    for offset, (value, guard) in zip(facts.return_offsets, facts.returns):
        if value not in aliases or offset < release.token_offset:
            continue
        for condition in success or [dict(UNKNOWN)]:
            atoms = _frozen_guard_atoms(
                context, facts, conjunction([release.guard, guard, acquire.guard, condition])
            )
            if "contradictory_effect_condition" not in predicate_errors(conjunction(atoms)):
                return True
    return False


def derive_contracts(
    context: Mapping[str, Any], registry: ContractRegistry
) -> list[dict[str, Any]]:
    from .native_wrappers import infer_native_wrapper

    native = infer_native_wrapper(context, registry)
    return _combine_wrapper_contracts(context, registry, native)


def _combine_wrapper_contracts(
    context: Mapping[str, Any], registry: ContractRegistry, native: Any
) -> list[dict[str, Any]]:
    from .build_scope import context_symbol_usr

    source = _derive_source_contracts(context, registry)
    if not native["attempted"]:
        return source
    # A failed native check must not re-authorize its resource through tokens.
    rows = [
        row
        for row in source
        if row["role"] not in {"allocator", "calloc", "reallocator", "deallocator"}
    ]
    # Native wrapper rows publish under the checked body's owner receipt, the
    # same authority every other publication path uses; direct row consumers
    # get the exact native USR instead of a name-level record.
    owner_usr = context_symbol_usr(context)
    for row in native["contracts"]:
        symbol = row.get("symbol")
        if owner_usr and isinstance(symbol, dict) and not symbol.get("usr"):
            row = dict(row, symbol={**symbol, "usr": owner_usr})
        rows.append(row)
    return rows


def _derive_source_contracts(
    context: Mapping[str, Any], registry: ContractRegistry
) -> list[dict[str, Any]]:
    from .contract_review import proof_key
    from .build_scope import context_build_id, context_symbol_usr
    from .call_context import callee_usr_map

    registry = registry.for_context(context)
    facts = read_source_facts(context, registry)
    if not facts.complete:
        return []
    symbol = SymbolIdentity.from_value(
        {},
        name=context.get("func_name"),
        file_path=context.get("file_path"),
        signature=context.get("signature"),
        symbol_type="macro" if context.get("is_macro") else "function",
        build_context_id=context_build_id(context),
        usr=context_symbol_usr(context),
    )
    callee_usr = callee_usr_map(context)
    returned_names = {expr for expr, _ in facts.returns}
    lifecycle_calls = [
        call
        for call in facts.calls
        if any(
            c.role in ACQUIRE_ROLES | RELEASE_ROLES
            for c in registry.find_for_call(call.name, usr=callee_usr.get(call.name, ""))
        )
    ]
    internal_calls: set[int] = set()
    for acquire in lifecycle_calls:
        for release in lifecycle_calls:
            if not (
                acquire.token_offset < release.token_offset
                and _source_pair_compatible(
                    acquire.name,
                    release.name,
                    registry,
                    acquire_usr=callee_usr.get(acquire.name, ""),
                    release_usr=callee_usr.get(release.name, ""),
                )
            ):
                continue
            success_guards = [
                conjunction(
                    [acquire.guard, _map_predicate(case["when"], acquire, facts, returned=False)]
                )
                for contract in registry.find_for_call(
                    acquire.name, usr=callee_usr.get(acquire.name, "")
                )
                if contract.role == "lock"
                for case in _base_cases(contract)
                if case["effect"] == "applies"
            ]

            def same_guard(left: dict[str, Any], right: dict[str, Any]) -> bool:
                return left == right or (
                    "contradictory_effect_condition"
                    in predicate_errors(conjunction([left, negate(right)]))
                    and "contradictory_effect_condition"
                    in predicate_errors(conjunction([right, negate(left)]))
                )

            if not same_guard(release.guard, acquire.guard) and not any(
                same_guard(release.guard, guard) for guard in success_guards
            ):
                continue
            if any(
                acquire.token_offset < offset < release.token_offset
                and any(
                    not predicate_errors(conjunction([return_guard, success_guard]))
                    for success_guard in success_guards
                )
                for offset, (_expression, return_guard) in zip(facts.return_offsets, facts.returns)
            ):
                continue
            acquired_objects = {
                c.carrier.resolve(acquire.arguments, acquire.result)
                for c in registry.find_for_call(acquire.name, usr=callee_usr.get(acquire.name, ""))
                if c.role == "lock"
            }
            released_objects = {
                c.carrier.resolve(release.arguments, release.result)
                for c in registry.find_for_call(release.name, usr=callee_usr.get(release.name, ""))
                if c.role == "unlock"
            }
            if (acquired_objects & released_objects) - {""}:
                internal_calls.update((acquire.token_offset, release.token_offset))
    result = []
    for call in facts.calls:
        if call.token_offset in internal_calls:
            continue
        result_aliases = {call.result} if call.result else set()
        for _ in range(len(facts.assignments)):
            expanded = result_aliases | {
                left for left, right in facts.assignments.items() if right in result_aliases
            }
            if expanded == result_aliases:
                break
            result_aliases = expanded
        expected = call.name + "(" + ",".join(call.arguments) + ")"
        if (
            call.result
            and call.result != "$return"
            and facts.assignments.get(call.result) != expected
        ):
            # The destination was overwritten or transformed. No alias/return
            # proof can be obtained from the final source assignment map.
            result_aliases = set()
        for base in registry.find_for_call(call.name, usr=callee_usr.get(call.name, "")):
            carrier: ObjectBinding | None = None
            frozen_parameter_alias = False
            outward_return = call.result == "$return" or bool(result_aliases & returned_names)
            if base.carrier.kind == "return":
                if outward_return:
                    carrier = ObjectBinding("return")
                elif result_aliases:
                    for destination in sorted(result_aliases):
                        carrier = _global_binding(destination, context)
                        if carrier is None and (destination.startswith("*") or "->" in destination):
                            carrier = _binding(destination, facts.parameters, output=True)
                        if carrier is not None:
                            break
                if (
                    carrier
                    and carrier.kind == "return"
                    and base.role in {"allocator", "calloc", "reallocator"}
                    and call.result != "$return"
                    and result_aliases
                    and any(
                        value not in result_aliases | {"NULL", "nullptr", "0"}
                        for value, _ in facts.returns
                    )
                ):
                    # A non-null alternative is not necessarily this allocation.
                    carrier = None
                if carrier and carrier.kind == "return" and call.result != "$return":
                    returned_aliases = result_aliases & returned_names
                    source_tokens = code_tokens(str(context.get("code") or ""))
                    source = "".join(source_tokens)
                    if any(
                        alias not in facts.local_variables
                        or facts.assignment_counts.get(alias, 0) > 1
                        or _address_of_slot(source_tokens, alias)
                        or re.search(
                            r"(?:\+\+|--)\s*"
                            + re.escape(alias)
                            + r"\b|\b"
                            + re.escape(alias)
                            + r"(?:\+\+|--|\+=|-=)",
                            source,
                        )
                        for alias in returned_aliases
                    ):
                        carrier = None
                if carrier and any(
                    c.token_offset > call.token_offset
                    and _source_pair_compatible(
                        call.name,
                        c.name,
                        registry,
                        acquire_usr=callee_usr.get(call.name, ""),
                        release_usr=callee_usr.get(c.name, ""),
                    )
                    and any(
                        release.role in RELEASE_ROLES
                        and release.carrier.resolve(c.arguments)
                        in {ObjectBinding("return").resolve([], alias) for alias in result_aliases}
                        for release in registry.find_for_call(
                            c.name, usr=callee_usr.get(c.name, "")
                        )
                    )
                    and (
                        carrier.kind != "return"
                        or _release_can_reach_return(context, facts, call, c, base, result_aliases)
                    )
                    for c in facts.calls
                ):
                    carrier = None
            elif base.carrier.kind == "global":
                carrier = base.carrier
            elif base.carrier.argument_index is not None and base.carrier.argument_index < len(
                call.arguments
            ):
                expression = (
                    "".join(unparen(code_tokens(call.arguments[base.carrier.argument_index])))
                    + base.carrier.member_path
                )
                if base.carrier.address_of:
                    expression = "&(" + expression + ")"
                expression, frozen_parameter_alias = _parameter_alias_expression(
                    expression, facts.parameters, call.aliases_at_call
                )
                carrier = _binding(
                    expression,
                    facts.parameters,
                    output=base.carrier.kind == "output_argument",
                    implicit_output=base.carrier.kind == "output_argument",
                )
                if (
                    carrier
                    and base.carrier.kind == "output_argument"
                    and carrier.address_of
                    and not carrier.member_path
                    and not context.get("is_macro")
                ):
                    # Taking the address of a by-value parameter writes only the
                    # wrapper's local slot, not an output visible to its caller.
                    carrier = None
                if carrier is None:
                    carrier = _global_binding(expression, context)
            if (
                carrier is None
                or carrier.kind == "argument"
                and base.role in {"allocator", "calloc", "reallocator"}
            ):
                continue
            if (
                not frozen_parameter_alias
                and carrier.argument_index is not None
                and carrier.argument_index < len(facts.parameters)
                and facts.parameters[carrier.argument_index] in call.aliases_at_call
            ):
                # This value no longer denotes the incoming parameter.
                continue
            cases = []
            for case in _base_cases(base):
                when = conjunction(
                    [call.guard, _map_predicate(case["when"], call, facts, returned=outward_return)]
                )
                if predicate_errors(when, parameter_count=len(facts.parameters)):
                    continue
                cases.append({"when": when, "effect": case["effect"]})
            if not cases:
                continue
            excluded = _excluded_failure_calls(context, facts, call, base, carrier, result_aliases)
            if excluded is None and base.effects_trusted and len(lifecycle_calls) == 1:
                # Certify each success branch separately. In particular, recovery
                # on nonzero mutex status overlaps EOWNERDEAD but not status zero.
                # A proved branch remains useful without claiming the others safe.
                from dataclasses import replace

                proved = set()
                certificates: list[dict[str, Any]] = []
                for case in _base_cases(base):
                    if case["effect"] != "applies":
                        continue
                    certificate = _excluded_failure_calls(
                        context,
                        facts,
                        call,
                        replace(base, effect_cases=[case]),
                        carrier,
                        result_aliases,
                    )
                    if certificate is not None:
                        when = conjunction(
                            [
                                call.guard,
                                _map_predicate(case["when"], call, facts, returned=outward_return),
                            ]
                        )
                        proved.add(digest(when))
                        certificates.extend(dict(c, proven_effect_guard=when) for c in certificate)
                if proved:
                    cases = [
                        (
                            dict(c, effect="unknown")
                            if c["effect"] == "applies" and digest(c["when"]) not in proved
                            else c
                        )
                        for c in cases
                    ]
                    excluded = certificates
            if facts.unknown_calls and len(lifecycle_calls) != 1:
                excluded = None
            trusted = base.effects_trusted and excluded is not None
            if facts.unknown_calls and trusted and base.role in {"lock", "unlock"}:
                # Opaque calls on a failed primitive branch may still affect a
                # global lock. Only the successful branch has been proved.
                cases = [
                    dict(c, effect="unknown") if c["effect"] == "no_effect" else c for c in cases
                ]
                cases.extend(
                    {"when": deepcopy(c.guard), "effect": "unknown"} for c in facts.opaque_calls
                )
            protocols = base.delegates or [
                {
                    "symbol": asdict(base.symbol),
                    "role": base.role,
                    "carrier": asdict(base.carrier),
                    "transparent": True,
                }
            ]
            protocols = deepcopy(protocols)
            for protocol in protocols:
                protocol["transparent"] = (
                    bool(protocol.get("transparent"))
                    and len(lifecycle_calls) == 1
                    and not carrier.member_path
                )
            evidence = [
                {
                    "source_index": context.get("index_name"),
                    "call_token_offset": call.token_offset,
                    "callee": asdict(base.symbol),
                    "arguments": call.arguments,
                    "result": call.result,
                }
            ]
            raw = {
                "symbol": asdict(symbol),
                "role": base.role,
                "carrier": asdict(carrier),
                "conditions": [],
                "preconditions": dict(TRUE),
                "effect_cases": cases,
                "pairs": (
                    [asdict(p.release) for p in registry.pairs if p.acquire == base.symbol]
                    if base.role in ACQUIRE_ROLES
                    and sum(
                        any(
                            c.role in ACQUIRE_ROLES
                            for c in registry.find_for_call(
                                other.name, usr=callee_usr.get(other.name, "")
                            )
                        )
                        for other in lifecycle_calls
                        if other.token_offset not in internal_calls
                    )
                    == 1
                    else (
                        [asdict(p.acquire) for p in registry.pairs if p.release == base.symbol]
                        if protocols and all(p.get("transparent") for p in protocols)
                        else []
                    )
                ),
                "resource_family": base.resource_family,
                "resource_domain": None,
                "protocol": _map_composite_protocol(
                    base, call, facts, context, carrier, outward_return
                ),
                "confidence": 1.0,
                "source": "inferred:semantic_modeling",
                "evidence": evidence,
                "delegates": deepcopy(protocols),
                "verification": {
                    "method": "source_composition",
                    "mapping_verified": excluded is not None
                    or (facts.unknown_calls <= {base.symbol.name} and len(facts.calls) == 1),
                    "proof_dependencies": [proof_key(base)],
                    "compiler_version": CONTRACT_COMPILER_VERSION,
                    "source_hash": digest(code_tokens(str(context.get("code") or ""))),
                    "proof_authority": False,
                    "effect_strength": ("must_under_guard" if trusted else "unverified"),
                    "excluded_failure_calls": excluded or [],
                    "assumptions": deepcopy(base.verification.get("assumptions", []))
                    + (
                        [{"symbol": asdict(base.symbol), "source": base.source}]
                        if base.source != "builtin_defaults"
                        and not base.source.startswith("inferred")
                        else []
                    ),
                },
            }
            if base.resource_domain:
                domain_expression, frozen_domain_alias = _parameter_alias_expression(
                    base.resource_domain.resolve(call.arguments),
                    facts.parameters,
                    call.aliases_at_call,
                )
                domain = _binding(domain_expression, facts.parameters) or _global_binding(
                    domain_expression, context
                )
                if domain is None:
                    # An opaque/local pool cannot be relabeled as a heap resource.
                    continue
                if (
                    not frozen_domain_alias
                    and domain.argument_index is not None
                    and domain.argument_index < len(facts.parameters)
                    and facts.parameters[domain.argument_index] in call.aliases_at_call
                ):
                    continue
                raw["resource_domain"] = asdict(domain)
            result.append(raw)
    return list(
        {digest({k: v for k, v in row.items() if k != "evidence"}): row for row in result}.values()
    )


def validate_contract(raw: Mapping[str, Any], context: Mapping[str, Any]) -> list[str]:
    parameters = parameter_names(context)
    contract = ApiContract.from_row(
        {"contract": dict(raw), "symbol_name": context.get("func_name")}
    )
    if contract is None:
        return ["invalid_contract_schema"]
    errors = []
    if contract.resource_domain:
        domain = contract.resource_domain
        if domain.kind not in {"argument", "global"} or (
            domain.kind == "argument"
            and (domain.argument_index is None or domain.argument_index >= len(parameters))
        ):
            errors.append("invalid_resource_domain")
        if domain.kind == "global" and _global_binding(domain.global_name, context) is None:
            errors.append("resource_domain_not_in_source")
    binding = contract.carrier
    raw_carrier = raw.get("carrier")
    if (
        isinstance(raw_carrier, dict)
        and "address_of" in raw_carrier
        and not isinstance(raw_carrier["address_of"], bool)
    ):
        errors.append("invalid_carrier_address_of")
    if binding.kind in {"argument", "output_argument"} and (
        binding.argument_index is None or binding.argument_index >= len(parameters)
    ):
        errors.append("carrier_argument_out_of_range")
    if binding.kind not in {"return", "argument", "output_argument", "global"}:
        errors.append("unresolved_carrier")
    if binding.member_path and not re.fullmatch(
        r"(?:(?:\.|->)[A-Za-z_]\w*|\[\d+\])+", binding.member_path
    ):
        errors.append("invalid_member_path")
    if (
        binding.member_path
        and binding.argument_index is not None
        and binding.argument_index < len(parameters)
    ):
        expression = parameters[binding.argument_index] + binding.member_path
        if expression not in "".join(code_tokens(str(context.get("code") or ""))).replace(
            "(", ""
        ).replace(")", ""):
            errors.append("member_path_not_in_source")
    if binding.kind == "global" and _global_binding(binding.global_name, context) is None:
        errors.append("global_carrier_not_in_source_facts")
    if binding.kind == "global" and (
        binding.member_path or re.search(r"\.|->", binding.global_name)
    ):
        expression = binding.global_name + binding.member_path
        source = (
            "".join(code_tokens(str(context.get("code") or ""))).replace("(", "").replace(")", "")
        )
        if expression not in source:
            errors.append("global_member_path_not_in_source")
    errors.extend(predicate_errors(contract.preconditions, parameter_count=len(parameters)))
    if not contract.effect_cases:
        errors.append("missing_typed_effect_cases")
    for case in contract.effect_cases:
        if not isinstance(case, dict) or case.get("effect") not in {
            "applies",
            "no_effect",
            "unknown",
        }:
            errors.append("invalid_effect_case")
            continue
        errors.extend(predicate_errors(case.get("when"), parameter_count=len(parameters)))
        if case.get("effect") == "applies" and isinstance(case.get("when"), dict):
            errors.extend(
                predicate_errors(
                    conjunction([contract.preconditions, case["when"]]),
                    parameter_count=len(parameters),
                )
            )
    effects_by_condition: dict[str, set[str]] = {}
    for case in contract.effect_cases:
        if isinstance(case, dict):
            effects_by_condition.setdefault(digest(case.get("when")), set()).add(
                str(case.get("effect"))
            )
    if any({"applies", "no_effect"} <= effects for effects in effects_by_condition.values()):
        errors.append("conflicting_effect_cases")
    for index, first in enumerate(contract.effect_cases):
        if not isinstance(first, dict) or first.get("effect") not in {"applies", "no_effect"}:
            continue
        for second in contract.effect_cases[index + 1 :]:
            if (
                isinstance(second, dict)
                and {first["effect"], second.get("effect")} == {"applies", "no_effect"}
                and predicates_overlap(
                    contract.preconditions, first.get("when"), second.get("when")
                )
            ):
                errors.append("conflicting_effect_cases")
    if not raw.get("evidence"):
        errors.append("missing_contract_evidence")
    elif not any(
        isinstance(e, dict)
        and re.search(r"\d+", str(e.get("lines") or ""))
        and all(
            int(n) >= int(context.get("start_line") or 1)
            and int(n)
            <= int(
                context.get("end_line") or max(1, str(context.get("code") or "").count("\n") + 1)
            )
            for n in re.findall(r"\d+", str(e.get("lines") or ""))
        )
        for e in raw["evidence"]
    ):
        errors.append("contract_evidence_not_in_source")
    if binding.kind == "return" and not context.get("is_macro"):
        signature = str(context.get("signature") or "")
        if re.match(
            r"\s*(?:static\s+)?void\s+" + re.escape(str(context.get("func_name") or "")) + r"\s*\(",
            signature,
        ):
            errors.append("void_function_has_no_return_carrier")
    return sorted(set(errors))


def compile_snapshot(
    snapshot: dict[str, Any],
    context: Mapping[str, Any],
    registry: ContractRegistry,
    *,
    terminal_submissions: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Replace transparent proposals with source composition; validate all others."""
    from .build_scope import context_build_id, context_symbol_usr

    registry = registry.for_context(context)
    if context_build_id(context):
        snapshot["build_context_id"] = context_build_id(context)
    snapshot["usr"] = context_symbol_usr(context)
    raw = snapshot.get("interface_contracts")
    if not isinstance(raw, list):
        return ["missing_interface_contracts"]
    from .native_wrappers import infer_native_wrapper

    native = infer_native_wrapper(context, registry)
    derived = _combine_wrapper_contracts(context, registry, native)
    facts = read_source_facts(context, registry)
    derived_roles = {item["role"] for item in derived}
    # A known calloc/reallocator cannot be downgraded to a generic allocator.
    if derived_roles & {"calloc", "reallocator"}:
        derived_roles.add("allocator")
    accepted = list(derived)
    errors: list[str] = []
    diagnostics: list[dict[str, Any]] = []
    if native["attempted"]:
        diagnostics.append(
            {
                "action": "native_value_flow",
                "errors": native["reasons"],
                "status": "source_verified" if native["contracts"] else "unsupported",
            }
        )
    for item in raw:
        if not isinstance(item, dict):
            errors.append("invalid_interface_contract")
            continue
        problems = validate_contract(item, context)
        if item.get("protocol"):
            from .retention_protocols import verify_resource_protocol

            verified = verify_resource_protocol(item, context)
            if verified is not None and not problems:
                accepted.append(verified)
                diagnostics.append(
                    {
                        "role": item.get("role"),
                        "published_role": verified["role"],
                        "action": "source_protocol",
                        "errors": [],
                    }
                )
                continue
        if item.get("role") in derived_roles:
            diagnostics.append(
                {"role": item.get("role"), "action": "source_composition", "errors": problems}
            )
            continue
        if (
            facts.complete
            and not facts.unknown_calls
            and item.get("role") == "lock"
            and derived_roles
            and derived_roles <= {"lock_init", "lock_destroy", "lock_state"}
            and not any(
                destination not in facts.local_variables for destination in facts.assignments
            )
        ):
            # Initialization alone does not acquire a lock. In general, however,
            # absence of a composition is not proof that a proposed role is false.
            # Unproved mappings remain schema_only, never lifecycle authority.
            problems.append("role_not_supported_by_source_operations")
        if problems:
            errors.extend(problems)
            diagnostics.append(
                {"role": item.get("role"), "action": "not_published", "errors": problems}
            )
        else:
            cleaned = {
                key: value
                for key, value in item.items()
                if key
                in {
                    "role",
                    "carrier",
                    "conditions",
                    "preconditions",
                    "effect_cases",
                    "pairs",
                    "resource_family",
                    "resource_domain",
                    "protocol",
                    "confidence",
                    "evidence",
                }
            }
            accepted.append(
                {
                    **cleaned,
                    "symbol": asdict(
                        SymbolIdentity.from_value(
                            {},
                            name=context.get("func_name"),
                            file_path=context.get("file_path"),
                            signature=context.get("signature"),
                            symbol_type="macro" if context.get("is_macro") else "function",
                            build_context_id=context_build_id(context),
                            usr=context_symbol_usr(context),
                        )
                    ),
                    "source": "inferred:semantic_modeling",
                    "verification": {
                        "method": "schema_only",
                        "proof_authority": False,
                        "source_hash": digest(code_tokens(str(context.get("code") or ""))),
                    },
                }
            )
    # A schema repair may discard an earlier protocol discovery. A proposal is
    # only a selector for the bounded implementation checker, never authority.
    # Recheck the complete current body; unsupported proposals stay in the audit.
    discovery_audit = []
    seen_proposals: set[str] = set()
    for submission in terminal_submissions or []:
        payload = submission.get("payload")
        if not isinstance(payload, dict):
            continue
        candidates = [payload]
        candidates.extend(
            payload[key]
            for key in ("function_snapshot", "payload")
            if isinstance(payload.get(key), dict)
        )
        for candidate in candidates:
            proposals = candidate.get("interface_contracts")
            if not isinstance(proposals, list):
                continue
            for proposal in proposals:
                if not isinstance(proposal, dict) or not proposal.get("protocol"):
                    continue
                proposal_id = digest(proposal)
                if proposal_id in seen_proposals:
                    continue
                seen_proposals.add(proposal_id)
                from .retention_protocols import verify_resource_protocol

                verified = verify_resource_protocol(proposal, context)
                discovery_audit.append(
                    {
                        "proposal": deepcopy(proposal),
                        "status": "source_verified" if verified else "unverified",
                    }
                )
                if verified is None:
                    continue
                identity = lambda item: (
                    item.get("role"),
                    item.get("carrier"),
                    item.get("resource_domain"),
                )
                matching = [item for item in accepted if identity(item) == identity(verified)]
                if any(
                    item.get("verification", {}).get("method") == "source_protocol"
                    for item in matching
                ):
                    continue
                accepted = [item for item in accepted if identity(item) != identity(verified)]
                accepted.append(verified)
                diagnostics.append(
                    {
                        "role": verified["role"],
                        "action": "source_protocol_recovered",
                        "errors": [],
                        "proposal_id": proposal_id,
                    }
                )
    if discovery_audit:
        snapshot["protocol_discovery_audit"] = discovery_audit
    snapshot["interface_contracts"] = accepted
    snapshot["contract_diagnostics"] = diagnostics
    snapshot["raw_interface_contracts"] = raw
    return sorted(set(errors))


def complete_transparent_pairs(snapshots: list[dict[str, Any]], registry: ContractRegistry) -> int:
    """Materialize only adapter-derived edges, never shared-endpoint closure."""
    rows = [
        (
            snapshot,
            raw,
            ApiContract.from_row(
                {
                    "contract": raw,
                    "symbol_name": snapshot.get("func_name"),
                    "file_path": snapshot.get("file_path"),
                    "signature": snapshot.get("signature"),
                }
            ),
        )
        for snapshot in snapshots
        for raw in snapshot.get("interface_contracts", [])
    ]
    added = 0
    for _snapshot, raw, acquire in rows:
        if acquire is None or acquire.role not in ACQUIRE_ROLES:
            continue
        for _other, _release_raw, release in rows:
            if release is None or release.role not in RELEASE_ROLES:
                continue
            if acquire.symbol.build_context_id != release.symbol.build_context_id:
                continue
            from .pool_protocols import pool_pair_compatible

            pool_pair = pool_pair_compatible(acquire, release)
            if not pool_pair and not transparent_pair_compatible(acquire, release, registry):
                continue
            target = asdict(release.symbol)
            pairs = raw.setdefault("pairs", [])
            if target not in pairs:
                pairs.append(target)
                raw.setdefault("pair_evidence", []).append(
                    {
                        "release": target,
                        "method": (
                            "verified_pool_protocol"
                            if pool_pair
                            else "transparent_adapter_composition"
                        ),
                        "acquire_delegates": acquire.delegates,
                        "release_delegates": release.delegates,
                    }
                )
                added += 1
    return added


def deterministic_contract_snapshot(
    context: Mapping[str, Any], registry: ContractRegistry
) -> dict[str, Any] | None:
    """Only completely understood adapters bypass discovery; unknown pools do not."""
    from .build_scope import context_build_id

    registry = registry.for_context(context)
    facts = read_source_facts(context, registry)
    if not facts.complete:
        return None
    tokens = code_tokens(str(context.get("code") or ""))
    name = str(context.get("func_name") or "")
    at = next((i for i in range(len(tokens) - 1) if tokens[i] == name and tokens[i + 1] == "("), -1)
    body = tokens[closing(tokens, at + 1) + 1 :] if at >= 0 else []
    empty = (
        bool(context.get("is_macro"))
        and body
        in (
            ["{", "}"],
            ["do", "{", "}", "while", "(", "0", ")"],
            ["do", "{", "}", "while", "(", "0", ")", ";"],
        )
    ) or (
        at >= 0
        and "void" in tokens[:at]
        and set(tokens[:at]) <= {"static", "inline", "extern", "void"}
        and body == ["{", "}"]
    )
    contracts = derive_contracts(context, registry)
    if (not contracts and not empty) or any(
        (parsed := ApiContract.from_row({"contract": c})) is None or not parsed.effects_trusted
        for c in contracts
    ):
        return None
    from ..snapshots.policy import build_trivial_snapshot

    snapshot = build_trivial_snapshot(str(context.get("func_name") or ""), dict(context))
    snapshot.update(
        interface_contracts=contracts,
        raw_interface_contracts=[],
        contract_diagnostics=[],
        snapshot_kind="syntactic",
        summary=(
            "Empty implementation has no interface effects."
            if empty
            else "Caller-visible adapter effects composed from verified implementation or explicit contracts."
        ),
        code=context.get("code", ""),
    )
    if context_build_id(context):
        snapshot["build_context_id"] = context_build_id(context)
    return snapshot
