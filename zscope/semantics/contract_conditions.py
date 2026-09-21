"""Typed, three-valued predicates shared by API contract producers/consumers.

Unknown is not false and never authorizes a release. Descriptions are not
expressions: every operand names a caller object or an anchored call result.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

UNKNOWN = object()
COMPARISONS = frozenset({"==", "!=", "<", "<=", ">", ">="})
REFERENCE_KINDS = frozenset({"return", "argument", "global", "call_result", "literal", "constant", "target"})


def compare(left: dict[str, Any], operator: str, value: Any) -> dict[str, Any]:
    return {
        "op": "compare",
        "left": left,
        "operator": operator,
        "right": {"kind": "literal", "value": value},
    }


def conjunction(items: list[dict[str, Any]]) -> dict[str, Any]:
    import json

    flattened = [
        part
        for item in items
        for part in (item.get("items", []) if item.get("op") == "all" else [item])
    ]
    values = list(
        {
            json.dumps(item, sort_keys=True): item for item in flattened if item != {"op": "true"}
        }.values()
    )
    values.sort(key=lambda item: json.dumps(item, sort_keys=True))
    if not values:
        return {"op": "true"}
    return values[0] if len(values) == 1 else {"op": "all", "items": values}


def negate(predicate: dict[str, Any]) -> dict[str, Any]:
    if predicate.get("op") == "compare":
        return {
            **predicate,
            "operator": {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}[
                predicate["operator"]
            ],
        }
    return {"op": "not", "item": predicate}


def predicate_errors(value: Any, *, parameter_count: int | None = None) -> list[str]:
    if not isinstance(value, dict):
        return ["predicate_must_be_object"]
    op = value.get("op")
    if op in {"true", "false", "unknown"}:
        return []
    if op in {"all", "any"}:
        items = value.get("items")
        if not isinstance(items, list):
            return ["predicate_items_must_be_array"]
        errors = [
            error
            for item in items
            for error in predicate_errors(item, parameter_count=parameter_count)
        ]
        if op == "all":
            flat = conjunction([item for item in items if isinstance(item, dict)])
            flat_items = flat.get("items", []) if flat.get("op") == "all" else [flat]
            atoms = {
                (repr(item.get("left")), repr(item.get("right")), item.get("operator"))
                for item in flat_items
                if isinstance(item, dict) and item.get("op") == "compare"
            }
            complements = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}
            if any(
                (left, right, complements[operator]) in atoms
                for left, right, operator in atoms
                if operator in complements
            ):
                errors.append("contradictory_effect_condition")
            # Also reject incompatible equalities and numeric intervals, e.g.
            # status == 0 && status == 1, or size > 8 && size <= 4.
            groups: dict[str, list[tuple[str, Any]]] = {}
            for item in flat_items:
                if not isinstance(item, dict) or item.get("op") != "compare":
                    continue
                left, right = item.get("left", {}), item.get("right", {})
                operator = item.get("operator")
                if (
                    isinstance(left, dict)
                    and isinstance(right, dict)
                    and right.get("kind") == "literal"
                ):
                    groups.setdefault(repr(left), []).append((str(operator), right.get("value")))
            for constraints in groups.values():
                equalities = [value for operator, value in constraints if operator == "=="]
                if equalities:
                    constant = equalities[0]
                    if any(
                        evaluate(compare({"kind": "literal", "value": constant}, operator, value))
                        == "does_not_apply"
                        for operator, value in constraints
                        if operator in COMPARISONS
                    ):
                        errors.append("contradictory_effect_condition")
                lower = [
                    (value, operator == ">")
                    for operator, value in constraints
                    if operator in {">", ">="} and isinstance(value, (int, float))
                ]
                upper = [
                    (value, operator == "<")
                    for operator, value in constraints
                    if operator in {"<", "<="} and isinstance(value, (int, float))
                ]
                if any(
                    lo > hi or (lo == hi and (lo_strict or hi_strict))
                    for lo, lo_strict in lower
                    for hi, hi_strict in upper
                ):
                    errors.append("contradictory_effect_condition")
        return errors
    if op == "not":
        return predicate_errors(value.get("item"), parameter_count=parameter_count)
    if op != "compare" or value.get("operator") not in COMPARISONS:
        return ["unsupported_predicate_operator"]
    errors = []
    for side in ("left", "right"):
        ref = value.get(side)
        if not isinstance(ref, dict) or ref.get("kind") not in REFERENCE_KINDS:
            errors.append("invalid_predicate_reference")
            continue
        kind = ref["kind"]
        if kind == "argument":
            index = ref.get("index")
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or (parameter_count is not None and index >= parameter_count)
            ):
                errors.append("predicate_argument_out_of_range")
        if kind in {"global", "call_result", "constant", "target"} and not str(ref.get("name") or "").strip():
            errors.append("predicate_reference_missing_identity")
        if ref.get("member_path") and not re.fullmatch(
            r"(?:(?:\.|->)[A-Za-z_]\w*|\[\d+\])+", str(ref["member_path"])
        ):
            errors.append("invalid_predicate_member_path")
    return errors


def legacy_predicate(conditions: Any, parameters: list[str] | None = None) -> dict[str, Any]:
    """Read legacy human rows conservatively. Only bound identifiers are executable."""
    if not conditions:
        return {"op": "true"}
    if isinstance(conditions, dict):
        return conditions if not predicate_errors(conditions) else {"op": "unknown"}
    if not isinstance(conditions, list):
        return {"op": "unknown"}
    result = []
    for item in conditions:
        if not isinstance(item, dict):
            result.append({"op": "unknown"})
            continue
        subject = str(item.get("subject") or "")
        ref: dict[str, Any]
        if subject in {"return", "$return", "return_value"}:
            ref = {"kind": "return"}
        elif parameters and subject in parameters:
            ref = {"kind": "argument", "index": parameters.index(subject)}
        elif re.fullmatch(r"\$?arg(?:ument)?\[?\d+\]?", subject):
            ref = {"kind": "argument", "index": int(re.search(r"\d+", subject)[0])}  # type: ignore[index]
        else:
            result.append({"op": "unknown"})
            continue
        operator = item.get("operator")
        if operator not in COMPARISONS:
            result.append({"op": "unknown"})
            continue
        value = item.get("value")
        if value in ("NULL", "nullptr"):
            value = None
        result.append(compare(ref, operator, value))
    return conjunction(result)


def _operand(
    ref: Mapping[str, Any], arguments: list[str], returned: str, facts: Mapping[str, Any]
) -> Any:
    kind = ref.get("kind")
    if kind == "literal":
        return ref.get("value")
    if kind == "argument":
        index = ref.get("index")
        name = arguments[index] if isinstance(index, int) and 0 <= index < len(arguments) else ""
    elif kind == "return":
        name = returned
    else:
        name = str(ref.get("name") or "")
    name = re.sub(r"\s+", "", name)
    while name.startswith("(") and name.endswith(")") and name.count("(") == 1:
        name = name[1:-1]
    name += str(ref.get("member_path") or "")
    if name in facts:
        return facts[name]
    if name in {"NULL", "nullptr", "(void*)0"}:
        return None
    if re.fullmatch(r"[-+]?\d+", name):
        return int(name)
    if re.fullmatch(r"&[A-Za-z_]\w*", name):
        return facts.get(name[1:], object())
    return UNKNOWN


def evaluate(
    predicate: Any,
    arguments: list[str] | None = None,
    returned: str = "",
    facts: Mapping[str, Any] | None = None,
) -> str:
    """Return applies, does_not_apply, or unknown without evaluating C as Python."""
    if predicate_errors(predicate):
        return "unknown"
    args, known = arguments or [], facts or {}
    op = predicate["op"]
    if op in {"true", "false", "unknown"}:
        return {"true": "applies", "false": "does_not_apply", "unknown": "unknown"}[op]
    if op == "not":
        return {"applies": "does_not_apply", "does_not_apply": "applies", "unknown": "unknown"}[
            evaluate(predicate["item"], args, returned, known)
        ]
    if op in {"all", "any"}:
        values = [evaluate(item, args, returned, known) for item in predicate["items"]]
        decisive = "does_not_apply" if op == "all" else "applies"
        if decisive in values:
            return decisive
        if "unknown" in values:
            return "unknown"
        return "applies" if op == "all" else "does_not_apply"
    left, right = (_operand(predicate[side], args, returned, known) for side in ("left", "right"))
    if left is UNKNOWN or right is UNKNOWN:
        return "unknown"
    # Non-null symbolic resources can be supplied as opaque objects by a caller
    # tracking an already acquired resource. Ordering is deliberately unsupported.
    operator = predicate["operator"]
    if operator in {"==", "!="}:
        equal = left == right or (left is None and right == 0) or (right is None and left == 0)
        ok = equal if operator == "==" else not equal
    elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
        ok = {"<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right}[
            operator
        ]
    else:
        return "unknown"
    return "applies" if ok else "does_not_apply"
