"""Native counterevidence to proposals that erase a pointer displacement.

This checks contradictions, not complete ownership or bounds proofs. Only the
current function's native declaration identities and supplied standard roots
participate; source names and model explanations never authorize an effect.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..semantics.contracts import code_tokens


def offset_conflicts(
    body: Mapping[str, Any], roots: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    parameters = body.get("parameters") or []
    parameter_usrs = {str(p.get("usr")): i for i, p in enumerate(parameters) if p.get("usr")}
    events = body.get("events") or []
    definitions: dict[str, list[Mapping[str, Any]]] = {}
    for event in events:
        for definition in event.get("defs") or []:
            usr = str(definition.get("usr") or "")
            if usr and usr not in parameter_usrs:
                definitions.setdefault(usr, []).append(event)

    def trace(
        expression: str, uses: Sequence[Mapping[str, Any]], seen: frozenset[str]
    ) -> dict[int, tuple[bool, bool]]:
        tokens = code_tokens(expression)
        # An explicit literal-zero displacement preserves the base. This is
        # deliberately not a symbolic bounds/guard solver.
        offsets = []
        for position, token in enumerate(tokens):
            if token not in {"+", "-"}:
                continue
            operand = tokens[position + 1] if position + 1 < len(tokens) else ""
            if operand.lower().rstrip("ul") in {"0", "0x0", "0b0"}:
                continue
            offsets.append(token)
        displaced, backwards = bool(offsets), "-" in offsets
        result: dict[int, tuple[bool, bool]] = {}
        for use in uses:
            # Length/count arithmetic does not displace an unrelated pointer.
            if use.get("integer_bits") or use.get("floating_value"):
                continue
            usr = str(use.get("usr") or use.get("referenced_usr") or "")
            if usr in parameter_usrs:
                result[parameter_usrs[usr]] = (displaced, backwards)
            elif usr and usr not in seen:
                for event in definitions.get(usr, []):
                    rhs = str(event.get("assignment_value") or event.get("expression") or "")
                    for index, flags in trace(rhs, event.get("uses") or [], seen | {usr}).items():
                        # Multiple native definitions are alternatives, not a
                        # single sequence of cumulative displacements. Without
                        # path selection a direct-base alternative must prevent
                        # a universal rejection of that object's possible effect.
                        prior = result.get(index, (True, True))
                        result[index] = (
                            prior[0] and (displaced or flags[0]),
                            prior[1] and (backwards or flags[1]),
                        )
        return result

    root_by_name: dict[str, list[Mapping[str, Any]]] = {}
    for root in roots:
        if root.get("role") in {"deallocator", "copy", "recv_source"}:
            root_by_name.setdefault(str(root.get("symbol", {}).get("name") or ""), []).append(root)
    sites: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for event in events:
        if event.get("event_kind") != "call":
            continue
        callee = event.get("callee") or {}
        for root in root_by_name.get(str(callee.get("name") or ""), []):
            expected_usr = root.get("symbol", {}).get("usr")
            actual_usr = callee.get("usr") or callee.get("referenced_usr")
            if expected_usr and expected_usr != actual_usr:
                continue
            # A local namesake is not a standard root merely because a root
            # of that name also occurs elsewhere in this function.
            if callee.get("has_definition") and not callee.get("is_system_header"):
                continue
            carrier = root.get("carrier") or {}
            index = carrier.get("argument_index")
            arguments, uses = event.get("arguments") or [], event.get("argument_uses") or []
            if type(index) is not int or not 0 <= index < min(len(arguments), len(uses)):
                continue
            expression = str(arguments[index])
            for param, (displaced, backwards) in trace(
                expression, uses[index], frozenset()
            ).items():
                role = str(root["role"])
                bad = displaced if role == "deallocator" else backwards
                sites.setdefault((param, role), []).append(
                    {
                        "expression": expression,
                        "event_id": event.get("event_id"),
                        "conflicting": bad,
                    }
                )
    return [
        {
            "argument_index": index,
            "role": role,
            "reason": "offset_object_not_representable",
            "sites": rows,
        }
        for (index, role), rows in sorted(sites.items())
        if rows and all(row["conflicting"] for row in rows)
    ]
