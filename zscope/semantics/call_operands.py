"""Resolve call operands through the published contracts, never API spelling.

This source adapter is a discovery aid. Compiler checks independently bind the
operand to a real call before granting proof authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from .contracts import ContractRegistry, code_tokens


@dataclass(frozen=True)
class CallOperand:
    name: str
    arguments: tuple[str, ...]
    expression: str
    argument_index: int
    contract_version: str
    trusted: bool


def is_literal_string(expression: str) -> bool:
    from .contract_compiler import unparen

    tokens = unparen(code_tokens(expression))
    tokens = [
        token
        for i, token in enumerate(tokens)
        if not (
            token in {"u8", "u", "U", "L"} and i + 1 < len(tokens) and tokens[i + 1].startswith('"')
        )
    ]
    return bool(tokens) and all(
        re.fullmatch(r'(?:u8|u|U|L)?"(?:\\.|[^"\\])*"', token, re.S) for token in tokens
    )


def call_operands(
    registry: ContractRegistry, text: str, role: str, *, file_path: str = ""
) -> list[CallOperand]:
    from .contract_compiler import closing, split_tokens

    tokens = code_tokens(text)
    result = []
    for index, name in enumerate(tokens[:-1]):
        if tokens[index + 1] != "(" or not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        end = closing(tokens, index + 1)
        if end >= len(tokens) or tokens[end] != ")":
            continue
        # A declaration/definition is not an invocation of its own contract.
        if end + 1 < len(tokens) and tokens[end + 1] == "{":
            continue
        args = ["".join(part) for part in split_tokens(tokens[index + 2 : end])]
        contracts = registry.find(name, role, file_path)
        bindings = {
            (c.carrier.argument_index, c.carrier.resolve(args))
            for c in contracts
            if c.carrier.kind == "argument" and c.carrier.argument_index is not None
        }
        # Conflicting overloads/mappings must be resolved by the compiler.
        if len(bindings) != 1:
            continue
        slot, expression = next(iter(bindings))
        if not expression or slot is None or slot >= len(args):
            continue
        result.append(
            CallOperand(
                name,
                tuple(args),
                expression,
                slot,
                registry.version,
                bool(contracts) and all(c.effects_trusted for c in contracts),
            )
        )
    return result
