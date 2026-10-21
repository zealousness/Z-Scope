"""Bounded lock coverage over current compiler AST, never serialized locksets.

Only nonescaping TU-static locks and scalar accesses are closed. A checked
status branch establishes a mode; condition waits, recursive acquisition,
upgrades, aliases, arbitrary helpers and C++ lifetime effects stay unknown.
"""

from dataclasses import replace
from pathlib import Path
import re
from typing import Any

from ...semantics.contracts import ApiContract, ContractRegistry, SymbolIdentity
from ...retrieval.validation_facts import walk_ast


def lock_constants(data: dict[str, Any]) -> dict[str, int]:
    """Read a unique target errno definition from dependency-bound system headers.

    A project or command-line redefine is not the library's errno ABI. Retain
    unknown when provenance, dependency bytes or an unambiguous value is absent.
    """
    values = []
    file, system = "", False
    for line in str(data.get("preprocessor") or "").splitlines():
        marker = re.match(r'#\s+\d+\s+"([^"]+)"(.*)$', line)
        if marker:
            file, system = marker[1], "3" in marker[2].split()
            continue
        if re.match(r"#(?:define|undef)\s+EOWNERDEAD\b", line):
            definition = re.fullmatch(r"#define EOWNERDEAD ([0-9]+)\s*", line)
            path = str(Path(file).resolve()) if file and not file.startswith("<") else ""
            values.append(
                int(definition[1])
                if definition and system and path in data.get("dependencies", {})
                else None
            )
    return {"EOWNERDEAD": values[0]} if len(values) == 1 and values[0] is not None else {}


def lock_coverage(
    subject: str,
    functions: dict[str, Any],
    checked: set[str],
    global_locks: set[str],
    ast: dict[str, Any],
    registry: ContractRegistry,
    constants: dict[str, int],
    details: dict[str, Any] | None = None,
) -> bool:
    from .review_checks import call, integer, strip, symbol, ReviewClaimChecker

    details = details if details is not None else {}
    details.update(
        status="unknown",
        reason="lock_identity_or_access_coverage_unclosed",
        identity_scope="current_compiler_fact_store",
        accesses=[],
        acquisitions=[],
        limits={"steps": 10000, "states": 128, "wrapper_rounds": 12},
    )
    # Roots are current reviewed standards. Project definitions cannot borrow
    # a standard name. Recheck transparent helpers from this exact AST instead
    # of trusting a saved contract, arbitrary user assertion or model proposal.
    apis: dict[str, ApiContract] = {}
    dependencies: dict[str, set[str]] = {}
    definitions = {
        str(n.get("name"))
        for n in walk_ast(ast)
        if n.get("kind") == "FunctionDecl"
        and any(c.get("kind") == "CompoundStmt" for c in n.get("inner", []))
    }
    for contract in registry.contracts:
        name = contract.symbol.name
        if (
            name not in definitions
            and contract.source == "builtin_defaults"
            and contract.role in {"lock", "unlock"}
            and contract.carrier.kind == "argument"
            and contract.carrier.argument_index == 0
            and (contract.role == "unlock" or contract.lock_mode != "unknown")
            and registry.find_for_call(name, contract.role) == [contract]
        ):
            apis[name] = contract
            dependencies[name] = set()
    for _ in range(12):
        changed = False
        for name, fn in functions.items():
            if name in apis:
                continue
            params = [n for n in fn.get("inner", []) if n.get("kind") == "ParmVarDecl"]
            body = ReviewClaimChecker._body(fn).get("inner", [])
            if (
                len(params) != 1
                or len(body) != 1
                or body[0].get("kind") != "ReturnStmt"
                or len(body[0].get("inner", [])) != 1
                or any(str(n.get("kind", "")).endswith("Attr") for n in walk_ast(fn))
            ):
                continue
            target, args = call(body[0]["inner"][0])
            if (
                target not in apis
                or len(args) != 1
                or strip(args[0]).get("kind") != "DeclRefExpr"
                or any(
                    "Cast" in str(n.get("kind", ""))
                    and n.get("castKind") not in {"NoOp", "LValueToRValue"}
                    for n in walk_ast(args[0])
                )
                or symbol(args[0]) != str(params[0].get("id"))
            ):
                continue
            apis[name] = replace(apis[target], symbol=SymbolIdentity(name))
            dependencies[name] = dependencies[target] | {name}
            changed = True
        if not changed:
            break

    def operation(node):
        name, args = call(node)
        if (
            name in apis
            and len(args) == 1
            and symbol(args[0]).startswith("&")
            and not any(
                "Cast" in str(n.get("kind", ""))
                and n.get("castKind") not in {"NoOp", "LValueToRValue"}
                for n in walk_ast(args[0])
            )
        ):
            return name, symbol(args[0])[1:]
        return "", ""

    used = {operation(n)[1] for f in functions.values() for n in walk_ast(f)}
    global_locks = global_locks & used
    if not global_locks:
        return False
    refs = [
        n for n in walk_ast(ast) if n.get("kind") == "DeclRefExpr" and symbol(n) in global_locks
    ]
    function_refs = [
        n
        for f in functions.values()
        for n in walk_ast(f)
        if n.get("kind") == "DeclRefExpr" and symbol(n) in global_locks
    ]
    if len(refs) != len(function_refs):
        return False
    for fn in functions.values():
        parents = {
            str(c.get("id")): n for n in walk_ast(fn) for c in n.get("inner", []) if c.get("id")
        }
        for ref in walk_ast(fn):
            if ref.get("kind") != "DeclRefExpr" or symbol(ref) not in global_locks:
                continue
            ancestor = ref
            while str(ancestor.get("id")) in parents:
                ancestor = parents[str(ancestor["id"])]
                if ancestor.get("kind") == "CallExpr":
                    name, lock = operation(ancestor)
                    if name and lock == symbol(ref):
                        checked.update(dependencies[name])
                        break
                    details["reason"] = "lock_escape_or_unmodeled_effect"
                    return False
                if ancestor.get("kind") in {
                    "CompoundStmt",
                    "BinaryOperator",
                    "ReturnStmt",
                    "DeclStmt",
                }:
                    return False
            else:
                return False

    access_locks: list[set[str]] = []
    # Only a compiler LValueToRValue conversion is a known read. Everything
    # else (including ++, assignment and escaped addresses) needs exclusion.
    reads = {
        str(c.get("id"))
        for f in functions.values()
        for n in walk_ast(f)
        if n.get("kind") == "ImplicitCastExpr" and n.get("castKind") == "LValueToRValue"
        for c in n.get("inner", [])
        if c.get("kind") == "DeclRefExpr" and symbol(c) == subject
    }
    steps = 0

    def inspect(node, held):
        nonlocal steps
        steps += 1
        if steps > 10000:
            details["reason"] = "step_budget"
            return None
        node = strip(node)
        kind, children = node.get("kind"), node.get("inner", [])
        if kind == "CompoundStmt":
            states = [(dict(held), False)]
            for child in children:
                result = []
                for locks, ended in states:
                    branch = [(locks, True)] if ended else inspect(child, dict(locks))
                    if branch is None:
                        return None
                    result.extend(branch)
                if len(result) > 128:
                    details["reason"] = "state_budget"
                    return None
                states = result
            return states
        if kind == "IfStmt" and len(children) in {2, 3} and not node.get("hasInit"):
            cond = strip(children[0])
            parts = cond.get("inner", [])
            yes, no = dict(held), dict(held)
            acquisition = False
            if (
                cond.get("kind") == "BinaryOperator"
                and cond.get("opcode") in {"==", "!="}
                and len(parts) == 2
            ):
                name, lock = operation(parts[0])
                value = integer(parts[1])
                if (
                    name
                    and apis[name].role == "lock"
                    and lock in global_locks
                    and value is not None
                ):
                    if lock in held:
                        # Recursive count, mode upgrade and recursive attributes
                        # need a dedicated protocol; set membership is unsound.
                        details["reason"] = "recursive_or_mode_change_unmodeled"
                        return None
                    status = apis[name].applicability(
                        ["&" + lock], "status", {**constants, "status": value}
                    )
                    if status == "unknown":
                        return None
                    if status == "applies":
                        (yes if cond["opcode"] == "==" else no)[lock] = (
                            apis[name].lock_mode,
                            apis[name].resource_family,
                        )
                        details["acquisitions"].append(
                            {
                                "call_node": str(strip(parts[0]).get("id", "")),
                                "lock_declaration": lock,
                                "api": name,
                                "mode": apis[name].lock_mode,
                                "checked_status": value,
                                "family": apis[name].resource_family,
                            }
                        )
                    acquisition = True
            if not acquisition and inspect(cond, dict(held)) is None:
                return None
            a = inspect(children[1], yes)
            b = inspect(children[2], no) if len(children) == 3 else [(no, False)]
            return None if a is None or b is None else a + b
        if kind == "DoStmt" and len(children) == 2 and integer(children[1]) == 0:
            return inspect(children[0], held)
        if kind in {
            "WhileStmt",
            "ForStmt",
            "GotoStmt",
            "IndirectGotoStmt",
            "SwitchStmt",
            "CXXTryStmt",
            "CXXThrowExpr",
            "GCCAsmStmt",
            "MSAsmStmt",
            "SEHTryStmt",
            "IfStmt",
        }:
            return None
        name, lock = operation(node)
        if name:
            if (
                apis[name].role != "unlock"
                or lock not in held
                or held[lock][1] != apis[name].resource_family
            ):
                return None
            # An unchecked unlock may have released the lock. No subsequent
            # access can retain protection merely because failure is possible.
            del held[lock]
            return [(held, False)]
        if (
            kind == "UnaryOperator"
            and node.get("opcode") == "&"
            and children
            and symbol(children[0]) == subject
        ):
            return None
        if kind == "CallExpr" or ReviewClaimChecker._unsupported_lifetime_effects(node):
            return None
        if any(n.get("kind") == "CallExpr" for c in children for n in walk_ast(c)):
            return None
        if kind == "DeclRefExpr" and symbol(node) == subject:
            read = str(node.get("id")) in reads
            access_locks.append(
                {
                    lock
                    for lock, (mode, _) in held.items()
                    if mode == "exclusive" or (read and mode == "shared")
                }
            )
            details["accesses"].append(
                {
                    "node": str(node.get("id", "")),
                    "subject_declaration": subject,
                    "access": "read" if read else "write_or_unknown",
                    "compatible_locks": sorted(access_locks[-1]),
                    "held": [
                        {"declaration": lock, "mode": mode, "family": family}
                        for lock, (mode, family) in sorted(held.items())
                    ],
                }
            )
        for child in children:
            if inspect(child, dict(held)) is None:
                return None
        return [(held, kind == "ReturnStmt")]

    for name, fn in functions.items():
        if any(
            n.get("kind") == "DeclRefExpr" and symbol(n) in (global_locks | {subject})
            for n in walk_ast(fn)
        ):
            checked.add(name)
            if inspect(ReviewClaimChecker._body(fn), {}) is None:
                return False
    common = set.intersection(*access_locks) if access_locks else set()
    details.update(
        status="supported" if common else "unknown", common_locks=sorted(common), steps=steps
    )
    if common:
        details["reason"] = "all_accesses_have_compatible_common_lock"
    return bool(common)
