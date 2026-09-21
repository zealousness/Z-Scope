"""Over-approximate reachability of one source operation to a later claim.

This does not infer lock success or erase unknown releases. It answers only
whether the reported acquisition can precede the reported observation in the
same invocation. Both boolean branches are retained; loop states reach a fixed
point. Unstructured flow is unsupported, never silently treated as an exit.
"""

from typing import Any

from .validation_facts import walk_ast


def operation_reaches_observation(
    function: dict[str, Any], operations: set[str], observations: set[str]
) -> tuple[bool, set[bool]]:
    unsupported = {
        "GotoStmt",
        "IndirectGotoStmt",
        "LabelStmt",
        "SwitchStmt",
        "GCCAsmStmt",
        "MSAsmStmt",
        "StmtExpr",
        "SEHTryStmt",
        "BlockExpr",
    }
    if any(
        n.get("kind") in unsupported or str(n.get("kind", "")).startswith(("CXX", "ObjC"))
        for n in walk_ast(function)
    ):
        return False, set()
    observed: set[bool] = set()

    def expression(node: dict[str, Any], incoming: set[bool]) -> set[bool]:
        # Nested expressions can be evaluated conditionally or in unspecified
        # order. Keeping both outcomes over-approximates all such orders.
        touched = any(n.get("id") in operations for n in walk_ast(node))
        result = incoming | ({True} if touched else set())
        if any(n.get("id") in observations for n in walk_ast(node)):
            observed.update(result)
        return result

    def execute(node: dict[str, Any], states: set[tuple[bool, str]]) -> set[tuple[bool, str]]:
        ended = {(s, tag) for s, tag in states if tag != "next"}
        live = {s for s, tag in states if tag == "next"}
        if not live:
            return ended
        kind, children = str(node.get("kind") or ""), node.get("inner", [])
        if kind == "CompoundStmt":
            current = {(s, "next") for s in live}
            for child in children:
                current = execute(child, current)
            return ended | current
        if kind == "IfStmt" and len(children) in {2, 3} and not node.get("hasInit"):
            current = {(s, "next") for s in expression(children[0], live)}
            return (
                ended
                | execute(children[1], current)
                | (execute(children[2], current) if len(children) == 3 else current)
            )
        if kind in {"ForStmt", "WhileStmt", "DoStmt"}:
            if kind == "ForStmt" and len(children) == 5:
                initial, _, condition, step, body = children
                start = execute(initial, {(s, "next") for s in live})
                ended |= {(s, tag) for s, tag in start if tag != "next"}
                head = {s for s, tag in start if tag == "next"}
            elif kind == "WhileStmt" and len(children) == 2:
                condition, body = children
                head, step = set(live), {}
            elif kind == "DoStmt" and len(children) == 2:
                body, condition = children
                head, step = set(live), {}
            else:
                raise ValueError("unsupported loop layout")
            exits: set[tuple[bool, str]] = set()
            visited: set[bool] = set()
            while head - visited:
                visited |= head
                test = expression(condition, head)
                # Including a zero-iteration do-while path is conservative for
                # reachability; it can withhold a refutation, never invent one.
                exits |= {(s, "next") for s in test}
                after = execute(body, {(s, "next") for s in test})
                exits |= {
                    (s, "next" if tag == "break" else tag)
                    for s, tag in after
                    if tag in {"break", "return"}
                }
                head |= expression(step, {s for s, tag in after if tag in {"next", "continue"}})
            return ended | exits
        if kind in {"IfStmt", "ForStmt", "WhileStmt", "DoStmt"}:
            raise ValueError("unsupported statement layout")
        values = expression(node, live)
        tag = {"ReturnStmt": "return", "BreakStmt": "break", "ContinueStmt": "continue"}.get(
            kind, "next"
        )
        return ended | {(s, tag) for s in values}

    body = next((n for n in function.get("inner", []) if n.get("kind") == "CompoundStmt"), None)
    if body is None:
        return False, set()
    try:
        execute(body, {(False, "next")})
    except ValueError:
        return False, observed
    return True, observed
