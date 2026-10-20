"""Project only native-verified C/glibc cleanup scaffolds; retain raw input hashes."""

from typing import Any

from .lifecycle_paths import Unclosed


def project_cleanup(body: dict[str, Any]) -> dict[str, Any]:
    events = body.get("events", [])
    marked = [e for e in events if e.get("pthread_cleanup")]
    if not marked:
        return body
    if body.get("pthread_cleanup_control_exit"):
        raise Unclosed("async_cleanup_control_exit_unsupported")
    if body.get("pthread_cleanup_facts_version") != "zscope.pthread-cleanup.v1":
        raise Unclosed("async_cleanup_receipt_missing")
    projected = []
    operations: dict[tuple[int, str], dict[str, Any]] = {}
    for event in events:
        marker = event.get("pthread_cleanup")
        if not marker:
            projected.append(event)
            continue
        if marker.get("schema") != "zscope.pthread-cleanup.v1" or not event.get("macro_expansion"):
            raise Unclosed("async_cleanup_receipt_invalid")
        if not marker.get("operation"):
            continue
        key = marker["pair"], marker["action"]
        # Native can materialize one call twice; collapse only the same site.
        if key in operations:
            if operations[key]["location"] != event["location"]:
                raise Unclosed("async_cleanup_operation_ambiguous")
            continue
        operations[key] = event
        values = [
            v for e in events for v in e.get("uses", []) if v.get("usr") == marker["argument_usr"]
        ]
        if not values:
            raise Unclosed("async_cleanup_argument_unbound")
        projected.append(
            {
                **event,
                "event_kind": "call",
                "expression": "cleanup_" + marker["action"] + "_" + str(marker["pair"]),
                "callee": {"name": "__zscope_cleanup_" + marker["action"], "usr": str(key)},
                "arguments": [],
                "argument_objects": [],
                "argument_uses": [],
                "object": {},
                "defs": [],
                "uses": [{**values[0], "expression": marker["argument"]}],
                "contains_macro": False,
            }
        )
    pairs = {key[0] for key in operations}
    if any((pair, action) not in operations for pair in pairs for action in ("push", "pop")):
        raise Unclosed("async_cleanup_pair_unclosed")
    edges = []
    for edge in body.get("cfg_edges", []):
        marker = edge.get("pthread_cleanup")
        if marker:
            if (
                marker.get("pair") not in pairs
                or marker.get("schema") != "zscope.pthread-cleanup.v1"
            ):
                raise Unclosed("async_cleanup_branch_unbound")
            # Normal registration bypasses the setjmp unwind branch; pop is
            # replayed explicitly. Constant-zero macro do-loops never repeat.
            edge = {
                **edge,
                "condition": str(marker.get("condition_value", 0)),
                "condition_uses": [],
            }
        edges.append(edge)
    return {**body, "events": projected, "cfg_edges": edges}
