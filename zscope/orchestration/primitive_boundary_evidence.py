"""Compact native observations for boundary review, never a semantic proof.

Keep slot writes, call results and literal sink operands visible. These are
observations from the exact native instance; no source-name heuristics or
benchmark answers participate. The model still checks paths and aliases.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence
import re
from copy import deepcopy
from pathlib import Path
from ..semantics.contracts import code_tokens


def _compact(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or ""))


def native_guard_globals(body: Mapping[str, Any]) -> dict[str, str]:
    """Unambiguous native global names, never a spelling-prefix heuristic."""
    records = [r for e in body.get("events", []) for r in [*e.get("defs", []), *e.get("uses", [])]]
    records += [r for e in body.get("cfg_edges", []) for r in e.get("condition_uses", [])]
    result = {}
    for r in records:
        name, usr = r.get("name"), r.get("usr")
        if not name or not usr or r.get("value_kind") != "global":
            continue
        if any(x.get("name") == name and x.get("usr") != usr for x in records):
            continue  # A shadowed or ambiguous identifier needs explicit reasoning.
        result[name] = "int" if r.get("integer_bits") else ""
    return result


def field_declarations(body: Mapping[str, Any], root: Path) -> list[dict[str, str]]:
    """Small source excerpts at native field declarations, not inferred types.

    Source context helps distinguish inline buffers from pointer slots. These
    excerpts confer no additional proof authority; native identities stay private.
    """
    result: list[dict[str, str]] = []
    seen = set()
    for event in body.get("events", []):
        for record in [*event.get("uses", []), *event.get("defs", [])]:
            if record.get("value_kind") != "field" or not record.get("usr"):
                continue
            loc = record.get("declaration") or {}
            path = Path(str(loc.get("file") or "")).resolve()
            line = loc.get("line")
            if not path.is_relative_to(root.resolve()) or type(line) is not int or line < 1:
                continue
            key = (str(path), line)
            if key in seen or len(result) >= 24:
                continue
            try:
                text = path.read_text().splitlines()[line - 1].strip()
            except (OSError, UnicodeError, IndexError):
                continue
            if len(text) > 300 or record.get("name") not in code_tokens(text):
                continue
            result.append({"expression": str(record.get("expression") or ""), "declaration": text})
            seen.add(key)
    return result


def overwritten_entry_member(body: Mapping[str, Any], expression: str) -> bool:
    """Reject confusing a dominating field overwrite with an entry-field guard.

    Limited to exact direct parameter members with complete CFG and no escape
    before the store. Unknown aliases or shadowing prevent this diagnostic.
    """
    if body.get("complete") is not True or not re.fullmatch(
        r"[A-Za-z_]\w*->[A-Za-z_]\w*", expression
    ):
        return False
    events = body.get("events", [])
    base = expression.split("->")[0]
    parameter: Mapping[str, Any] = next(
        (p for p in body.get("parameters", []) if p.get("name") == base), {}
    )
    if not parameter.get("usr"):
        return False
    if any(
        r.get("name") == base and r.get("usr") and r["usr"] != parameter["usr"]
        for e in events
        for r in [*e.get("defs", []), *e.get("uses", [])]
    ):
        return False
    stores = [
        e
        for e in events
        if e.get("event_kind") == "call"
        and _compact((e.get("object") or {}).get("expression")) == expression
        or e.get("event_kind") == "assignment"
        and _compact(e.get("assignment_target")) == expression
    ]
    if not stores:
        return False
    edges = body.get("cfg_edges", [])
    blocks = {e.get("from") for e in edges} | {e.get("to") for e in edges}
    entry = body.get("cfg_entry")
    if entry not in blocks:
        return False
    preds = {b: {e.get("from") for e in edges if e.get("to") == b} for b in blocks}
    dom = {b: {b} if b == entry else set(blocks) for b in blocks}
    for _ in range(len(blocks) + 1):
        new = {
            b: (
                {b}
                if b == entry or not preds[b]
                else {b} | set.intersection(*(dom[p] for p in preds[b]))
            )
            for b in blocks
        }
        if new == dom:
            break
        dom = new

    def after_store(block: Any, ordinal: int) -> bool:
        return any(
            s.get("block") in dom.get(block, set())
            and (s.get("block") != block or s.get("ordinal", 0) < ordinal)
            for s in stores
        )

    for event in events:
        reads = any(_compact(r.get("expression")) == expression for r in event.get("uses", []))
        escapes = event.get("event_kind") == "call" and any(
            _compact(a).lstrip("&") == base for a in event.get("arguments", [])
        )
        # A compound assignment or an RHS reading the old member is not a kill.
        rhs_reads = expression in _compact(event.get("assignment_value")) or any(
            expression in _compact(a) for a in event.get("arguments", [])
        )
        if event in stores and not rhs_reads:
            continue
        alias_escape = event.get("event_kind") in {"assignment", "declaration", "return"} and any(
            r.get("usr") == parameter["usr"] for r in event.get("uses", [])
        )
        if alias_escape and not after_store(event.get("block"), event.get("ordinal", 0)):
            return False
        if (reads or escapes or rhs_reads) and not after_store(
            event.get("block"), event.get("ordinal", 0)
        ):
            return False
    for edge in edges:
        if any(
            _compact(r.get("expression")) == expression for r in edge.get("condition_uses", [])
        ) and not after_store(edge.get("from"), 10**9):
            return False
    return True


def copy_boundary_gap(body: Mapping[str, Any], expression: str) -> str:
    """Identify unsupported object projections, not absence of all writes.

    Slot-only effects are outside the memory-copy proposal slice. Rebinding an
    out pointer needs generation-aware composition; a spelling shared before
    and after the call is insufficient. Do not guess through aliases/helpers.
    """
    expression = _compact(expression)
    if body.get("complete") is not True:
        return ""
    events = body.get("events", [])
    parameter_name = expression.lstrip("*").split("->", 1)[0]
    parameter: Mapping[str, Any] = next(
        (p for p in body.get("parameters", []) if p.get("name") == parameter_name), {}
    )
    if parameter.get("usr") and any(
        r.get("usr")
        and r["usr"] != parameter["usr"]
        and _compact(r.get("expression")) == parameter_name
        for e in events
        for r in [*e.get("defs", []), *e.get("uses", [])]
    ):
        return ""  # A shadowed spelling is not the same native object.
    if expression.startswith("*"):
        stores = [
            e
            for e in events
            if e.get("event_kind") == "call"
            and _compact((e.get("object") or {}).get("expression")) == expression
        ]
        if any(
            expression.lstrip("*") in code_tokens(str(a))
            for e in stores
            for a in e.get("arguments", [])
        ):
            # The callee may return/preserve the incoming pointer generation.
            return ""
        if stores:
            # A prior explicit write or alias can concern the old generation;
            # do not suppress that case using mere presence of a rebinding.
            entry = body.get("cfg_entry")
            edges = body.get("cfg_edges", [])
            blocks = {e.get("from") for e in edges} | {e.get("to") for e in edges}
            if entry not in blocks:
                return ""
            predecessors = {b: {e.get("from") for e in edges if e.get("to") == b} for b in blocks}
            dom = {b: ({b} if b == entry else set(blocks)) for b in blocks}
            for _ in range(len(blocks) + 1):
                next_dom = {
                    b: (
                        {b}
                        if b == entry
                        else (
                            {b} | set.intersection(*(dom[p] for p in predecessors[b]))
                            if predecessors[b]
                            else {b}
                        )
                    )
                    for b in blocks
                }
                if next_dom == dom:
                    break
                dom = next_dom
            uses = [
                e
                for e in events
                if e not in stores
                and any(expression in _compact(a) for a in (e.get("arguments") or []))
            ]
            aliases_or_writes = [
                e
                for e in events
                if e.get("event_kind") in {"assignment", "declaration"}
                and any(
                    expression in _compact(e.get(k))
                    for k in ("expression", "assignment_target", "assignment_value")
                )
            ]
            if uses and all(
                any(
                    s.get("block") in dom.get(e.get("block"), set())
                    and (
                        s.get("block") != e.get("block")
                        or s.get("ordinal", 0) < e.get("ordinal", 0)
                    )
                    for s in stores
                )
                for e in [*uses, *aliases_or_writes]
            ):
                return (
                    "output pointer is rebound by a call before every supplied pointee call use; "
                    "pre-state *out does not identify this post-call generation. Keep output ownership; "
                    "omit initialization-copy unless distinct old-generation writes are evidenced"
                )
    if "->" not in expression:
        return ""
    base = expression.split("->", 1)[0]
    writes = [
        e
        for e in events
        if e.get("event_kind") == "assignment"
        and (
            _compact(e.get("assignment_target")) == expression
            or _compact(e.get("assignment_target")).startswith(expression + "[")
            or _compact(e.get("assignment_target")).startswith(expression + "->")
        )
    ]
    # Passing the object/its parent to a call may expose real writes. This
    # limited slot check deliberately leaves those cases to semantic review.
    escaped = any(
        _compact(a).lstrip("&") == base or expression in _compact(a)
        for e in events
        if e.get("event_kind") == "call"
        for a in e.get("arguments", [])
    )
    if (
        writes
        and not escaped
        and all(
            e.get("defs") and all(d.get("value_kind") == "field" for d in e["defs"]) for e in writes
        )
    ):
        return (
            "only ordinary member-slot assignments support this object; no buffer operation or "
            "callee receiving it is supplied. Such bookkeeping is native data, not an independent "
            "copy contract; do not rename the slot to its containing aggregate to evade this gap"
        )
    return ""


def boundary_observations(
    body: Mapping[str, Any], roots: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    observations = []
    seen = set()
    parameters = {p.get("name") for p in body.get("parameters", [])}
    for event in body.get("events", []):
        kind = event.get("event_kind")
        row: dict[str, Any] = {}
        if kind == "assignment":
            target = str(event.get("assignment_target") or "")
            base = target.lstrip("*").split("->", 1)[0]
            if base in parameters and ("->" in target or target.startswith("*")):
                row = {"write_slot": target, "value": event.get("assignment_value")}
                if event.get("defs") and all(r.get("integer_bits") for r in event["defs"]):
                    row["slot_kind"] = (
                        "scalar_member_bookkeeping" if "->" in target else "scalar_output"
                    )
        elif kind == "call":
            callee = event.get("callee") or {}
            target = str((event.get("object") or {}).get("expression") or "")
            base = target.lstrip("*").split("->", 1)[0]
            if base in parameters and ("->" in target or target.startswith("*")):
                row = {"call_result_slot": target, "callee": callee.get("name")}
            for root in roots:
                symbol = root.get("symbol") or {}
                if root.get("role") != "format_sink" or symbol.get("name") != callee.get("name"):
                    continue
                if symbol.get("usr") and symbol["usr"] != callee.get("usr"):
                    continue
                if callee.get("has_definition") and not callee.get("is_system_header"):
                    continue
                index = (root.get("carrier") or {}).get("argument_index")
                args = event.get("arguments") or []
                if isinstance(index, int) and index < len(args):
                    row = {**row, "format_operand": args[index], "callee": callee.get("name")}
        if row:
            key = str(row)
            if key not in seen:
                observations.append(row)
                seen.add(key)
    return observations


def compact_draft(result: Mapping[str, Any]) -> dict[str, Any]:
    """Retain the current claims, references and their concise source witness.

    The witness is a model claim to check, not authority. Dropping it forced
    repeated derivation and hid contradictions between claims and their reasons.
    """
    return {
        key: (
            [compact_draft(item) if isinstance(item, Mapping) else item for item in value]
            if key in {"results", "contracts"} and isinstance(value, list)
            else value
        )
        for key, value in result.items()
        if key not in {"reason", "review_edits"}
    }


def apply_review_delta(
    result: Mapping[str, Any],
    previous: Mapping[str, Any],
    allowed_refs: set[str],
    supporting_refs: set[str] | None = None,
) -> dict[str, Any]:
    """Apply explicit claim edits, not an accidentally shortened replacement list.

    Reasons/references are auditable model claims, never deterministic proofs.
    The caller revalidates EVERY resulting contract against the current packet.
    """
    if "changes" not in result:
        return dict(result)
    before = previous.get("contracts")
    if not isinstance(before, list):
        raise ValueError("review delta requires the last complete contract list")
    changes, additions = result["changes"], result.get("add", [])
    if not isinstance(changes, list) or not isinstance(additions, list):
        raise ValueError("changes and add must be arrays")
    edits = {}
    audit = []
    for edit in changes:
        if not isinstance(edit, dict):
            raise ValueError("each review edit must be an object")
        index = edit.get("index")
        if type(index) is not int or not 0 <= index < len(before) or index in edits:
            raise ValueError("review index must identify one existing clause exactly once")
        replacement = edit.get("contract")
        reason = str(
            edit.get("reason")
            or (replacement.get("rationale") if isinstance(replacement, dict) else "")
            or ""
        ).strip()
        # A replacement already carries its source citations. Do not force the
        # model to repeat them at the edit envelope; deletions still need refs.
        binding = "explicit"
        refs = edit.get("evidence_refs")
        if refs is None and isinstance(replacement, dict):
            refs = replacement.get("evidence_refs")
            binding = "replacement"
        if refs is None and isinstance(before[index], dict):
            refs = before[index].get("evidence_refs")
            binding = "previous_clause"
        if (
            not reason
            or not isinstance(refs, list)
            or not refs
            or not any(isinstance(r, str) and r in allowed_refs for r in refs)
            or any(
                not isinstance(r, str) or r not in allowed_refs | (supporting_refs or set())
                for r in refs
            )
        ):
            raise ValueError(
                f"review index {index}: each change/removal requires a concrete reason and allowed source evidence_refs; "
                f"received={refs!r}; source={sorted(allowed_refs)!r}; "
                f"optional roots={sorted(supporting_refs or set())!r}"
            )
        if "contract" not in edit or not (
            edit["contract"] is None or isinstance(edit["contract"], dict)
        ):
            raise ValueError(
                "review edit contract must be a replacement object or null for removal"
            )
        edits[index] = (
            {**replacement, "rationale": replacement.get("rationale") or reason}
            if isinstance(replacement, dict)
            else None
        )
        audit.append(
            {
                "index": index,
                "removed": replacement is None,
                "reason": reason,
                "evidence_refs": refs,
                "evidence_binding": binding,
            }
        )
    return {
        "contracts": [edits.get(i, c) for i, c in enumerate(before) if edits.get(i, c) is not None]
        + additions,
        "reason": str(result.get("reason") or previous.get("reason") or ""),
        "review_edits": audit,
    }


def compact_evidence_ids(public: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Short request-local references; full native identities stay in the audit.

    Rewrite only schema identity fields, never source, expressions or names.
    These aliases supply no authority: responses are expanded before the normal
    exact-instance/evidence checks. A different request gets a separate map.
    """
    aliases = {n["id"]: f"n{i}" for i, n in enumerate(public["nodes"])}
    aliases.update({rid: f"r:{i}" for i, rid in enumerate(public["roots"])})
    result = deepcopy(dict(public))
    if "id" in result:
        result["id"] = aliases[result["id"]]
    for target in result["targets"]:
        target["id"] = aliases[target["id"]]
        target["evidence_refs"] = [aliases[ref] for ref in target["evidence_refs"]]
    for node in result["nodes"]:
        node["id"] = aliases[node["id"]]
        node["root_ids"] = [aliases[ref] for ref in node["root_ids"]]
    result["roots"] = {aliases[key]: value for key, value in result["roots"].items()}
    return result, {value: key for key, value in aliases.items()}


def map_proposal_refs(value: Mapping[str, Any], mapping: Mapping[str, str]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    if "id" in result:
        result["id"] = (
            mapping.get(result["id"], result["id"])
            if isinstance(result["id"], str)
            else result["id"]
        )
    if isinstance(result.get("evidence_refs"), list):
        result["evidence_refs"] = [
            mapping.get(ref, ref) if isinstance(ref, str) else ref
            for ref in result["evidence_refs"]
        ]
    for key in ("results", "contracts", "changes", "add"):
        if isinstance(result.get(key), list):
            result[key] = [
                map_proposal_refs(v, mapping) if isinstance(v, Mapping) else v for v in result[key]
            ]
    if isinstance(result.get("contract"), Mapping):
        result["contract"] = map_proposal_refs(result["contract"], mapping)
    return result
