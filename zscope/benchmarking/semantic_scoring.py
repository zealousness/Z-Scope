"""Host-only comparison with the independently source-reviewed scan YAML."""

from copy import deepcopy
import re
from typing import Any, Mapping

from ..config.project_semantics import canonical_digest, validate_project_semantics
from ..semantics.contracts import code_tokens
from .semantics import COLLECTIONS, proposition


def _normal(value: Any) -> Any:
    """Only mechanical equivalences; do not guess predicate implication."""
    if isinstance(value, list):
        return [_normal(item) for item in value]
    if not isinstance(value, Mapping):
        return value
    result = {key: _normal(item) for key, item in value.items()}
    if result.get("op") == "not":
        item = result.get("item", {})
        if item.get("op") == "compare":
            inverse = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}
            return {**item, "operator": inverse[item["operator"]]}
        if item.get("op") == "not":
            return item["item"]
        if item.get("op") in {"all", "any"}:
            return _normal(
                {
                    "op": "any" if item["op"] == "all" else "all",
                    "items": [{"op": "not", "item": x} for x in item["items"]],
                }
            )
        if item.get("op") in {"true", "false"}:
            return {"op": "false" if item["op"] == "true" else "true"}
    # ObjectBinding accepts both spellings, with argument_index taking
    # precedence. This is an executable-schema alias, not an inferred proof.
    if result.get("kind") in {"argument", "output_argument"} and "argument_index" in result:
        result["index"] = result.pop("argument_index")
    if result.get("op") in {"all", "any"}:
        op = result["op"]
        identity, absorbing = ("true", "false") if op == "all" else ("false", "true")
        items: list[dict[str, Any]] = []
        for item in result.get("items", []):
            items.extend(item["items"] if item.get("op") == op else [item])
        if {"op": absorbing} in items:
            return {"op": absorbing}
        items = [item for item in items if item != {"op": identity}]
        by_key = {canonical_digest(item): item for item in items}
        items = [by_key[key] for key in sorted(by_key)]
        return (
            {"op": identity}
            if not items
            else items[0] if len(items) == 1 else {"op": op, "items": items}
        )
    return result


def _unsigned_arguments(signature: str) -> set[int]:
    """Only explicit scalar C unsigned types in an unambiguous prototype.

    Never guess typedefs, fields, pointers, callbacks or platform char signedness.
    The signature remains part of the strict assertion identity.
    """
    match = re.fullmatch(r"[^()]+\(([^()]*)\)", signature)
    if not match:
        return set()
    result = set()
    allowed = {"unsigned", "int", "short", "long", "char", "const", "volatile", "restrict"}
    for index, parameter in enumerate(match[1].split(",")):
        tokens = parameter.split()
        if "unsigned" in tokens and set(tokens) <= allowed:
            result.add(index)
    return result


def _unsigned_zero_conditions(value: Any, unsigned: set[int]) -> Any:
    """Exact zero-bound equivalences; no data-dependent predicate implication."""
    if isinstance(value, list):
        return [_unsigned_zero_conditions(x, unsigned) for x in value]
    if not isinstance(value, Mapping):
        return value
    row = {k: _unsigned_zero_conditions(v, unsigned) for k, v in value.items()}
    if row.get("op") != "compare":
        return row
    left, right = row.get("left", {}), row.get("right", {})
    if (
        left.get("kind") == "argument"
        and left.get("argument_index", left.get("index")) in unsigned
        and not left.get("member_path")
        and right.get("kind") == "literal"
        and type(right.get("value")) is int
        and right["value"] == 0
    ):
        if row.get("operator") == "<":
            return {"op": "false"}
        if row.get("operator") == ">=":
            return {"op": "true"}
        if row.get("operator") in {"<=", ">"}:
            row["operator"] = {"<=": "==", ">": "!="}[row["operator"]]
    return row


def _selector(row: Mapping[str, Any]) -> dict[str, Any]:
    selector = dict(proposition("interfaces", row)["selector"])
    selector["signature"] = " ".join(code_tokens(selector["signature"]))
    if selector["kind"] == "macro":
        # Native macro USR + source file identifies the definition. The
        # product binder deliberately does not compare display signatures.
        selector["signature"] = ""
    return selector


def _entity(selector: Mapping[str, Any]) -> str:
    # A wrong USR/signature of a known C interface is a mismatch, not a new API.
    return canonical_digest({key: selector.get(key) for key in ("kind", "file", "name")})


def _pair(value: str, document: Mapping[str, Any]) -> Any:
    if value.startswith("builtin:"):
        return value
    for row in document.get("interfaces", []):
        if row.get("id") == value:
            return _selector(row)
    return {"unresolved_pair": value}


def _assertions(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for collection in COLLECTIONS:
        for row in document.get(collection, []):
            if collection != "interfaces":
                value = proposition(collection, row)
                result.append(
                    {
                        "collection": collection,
                        "row": row,
                        "value": value,
                        "entity": canonical_digest(value),
                    }
                )
                continue
            selector = _selector(row)
            unsigned = _unsigned_arguments(selector["signature"])
            for effect in row.get("effects", []) or [{}]:
                carrier = {
                    "phase": "post",
                    "dereference": 0,
                    "members": [],
                    **effect.get("carrier", {}),
                }
                protocol = {
                    key: value
                    for key, value in (effect.get("protocol") or {}).items()
                    if key not in {"version", "compiler_version"}
                }
                cases = [
                    # Normalize negation before zero bounds, then simplify the
                    # resulting boolean tree once more.
                    _normal(_unsigned_zero_conditions(_normal(case), unsigned))
                    for case in row.get("cases", [])
                    if case.get("when") != {"op": "false"}
                ]
                value = {
                    "selector": selector,
                    "role": effect.get("role"),
                    "domain": effect.get("domain"),
                    "carrier": carrier,
                    "strength": effect.get("strength", "must_under_guard"),
                    "resource_family": effect.get("resource_family", ""),
                    "preconditions": _normal(effect.get("preconditions") or {"op": "true"}),
                    "protocol": _normal(protocol),
                    "cases": sorted(cases, key=canonical_digest),
                    "otherwise": row.get("otherwise"),
                    "pairs": sorted(
                        (_pair(pair, document) for pair in row.get("pairs", [])),
                        key=canonical_digest,
                    ),
                }
                result.append(
                    {
                        "collection": collection,
                        "row": row,
                        "value": value,
                        "entity": _entity(selector),
                    }
                )
    return result


def _confirmation_errors(
    document: Mapping[str, Any],
) -> tuple[dict[tuple[str, str], str], str | None]:
    errors = {}
    all_confirmed = deepcopy(dict(document))
    for collection in COLLECTIONS:
        for row in all_confirmed.get(collection, []):
            row["status"] = "confirmed"
    try:
        validate_project_semantics(all_confirmed)
        document_error = None
    except (ValueError, TypeError, KeyError) as exc:
        document_error = str(exc)
    # Keep valid output measurable even when another emitted row is unusable.
    for collection in COLLECTIONS:
        for index, row in enumerate(document.get(collection, [])):
            probe = deepcopy(dict(document))
            for other in COLLECTIONS:
                for item in probe.get(other, []):
                    item["status"] = "pending"
            probe[collection][index]["status"] = "confirmed"
            try:
                validate_project_semantics(probe)
            except (ValueError, TypeError, KeyError) as exc:
                errors[(collection, row["id"])] = str(exc)
    return errors, document_error


def score_discovery(discovered: Mapping[str, Any], reference: Mapping[str, Any]) -> dict[str, Any]:
    """Score fixed source-review obligations, never a subset selected by discovery.

    Exact normalized agreement is measured separately from semantic soundness:
    non-identical contracts need review unless a source-reviewed prohibition
    proves them incorrect. Missing expected effects remain false negatives.
    """
    expected = {
        (item["collection"], canonical_digest(item["value"])): item
        for item in _assertions(reference)
        if item["row"].get("status") == "confirmed"
    }
    entities = {(item["collection"], item["entity"]) for item in expected.values()}
    negatives = (
        reference.get("discovery_receipt", {})
        .get("benchmark_review", {})
        .get("negative_contracts", [])
    )
    errors, document_error = _confirmation_errors(discovered)
    seen, found = set(), set()
    rows = []
    # A malformed duplicate must not hide a valid assertion merely by being
    # emitted first. Whole-document validity is still reported separately.
    emitted_items = sorted(
        _assertions(discovered),
        key=lambda item: (
            bool(errors.get((item["collection"], item["row"]["id"]))),
            item["row"]["id"],
        ),
    )
    for item in emitted_items:
        collection, row, value = item["collection"], item["row"], item["value"]
        key = (collection, canonical_digest(value))
        forbidden = collection == "interfaces" and any(
            _entity(negative["selector"]) == item["entity"]
            and value["role"] in negative["forbidden_roles"]
            and value["resource_family"] == negative.get("resource_family", "")
            for negative in negatives
        )
        error = errors.get((collection, row["id"]))
        if key in seen:
            outcome = "duplicate"
        elif error:
            outcome = "invalid"
        elif key in expected:
            outcome = "correct"
        elif forbidden:
            outcome = "incorrect"
        elif (collection, item["entity"]) in entities:
            outcome = "mismatch"
        else:
            outcome = "unreviewed"
        seen.add(key)
        if outcome == "correct":
            found.add(key)
        rows.append(
            {
                "collection": collection,
                "id": row["id"],
                "role": value.get("role"),
                "carrier": value.get("carrier"),
                "outcome": outcome,
                "validation_error": error,
                "llm_review": row.get("llm_review", {}),
                "reference_differences": (
                    [
                        {
                            "reference_id": candidate["row"]["id"],
                            "fields": [
                                field
                                for field in value
                                if value.get(field) != candidate["value"].get(field)
                            ],
                        }
                        for candidate in expected.values()
                        if candidate["collection"] == collection
                        and candidate["entity"] == item["entity"]
                    ]
                    if outcome == "mismatch"
                    else []
                ),
            }
        )
    counts = {
        name: sum(row["outcome"] == name for row in rows)
        for name in ("correct", "incorrect", "invalid", "mismatch", "unreviewed", "duplicate")
    }
    emitted = len(rows) - counts["duplicate"]
    unresolved = counts["mismatch"] + counts["unreviewed"]
    coverage = []
    for key, expected_item in expected.items():
        value = expected_item["value"]
        related = [
            (item, result)
            for item, result in zip(emitted_items, rows)
            if item["collection"] == expected_item["collection"]
            and item["entity"] == expected_item["entity"]
            and (
                item["value"].get("role") == value.get("role")
                # Same allocation object, different allocation subtype. This
                # only locates a disputed candidate; strict matching above
                # still requires the original role and all contract fields.
                or {item["value"].get("role"), value.get("role")} == {"allocator", "calloc"}
            )
            and {k: v for k, v in item["value"].get("carrier", {}).items() if k != "phase"}
            == {k: v for k, v in value.get("carrier", {}).items() if k != "phase"}
        ]
        status = (
            "matched"
            if key in found
            else (
                "invalid_candidate"
                if related and all(r[1]["outcome"] == "invalid" for r in related)
                else "contract_difference" if related else "absent_effect"
            )
        )
        coverage.append(
            {
                "id": expected_item["row"]["id"],
                "selector": expected_item["row"].get("selector"),
                "role": value.get("role"),
                "carrier": value.get("carrier"),
                "status": status,
                "candidate_ids": [r[1]["id"] for r in related],
            }
        )
    return {
        "schema_version": "zscope.semantic-discovery-score.v2",
        "reference_kind": "source_reviewed_scan_yaml",
        "assumption": "confirm_every_emitted_row_without_repair",
        "comparison": "normalized_effect_contracts including explicit unsigned scalar zero bounds; nonidentical predicates require independent review",
        "release_eligible": False,
        "counts": counts,
        "emitted_assertions": emitted,
        "emitted_rows": sum(len(discovered.get(key, [])) for key in COLLECTIONS),
        "expected_assertions": len(expected),
        "matched_assertions": len(found),
        "strict_precision": len(found) / emitted if emitted else None,
        "strict_recall": len(found) / len(expected) if expected else None,
        "precision_lower_bound": len(found) / emitted if emitted else None,
        "precision_upper_bound": (len(found) + unresolved) / emitted if emitted else None,
        "semantic_accuracy_complete": unresolved == 0,
        "all_confirm_document_valid": document_error is None,
        "all_confirm_document_error": document_error,
        "missing": [
            {
                "id": item["row"]["id"],
                "collection": item["collection"],
                "role": item["value"].get("role"),
                "carrier": item["value"].get("carrier"),
            }
            for key, item in expected.items()
            if key not in found
        ],
        "reference_coverage": coverage,
        "reference_coverage_counts": {
            status: sum(item["status"] == status for item in coverage)
            for status in ("matched", "invalid_candidate", "contract_difference", "absent_effect")
        },
        "scope": reference.get("discovery_receipt", {})
        .get("benchmark_review", {})
        .get("scope", {}),
        "rows": rows,
        "discovery_llm": discovered.get("discovery_receipt", {}).get("llm", {}),
    }
