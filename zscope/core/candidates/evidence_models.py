"""Generic structured evidence shared by discovery and validation."""

from __future__ import annotations

from typing import Any, Dict, Mapping


def _mapping(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _present(**values: Any) -> Dict[str, Any]:
    return {
        key: value
        for key, value in values.items()
        if value not in (None, "", [], {})
    }


def build_evidence_models(issue: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Normalize only explicit facts; absence remains unknown, never safe."""
    pack = _mapping(issue.get("evidence_pack"))
    path = _mapping(pack.get("path"))
    value = _mapping(pack.get("value_flow") or pack.get("value_range"))
    ownership = _mapping(pack.get("ownership") or pack.get("resource_typestate"))
    concurrency = _mapping(pack.get("concurrency"))
    contract = _mapping(pack.get("contract") or pack.get("cross_procedure_contract"))

    models = {
        "value_flow": _present(
            source=issue.get("source") or pack.get("source"),
            sink=issue.get("sink") or pack.get("sink"),
            ranges=value.get("ranges") or pack.get("ranges"),
            length_constraints=value.get("length_constraints")
            or pack.get("length_constraints"),
            integer_constraints=value.get("integer_constraints")
            or pack.get("integer_constraints"),
            overflow_checks=value.get("overflow_checks") or pack.get("overflow_checks"),
            sanitizers=value.get("sanitizers") or pack.get("sanitizers"),
            path_constraints=issue.get("path_constraints")
            or path.get("constraints")
            or pack.get("path_constraints"),
        ),
        "ownership_typestate": _present(
            resource=issue.get("resource_signature")
            or issue.get("resource")
            or pack.get("resource_signature")
            or pack.get("resource"),
            owner=ownership.get("owner") or issue.get("owner_object"),
            aliases=ownership.get("aliases"),
            transitions=ownership.get("transitions"),
            reference_count=ownership.get("reference_count")
            or pack.get("reference_count"),
            transfer=ownership.get("transfer") or pack.get("ownership_transfer"),
            cleanup_paths=ownership.get("cleanup_paths") or pack.get("cleanup_paths"),
        ),
        "concurrency": _present(
            object=issue.get("thread_object")
            or concurrency.get("object")
            or pack.get("thread_object"),
            lockset=concurrency.get("lockset") or pack.get("lockset"),
            happens_before=concurrency.get("happens_before")
            or pack.get("happens_before"),
            check_then_act=concurrency.get("check_then_act")
            or pack.get("check_then_act"),
            toctou=concurrency.get("toctou") or pack.get("toctou"),
            async_lifecycle=concurrency.get("async_lifecycle")
            or pack.get("async_lifecycle"),
        ),
        "cross_procedure_contract": _present(
            entry_function=issue.get("entry_function") or pack.get("entry_function"),
            call_path=issue.get("call_path")
            or issue.get("call_paths")
            or pack.get("call_path"),
            preconditions=contract.get("preconditions") or pack.get("preconditions"),
            postconditions=contract.get("postconditions") or pack.get("postconditions"),
            error_paths=contract.get("error_paths") or pack.get("error_paths"),
            cleanup_responsibility=contract.get("cleanup_responsibility")
            or pack.get("cleanup_responsibility"),
            caller_responsibility=contract.get("caller_responsibility")
            or pack.get("caller_responsibility"),
            complete_to_entry=path.get("complete_to_entry"),
        ),
    }
    return {name: facts for name, facts in models.items() if facts}
