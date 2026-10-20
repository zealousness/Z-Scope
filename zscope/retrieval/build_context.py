"""Content-bound compilation instances; a CDB is not a link manifest.

The command identity names an invocation. The build identity additionally binds
the compiler, source/dependency contents and observed target facts. Neither a
shared source path nor a shared USR makes two instances interchangeable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from pathlib import Path

from .indexing_identity import (
    command_identity,
    dependencies_current,
    digest_json,
    search_directories_current,
    InputValidator,
    include_probes_current,
)


@dataclass(frozen=True)
class BuildContext:
    context_id: str
    command_id: str
    source: str
    manifest_json: str

    @classmethod
    def create(
        cls,
        command: Mapping[str, Any],
        *,
        tool: Mapping[str, Any],
        dependencies: Mapping[str, str],
        dependencies_complete: bool,
        target: Mapping[str, Any] | None = None,
        link_target: Mapping[str, Any] | None = None,
        include_probes: Mapping[str, Any] | None = None,
        include_lookups: Mapping[str, Any] | None = None,
    ) -> "BuildContext":
        import json

        manifest = {
            "schema": "zscope.build-context.v1",
            "command": dict(command),
            "tool": dict(tool),
            "dependencies": dict(dependencies),
            "dependencies_complete": bool(dependencies_complete),
            "target": dict(target or {}),
            # Unknown must not collapse into an invented whole-project target.
            "link_target": dict(link_target) if link_target else None,
        }
        if include_probes is not None:
            manifest["include_probes"] = dict(include_probes)
        if include_lookups is not None:
            # Independent ordinary lookup evidence. Unknown modes constrain
            # only the live output view; they do not weaken legacy extraction.
            manifest["include_lookups"] = dict(include_lookups)
        return cls(
            digest_json(manifest),
            digest_json(command),
            str(command["source"]),
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        )

    def to_dict(self) -> dict[str, Any]:
        import json

        return {
            "build_context_id": self.context_id,
            "command_id": self.command_id,
            "source": self.source,
            **json.loads(self.manifest_json),
        }


def program_facts_result(
    values: list[dict[str, Any]], *, context: dict[str, Any] | None = None
) -> dict[str, Any]:
    bodies = [row for row in values if row.get("kind") == "program_function"]
    accesses = [row for row in values if row.get("kind") == "program_access"]
    result = {
        "complete": len(bodies) == 1 and bool(bodies[0].get("complete")),
        "fact_version": bodies[0].get("fact_version") if len(bodies) == 1 else None,
        "functions": bodies,
        "accesses": accesses,
        "events": [event for body in bodies for event in body.get("events", [])],
    }
    if context is not None:
        result["build_context"] = context
        result["build_context_id"] = context["build_context_id"]
        result["complete"] = bool(result["complete"] and context["dependencies_complete"])
        # A manifest field alone is not verified link membership. Exact linked
        # resolution validates observed artifacts through LinkedTargets.
        result["cross_tu_complete"] = False
    if len(bodies) > 1:
        # A build can contain overloads or identically named namespace members.
        # Their event/CFG namespaces cannot be combined into one proof body.
        result.update(
            complete=False,
            reason="ambiguous_function_identity",
            function_choices=[dict(body.get("owner") or {}) for body in bodies],
            functions=[],
            events=[],
            accesses=[],
        )
    elif context is not None:
        if not bodies:
            result["reason"] = "function_identity_not_found"
        else:
            usr = str((bodies[0].get("owner") or {}).get("usr") or "")
            if usr:
                identity = {"build_context_id": context["build_context_id"], "usr": usr}
                result["function_identity"] = {**identity, "key": digest_json(identity)}
    return result


def context_input_status(
    context: Mapping[str, Any], *, validator: InputValidator | None = None
) -> str:
    """Validate a persisted receipt before using it in an interactive query.

    This does not run a compiler, model or rebuild. Missing inputs stay unknown;
    source/response/environment edits cannot revive old facts as current proof.
    """
    if not context.get("dependencies_complete") or context.get("status") != "indexed":
        return "incomplete_compilation_instance"
    dependencies = validator.dependencies if validator else dependencies_current
    if not dependencies(context.get("dependencies")):
        return "stale_build_dependencies"
    database = context.get("compilation_database", {})
    if not database.get("path") or not dependencies({database["path"]: database.get("sha256")}):
        return "stale_compilation_database"
    command = context.get("command", {})
    try:
        observed = command_identity(
            {
                "file": command["source"],
                "directory": command["directory"],
                "arguments": command["arguments"],
            },
            Path(command["directory"]),
        )
    except (KeyError, OSError, ValueError):
        return "unverifiable_build_command"
    if digest_json(observed) != context.get("command_id"):
        return "stale_build_command"
    searches_current = (
        validator.searches(context.get("search_directories"))
        if validator
        else search_directories_current(
            context.get("search_directories"),
            exclude_paths=(Path(path) for path in context.get("search_excludes", [])),
        )
    )
    if not searches_current:
        return "stale_include_search"
    if not include_probes_current(context.get("include_probes")):
        return "stale_include_probe"
    return "current"


def _context_carries_receipt(context: Mapping[str, Any]) -> bool:
    """True when a stored context still holds the receipts currency needs.

    ``status: indexed`` alone is a claim about the extraction, not about the
    inputs: only a context with a command digest and a dependency snapshot can
    be re-verified. A receipt-less summary stays ``unmeasured`` instead of being
    promoted to a current instance.
    """

    return bool(context.get("command_id")) and isinstance(context.get("dependencies"), dict)


def scan_build_coverage(code_index: Any) -> dict[str, Any]:
    """Describe stored coverage without promoting navigation to scan coverage.

    A scoped instance facade pins ``get_build_contexts`` to its own instance on
    purpose (instance semantics require exactly one current context), so a
    coverage consumer that asks the facade directly would report one instance
    and hide its siblings. Resolve the unwrapped index for the counts and label
    the result, keeping the pinned identity so a per-entry view is never read
    as scan coverage.

    """

    resolver = getattr(code_index, "coverage_index", None)
    base_index = resolver() if callable(resolver) else None
    view = "scan"
    pinned = ""
    if base_index is not None and base_index is not code_index:
        view = "instance"
        pinned = str(getattr(code_index, "pinned_build_context_id", "") or "")
        source_index = base_index
    else:
        source_index = code_index
    getter = getattr(source_index, "get_build_contexts", None)
    contexts = getter() if callable(getter) else []
    if not isinstance(contexts, list) or not contexts:
        return {"status": "unavailable", "reasons": ["compilation_instances_unavailable"]}
    if view == "instance":
        # One entry's view covers every stored instance of that entry's source,
        # not unrelated files that happen to share the index.
        source = next(
            (
                str(context.get("source") or "")
                for context in contexts
                if str(context.get("build_context_id") or "") == pinned
            ),
            "",
        )
        if source:
            contexts = [
                context for context in contexts if str(context.get("source") or "") == source
            ]
            if not contexts:
                return {
                    "status": "unavailable",
                    "reasons": ["compilation_instances_unavailable"],
                    "view": view,
                    "pinned_build_context_id": pinned,
                }
    sources: dict[str, int] = {}
    failed = []
    uncurrent: list[str] = []
    input_status: dict[str, str] = {}
    # One validator per coverage pass: parallel instances usually share the same
    # headers, so each content digest is computed once.
    validator = InputValidator()
    for context in contexts:
        source = str(context.get("source") or "")
        sources[source] = sources.get(source, 0) + 1
        build = str(context.get("build_context_id") or "")
        if context.get("status") != "indexed" or not context.get("dependencies_complete"):
            failed.append(build)
            continue
        if not _context_carries_receipt(context):
            input_status[build] = "unmeasured"
            continue
        currency = context_input_status(context, validator=validator)
        input_status[build] = currency
        if currency != "current":
            uncurrent.append(build)
    variants = {source: count for source, count in sources.items() if count > 1}
    reasons = []
    if failed:
        reasons.append("incomplete_compilation_instances")
    if uncurrent:
        reasons.append("stale_compilation_instance_inputs")
    if variants:
        reasons.append("scan_consumers_use_navigation_projection")
    factory = getattr(source_index, "linked_targets", None)
    linked = factory() if callable(factory) else None
    covered = (
        {build for target in linked.targets for build in target["members"]} if linked else set()
    )
    if any(context["build_context_id"] not in covered for context in contexts):
        reasons.append("link_targets_unverified")
    coverage = {
        "status": "partial" if reasons else "indexed",
        "instances": len(contexts),
        "sources": len(sources),
        "variant_sources": variants,
        "failed_instances": failed,
        "uncurrent_instances": uncurrent,
        "instance_input_status": input_status,
        "extraction_complete": not failed,
        "scan_complete": False,
        "reasons": reasons,
        "view": view,
        "observed_link_targets": (
            [t["receipt"]["target_id"] for t in linked.targets] if linked else []
        ),
        "link_diagnostics": linked.diagnostics if linked else [],
    }
    if view == "instance":
        coverage["pinned_build_context_id"] = pinned
    return coverage
