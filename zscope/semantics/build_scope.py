"""Compilation scope shared by contract producers and parallel consumers."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import re
from typing import Any, Iterator, Mapping

_ACTIVE_SCOPE: ContextVar[str] = ContextVar("contract_build_scope", default="")
# (name, usr) of the analysis context's own entry symbol, from its native
# owner receipt; ("", "") when the bound context states no entry identity.
_ACTIVE_SCOPE_SYMBOL: ContextVar[tuple[str, str]] = ContextVar(
    "contract_build_scope_symbol", default=("", "")
)


def context_build_id(context: Mapping[str, Any]) -> str:
    facts = context.get("program_facts") or {}
    return str(facts.get("build_context_id") or context.get("build_context_id") or "")


def context_symbol_usr(context: Mapping[str, Any]) -> str:
    """The native USR of the context's own symbol, only from verified facts.

    The USR is read from the complete program facts' identity receipt and the
    complete bodies' owners.  A receipt that names another build's identity,
    or owners that disagree (ambiguous overloads), resolve to "" — an unknown
    USR is never a first-match guess, and nothing outside the native chain
    (user YAML, workbook rows) can supply this value.
    """

    facts = context.get("program_facts") or {}
    if not isinstance(facts, Mapping) or not facts.get("complete"):
        return ""
    build = str(facts.get("build_context_id") or "")
    usrs: set[str] = set()
    identity = facts.get("function_identity")
    if isinstance(identity, Mapping):
        identity_usr = str(identity.get("usr") or "")
        if identity_usr:
            identity_build = str(identity.get("build_context_id") or "")
            if not build or not identity_build or identity_build != build:
                # A receipt from another build — or one that does not name its
                # own build — cannot supply this context's identity.
                return ""
            usrs.add(identity_usr)
    for body in facts.get("functions", []) or []:
        if not isinstance(body, Mapping) or not body.get("complete"):
            continue
        owner_usr = str((body.get("owner") or {}).get("usr") or "")
        if owner_usr:
            usrs.add(owner_usr)
    if len(usrs) == 1:
        return next(iter(usrs))
    return ""


def current_build_id() -> str:
    return _ACTIVE_SCOPE.get()


def current_scope_symbol_usr(name: str) -> str:
    """The bound analysis context's own entry USR, when it names ``name``.

    This is the identity of the function being analyzed — carried by the
    context that ``bind_build_scope`` received — never a guess about an
    unknown callee: queries for any other name resolve to "".
    """

    bound_name, usr = _ACTIVE_SCOPE_SYMBOL.get()
    if usr and name and bound_name == name:
        return usr
    return ""


def _context_entry_symbol(context: Mapping[str, Any]) -> tuple[str, str]:
    """(name, usr) of the context's entry from its native owner receipt.

    Uses the same currency and conflict rules as :func:`context_symbol_usr`:
    facts must be complete with no staleness reason, the context's own build
    id (when stated) must match the facts, the identity receipt must not
    name another build or a conflicting USR, and exactly one complete body
    must be owned by the context's function name.  Anything damaged,
    stale, conflicting, or ambiguous is ("", "") — never re-authorized by
    this helper.
    """

    name = str(context.get("func_name") or "")
    if not name:
        return "", ""
    facts = context.get("program_facts") or {}
    if not isinstance(facts, Mapping) or not facts.get("complete"):
        return "", ""
    if facts.get("reason"):
        return "", ""
    build = str(facts.get("build_context_id") or "")
    context_build = str(context.get("build_context_id") or "")
    if build and context_build and context_build != build:
        return "", ""
    usr = context_symbol_usr(context)
    if not usr:
        return "", ""
    owned = []
    for body in facts.get("functions", []) or []:
        if not isinstance(body, Mapping) or not body.get("complete"):
            continue
        owner = body.get("owner") or {}
        if owner.get("name") == name:
            owned.append(str(owner.get("usr") or ""))
    if len(owned) != 1 or owned[0] != usr:
        return "", ""
    return name, usr


def bind_candidate_build_scope(issues: list[dict[str, Any]], context: Mapping[str, Any]) -> None:
    """Carry a usable native compilation receipt into candidate consumers."""
    facts = context.get("program_facts") or {}
    scope = str(facts.get("build_context_id") or "")
    if not scope or not facts.get("complete") or source_scope_problem(context):
        return
    for issue in issues:
        issue["build_context_id"] = scope
        issue.setdefault("evidence_pack", {})["build_context_id"] = scope


@contextmanager
def bind_build_scope(context: Mapping[str, Any]) -> Iterator[None]:
    marker = _ACTIVE_SCOPE.set(context_build_id(context))
    symbol_marker = _ACTIVE_SCOPE_SYMBOL.set(_context_entry_symbol(context))
    try:
        yield
    finally:
        _ACTIVE_SCOPE_SYMBOL.reset(symbol_marker)
        _ACTIVE_SCOPE.reset(marker)


def source_scope_problem(context: Mapping[str, Any]) -> str:
    """Raw source cannot prove effects of ambiguous or unexpanded branches."""
    facts = context.get("program_facts") or {}
    if facts.get("reason"):
        return str(facts["reason"])
    if facts.get("build_contexts") and not facts.get("build_context_id"):
        return "ambiguous_build_context"
    selected = context.get("build_context_id")
    observed = facts.get("build_context_id")
    if selected and observed and selected != observed:
        return "build_context_mismatch"
    if observed and not facts.get("complete"):
        return "incomplete_compilation_instance"
    code = re.sub(r"(?m)^\s*\d+\s*\| ?", "", str(context.get("code") or ""))
    if re.search(r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b", code):
        return "unexpanded_conditional_source"
    return ""
