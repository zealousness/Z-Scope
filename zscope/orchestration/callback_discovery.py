"""Source-backed callback registration roots; these are reachability hints, not proofs."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from ..semantics.contract_compiler import (
    closing,
    parameter_names,
    read_source_facts,
    split_tokens,
    unparen,
)
from ..semantics.contracts import code_tokens
from ..semantics.defaults import default_local_pattern_semantics


@dataclass(frozen=True)
class CallbackSlot:
    argument: int
    members: tuple[str, ...] = ()
    context: str = "signal"


# Standard registration protocols only. Project wrappers are derived below.
# sigaction's second argument is the NEW action; its third is an output query.
CALLBACK_REGISTRATIONS = {
    "signal": (CallbackSlot(1),),
    "sigaction": (CallbackSlot(1, ("sa_handler",)), CallbackSlot(1, ("sa_sigaction",))),
    "atexit": (CallbackSlot(0, context="exit"),),
    "at_quick_exit": (CallbackSlot(0, context="exit"),),
    "on_exit": (CallbackSlot(0, context="exit"),),
}
NON_CALLBACK_VALUES = {"NULL", "nullptr", "SIG_DFL", "SIG_IGN", "SIG_ERR"}


def _strip_reference(words: list[str]) -> list[str]:
    words = unparen(words)
    while words:
        if words[0] == "&":
            words = unparen(words[1:])
        elif words[0] == "(":
            end = closing(words, 0)
            cast = words[1:end]
            if (
                not cast
                or end == len(words) - 1
                or any(not (re.fullmatch(r"[A-Za-z_]\w*", t) or t in {"*", "(", ")"}) for t in cast)
            ):
                break
            words = unparen(words[end + 1 :])
        else:
            break
    return words


def _path(words: list[str]) -> str:
    text = "".join(_strip_reference(words)).replace("->", ".")
    return text if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", text) else ""


@dataclass
class RegistrationCall:
    name: str
    arguments: list[str]
    parameters: list[str]
    assignments: dict[str, str]
    locals: set[str]
    complete: bool
    line: int = 0

    def value(self, expression: str, members: tuple[str, ...] = ()) -> str:
        """Resolve a frozen local binding, never a guessed function-pointer target."""
        path = _path(code_tokens(expression))
        if not path or path in NON_CALLBACK_VALUES:
            return ""
        if members:
            path += "." + ".".join(members)
        seen: set[str] = set()
        while path and path not in seen:
            seen.add(path)
            parts = path.split(".")
            if any(
                self.assignments.get(".".join(parts[:length])) == "<address_escaped>"
                for length in range(1, len(parts) + 1)
            ):
                return ""
            # The two handler names can share storage. Respect a known flag;
            # unknown flags retain possible roots without claiming registration success.
            if parts[-1] in {"sa_handler", "sa_sigaction"}:
                flags = self.assignments.get(".".join(parts[:-1] + ["sa_flags"]), "")
                flag_words = code_tokens(flags)
                if flags == "0" and parts[-1] == "sa_sigaction":
                    return ""
                if "SA_SIGINFO" in flag_words and all(
                    word in {"|", "(", ")"} or re.fullmatch(r"[A-Za-z_]\w*|\d+", word)
                    for word in flag_words
                ):
                    if parts[-1] == "sa_handler":
                        return ""
            replaced = False
            for length in range(len(parts), 0, -1):
                prefix = ".".join(parts[:length])
                if prefix not in self.assignments:
                    continue
                replacement = _path(code_tokens(self.assignments[prefix]))
                if not replacement or replacement in NON_CALLBACK_VALUES:
                    return ""
                path = ".".join([replacement, *parts[length:]])
                replaced = True
                break
            if replaced:
                continue
            if parts[0] in self.parameters:
                return path if self.complete else ""
            if parts[0] in self.locals:
                return ""
            return path
        return ""


def _assignments(values: dict[str, str], prefix: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    normalized = ["." if token == "->" else token for token in prefix]

    def last_assignment(name: str) -> int:
        pattern = code_tokens(name.replace("->", ".")) + ["="]
        return max(
            (i for i in range(len(normalized)) if normalized[i : i + len(pattern)] == pattern),
            default=-1,
        )

    for name, expression in sorted(values.items(), key=lambda item: last_assignment(item[0])):
        name = name.replace("->", ".")
        words = code_tokens(expression)
        if words[:1] == ["{"] and words[-1:] == ["}"]:
            # Designated initializers; positional struct layout is not inferred.
            for group in split_tokens(words[1:-1]):
                pair = split_tokens(group, "=")
                if len(pair) == 2 and pair[0][:1] == ["."]:
                    member = _path(pair[0][1:])
                    if member:
                        result[name + "." + member] = "".join(pair[1])
            continue
        result[name] = expression
        if name.endswith(".sa_handler"):
            result[name.rsplit(".", 1)[0] + ".sa_sigaction"] = "<overwritten>"
        elif name.endswith(".sa_sigaction"):
            result[name.rsplit(".", 1)[0] + ".sa_handler"] = "<overwritten>"
    return result


def _calls(
    name: str, implementation: dict[str, Any], interesting: set[str]
) -> list[RegistrationCall]:
    from ..semantics.contracts import _CODE_TOKEN_PATTERN

    code = str(implementation.get("code") or "")
    plain = re.sub(r"(?m)^\s*\d+\s*\| ?", "", code)
    words = code_tokens(code)
    spans = [m for m in re.finditer(_CODE_TOKEN_PATTERN, plain)
             if not m[0].startswith(("//", "/*"))]
    spans_match = [m[0] for m in spans] == words
    numbered = [re.match(r"\s*(\d+)\s*\|", line) for line in code.splitlines()]
    start = next((i + 1 for i, t in enumerate(words[:-1]) if t == name and words[i + 1] == "("), -1)
    if start < 0:
        return []
    begin = closing(words, start) + 1
    context = {**implementation, "func_name": name}
    parameters = parameter_names(context)
    registry = default_local_pattern_semantics().contracts
    result = []
    for i in range(begin, len(words) - 1):
        if words[i + 1] != "(" or words[i] not in interesting:
            continue
        if words[i] in {"if", "for", "while", "switch", "sizeof", "return", "alignof"}:
            continue
        if i and words[i - 1] in {".", "->"}:
            continue
        if i > 1 and words[i - 1] == "::" and words[i - 2] != "std":
            continue
        end = closing(words, i + 1)
        prefix = words[:i]
        # Freeze assignments BEFORE this registration (including struct fields).
        # A direct symbol can still be discovered past unsupported control flow;
        # aliases/forwarded parameters cannot claim facts that were not parsed.
        depth = prefix.count("{") - prefix.count("}")
        facts = read_source_facts(
            {**context, "code": " ".join(prefix + [";"] + ["}"] * depth)}, registry
        )
        source_line = plain[:spans[i].start()].count("\n") if spans_match else 0
        line_match = numbered[source_line] if spans_match else None
        registration_line = (int(line_match[1]) if line_match else int(implementation.get("start_line") or 1) + source_line) if spans_match else 0
        result.append(
            RegistrationCall(
                words[i],
                ["".join(g) for g in split_tokens(words[i + 2 : end])],
                parameters,
                _assignments(facts.assignments, prefix) if facts.complete else {},
                facts.local_variables,
                facts.complete,
                registration_line,
            )
        )
    return result


def registered_callback_targets(
    implementations: list[tuple[str, dict[str, Any]]],
    *, edges: list[dict[str, Any]] | None = None,
) -> list[list[tuple[str, str, str]]]:
    """Return (target, registration call, context) per caller, including wrappers."""
    names = [str(impl.get("func_name") or name) for name, impl in implementations]
    files = [str(impl.get("file") or "") for _, impl in implementations]
    by_name: dict[str, list[int]] = {}
    for i, name in enumerate(names):
        by_name.setdefault(name, []).append(i)
    # Parse bindings only in the source closure that can reach a registrar.
    # This avoids repeatedly parsing prefixes of unrelated large functions.
    dependencies = []
    for _, impl in implementations:
        words = code_tokens(str(impl.get("code") or ""))
        dependencies.append({words[i] for i in range(len(words) - 1) if words[i + 1] == "("})
    interesting = set(CALLBACK_REGISTRATIONS)
    while True:
        expanded = interesting | {
            name for name, deps in zip(names, dependencies) if deps & interesting
        }
        if expanded == interesting:
            break
        interesting = expanded
    calls = [_calls(name, impl, interesting) for name, (_, impl) in zip(names, implementations)]
    derived: list[set[CallbackSlot]] = [set() for _ in implementations]

    def slots(caller: int, call: RegistrationCall) -> tuple[CallbackSlot, ...]:
        if call.name in call.parameters or call.name in call.locals:
            return ()
        choices = by_name.get(call.name, [])
        if choices:
            local = [i for i in choices if files[i] == files[caller]]
            visible = local or choices
            return tuple(derived[visible[0]]) if len(visible) == 1 else ()
        return CALLBACK_REGISTRATIONS.get(call.name, ())

    changed = True
    while changed:
        changed = False
        for i, sites in enumerate(calls):
            for call in sites:
                for slot in slots(i, call):
                    if slot.argument >= len(call.arguments):
                        continue
                    value = call.value(call.arguments[slot.argument], slot.members)
                    parts = value.split(".")
                    if parts[0] not in call.parameters:
                        continue
                    # A recursive member traversal has an unbounded path set.
                    # Do not manufacture ever-longer wrapper summaries.
                    if len(parts) - 1 > len(slot.members):
                        visited = {call.name}
                        pending = [call.name]
                        while pending:
                            current = pending.pop()
                            for target in by_name.get(current, []):
                                for dependency in dependencies[target] - visited:
                                    visited.add(dependency)
                                    pending.append(dependency)
                        if names[i] in visited:
                            continue
                    forwarded = CallbackSlot(
                        call.parameters.index(parts[0]), tuple(parts[1:]), slot.context
                    )
                    if forwarded not in derived[i]:
                        derived[i].add(forwarded)
                        changed = True

    result: list[list[tuple[str, str, str]]] = []
    for i, sites in enumerate(calls):
        targets = set()
        for call in sites:
            for slot in slots(i, call):
                if slot.argument >= len(call.arguments):
                    continue
                value = call.value(call.arguments[slot.argument], slot.members)
                if value and "." not in value and value not in call.parameters:
                    targets.add((value, call.name, slot.context))
                    if edges is not None:
                        edges.append({"caller_name": names[i], "caller_file": files[i],
                            "callee_name": value, "registrar": call.name, "call_line": call.line,
                            "context": slot.context, "call_type": "callback_registration",
                            "execution": "asynchronous", "source": "callback_registration",
                            "registration_success": "unknown", "proof_authority": False})
        result.append(sorted(targets))
    return result
