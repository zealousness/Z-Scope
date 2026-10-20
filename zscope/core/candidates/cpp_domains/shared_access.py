"""Name-independent shared-access leads; concurrency must be proved separately."""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, defaultdict
import re
from typing import Any, Mapping, Sequence


class SharedAccessIndex:
    """Build declarations, accesses and lexical lock prefixes once per function.

    This is a candidate filter, not a happens-before or path-feasibility proof.
    An instance belongs to one detector invocation, so changing the function or
    compiler facts cannot reuse an earlier invocation's synchronization state.
    """

    def __init__(
        self,
        lines: Sequence[Any],
        facts: Mapping[str, Any],
        lock_names: set[str],
        unlock_names: set[str],
        contracts: Any = None,
        *,
        restrict_to_semantics: bool = False,
    ) -> None:
        self.restrict_to_semantics = restrict_to_semantics
        self.complete = bool(facts.get("complete"))
        self.accesses: dict[int, set[str]] = defaultdict(set)
        for row in facts.get("accesses", []):
            if row.get("atomic") or row.get("const") or row.get("storage_class") == "thread_local":
                continue
            name = str((row.get("target") or {}).get("name") or "")
            if name:
                number = int((row.get("location") or {}).get("line") or 0)
                self.accesses[number].add(name)
        self.declarations: set[str] = set()
        if not self.complete:
            source = "\n".join(item.text for item in lines)
            self.declarations = set(
                re.findall(
                    r"\b(?:const\s+|static\s+|thread_local\s+|_Thread_local\s+)?"
                    r"(?:unsigned\s+|signed\s+|struct\s+)?[A-Za-z_]\w*(?:\s*<[^;{}]+>)?\s+[&*\s]*"
                    r"([A-Za-z_]\w*)\s*(?=[=;,)\[])",
                    source,
                )
            )
        self.lock_prefixes: dict[int, tuple[bool, list[int], list[bool]]] = {}
        if contracts is None:
            from ....semantics.defaults import default_local_pattern_semantics

            contracts = default_local_pattern_semantics().contracts
        interrupts = {
            c.symbol.name
            for c in contracts.contracts
            if c.role in {"lock_wait", "lock_init", "lock_destroy", "lock_state"}
        }
        names = "|".join(re.escape(n) for n in sorted(lock_names | unlock_names | interrupts))
        lock_call = re.compile(rf"\b({names or '__no_lock__'})\s*\(([^)]*)\)")
        held: Counter[tuple[str, str]] = Counter()
        count = 0
        for line in lines:
            before = bool(count)
            offsets, guarded = [], []
            for call in lock_call.finditer(line.text):
                role = "unlock" if call[1] in unlock_names else "lock"
                matches = contracts.match_call(call[1], role, call[2].split(","))
                if (
                    call[1] in interrupts
                    or not matches
                    or any(m.applicability == "unknown" for m in matches)
                ):
                    # Unknown releases and interrupted ownership cannot leave
                    # a stale prefix that hides a later access candidate.
                    held.clear()
                    count = 0
                    offsets.append(call.end())
                    guarded.append(False)
                    continue
                lock = next(
                    (
                        m.object
                        for m in matches
                        if m.applicability == "applies"
                        and (role == "unlock" or m.lock_mode == "exclusive")
                    ),
                    "",
                )
                if not lock:
                    continue
                if call[1] in unlock_names:
                    key = next(
                        (
                            key
                            for key in held
                            if held[key]
                            and key[1] == lock
                            and contracts.release_in_text(key[0], call[1], line.text, lock)
                            == "applies"
                        ),
                        None,
                    )
                    if key is not None:
                        held[key] -= 1
                        count -= 1
                else:
                    held[(call[1], lock)] += 1
                    count += 1
                offsets.append(call.end())
                guarded.append(bool(count))
            self.lock_prefixes[line.index] = before, offsets, guarded

    def _visibly_guarded(self, line: Any, match: Any) -> bool:
        before, offsets, states = self.lock_prefixes[line.index]
        position = bisect_right(offsets, match.start()) - 1
        return states[position] if position >= 0 else before

    def match(self, line: Any) -> Any:
        # A name-level standard_operation contract does not prove that this
        # particular access is atomic. Exact instances use the current native
        # access facts collected above; an atomic-looking call/type spelling
        # cannot suppress an unrelated write on the same line.
        if not self.restrict_to_semantics and re.search(
            r"\batomic\w*\s*\(|\bstd::atomic\b", line.text
        ):
            return None
        if self.complete:
            names = self.accesses.get(line.number, set())
            for match in re.finditer(r"\b(?P<global>[A-Za-z_]\w*)\b", line.text):
                if match["global"] in names and not self._visibly_guarded(line, match):
                    return match
            return None

        # Unresolved non-local accesses are hypotheses. Exclude declarations
        # and parameters by syntax, never by an identifier's spelling.
        if not re.search(r"\+\+|--|\b(?:if|while)\s*\(|(?<![=!<>])=(?!=)", line.text):
            return None
        for match in re.finditer(r"\b(?P<global>[A-Za-z_]\w*)\b", line.text):
            name = match["global"]
            if name in self.declarations or name in _KEYWORDS:
                continue
            tail = line.text[match.end() :]
            if re.match(r"\s*(?:\(|::|\*\s*\w)", tail):
                continue
            if re.match(r"\s+[A-Za-z_]\w*", tail):
                continue
            if re.search(r"(?:->|\.)\s*$", line.text[: match.start()]):
                continue
            if not self._visibly_guarded(line, match):
                return match
        return None


_KEYWORDS = {"return", "if", "while", "for", "else", "sizeof", "NULL", "nullptr", "true", "false"}
