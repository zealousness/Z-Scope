"""Conservative lexical events with physical source coordinates.

This is a fallback, not a control-flow proof. Semicolons inside parentheses,
strings and macro bodies are never treated as statement boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any, Callable, Iterable, Sequence


@dataclass(frozen=True)
class SourceEvent:
    number: int
    column: int
    offset: int
    ordinal: int
    text: str
    raw: str
    ordered: bool = True


_TOKEN = re.compile(
    r'(?P<raw>(?:u8|u|U|L)?R"(?P<delim>[^ ()\\\t\r\n]{0,16})\([\s\S]*?\)(?P=delim)")'
    r'|(?P<string>(?:u8|u|U|L)?"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\')'
    r"|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)"
    r"|(?P<directive>^[ \t]*\#(?:[^\n]*\\\n)*[^\n]*)",
    re.MULTILINE,
)


def strip_comments_preserve_literals(code: str) -> str:
    """Remove comments without changing coordinates or string literals.

    Java rules need string contents for sink matching, while comments must never
    satisfy either a sink or a guard.  Reusing the lexer here keeps the two
    behaviours separate and preserves physical line/column coordinates.
    """

    chars = list(str(code or ""))
    for match in _TOKEN.finditer(str(code or "")):
        if match.group("comment") is None:
            continue
        for index in range(match.start(), match.end()):
            if chars[index] != "\n":
                chars[index] = " "
    return "".join(chars)


def _if_condition_and_tail(text: str) -> tuple[str, str] | None:
    match = re.search(r"\bif\s*\(", str(text or ""))
    if not match:
        return None
    opening = str(text).find("(", match.start())
    depth = 0
    for index in range(opening, len(str(text))):
        char = str(text)[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return str(text)[opening + 1 : index], str(text)[index + 1 :].strip()
    return None


def _is_terminal_statement(text: str) -> bool:
    candidate = str(text or "").lstrip("{} \t")
    return bool(
        re.match(r"(?:return|throw|goto|break|continue)\b", candidate)
        or re.match(r"(?:abort|exit|_Exit)\s*\(", candidate)
    )


def has_terminating_guard(
    lines: Sequence[Any],
    sink_index: int,
    condition_matches: Callable[[str], bool],
    *,
    lookback: int = 12,
) -> bool:
    """Return true only for a matching guard whose rejected branch terminates.

    This is deliberately a conservative source-level fallback.  It recognizes
    the common ``if (bad) return/throw`` forms but does not infer safety from a
    comparison, a log call, or a comment alone.  Native CFG evidence remains
    available to the downstream validator for more complex control flow.
    """

    begin = max(0, int(sink_index) - max(1, int(lookback)))
    end = min(len(lines), int(sink_index))
    for position in range(begin, end):
        parsed = _if_condition_and_tail(getattr(lines[position], "text", ""))
        if parsed is None:
            continue
        condition, tail = parsed
        if not condition_matches(condition):
            continue
        if _is_terminal_statement(tail):
            return True
        # For both braced and one-line-following forms, accept only an
        # immediately terminal first statement.  A preceding log/check call is
        # not proof that the unsafe path is blocked.
        next_position = position + 1
        while next_position < end:
            following = str(getattr(lines[next_position], "text", "") or "").strip()
            if following in {"", "{"}:
                next_position += 1
                continue
            if following.startswith("}"):
                break
            if _is_terminal_statement(following):
                return True
            break
    return False


def null_rejection_condition(condition: str, variable: str) -> bool:
    escaped = re.escape(str(variable or ""))
    text = str(condition or "")
    return bool(
        re.search(rf"!\s*\b{escaped}\b", text)
        or re.search(rf"\b{escaped}\b\s*==\s*(?:NULL|nullptr|0)\b", text)
        or re.search(rf"\b(?:NULL|nullptr|0)\s*==\s*{escaped}\b", text)
    )


def overflow_rejection_condition(condition: str, operands: Iterable[str]) -> bool:
    names = [str(item).strip() for item in operands if str(item).strip()]
    text = str(condition or "")
    if len(names) < 2:
        return False
    left, right = names[0], names[1]
    escaped_left, escaped_right = re.escape(left), re.escape(right)
    maximum = r"(?:SIZE_MAX|UINT(?:8|16|32|64)?_MAX|UINT_MAX|INT_MAX)"
    multiplication = (
        rf"\b{escaped_left}\b\s*>\s*{maximum}\s*/\s*\b{escaped_right}\b",
        rf"\b{escaped_right}\b\s*>\s*{maximum}\s*/\s*\b{escaped_left}\b",
    )
    addition = (
        rf"\b{escaped_left}\b\s*>\s*{maximum}\s*-\s*\b{escaped_right}\b",
        rf"\b{escaped_right}\b\s*>\s*{maximum}\s*-\s*\b{escaped_left}\b",
    )
    if any(re.search(pattern, text) for pattern in (*multiplication, *addition)):
        return True
    builtin = re.search(r"\b__builtin_(?:add|mul)_overflow\s*\((?P<args>[^)]*)\)", text)
    return bool(
        builtin
        and re.search(rf"\b{escaped_left}\b", builtin.group("args"))
        and re.search(rf"\b{escaped_right}\b", builtin.group("args"))
    )


def source_events(code: str) -> list[SourceEvent]:
    physical: list[int] = []
    clean_lines: list[str] = []
    for i, raw in enumerate(code.splitlines()):
        match = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", raw)
        physical.append(int(match[1]) if match else i + 1)
        clean_lines.append(match[2] if match else raw)
    source = "\n".join(clean_lines)
    chars = list(source)
    lexical = list(source)
    for match in _TOKEN.finditer(source):
        for i in range(match.start(), match.end()):
            if source[i] != "\n":
                lexical[i] = " "
                chars[i] = " "
    text = "".join(chars)
    masked = "".join(lexical)
    positions: list[tuple[int, int]] = []
    byte_offsets: list[int] = []
    byte_offset = 0
    row, column = 0, 1
    for ch in source:
        positions.append((physical[row] if row < len(physical) else row + 1, column))
        byte_offsets.append(byte_offset)
        width = len(ch.encode("utf-8"))
        byte_offset += width
        if ch == "\n":
            row, column = row + 1, 1
        else:
            column += width
    result: list[SourceEvent] = []
    start = 0
    paren = bracket = 0

    def emit(end: int) -> None:
        nonlocal start
        while start < end and text[start].isspace():
            start += 1
        if start < end:
            number, col = positions[start]
            fragment = text[start:end].strip()
            # Expression sequencing/ternaries require compiler facts.
            ordered = not bool(re.search(r"\?|&&|\|\||,(?![^()]*\))", masked[start:end]))
            raw = source[start:end].strip()
            result.append(
                SourceEvent(number, col, byte_offsets[start], len(result), fragment, raw, ordered)
            )
        start = end

    for i, ch in enumerate(masked):
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif not paren and not bracket and ch in ";{}":
            if ch == "}" and text[start:i].strip():
                emit(i)
            emit(i + 1)
    emit(len(source))
    return result


def ordered_lines(lines: Sequence[Any], line_type: Any, facts: Any = None) -> list[Any]:
    source = "\n".join(
        line.raw if re.match(r"^\s*\d+\s*\|", line.raw) else f"{line.number} | {line.raw}"
        for line in lines
    )
    result = []
    block = 0
    for event in source_events(source):
        if re.match(r"(?:if|else|while|for|switch|case|default)\b|}", event.text):
            block += 1
        args = dict(
            number=event.number,
            raw=event.raw,
            text=event.text,
            index=event.ordinal,
            column=event.column,
            offset=event.offset,
            ordinal=event.ordinal,
            ordered=event.ordered,
        )
        if "block_id" in line_type.__dataclass_fields__:
            args["block_id"] = block
        result.append(line_type(**args))
        if re.search(r"\breturn\b", event.text) or event.text.endswith(":"):
            block += 1
    if not facts or not facts.get("complete"):
        return result
    # Compiler expansion is essential for macros and multiple expression
    # operations. Keep lexical control statements as context; CFG order is
    # evidence, never a proof that operations from different paths coexecute.
    operations = sorted(
        (event for event in facts.get("events", []) if event.get("operation")),
        key=lambda event: (
            event["location"]["line"],
            event["location"]["column"],
            event.get("block", 0),
            event.get("ordinal", 0),
        ),
    )
    expanded = []
    cursor = 0
    for i, line in enumerate(result):
        begin = (line.number, line.column)
        end = (result[i + 1].number, result[i + 1].column) if i + 1 < len(result) else (10**12, 0)
        selected = []
        while (
            cursor < len(operations)
            and (operations[cursor]["location"]["line"], operations[cursor]["location"]["column"])
            < end
        ):
            event = operations[cursor]
            if (event["location"]["line"], event["location"]["column"]) >= begin:
                selected.append(event)
            cursor += 1
        if selected and (
            any(event.get("macro_expansion") for event in selected)
            or (len(selected) > 1 and not line.ordered)
        ):
            for event in selected:
                location = event["location"]
                expanded.append(
                    replace(
                        line,
                        number=location["line"],
                        column=location["column"],
                        offset=location.get("offset", line.offset),
                        offset_basis="file_utf8",
                        text=event["operation"] + ";",
                        ordered=False,
                    )
                )
        else:
            expanded.append(line)
    return [replace(line, index=i, ordinal=i) for i, line in enumerate(expanded)]
