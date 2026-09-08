"""Conservative lexical events with physical source coordinates.

This is a fallback, not a control-flow proof. Semicolons inside parentheses,
strings and macro bodies are never treated as statement boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any, Sequence


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
