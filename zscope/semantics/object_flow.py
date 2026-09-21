"""Small, shared must-alias environment for source consumers.

Only straight-line copies establish equality. Conditional writes and unknown
expressions create fresh identities, so may-alias information never discharges
an obligation. Allocation sites get separate instances even through one API.
"""

from __future__ import annotations

import re

from .contracts import ObjectBinding, code_tokens


class ObjectFlow:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.serial = 0
        self.conditional_depth = 0
        self.pending_branch = False

    def resolve(self, expression: str) -> str:
        clean = ObjectBinding("return").resolve([], expression)
        match = re.fullmatch(
            r"(?P<unary>[&*]?)(?P<root>[A-Za-z_]\w*)(?P<path>(?:(?:->|\.)[A-Za-z_]\w*|\[\d+\])*)",
            clean,
        )
        if not match:
            return clean
        return match["unary"] + self.values.get(match["root"], match["root"]) + match["path"]

    def observe(self, text: str) -> None:
        tokens = code_tokens(text)
        branch = any(t in {"if", "else", "for", "while", "switch", "case", "?"} for t in tokens)
        conditional = branch or bool(self.conditional_depth) or self.pending_branch
        if branch and "{" in tokens:
            self.conditional_depth += tokens.count("{")
        elif self.conditional_depth:
            self.conditional_depth += tokens.count("{")
        self.conditional_depth = max(0, self.conditional_depth - tokens.count("}"))
        self.pending_branch = branch and ";" not in tokens and "{" not in tokens
        if "=" not in tokens:
            return
        split = tokens.index("=")
        left = tokens[:split]
        if not left or left[0] in {"*", "&"} or any(t in left for t in ("->", ".", "[", "(", ")")):
            return
        target = left[-1]
        if not re.fullmatch(r"[A-Za-z_]\w*", target):
            return
        right = "".join(tokens[split + 1 :]).rstrip(";")
        self.serial += 1
        if not conditional and re.fullmatch(
            r"[&*]?[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*|\[\d+\])*", right
        ):
            self.values[target] = self.resolve(right)
        else:
            self.values[target] = f"{target}@{self.serial}"
