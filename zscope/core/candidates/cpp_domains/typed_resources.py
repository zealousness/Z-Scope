# mypy: disable-error-code="attr-defined"
"""Typed resource candidates. Lexical lifetime paths always require validation."""

from __future__ import annotations

import re
from typing import Any, Optional, Sequence, Set

from .models import ClangCfgLine
from .source_events import ordered_lines
from ....semantics.defaults import load_default_semantics_data

MISMATCH_RULE = "zscope.c_cpp.cpp_clang_cfg.resource_family_release_mismatch"
LEAK_RULE = "zscope.c_cpp.cpp_clang_cfg.typed_resource_leak"


class ClangTypedResourceRules:
    def _run_typed_resource_lifetimes(
        self,
        issues: list[dict[str, Any]],
        func_name: str,
        file_path: str,
        original: Sequence[ClangCfgLine],
        allowed: Optional[Set[str]],
    ) -> None:
        lines = ordered_lines(original, ClangCfgLine, self.program_facts)
        # Separate C handles from integer descriptors and C++ operator families.
        families = load_default_semantics_data()["resource_families"]
        acquire = {
            api: family for family in ("file", "directory") for api in families[family]["acquire"]
        }
        release = {
            api: family
            for family in ("file", "directory", "malloc")
            for api in families[family]["release"]
        }
        # Wrapper roles come from the existing semantic contract. The family
        # can be declared explicitly, or inferred from a FILE*/DIR* carrier.
        for row in self.semantic_overlay.get("resource_models", []):
            family = row.get("resource_family") or ""
            if not family:
                match = re.search(
                    r"\bresource_family\s*=\s*(\w+)", str(row.get("description") or "")
                )
                family = match[1] if match else ""
            if family not in families:
                continue
            if row.get("kind") in {"io_acquire", "allocator"}:
                acquire[str(row.get("name"))] = family
            if row.get("kind") in {"io_release", "deallocator"}:
                release[str(row.get("name"))] = family
        aliases: dict[str, int] = {}
        resources: dict[int, dict[str, Any]] = {}
        custom_allocations = {
            (event.get("object") or {}).get("name")
            for event in self.program_facts.get("events", [])
            if event.get("resource_family") == "custom_allocation"
        }
        parameter_families = {
            name: {"FILE": "file", "DIR": "directory"}[kind]
            for kind, name in re.findall(
                r"\b(FILE|DIR)\s*\*\s*(\w+)", "\n".join(item.text for item in lines[:1])
            )
        }
        close_pattern = re.compile(
            r"\b("
            + "|".join(map(re.escape, sorted(set(release) | self._io_release_names)))
            + r")\s*\(\s*([A-Za-z_]\w*)\s*\)"
        )

        for line in lines:
            text = line.text
            assignment = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<value>[^;]+)", text)
            if assignment:
                var, value = assignment["var"], assignment["value"].strip()
                family = ""
                if re.match(r"new\b", value):
                    # Placement/custom allocator syntax needs explicit semantics.
                    family = (
                        "custom"
                        if re.match(r"new\s*\(", value)
                        else ("new_array" if "[" in value else "new_scalar")
                    )
                else:
                    call = re.match(r"(?:(?:std)::)?(\w+)\s*\(", value)
                    if call:
                        family = acquire.get(call[1], "")
                        if not family and call[1] in self._allocator_names | self._calloc_names:
                            family = "malloc"
                        if not family and call[1] in self._io_acquire_names:
                            declared = re.search(r"\b(FILE|DIR)\s*\*", text[: assignment.start()])
                            if declared:
                                family = {"FILE": "file", "DIR": "directory"}[declared[1]]
                if family:
                    if var in custom_allocations:
                        family = "custom"
                    reopened = re.search(r"\bfreopen\s*\([^,]*,[^,]*,\s*(\w+)\s*\)", value)
                    if reopened and reopened[1] in aliases:
                        resources[aliases[reopened[1]]]["transferred"] = True
                    resources[line.index] = dict(
                        var=var, family=family, line=line, released=False, transferred=False
                    )
                    aliases[var] = line.index
                elif value in aliases:
                    aliases[var] = aliases[value]
                elif re.fullmatch(r"(?:NULL|nullptr|0)", value):
                    aliases.pop(var, None)

            deleted = re.search(
                r"\bdelete\s*(?P<array>\[\s*\])?\s*\(?\s*(?P<var>[A-Za-z_]\w*)\s*\)?\s*;", text
            )
            closed = close_pattern.search(text)
            if deleted or closed:
                var = deleted["var"] if deleted else closed[2]  # type: ignore[index]
                family = ("new_array" if deleted["array"] else "new_scalar") if deleted else release.get(closed[1], "")  # type: ignore[index]
                if var in aliases:
                    state = resources[aliases[var]]
                    if not family:
                        # A configured generic IO releaser consumes a typed
                        # carrier; this remains a candidate-level assumption.
                        family = state["family"]
                    if state["family"] == "custom":
                        state["uncertain_release"] = line
                        continue
                    if state["family"] != family:
                        self._emit_typed_resource_issue(
                            issues,
                            func_name,
                            file_path,
                            lines,
                            allowed,
                            rule="zscope.c_cpp.cpp_clang_cfg.resource_family_release_mismatch",
                            category="invalid_free",
                            state=state,
                            line=line,
                            reason="Resource acquisition and release families do not match.",
                        )
                    elif state["released"] or line.block_id in state.get(
                        "released_branches", set()
                    ):
                        self._emit_typed_resource_issue(
                            issues,
                            func_name,
                            file_path,
                            lines,
                            allowed,
                            rule="clang_cfg_same_object_released_twice",
                            category="double_free",
                            state=state,
                            line=line,
                            reason="The same resource is released more than once.",
                        )
                    if self._is_terminal_conditional_branch_line(lines, line):
                        state.setdefault("released_branches", set()).add(line.block_id)
                    else:
                        state["released"] = True
                elif (deleted or var in parameter_families) and var not in {"NULL", "nullptr"}:
                    # Parameters can be released twice even without a local new.
                    key = -line.index - 1
                    resources[key] = dict(
                        var=var, family=family, line=line, released=True, transferred=False
                    )
                    aliases[var] = key

            for var, key in list(aliases.items()):
                state = resources[key]
                if re.search(rf"\breturn\s+{re.escape(var)}\s*;", text):
                    state["transferred"] = True
                if re.search(r"\b(?:unique_ptr|shared_ptr)\s*<", text) and re.search(
                    rf"[({{]\s*{re.escape(var)}\s*[)}}]", text
                ):
                    state["transferred"] = True
                if re.search(rf"(?:->|\.)\w+\s*=\s*{re.escape(var)}\s*;", text):
                    state["transferred"] = True
                if (
                    re.search(r"\b(?:throw|return)\b", text)
                    and not state["released"]
                    and not state["transferred"]
                    and line.block_id not in state.get("released_branches", set())
                ):
                    # Failure of the acquisition leaves no live allocation.
                    guard = " ".join(
                        item.text for item in lines[max(0, line.index - 2) : line.index + 1]
                    )
                    null_failure = re.search(
                        rf"\bif\s*\(\s*(?:!\s*{re.escape(var)}|{re.escape(var)}\s*==\s*(?:NULL|nullptr|0))\s*\)",
                        guard,
                    )
                    if not null_failure:
                        state.setdefault("unreleased_exit", line)

        if not lines:
            return
        for state in resources.values():
            if state["family"] == "malloc":
                continue  # Existing malloc state machine owns leak reporting.
            if (state["released"] or state["transferred"]) and not state.get("unreleased_exit"):
                continue
            category = (
                "memory_leak"
                if state["family"].startswith("new_") or state["family"] == "custom"
                else "resource_leak"
            )
            rule = (
                "clang_cfg_acquire_without_release_on_exit"
                if category == "memory_leak"
                else "zscope.c_cpp.cpp_clang_cfg.typed_resource_leak"
            )
            self._emit_typed_resource_issue(
                issues,
                func_name,
                file_path,
                lines,
                allowed,
                rule=rule,
                category=category,
                state=state,
                line=state.get("unreleased_exit") or state.get("uncertain_release") or lines[-1],
                reason=(
                    "Custom allocation ownership requires evidence."
                    if state["family"] == "custom"
                    else "No matching release or verified ownership transfer is visible before a function exit."
                ),
            )

    def _emit_typed_resource_issue(
        self,
        issues: list[dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed: Optional[Set[str]],
        *,
        rule: str,
        category: str,
        state: dict[str, Any],
        line: ClangCfgLine,
        reason: str,
    ) -> None:
        origin = state["line"]
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed,
            defect_class=category,
            rule=rule,
            line=line,
            description=reason,
            root_cause="Resource acquisition, release and ownership must agree on every feasible path.",
            suggested_fix="Use the matching release operation or transfer ownership to a verified owner.",
            source=f"{state['family']} acquisition of {state['var']} at line {origin.number}",
            sink=line.text,
            confidence=0.8,
            positive=[
                f"line {origin.number}, column {origin.column}: {origin.text}",
                f"line {line.number}, column {line.column}: {line.text}",
            ],
            negative=[
                "Validate branch feasibility, allocation failure, exceptions, custom operators and ownership transfer."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "typed_acquire", origin, state["var"], state["family"], origin.text
                    ),
                    self._event("typed_lifetime_sink", line, state["var"], "", line.text),
                ],
                [origin.number, line.number],
            ),
            validation_required=True,
            finding_kind=(
                "audit_observation" if state["family"] == "custom" else "clang_ast_cfg_candidate"
            ),
            audit_observation_reason=(
                "custom_allocation_ownership_unresolved" if state["family"] == "custom" else ""
            ),
        )
