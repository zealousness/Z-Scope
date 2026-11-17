"""A bounded model view for reusing hierarchical summaries across build receipts.

Current compiler receipts remain owned by the static pass.  This module only
aliases identity fields and hides receipt content hashes from the *actual*
model-readable store; it never decides whether compiler evidence is current.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping


VIEW_VERSION = "zscope.hierarchical-reuse-view.v2"
_TASK_ID = re.compile(r"(?<![A-Za-z0-9_])(?:FN|FEATURE|MODULE)_[0-9a-f]{32}(?![A-Za-z0-9_])")


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def select_reference_bindings(value: Any, bindings: Mapping[str, Any]) -> dict[str, Any]:
    """Attach only the logical references used by this unverified context."""
    mentioned = {token for text in _strings(value) for token in _TASK_ID.findall(text)}
    return {token: deepcopy(bindings[token]) for token in sorted(mentioned) if token in bindings}


class SummaryReuseView:
    """Keep runtime authority separate from an identical, bounded model input."""

    def __init__(self, hierarchy: Mapping[str, Any], lifecycle: Mapping[str, Any]):
        self.original = hierarchy
        self.reason = ""
        self.ids: dict[str, str] = {}
        self.builds: dict[str, str] = {}
        self.targets: dict[str, str] = {}
        self.hierarchy: dict[str, Any] = {}
        self.lifecycle: dict[str, Any] = {}
        functions = hierarchy["functions"]
        locators: set[tuple[str, str, str]] = set()
        for uid, unit in functions.items():
            receipt = unit.get("facts", {}).get("build_context", {})
            command = str(unit.get("command_id") or receipt.get("command_id") or "")
            locator = (str(unit["file"]), command, str(unit["usr"]))
            if not command:
                self.reason = "command_identity_unavailable"
                return
            if locator in locators:
                self.reason = "ambiguous_command_symbol"
                return
            locators.add(locator)
            self.ids[uid] = "FN_" + _digest(locator)[:32]
            build_alias = "BUILD_" + _digest(command)[:32]
            build = unit["build_context_id"]
            if build in self.builds and self.builds[build] != build_alias:
                self.reason = "ambiguous_build_command"
                return
            self.builds[build] = build_alias
        self.reverse_builds = {alias: build for build, alias in self.builds.items()}
        if len(self.reverse_builds) != len(self.builds):
            self.reason = "ambiguous_build_command"
            return
        for link in hierarchy.get("link_receipts", []):
            receipt = link.get("receipt", {})
            target = str(link.get("target_id") or "")
            if target:
                # Link bytes authorize the current run; output/command and
                # exact membership describe the scope visible to the model.
                self.targets[target] = (
                    "LINK_"
                    + _digest(
                        [
                            receipt.get("output", target),
                            receipt.get("arguments"),
                            sorted(self.builds.get(m, m) for m in link.get("members", [])),
                        ]
                    )[:32]
                )
        for unit in hierarchy["units"]:
            members = sorted(self.ids[m] for m in unit["members"])
            name = self._name(str(unit.get("name") or ""))
            self.ids[unit["id"]] = (
                unit["level"].upper()
                + "_"
                + _digest([name, members, unit.get("boundary_confirmed"), unit.get("coverage")])[
                    :32
                ]
            )
        self.reverse = {alias: uid for uid, alias in self.ids.items()}
        if len(self.reverse) != len(self.ids):
            self.reason = "ambiguous_unit_mapping"
            return
        runtime_units = {unit["id"]: unit for unit in hierarchy["units"]}
        runtime_units.update(functions)
        self.reference_bindings = {
            alias: {
                "unit_id": uid,
                **{
                    key: runtime_units[uid][key]
                    for key in (
                        "level",
                        "function",
                        "usr",
                        "build_context_id",
                        "file",
                        "start_line",
                        "end_line",
                    )
                    if key in runtime_units[uid]
                },
            }
            for alias, uid in self.reverse.items()
        }
        model_functions = {}
        for uid, unit in functions.items():
            readable = dict(unit)
            facts = dict(unit["facts"])
            if isinstance(facts.get("build_context"), dict):
                facts["build_context"] = {
                    key: item
                    for key, item in facts["build_context"].items()
                    if key not in {"dependencies", "search_directories", "search_excludes"}
                }
            readable["facts"] = facts
            value = self._value(readable)
            value["id"] = self.ids[uid]
            value["manifest"] = {
                **value.get("manifest", {}),
                "analysis_unit_id": self.ids[uid],
                "fact_digest": _digest(value["facts"]),
            }
            model_functions[value["id"]] = value
        parents = []
        for unit in hierarchy["units"]:
            value = self._value(unit)
            value["id"] = self.ids[unit["id"]]
            value["name"] = self._name(str(unit.get("name") or ""))
            value["members"] = sorted(self.ids[m] for m in unit["members"])
            parents.append(value)
        self.lifecycle = self._value(lifecycle)
        self.hierarchy = {
            "functions": model_functions,
            "units": parents,
            "edges": sorted([[self.ids[a], self.ids[b]] for a, b in hierarchy["edges"]]),
            "gaps": self._value(hierarchy["gaps"]),
            "link_receipts": [
                {
                    "target_id": self.targets.get(link.get("target_id"), link.get("target_id")),
                    "members": sorted(self.builds.get(m, m) for m in link.get("members", [])),
                    "current_membership": True,
                }
                for link in hierarchy.get("link_receipts", [])
            ],
        }
        # Unknown fields remain intact in the actual view and its cache input;
        # their changes therefore miss instead of being silently normalized.

    @property
    def available(self) -> bool:
        return bool(self.hierarchy) and not self.reason

    def _name(self, name: str) -> str:
        if name.startswith("unlinked:"):
            return "unlinked:" + self.builds.get(name[9:], name[9:])
        return self.ids.get(name, self.targets.get(name, name))

    def _value(self, value: Any, field: str = "") -> Any:
        if isinstance(value, list):
            if field in {"members", "member_build_context_ids"}:
                mapping = self.ids if field == "members" else self.builds
                return sorted(mapping.get(v, self.builds.get(v, v)) for v in value)
            return [self._value(v) for v in value]
        if not isinstance(value, dict):
            if isinstance(value, str):
                if field in {"id", "unit", "caller", "owner", "origin_unit", "transfer_to"}:
                    return self.ids.get(value, value)
                if field in {"build_context_id", "definition_build_context_id"}:
                    return self.builds.get(value, value)
            return deepcopy(value)
        result = {key: self._value(item, key) for key, item in value.items()}
        if field == "function_identity" and "key" in result:
            result["key"] = _digest({k: v for k, v in result.items() if k != "key"})
        return result

    def bindings_digest(self, unit: Mapping[str, Any]) -> str:
        members = unit.get("members", [unit["id"]])
        return _digest(
            [
                (self.reverse[m], self.original["functions"][self.reverse[m]]["build_context_id"])
                for m in members
            ]
        )

    def bind_summary(self, summary: Mapping[str, Any]) -> dict[str, Any]:
        """Rebind schema-defined references, never perform prose replacement."""
        result = deepcopy(dict(summary))
        for section in (
            "preconditions",
            "postconditions",
            "actual_effects",
            "state_transitions",
            "obligations",
        ):
            for row in result[section]:
                row["refs"] = [self._bind_ref(ref) for ref in row["refs"]]
                if section == "obligations":
                    for key in ("owner", "transfer_to"):
                        row[key] = self.reverse.get(row[key], row[key])
        for row in result["hypotheses"]:
            for key in ("source_ref", "sink_ref"):
                row[key] = self._bind_ref(row[key])
        return result

    def _bind_ref(self, ref: str) -> str:
        uid, _, line = ref.rpartition(":")
        return self.reverse.get(uid, uid) + ":" + line

    def template_supported(self, summary: Mapping[str, Any]) -> bool:
        # Prose and example code keep their stable logical aliases verbatim.
        # A separate current binding table resolves them; only schema-defined
        # evidence references are rewritten by bind_summary. Unknown references
        # cannot be given a current binding and do not enter the reuse cache.
        return all(
            token in self.reverse for text in _strings(summary) for token in _TASK_ID.findall(text)
        )

    def bind_gap(self, gap: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: (
                self.reverse.get(value, value)
                if key in {"unit", "caller"} and isinstance(value, str)
                else (
                    self.reverse_builds.get(value, value)
                    if key in {"build_context_id", "definition_build_context_id"}
                    and isinstance(value, str)
                    else deepcopy(value)
                )
            )
            for key, value in gap.items()
        }
