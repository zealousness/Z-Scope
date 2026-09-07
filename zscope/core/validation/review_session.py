"""Candidate-bound experimental tools shared by V3 and V2b."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .review_checks import ReviewClaimChecker, check_guard_call_sites, function_in_source, line_of


def _tool(
    name: str, description: str, properties: Dict[str, Any], required: list[str]
) -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "properties": properties,
                "required": required,
            },
        },
    }


class ReviewSession:
    def __init__(
        self,
        checker: ReviewClaimChecker,
        issue: Dict[str, Any],
        *,
        related: bool = False,
        facts_enabled: bool = True,
        checkpoint: Optional[Callable[[], None]] = None,
    ):
        self.checker, self.issue, self.related = checker, issue, related
        self.checkpoint = checkpoint
        self.facts_enabled = facts_enabled
        self.queried_functions = {str(issue.get("function") or "")}

    def schemas(self) -> list[Dict[str, Any]]:
        if not self.facts_enabled:
            return []
        schemas = [
            _tool(
                "query_guard_coverage",
                "Check actual-argument range contracts at known call sites. Unknown indirect calls and public entry boundaries remain explicit; this table is not whole-program safety proof.",
                {
                    "parameter": {"type": "integer", "minimum": 0},
                    "lower": {"type": "integer"},
                    "upper": {"type": "integer"},
                },
                ["parameter", "lower", "upper"],
            ),
            _tool(
                "query_validation_facts",
                "Read complete compiler facts through pages. A page is not a proof of path coverage.",
                {
                    "kind": {
                        "type": "string",
                        "enum": ["functions", "types", "cfg", "macros", "ast_nodes"],
                    },
                    "symbol": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                ["kind", "symbol", "offset", "limit"],
            ),
            _tool(
                "check_validation_claim",
                "Independently check the ORIGINAL candidate against complete compiler facts. Unknown is not safety. Scope cannot be changed by the model.",
                {
                    "kind": {
                        "type": "string",
                        "enum": [
                            "auto",
                            "type_identity",
                            "ownership_cleanup",
                            "guard_bounds",
                            "lock_coverage",
                        ],
                    }
                },
                ["kind"],
            ),
        ]
        if self.related and not self.issue.get("related_generation"):
            fields = {
                key: {"type": "string", "minLength": 1, "maxLength": 2000}
                for key in (
                    "function",
                    "category",
                    "source",
                    "sink",
                    "description",
                    "trigger_condition",
                )
            }
            fields.update(
                line={"type": "integer", "minimum": 1},
                evidence_refs={
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "items": {"type": "string"},
                },
                analysis_scope={
                    "type": "string",
                    "enum": ["current_build", "conditional_source_branch"],
                },
            )
            schemas.append(
                _tool(
                    "propose_related_candidate",
                    "Register an evidenced neighboring defect in the original or queried function. One generation only; every proposal needs normal validation.",
                    fields,
                    list(fields),
                )
            )
        return schemas

    def record_result(self, name: str, arguments: Any, result: Any) -> None:
        record = {"name": name, "arguments": deepcopy(arguments), "result": deepcopy(result)}
        records = self.issue.setdefault("review_tool_results", [])
        if record not in records:
            records.append(record)
        if self.checkpoint:
            self.checkpoint()

    def execute(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        uid = str((self.issue.get("review_fact_store") or {}).get("fact_store_id") or "")
        if name == "query_guard_coverage":
            data = check_guard_call_sites(
                self.checker.store, uid, str(self.issue.get("function") or ""), **arguments
            )
            self.issue["review_guard_coverage"] = data
        elif name == "query_validation_facts":
            data = self.checker.store.query(uid, **arguments)
            if data.get("complete") and arguments.get("symbol"):
                self.queried_functions.add(str(arguments["symbol"]))
        elif name == "check_validation_claim":
            data = self.checker.check(self.issue, str(arguments.get("kind") or "auto"))
        elif name == "propose_related_candidate":
            data = self._propose(arguments)
        else:
            return {"success": False, "error": "unknown review tool"}
        if self.checkpoint:
            self.checkpoint()
        descriptor = self.issue.get("review_fact_store") or {}
        return {
            "success": True,
            "data": {
                **data,
                "file_path": descriptor.get("source"),
                "function": self.issue.get("function"),
            },
        }

    def _propose(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self.related or self.issue.get("related_generation"):
            return {"accepted": False, "reason": "one_generation_only"}
        proposals = self.issue.setdefault("review_related_proposals", [])
        if len(proposals) >= 16:
            return {"accepted": False, "reason": "proposal_limit"}
        uid = str((self.issue.get("review_fact_store") or {}).get("fact_store_id") or "")
        data = self.checker.store.load(uid)
        fn = (
            self.checker._functions(data).get(str(arguments.get("function") or ""))
            if data.get("complete")
            else None
        )
        if (
            not fn
            or not function_in_source(fn, data["source"])
            or str(arguments["function"]) not in self.queried_functions
        ):
            return {"accepted": False, "reason": "queried_function_required"}
        source = Path(data["source"]).read_text(encoding="utf-8")
        start, end = line_of(fn, source), line_of(
            {"loc": fn.get("range", {}).get("end", {})}, source
        )
        if not start <= int(arguments.get("line") or 0) <= end:
            return {"accepted": False, "reason": "source_anchor_outside_queried_function"}
        proposal = deepcopy(arguments)
        proposal.update(
            file=data["source"],
            location=f'{data["source"]}:{arguments["line"]}',
            parent_fact_store_id=uid,
        )
        if proposal not in proposals:
            proposals.append(proposal)
        return {"accepted": True, "index": proposals.index(proposal), "validation_required": True}
