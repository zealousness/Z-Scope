"""Candidate-local condition progress and query-scope subscriptions.

Plans retain evidence-backed claim recipes. A current model explicitly checks
each ready recipe against freshly executed queries before registering a fact;
the validation pipeline continues to own proofs and final dispositions.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Mapping

PROTOCOL = "zscope.validator-conditions.v1"
ENABLED = True  # Internal paired-experiment switch.
UNIVERSAL_COUNTERFACTS = {
    "all_paths_release": "all_paths",
    "same_lock_covers_all_accesses": "all_accessors",
    "balanced_lock_state_all_paths": "all_paths",
    "state_restored_all_paths": "all_paths",
}
COLLECTIONS = (
    "callers",
    "callees",
    "accesses",
    "edges",
    "paths",
    "records",
    "matches",
    "items",
    "symbols",
)
COUNTERS = (
    "condition_rows",
    "ready_conditions",
    "reconfirmed_conditions",
    "reopened_conditions",
    "remaining_tasks",
    "scope_subscriptions",
    "scope_added",
    "scope_removed",
    "scope_incomplete",
)


def query_id(name: str, arguments: Any) -> str:
    value = json.dumps([name, arguments], ensure_ascii=False, sort_keys=True)
    return "QUERY_" + hashlib.sha256(value.encode()).hexdigest()[:16]


def observation_view(result: Mapping[str, Any]) -> dict[str, Any]:
    view = deepcopy(dict(result))
    # Source revisions identify the whole file. The full returned source,
    # location, scope, page and coverage remain in the comparison.
    data = view.get("data")
    source = data.get("source") if isinstance(data, dict) else None
    if isinstance(source, dict):
        source.pop("revision", None)
    if isinstance(data, dict) and isinstance(data.get("matches"), list):
        # Search view IDs address this run's pagination. Keep the entire page,
        # membership, match contents and coverage, excluding only these handles.
        data.pop("view_id", None)
        for match in data["matches"]:
            if isinstance(match, dict):
                match.pop("revision", None)
    return view


def task_context(request: Mapping[str, Any]) -> dict[str, Any]:
    from .initial_reuse import initial_request_view

    view = initial_request_view(dict(request))
    for key in list(view):
        if key.startswith("_") or key == "candidate_build_context_id":
            del view[key]
    return view


def scope_view(result: Mapping[str, Any]) -> dict[str, Any]:
    data = observation_view(result).get("data") or {}
    if isinstance(data, list):
        data = {"items": data}
    elif not isinstance(data, Mapping):
        data = {}
    coverage = result.get("coverage") or {}
    page = result.get("page") or {}
    members = [
        {"collection": key, "value": value}
        for key in COLLECTIONS
        for value in (data[key] if isinstance(data.get(key), list) else [])
    ]
    collection = any(isinstance(data.get(key), list) for key in COLLECTIONS)
    partial = (
        result.get("status") == "partial"
        or coverage.get("level") in {"partial", "unsupported", "unavailable"}
        or bool(coverage.get("missing"))
        or data.get("truncated") is True
        or data.get("complete") is False
        or page.get("has_more") is True
        or page.get("next_offset") is not None
        or (page.get("offset") or 0) > 0
    )
    complete = (
        coverage.get("level") == "complete"
        or data.get("complete") is True
        or data.get("truncated") is False
    )
    return {
        "kind": "collection" if collection else "observation",
        "coverage": "partial" if partial else "complete" if complete else "unknown",
        "members": members,
        "page": deepcopy(page),
        "missing": deepcopy(coverage.get("missing") or []),
    }


def _members(values: list[Any]) -> dict[str, Any]:
    return {json.dumps(value, sort_keys=True, ensure_ascii=False): value for value in values}


class ConditionTable:
    def __init__(self, request: Mapping[str, Any]) -> None:
        obligation = request["evidence_slice"].get("obligation") or {}
        self.rows = {
            name: {
                "condition_id": name,
                "goal": name,
                "mode": "witness",
                "purpose": "confirm",
                "status": "pending",
                "fact_refs": [],
                "query_ids": [],
            }
            for name in obligation.get("positive_conditions") or []
        }
        for name in obligation.get("counterfact_kinds") or []:
            if name in UNIVERSAL_COUNTERFACTS:
                self.rows[name] = {
                    "condition_id": name,
                    "goal": name,
                    "mode": "coverage",
                    "purpose": "reject",
                    "claim_scope": UNIVERSAL_COUNTERFACTS[name],
                    "status": "pending",
                    "fact_refs": [],
                    "query_ids": [],
                }
        self.context = task_context(request)
        self.build = str(request.get("candidate_build_context_id") or "")
        self.subject = str(
            request.get("candidate_subject_uid") or obligation.get("subject_uid") or ""
        )
        self.runtime_ids = {
            str(value)
            for value in (
                self.build,
                obligation.get("candidate_uid"),
                obligation.get("validation_cluster_uid"),
                obligation.get("obligation_uid"),
            )
            if value
        }
        self.subscriptions: dict[str, dict[str, Any]] = {}
        self.observations: dict[str, dict[str, Any]] = {}
        self.recipes: list[dict[str, Any]] = []
        self.ready: dict[str, dict[str, Any]] = {}
        self.counts = {key: 0 for key in COUNTERS}

    def observe(
        self, name: str, arguments: Any, result: Mapping[str, Any], previous: Any = None
    ) -> str:
        qid = query_id(name, arguments)
        current = scope_view(result)
        old = scope_view(previous) if previous is not None else None
        from .investigation_reuse import query_succeeded

        failed = not query_succeeded(result)
        if failed:
            current.update(
                kind=old["kind"] if old else current["kind"],
                coverage="unknown",
                missing=["current_query"],
            )
        before = _members(old["members"]) if old else {}
        after = _members(current["members"])
        self.subscriptions[qid] = {
            "query_id": qid,
            "tool": name,
            "arguments": deepcopy(arguments),
            **current,
            "change": (
                "new"
                if old is None
                else (
                    "unchanged"
                    if observation_view(result) == observation_view(previous)
                    else "changed"
                )
            ),
            "added": (
                [after[key] for key in sorted(after.keys() - before.keys())]
                if old and not failed
                else []
            ),
            "removed": (
                [before[key] for key in sorted(before.keys() - after.keys())]
                if old and not failed
                else []
            ),
        }
        self.observations[qid] = {"result": deepcopy(dict(result)), "evidence_ref": ""}
        if current["kind"] == "collection" and self.subscriptions[qid]["change"] != "unchanged":
            for row in self.rows.values():
                if row["mode"] == "coverage" and row["status"] != "pending":
                    row.update(status="pending", fact_refs=[])
                    self.ready.pop(row.pop("recipe_id", ""), None)
        return qid

    def bind_evidence(self, qid: str, ref: str) -> None:
        self.observations[qid]["evidence_ref"] = ref

    def record(self, fact: Mapping[str, Any], catalog: Mapping[str, Any]) -> None:
        from .investigation_reuse import query_succeeded

        ids = fact.get("condition_ids") or []
        if not ids:
            return
        for rid, proposal in list(self.ready.items()):
            if set(ids).intersection(proposal["condition_ids"]):
                del self.ready[rid]
        self.recipes = [
            recipe for recipe in self.recipes if not set(ids).intersection(recipe["condition_ids"])
        ]
        backing = [catalog[ref].get("query_id") for ref in fact["evidence_refs"]]
        outcome = fact.get("condition_outcome") or "supported"
        for cid in ids:
            row = self.rows[cid]
            row.update(status=outcome, fact_refs=[fact["fact_uid"]], query_ids=backing)
            if row["mode"] == "coverage" and outcome == "supported":
                scopes = [
                    value for value in self.subscriptions.values() if value["kind"] == "collection"
                ]
                if not scopes or any(value["coverage"] != "complete" for value in scopes):
                    row["status"] = "scope_pending"
        if any(ref in fact["summary"] for ref in self.runtime_ids | set(catalog)):
            return
        inputs = {
            qid: observation
            for qid, observation in self.observations.items()
            if query_succeeded(observation["result"])
        }
        # Failed lookups supplied no evidence for a concrete witness. A scope
        # claim, in contrast, still needs its unresolved searches completed.
        if any(self.rows[cid]["mode"] == "coverage" for cid in ids) and len(inputs) != len(
            self.observations
        ):
            return
        self.recipes.append(
            {
                "condition_ids": list(ids),
                "condition_outcome": outcome,
                "fact_kind": fact["fact_kind"],
                "summary": fact["summary"],
                "claim_scope": fact.get("claim_scope") or "",
                "evidence_queries": backing,
                # Retain every successful observation visible to this claim.
                "input_queries": list(inputs),
            }
        )

    def prepare(self, plan: Any, steps: list[dict[str, Any]]) -> None:
        if not isinstance(plan, dict) or plan.get("schema_version") != PROTOCOL:
            return
        same_context = plan.get("context") == self.context
        previous = {
            query_id(step["name"], step["arguments"]): step["observation"] for step in steps
        }
        reopened: set[str] = set()
        for recipe in plan.get("recipes") or []:
            ids = recipe["condition_ids"]
            if not ids or any(cid not in self.rows for cid in ids):
                continue
            inputs = recipe["input_queries"]
            ready = (
                same_context
                and bool(inputs)
                and all(
                    qid in previous
                    and qid in self.observations
                    and observation_view(previous[qid])
                    == observation_view(self.observations[qid]["result"])
                    for qid in inputs
                )
            )
            refs = [
                self.observations.get(qid, {}).get("evidence_ref")
                for qid in recipe["evidence_queries"]
            ]
            ready = ready and bool(refs) and all(refs)
            if any(self.rows[cid]["mode"] == "coverage" for cid in ids):
                scopes = [
                    value for value in self.subscriptions.values() if value["kind"] == "collection"
                ]
                ready = (
                    ready
                    and bool(scopes)
                    and all(
                        value["coverage"] == "complete" and value["change"] == "unchanged"
                        for value in scopes
                    )
                )
            if ready:
                rid = f"R{len(self.ready) + 1}"
                self.ready[rid] = {
                    **deepcopy(recipe),
                    "evidence_refs": refs,
                    "confirmation_ref": "CONDITION_" + rid,
                }
                for cid in ids:
                    self.rows[cid].update(
                        status="evidence_ready", recipe_id=rid, query_ids=recipe["evidence_queries"]
                    )
            else:
                reopened.update(ids)
                for cid in ids:
                    self.rows[cid]["status"] = "pending"
        self.counts["ready_conditions"] = sum(
            row["status"] == "evidence_ready" for row in self.rows.values()
        )
        self.counts["reopened_conditions"] = len(reopened)

    def remaining(self) -> list[dict[str, Any]]:
        tasks = []
        for cid, row in self.rows.items():
            if row["status"] in {"supported", "refuted"}:
                continue
            tasks.append(
                {
                    "condition_id": cid,
                    "goal": row["goal"],
                    "purpose": row["purpose"],
                    "action": (
                        "check_current_evidence_and_confirm"
                        if row["status"] == "evidence_ready"
                        else "investigate"
                    ),
                    "completion": (
                        "Check the current evidence and cite the recipe's confirmation_ref in the final decision."
                        if row["status"] == "evidence_ready"
                        else "Record current evidence supporting or refuting this condition."
                    ),
                    "recipe_id": row.get("recipe_id"),
                }
            )
            if row["mode"] == "coverage":
                for scope in self.subscriptions.values():
                    if scope["kind"] != "collection":
                        continue
                    for member in scope["added"]:
                        tasks.append(
                            {
                                "condition_id": cid,
                                "action": "check_added_member",
                                "member": member,
                                "query_id": scope["query_id"],
                            }
                        )
                    if scope["coverage"] != "complete":
                        tasks.append(
                            {
                                "condition_id": cid,
                                "action": "complete_query_scope",
                                "query_id": scope["query_id"],
                                "page": scope["page"],
                                "missing": scope["missing"],
                            }
                        )
        return tasks

    def snapshot(self) -> dict[str, Any]:
        tasks = self.remaining()
        return {
            "schema_version": PROTOCOL,
            "build_context_id": self.build,
            "subject_uid": self.subject,
            "conditions": list(self.rows.values()),
            "subscriptions": list(self.subscriptions.values()),
            "remaining_tasks": tasks,
            "metrics": {
                **self.counts,
                "condition_rows": len(self.rows),
                "remaining_tasks": len(tasks),
                "scope_subscriptions": len(self.subscriptions),
                "scope_added": sum(len(s["added"]) for s in self.subscriptions.values()),
                "scope_removed": sum(len(s["removed"]) for s in self.subscriptions.values()),
                "scope_incomplete": sum(
                    s["kind"] == "collection" and s["coverage"] != "complete"
                    for s in self.subscriptions.values()
                ),
            },
        }

    def export(self, steps: list[dict[str, Any]]) -> dict[str, Any]:
        available = {query_id(step["name"], step["arguments"]) for step in steps}
        return {
            "schema_version": PROTOCOL,
            "context": self.context,
            "recipes": [
                recipe
                for recipe in self.recipes
                if set(recipe["input_queries"]) <= available
                and all(recipe["evidence_queries"])
                and all(
                    self.rows[cid]["status"] in {"supported", "refuted"}
                    for cid in recipe["condition_ids"]
                )
            ],
        }
