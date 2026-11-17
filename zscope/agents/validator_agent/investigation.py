"""Candidate-local V3 evidence, progress and terminal validation.

The agent owns model calls; this session owns only the evidence acquired during
one investigation. Registered facts remain claims, never program proof authority.
"""

import hashlib
import json
from typing import Any, Callable, Dict, Iterable, List, Mapping

from ...common.cancellation import current_cancellation_token
from ...common.validator_protocol import VALIDATOR_MISSING_FACT_KINDS, bind_validator_decision
from ...framework.base import validate_function_arguments
from .output import DecisionOutput

_NON_EVIDENCE_TOOL_RESULT_KEYS = frozenset(
    {
        "args",
        "arguments",
        "coverage",
        "duration",
        "duration_ms",
        "elapsed",
        "elapsed_ms",
        "error",
        "message",
        "metadata",
        "provenance",
        "next_actions",
        "page",
        "query",
        "request",
        "status",
        "success",
        "timestamp",
        "tool",
        "tool_name",
        "trace",
        "warnings",
    }
)


def _digest(value: Any) -> str:
    """Use one canonical JSON encoding for session-local evidence identities."""
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _tool_result_evidence_atoms(value: Any) -> set[str]:
    """Hash complete result-body records, retaining values and associations.

    Skip wrappers and cache diagnostics; zero/false, arguments and source
    whitespace remain evidence.
    """
    if isinstance(value, Mapping):
        if (
            value.get("success") is False
            or value.get("status", "ok") not in {"ok", "partial"}
            or value.get("error")
        ):
            return set()
        value = value.get("data", value)
    if not isinstance(value, Mapping):
        return set()
    collections = value.keys() & {
        "records",
        "edges",
        "paths",
        "findings",
        "symbols",
        "matches",
        "files",
        "results",
        "items",
        "rows",
    }
    if collections:
        records = [(key, record) for key in sorted(collections) for record in value[key]]
    elif (
        value.get("complete") is False
        and "reason" in value
        or ("claim_kind" in value and value.get("status") == "unknown")
    ):
        return set()
    elif "snapshot" in value or "security_semantics" in value:
        snapshot, semantics = value.get("snapshot") or {}, value.get("security_semantics") or {}
        body = {
            "snapshot": snapshot.get("data") if snapshot.get("status") == "current" else None,
            "contract": value.get("contract"),
        }
        records = [(key, record) for key, record in body.items() if record]
        if semantics.get("status") == "current":
            records.extend(("security_semantics", record) for record in semantics["records"])
    elif "source" in value or "symbol" in value:
        source = value.get("source")
        records = [
            (
                "data",
                {
                    "source": (
                        source if isinstance(source, Mapping) and source.get("code") else None
                    ),
                    "symbol": value.get("symbol"),
                    "contract": (value.get("definition") or {}).get("contract"),
                    "macro": value.get("macro"),
                    "members": value.get("members"),
                },
            )
        ]
    else:
        records = [
            (
                "data",
                {
                    key: nested
                    for key, nested in value.items()
                    if key not in _NON_EVIDENCE_TOOL_RESULT_KEYS and key != "summary"
                },
            )
        ]

    def present(record: Any) -> bool:
        if isinstance(record, Mapping):
            return any(present(nested) for nested in record.values())
        if isinstance(record, (list, tuple)):
            return any(present(nested) for nested in record)
        return record is not None and record != ""

    return {
        _digest([key, value.get("subject"), value.get("build_context_id"), record])
        for key, record in records
        if present(record)
    }


class InvestigationSession:
    """A callable tool executor with an explicit, isolated investigation lifetime."""

    def __init__(
        self,
        input_data: Dict[str, Any],
        *,
        execute_tool: Callable[[str, Any], Dict[str, Any]],
        tools_schema: List[Dict[str, Any]],
        pass_kind: str,
    ) -> None:
        # The validation package exports a runner that imports ValidatorAgent.
        # Resolve the query-plan helpers only after agent initialization.
        from ...core.validation import condition_tasks, investigation_reuse

        self.query_plans = investigation_reuse
        self.input_data = input_data
        self.prior_queries = self.query_plans.load_steps(
            input_data.get("_investigation_query_plan")
        )
        self.prior_observations = {
            _digest([step["name"], step["arguments"]]): step["observation"]
            for step in self.prior_queries
        }
        self.evidence_slice = input_data["evidence_slice"]
        self.pass_kind = pass_kind
        self.execute_tool = execute_tool
        self.tools_schema = tools_schema
        self.fact_tool_name = "record_validator_investigation_fact"
        self.fact_ids: set[str] = set()
        obligation = self.evidence_slice.get("obligation")
        obligation = obligation if isinstance(obligation, dict) else {}
        self.candidate_uid = str(
            self.input_data.get("finding_uid") or obligation.get("candidate_uid") or ""
        )
        self.cluster_uid = str(
            self.input_data.get("validation_cluster_uid")
            or obligation.get("validation_cluster_uid")
            or ""
        )
        self.build_context_id = str(input_data.get("candidate_build_context_id") or "")
        self.subject_uid = str(
            input_data.get("candidate_subject_uid") or obligation.get("subject_uid") or ""
        )
        self.function_uid = str(obligation.get("function_uid") or obligation.get("function") or "")
        catalog = self.evidence_slice.get("evidence_ref_catalog")
        self.allowed_refs = set(catalog) if isinstance(catalog, dict) else set()
        decision_facts = self.evidence_slice.get("decision_facts")
        decision_facts = decision_facts if isinstance(decision_facts, dict) else {}
        raw_missing = self.evidence_slice.get("allowed_missing_fact_kinds")
        candidate_policy_present = isinstance(raw_missing, list)
        if not candidate_policy_present:
            raw_missing = decision_facts.get("missing_fact_kinds")
        self.allowed_fact_kinds = {
            str(value).strip().lower()
            for value in (raw_missing if isinstance(raw_missing, list) else [])
            if str(value).strip()
        }
        if not self.allowed_fact_kinds and not candidate_policy_present:
            self.allowed_fact_kinds = set(VALIDATOR_MISSING_FACT_KINDS)
        if self.input_data.get("autonomous_validation") is True:
            # Providers remain accelerators, not a limit on the questions a
            # Validator may resolve from current read-only source evidence.
            from ...core.validation.evidence_completion import SUPPORTED_FACT_KINDS

            self.allowed_fact_kinds |= set(SUPPORTED_FACT_KINDS) | {
                "counterexample",
                "uninitialized_on_reachable_path",
                "overflow_value_reachable",
                "overflow_reaches_security_sink",
                "runtime_bound_controllable",
                "safe_upper_bound_absent",
            }
        self.review_enabled = self.input_data.get("review_protocol_enabled") is True
        self.review_session = self.input_data.get("_review_session")
        self.review_schemas = (
            self.review_session.schemas() if self.review_session is not None else []
        )
        self.review_tools = {value["function"]["name"] for value in self.review_schemas}
        self.accepted_review: Dict[str, Any] = {}
        self.terminal_output: DecisionOutput | None = None
        self.terminal_schema: Dict[str, Any] | None = None
        self.accepted_result: Dict[str, Any] | None = None
        self.tool_call_signatures: set[str] = set()
        self.evidence_atoms: set[str] = set()
        self.tool_fact_catalog: Dict[str, Dict[str, Any]] = {}
        self.review_tool_results: List[Dict[str, Any]] = []
        self.investigation_facts: List[Dict[str, Any]] = []
        self.fact_progress: set[tuple[str, ...]] = set()
        self.observed_queries: List[Dict[str, Any]] = []
        self.query_reuse = self.query_plans.metrics()
        self.consecutive_no_evidence_fact_iterations = 0
        self.last_started_iteration = 0
        self.evidence_facts_at_iteration_start = 0
        self.no_new_evidence_fact_stop = False
        self.conditions = None
        if (
            condition_tasks.ENABLED
            and investigation_reuse.ENABLED
            and pass_kind == "investigation_synthesis"
            and not self.review_enabled
            and self.review_session is None
        ):
            table = condition_tasks.ConditionTable(input_data)
            if table.rows:
                self.conditions = table
        self.fact_tool_schema = self._make_fact_schema()

    def _make_fact_schema(self) -> Dict[str, Any]:
        properties: Dict[str, Any] = {
            "fact_kind": {"type": "string", "enum": sorted(self.allowed_fact_kinds)},
            "evidence_refs": {
                "type": "array",
                "minItems": 1,
                "maxItems": 8,
                "items": {"type": "string"},
                "description": (
                    "Only current TOOLFACT refs from successful reads; "
                    "no input-catalog or FACT_V3 refs."
                ),
            },
            "summary": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1000,
                "description": "Evidence-backed fact summary written in Simplified Chinese.",
            },
            "claim_scope": {
                "type": "string",
                "enum": ["candidate_premise", "all_paths", "all_accessors"],
                "description": (
                    "Only for fact_kind=counterexample; omit for all other kinds. "
                    "Distinguish a concrete refuted premise from a universal claim."
                ),
            },
            "subject_uid": {
                "type": "string",
                "description": (
                    "Only for fact_kind=counterexample; omit for all other kinds. "
                    "Copy the exact candidate subject UID for the refuted object."
                ),
            },
        }
        if "counterexample" not in self.allowed_fact_kinds:
            del properties["claim_scope"]
            del properties["subject_uid"]
        if self.conditions is not None:
            properties["condition_ids"] = {
                "type": "array",
                "minItems": 1,
                "maxItems": len(self.conditions.rows),
                "items": {"type": "string", "enum": list(self.conditions.rows)},
                "description": "Conditions this current evidence supports or refutes.",
            }
            properties["condition_outcome"] = {
                "type": "string",
                "enum": ["supported", "refuted"],
                "description": "Whether the cited evidence supports or refutes the named condition.",
            }
        return {
            "type": "function",
            "function": {
                "name": self.fact_tool_name,
                "description": (
                    "Record one evidence-backed fact resolved by prior read-only tool results. "
                    "This only updates the current Validator session."
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": properties,
                    "required": ["fact_kind", "evidence_refs", "summary"],
                },
            },
        }

    def prompt(self, iteration_limit: int) -> str:
        if self.pass_kind == "v2b_adjudication":
            session_directive = (
                "Adversarially audit this prior rejection, which lacks deterministic proof. "
                "Look for missed release paths, ineffective guards, ownership transfers, "
                "reachability or lock-coverage facts that challenge its reasoning.\n"
            )
        else:
            session_directive = "Investigate the candidate's unresolved conditions.\n"
        if self.input_data.get("autonomous_validation") is True:
            session_directive += (
                f"Candidate subject UID: {self.subject_uid}. "
                "Follow relevant callers, callees, object transfers and lifecycle endpoints "
                "without waiting for a named provider. To refute this obligation, record a "
                "counterexample with the exact subject_uid and claim_scope. Universal cleanup "
                "or protection claims also need cleanup_coverage or lockset/happens_before "
                "facts for that scope. Keep unrelated root causes as investigation leads.\n"
            )
        if self.review_enabled:
            session_directive += (
                "Review the prior_rejection and construct a separate defect_case. A supported "
                "case identifies the actual subject, source, sink, feasible path, trigger and "
                "guard analysis, cites recorded tool evidence and has no missing conditions. "
                "defect_case and refuted prior_rejection cite only current TOOLFACT or FACT_V3 "
                "refs, not input-catalog refs. Every defect_case ref must also appear in "
                "decision.evidence_refs. "
                "The final tool carries decision, prior_rejection and defect_case.\n"
            )
        if self.input_data.get("review_positive_case") is True:
            session_directive += (
                "Positive-case experiment: build one concrete witness and test each missing "
                "condition against tools, without lowering confirmation requirements.\n"
            )
        if self.conditions is not None:
            session_directive += (
                "The condition table gives the candidate's current verification tasks. "
                "When recording a fact, name the condition_ids it supports or refutes and its "
                "condition_outcome. Confirmation requires the witness conditions together; "
                "coverage counterclaims are alternative rejection branches, not a mandatory checklist. "
                "Check supplied evidence-ready recipes against current observations. Cite their "
                "CONDITION_R* confirmation_refs directly in the final decision to reconfirm them "
                "and register fresh FACT_V3 refs in that same turn. Use this direct final route for "
                "unchanged conditions; investigate and record only new or contradicted conditions. "
                "This creates current claims, not proof authority.\n"
                + json.dumps(
                    {
                        "condition_requirements": [
                            {key: row[key] for key in ("condition_id", "goal", "mode", "purpose")}
                            for row in self.conditions.rows.values()
                        ]
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
        registration = (
            "For evidence-ready conditions, check their current observations and cite the supplied "
            "confirmation_refs in the final tool; this performs current fact registration in that "
            "same turn. For additional or changed conditions, use " + self.fact_tool_name + " with "
            "current TOOLFACT refs. Final evidence_refs accept CONDITION_R* confirmation refs, "
            "registered FACT_V3 refs and input-catalog refs. "
            if self.conditions is not None
            else f"Record each resolved condition through {self.fact_tool_name} with its TOOLFACT "
            "refs. Non-Review final decisions cite input-catalog or registered FACT_V3 refs, "
            "never raw TOOLFACT refs; Review may cite current tool evidence. "
        )
        session_directive += (
            f"Use the supplied read-only tools within {iteration_limit} model iterations; "
            "there is no independent tool-query quota. Read for a specific candidate condition. "
            + registration
            + "Failed/empty reads "
            "cannot support facts. Fact kinds are a vocabulary, not a checklist. Rephrasing or "
            "rebundling existing support is not progress. After two completed rounds without "
            "new evidence or condition support, finish with what is established. Query further "
            "only for a remaining condition or contradiction; stop when the decision is supported "
            "or the missing condition cannot be resolved. Independent fact records may be "
            "submitted together; submit the final tool alone on the following turn.\n\n"
        )
        return session_directive + json.dumps(
            self.evidence_slice, ensure_ascii=False, separators=(",", ":")
        )

    @staticmethod
    def evidence_location(args: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        arguments = args if isinstance(args, dict) else {}
        data = result.get("data") if isinstance(result, dict) else None
        data = data if isinstance(data, dict) else {}
        symbol = data.get("symbol") or data.get("subject") or {}
        symbol = symbol if isinstance(symbol, dict) else {}

        def locate(value: Any) -> Dict[str, Any]:
            children: Iterable[Any]
            if isinstance(value, dict):
                if value.get("file") or value.get("file_path"):
                    return value
                preferred = (
                    "site",
                    "location",
                    "records",
                    "edges",
                    "paths",
                    "findings",
                    "matches",
                    "items",
                    "source",
                    "symbol",
                    "subject",
                )
                children = (value.get(key) for key in dict.fromkeys((*preferred, *value)))
            elif isinstance(value, list):
                children = iter(value)
            else:
                return {}
            for nested in children:
                found = locate(nested)
                if found:
                    return found
            return {}

        location = locate(data) or arguments
        return {
            "file": str(location.get("file") or location.get("file_path") or ""),
            "function": str(
                symbol.get("qualified_name")
                or symbol.get("name")
                or data.get("function")
                or arguments.get("func_name")
                or ""
            ),
            "start_line": location.get("start_line") or location.get("line"),
            "end_line": location.get("end_line") or location.get("line"),
        }

    def record_fact(self, args: Any) -> Dict[str, Any]:
        prepared = self._prepare_fact(args)
        if not prepared["success"]:
            return prepared
        self._register_fact(prepared["fact"], args)
        prepared["instruction"] = (
            "Cite this FACT_V3 ref in the final result. Record other resolved "
            "conditions if needed; query only for a specific unresolved condition "
            "or contradiction. If none remain, submit the final tool alone. "
            "Recording a fact does not by itself prove the candidate."
        )
        if self.conditions is not None:
            prepared["remaining_validation_tasks"] = self.conditions.remaining()
        return prepared

    def _prepare_fact(self, args: Any) -> Dict[str, Any]:
        """Validate and construct a claim without changing session or condition state."""
        error = validate_function_arguments(self.fact_tool_schema["function"]["parameters"], args)
        if error:
            return {"success": False, "error": error}
        fact_kind, refs = args["fact_kind"], sorted(set(args["evidence_refs"]))
        if any(ref not in self.tool_fact_catalog for ref in refs):
            return {
                "success": False,
                "error": "investigation facts must cite prior TOOLFACT refs",
            }
        summary = args["summary"].strip()
        if not summary:
            return {"success": False, "error": "fact summary is invalid"}
        subject_uid = str(args.get("subject_uid") or "")
        if fact_kind != "counterexample" and (subject_uid or args.get("claim_scope")):
            return {
                "success": False,
                "error": "subject_uid and claim_scope require a counterexample fact",
            }
        if fact_kind == "counterexample" and (
            not subject_uid
            or subject_uid != self.subject_uid
            or not self.build_context_id
            or args.get("claim_scope") not in {"candidate_premise", "all_paths", "all_accessors"}
        ):
            return {
                "success": False,
                "error": "counterclaim requires the current exact object, build and claim scope",
            }
        backing = [self.tool_fact_catalog[ref] for ref in refs]
        if self.build_context_id and any(
            observed != self.build_context_id
            for value in backing
            for observed in value["build_context_ids"]
        ):
            return {"success": False, "error": "fact evidence belongs to a different build"}
        fact = {
            "fact_kind": fact_kind,
            "evidence_refs": refs,
            "summary": summary,
            "claim_scope": str(args.get("claim_scope") or ""),
            "subject_uid": subject_uid,
            "build_context_id": self.build_context_id,
        }
        condition_ids = sorted(set(args.get("condition_ids") or []))
        if condition_ids:
            fact["condition_ids"] = condition_ids
            fact["condition_outcome"] = args.get("condition_outcome") or "supported"
        dependencies = sorted({str(value.get("dependency_code_hash") or "") for value in backing})
        identity = {
            **fact,
            "candidate": self.candidate_uid,
            "cluster": self.cluster_uid,
            "dependency_hashes": dependencies,
        }
        fact.update(
            fact_uid="FACT_V3_" + _digest(identity)[:32],
            producer_engine="validator_readonly_tool_session",
            dependency_code_hash=hashlib.sha256(
                "\n".join(dependencies).encode("utf-8")
            ).hexdigest(),
            locations=[value.get("location") for value in backing],
            origin="validator_tool_evidence",
        )
        return {"success": True, "fact": fact}

    def _register_fact(self, fact: Dict[str, Any], args: Any) -> None:
        fact_uid = fact["fact_uid"]
        if fact_uid not in self.fact_ids:
            self.fact_ids.add(fact_uid)
            self.investigation_facts.append(fact)
            if self.conditions is not None:
                self.conditions.record(fact, self.tool_fact_catalog)
        # New conditions/outcomes are progress; rephrasing or rebundling old support is not.
        self.fact_progress.update(
            (
                fact["fact_kind"],
                ref,
                fact["subject_uid"],
                fact["claim_scope"],
                condition,
                fact.get("condition_outcome", ""),
            )
            for ref in fact["evidence_refs"]
            for condition in fact.get("condition_ids") or [""]
        )
        self.allowed_refs.add(fact_uid)
        if self.review_session is not None:
            self.review_session.record_result(
                self.fact_tool_name, args, {"success": True, "fact": fact}
            )

    def _prepare_confirmations(self, recipes: list[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare the whole terminal batch before publishing any current fact."""
        prepared = []
        for recipe in recipes:
            fact_args = {
                key: recipe[key]
                for key in (
                    "fact_kind",
                    "summary",
                    "evidence_refs",
                    "condition_ids",
                    "condition_outcome",
                )
            }
            if recipe["fact_kind"] == "counterexample":
                fact_args.update(claim_scope=recipe["claim_scope"], subject_uid=self.subject_uid)
            result = self._prepare_fact(fact_args)
            if not result["success"]:
                return result
            prepared.append((result["fact"], fact_args))
        return {"success": True, "facts": prepared}

    def __call__(self, name: str, args: Any) -> Dict[str, Any]:
        token = current_cancellation_token()
        if token is not None:
            token.raise_if_cancelled()
        if name == self.fact_tool_name:
            return self.record_fact(args)
        signature = _digest([name, args])
        if signature in self.tool_call_signatures:
            return {
                "success": False,
                "error": "validator_v3_duplicate_tool_query",
            }
        if self.no_new_evidence_fact_stop:
            return {
                "success": False,
                "error": "validator_v3_no_new_evidence_fact_stop; emit the final result",
            }
        if name == "propose_related_candidate":
            refs = args.get("evidence_refs", []) if isinstance(args, dict) else []
            if not refs or any(
                ref not in self.tool_fact_catalog and ref not in self.fact_ids for ref in refs
            ):
                return {
                    "success": False,
                    "error": "related proposal requires recorded tool evidence",
                }
        tool_result = (
            self.review_session.execute(name, args)
            if self.review_session is not None and name in self.review_tools
            else self.execute_tool(name, args)
        )
        if token is not None:
            token.raise_if_cancelled()
        if self.query_plans.query_succeeded(tool_result):
            self.tool_call_signatures.add(signature)
        self.query_plans.remember_query(self.observed_queries, name, args, tool_result)
        qid = ""
        if self.conditions is not None:
            qid = self.conditions.observe(
                name, args, tool_result, self.prior_observations.get(signature)
            )
        if self.review_enabled or self.review_session is not None:
            self.review_tool_results.append(
                {"name": name, "arguments": args, "result": tool_result}
            )
        result_atoms = _tool_result_evidence_atoms(tool_result)
        new_atoms = result_atoms - self.evidence_atoms
        result = dict(tool_result)
        if not new_atoms:
            result["validator_new_evidence"] = False
            result["instruction"] = (
                "This result adds no source evidence. Use existing TOOLFACT refs for "
                "supported facts; do not infer safety from an empty observation."
                if self.query_plans.query_succeeded(tool_result)
                else "The query failed and supplied no evidence. Correct the indicated "
                "arguments if this read is still needed. Do not record a fact from "
                "this error; if the condition cannot be resolved, finish uncertain."
            )
        else:
            fingerprint = _digest(tool_result)
            self.evidence_atoms.update(new_atoms)
            ref = (
                "TOOLFACT_"
                + _digest(
                    [
                        self.candidate_uid,
                        self.cluster_uid,
                        self.build_context_id,
                        name,
                        args,
                        fingerprint,
                    ]
                )[:32]
            )

            def builds(value: Any) -> set[str]:
                if isinstance(value, dict):
                    found = {value["build_context_id"]} if value.get("build_context_id") else set()
                    return found.union(*(builds(nested) for nested in value.values()))
                if isinstance(value, list):
                    return set().union(*(builds(nested) for nested in value))
                return set()

            record: Dict[str, Any] = {
                "evidence_ref": ref,
                "tool_name": name,
                "arguments_hash": _digest(args),
                "result_hash": fingerprint,
                "dependency_code_hash": fingerprint,
                "build_context_ids": sorted(builds(args) | builds(tool_result.get("data"))),
                "location": self.evidence_location(args, tool_result),
            }
            self.tool_fact_catalog[ref] = record
            if self.conditions is not None:
                record["query_id"] = qid
                self.conditions.bind_evidence(qid, ref)
            if self.review_enabled:
                self.allowed_refs.add(ref)
            result["evidence_ref"] = ref
            result["validator_new_evidence"] = True
            result["instruction"] = (
                f"If this resolves a required condition, call {self.fact_tool_name} now, citing {ref}. "
                "This TOOLFACT is raw evidence, not a final FACT_V3 reference. "
                "Do not defer supported fact registration until the iteration budget is exhausted."
            )
            if self.conditions is not None:
                result["instruction"] = (
                    "Use this CURRENT evidence to check the condition tasks. Evidence-ready recipes "
                    "can be reconfirmed by citing their confirmation_ref directly in the final tool. "
                    f"Record only newly resolved or changed conditions through {self.fact_tool_name}."
                )
        if self.review_session is not None:
            self.review_session.record_result(name, args, result)
        return result

    def _zscope_start_iteration(self, iteration: int) -> bool:
        """Stop after two rounds with no new evidence or condition support."""
        # Read observations advance progress without granting proof authority.
        if self.terminal_schema is not None:
            refs = self.allowed_refs | {
                value["confirmation_ref"]
                for value in (self.conditions.ready.values() if self.conditions else [])
            }
            schema = self.terminal_schema["function"]["parameters"]["properties"]["evidence_refs"]
            schema["items"] = (
                {"type": "string", "enum": sorted(refs)} if refs else {"type": "string"}
            )
            schema["maxItems"] = 32 if refs else 0
        normalized = max(1, int(iteration or 1))
        if normalized <= self.last_started_iteration:
            return self.no_new_evidence_fact_stop
        current_evidence_fact_count = len(self.tool_fact_catalog) + len(self.fact_progress)
        if self.last_started_iteration:
            if current_evidence_fact_count > self.evidence_facts_at_iteration_start:
                self.consecutive_no_evidence_fact_iterations = 0
            else:
                self.consecutive_no_evidence_fact_iterations += 1
        self.evidence_facts_at_iteration_start = current_evidence_fact_count
        self.last_started_iteration = normalized
        self.no_new_evidence_fact_stop = self.consecutive_no_evidence_fact_iterations >= 2
        return self.no_new_evidence_fact_stop

    def replay_queries(self, messages: List[Dict[str, Any]]) -> None:
        # Re-execute a prior read-only plan before the first model turn. No old
        # answer, FACT_V3 record, terminal decision or proof is restored.
        prefetched = []
        available_tools = {schema["function"]["name"] for schema in self.tools_schema}
        for step in self.prior_queries:
            cancellation = current_cancellation_token()
            if cancellation is not None:
                cancellation.raise_if_cancelled()
            if step["name"] not in available_tools:
                continue
            current = self(step["name"], step["arguments"])
            self.query_reuse["replayed_queries"] += 1
            observation = next(
                (
                    value["observation"]
                    for value in self.observed_queries
                    if value["name"] == step["name"] and value["arguments"] == step["arguments"]
                ),
                None,
            )
            if not self.query_plans.query_succeeded(current):
                self.query_reuse["failed_queries"] += 1
                change = "query_failed"
            else:
                changed = observation != step["observation"]
                self.query_reuse["changed_results" if changed else "unchanged_results"] += 1
                change = "changed" if changed else "unchanged"
            prefetched.append(
                {
                    "tool": step["name"],
                    "arguments": step["arguments"],
                    "change": change,
                    "current_result": current,
                }
            )
        if prefetched:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "These read-only queries were executed again in the CURRENT build, before this turn. "
                        "Use their current results instead of repeating identical queries. They are observations, "
                        "not prior verdicts or proofs. Reassess the current candidate, new counterevidence and "
                        "remaining obligations; query further whenever needed. Empty, paged or truncated results "
                        "do not establish universal absence. Use the condition continuation instructions below "
                        "when provided; otherwise record supported facts through the normal fact tool.\n"
                        + json.dumps(prefetched, ensure_ascii=False, separators=(",", ":"))
                    ),
                }
            )
        if self.conditions is not None and prefetched:
            plan = self.input_data.get("_investigation_query_plan") or {}
            self.conditions.prepare(plan.get("condition_plan"), self.prior_queries)
            messages.append(
                {
                    "role": "user",
                    "content": "Current condition progress and remaining tasks. Check proposed claims against CURRENT query results. Cite matching confirmation_ref values in the final decision to register fresh facts and conclude in one turn; investigate changed or contradicted conditions.\n"
                    + json.dumps(
                        {
                            "conditions": list(self.conditions.rows.values()),
                            "remaining_tasks": self.conditions.remaining(),
                            "ready_recipes": {
                                rid: {
                                    key: recipe[key]
                                    for key in (
                                        "condition_ids",
                                        "condition_outcome",
                                        "summary",
                                        "evidence_refs",
                                        "confirmation_ref",
                                    )
                                }
                                for rid, recipe in self.conditions.ready.items()
                            },
                            "query_scope_changes": [
                                {
                                    key: value[key]
                                    for key in (
                                        "query_id",
                                        "kind",
                                        "coverage",
                                        "change",
                                        "added",
                                        "removed",
                                        "page",
                                        "missing",
                                    )
                                }
                                for value in self.conditions.subscriptions.values()
                            ],
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                }
            )

    def accept_result(self, payload: Any) -> Dict[str, Any]:
        # Retain this attempt's decoded output; an invalid retry cannot reuse an old verdict.
        self.accepted_result = None
        self.accepted_review.clear()
        self.terminal_output = (
            payload if isinstance(payload, DecisionOutput) else DecisionOutput.from_payload(payload)
        )
        payload = self.terminal_output.payload
        if not isinstance(payload, dict):
            return {"valid": False, "error": "invalid Validator decision object"}
        decision = payload.get("decision") if self.review_enabled else payload
        if not isinstance(decision, dict):
            return {"valid": False, "error": "invalid review decision object"}
        refs = decision.get("evidence_refs")
        raw_refs = (
            [ref for ref in refs if isinstance(ref, str) and ref in self.tool_fact_catalog]
            if isinstance(refs, list)
            else []
        )
        if raw_refs and not self.review_enabled:
            return {
                "valid": False,
                "error": (
                    "Final evidence_refs must cite recorded FACT_V3 refs or supplied catalog refs. "
                    f"Call {self.fact_tool_name} with the supporting TOOLFACT refs and an allowed "
                    "fact_kind, then cite the returned fact_uid. Do not rename raw refs or "
                    "drop the evidence to bypass registration. Unresolved conditions stay uncertain."
                ),
                "unrecorded_tool_refs": raw_refs,
            }
        request = decision.get("missing_fact_request")
        if (
            isinstance(request, dict)
            and isinstance(request.get("fact_kind"), str)
            and request["fact_kind"] not in self.allowed_fact_kinds
        ):
            return {"valid": False, "error": "unsupported investigation fact kind"}
        confirmations = {
            recipe["confirmation_ref"]: recipe
            for recipe in (self.conditions.ready.values() if self.conditions else [])
        }
        parsed = bind_validator_decision(
            decision,
            candidate_uid=self.candidate_uid,
            validation_cluster_uid=self.cluster_uid,
            expected_pass=self.pass_kind,
            allowed_evidence_refs=sorted(self.allowed_refs | set(confirmations)),
            allowed_missing_fact_kinds=self.allowed_fact_kinds,
            subject_uid=self.subject_uid,
            function_uid=self.function_uid,
        )
        if parsed is None:
            return {
                "valid": False,
                "error": (
                    "Invalid Validator decision. Follow the supplied schema and cite current "
                    "allowed refs. Use missing_fact_request only for an uncertain decision; "
                    "otherwise use JSON null. Historical result identities must match this request."
                ),
            }
        if self.review_enabled:
            from ...core.validation.review_protocol import (
                REVIEW_VERSION,
                parse_review_result,
                adjudicate_review,
            )

            adapted = {**payload, "decision": parsed.to_dict()}
            # Only compact decisions use the new unversioned wire envelope.
            if "schema_version" not in decision and "schema_version" not in payload:
                adapted["schema_version"] = REVIEW_VERSION
            envelope = parse_review_result(
                adapted,
                candidate_uid=self.candidate_uid,
                cluster_uid=self.cluster_uid,
                expected_pass=self.pass_kind,
                allowed_refs=self.allowed_refs,
                rejection_expected=self.input_data.get("review_rejection_expected") is True,
            )
            if envelope is None:
                return {"valid": False, "error": "invalid versioned review envelope"}
            accepted, reason = adjudicate_review(
                envelope, backed_refs=set(self.tool_fact_catalog) | self.fact_ids
            )
            self.accepted_review.update(envelope=envelope, decision=accepted, reason=reason)
            self.accepted_result = accepted
        else:
            selected = {
                ref: confirmations[ref] for ref in parsed.evidence_refs if ref in confirmations
            }
            bound = {}
            if self.conditions is not None and selected:
                prepared = self._prepare_confirmations(list(selected.values()))
                if not prepared["success"]:
                    return {"valid": False, "error": prepared["error"]}
                for ref, (fact, args) in zip(selected, prepared["facts"]):
                    self._register_fact(fact, args)
                    self.conditions.counts["reconfirmed_conditions"] += len(fact["condition_ids"])
                    bound[ref] = fact["fact_uid"]
            self.accepted_result = {
                **parsed.to_dict(),
                "evidence_refs": [bound.get(ref, ref) for ref in parsed.evidence_refs],
            }
        return {"valid": True, "payload": self.accepted_result}
