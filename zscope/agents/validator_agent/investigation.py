"""保存一条告警在本次调查里查到的材料、来源和进展。

提问由外层程序负责。这里记下模型的解释和它引用的材料，供程序独立核查。
"""

import hashlib
import json
from typing import Any, Callable, Dict, Iterable, List, Mapping

from ...common.cancellation import current_cancellation_token
from ...common.validator_protocol import VALIDATOR_MISSING_FACT_KINDS, bind_validator_decision
from ...framework.base import validate_function_arguments
from .output import DecisionOutput

# 复核工具中，只有下面三种会返回与代码有关的材料。其他工具的回执只说明操作已执行。
_REVIEW_EVIDENCE_TOOLS = {
    "query_guard_coverage",
    "query_validation_facts",
    "check_validation_claim",
}

# 每种查询只取表中列出的内容。比如搜索取匹配项，空页没有新证据。
# 自定义读取工具可以把查到的内容放在 data.records。
_RECORD_COLLECTIONS = {
    "search_code": ("symbols", "matches"),
    "query_code_graph": ("edges",),
    "trace_data_flow": ("paths",),
    "query_static_findings": ("findings",),
    "query_guard_coverage": ("rows",),
    "query_validation_facts": ("items",),
    "get_callers": ("callers",),
    "get_function_info": ("matches",),
    "list_known_functions": ("functions",),
    "find_function_pointers": ("references",),
    "query_pointer_alias": ("indirect_callees",),
}


def _digest(value: Any) -> str:
    """先按名称排好各项，再算编号。同一条记录即使颠倒了字段顺序，也能认出来。"""
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _evidence_records(name: str, data: Mapping[str, Any]) -> Iterable[tuple[str, Any]]:
    """只取工具实际读到的内容。例如读代码取原文和位置，查询耗时留在记录里。"""
    if name in {"read_code", "get_file_snippet"}:
        source = data.get("source", data)
        body = {key: data[key] for key in ("symbol", "macro", "members") if key in data}
        body["contract"] = (data.get("definition") or {}).get("contract")
        if isinstance(source, Mapping) and isinstance(source.get("code"), str) and source["code"]:
            body["source"] = {
                key: source[key]
                for key in ("code", "file", "file_path", "start_line", "end_line", "revision")
                if key in source
            }
        yield "data", body
    elif name == "check_validation_claim":
        if (
            data.get("status") == "supported"
            and data.get("claim_kind")
            and data.get("evidence_refs")
        ):
            yield "claim", {
                key: data.get(key)
                for key in (
                    "claim_kind",
                    "reason",
                    "coverage",
                    "checked_functions",
                    "evidence_refs",
                )
            }
    elif name == "get_semantic_context" and "snapshot" in data:
        snapshot = data.get("snapshot") or {}
        if snapshot.get("status") == "current":
            yield "snapshot", snapshot.get("data")
            yield "contract", data.get("contract")
        semantics = data.get("security_semantics") or {}
        if semantics.get("status") == "current":
            for record in semantics.get("records", []):
                yield "security_semantics", record
    else:
        for key in _RECORD_COLLECTIONS.get(name, ("records",)):
            collection = data.get(key)
            if isinstance(collection, list):
                for record in collection:
                    yield key, record


def _tool_result_evidence_atoms(name: str, result: Mapping[str, Any]) -> set[str]:
    """按整条记录识别重复项，保留字段之间的关系。查到 0 或“否”也算查到了值。"""
    data = result.get("data")
    if (
        result.get("success") is not True
        or result.get("status", "ok") not in {"ok", "partial"}
        or result.get("error")
        or not isinstance(data, Mapping)
    ):
        return set()

    def present(record: Any) -> bool:
        if isinstance(record, Mapping):
            return any(present(nested) for nested in record.values())
        if isinstance(record, (list, tuple)):
            return any(present(nested) for nested in record)
        return record is not None and record != ""

    return {
        _digest([key, data.get("subject"), data.get("build_context_id"), record])
        for key, record in _evidence_records(name, data)
        if present(record)
    }


def _build_context_ids(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        if value.get("build_context_id"):
            yield value["build_context_id"]
        value = value.values()
    elif not isinstance(value, list):
        return
    for nested in value:
        yield from _build_context_ids(nested)


class InvestigationSession:
    """一次调查用一份记录本，防止把另一条告警查到的材料混进来。"""

    def __init__(
        self,
        input_data: Dict[str, Any],
        *,
        execute_tool: Callable[[str, Any], Dict[str, Any]],
        tools_schema: List[Dict[str, Any]],
        pass_kind: str,
    ) -> None:
        # 查询模块启动时也会用到这里的代码。等调查开始再加载它，两边就都能准备好。
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
            # 自动检查能回答一部分问题，其余允许的问题也可以从本次读到的源码中找答案。
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
        self.review_tools = {schema["function"]["name"]: schema for schema in self.review_schemas}
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
                "A related-candidate proposal returns an audit receipt and supplies no evidence. "
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
                "Confirmed conditions remain claims, not program proof.\n"
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
            "For an unchanged condition, check the current observations and cite its CONDITION_R* "
            "confirmation_ref in the final tool to register a fresh FACT_V3 in the same turn. "
            f"For new or changed conditions, use {self.fact_tool_name} with current TOOLFACT refs. "
            "The final tool also accepts registered FACT_V3 refs and input-catalog refs. "
            if self.conditions is not None
            else f"Record each resolved condition through {self.fact_tool_name} with its TOOLFACT "
            "refs. Non-Review final decisions cite input-catalog or registered FACT_V3 refs, "
            "never raw TOOLFACT refs; Review may cite current tool evidence. "
        )
        session_directive += (
            f"Use the supplied read-only tools within {iteration_limit} model iterations; "
            "there is no independent tool-query quota. Read for a specific candidate condition. "
            + registration
            + "Only new code or fact records from successful reads and checks earn a TOOLFACT. "
            "Partial results support only the records returned. Errors, empty reads and diagnostics "
            "supply no evidence. Fact kinds are a vocabulary, not a checklist. Rephrasing or "
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
        """先核对这条说法及其来源。核对通过后，调用方才会把它记入调查记录。"""
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
        # 同一份材料换个说法只算一次。它若回答了新问题，或改变了之前的判断，就算新进展。
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
        """先把整组材料都核对一遍，避免最后一项出错时，前几项已经被当作事实。"""
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
            return {"success": False, "error": "validator_v3_duplicate_tool_query"}
        if self.no_new_evidence_fact_stop:
            return {
                "success": False,
                "error": "validator_v3_no_new_evidence_fact_stop; emit the final result",
            }
        if self.review_session is not None and name in self.review_tools:
            error = validate_function_arguments(self.review_tools[name], args)
            if error:
                return {"success": False, "error": error}
            if name == "propose_related_candidate" and any(
                ref not in self.tool_fact_catalog and ref not in self.fact_ids
                for ref in args["evidence_refs"]
            ):
                return {
                    "success": False,
                    "error": "related proposal requires recorded tool evidence",
                }
            tool_result = self.review_session.execute(name, args)
        else:
            tool_result = self.execute_tool(name, args)
        if token is not None:
            token.raise_if_cancelled()
        succeeded = self.query_plans.query_succeeded(tool_result)
        if succeeded:
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
        result = dict(tool_result)
        if name in self.review_tools and name not in _REVIEW_EVIDENCE_TOOLS:
            result.update(
                validator_new_evidence=False,
                instruction="This action receipt is not code evidence.",
            )
        else:
            result.update(self._admit_observation(name, args, tool_result, qid, succeeded))
        if self.review_session is not None:
            self.review_session.record_result(name, args, result)
        return result

    def _admit_observation(
        self, name: str, args: Any, tool_result: Dict[str, Any], qid: str, succeeded: bool
    ) -> Dict[str, Any]:
        """工具确实带回新材料时才给它编号，后续可以凭编号找回来源。"""
        new_atoms = _tool_result_evidence_atoms(name, tool_result) - self.evidence_atoms
        if not new_atoms:
            instruction = (
                "This result adds no source evidence. Use existing TOOLFACT refs for "
                "supported facts; do not infer safety from an empty observation."
                if succeeded
                else "The query failed and supplied no evidence. Correct the indicated "
                "arguments if this read is still needed. Do not record a fact from "
                "this error; if the condition cannot be resolved, finish uncertain."
            )
            return {"validator_new_evidence": False, "instruction": instruction}

        fingerprint = _digest(tool_result)
        identity = [
            self.candidate_uid,
            self.cluster_uid,
            self.build_context_id,
            name,
            args,
            fingerprint,
        ]
        ref = "TOOLFACT_" + _digest(identity)[:32]
        record = {
            "evidence_ref": ref,
            "tool_name": name,
            "arguments_hash": _digest(args),
            "result_hash": fingerprint,
            "dependency_code_hash": fingerprint,
            "build_context_ids": sorted(set(_build_context_ids([args, tool_result.get("data")]))),
            "location": self.evidence_location(args, tool_result),
        }
        self.evidence_atoms.update(new_atoms)
        self.tool_fact_catalog[ref] = record
        if self.conditions is not None:
            record["query_id"] = qid
            self.conditions.bind_evidence(qid, ref)
            instruction = (
                "Use this CURRENT evidence to check the condition tasks. Evidence-ready recipes "
                "can be reconfirmed by citing their confirmation_ref directly in the final tool. "
                f"Record only newly resolved or changed conditions through {self.fact_tool_name}."
            )
        else:
            instruction = (
                f"If this resolves a required condition, call {self.fact_tool_name} now, citing {ref}. "
                "This TOOLFACT is raw evidence, not a final FACT_V3 reference. "
                "Do not defer supported fact registration until the iteration budget is exhausted."
            )
        if self.review_enabled:
            self.allowed_refs.add(ref)
        return {"evidence_ref": ref, "validator_new_evidence": True, "instruction": instruction}

    def _zscope_start_iteration(self, iteration: int) -> bool:
        """连续两轮既没读到新材料，也没查清新条件，就请模型用已有材料收尾。"""
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
        # 提问前用上次的查法重读当前代码。旧答案和旧证明可能已经过时。
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
        # 先清掉上次结论，免得这次回答失败时还显示上次的成功结果。
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
            # 普通调查要先写清“这条材料说明了什么”，交答案时才能引用登记好的事实。
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
        # 如果本轮证据推翻了问题成立的必要条件，这次就不能接受“已确认”。
        if self.conditions and self.conditions.contradicts_verdict(
            parsed, self.investigation_facts
        ):
            return {"valid": False, "error": "Verified contradicts refuted required conditions."}
        if self.review_enabled:
            from ...core.validation.review_protocol import (
                REVIEW_VERSION,
                parse_review_result,
                adjudicate_review,
            )

            adapted = {**payload, "decision": parsed.to_dict()}
            # 简短格式由程序补上版本号。旧格式自己带版本号，后面会核对。
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
